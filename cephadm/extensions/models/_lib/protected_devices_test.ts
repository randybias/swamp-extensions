import { assert, assertEquals } from "jsr:@std/assert@1.0.19";
import {
  assess,
  type CommandProbe,
  examineTargets,
  type FileProbe,
  normalizeUuid,
  parseExamineUuid,
  parseMdstat,
  parseZpoolStatus,
  type ProbeInputs,
  type ProtectedSet,
  unionProtected,
  volumeGroupOf,
} from "./protected_devices.ts";

// --- fixture builders (synthetic names only) --------------------------------

interface Dev {
  name: string;
  type: string;
  fstype?: string;
  uuid?: string;
  partuuid?: string;
  label?: string;
  mounts?: string[];
  path?: string;
  children?: Dev[];
}

function row(d: Dev): Record<string, unknown> {
  const path = d.path ??
    (d.type === "lvm" || d.type === "crypt"
      ? `/dev/mapper/${d.name}`
      : `/dev/${d.name}`);
  return {
    name: d.name,
    path,
    pkname: null,
    type: d.type,
    fstype: d.fstype ?? null,
    uuid: d.uuid ?? null,
    partuuid: d.partuuid ?? null,
    label: d.label ?? null,
    mountpoints: d.mounts ?? [null],
    ...(d.children ? { children: d.children.map(row) } : {}),
  };
}

const ok = (stdout: string): CommandProbe => ({ code: 0, stdout });
const missing: CommandProbe = { code: 127, stdout: "" };
const file = (text: string): FileProbe => ({ state: "ok", text });
/** What real mdadm prints for a device that is not an array member: on stderr. */
const NO_SB: CommandProbe = {
  code: 1,
  stdout: "",
  stderr: "mdadm: No md superblock detected on /dev/x.\n",
};
const SWAP_HEADER = "Filename\t\t\t\tType\t\tSize\t\tUsed\t\tPriority\n";

function lsblk(...devs: Dev[]): CommandProbe {
  return ok(JSON.stringify({ blockdevices: devs.map(row) }));
}

function findmnt(
  ...mounts: { target: string; source: string; fstype: string }[]
): CommandProbe {
  return ok(JSON.stringify({ filesystems: mounts }));
}

const ARRAY_UUID = "7a0d6e3f:11112222:33334444:55556666";
const examineOut = (uuid: string) =>
  `/dev/x:\n          Magic : a92b4efc\n        Version : 1.2\n     Array UUID : ${uuid}\n           Name : host:0\n`;

/** A plain host: root on sda2, ESP on sda1, sdb and sdc raw. */
function plain(overrides: Partial<ProbeInputs> = {}): ProbeInputs {
  return {
    lsblk: lsblk(
      {
        name: "sda",
        type: "disk",
        children: [
          {
            name: "sda1",
            type: "part",
            fstype: "vfat",
            uuid: "ABCD-1234",
            mounts: ["/boot/efi"],
          },
          {
            name: "sda2",
            type: "part",
            fstype: "ext4",
            uuid: "11111111-2222-3333-4444-555555555555",
            mounts: ["/"],
          },
        ],
      },
      { name: "sdb", type: "disk" },
      { name: "sdc", type: "disk" },
    ),
    findmnt: findmnt(
      { target: "/", source: "/dev/sda2", fstype: "ext4" },
      { target: "/boot/efi", source: "/dev/sda1", fstype: "vfat" },
      { target: "/run", source: "tmpfs", fstype: "tmpfs" },
    ),
    fstab: file(
      "UUID=11111111-2222-3333-4444-555555555555 / ext4 defaults 0 1\n" +
        "UUID=ABCD-1234 /boot/efi vfat umask=0077 0 1\n",
    ),
    swaps: file(SWAP_HEADER),
    mdstat: { state: "absent" },
    links: ok(""),
    blkid: missing,
    zpool: missing,
    pvs: missing,
    mdExamine: {},
    ...overrides,
  };
}

/** Answers "not a member" for every examine target the test did not script. */
function withExamine(input: ProbeInputs, candidates: string[]): ProbeInputs {
  const mdExamine = { ...input.mdExamine };
  for (const path of examineTargets(input, candidates)) {
    mdExamine[path] ??= NO_SB;
  }
  return { ...input, mdExamine };
}

function refusal(
  input: ProbeInputs,
  candidates: string[],
  previous?: ProtectedSet,
) {
  const result = assess(withExamine(input, candidates), candidates, previous);
  assert(!result.ok, "expected a refusal");
  return result.refusal;
}

/** Asserts a refusal of the given code, showing the reason when it differs. */
function refused(
  input: ProbeInputs,
  candidates: string[],
  code: "protected" | "unverifiable" = "protected",
  note = "",
  previous?: ProtectedSet,
): void {
  const r = refusal(input, candidates, previous);
  assertEquals(
    r.code,
    code,
    `${note} ${r.message} ${JSON.stringify(r.detail)}`,
  );
}

function safe(input: ProbeInputs, candidates: string[]) {
  const result = assess(withExamine(input, candidates), candidates);
  assert(result.ok, result.ok ? "" : JSON.stringify(result.refusal));
  return result.set;
}

// --- baseline ---------------------------------------------------------------

Deno.test("an unrelated raw disk is allowed on a plain host", () => {
  const set = safe(plain(), ["/dev/sdb"]);
  assertEquals(Object.keys(set.devices).sort(), [
    "/dev/sda",
    "/dev/sda1",
    "/dev/sda2",
  ]);
});

// --- case 1: / ---------------------------------------------------------------

Deno.test("1a root on a plain partition protects the whole disk", () => {
  const r = refusal(plain(), ["/dev/sda"]);
  assertEquals(r.code, "protected");
  assert(JSON.stringify(r.detail).includes("/"));
});

Deno.test("1b root on md RAID1 protects every member disk", () => {
  const input = plain({
    lsblk: lsblk(
      {
        name: "sda",
        type: "disk",
        children: [{
          name: "sda1",
          type: "part",
          fstype: "linux_raid_member",
          uuid: ARRAY_UUID.replaceAll(":", "-"),
          children: [{
            name: "md0",
            type: "raid1",
            fstype: "ext4",
            mounts: ["/"],
          }],
        }],
      },
      {
        name: "sdb",
        type: "disk",
        children: [{
          name: "sdb1",
          type: "part",
          fstype: "linux_raid_member",
          uuid: ARRAY_UUID.replaceAll(":", "-"),
          children: [{
            name: "md0",
            type: "raid1",
            fstype: "ext4",
            mounts: ["/"],
          }],
        }],
      },
      { name: "sdc", type: "disk" },
    ),
    findmnt: findmnt({ target: "/", source: "/dev/md0", fstype: "ext4" }),
    fstab: file("/dev/md0 / ext4 defaults 0 1\n"),
    mdstat: file("md0 : active raid1 sdb1[1] sda1[0]\n"),
    mdExamine: {
      "/dev/sda1": ok(examineOut(ARRAY_UUID)),
      "/dev/sdb1": ok(examineOut(ARRAY_UUID)),
    },
  });
  refused(input, ["/dev/sda"], "protected");
  refused(input, ["/dev/sdb"], "protected");
  safe(input, ["/dev/sdc"]);
});

Deno.test("1c root on LVM directly on the disk, and every PV of its VG", () => {
  const root: Dev = {
    name: "vg0-root",
    type: "lvm",
    fstype: "ext4",
    mounts: ["/"],
  };
  const input = plain({
    lsblk: lsblk(
      {
        name: "sda",
        type: "disk",
        children: [{
          name: "sda1",
          type: "part",
          fstype: "LVM2_member",
          children: [root],
        }],
      },
      {
        name: "sdb",
        type: "disk",
        fstype: "LVM2_member",
      },
      { name: "sdc", type: "disk" },
    ),
    findmnt: findmnt({
      target: "/",
      source: "/dev/mapper/vg0-root",
      fstype: "ext4",
    }),
    fstab: file("/dev/mapper/vg0-root / ext4 defaults 0 1\n"),
    pvs: ok("  /dev/sda1  vg0\n  /dev/sdb   vg0\n"),
    links: ok("/dev/mapper/vg0-root /dev/dm-0\n"),
  });
  refused(input, ["/dev/sda"], "protected");
  // sdb is a PV of the same volume group: wiping it would break the root LV.
  const r = refusal(input, ["/dev/sdb"]);
  assertEquals(r.code, "protected");
  safe(input, ["/dev/sdc"]);
});

Deno.test("1d root on LVM on md protects the md members", () => {
  const input = plain({
    lsblk: lsblk(
      {
        name: "sda",
        type: "disk",
        children: [{
          name: "sda1",
          type: "part",
          fstype: "linux_raid_member",
          children: [{
            name: "md1",
            type: "raid1",
            fstype: "LVM2_member",
            children: [{
              name: "vg0-root",
              type: "lvm",
              fstype: "ext4",
              mounts: ["/"],
            }],
          }],
        }],
      },
      {
        name: "sdb",
        type: "disk",
        children: [{
          name: "sdb1",
          type: "part",
          fstype: "linux_raid_member",
          children: [{
            name: "md1",
            type: "raid1",
            fstype: "LVM2_member",
            children: [{
              name: "vg0-root",
              type: "lvm",
              fstype: "ext4",
              mounts: ["/"],
            }],
          }],
        }],
      },
      { name: "sdc", type: "disk" },
    ),
    findmnt: findmnt({
      target: "/",
      source: "/dev/mapper/vg0-root",
      fstype: "ext4",
    }),
    fstab: file("/dev/mapper/vg0-root / ext4 defaults 0 1\n"),
    mdstat: file("md1 : active raid1 sdb1[1] sda1[0]\n"),
    pvs: ok("  /dev/md1  vg0\n"),
    links: ok("/dev/mapper/vg0-root /dev/dm-0\n"),
    mdExamine: {
      "/dev/sda1": ok(examineOut(ARRAY_UUID)),
      "/dev/sdb1": ok(examineOut(ARRAY_UUID)),
    },
  });
  refused(input, ["/dev/sda"], "protected");
  refused(input, ["/dev/sdb"], "protected");
  safe(input, ["/dev/sdc"]);
});

Deno.test("1e root on dm-crypt over a partition", () => {
  const input = plain({
    lsblk: lsblk(
      {
        name: "sda",
        type: "disk",
        children: [{
          name: "sda2",
          type: "part",
          fstype: "crypto_LUKS",
          children: [{
            name: "cryptroot",
            type: "crypt",
            fstype: "ext4",
            mounts: ["/"],
          }],
        }],
      },
      { name: "sdb", type: "disk" },
    ),
    findmnt: findmnt({
      target: "/",
      source: "/dev/mapper/cryptroot",
      fstype: "ext4",
    }),
    fstab: file("/dev/mapper/cryptroot / ext4 defaults 0 1\n"),
    links: ok("/dev/mapper/cryptroot /dev/dm-0\n"),
  });
  refused(input, ["/dev/sda"], "protected");
  safe(input, ["/dev/sdb"]);
});

Deno.test("1f ZFS root pool with by-id vdevs resolves to the real disks", () => {
  const input = plain({
    lsblk: lsblk(
      {
        name: "sda",
        type: "disk",
        children: [
          {
            name: "sda1",
            type: "part",
            fstype: "vfat",
            uuid: "ABCD-1234",
            mounts: ["/boot/efi"],
          },
          {
            name: "sda3",
            type: "part",
            fstype: "zfs_member",
            label: "rpool",
          },
        ],
      },
      {
        name: "sdb",
        type: "disk",
        children: [{
          name: "sdb3",
          type: "part",
          fstype: "zfs_member",
          label: "rpool",
        }],
      },
      { name: "sdc", type: "disk" },
      {
        name: "sdd",
        type: "disk",
        children: [{
          name: "sdd1",
          type: "part",
          fstype: "zfs_member",
          label: "tank",
        }],
      },
    ),
    findmnt: findmnt(
      { target: "/", source: "rpool/ROOT/debian", fstype: "zfs" },
      { target: "/boot/efi", source: "/dev/sda1", fstype: "vfat" },
    ),
    fstab: file("UUID=ABCD-1234 /boot/efi vfat umask=0077 0 1\n"),
    links: ok(
      "/dev/disk/by-id/ata-EXAMPLE_A-part3 /dev/sda3\n" +
        "/dev/disk/by-id/ata-EXAMPLE_B-part3 /dev/sdb3\n",
    ),
    zpool: ok(
      "  pool: rpool\n state: ONLINE\nconfig:\n\n" +
        "\tNAME                                  STATE     READ WRITE CKSUM\n" +
        "\trpool                                 ONLINE       0     0     0\n" +
        "\t  mirror-0                            ONLINE       0     0     0\n" +
        "\t    /dev/disk/by-id/ata-EXAMPLE_A-part3  ONLINE       0     0     0\n" +
        "\t    /dev/disk/by-id/ata-EXAMPLE_B-part3  ONLINE       0     0     0\n\n" +
        "errors: No known data errors\n\n" +
        "  pool: tank\n state: ONLINE\nconfig:\n\n" +
        "\tNAME        STATE     READ WRITE CKSUM\n" +
        "\ttank        ONLINE       0     0     0\n" +
        "\t  /dev/sdd1  ONLINE       0     0     0\n\nerrors: No known data errors\n",
    ),
  });
  refused(input, ["/dev/sda"], "protected");
  refused(input, ["/dev/sdb"], "protected");
  safe(input, ["/dev/sdc"]);
  // The data pool is not behind a mount, so its disk may be wiped.
  safe(input, ["/dev/sdd"]);
});

// --- case 2: /boot, /boot/efi --------------------------------------------------

Deno.test("2 /boot on its own disk protects that disk", () => {
  const input = plain({
    lsblk: lsblk(
      {
        name: "sda",
        type: "disk",
        children: [{
          name: "sda1",
          type: "part",
          fstype: "ext4",
          mounts: ["/"],
        }],
      },
      {
        name: "sdb",
        type: "disk",
        children: [{
          name: "sdb1",
          type: "part",
          fstype: "ext4",
          mounts: ["/boot"],
        }],
      },
      {
        name: "nvme0n1",
        type: "disk",
        children: [{
          name: "nvme0n1p1",
          type: "part",
          fstype: "vfat",
          mounts: ["/boot/efi"],
        }],
      },
      { name: "sdc", type: "disk" },
    ),
    findmnt: findmnt(
      { target: "/", source: "/dev/sda1", fstype: "ext4" },
      { target: "/boot", source: "/dev/sdb1", fstype: "ext4" },
      { target: "/boot/efi", source: "/dev/nvme0n1p1", fstype: "vfat" },
    ),
    fstab: file(""),
  });
  refused(input, ["/dev/sdb"], "protected");
  refused(input, ["/dev/nvme0n1"], "protected");
  safe(input, ["/dev/sdc"]);
});

// --- case 3: fstab and swap ---------------------------------------------------

function withExtraDisk(): Dev[] {
  return [
    {
      name: "sda",
      type: "disk",
      children: [
        {
          name: "sda1",
          type: "part",
          fstype: "vfat",
          uuid: "ABCD-1234",
          mounts: ["/boot/efi"],
        },
        {
          name: "sda2",
          type: "part",
          fstype: "ext4",
          uuid: "11111111-2222-3333-4444-555555555555",
          mounts: ["/"],
        },
      ],
    },
    {
      name: "sdb",
      type: "disk",
      children: [{
        name: "sdb1",
        type: "part",
        fstype: "ext4",
        uuid: "22222222-3333-4444-5555-666666666666",
        partuuid: "aaaaaaaa-01",
        label: "scratch",
      }],
    },
    {
      name: "sdc",
      type: "disk",
      children: [{
        name: "sdc1",
        type: "part",
        fstype: "swap",
        uuid: "33333333-4444-5555-6666-777777777777",
      }],
    },
    { name: "sdd", type: "disk" },
  ];
}

Deno.test("3a an unmounted fstab entry (UUID=) protects its disk", () => {
  const input = plain({
    lsblk: lsblk(...withExtraDisk()),
    fstab: file(
      plainFstab() +
        "UUID=22222222-3333-4444-5555-666666666666 /var/lib/data ext4 noauto 0 2\n",
    ),
  });
  refused(input, ["/dev/sdb"], "protected");
  safe(input, ["/dev/sdd"]);
});

function plainFstab(): string {
  return "UUID=11111111-2222-3333-4444-555555555555 / ext4 defaults 0 1\n" +
    "UUID=ABCD-1234 /boot/efi vfat umask=0077 0 1\n";
}

Deno.test("3b fstab LABEL= and PARTUUID= entries resolve and protect", () => {
  for (const spec of ["LABEL=scratch", "PARTUUID=aaaaaaaa-01"]) {
    const input = plain({
      lsblk: lsblk(...withExtraDisk()),
      fstab: file(plainFstab() + `${spec} /srv ext4 nofail 0 2\n`),
    });
    refused(input, ["/dev/sdb"], "protected", spec);
  }
});

Deno.test("3c an inactive fstab swap (UUID=) protects its disk", () => {
  const input = plain({
    lsblk: lsblk(...withExtraDisk()),
    fstab: file(
      plainFstab() +
        "UUID=33333333-4444-5555-6666-777777777777 none swap sw 0 0\n",
    ),
  });
  refused(input, ["/dev/sdc"], "protected");
});

Deno.test("3d active swap that is not in fstab protects its disk", () => {
  const input = plain({
    lsblk: lsblk(...withExtraDisk()),
    swaps: file(
      SWAP_HEADER + "/dev/sdc1\t\t\t\tpartition\t1048572\t\t0\t\t-2\n",
    ),
  });
  refused(input, ["/dev/sdc"], "protected");
});

Deno.test("3e non-block fstab sources are ignored, odd ones are not", () => {
  const base = plain({ lsblk: lsblk(...withExtraDisk()) });
  safe(
    {
      ...base,
      fstab: file(
        plainFstab() +
          "tmpfs /tmp tmpfs defaults 0 0\n" +
          "nas.example.com:/export /mnt nfs defaults 0 0\n" +
          "/srv/data /mnt/data none bind 0 0\n" +
          "/swapfile none swap sw 0 0\n",
      ),
    },
    ["/dev/sdd"],
  );
  const weird = refusal({
    ...base,
    fstab: file(plainFstab() + "mystery /mnt ext4 defaults 0 0\n"),
  }, ["/dev/sdd"]);
  assertEquals(weird.code, "unverifiable");
});

// --- case 4: md members, including inactive and dropped ------------------------

function raidHost(extra: Partial<ProbeInputs> = {}): ProbeInputs {
  const member = (name: string): Dev => ({
    name,
    type: "part",
    fstype: "linux_raid_member",
    uuid: ARRAY_UUID.replaceAll(":", "-"),
    children: [{ name: "md0", type: "raid1", fstype: "ext4", mounts: ["/"] }],
  });
  return plain({
    lsblk: lsblk(
      { name: "sda", type: "disk", children: [member("sda1")] },
      { name: "sdb", type: "disk", children: [member("sdb1")] },
      {
        name: "sdc",
        type: "disk",
        children: [{
          name: "sdc1",
          type: "part",
          fstype: "linux_raid_member",
          uuid: ARRAY_UUID.replaceAll(":", "-"),
        }],
      },
      { name: "sdd", type: "disk" },
    ),
    findmnt: findmnt({ target: "/", source: "/dev/md0", fstype: "ext4" }),
    fstab: file("/dev/md0 / ext4 defaults 0 1\n"),
    mdstat: file("md0 : active raid1 sdb1[1] sda1[0]\n"),
    mdExamine: {
      "/dev/sda1": ok(examineOut(ARRAY_UUID)),
      "/dev/sdb1": ok(examineOut(ARRAY_UUID)),
      "/dev/sdc1": ok(examineOut(ARRAY_UUID)),
      "/dev/sdc": NO_SB,
      "/dev/sdd": NO_SB,
    },
    ...extra,
  });
}

Deno.test("4a a dropped member that is not in mdstat is matched by array UUID", () => {
  const input = raidHost();
  const r = refusal(input, ["/dev/sdc"]);
  assertEquals(r.code, "protected");
  safe(input, ["/dev/sdd"]);
});

Deno.test("4b a faulty member with several flag groups is protected by mdstat", () => {
  const input = raidHost({
    lsblk: lsblk(
      {
        name: "sda",
        type: "disk",
        children: [{
          name: "sda1",
          type: "part",
          fstype: "linux_raid_member",
          children: [{
            name: "md0",
            type: "raid1",
            fstype: "ext4",
            mounts: ["/"],
          }],
        }],
      },
      {
        name: "sdc",
        type: "disk",
        children: [{ name: "sdc1", type: "part", fstype: "linux_raid_member" }],
      },
      { name: "sdd", type: "disk" },
    ),
    mdstat: file("md0 : active raid1 sdc1[2](W)(F) sda1[0]\n"),
    mdExamine: {
      "/dev/sda1": ok(examineOut(ARRAY_UUID)),
      "/dev/sdc1": ok(examineOut(ARRAY_UUID)),
      "/dev/sdc": NO_SB,
      "/dev/sdd": NO_SB,
    },
  });
  refused(input, ["/dev/sdc"], "protected");
  safe(input, ["/dev/sdd"]);
});

Deno.test("4c an inactive array named only in fstab and mdstat", () => {
  const input = plain({
    lsblk: lsblk(
      {
        name: "sda",
        type: "disk",
        children: [{
          name: "sda1",
          type: "part",
          fstype: "linux_raid_member",
          uuid: ARRAY_UUID.replaceAll(":", "-"),
        }],
      },
      {
        name: "sdb",
        type: "disk",
        children: [{
          name: "sdb1",
          type: "part",
          fstype: "linux_raid_member",
          uuid: ARRAY_UUID.replaceAll(":", "-"),
        }],
      },
      { name: "sdc", type: "disk" },
      {
        name: "sde",
        type: "disk",
        children: [{
          name: "sde1",
          type: "part",
          fstype: "ext4",
          mounts: ["/"],
        }],
      },
    ),
    findmnt: findmnt({ target: "/", source: "/dev/sde1", fstype: "ext4" }),
    fstab: file(
      "/dev/sde1 / ext4 defaults 0 1\n/dev/md0 /data ext4 nofail 0 2\n",
    ),
    mdstat: file("md0 : inactive sdb1[1](S) sda1[0](S)\n"),
    mdExamine: {
      "/dev/sda1": ok(examineOut(ARRAY_UUID)),
      "/dev/sdb1": ok(examineOut(ARRAY_UUID)),
      "/dev/sdc": NO_SB,
    },
  });
  refused(input, ["/dev/sda"], "protected");
  refused(input, ["/dev/sdb"], "protected");
  safe(input, ["/dev/sdc"]);
});

Deno.test("4d an md array named in fstab but nowhere else is unverifiable", () => {
  const input = plain({
    fstab: file(plainFstab() + "/dev/md9 /data ext4 nofail 0 2\n"),
  });
  refused(input, ["/dev/sdb"], "unverifiable");
});

// --- case 5: symlinks and udev-less hosts -----------------------------------

Deno.test("5a fstab by-id / by-path sources resolve through the link table", () => {
  for (
    const link of [
      "/dev/disk/by-id/ata-EXAMPLE_DISK-part1",
      "/dev/disk/by-path/pci-0000:00:1f.2-ata-1-part1",
    ]
  ) {
    const input = plain({
      lsblk: lsblk(...withExtraDisk()),
      fstab: file(plainFstab() + `${link} /srv ext4 nofail 0 2\n`),
      links: ok(`${link} /dev/sdb1\n`),
    });
    refused(input, ["/dev/sdb"], "protected", link);
  }
});

Deno.test("5b a source that resolves nowhere fails closed", () => {
  const input = plain({
    fstab: file(
      plainFstab() + "/dev/disk/by-id/ata-GONE-part1 /srv ext4 nofail 0 2\n",
    ),
  });
  refused(input, ["/dev/sdb"], "unverifiable");
});

Deno.test("5c a UUID that lsblk cannot see is resolved by blkid, else refused", () => {
  const rows: Dev[] = withExtraDisk().map((d) => ({
    ...d,
    children: d.children?.map((c) => ({
      ...c,
      uuid: undefined,
      label: undefined,
      partuuid: undefined,
    })),
  }));
  const fstab = file(
    "/dev/sda2 / ext4 defaults 0 1\n" +
      "UUID=22222222-3333-4444-5555-666666666666 /srv ext4 nofail 0 2\n",
  );
  const base = plain({
    lsblk: lsblk(...rows),
    findmnt: findmnt({ target: "/", source: "/dev/sda2", fstype: "ext4" }),
    fstab,
  });
  refused(base, ["/dev/sdd"], "unverifiable");
  const withBlkid = {
    ...base,
    blkid: ok(
      '/dev/sdb1: UUID="22222222-3333-4444-5555-666666666666" TYPE="ext4"\n',
    ),
  };
  refused(withBlkid, ["/dev/sdb"], "protected");
  safe(withBlkid, ["/dev/sdd"]);
});

// --- case 6: multi-parent devices -------------------------------------------

Deno.test("6 an LV that spans two disks protects both parents", () => {
  const spanning: Dev = {
    name: "vg1-data",
    type: "lvm",
    fstype: "xfs",
    mounts: ["/srv"],
  };
  const input = plain({
    lsblk: lsblk(
      {
        name: "sda",
        type: "disk",
        children: [{
          name: "sda1",
          type: "part",
          fstype: "ext4",
          mounts: ["/"],
        }],
      },
      {
        name: "sdb",
        type: "disk",
        fstype: "LVM2_member",
        children: [spanning],
      },
      {
        name: "sdc",
        type: "disk",
        fstype: "LVM2_member",
        children: [spanning],
      },
      { name: "sdd", type: "disk" },
    ),
    findmnt: findmnt(
      { target: "/", source: "/dev/sda1", fstype: "ext4" },
      { target: "/srv", source: "/dev/mapper/vg1-data", fstype: "xfs" },
    ),
    fstab: file("/dev/sda1 / ext4 defaults 0 1\n"),
    links: ok("/dev/mapper/vg1-data /dev/dm-3\n"),
    pvs: ok("  /dev/sdb  vg1\n  /dev/sdc  vg1\n"),
  });
  refused(input, ["/dev/sdb"], "protected");
  refused(input, ["/dev/sdc"], "protected");
  safe(input, ["/dev/sdd"]);
});

// --- case 7: member fstypes ---------------------------------------------------

Deno.test("7 a zfs_member labelled with a protected pool is protected without a vdev name", () => {
  const input = plain({
    lsblk: lsblk(
      {
        name: "sda",
        type: "disk",
        children: [{
          name: "sda3",
          type: "part",
          fstype: "zfs_member",
          label: "rpool",
        }],
      },
      {
        name: "sdb",
        type: "disk",
        children: [{
          name: "sdb3",
          type: "part",
          fstype: "zfs_member",
          label: "rpool",
        }],
      },
      { name: "sdc", type: "disk" },
    ),
    findmnt: findmnt({
      target: "/",
      source: "rpool/ROOT/debian",
      fstype: "zfs",
    }),
    fstab: file(""),
    zpool: ok(
      "  pool: rpool\nconfig:\n\n\tNAME  STATE\n\trpool  ONLINE\n\t  /dev/sda3  ONLINE\n\nerrors: none\n",
    ),
  });
  refused(input, ["/dev/sda"], "protected");
  refused(input, ["/dev/sdb"], "protected");
  safe(input, ["/dev/sdc"]);
});

// --- case 8: fail closed ------------------------------------------------------

Deno.test("8 every probe failure refuses and none degrades to protecting nothing", () => {
  const good = plain();
  const bad: [string, Partial<ProbeInputs>][] = [
    ["lsblk exit", { lsblk: NO_SB }],
    ["lsblk empty", { lsblk: ok("") }],
    ["lsblk json", { lsblk: ok("not json") }],
    ["lsblk no devices", { lsblk: ok('{"blockdevices":[]}') }],
    ["findmnt exit", { findmnt: NO_SB }],
    ["findmnt empty", { findmnt: ok("") }],
    ["findmnt json", { findmnt: ok("{") }],
    ["findmnt no root", {
      findmnt: findmnt({
        target: "/boot/efi",
        source: "/dev/sda1",
        fstype: "vfat",
      }),
    }],
    ["findmnt root without source", {
      findmnt: findmnt({ target: "/", source: "", fstype: "ext4" }),
    }],
    ["fstab error", { fstab: { state: "error", detail: "EIO" } }],
    ["swaps error", { swaps: { state: "error" } }],
    ["swaps absent", { swaps: { state: "absent" } }],
    ["mdstat error", { mdstat: { state: "error" } }],
    ["links exit", { links: NO_SB }],
  ];
  for (const [name, patch] of bad) {
    const r = refusal({ ...good, ...patch }, ["/dev/sdb"]);
    assertEquals(r.code, "unverifiable", name);
  }
});

Deno.test("8b mdadm, zpool and pvs errors refuse where they matter", () => {
  const raid = raidHost();
  refused(
    {
      ...raid,
      mdExamine: { ...raid.mdExamine, "/dev/sda1": NO_SB },
    },
    ["/dev/sdd"],
    "unverifiable",
  );
  refused(
    {
      ...raid,
      mdExamine: { ...raid.mdExamine, "/dev/sda1": ok("garbage") },
    },
    ["/dev/sdd"],
    "unverifiable",
  );
  const missingProbe = { ...raid.mdExamine };
  delete missingProbe["/dev/sda1"];
  refused({ ...raid, mdExamine: missingProbe }, ["/dev/sdd"], "unverifiable");

  const zfs = plain({
    findmnt: findmnt({
      target: "/",
      source: "rpool/ROOT/debian",
      fstype: "zfs",
    }),
    fstab: file(""),
  });
  for (const zpool of [NO_SB, missing, ok("")]) {
    refused({ ...zfs, zpool }, ["/dev/sdb"], "unverifiable");
  }

  const lvm = plain({
    lsblk: lsblk(
      {
        name: "sda",
        type: "disk",
        children: [{
          name: "sda1",
          type: "part",
          fstype: "LVM2_member",
          children: [{
            name: "vg0-root",
            type: "lvm",
            fstype: "ext4",
            mounts: ["/"],
          }],
        }],
      },
      { name: "sdb", type: "disk" },
    ),
    findmnt: findmnt({
      target: "/",
      source: "/dev/mapper/vg0-root",
      fstype: "ext4",
    }),
    fstab: file(""),
    links: ok("/dev/mapper/vg0-root /dev/dm-0\n"),
  });
  for (const pvs of [NO_SB, missing, ok("")]) {
    refused({ ...lvm, pvs }, ["/dev/sdb"], "unverifiable");
  }
});

Deno.test("8c file reads: absent is allowed only where it is meaningful", () => {
  safe(plain({ fstab: { state: "absent" } }), ["/dev/sdb"]);
  safe(plain({ mdstat: { state: "absent" } }), ["/dev/sdb"]);
  // md devices exist, so a missing /proc/mdstat is a contradiction.
  const raid = raidHost({ mdstat: { state: "absent" } });
  refused(raid, ["/dev/sdd"], "unverifiable");
});

Deno.test("8d a candidate that lsblk does not list is unverifiable", () => {
  refused(plain(), ["/dev/sdz"], "unverifiable");
  refused(plain(), [], "unverifiable");
});

// --- case 9: the set survives re-reads ------------------------------------------

Deno.test("9 the protected set is never smaller after a re-read", () => {
  const first = safe(plain(), ["/dev/sdb"]);
  // A later read in which the root disk looks unremarkable still keeps it.
  const reread = plain({
    lsblk: lsblk(
      { name: "sda", type: "disk" },
      { name: "sdb", type: "disk", fstype: "ext4", mounts: ["/"] },
      { name: "sdc", type: "disk" },
    ),
    findmnt: findmnt({ target: "/", source: "/dev/sdb", fstype: "ext4" }),
    fstab: file(""),
  });
  const r = refusal(reread, ["/dev/sda"], first);
  assertEquals(r.code, "protected");
  const merged = unionProtected(first, safe(reread, ["/dev/sdc"]));
  assert("/dev/sda2" in merged.devices && "/dev/sdb" in merged.devices);
});

// --- helpers ------------------------------------------------------------------

Deno.test("examineTargets lists members and the candidates' partitions", () => {
  const input = raidHost();
  const targets = examineTargets(input, ["/dev/sdd"]);
  assertEquals(targets, [
    "/dev/sda1",
    "/dev/sdb1",
    "/dev/sdc1",
    "/dev/sdd",
  ]);
  assertEquals(
    examineTargets({ ...input, lsblk: NO_SB }, ["/dev/sdd"]),
    [],
  );
});

Deno.test("parsers", () => {
  assertEquals(
    parseMdstat(
      "Personalities : [raid1]\nmd0 : active raid1 sdc1[2](W)(F) sdb1[1](S) nvme0n1p2[0]\n      1048576 blocks\nmd127 : inactive sdd[1](S)\n",
    ),
    [
      { name: "md0", members: ["sdc1", "sdb1", "nvme0n1p2"] },
      { name: "md127", members: ["sdd"] },
    ],
  );
  assertEquals(
    normalizeUuid("7A0D6E3F:11112222:33334444:55556666"),
    normalizeUuid("7a0d6e3f-1111-2222-3333-444455556666"),
  );
  assertEquals(
    parseExamineUuid("   Device UUID : zzzz\n     Array UUID : 7a0d:6e3f\n"),
    "7a0d6e3f",
  );
  assertEquals(parseExamineUuid("mdadm: No md superblock detected"), null);
  assertEquals(volumeGroupOf("vg--a-root--lv"), "vg-a");
  assertEquals(volumeGroupOf("plain"), null);
  assertEquals(
    [...parseZpoolStatus(
      "  pool: p\nconfig:\n\n\tNAME  STATE\n\tp  ONLINE\n\t  mirror-0  ONLINE\n\t    /dev/sda3  ONLINE\n\t    /dev/sdb3  ONLINE\n\t  logs\n\t    /dev/sdc1  ONLINE\n\nerrors: none\n",
    )],
    [["p", ["/dev/sda3", "/dev/sdb3", "/dev/sdc1"]]],
  );
});

Deno.test("fixtures use only synthetic names", async () => {
  const src = await Deno.readTextFile(
    new URL("./protected_devices_test.ts", import.meta.url),
  );
  assert(
    !/\b(?:\d{1,3}\.){3}\d{1,3}\b/.test(src.replace(/\b192\.0\.2\.\d+\b/g, "")),
  );
});

Deno.test("10 a btrfs root spanning two disks protects both", () => {
  const btrfs = (name: string, mounts: string[] | undefined) => ({
    name,
    type: "part",
    fstype: "btrfs",
    uuid: "99999999-8888-7777-6666-555555555555",
    mounts,
  });
  const input = plain({
    lsblk: lsblk(
      { name: "sda", type: "disk", children: [btrfs("sda2", ["/"])] },
      { name: "sdb", type: "disk", children: [btrfs("sdb2", undefined)] },
      { name: "sdc", type: "disk" },
    ),
    findmnt: findmnt({ target: "/", source: "/dev/sda2[/@]", fstype: "btrfs" }),
    fstab: file(""),
  });
  refused(input, ["/dev/sdb"], "protected");
  safe(input, ["/dev/sdc"]);
});

Deno.test("11 an mdadm examine that fails for any reason but 'not a member' refuses", () => {
  for (
    const probe of [
      { code: 127, stdout: "" },
      { code: 1, stdout: "mdadm: cannot open /dev/sdd: Permission denied" },
      { code: 2, stdout: "" },
    ]
  ) {
    const input = raidHost();
    input.mdExamine["/dev/sdd"] = probe;
    refused(input, ["/dev/sdd"], "unverifiable", `exit ${probe.code}`);
  }
});

// --- round 2: hosts without udev, links, stderr, fixpoint -----------------------

/** lsblk rows as an unprivileged or udev-less host prints them: no types, no UUIDs. */
function bare(...devs: Dev[]): CommandProbe {
  const strip = (d: Dev): Dev => ({
    name: d.name,
    type: d.type,
    mounts: d.mounts,
    children: d.children?.map(strip),
  });
  return lsblk(...devs.map(strip));
}

const BTRFS_UUID = "99999999-8888-7777-6666-555555555555";
const btrfsDevs = (): Dev[] => [
  {
    name: "sda",
    type: "disk",
    children: [{
      name: "sda2",
      type: "part",
      fstype: "btrfs",
      uuid: BTRFS_UUID,
      mounts: ["/"],
    }],
  },
  {
    name: "sdb",
    type: "disk",
    children: [{
      name: "sdb2",
      type: "part",
      fstype: "btrfs",
      uuid: BTRFS_UUID,
    }],
  },
  { name: "sdc", type: "disk" },
];
const btrfsBlkid = ok(
  `/dev/sda2: UUID="${BTRFS_UUID}" UUID_SUB="aaaa" TYPE="btrfs"\n` +
    `/dev/sdb2: UUID="${BTRFS_UUID}" UUID_SUB="bbbb" TYPE="btrfs"\n`,
);

Deno.test("12a udev-less btrfs root: blkid fills the empty columns, so the sibling is protected", () => {
  const input = plain({
    lsblk: bare(...btrfsDevs()),
    findmnt: findmnt({ target: "/", source: "/dev/sda2[/@]", fstype: "btrfs" }),
    fstab: file(""),
    blkid: btrfsBlkid,
  });
  refused(input, ["/dev/sdb"], "protected");
  safe(input, ["/dev/sdc"]);
});

Deno.test("12b udev-less and no blkid: the missing filesystem type refuses", () => {
  const input = plain({
    lsblk: bare(...btrfsDevs()),
    findmnt: findmnt({ target: "/", source: "/dev/sda2", fstype: "btrfs" }),
    fstab: file(""),
    blkid: missing,
  });
  // Neither candidate may be wiped: the mounted root has no known type.
  refused(input, ["/dev/sdb"], "unverifiable");
  refused(input, ["/dev/sdc"], "unverifiable");
  // The same when blkid runs but knows nothing.
  refused(
    { ...input, blkid: { code: 2, stdout: "" } },
    ["/dev/sdc"],
    "unverifiable",
  );
});

Deno.test("13a udev-less dropped array member: blkid and the examine UUID both find it", () => {
  const md = (name: string): Dev => ({
    name,
    type: "part",
    children: [{ name: "md0", type: "raid1", mounts: ["/"] }],
  });
  const lsblkOut = bare(
    { name: "sda", type: "disk", children: [md("sda1")] },
    { name: "sdb", type: "disk", children: [md("sdb1")] },
    { name: "sdc", type: "disk", children: [{ name: "sdc1", type: "part" }] },
    { name: "sdd", type: "disk" },
  );
  const u = ARRAY_UUID.replaceAll(":", "-");
  const input = plain({
    lsblk: lsblkOut,
    findmnt: findmnt({ target: "/", source: "/dev/md0", fstype: "ext4" }),
    fstab: file("/dev/md0 / ext4 defaults 0 1\n"),
    mdstat: file("md0 : active raid1 sdb1[1] sda1[0]\n"),
    blkid: ok(
      `/dev/sda1: UUID="${u}" TYPE="linux_raid_member"\n` +
        `/dev/sdb1: UUID="${u}" TYPE="linux_raid_member"\n` +
        `/dev/sdc1: UUID="${u}" TYPE="linux_raid_member"\n` +
        `/dev/md0: UUID="11111111-2222-3333-4444-555555555555" TYPE="ext4"\n`,
    ),
    mdExamine: {
      "/dev/sda1": ok(examineOut(ARRAY_UUID)),
      "/dev/sdb1": ok(examineOut(ARRAY_UUID)),
      "/dev/sdc1": ok(examineOut(ARRAY_UUID)),
    },
  });
  refused(input, ["/dev/sdc"], "protected");
  safe(input, ["/dev/sdd"]);
  // Without blkid the same host cannot be judged, so it refuses everything.
  refused({ ...input, blkid: missing }, ["/dev/sdd"], "unverifiable");
});

Deno.test("13b the examine UUID alone finds a dropped member when types are known", () => {
  const input = raidHost();
  // Drop the lsblk type of the dropped member: only mdadm still knows it.
  input.lsblk = lsblk(
    {
      name: "sda",
      type: "disk",
      children: [{
        name: "sda1",
        type: "part",
        fstype: "linux_raid_member",
        children: [{
          name: "md0",
          type: "raid1",
          fstype: "ext4",
          mounts: ["/"],
        }],
      }],
    },
    { name: "sdc", type: "disk", children: [{ name: "sdc1", type: "part" }] },
    { name: "sdd", type: "disk" },
  );
  input.mdstat = file("md0 : active raid1 sda1[0]\n");
  refused(input, ["/dev/sdc"], "protected");
});

Deno.test("14 a by-id or by-path candidate is resolved and examined", () => {
  const input = raidHost({
    links: ok(
      "/dev/disk/by-id/ata-EXAMPLE_D /dev/sdd\n/dev/disk/by-id/ata-EXAMPLE_C /dev/sdc\n",
    ),
  });
  assert(
    examineTargets(input, ["/dev/disk/by-id/ata-EXAMPLE_D"]).includes(
      "/dev/sdd",
    ),
  );
  safe(input, ["/dev/disk/by-id/ata-EXAMPLE_D"]);
  // The dropped member reached through its by-id name is still refused.
  refused(input, ["/dev/disk/by-id/ata-EXAMPLE_C"], "protected");
  // A candidate that was never examined cannot be judged.
  const unexamined = { ...input, mdExamine: { ...input.mdExamine } };
  delete unexamined.mdExamine["/dev/sdd"];
  const bare = assess(unexamined, ["/dev/sdd"]);
  assert(!bare.ok && bare.refusal.code === "unverifiable");
});

Deno.test("15 mdadm's 'not a member' answer is accepted on stderr or stdout", () => {
  const onStdout: CommandProbe = {
    code: 1,
    stdout: "mdadm: No md superblock detected on /dev/x.\n",
  };
  for (const probe of [NO_SB, onStdout]) {
    const input = raidHost();
    input.mdExamine["/dev/sdd"] = probe;
    safe(input, ["/dev/sdd"]);
  }
});

Deno.test("16 a protected ZFS volume protects its pool; an unmapped one refuses", () => {
  const input = plain({
    findmnt: findmnt({ target: "/", source: "/dev/sda1", fstype: "ext4" }),
    fstab: file(""),
    lsblk: lsblk(
      {
        name: "sda",
        type: "disk",
        children: [
          { name: "sda1", type: "part", fstype: "ext4", mounts: ["/"] },
          { name: "sda3", type: "part", fstype: "zfs_member", label: "tank" },
        ],
      },
      { name: "zd0", type: "disk", fstype: "swap" },
      {
        name: "sdb",
        type: "disk",
        children: [{
          name: "sdb1",
          type: "part",
          fstype: "zfs_member",
          label: "tank",
        }],
      },
      { name: "sdc", type: "disk" },
    ),
    swaps: file(
      SWAP_HEADER +
        "/dev/zd0\\t\\t\\t\\tpartition\\t1048572\\t0\\t-2\\n".replaceAll(
          "\\t",
          "\t",
        ),
    ),
    links: ok("/dev/zvol/tank/swap /dev/zd0\\n".replaceAll("\\n", "\n")),
    zpool: ok(
      "  pool: tank\nconfig:\n\n\tNAME  STATE\n\ttank  ONLINE\n\t  /dev/sda3  ONLINE\n\t  /dev/sdb1  ONLINE\n\nerrors: none\n",
    ),
  });
  refused(input, ["/dev/sdb"], "protected");
  safe(input, ["/dev/sdc"]);
  refused({ ...input, links: ok("") }, ["/dev/sdc"], "unverifiable");
});

Deno.test("17 expansion repeats: an md PV added by LVM protects its own dropped member", () => {
  const u = ARRAY_UUID.replaceAll(":", "-");
  const member = (name: string, kids?: Dev[]): Dev => ({
    name,
    type: "part",
    fstype: "linux_raid_member",
    uuid: u,
    children: kids,
  });
  const input = plain({
    lsblk: lsblk(
      {
        name: "sda",
        type: "disk",
        children: [{
          name: "sda1",
          type: "part",
          fstype: "LVM2_member",
          children: [{
            name: "vg0-root",
            type: "lvm",
            fstype: "ext4",
            mounts: ["/"],
          }],
        }],
      },
      {
        name: "sdb",
        type: "disk",
        children: [
          member("sdb1", [{
            name: "md2",
            type: "raid1",
            fstype: "LVM2_member",
          }]),
        ],
      },
      {
        name: "sdc",
        type: "disk",
        children: [
          member("sdc1", [{
            name: "md2",
            type: "raid1",
            fstype: "LVM2_member",
          }]),
        ],
      },
      { name: "sdd", type: "disk", children: [member("sdd1")] },
      { name: "sde", type: "disk" },
    ),
    findmnt: findmnt({
      target: "/",
      source: "/dev/mapper/vg0-root",
      fstype: "ext4",
    }),
    fstab: file("/dev/mapper/vg0-root / ext4 defaults 0 1\n"),
    links: ok("/dev/mapper/vg0-root /dev/dm-0\n"),
    mdstat: file("md2 : active raid1 sdc1[1] sdb1[0]\n"),
    pvs: ok("  /dev/sda1  vg0\n  /dev/md2  vg0\n"),
    mdExamine: {
      "/dev/sdb1": ok(examineOut(ARRAY_UUID)),
      "/dev/sdc1": ok(examineOut(ARRAY_UUID)),
      "/dev/sdd1": ok(examineOut(ARRAY_UUID)),
    },
  });
  refused(input, ["/dev/sdd"], "protected");
  safe(input, ["/dev/sde"]);
});

Deno.test("18 a protected volume group needs its own pvs row, and a failed re-read refuses", () => {
  const lvm = (pvs: CommandProbe): ProbeInputs =>
    plain({
      lsblk: lsblk(
        {
          name: "sda",
          type: "disk",
          children: [{
            name: "sda1",
            type: "part",
            fstype: "LVM2_member",
            children: [{
              name: "vg0-root",
              type: "lvm",
              fstype: "ext4",
              mounts: ["/"],
            }],
          }],
        },
        { name: "sdb", type: "disk" },
      ),
      findmnt: findmnt({
        target: "/",
        source: "/dev/mapper/vg0-root",
        fstype: "ext4",
      }),
      fstab: file(""),
      links: ok("/dev/mapper/vg0-root /dev/dm-0\n"),
      pvs,
    });
  refused(lvm(ok("  /dev/sdz  other\n")), ["/dev/sdb"], "unverifiable");
  const first = safe(lvm(ok("  /dev/sda1  vg0\n")), ["/dev/sdb"]);
  // A later read of a host with no LVM tools cannot clear the earlier set.
  refused(plain({ pvs: missing }), ["/dev/sdb"], "unverifiable", "", first);
});

Deno.test("19 a systemd automount /boot/efi is accepted only beside a block-backed mount", () => {
  const efi = { target: "/boot/efi", source: "systemd-1", fstype: "autofs" };
  const root = { target: "/", source: "/dev/sda2", fstype: "ext4" };
  const real = { target: "/boot/efi", source: "/dev/sda1", fstype: "vfat" };
  refused(plain({ findmnt: findmnt(root, efi) }), ["/dev/sdb"], "unverifiable");
  safe(plain({ findmnt: findmnt(root, efi, real) }), ["/dev/sdb"]);
});

Deno.test("20 /proc/swaps must have its header and well-formed rows", () => {
  refused(plain({ swaps: file("") }), ["/dev/sdb"], "unverifiable");
  refused(plain({ swaps: file("/dev/sdc1 partition 100 0 -2\n") }), [
    "/dev/sdb",
  ], "unverifiable");
  refused(
    plain({ swaps: file(SWAP_HEADER + "/dev/sdc1 partition\n") }),
    ["/dev/sdb"],
    "unverifiable",
  );
});

Deno.test("21 any /dev-sourced mount is seeded, whatever its filesystem type", () => {
  const input = plain({
    lsblk: lsblk(
      ...withExtraDisk(),
    ),
    findmnt: findmnt(
      { target: "/", source: "/dev/sda2", fstype: "ext4" },
      { target: "/mnt/odd", source: "/dev/sdb1", fstype: "squashfs" },
    ),
  });
  refused(input, ["/dev/sdb"], "protected");
});

Deno.test("22 a mounted non-root filesystem outside fstab also needs a known type", () => {
  const rows = (fstype?: string): CommandProbe =>
    lsblk(
      {
        name: "sda",
        type: "disk",
        children: [
          {
            name: "sda1",
            type: "part",
            fstype: "vfat",
            uuid: "ABCD-1234",
            mounts: ["/boot/efi"],
          },
          {
            name: "sda2",
            type: "part",
            fstype: "ext4",
            uuid: "11111111-2222-3333-4444-555555555555",
            mounts: ["/"],
          },
        ],
      },
      {
        name: "sdb",
        type: "disk",
        children: [{ name: "sdb1", type: "part", fstype, mounts: ["/srv"] }],
      },
      { name: "sdc", type: "disk" },
    );
  const mounted = {
    findmnt: findmnt(
      { target: "/", source: "/dev/sda2", fstype: "ext4" },
      { target: "/boot/efi", source: "/dev/sda1", fstype: "vfat" },
      { target: "/srv", source: "/dev/sdb1", fstype: "xfs" },
    ),
  };
  refused(
    plain({ ...mounted, lsblk: rows(undefined) }),
    ["/dev/sdc"],
    "unverifiable",
  );
  refused(plain({ ...mounted, lsblk: rows("xfs") }), ["/dev/sdb"], "protected");
  safe(plain({ ...mounted, lsblk: rows("xfs") }), ["/dev/sdc"]);
});

// --- round 3: siblings of a protected partition are not protected ----------------

/** The Cherry two-disk layout: root RAID1 on sdX1, free space in sdX2. */
function twinHost(opts: {
  sibling?: Partial<Dev>;
  extra?: Partial<ProbeInputs>;
} = {}): ProbeInputs {
  const u = ARRAY_UUID.replaceAll(":", "-");
  const member = (n: string): Dev => ({
    name: `${n}1`,
    type: "part",
    fstype: "linux_raid_member",
    uuid: u,
    children: [{ name: "md0", type: "raid1", fstype: "ext4", mounts: ["/"] }],
  });
  const free = (n: string): Dev => ({
    name: `${n}2`,
    type: "part",
    ...(opts.sibling ?? {}),
  });
  return plain({
    lsblk: lsblk(
      { name: "sda", type: "disk", children: [member("sda"), free("sda")] },
      { name: "sdb", type: "disk", children: [member("sdb"), free("sdb")] },
    ),
    findmnt: findmnt({ target: "/", source: "/dev/md0", fstype: "ext4" }),
    fstab: file("/dev/md0 / ext4 defaults 0 1\n"),
    mdstat: file("md0 : active raid1 sdb1[1] sda1[0]\n"),
    links: ok(
      "/dev/disk/by-id/ata-EXAMPLE_A-part2 /dev/sda2\n" +
        "/dev/disk/by-id/ata-EXAMPLE_B-part2 /dev/sdb2\n",
    ),
    mdExamine: {
      "/dev/sda1": ok(examineOut(ARRAY_UUID)),
      "/dev/sdb1": ok(examineOut(ARRAY_UUID)),
    },
    ...opts.extra,
  });
}

Deno.test("23a whole disks of the twin layout are refused", () => {
  const input = twinHost();
  refused(input, ["/dev/sda"], "protected");
  refused(input, ["/dev/sdb"], "protected");
});

Deno.test("23b a free sibling partition is allowed, plain and by-id", () => {
  const input = twinHost();
  safe(input, ["/dev/sda2"]);
  safe(input, ["/dev/sdb2"]);
  safe(input, ["/dev/disk/by-id/ata-EXAMPLE_A-part2"]);
  safe(input, ["/dev/sda2", "/dev/sdb2"]);
  // The protected partitions themselves stay refused, however they are named.
  refused(input, ["/dev/sda1"], "protected");
  refused(input, ["/dev/sda2", "/dev/sdb1"], "protected");
});

Deno.test("23c a sibling that is swap, in fstab, a PV of root's VG or an array member is refused", () => {
  // active swap
  refused(
    twinHost({
      sibling: { fstype: "swap" },
      extra: {
        swaps: file(SWAP_HEADER + "/dev/sda2 partition 100 0 -2\n"),
      },
    }),
    ["/dev/sda2"],
    "protected",
  );
  // listed in fstab
  refused(
    twinHost({
      sibling: { fstype: "ext4", uuid: "44444444-5555-6666-7777-888888888888" },
      extra: {
        fstab: file(
          "/dev/md0 / ext4 defaults 0 1\nUUID=44444444-5555-6666-7777-888888888888 /srv ext4 nofail 0 2\n",
        ),
      },
    }),
    ["/dev/sda2"],
    "protected",
  );
  // member of the root array that dropped out
  refused(
    twinHost({
      sibling: {
        fstype: "linux_raid_member",
        uuid: ARRAY_UUID.replaceAll(":", "-"),
      },
      extra: {
        mdExamine: {
          "/dev/sda1": ok(examineOut(ARRAY_UUID)),
          "/dev/sdb1": ok(examineOut(ARRAY_UUID)),
          "/dev/sda2": ok(examineOut(ARRAY_UUID)),
          "/dev/sdb2": ok(examineOut(ARRAY_UUID)),
        },
      },
    }),
    ["/dev/sda2"],
    "protected",
  );
});

Deno.test("23d a sibling that is a PV of the root volume group is refused", () => {
  const input = plain({
    lsblk: lsblk(
      {
        name: "sda",
        type: "disk",
        children: [
          {
            name: "sda1",
            type: "part",
            fstype: "LVM2_member",
            children: [
              { name: "vg0-root", type: "lvm", fstype: "ext4", mounts: ["/"] },
            ],
          },
          { name: "sda2", type: "part", fstype: "LVM2_member" },
          { name: "sda3", type: "part" },
        ],
      },
    ),
    findmnt: findmnt({
      target: "/",
      source: "/dev/mapper/vg0-root",
      fstype: "ext4",
    }),
    fstab: file(""),
    links: ok("/dev/mapper/vg0-root /dev/dm-0\n"),
    pvs: ok("  /dev/sda1  vg0\n  /dev/sda2  vg0\n"),
  });
  refused(input, ["/dev/sda2"], "protected");
  safe(input, ["/dev/sda3"]);
});

Deno.test("23e udev-less host with working blkid: an empty sibling is allowed", () => {
  const input = plain({
    lsblk: bare(
      {
        name: "sda",
        type: "disk",
        children: [
          {
            name: "sda1",
            type: "part",
            children: [{ name: "md0", type: "raid1", mounts: ["/"] }],
          },
          { name: "sda2", type: "part" },
        ],
      },
      {
        name: "sdb",
        type: "disk",
        children: [
          {
            name: "sdb1",
            type: "part",
            children: [{ name: "md0", type: "raid1", mounts: ["/"] }],
          },
          { name: "sdb2", type: "part" },
        ],
      },
    ),
    findmnt: findmnt({ target: "/", source: "/dev/md0", fstype: "ext4" }),
    fstab: file("/dev/md0 / ext4 defaults 0 1\n"),
    mdstat: file("md0 : active raid1 sdb1[1] sda1[0]\n"),
    // blkid reports the raid members and md0, and nothing at all for sda2/sdb2.
    blkid: ok(
      `/dev/sda1: UUID="${
        ARRAY_UUID.replaceAll(":", "-")
      }" TYPE="linux_raid_member"\n` +
        `/dev/sdb1: UUID="${
          ARRAY_UUID.replaceAll(":", "-")
        }" TYPE="linux_raid_member"\n` +
        `/dev/md0: UUID="11111111-2222-3333-4444-555555555555" TYPE="ext4"\n`,
    ),
    mdExamine: {
      "/dev/sda1": ok(examineOut(ARRAY_UUID)),
      "/dev/sdb1": ok(examineOut(ARRAY_UUID)),
    },
  });
  safe(input, ["/dev/sda2"]);
  refused(input, ["/dev/sda"], "protected");
  // blkid failing: nothing can be told apart, so the same host refuses.
  for (const failing of [missing, NO_SB, { code: 2, stdout: "" }]) {
    refused({ ...input, blkid: failing }, ["/dev/sda2"], "unverifiable");
  }
});
