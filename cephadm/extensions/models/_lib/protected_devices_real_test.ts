/**
 * Tests built from the output of a real two-disk Ubuntu 24.04 bare-metal host
 * (mdadm 4.3, util-linux 2.39): a 1 MiB BIOS-boot partition and a root RAID1
 * member partition on each disk, free space after them. Identifiers are
 * replaced by synthetic ones; the shapes, flags and messages are as captured.
 */
import { assert, assertEquals, assertThrows } from "jsr:@std/assert@1.0.19";
import {
  assess,
  type CommandProbe,
  DEVICE_PATH_RE,
  efiBootPartuuids,
  examineTargets,
  LSBLK_COMMAND,
  mbrReadCommand,
  mdExamineCommand,
  type ProbeInputs,
} from "./protected_devices.ts";
import { sector0, withMbr } from "./boot_fixtures.ts";

const BIOS_BOOT = "21686148-6449-6e6f-744e-656564454649";
const ESP = "c12a7328-f81f-11d2-ba4b-00a0c93ec93b";
const LINUX_FS = "0fc63daf-8483-4772-8e79-3d69d8477de4";
const ZFS_PART = "6a898cc3-1dd2-11b2-99a6-080020736631";
const ARRAY = "777c3ba6-ac3b-1753-f920-8445a01c3c16";

const ok = (stdout: string): CommandProbe => ({ code: 0, stdout });

interface P {
  name: string;
  type: string;
  parttype: string | null;
  parttypename?: string | null;
  fstype?: string | null;
  mounts?: (string | null)[];
  partuuid?: string | null;
  uuid?: string | null;
  label?: string | null;
  children?: P[];
}

function row(p: P, parent: string | null): Record<string, unknown> {
  return {
    name: p.name,
    path: `/dev/${p.name}`,
    pkname: parent,
    type: p.type,
    fstype: p.fstype ?? null,
    uuid: p.uuid ?? null,
    partuuid: p.partuuid ?? null,
    label: p.label ?? null,
    mountpoints: p.mounts ?? [null],
    parttype: p.parttype,
    parttypename: p.parttypename ?? null,
    ...(p.children ? { children: p.children.map((c) => row(c, p.name)) } : {}),
  };
}

const md0 = (): P => ({
  name: "md0",
  type: "raid1",
  parttype: null,
  fstype: "ext4",
  uuid: "11111111-aaaa-4bbb-8ccc-222222222222",
  mounts: ["/"],
});

/** sdX1 BIOS boot, sdX2 root RAID member, optionally sdX3 free. */
function disk(n: string, free: boolean, parttype1 = BIOS_BOOT): P {
  return {
    name: n,
    type: "disk",
    parttype: null,
    children: [
      {
        name: `${n}1`,
        type: "part",
        parttype: parttype1,
        parttypename: parttype1 === BIOS_BOOT ? "BIOS boot" : "EFI System",
        partuuid: `0000000${n === "sda" ? 1 : 2}-0000-4000-8000-000000000001`,
      },
      {
        name: `${n}2`,
        type: "part",
        parttype: LINUX_FS,
        parttypename: "Linux filesystem",
        fstype: "linux_raid_member",
        uuid: ARRAY,
        label: "host:0",
        partuuid: `0000000${n === "sda" ? 1 : 2}-0000-4000-8000-000000000002`,
        children: [md0()],
      },
      ...(free
        ? [{
          name: `${n}3`,
          type: "part",
          parttype: ZFS_PART,
          parttypename: "Solaris /usr & Apple ZFS",
          partuuid: `0000000${n === "sda" ? 1 : 2}-0000-4000-8000-000000000003`,
        }]
        : []),
    ],
  };
}

const NO_SB = (dev: string): CommandProbe => ({
  code: 1,
  stdout: "",
  stderr: `mdadm: No md superblock detected on ${dev}.\n`,
});

const examineMember = (dev: string, device: string): CommandProbe =>
  ok(
    `${dev}:\n          Magic : a92b4efc\n        Version : 1.2\n    Feature Map : 0x0\n     Array UUID : 777c3ba6:ac3b1753:f9208445:a01c3c16\n           Name : host:0\n  Creation Time : Sat Oct 17 12:24:26 2026\n     Raid Level : raid1\n   Raid Devices : 2\n\n Avail Dev Size : 83818496 sectors (39.97 GiB 42.92 GB)\n    Device UUID : ${device}\n\n          State : clean\n   Device Role : Active device 0\n   Array State : AA ('A' == active, '.' == missing, 'R' == replacing)\n`,
  );

/** The probes of the captured host; `free` adds an unused third partition. */
function realHost(free = true): ProbeInputs {
  const blkid = [
    `/dev/sdb2: UUID="${ARRAY}" UUID_SUB="1ea8faa1-189c-e241-a68d-e91c9285dd83" LABEL="host:0" TYPE="linux_raid_member" PARTUUID="00000002-0000-4000-8000-000000000002"`,
    `/dev/md0: UUID="11111111-aaaa-4bbb-8ccc-222222222222" BLOCK_SIZE="4096" TYPE="ext4"`,
    `/dev/sda2: UUID="${ARRAY}" UUID_SUB="81f582c5-f419-cea8-05c5-da28f9ad2ecf" LABEL="host:0" TYPE="linux_raid_member" PARTUUID="00000001-0000-4000-8000-000000000002"`,
    // The BIOS-boot partitions have a PARTUUID and nothing else.
    `/dev/sdb1: PARTUUID="00000002-0000-4000-8000-000000000001"`,
    `/dev/sda1: PARTUUID="00000001-0000-4000-8000-000000000001"`,
  ].join("\n") + "\n";
  return {
    lsblk: ok(JSON.stringify({
      blockdevices: [disk("sda", free), disk("sdb", free)].map((d) =>
        row(d, null)
      ),
    })),
    findmnt: ok(JSON.stringify({
      filesystems: [{
        target: "/",
        source: "/dev/md0",
        fstype: "ext4",
        options: "rw,relatime",
      }],
    })),
    fstab: {
      state: "ok",
      text:
        "# /etc/fstab: static file system information.\n#\n# <file system> <mount point>   <type>  <options>       <dump>  <pass>\n/dev/disk/by-id/md-uuid-777c3ba6:ac3b1753:f9208445:a01c3c16 / ext4 defaults 0 1\n/swap.img\tnone\tswap\tsw\t0\t0\n",
    },
    swaps: {
      state: "ok",
      text:
        "Filename\t\t\t\tType\t\tSize\t\tUsed\t\tPriority\n/swap.img                               file\t\t8388604\t\t0\t\t-2\n",
    },
    mdstat: {
      state: "ok",
      text:
        "Personalities : [raid1] [raid0] [raid6] [raid5] [raid4] [raid10] \nmd0 : active raid1 sda2[0] sdb2[1]\n      41909248 blocks super 1.2 [2/2] [UU]\n      \nunused devices: <none>\n",
    },
    links: ok(
      "/dev/block/9:0 /dev/md0\n/dev/disk/by-uuid/11111111-aaaa-4bbb-8ccc-222222222222 /dev/md0\n/dev/disk/by-id/md-name-host:0 /dev/md0\n/dev/disk/by-id/md-uuid-777c3ba6:ac3b1753:f9208445:a01c3c16 /dev/md0\n/dev/disk/by-id/ata-EXAMPLE_DISK_A-part3 /dev/sda3\n/dev/disk/by-id/ata-EXAMPLE_DISK_B-part3 /dev/sdb3\n",
    ),
    blkid: ok(blkid),
    zpool: { code: 0, stdout: "no pools available\n" },
    pvs: { code: 0, stdout: "" },
    // The captured host boots by BIOS: no EFI.
    efi: { code: 1, stdout: "" },
    efibootmgr: { code: 127, stdout: "" },
    mdExamine: {
      "/dev/sda": NO_SB("/dev/sda"),
      "/dev/sdb": NO_SB("/dev/sdb"),
      "/dev/sda1": NO_SB("/dev/sda1"),
      "/dev/sdb1": NO_SB("/dev/sdb1"),
      "/dev/sda2": examineMember(
        "/dev/sda2",
        "81f582c5:f419cea8:05c5da28:f9ad2ecf",
      ),
      "/dev/sdb2": examineMember(
        "/dev/sdb2",
        "1ea8faa1:189ce241:a68de91c:9285dd83",
      ),
      "/dev/sda3": NO_SB("/dev/sda3"),
      "/dev/sdb3": NO_SB("/dev/sdb3"),
    },
    mbr: {},
  };
}

function assessM(
  input: ProbeInputs,
  candidates: string[],
  previous?: Parameters<typeof assess>[2],
  options?: Parameters<typeof assess>[3],
) {
  return assess(withMbr(input, candidates), candidates, previous, options);
}

function code(input: ProbeInputs, candidates: string[]): string {
  const r = assess(withMbr(input, candidates), candidates);
  return r.ok ? "allowed" : r.refusal.code;
}

Deno.test("the probe asks lsblk for the partition type, and not for the name", () => {
  assert(LSBLK_COMMAND.endsWith(",PARTTYPE"));
  // PARTTYPENAME needs util-linux 2.35: on 2.34 (Ubuntu 20.04) lsblk errors and
  // every wipe would be refused. The module never read it.
  assertEquals(LSBLK_COMMAND.includes("PARTTYPENAME"), false);
});

Deno.test("mdadm is given the device bare: never after `--`, and only a plain /dev path", () => {
  // mdadm 4.3 answered "No devices to examine" (exit 2) to `--examine -- <dev>`
  // for every device, which made every candidate unverifiable.
  assertEquals(mdExamineCommand("/dev/sda2"), "mdadm --examine '/dev/sda2'");
  assertEquals(mdExamineCommand("/dev/md/0"), "mdadm --examine '/dev/md/0'");
  assert(!/ -- /.test(mdExamineCommand("/dev/nvme0n1p1")));
  for (
    const bad of [
      "sda",
      "/dev/",
      "/dev/sda; rm -rf /",
      "/dev/sda' ; id ; '",
      "/dev/sda\n/dev/sdb",
      "/dev/../etc/passwd",
      "/dev/-oops",
      "/dev/sd a",
      "/etc/passwd",
      "--scan",
    ]
  ) {
    assertEquals(DEVICE_PATH_RE.test(bad) && !bad.includes(".."), false, bad);
    assertThrows(() => mdExamineCommand(bad), Error, "plain /dev device path");
  }
});

Deno.test("a path mdadm could not safely be given is never made an examine target", () => {
  const withMember = (path: string) => {
    const input = realHost();
    const weird = JSON.parse(input.lsblk.stdout);
    // An md member (so examineTargets would normally list it) at `path`.
    weird.blockdevices.push({
      name: "sdz",
      path,
      pkname: null,
      type: "disk",
      fstype: "linux_raid_member",
      uuid: null,
      partuuid: null,
      label: null,
      mountpoints: [null],
      parttype: null,
    });
    return examineTargets({ ...input, lsblk: ok(JSON.stringify(weird)) }, [
      "/dev/sda3",
    ]);
  };
  // Control: the same member at a plain path is a target ...
  assert(withMember("/dev/sdz").includes("/dev/sdz"));
  // ... and at an unsafe one it is left out.
  for (const bad of ["/dev/sdz; id", "/dev/sdz'x", "/dev/../sdz"]) {
    assertEquals(withMember(bad).includes(bad), false, bad);
  }
});

Deno.test("the real failing mdadm answer ('No devices to examine') still refuses, as unverifiable", () => {
  const input = realHost();
  input.mdExamine["/dev/sda3"] = {
    code: 2,
    stdout: "",
    stderr: "mdadm: No devices to examine\n",
  };
  assertEquals(code(input, ["/dev/sda3"]), "unverifiable");
});

Deno.test("real layout: the BIOS-boot partition, the root members, md0 and the whole disks are refused", () => {
  const input = realHost();
  for (
    const dev of [
      "/dev/sda1",
      "/dev/sdb1",
      "/dev/sda2",
      "/dev/sdb2",
      "/dev/md0",
      "/dev/sda",
      "/dev/sdb",
    ]
  ) {
    const r = assessM(input, [dev]);
    assert(!r.ok, `${dev} must be refused`);
    assertEquals(r.refusal.code, "protected", dev);
  }
  // Also by their stable names, and in combination with a free partition.
  assertEquals(code(input, ["/dev/sda3", "/dev/sda1"]), "protected");
});

Deno.test("real layout: the free third partitions are allowed, plain and by-id, with blkid and mdadm working", () => {
  const input = realHost();
  assertEquals(code(input, ["/dev/sda3"]), "allowed");
  assertEquals(code(input, ["/dev/sdb3"]), "allowed");
  assertEquals(code(input, ["/dev/sda3", "/dev/sdb3"]), "allowed");
  assertEquals(
    code(input, [
      "/dev/disk/by-id/ata-EXAMPLE_DISK_A-part3",
      "/dev/disk/by-id/ata-EXAMPLE_DISK_B-part3",
    ]),
    "allowed",
  );
});

Deno.test("real layout: the BIOS-boot partition is refused because of its type, with nothing else claiming it", () => {
  const input = realHost();
  const r = assessM(input, ["/dev/sda1"]);
  assert(!r.ok);
  assert(
    JSON.stringify(r.refusal.detail).includes("boot partition"),
    "the reason names the boot partition",
  );
  // Without the boot-partition rule nothing mounts, lists or labels it: it has
  // no filesystem, no mount point, and is in no fstab, swap, md or LVM stack.
  const noType = realHost();
  const lsblk = JSON.parse(noType.lsblk.stdout);
  for (const d of lsblk.blockdevices) {
    d.children[0].parttype = LINUX_FS;
  }
  noType.lsblk = ok(JSON.stringify(lsblk));
  assertEquals(code(noType, ["/dev/sda1"]), "allowed");
});

Deno.test("an EFI System partition on a disk that holds a protected device is refused", () => {
  const input = realHost();
  const lsblk = JSON.parse(input.lsblk.stdout);
  lsblk.blockdevices[0].children[0].parttype = ESP;
  input.lsblk = ok(JSON.stringify(lsblk));
  assertEquals(code(input, ["/dev/sda1"]), "protected");
  // The other disk's BIOS-boot partition is refused on the same grounds.
  assertEquals(code(input, ["/dev/sdb1"]), "protected");
});

Deno.test("MBR boot partition codes are recognised too", () => {
  const input = realHost();
  const lsblk = JSON.parse(input.lsblk.stdout);
  lsblk.blockdevices[0].children[0].parttype = "0xef";
  input.lsblk = ok(JSON.stringify(lsblk));
  assertEquals(code(input, ["/dev/sda1"]), "protected");
});

Deno.test("an unreadable partition type on a disk holding a protected device refuses everything", () => {
  const input = realHost();
  const lsblk = JSON.parse(input.lsblk.stdout);
  lsblk.blockdevices[0].children[2].parttype = null;
  input.lsblk = ok(JSON.stringify(lsblk));
  assertEquals(code(input, ["/dev/sda3"]), "unverifiable");
  assertEquals(code(input, ["/dev/sdb3"]), "unverifiable");
});

/** A third disk, away from the root topology, carrying one boot-type partition. */
function withBootDisk(parttype: string, mounted = false): ProbeInputs {
  const input = realHost();
  const lsblk = JSON.parse(input.lsblk.stdout);
  lsblk.blockdevices.push(
    row({
      name: "sdc",
      type: "disk",
      parttype: null,
      children: [{
        name: "sdc1",
        type: "part",
        parttype,
        fstype: parttype === ESP ? "vfat" : null,
        mounts: mounted ? ["/boot/efi"] : [null],
        partuuid: "00000003-0000-4000-8000-000000000001",
      }, {
        name: "sdc2",
        type: "part",
        parttype: LINUX_FS,
        partuuid: "00000003-0000-4000-8000-000000000002",
      }],
    }, null),
  );
  input.lsblk = ok(JSON.stringify(lsblk));
  for (const d of ["/dev/sdc", "/dev/sdc1", "/dev/sdc2"]) {
    input.mdExamine[d] = NO_SB(d);
  }
  input.blkid = ok(
    input.blkid.stdout +
      '/dev/sdc1: PARTUUID="00000003-0000-4000-8000-000000000001"\n',
  );
  return input;
}

Deno.test("a boot partition on a disk holding nothing protected is refused by default", () => {
  // A legacy-BIOS host can keep GRUB's core image on a SATA disk while / and
  // /boot sit on NVMe; an unmounted fallback ESP is the UEFI equivalent. The
  // firmware's boot device is not discoverable from the root topology.
  for (const type of [BIOS_BOOT, ESP]) {
    const input = withBootDisk(type);
    for (const dev of ["/dev/sdc", "/dev/sdc1"]) {
      const r = assessM(input, [dev]);
      assert(!r.ok, `${type} ${dev}`);
      assertEquals(r.refusal.code, "boot-partition", `${type} ${dev}`);
    }
    // The free sibling partition on that disk is not a boot partition.
    assertEquals(code(input, ["/dev/sdc2"]), "allowed");
  }
});

Deno.test("the acknowledgement lifts only the boot-partition refusal, only for the named disk", () => {
  const input = withBootDisk(BIOS_BOOT);
  const ok1 = assessM(input, ["/dev/sdc"], undefined, {
    bootAcknowledged: ["/dev/sdc"],
  });
  assert(ok1.ok, "the named disk is allowed");
  // Naming a partition's disk is what counts; a partition candidate needs it too.
  assert(
    assessM(input, ["/dev/sdc1"], undefined, { bootAcknowledged: ["/dev/sdc"] })
      .ok,
  );
  // A different disk's acknowledgement does not help this one.
  const other = assessM(input, ["/dev/sdc"], undefined, {
    bootAcknowledged: ["/dev/sda"],
  });
  assert(!other.ok && other.refusal.code === "boot-partition");
  // And it never lifts a protection: the root disks stay refused as protected.
  for (const dev of ["/dev/sda", "/dev/sda1", "/dev/sdb1", "/dev/md0"]) {
    const r = assessM(input, [dev], undefined, {
      bootAcknowledged: ["/dev/sda", "/dev/sdb", "/dev/sdc"],
    });
    assert(!r.ok, dev);
    assertEquals(r.refusal.code, "protected", dev);
  }
});

Deno.test("an EFI System partition that is mounted is seeded by its mount, not only by its type", () => {
  const input = withBootDisk(ESP, true);
  input.findmnt = ok(JSON.stringify({
    filesystems: [
      { target: "/", source: "/dev/md0", fstype: "ext4" },
      { target: "/boot/efi", source: "/dev/sdc1", fstype: "vfat" },
    ],
  }));
  const r = assessM(input, ["/dev/sdc"], undefined, {
    bootAcknowledged: ["/dev/sdc"],
  });
  assert(!r.ok);
  assertEquals(r.refusal.code, "protected", "a mounted ESP stays protected");
});

Deno.test("an unmounted ESP on a multipath root device is refused", () => {
  const mp = (extra: Partial<P>): P => ({
    name: "mpatha",
    type: "mpath",
    parttype: null,
    ...extra,
  });
  const part = (n: number, p: Partial<P>): P => ({
    name: `mpatha${n}`,
    type: "part",
    parttype: LINUX_FS,
    ...p,
  });
  const children = [
    part(1, { parttype: ESP, fstype: "vfat" }),
    part(2, { fstype: "ext4", mounts: ["/"] }),
  ];
  const device = (name: string): P => ({
    name,
    type: "disk",
    parttype: null,
    children: [mp({ children })],
  });
  const input = realHost(false);
  input.lsblk = ok(JSON.stringify({
    blockdevices: [device("sdc"), device("sdd")].map((d) => row(d, null)),
  }));
  input.findmnt = ok(JSON.stringify({
    filesystems: [{ target: "/", source: "/dev/mpatha2", fstype: "ext4" }],
  }));
  input.fstab = { state: "ok", text: "/dev/mpatha2 / ext4 defaults 0 1\n" };
  input.mdstat = { state: "absent" };
  input.links = ok("");
  input.blkid = ok(
    '/dev/mpatha1: UUID="AAAA-AAAA" TYPE="vfat"\n/dev/mpatha2: UUID="22222222-bbbb-4ccc-8ddd-333333333333" TYPE="ext4"\n',
  );
  input.mdExamine = {};
  for (const d of ["/dev/sdc", "/dev/sdd", "/dev/mpatha1", "/dev/mpatha2"]) {
    input.mdExamine[d] = NO_SB(d);
  }
  const r = assessM(input, ["/dev/mpatha1"]);
  assert(!r.ok);
  assertEquals(r.refusal.code, "protected");
  // Even with the disks acknowledged: it sits in the root's own stack.
  const lifted = assessM(input, ["/dev/mpatha1"], undefined, {
    bootAcknowledged: ["/dev/sdc", "/dev/sdd"],
  });
  assert(!lifted.ok && lifted.refusal.code === "protected");
});

Deno.test("GUID case does not matter: an upper-case boot type is still a boot type", () => {
  const input = realHost();
  const lsblk = JSON.parse(input.lsblk.stdout);
  lsblk.blockdevices[0].children[0].parttype = BIOS_BOOT.toUpperCase();
  lsblk.blockdevices[1].children[0].parttype = ESP.toUpperCase();
  input.lsblk = ok(JSON.stringify(lsblk));
  assertEquals(code(input, ["/dev/sda1"]), "protected");
  assertEquals(code(input, ["/dev/sdb1"]), "protected");
  // And on a disk away from the root, the upper-case type is refused as well.
  const away = withBootDisk(ESP.toUpperCase());
  assertEquals(code(away, ["/dev/sdc"]), "boot-partition");
});

const EFIBOOTMGR = `BootCurrent: 0001
Timeout: 1 seconds
BootOrder: 0001,0000
Boot0000* UEFI: PXE IPv4	PciRoot(0x0)/Pci(0x1c,0x0)/MAC(020000000001,1)/IPv4(0.0.0.0)
Boot0001* ubuntu	HD(1,GPT,00000003-0000-4000-8000-000000000002,0x800,0x100000)/File(\\EFI\\ubuntu\\shimx64.efi)
Boot0002* old	HD(1,GPT,00000009-0000-4000-8000-000000000009,0x800,0x100000)/File(\\EFI\\old.efi)
`;

Deno.test("EFI boot entries are extra, hard evidence: the partition they name is protected even when acknowledged", () => {
  assertEquals(efiBootPartuuids(EFIBOOTMGR), [
    "00000003-0000-4000-8000-000000000002",
  ]);
  const input = withBootDisk(BIOS_BOOT);
  input.efi = { code: 0, stdout: "" };
  input.efibootmgr = ok(EFIBOOTMGR);
  // sdc2 is typed as plain Linux data but is what the firmware boots.
  const r = assessM(input, ["/dev/sdc2"], undefined, {
    bootAcknowledged: ["/dev/sdc"],
  });
  assert(!r.ok);
  assertEquals(r.refusal.code, "protected");
  const whole = assessM(input, ["/dev/sdc"], undefined, {
    bootAcknowledged: ["/dev/sdc"],
  });
  assert(!whole.ok && whole.refusal.code === "protected");
});

Deno.test("efibootmgr is never the only evidence, and a missing one does not block an EFI host", () => {
  const input = withBootDisk(BIOS_BOOT);
  input.efi = { code: 0, stdout: "" };
  for (
    const efibootmgr of [{ code: 127, stdout: "" }, { code: 1, stdout: "" }]
  ) {
    const r = assessM({ ...input, efibootmgr }, ["/dev/sdc2"]);
    assert(r.ok, "the type-based rules still decide");
    const boot = assessM({ ...input, efibootmgr }, ["/dev/sdc"]);
    assert(!boot.ok && boot.refusal.code === "boot-partition");
  }
  // The firmware type must be readable: neither an EFI nor a BIOS answer refuses.
  const odd = assessM({ ...input, efi: { code: 2, stdout: "" } }, [
    "/dev/sdc2",
  ]);
  assert(!odd.ok && odd.refusal.code === "unverifiable");
});

Deno.test("the live probes do not break with blkid or mdadm failing on the real layout", () => {
  const input = realHost();
  // blkid failing: the untyped BIOS-boot and free partitions can no longer be
  // told from something in use.
  assertEquals(
    code({ ...input, blkid: { code: 127, stdout: "" } }, ["/dev/sda3"]),
    "unverifiable",
  );
  const noMdadm = realHost();
  noMdadm.mdExamine["/dev/sda3"] = { code: 127, stdout: "" };
  assertEquals(code(noMdadm, ["/dev/sda3"]), "unverifiable");
});

// --- r8: MBR-form EFI entries, MBR boot code, BootNext, empty type -----------

/** withBootDisk, relabelled msdos: sdc1 and sdc2 get dos types and PARTUUIDs. */
function msdosBootDisk(sig: string, types: [string, string]): ProbeInputs {
  const input = withBootDisk(LINUX_FS);
  const lsblk = JSON.parse(input.lsblk.stdout);
  const sdc = lsblk.blockdevices.find((d: { name: string }) =>
    d.name === "sdc"
  );
  const ids = [`${sig}-01`, `${sig}-02`];
  sdc.children.forEach((c: Record<string, unknown>, i: number) => {
    c.parttype = types[i];
    c.partuuid = ids[i];
  });
  input.lsblk = ok(JSON.stringify(lsblk));
  input.blkid = ok(
    input.blkid.stdout.replace(
      "00000003-0000-4000-8000-000000000001",
      ids[0],
    ),
  );
  input.efi = { code: 0, stdout: "" };
  return input;
}

const mbrEntry = (n: number, sig: string) =>
  `BootCurrent: 0001\nBootOrder: 0001\nBoot0001* disk\tHD(${n},MBR,0x${sig},0x800,0x100000)/File(\\EFI\\boot\\bootx64.efi)\n`;

Deno.test("an MBR-form EFI entry maps to libblkid's dos PARTUUID, padded and lowercased", () => {
  assertEquals(efiBootPartuuids(mbrEntry(1, "A1B2C3D4")), ["a1b2c3d4-01"]);
  assertEquals(efiBootPartuuids(mbrEntry(2, "1b2c3d4")), ["01b2c3d4-02"]);
  assertEquals(efiBootPartuuids(mbrEntry(17, "b2c3d4")), ["00b2c3d4-11"]);
});

Deno.test("BootNext names a partition too", () => {
  const text = `BootNext: 0002
BootCurrent: 0001
BootOrder: 0001
Boot0001* a\tHD(1,GPT,00000003-0000-4000-8000-000000000001,0x800,0x1)/File(a)
Boot0002* b\tHD(1,GPT,00000003-0000-4000-8000-000000000002,0x800,0x1)/File(b)
Boot0003* c\tHD(1,GPT,00000003-0000-4000-8000-000000000003,0x800,0x1)/File(c)
`;
  assertEquals(efiBootPartuuids(text).sort(), [
    "00000003-0000-4000-8000-000000000001",
    "00000003-0000-4000-8000-000000000002",
  ]);
});

Deno.test("a booted msdos ESP is protected even when acknowledged: whole disk and partition", () => {
  for (const sig of ["a1b2c3d4", "0b2c3d4"]) {
    const input = msdosBootDisk(sig.padStart(8, "0"), ["0xef", "0x83"]);
    input.efibootmgr = ok(mbrEntry(1, sig));
    for (const dev of ["/dev/sdc", "/dev/sdc1"]) {
      const r = assessM(input, [dev], undefined, {
        bootAcknowledged: ["/dev/sdc"],
      });
      assert(!r.ok && r.refusal.code === "protected", `${sig} ${dev}`);
    }
  }
});

Deno.test("a booted FAT partition typed 0x0c (not a boot type) is protected without any ack", () => {
  const input = msdosBootDisk("a1b2c3d4", ["0x83", "0x0c"]);
  input.efibootmgr = ok(mbrEntry(2, "a1b2c3d4"));
  const r = assessM(input, ["/dev/sdc2"]);
  assert(!r.ok && r.refusal.code === "protected");
  // Without the entry the 0x0c partition is just data.
  input.efibootmgr = { code: 127, stdout: "" };
  assertEquals(code(input, ["/dev/sdc2"]), "allowed");
});

const sdcWithSector = (sector: CommandProbe | undefined): ProbeInputs => {
  const input = withBootDisk(LINUX_FS);
  if (sector) input.mbr["/dev/sdc"] = sector;
  return input;
};

Deno.test("MBR boot code with 55aa refuses as boot-partition; the ack for that disk lifts it", () => {
  const input = sdcWithSector(ok(sector0({ code: true })));
  const r = assessM(input, ["/dev/sdc"]);
  assert(!r.ok && r.refusal.code === "boot-partition");
  assertEquals(r.refusal.detail.evidence, "mbr-boot-code");
  assert(
    assessM(input, ["/dev/sdc"], undefined, { bootAcknowledged: ["/dev/sdc"] })
      .ok,
  );
  // The ack for another disk does not help this one.
  const other = assessM(input, ["/dev/sdc"], undefined, {
    bootAcknowledged: ["/dev/sda"],
  });
  assert(!other.ok && other.refusal.code === "boot-partition");
  // A partition candidate does not touch the MBR, so it is not judged by it.
  assertEquals(code(input, ["/dev/sdc2"]), "allowed");
});

Deno.test("sector 0 without boot code, or without 55aa, is allowed", () => {
  assertEquals(code(sdcWithSector(ok(sector0())), ["/dev/sdc"]), "allowed");
  assertEquals(
    code(sdcWithSector(ok(sector0({ code: true, sig: false }))), ["/dev/sdc"]),
    "allowed",
    "a whole-disk filesystem label has no 55aa",
  );
});

Deno.test("an unreadable first sector is unverifiable: failed, short, empty, malformed or never read", () => {
  for (
    const probe of [
      { code: 1, stdout: sector0() },
      { code: 0, stdout: "" },
      { code: 0, stdout: "00 00 00\n" },
      { code: 0, stdout: sector0() + " 00\n" },
      { code: 0, stdout: sector0().replace("00", "zz") },
    ]
  ) {
    assertEquals(code(sdcWithSector(probe), ["/dev/sdc"]), "unverifiable");
  }
  // No probe at all (a caller that skipped the read) is unverifiable.
  const never = withBootDisk(LINUX_FS);
  const r = assess(never, ["/dev/sdc"]);
  assert(!r.ok && r.refusal.code === "unverifiable");
});

Deno.test("the sector read is one bare read-only command on a plain device path", () => {
  assertEquals(
    mbrReadCommand("/dev/sdc"),
    "dd if='/dev/sdc' bs=512 count=1 status=none | od -An -v -tx1",
  );
  for (
    const bad of ["sdc", "/dev/sdc'; id", "/dev/../etc/passwd", "/dev/s c"]
  ) {
    assertThrows(() => mbrReadCommand(bad), Error, "plain /dev device path");
  }
});

Deno.test("a partition whose type cannot be read is a boot-partition refusal the ack lifts", () => {
  const input = withBootDisk(LINUX_FS);
  const lsblk = JSON.parse(input.lsblk.stdout);
  lsblk.blockdevices.find((d: { name: string }) => d.name === "sdc")
    .children[1].parttype = null;
  input.lsblk = ok(JSON.stringify(lsblk));
  const r = assessM(input, ["/dev/sdc"]);
  assert(!r.ok && r.refusal.code === "boot-partition");
  assert(
    assessM(input, ["/dev/sdc"], undefined, { bootAcknowledged: ["/dev/sdc"] })
      .ok,
  );
});

/** A partitioned IMSM-style array md126 over sdc and sdd, with an ESP md126p1. */
function imsmHost(): ProbeInputs {
  const input = realHost();
  const lsblk = JSON.parse(input.lsblk.stdout);
  const esp: P = {
    name: "md126p1",
    type: "part",
    parttype: ESP,
    fstype: "vfat",
    partuuid: "00000004-0000-4000-8000-000000000001",
  };
  const md: P = {
    name: "md126",
    type: "raid1",
    parttype: null,
    children: [esp],
  };
  for (const n of ["sdc", "sdd"]) {
    lsblk.blockdevices.push(
      row({ name: n, type: "disk", parttype: null, children: [md] }, null),
    );
  }
  input.lsblk = ok(JSON.stringify(lsblk));
  for (const d of ["/dev/sdc", "/dev/sdd", "/dev/md126", "/dev/md126p1"]) {
    input.mdExamine[d] = NO_SB(d);
  }
  input.blkid = ok(
    input.blkid.stdout +
      '/dev/md126p1: PARTUUID="00000004-0000-4000-8000-000000000001"\n',
  );
  return input;
}

Deno.test("an ESP on an md array over two disks needs BOTH disks acknowledged", () => {
  const input = imsmHost();
  for (const ack of [["/dev/sdc"], ["/dev/sdd"], []]) {
    const r = assessM(input, ["/dev/md126p1"], undefined, {
      bootAcknowledged: ack,
    });
    assert(!r.ok, ack.join());
    assertEquals(
      r.refusal.code,
      "boot-partition",
      `${ack.join()} ${JSON.stringify(r.refusal)}`,
    );
  }
  assert(
    assessM(input, ["/dev/md126p1"], undefined, {
      bootAcknowledged: ["/dev/sdc", "/dev/sdd"],
    }).ok,
  );
});

Deno.test("an acknowledged ESP-typed partition that is a physical volume of a protected group is still protected", () => {
  // Only conflict() can know this: the group is in the previously established
  // set. The acknowledgement must not skip the checks that follow the boot one.
  const input = withBootDisk(ESP);
  input.pvs = { code: 0, stdout: "  /dev/sdc1  vgx\n" };
  const previous = {
    devices: {},
    volumeGroups: ["vgx"],
    arrayUuids: [],
    pools: [],
  };
  const r = assessM(input, ["/dev/sdc"], previous, {
    bootAcknowledged: ["/dev/sdc"],
  });
  assert(!r.ok);
  assertEquals(r.refusal.code, "protected", JSON.stringify(r.refusal));
});

Deno.test("only bytes 0-439 count as boot code: the boundary is exact", () => {
  const at = (bytes: Record<number, number>) =>
    code(sdcWithSector(ok(sector0({ bytes }))), ["/dev/sdc"]);
  assertEquals(at({ 439: 1 }), "boot-partition");
  assertEquals(at({ 0: 0xeb }), "boot-partition");
  assertEquals(at({ 5: 1 }), "boot-partition", "code that starts after byte 0");
  // The disk signature and reserved bytes (440-445) are not boot code.
  assertEquals(at({ 440: 1, 441: 2, 442: 3, 443: 4, 445: 9 }), "allowed");
});

/** A multipath LUN: mpath_member paths sdc and sdd behind mpathb (dm-3). */
function multipathHost(): ProbeInputs {
  const input = realHost();
  const lsblk = JSON.parse(input.lsblk.stdout);
  const dm: P = {
    name: "dm-3",
    type: "mpath",
    parttype: null,
    fstype: null,
  };
  for (const n of ["sdc", "sdd"]) {
    lsblk.blockdevices.push(row({
      name: n,
      type: "disk",
      parttype: null,
      fstype: "mpath_member",
      children: [dm],
    }, null));
  }
  input.lsblk = ok(JSON.stringify(lsblk));
  for (const d of ["/dev/sdc", "/dev/sdd", "/dev/dm-3"]) {
    input.mdExamine[d] = NO_SB(d);
  }
  return input;
}

Deno.test("a multipath candidate is judged by the sector 0 of the disks behind it", () => {
  // (a) boot code on the paths: refused, and the ack for one path is not enough.
  const withCode = multipathHost();
  for (const d of ["/dev/sdc", "/dev/sdd"]) {
    withCode.mbr[d] = ok(sector0({ code: true }));
  }
  const r = assessM(withCode, ["/dev/dm-3"]);
  assert(!r.ok);
  assertEquals(r.refusal.code, "boot-partition", JSON.stringify(r.refusal));
  assertEquals(r.refusal.detail.evidence, "mbr-boot-code");
  // (b) no sector-0 probe at all: unverifiable, never allowed.
  const none = assess(multipathHost(), ["/dev/dm-3"]);
  assert(!none.ok);
  assertEquals(none.refusal.code, "unverifiable");
  // A single missing path is enough to refuse.
  const half = multipathHost();
  half.mbr["/dev/sdc"] = ok(sector0());
  const h = assess(half, ["/dev/dm-3"]);
  assert(!h.ok && h.refusal.code === "unverifiable");
  // (c) zero boot code: allowed.
  assertEquals(code(multipathHost(), ["/dev/dm-3"]), "allowed");
});
