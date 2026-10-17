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
  examineTargets,
  LSBLK_COMMAND,
  mdExamineCommand,
  type ProbeInputs,
} from "./protected_devices.ts";

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
  };
}

function code(input: ProbeInputs, candidates: string[]): string {
  const r = assess(input, candidates);
  return r.ok ? "allowed" : r.refusal.code;
}

Deno.test("the probe asks lsblk for the partition type and name", () => {
  assert(LSBLK_COMMAND.includes("PARTTYPE,PARTTYPENAME"));
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
  const input = realHost();
  const weird = JSON.parse(input.lsblk.stdout);
  weird.blockdevices.push({
    name: "sdz",
    path: "/dev/sdz; id",
    pkname: null,
    type: "disk",
    fstype: null,
    uuid: null,
    partuuid: null,
    label: null,
    mountpoints: [null],
    parttype: null,
    parttypename: null,
  });
  const lsblk = ok(JSON.stringify(weird));
  const targets = examineTargets({ ...input, lsblk }, ["/dev/sda3"]);
  assertEquals(targets.some((t) => t.includes(";")), false);
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
    const r = assess(input, [dev]);
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
  const r = assess(input, ["/dev/sda1"]);
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

Deno.test("a boot partition on a disk that holds nothing protected is not swept in", () => {
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
        parttype: BIOS_BOOT,
        parttypename: "BIOS boot",
      }],
    }, null),
  );
  input.lsblk = ok(JSON.stringify(lsblk));
  input.mdExamine["/dev/sdc"] = NO_SB("/dev/sdc");
  input.mdExamine["/dev/sdc1"] = NO_SB("/dev/sdc1");
  assertEquals(code(input, ["/dev/sdc"]), "allowed");
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
