import { assertEquals, assertThrows } from "jsr:@std/assert@1.0.19";
import { parsePoolVdevs } from "./zfs.ts";
import {
  assertProtectedRefsResolvable,
  assertVdevsSafe,
  type BlockDevice,
  computeProtectedDevices,
  deviceFamily,
  flattenDevices,
  parseFstab,
  parseLsblk,
  parseMdstatMembers,
  parseMounts,
  parseSwapSources,
} from "./safety.ts";

function disk(
  name: string,
  extra: Partial<BlockDevice> = {},
): BlockDevice {
  return {
    name,
    path: `/dev/${name}`,
    type: "disk",
    mountpoint: null,
    fstype: null,
    pkname: null,
    uuid: null,
    partuuid: null,
    label: null,
    children: [],
    ...extra,
  };
}

function part(
  name: string,
  pkname: string,
  extra: Partial<BlockDevice> = {},
): BlockDevice {
  return disk(name, { type: "part", pkname, ...extra });
}

function hostTree(): BlockDevice[] {
  return [
    disk("sda", {
      children: [
        part("sda1", "sda", {
          mountpoint: "/",
          fstype: "ext4",
          uuid: "ROOT-UUID",
        }),
        part("sda2", "sda", { fstype: "swap", uuid: "SWAP-UUID" }),
      ],
    }),
    disk("sdb"),
    disk("sdc", {
      children: [
        part("sdc1", "sdc", { fstype: "ext4", uuid: "DATA-UUID" }),
      ],
    }),
    disk("sdd", {
      children: [part("sdd1", "sdd", { fstype: "linux_raid_member" })],
    }),
    disk("sde"),
    disk("sdf"),
  ];
}

const MOUNTS = [
  "/dev/sda1 / ext4 rw,relatime 0 0",
  "proc /proc proc rw 0 0",
  "tmpfs /run tmpfs rw 0 0",
].join("\n");

const FSTAB = [
  "# /etc/fstab",
  "UUID=ROOT-UUID / ext4 defaults 0 1",
  "UUID=DATA-UUID /data ext4 defaults 0 2",
  "/dev/sdc1 /scratch ext4 defaults 0 2",
].join("\n");

const MDSTAT = [
  "Personalities : [raid1]",
  "md0 : active raid1 sdd1[0]",
  "      1047552 blocks super 1.2 [1/1] [U]",
  "",
  "md1 : inactive raid1 sdf1[0](S)",
  "      unused devices: <none>",
].join("\n");

const SWAPS = ["Filename Type Size Used Priority", "/dev/sda2 partition 1 0 -2"]
  .join("\n");

const ZFS_STATUS = [
  "  pool: old",
  " state: ONLINE",
  "config:",
  "",
  "\tNAME        STATE     READ WRITE CKSUM",
  "\told         ONLINE       0     0     0",
  "\t  /dev/sde  ONLINE       0     0     0",
  "",
  "errors: No known data errors",
].join("\n");

function buildProtectedSet(): Set<string> {
  const devices = hostTree();
  return computeProtectedDevices(
    devices,
    parseMounts(MOUNTS),
    parseFstab(FSTAB),
    parseMdstatMembers(MDSTAT),
    parsePoolVdevs(ZFS_STATUS),
    parseSwapSources(SWAPS),
  );
}

Deno.test("parseLsblk reads the tree and preserves parent links", () => {
  const devices = parseLsblk(JSON.stringify({ blockdevices: hostTree() }));
  assertEquals(devices.length, 6);
  const flat = flattenDevices(devices);
  assertEquals(flat.length, 10);
  assertEquals(
    flat.find((d) => d.name === "sda1")?.mountpoint,
    "/",
  );
  assertThrows(() => parseLsblk('{"blockdevices": null}'), Error);
});

Deno.test("parseMounts decodes octal escapes and parseFstab skips comments", () => {
  assertEquals(parseMounts("/dev/a\\040b /mnt/x ext4 rw 0 0"), [{
    source: "/dev/a b",
    target: "/mnt/x",
    fstype: "ext4",
  }]);
  assertEquals(parseFstab(FSTAB).length, 3);
  assertEquals(parseFstab(FSTAB)[0].device, "UUID=ROOT-UUID");
});

Deno.test("parseMdstatMembers finds active, degraded and inactive members", () => {
  assertEquals(parseMdstatMembers(MDSTAT), ["sdd1", "sdf1"]);
  assertEquals(parseSwapSources(SWAPS), ["/dev/sda2"]);
});

Deno.test("parseMdstatMembers handles nvme, whole-disk, mmcblk and dm members", () => {
  const text = [
    "md0 : active raid1 nvme0n1p2[0] sdb[1]",
    "      1047552 blocks super 1.2 [2/2] [UU]",
    "md1 : inactive raid1 mmcblk0p1[0](S) dm-0[1](F)",
    "      unused devices: <none>",
  ].join("\n");
  assertEquals(parseMdstatMembers(text), [
    "dm-0",
    "mmcblk0p1",
    "nvme0n1p2",
    "sdb",
  ]);
});

Deno.test("protected /dev/disk/by-id references resolve to the disk behind them", () => {
  const devices = hostTree();
  const resolved = new Map([["/dev/disk/by-id/wwn-rpool", "/dev/sda"]]);
  const set = computeProtectedDevices(
    devices,
    [],
    [],
    [],
    ["/dev/disk/by-id/wwn-rpool"],
    [],
    resolved,
  );
  assertEquals(set.has("/dev/sda"), true);
  assertEquals(set.has("/dev/sda2"), true);
});

Deno.test("unassembled raid/zfs members are protected by fstype", () => {
  const devices = [
    ...hostTree(),
    disk("sdg", {
      children: [part("sdg1", "sdg", { fstype: "linux_raid_member" })],
    }),
    disk("sdh", { fstype: "zfs_member" }),
  ];
  const set = computeProtectedDevices(devices, [], [], [], [], []);
  assertEquals(set.has("/dev/sdg"), true);
  assertEquals(set.has("/dev/sdg1"), true);
  assertEquals(set.has("/dev/sdh"), true);
});

Deno.test("an unresolvable protected reference refuses rather than protects nothing", () => {
  assertThrows(
    () =>
      assertProtectedRefsResolvable(
        ["/dev/disk/by-id/gone"],
        new Map([["/dev/disk/by-id/gone", "/dev/sdZ"]]),
        hostTree(),
      ),
    Error,
    "did not resolve",
  );
});

Deno.test("deviceFamily spans a whole disk and its partitions", () => {
  const devices = hostTree();
  const flat = flattenDevices(devices);
  const sda = flat.find((d) => d.name === "sda") as BlockDevice;
  const family = deviceFamily(sda, flat).sort();
  assertEquals(family, ["/dev/sda", "/dev/sda1", "/dev/sda2"]);
});

Deno.test("computeProtectedDevices covers boot, fstab, md, zfs and swap", () => {
  const protectedSet = buildProtectedSet();
  for (
    const path of [
      "/dev/sda",
      "/dev/sda1",
      "/dev/sda2",
      "/dev/sdc",
      "/dev/sdc1",
      "/dev/sdd",
      "/dev/sdd1",
      "/dev/sde",
    ]
  ) {
    assertEquals(protectedSet.has(path), true, path);
  }
  assertEquals(protectedSet.has("/dev/sdb"), false);
  assertEquals(protectedSet.has("/dev/sdf"), false);
});

Deno.test("assertVdevsSafe allows spares and refuses protected or unknown devices", () => {
  const devices = hostTree();
  const protectedSet = buildProtectedSet();
  // A spare disk with no role is allowed.
  assertVdevsSafe(
    ["/dev/disk/by-id/spare"],
    new Map([["/dev/disk/by-id/spare", "/dev/sdb"]]),
    devices,
    protectedSet,
  );
  // The boot disk, a mounted partition, an fstab entry, an md member, an
  // existing ZFS vdev and a swap partition are all refused by family.
  for (
    const real of [
      "/dev/sda",
      "/dev/sda1",
      "/dev/sdc1",
      "/dev/sdd",
      "/dev/sde",
      "/dev/sda2",
    ]
  ) {
    assertThrows(
      () =>
        assertVdevsSafe(
          ["/dev/disk/by-id/x"],
          new Map([["/dev/disk/by-id/x", real]]),
          devices,
          protectedSet,
        ),
      Error,
      "protected device set",
      real,
    );
  }
  // An unresolved or unknown device is refused rather than guessed at.
  assertThrows(
    () =>
      assertVdevsSafe(["/dev/disk/by-id/x"], new Map(), devices, protectedSet),
    Error,
    "could not resolve",
  );
  assertThrows(
    () =>
      assertVdevsSafe(
        ["/dev/disk/by-id/x"],
        new Map([["/dev/disk/by-id/x", "/dev/sdZ"]]),
        devices,
        protectedSet,
      ),
    Error,
    "not a known block device",
  );
});

Deno.test("the protected set is stable when the same facts are re-read", () => {
  const first = [...buildProtectedSet()].sort();
  const second = [...buildProtectedSet()].sort();
  assertEquals(first, second);
  assertEquals(first, [...first].sort());
});
