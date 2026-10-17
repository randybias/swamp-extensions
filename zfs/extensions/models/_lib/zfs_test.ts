import { assertEquals, assertThrows } from "jsr:@std/assert@1.0.19";
import {
  assertDatasetName,
  assertDevicePath,
  assertPoolName,
  assertProperties,
  assertSnapshotTag,
  assertVolsize,
  cloneArgv,
  commandReason,
  datasetCreateArgv,
  destroyArgv,
  DEVICE_RE,
  diffProperties,
  instanceKey,
  laterSnapshots,
  parseDatasets,
  parsePoolList,
  parsePoolVdevs,
  parseSize,
  parseSnapshots,
  parseTabbed,
  poolCreateArgv,
  poolDescendantsArgv,
  poolDestroyArgv,
  poolExportArgv,
  propertyString,
  rollbackArgv,
  snapshotArgv,
  splitSnapshot,
  vdevsMatch,
  volsizeToBytes,
  zvolCreateArgv,
} from "./zfs.ts";

Deno.test("name grammars accept valid ZFS names and reject injection", () => {
  assertPoolName("tank");
  assertPoolName("tank-2:pool");
  assertDatasetName("tank/data/set");
  assertSnapshotTag("daily-2026-01-01");
  assertVolsize("10G");
  assertVolsize("1.5T");
  assertDevicePath("/dev/disk/by-id/ata-EXAMPLE");
  assertThrows(() => assertPoolName("tank; rm -rf /"));
  assertThrows(() => assertDatasetName("tank/a b"));
  assertThrows(() => assertDatasetName("tank/../x"));
  assertThrows(() => assertSnapshotTag("bad tag"));
  assertThrows(() => assertVolsize("10G; rm"));
  assertThrows(() => assertDevicePath("/dev/sdb; rm -rf /"));
  assertThrows(() => assertDevicePath("/dev/../etc/passwd"));
  assertEquals(DEVICE_RE.test("/dev/nvme0n1"), true);
});

Deno.test("device grammar accepts by-id names with colons but no injection", () => {
  // The md-uuid form Ubuntu writes in fstab, and a -partN suffix.
  assertDevicePath(
    "/dev/disk/by-id/md-uuid-00000000:11111111:22222222:33333333",
  );
  assertDevicePath(
    "/dev/disk/by-id/ata-ExampleDisk_SYNTHETIC0001-part3",
  );
  assertEquals(
    DEVICE_RE.test(
      "/dev/disk/by-id/md-uuid-00000000:11111111:22222222:33333333-part1",
    ),
    true,
  );
  // The colon does not loosen the rest of the grammar.
  for (
    const bad of [
      "/dev/sda; rm -rf /",
      "/dev/sda && id",
      "/dev/sda`id`",
      "/dev/sda\nroot",
      "/dev/disk/by-id/$(id)",
    ]
  ) {
    assertThrows(() => assertDevicePath(bad), Error, undefined, bad);
  }
});

Deno.test("pool destroy/export argv and the descendant list", () => {
  assertEquals(poolDestroyArgv("tank"), ["zpool", "destroy", "-f", "tank"]);
  assertEquals(poolDestroyArgv("tank", false), ["zpool", "destroy", "tank"]);
  assertEquals(poolExportArgv("tank"), ["zpool", "export", "-f", "tank"]);
  assertEquals(poolDescendantsArgv("tank"), [
    "zfs",
    "list",
    "-H",
    "-r",
    "-o",
    "name",
    "-t",
    "filesystem,volume,snapshot",
    "tank",
  ]);
});

Deno.test("commandReason keeps one sanitized line and drops control bytes", () => {
  assertEquals(
    commandReason({
      stdout: "",
      stderr:
        "cannot destroy 'tank/x': dataset is busy\n\u0001\u0007second line\n",
    }),
    "second line",
  );
  assertEquals(commandReason({ stdout: "", stderr: "" }), "");
  for (const bad of ["a\u0000b", "x\u001fy"]) {
    const reason = commandReason({ stdout: "", stderr: `err\n${bad}` });
    assertEquals(reason.includes("\u0000"), false);
    assertEquals(reason.includes("\u001f"), false);
  }
  const long = commandReason({ stdout: "", stderr: "e".repeat(400) });
  assertEquals(long.length, 303);
});

Deno.test("assertProperties enforces the allowlist and value grammar", () => {
  assertProperties(
    { compression: "zstd" },
    new Set(["compression"]),
    "dataset",
  );
  assertThrows(
    () => assertProperties({ bogus: "x" }, new Set(["compression"]), "dataset"),
    Error,
    "unknown",
  );
  assertThrows(
    () =>
      assertProperties(
        { compression: "zstd; rm" },
        new Set(["compression"]),
        "dataset",
      ),
    Error,
    "invalid value",
  );
});

Deno.test("splitSnapshot parses valid names and rejects malformed ones", () => {
  assertEquals(splitSnapshot("tank/data@snap"), {
    dataset: "tank/data",
    tag: "snap",
  });
  assertEquals(splitSnapshot("tankdata"), null);
  assertEquals(splitSnapshot("@snap"), null);
  assertEquals(splitSnapshot("tank/data@"), null);
  assertEquals(splitSnapshot("tank/data@bad tag"), null);
});

Deno.test("argv builders assemble the exact tool vectors", () => {
  assertEquals(
    poolCreateArgv("tank", ["/dev/sdb"], { ashift: "12" }),
    ["zpool", "create", "-o", "ashift=12", "tank", "/dev/sdb"],
  );
  assertEquals(datasetCreateArgv("tank/data", { compression: "zstd" }), [
    "zfs",
    "create",
    "-o",
    "compression=zstd",
    "tank/data",
  ]);
  assertEquals(zvolCreateArgv("tank/vol", "10G", true), [
    "zfs",
    "create",
    "-s",
    "-V",
    "10G",
    "tank/vol",
  ]);
  assertEquals(snapshotArgv("tank@a", true), [
    "zfs",
    "snapshot",
    "-r",
    "tank@a",
  ]);
  assertEquals(cloneArgv("tank@a", "tank/clone"), [
    "zfs",
    "clone",
    "tank@a",
    "tank/clone",
  ]);
  assertEquals(rollbackArgv("tank@a", true), [
    "zfs",
    "rollback",
    "-r",
    "tank@a",
  ]);
  assertEquals(destroyArgv("tank/data", true, true), [
    "zfs",
    "destroy",
    "-r",
    "-f",
    "tank/data",
  ]);
  assertThrows(() => poolCreateArgv("tank", ["/dev/sdb; rm"], {}), Error);
});

Deno.test("propertyString normalizes booleans", () => {
  assertEquals(propertyString(true), "on");
  assertEquals(propertyString(false), "off");
  assertEquals(propertyString(12), "12");
  assertEquals(propertyString("zstd"), "zstd");
});

Deno.test("parseTabbed and the list parsers read tool output", () => {
  assertEquals(parseTabbed("a\tb\n\nc\td\n"), [["a", "b"], ["c", "d"]]);
  assertEquals(
    parsePoolList("tank\t10G\t1G\t9G\tONLINE\t12345\n"),
    [{
      name: "tank",
      size: "10G",
      alloc: "1G",
      free: "9G",
      health: "ONLINE",
      guid: "12345",
    }],
  );
  assertEquals(
    parseDatasets("tank/data\tfilesystem\t1G\t9G\t1G\t/tank/data\n"),
    [{
      name: "tank/data",
      type: "filesystem",
      used: "1G",
      avail: "9G",
      refer: "1G",
      mountpoint: "/tank/data",
    }],
  );
  assertEquals(
    parseSnapshots("tank/data@a\t0\t1G\t1700000000\n"),
    [{
      name: "tank/data@a",
      dataset: "tank/data",
      tag: "a",
      used: "0",
      refer: "1G",
      creation: "1700000000",
    }],
  );
});

Deno.test("parsePoolVdevs reads the config block of zpool status", () => {
  const status = [
    "  pool: tank",
    " state: ONLINE",
    "config:",
    "",
    "\tNAME        STATE     READ WRITE CKSUM",
    "\ttank        ONLINE       0     0     0",
    "\t  /dev/sdb  ONLINE       0     0     0",
    "\t  mirror-0  ONLINE       0     0     0",
    "\t    /dev/sdc  ONLINE       0     0     0",
    "\t    /dev/sdd  ONLINE       0     0     0",
    "",
    "errors: No known data errors",
  ].join("\n");
  assertEquals(parsePoolVdevs(status), ["/dev/sdb", "/dev/sdc", "/dev/sdd"]);
  assertEquals(parsePoolVdevs("no config here"), []);
});

Deno.test("parsePoolVdevs reads every pool's config block, not just the first", () => {
  const status = [
    "  pool: data",
    " state: ONLINE",
    "config:",
    "",
    "\tNAME        STATE     READ WRITE CKSUM",
    "\tdata        ONLINE       0     0     0",
    "\t  /dev/sdb  ONLINE       0     0     0",
    "",
    "errors: No known data errors",
    "",
    "  pool: rpool",
    " state: ONLINE",
    "config:",
    "",
    "\tNAME         STATE     READ WRITE CKSUM",
    "\trpool        ONLINE       0     0     0",
    "\t  /dev/sda2  ONLINE       0     0     0",
    "",
    "errors: No known data errors",
  ].join("\n");
  assertEquals(parsePoolVdevs(status), ["/dev/sda2", "/dev/sdb"]);
});

Deno.test("volsizeToBytes normalizes literals and byte counts", () => {
  assertEquals(volsizeToBytes("10G"), 10737418240);
  assertEquals(volsizeToBytes("10737418240"), 10737418240);
  assertEquals(volsizeToBytes("512M"), 536870912);
  assertEquals(volsizeToBytes("1.5T"), 1.5 * 1024 ** 4);
  assertThrows(() => volsizeToBytes("lots"), Error);
});

Deno.test("parseSize returns null for an empty or unparseable value", () => {
  assertEquals(parseSize("10737418240"), 10737418240);
  assertEquals(parseSize("10G"), 10737418240);
  assertEquals(parseSize(""), null);
  assertEquals(parseSize("-"), null);
  assertEquals(parseSize("lots"), null);
});

Deno.test("vdevsMatch and diffProperties compare state", () => {
  assertEquals(vdevsMatch(["/dev/sdb"], ["/dev/sdb"]), true);
  assertEquals(vdevsMatch(["/dev/sdb"], ["/dev/sdc"]), false);
  assertEquals(vdevsMatch(["/dev/sdb"], ["/dev/sdb", "/dev/sdc"]), false);
  assertEquals(
    diffProperties(
      { compression: "zstd", quota: "10G" },
      { compression: "lz4", quota: "10G" },
    ),
    { changed: { compression: "lz4" }, unchanged: ["quota"] },
  );
});

Deno.test("laterSnapshots finds snapshots newer than the target", () => {
  const snapshots = [
    {
      name: "tank@a",
      dataset: "tank",
      tag: "a",
      creation: "100",
      used: "0",
      refer: "1M",
    },
    {
      name: "tank@b",
      dataset: "tank",
      tag: "b",
      creation: "200",
      used: "0",
      refer: "1M",
    },
    {
      name: "other@a",
      dataset: "other",
      tag: "a",
      creation: "300",
      used: "0",
      refer: "1M",
    },
  ];
  assertEquals(laterSnapshots(snapshots, snapshots[0]).map((s) => s.name), [
    "tank@b",
  ]);
  assertEquals(laterSnapshots(snapshots, snapshots[1]), []);
});

Deno.test("instanceKey is stable, filesystem-safe and collision-free", () => {
  const identity = { host: "192.0.2.10", port: 22, user: "root" };
  assertEquals(
    instanceKey(identity, "tank/data@a"),
    "192.0.2.10-22-root-tank_data_a-1878a54d",
  );
  // The `_` escape plus the hash suffix keep these two distinct.
  assertEquals(
    instanceKey(identity, "tank/a_b") !== instanceKey(identity, "tank_a/b"),
    true,
  );
  const key = instanceKey(identity, "tank/data@a");
  assertEquals(/^[A-Za-z0-9._-]+$/.test(key), true);
  assertEquals(key.length <= 255, true);
});
