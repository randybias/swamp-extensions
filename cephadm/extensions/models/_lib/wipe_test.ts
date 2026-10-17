import { assertEquals, assertRejects } from "jsr:@std/assert@1.0.19";
import { PhaseError } from "./errors.ts";
import { listByIdCommand } from "./resolve.ts";
import type { CommandResult, RunOptions, SshSession } from "./ssh.ts";
import {
  BLKID_COMMAND,
  FINDMNT_COMMAND,
  LINKS_COMMAND,
  LSBLK_COMMAND,
  PVS_COMMAND,
  ZPOOL_COMMAND,
} from "./protected_devices.ts";
import {
  arrayBasename,
  editMdConfig,
  ensureArrayLine,
  findNode,
  lsblkCommand,
  parseArrayScanLine,
  parseLsblk,
  removeArrayLine,
  subtreeMounts,
  subtreeTypes,
  wipeDiskToRaw,
} from "./wipe.ts";

const RAW_TREE = JSON.stringify({
  blockdevices: [
    {
      name: "nvme0n1",
      path: "/dev/nvme0n1",
      mountpoint: null,
      type: "disk",
      fstype: null,
    },
  ],
});

type Answer = CommandResult | ((command: string) => CommandResult);

/** Overrides for the boot-guard probes; keys are the probe names below. */
type Probes = Record<string, Answer>;

const done = (stdout: string, code = 0, stderr = ""): CommandResult => ({
  code,
  stdout,
  stderr,
});

/** A rich lsblk row builder for the guard's probe (synthetic names only). */
function guardRow(
  name: string,
  type: string,
  extra: Record<string, unknown> = {},
  children?: unknown[],
): Record<string, unknown> {
  return {
    name,
    path: type === "lvm" || type === "crypt"
      ? `/dev/mapper/${name}`
      : `/dev/${name}`,
    pkname: null,
    type,
    fstype: null,
    uuid: null,
    partuuid: null,
    label: null,
    parttype: type === "part" ? "0fc63daf-8483-4772-8e79-3d69d8477de4" : null,
    parttypename: null,
    mountpoints: [null],
    ...extra,
    ...(children ? { children } : {}),
  };
}

const guardLsblk = (...rows: unknown[]): CommandResult =>
  done(JSON.stringify({ blockdevices: rows }));

/** Root on sda1; the candidate nvme0n1 is raw. */
const HEALTHY: Probes = {
  lsblk: guardLsblk(
    guardRow("sda", "disk", {}, [
      guardRow("sda1", "part", { fstype: "ext4", mountpoints: ["/"] }),
    ]),
    guardRow("nvme0n1", "disk"),
  ),
  findmnt: done(
    JSON.stringify({
      filesystems: [{ target: "/", source: "/dev/sda1", fstype: "ext4" }],
    }),
  ),
  fstab: done("/dev/sda1 / ext4 defaults 0 1\n"),
  swaps: done("Filename\tType\tSize\tUsed\tPriority\n"),
  mdstat: done("", 1, "cat: /proc/mdstat: No such file or directory"),
  links: done(""),
  // A working blkid that knows one unrelated device and nothing about the
  // raw candidate disk.
  blkid: done('/dev/sdz9: UUID="1111" TYPE="ext4"\n'),
  zpool: done("", 127),
  pvs: done("", 127),
};

const NO_SUPERBLOCK = done("", 1, "mdadm: No md superblock detected\n");

/** Answers the guard's probes, or returns undefined for any other command. */
function probeAnswer(
  command: string,
  over: Probes,
): CommandResult | undefined {
  const names: [string, string][] = [
    [LSBLK_COMMAND, "lsblk"],
    [FINDMNT_COMMAND, "findmnt"],
    ["cat -- '/etc/fstab'", "fstab"],
    ["cat -- '/proc/swaps'", "swaps"],
    ["cat -- '/proc/mdstat'", "mdstat"],
    [LINKS_COMMAND, "links"],
    [BLKID_COMMAND, "blkid"],
    [ZPOOL_COMMAND, "zpool"],
    [PVS_COMMAND, "pvs"],
  ];
  const hit = names.find(([c]) => c === command);
  if (hit) {
    const answer = over[hit[1]] ?? HEALTHY[hit[1]];
    return typeof answer === "function" ? answer(command) : answer;
  }
  const examine = /^mdadm --examine '(.+)'$/.exec(command);
  if (examine) {
    const answer = over[`examine:${examine[1]}`] ?? NO_SUPERBLOCK;
    return typeof answer === "function" ? answer(command) : answer;
  }
  return undefined;
}

function fakeSession(
  route: (opts: RunOptions) => CommandResult,
  host = "192.0.2.10",
  probes: Probes = {},
): { session: SshSession; calls: RunOptions[] } {
  const calls: RunOptions[] = [];
  const session: SshSession = {
    target: { host, user: "admin", strictHostKeyChecking: "yes" },
    controlPath: null,
    run: (opts) => {
      calls.push(opts);
      const probe = probeAnswer(opts.command, probes);
      if (probe) return Promise.resolve(probe);
      if (
        opts.command.startsWith("mdadm --detail ") &&
        !opts.command.includes("--scan")
      ) {
        return Promise.resolve({ code: 0, stdout: "", stderr: "" });
      }
      return Promise.resolve(route(opts));
    },
    close: () => Promise.resolve({ closed: false, detail: "not multiplexed" }),
  };
  return { session, calls };
}

const deps = { now: () => 0, sleep: () => Promise.resolve(), random: () => 0 };

Deno.test("parseLsblk refuses invalid JSON under the wipe phase", () => {
  assertEquals(parseLsblk('{"blockdevices":[]}'), []);
  try {
    parseLsblk("not json");
    throw new Error("should throw");
  } catch (e) {
    assertEquals(e instanceof PhaseError, true);
    assertEquals((e as PhaseError).phase, "wipe.lsblk-invalid");
  }
  assertEquals(findNode([], "/dev/x"), null);
});

Deno.test("subtree walkers report mounts and child types", () => {
  const node = {
    path: "/dev/nvme0n1",
    mountpoint: null,
    children: [
      { path: "/dev/nvme0n1p1", mountpoint: "/boot", type: "part" },
      {
        path: "/dev/nvme0n1p2",
        mountpoint: null,
        type: "part",
        children: [{ path: "/dev/md0", mountpoint: "/", type: "raid1" }],
      },
    ],
  };
  assertEquals(subtreeMounts(node), ["/boot", "/"]);
  assertEquals(subtreeTypes(node), ["part", "part", "raid1"]);
  assertEquals(arrayBasename("/dev/md0"), "md0");
  assertEquals(
    parseArrayScanLine("ARRAY /dev/md0 metadata=1.2 name=x"),
    "/dev/md0",
  );
  assertEquals(parseArrayScanLine("not an array line"), null);
});

Deno.test(
  "md config removal is anchored to the exact array path", // leak-allow(decision D10)
  () => {
    const text = [
      "ARRAY /dev/md/data-old metadata=1.2",
      "ARRAY /dev/md/data metadata=1.2",
      "ARRAY /dev/md0 metadata=1.2",
      "MAILADDR root",
    ].join("\n");
    const next = removeArrayLine(text, "/dev/md/data");
    assertEquals(next.includes("/dev/md/data-old"), true);
    assertEquals(next.includes("ARRAY /dev/md/data "), false);
    assertEquals(next.includes("ARRAY /dev/md0"), true);
  },
);

Deno.test("ensureArrayLine restores a missing boot line without duplicates", () => {
  const withLine = ensureArrayLine(
    "ARRAY /dev/md0 metadata=1.2\n",
    "/dev/md0",
    "ARRAY /dev/md0 metadata=1.2",
  );
  assertEquals(withLine.match(/ARRAY \/dev\/md0/g)?.length, 1);
  const added = ensureArrayLine(
    "MAILADDR root\n",
    "/dev/md0",
    "ARRAY /dev/md0 metadata=1.2",
  );
  assertEquals(added.includes("ARRAY /dev/md0 metadata=1.2"), true);
});

Deno.test("editMdConfig removes stopped arrays and restores surviving ones", () => {
  const text = "ARRAY /dev/md/data metadata=1.2\nARRAY /dev/md0 metadata=1.2\n";
  const scan = "ARRAY /dev/md0 metadata=1.2 name=host:0\n";
  const next = editMdConfig(text, ["/dev/md/data"], scan);
  assertEquals(next.includes("/dev/md/data"), false);
  assertEquals(next.includes("/dev/md0"), true);
  assertEquals(next.endsWith("\n"), true);
});

Deno.test(
  "a serial in both lists refuses with zero ssh calls", // leak-allow(decision D3)
  async () => {
    const { session, calls } = fakeSession(() => {
      throw new Error("should not be called");
    });
    await assertRejects(
      () =>
        wipeDiskToRaw({ ...deps, session }, {
          dataDevices: [{ serial: "SN0001" }],
          excludeDevices: [{ serial: "SN0001" }],
        }),
      PhaseError,
      "wipe.conflict",
    );
    assertEquals(calls.length, 0);
  },
);

/** A session with no default interception, for the boot-protection gates. */
function routedSession(
  route: (opts: RunOptions) => CommandResult | undefined,
  host = "192.0.2.10",
  probes: Probes = {},
): { session: SshSession; calls: RunOptions[] } {
  const calls: RunOptions[] = [];
  const session: SshSession = {
    target: { host, user: "admin", strictHostKeyChecking: "yes" },
    controlPath: null,
    run: (opts) => {
      calls.push(opts);
      const probe = probeAnswer(opts.command, probes);
      if (probe) return Promise.resolve(probe);
      const r = route(opts);
      if (!r) throw new Error(`unexpected ${opts.command}`);
      return Promise.resolve(r);
    },
    close: () => Promise.resolve({ closed: false, detail: "not multiplexed" }),
  };
  return { session, calls };
}

const NO_DESTRUCTIVE =
  /wipefs|vgremove|vgchange|lvremove|pvremove|mdadm --stop|zero-superblock|sgdisk/;

/** Routes listing, readlink and one lsblk read for a single disk. */
function diskRouter(opts: RunOptions, lsblk: string): CommandResult {
  if (opts.command === listByIdCommand()) {
    return { code: 0, stdout: "nvme-SN0001\n", stderr: "" };
  }
  if (opts.command.startsWith("readlink")) {
    return { code: 0, stdout: "/dev/nvme0n1\n", stderr: "" };
  }
  if (opts.command === lsblkCommand()) {
    return { code: 0, stdout: lsblk, stderr: "" };
  }
  if (opts.command.startsWith("mdadm --examine")) {
    return { code: 0, stdout: "", stderr: "" };
  }
  if (opts.command.startsWith("pvs ")) {
    return { code: 0, stdout: "", stderr: "" };
  }
  throw new Error(`unexpected ${opts.command}`);
}

Deno.test(
  "a mounted disk is refused before anything destructive", // leak-allow(decision D3)
  async () => {
    const mounted = JSON.stringify({
      blockdevices: [
        {
          name: "nvme0n1",
          path: "/dev/nvme0n1",
          mountpoint: null,
          type: "disk",
          children: [{
            name: "nvme0n1p1",
            path: "/dev/nvme0n1p1",
            mountpoint: "/",
            type: "part",
          }],
        },
      ],
    });
    const { session, calls } = fakeSession((opts) => diskRouter(opts, mounted));
    await assertRejects(
      () =>
        wipeDiskToRaw({ ...deps, session }, {
          dataDevices: [{ serial: "SN0001" }],
          excludeDevices: [],
        }),
      PhaseError,
      "wipe.in-use",
    );
    assertEquals(
      calls.some((c) =>
        /wipefs|vgremove|mdadm --stop|zero-superblock/.test(c.command)
      ),
      false,
    );
  },
);

Deno.test("a dry run plans and runs nothing destructive", async () => {
  const { session, calls } = fakeSession((opts) => diskRouter(opts, RAW_TREE));
  const record = await wipeDiskToRaw({ ...deps, session }, {
    dataDevices: [{ serial: "SN0001" }],
    excludeDevices: [],
    dryRun: true,
  });
  assertEquals(record.dryRun, true);
  assertEquals(record.plannedDevices, [{
    serial: "SN0001",
    device: "/dev/disk/by-id/nvme-SN0001",
  }]);
  assertEquals(
    calls.some((c) => /wipefs|vgremove|zero-superblock/.test(c.command)),
    false,
  );
});

Deno.test(
  "a data device aliasing an excluded disk is refused", // leak-allow(decision D4)
  async () => {
    const { session } = fakeSession((opts) => {
      if (opts.command === listByIdCommand()) {
        return { code: 0, stdout: "ata-SNA\nata-SNB\n", stderr: "" };
      }
      if (opts.command.startsWith("readlink")) {
        return { code: 0, stdout: "/dev/nvme0n1\n", stderr: "" };
      }
      if (opts.command === lsblkCommand()) {
        return { code: 0, stdout: RAW_TREE, stderr: "" };
      }
      if (opts.command.startsWith("mdadm --examine")) {
        return { code: 0, stdout: "", stderr: "" };
      }
      throw new Error(`unexpected ${opts.command}`);
    });
    await assertRejects(
      () =>
        wipeDiskToRaw({ ...deps, session }, {
          dataDevices: [{ serial: "SNA" }],
          excludeDevices: [{ serial: "SNB" }],
        }),
      PhaseError,
      "wipe.excluded-path",
    );
  },
);

Deno.test("an already-raw disk completes the teardown idempotently", async () => {
  const { session, calls } = fakeSession((opts) => {
    if (opts.command === listByIdCommand()) {
      return { code: 0, stdout: "nvme-SN0001\n", stderr: "" };
    }
    if (opts.command.startsWith("readlink")) {
      return { code: 0, stdout: "/dev/nvme0n1\n", stderr: "" };
    }
    if (opts.command === lsblkCommand()) {
      return { code: 0, stdout: RAW_TREE, stderr: "" };
    }
    if (opts.command === "test -e /etc/mdadm/mdadm.conf") {
      return { code: 1, stdout: "", stderr: "" };
    }
    if (opts.command.startsWith("mdadm --detail --scan")) {
      return { code: 0, stdout: "", stderr: "" };
    }
    if (opts.command === "cat /etc/fstab") {
      return { code: 0, stdout: "UUID=x / ext4 defaults 0 1\n", stderr: "" };
    }
    if (opts.command.startsWith("pvs ")) {
      return { code: 0, stdout: "", stderr: "" };
    }
    if (opts.command.startsWith("mdadm --examine")) {
      return { code: 0, stdout: "", stderr: "" };
    }
    if (opts.command.startsWith("mdadm --zero-superblock")) {
      return { code: 0, stdout: "", stderr: "" };
    }
    if (opts.command.startsWith("wipefs -a")) {
      return { code: 0, stdout: "", stderr: "" };
    }
    if (opts.command.startsWith("sgdisk")) {
      return { code: 0, stdout: "", stderr: "" };
    }
    if (opts.command.startsWith("partprobe")) {
      return { code: 0, stdout: "", stderr: "" };
    }
    throw new Error(`unexpected ${opts.command}`);
  });
  const record = await wipeDiskToRaw({ ...deps, session }, {
    dataDevices: [{ serial: "SN0001" }],
    excludeDevices: [],
  });
  assertEquals(record.dryRun, false);
  assertEquals(record.wiped, [{
    serial: "SN0001",
    device: "/dev/disk/by-id/nvme-SN0001",
  }]);
  assertEquals(record.mdadmConfPresent, false);
  assertEquals(record.removedVolumeGroups, []);
  assertEquals(record.stoppedArrays, []);
  assertEquals(calls.some((c) => c.command.includes("vgremove")), false);
  assertEquals(calls.some((c) => c.command.includes("mdadm --stop")), false);
  // The config was absent, so no write or initramfs rebuild happened.
  assertEquals(calls.some((c) => c.command.startsWith("tee ")), false);
  assertEquals(
    calls.some((c) => c.command.includes("update-initramfs")),
    false,
  );
});

/** Routes serial discovery and the gate-3 lsblk for one raw NVMe disk. */
function discover(
  opts: RunOptions,
  tree: string = RAW_TREE,
): CommandResult | undefined {
  if (opts.command === listByIdCommand()) return done("nvme-SN0001\n");
  if (opts.command.startsWith("readlink")) return done("/dev/nvme0n1\n");
  if (opts.command === lsblkCommand()) return done(tree);
  if (opts.command.startsWith("mdadm --examine --scan")) return done("");
  if (opts.command.startsWith("pvs ")) return done("");
  return undefined;
}

/** A disk that still carries a filesystem signature, so it is not already raw. */
const DIRTY_TREE = JSON.stringify({
  blockdevices: [{
    name: "nvme0n1",
    path: "/dev/nvme0n1",
    mountpoint: null,
    type: "disk",
    fstype: "xfs",
  }],
});

const ARRAY_UUID = "7a0d6e3f:11112222:33334444:55556666";
const examineOut = (uuid = ARRAY_UUID) =>
  done(`/dev/x:\n     Array UUID : ${uuid}\n`);

/** Root on md0, whose members are sda1 and the candidate disk's partition. */
function rootArrayProbes(): Probes {
  const md = (children?: unknown[]) =>
    guardRow("md0", "raid1", { fstype: "ext4", mountpoints: ["/"] }, children);
  const member = (name: string) =>
    guardRow(name, "part", {
      fstype: "linux_raid_member",
      uuid: ARRAY_UUID.replaceAll(":", "-"),
    }, [md()]);
  return {
    lsblk: guardLsblk(
      guardRow("sda", "disk", {}, [member("sda1")]),
      guardRow("nvme0n1", "disk", {}, [member("nvme0n1p1")]),
    ),
    findmnt: done(
      JSON.stringify({
        filesystems: [{ target: "/", source: "/dev/md0", fstype: "ext4" }],
      }),
    ),
    fstab: done("/dev/md0 / ext4 defaults 0 1\n"),
    mdstat: done("md0 : active raid1 nvme0n1p1[1] sda1[0]\n"),
    "examine:/dev/sda1": examineOut(),
    "examine:/dev/nvme0n1p1": examineOut(),
  };
}

async function refusedWith(
  probes: Probes,
  phase: string,
  route: (opts: RunOptions) => CommandResult | undefined = discover,
): Promise<RunOptions[]> {
  const { session, calls } = routedSession(route, "192.0.2.10", probes);
  await assertRejects(
    () =>
      wipeDiskToRaw({ ...deps, session }, {
        dataDevices: [{ serial: "SN0001" }],
        excludeDevices: [],
      }),
    PhaseError,
    phase,
  );
  assertEquals(calls.some((c) => NO_DESTRUCTIVE.test(c.command)), false);
  assertEquals(
    calls.some((c) => c.command.startsWith("cp ")),
    false,
    "no backup or other host change happened",
  );
  return calls;
}

Deno.test("a disk under the active root array is refused before any mutation", async () => {
  await refusedWith(rootArrayProbes(), "wipe.boot-protected");
});

Deno.test("a member of an inactive array named by fstab is refused", async () => {
  await refusedWith({
    lsblk: guardLsblk(
      guardRow("sda", "disk", {}, [
        guardRow("sda1", "part", { fstype: "ext4", mountpoints: ["/"] }),
      ]),
      guardRow("nvme0n1", "disk", {}, [
        guardRow("nvme0n1p1", "part", {
          fstype: "linux_raid_member",
          uuid: ARRAY_UUID.replaceAll(":", "-"),
        }),
      ]),
    ),
    fstab: done(
      "/dev/sda1 / ext4 defaults 0 1\n/dev/md0 /data ext4 nofail 0 2\n",
    ),
    mdstat: done("md0 : inactive nvme0n1p1[1](S)\n"),
    "examine:/dev/nvme0n1p1": examineOut(),
  }, "wipe.boot-protected");
});

Deno.test("a dropped-out member of the root array is refused by array UUID", async () => {
  const probes = rootArrayProbes();
  // The candidate's partition is no longer in mdstat or under md0.
  probes.mdstat = done("md0 : active raid1 sda1[0]\n");
  probes.lsblk = guardLsblk(
    guardRow("sda", "disk", {}, [
      guardRow("sda1", "part", {
        fstype: "linux_raid_member",
        uuid: ARRAY_UUID.replaceAll(":", "-"),
      }, [guardRow("md0", "raid1", { fstype: "ext4", mountpoints: ["/"] })]),
    ]),
    guardRow("nvme0n1", "disk", {}, [
      guardRow("nvme0n1p1", "part", { fstype: "linux_raid_member" }),
    ]),
  );
  await refusedWith(probes, "wipe.boot-protected");
});

Deno.test("a PV of the root volume group is refused", async () => {
  await refusedWith({
    lsblk: guardLsblk(
      guardRow("sda", "disk", {}, [
        guardRow("sda1", "part", { fstype: "LVM2_member" }, [
          guardRow("vg0-root", "lvm", { fstype: "ext4", mountpoints: ["/"] }),
        ]),
      ]),
      guardRow("nvme0n1", "disk", { fstype: "LVM2_member" }),
    ),
    findmnt: done(
      JSON.stringify({
        filesystems: [{
          target: "/",
          source: "/dev/mapper/vg0-root",
          fstype: "ext4",
        }],
      }),
    ),
    fstab: done("/dev/mapper/vg0-root / ext4 defaults 0 1\n"),
    links: done("/dev/mapper/vg0-root /dev/dm-0\n"),
    pvs: done("  /dev/sda1  vg0\n  /dev/nvme0n1  vg0\n"),
  }, "wipe.boot-protected");
});

Deno.test("a ZFS root pool vdev reached through by-id is refused", async () => {
  await refusedWith({
    lsblk: guardLsblk(
      guardRow("nvme0n1", "disk", {}, [
        guardRow("nvme0n1p3", "part", { fstype: "zfs_member", label: "rpool" }),
      ]),
    ),
    findmnt: done(
      JSON.stringify({
        filesystems: [{
          target: "/",
          source: "rpool/ROOT/debian",
          fstype: "zfs",
        }],
      }),
    ),
    fstab: done(""),
    links: done("/dev/disk/by-id/nvme-EXAMPLE-part3 /dev/nvme0n1p3\n"),
    zpool: done(
      "  pool: rpool\nconfig:\n\n\tNAME  STATE\n\trpool  ONLINE\n\t  /dev/disk/by-id/nvme-EXAMPLE-part3  ONLINE\n\nerrors: none\n",
    ),
  }, "wipe.boot-protected");
});

Deno.test("every probe failure refuses as boot-unverifiable before any mutation", async () => {
  const failures: [string, Probes][] = [
    ["findmnt", { findmnt: done("", 1, "findmnt: failed") }],
    ["lsblk", { lsblk: done("", 1) }],
    ["fstab", { fstab: done("", 1, "cat: Input/output error") }],
    ["swaps", { swaps: done("", 1, "cat: Input/output error") }],
    ["links", { links: done("", 1) }],
  ];
  for (const [name, probes] of failures) {
    await refusedWith(probes, "wipe.boot-unverifiable");
    void name;
  }
  // mdadm and zpool errors matter when they guard something protected.
  const raid = rootArrayProbes();
  raid["examine:/dev/sda1"] = done("mdadm: error", 2);
  await refusedWith(raid, "wipe.boot-unverifiable");
  await refusedWith({
    lsblk: guardLsblk(guardRow("nvme0n1", "disk")),
    findmnt: done(
      JSON.stringify({
        filesystems: [{ target: "/", source: "rpool/ROOT/x", fstype: "zfs" }],
      }),
    ),
    fstab: done(""),
    zpool: done("", 1, "zpool: cannot open"),
  }, "wipe.boot-unverifiable");
});

Deno.test("sudo is used for the probes that need root", async () => {
  const { session, calls } = routedSession(discover, "192.0.2.10", {});
  await wipeDiskToRaw({ ...deps, session }, {
    dataDevices: [{ serial: "SN0001" }],
    excludeDevices: [],
    dryRun: true,
  });
  for (
    const cmd of [LSBLK_COMMAND, BLKID_COMMAND, ZPOOL_COMMAND, PVS_COMMAND]
  ) {
    assertEquals(calls.find((c) => c.command === cmd)?.sudo, true, cmd);
  }
});

Deno.test("the set is re-read and re-judged before the first change, and only grows", async () => {
  let reads = 0;
  let lsblkReads = 0;
  const probes: Probes = {
    fstab: done(""),
    findmnt: () => {
      reads++;
      // The second read finds the candidate's own partition mounted as root.
      return reads === 1 ? HEALTHY.findmnt as CommandResult : done(
        JSON.stringify({
          filesystems: [{
            target: "/",
            source: "/dev/nvme0n1p1",
            fstype: "ext4",
          }],
        }),
      );
    },
    lsblk: () =>
      ++lsblkReads <= 1 ? HEALTHY.lsblk as CommandResult : guardLsblk(
        guardRow("sda", "disk"),
        guardRow("nvme0n1", "disk", {}, [
          guardRow("nvme0n1p1", "part", { fstype: "ext4", mountpoints: ["/"] }),
        ]),
      ),
  };
  await refusedWith(
    probes,
    "wipe.boot-protected",
    (o) => discover(o, DIRTY_TREE),
  );
  assertEquals(reads, 2);
});

Deno.test("a healthy host passes both reads and the wipe proceeds", async () => {
  const { session, calls } = routedSession((opts) => {
    const base = discover(opts, DIRTY_TREE);
    if (base) return base;
    if (opts.command === "test -e /etc/mdadm/mdadm.conf") return done("", 1);
    if (opts.command.startsWith("mdadm --detail --scan")) return done("");
    if (opts.command === "cat /etc/fstab") {
      return done("/dev/sda1 / ext4 defaults 0 1\n");
    }
    if (
      /^(mdadm --zero-superblock|wipefs -a|sgdisk|partprobe)/.test(opts.command)
    ) {
      return done("");
    }
    return undefined;
  });
  const record = await wipeDiskToRaw({ ...deps, session }, {
    dataDevices: [{ serial: "SN0001" }],
    excludeDevices: [],
  });
  assertEquals(record.dryRun, false);
  // Two reads of the root mount table: the gate and the re-validation.
  assertEquals(calls.filter((c) => c.command === FINDMNT_COMMAND).length, 2);
});

Deno.test("a udev-less host (empty lsblk type columns, no blkid) refuses before any mutation", async () => {
  await refusedWith({
    lsblk: guardLsblk(
      guardRow("sda", "disk", {}, [
        guardRow("sda1", "part", { mountpoints: ["/"] }),
      ]),
      guardRow("nvme0n1", "disk"),
    ),
    blkid: done("", 127),
  }, "wipe.boot-unverifiable");
});

Deno.test("mdadm's not-a-member answer is read from stderr", async () => {
  // The default NO_SUPERBLOCK fixture puts the text on stderr like real mdadm;
  // a host where only stdout carries it would be refused as unverifiable.
  await refusedWith({
    "examine:/dev/nvme0n1": done(
      "",
      1,
      "mdadm: cannot open /dev/nvme0n1: Permission denied\n",
    ),
  }, "wipe.boot-unverifiable");
});

Deno.test("a failed mdadm --examine before --stop refuses and nothing is stopped", async () => {
  let examines = 0;
  const probes: Probes = {
    // Reads 1 and 2 are the two guard passes; read 3 is the belt check.
    "examine:/dev/nvme0n1": () => {
      examines++;
      return examines <= 2 ? NO_SUPERBLOCK : done("", 2, "mdadm: error\n");
    },
  };
  const { session, calls } = routedSession(
    (opts) => {
      if (opts.command.startsWith("mdadm --examine --scan")) {
        return done("ARRAY /dev/md9 metadata=1.2 name=host:9 UUID=abc\n");
      }
      if (opts.command === "test -e /etc/mdadm/mdadm.conf") return done("", 1);
      if (opts.command.startsWith("mdadm --detail --scan")) return done("");
      if (opts.command === "cat /etc/fstab") return done("");
      return discover(opts, DIRTY_TREE);
    },
    "192.0.2.10",
    probes,
  );
  await assertRejects(
    () =>
      wipeDiskToRaw({ ...deps, session }, {
        dataDevices: [{ serial: "SN0001" }],
        excludeDevices: [],
      }),
    PhaseError,
    "wipe.boot-unverifiable",
  );
  assertEquals(examines, 3);
  assertEquals(calls.some((c) => c.command.startsWith("mdadm --stop")), false);
});

Deno.test("no mdadm command is ever given `--` (mdadm 4.3 reads it as 'no devices')", async () => {
  const { session, calls } = routedSession((opts) => {
    const base = discover(opts, DIRTY_TREE);
    if (base) return base;
    if (opts.command === "test -e /etc/mdadm/mdadm.conf") return done("", 1);
    if (opts.command.startsWith("mdadm --detail --scan")) return done("");
    if (opts.command === "cat /etc/fstab") return done("");
    if (
      /^(mdadm --zero-superblock|wipefs -a|sgdisk|partprobe)/.test(
        opts.command,
      )
    ) {
      return done("");
    }
    return undefined;
  });
  await wipeDiskToRaw({ ...deps, session }, {
    dataDevices: [{ serial: "SN0001" }],
    excludeDevices: [],
  });
  const mdadm = calls.map((c) => c.command).filter((c) =>
    c.startsWith("mdadm ")
  );
  assertEquals(mdadm.length > 0, true);
  for (const c of mdadm) assertEquals(/ -- /.test(c), false, c);
  assertEquals(
    mdadm.includes("mdadm --zero-superblock '/dev/nvme0n1'"),
    true,
  );
  assertEquals(
    mdadm.some((c) => c === "mdadm --examine --scan '/dev/nvme0n1'"),
    true,
  );
});

Deno.test("an array stopped by the wipe is named bare, after the grammar check", async () => {
  let stopped = false;
  let examines = 0;
  const probes: Probes = {
    // The two guard reads see no superblock; the belt check before --stop
    // then sees the array's own (unprotected) UUID.
    "examine:/dev/nvme0n1": () =>
      ++examines <= 2 ? NO_SUPERBLOCK : examineOut(),
  };
  const { session, calls } = routedSession(
    (opts) => {
      if (opts.command.startsWith("mdadm --examine --scan")) {
        return done("ARRAY /dev/md9 metadata=1.2 name=host:9 UUID=abc\n");
      }
      if (opts.command.startsWith("mdadm --stop")) {
        stopped = true;
        return done("");
      }
      if (opts.command === "cat /proc/mdstat") {
        return done(stopped ? "" : "md9 : active raid1 nvme0n1[0]\n");
      }
      if (opts.command === "test -e /etc/mdadm/mdadm.conf") return done("", 1);
      if (opts.command.startsWith("mdadm --detail --scan")) return done("");
      if (opts.command === "cat /etc/fstab") return done("");
      if (
        /^(mdadm --zero-superblock|wipefs -a|sgdisk|partprobe)/.test(
          opts.command,
        )
      ) {
        return done("");
      }
      return discover(opts, DIRTY_TREE);
    },
    "192.0.2.10",
    probes,
  );
  await wipeDiskToRaw({ ...deps, session }, {
    dataDevices: [{ serial: "SN0001" }],
    excludeDevices: [],
  }).catch(() => undefined);
  const stops = calls.map((c) => c.command).filter((c) =>
    c.startsWith("mdadm --stop")
  );
  assertEquals(stops.length > 0, true);
  for (const c of stops) assertEquals(c, "mdadm --stop '/dev/md9'");
});
