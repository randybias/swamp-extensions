import { assertEquals, assertRejects } from "jsr:@std/assert@1.0.19";
import { PhaseError } from "./errors.ts";
import { listByIdCommand } from "./resolve.ts";
import type { CommandResult, RunOptions, SshSession } from "./ssh.ts";
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

function fakeSession(
  route: (opts: RunOptions) => CommandResult,
  host = "192.0.2.10",
): { session: SshSession; calls: RunOptions[] } {
  const calls: RunOptions[] = [];
  const session: SshSession = {
    target: { host, user: "admin", strictHostKeyChecking: "yes" },
    controlPath: null,
    run: (opts) => {
      calls.push(opts);
      // No boot filesystem is mounted in these fixtures.
      if (opts.command.startsWith("findmnt")) {
        return Promise.resolve({ code: 1, stdout: "", stderr: "" });
      }
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
): { session: SshSession; calls: RunOptions[] } {
  const calls: RunOptions[] = [];
  const session: SshSession = {
    target: { host, user: "admin", strictHostKeyChecking: "yes" },
    controlPath: null,
    run: (opts) => {
      calls.push(opts);
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

Deno.test(
  "a disk behind an active root array is refused before any mutation", // leak-allow(decision D3)
  async () => {
    const tree = JSON.stringify({
      blockdevices: [
        {
          name: "md0",
          path: "/dev/md0",
          type: "raid1",
          fstype: "ext4",
          mountpoint: "/",
          children: [{
            name: "nvme0n1",
            path: "/dev/nvme0n1",
            type: "disk",
            fstype: null,
          }],
        },
      ],
    });
    const { session, calls } = routedSession((opts) => {
      if (opts.command === listByIdCommand()) {
        return { code: 0, stdout: "nvme-SN0001\n", stderr: "" };
      }
      if (
        opts.command === "readlink -f '/dev/disk/by-id/nvme-SN0001' | sort -u"
      ) {
        return { code: 0, stdout: "/dev/nvme0n1\n", stderr: "" };
      }
      if (opts.command === lsblkCommand()) {
        return { code: 0, stdout: tree, stderr: "" };
      }
      if (opts.command === "findmnt -rno SOURCE,TARGET") {
        return { code: 0, stdout: "/dev/md0 /\n", stderr: "" };
      }
      if (opts.command.startsWith("findmnt --fstab")) {
        return { code: 1, stdout: "", stderr: "" };
      }
      if (opts.command.startsWith("readlink -f '/dev/md0'")) {
        return { code: 0, stdout: "/dev/md0\n", stderr: "" };
      }
      if (opts.command.startsWith("mdadm --detail ")) {
        return {
          code: 0,
          stdout:
            "     0       8       16        0      active sync   /dev/nvme0n1\n",
          stderr: "",
        };
      }
      return undefined;
    });
    await assertRejects(
      () =>
        wipeDiskToRaw({ ...deps, session }, {
          dataDevices: [{ serial: "SN0001" }],
          excludeDevices: [],
        }),
      PhaseError,
      "boot-protected",
    );
    assertEquals(calls.some((c) => NO_DESTRUCTIVE.test(c.command)), false);
  },
);

Deno.test(
  "a member of an inactive boot array named by fstab is refused", // leak-allow(decision D3)
  async () => {
    const { session, calls } = routedSession((opts) => {
      if (opts.command === listByIdCommand()) {
        return { code: 0, stdout: "nvme-SN0001\n", stderr: "" };
      }
      if (
        opts.command === "readlink -f '/dev/disk/by-id/nvme-SN0001' | sort -u"
      ) {
        return { code: 0, stdout: "/dev/nvme0n1\n", stderr: "" };
      }
      if (opts.command === lsblkCommand()) {
        return { code: 0, stdout: RAW_TREE, stderr: "" };
      }
      if (opts.command === "findmnt -rno SOURCE,TARGET") {
        return { code: 1, stdout: "", stderr: "" };
      }
      if (opts.command.startsWith("findmnt --fstab")) {
        return {
          code: 0,
          stdout: "/dev/md0 /boot ext4 defaults 0 0\n",
          stderr: "",
        };
      }
      if (opts.command.startsWith("readlink -f '/dev/md0'")) {
        return { code: 0, stdout: "/dev/md0\n", stderr: "" };
      }
      if (opts.command.startsWith("mdadm --detail ")) {
        return { code: 0, stdout: "", stderr: "" };
      }
      if (opts.command.startsWith("mdadm --examine")) {
        return {
          code: 0,
          stdout: "ARRAY /dev/md0 metadata=1.2 name=host:0 UUID=abc\n",
          stderr: "",
        };
      }
      return undefined;
    });
    await assertRejects(
      () =>
        wipeDiskToRaw({ ...deps, session }, {
          dataDevices: [{ serial: "SN0001" }],
          excludeDevices: [],
        }),
      PhaseError,
      "boot-protected",
    );
    assertEquals(calls.some((c) => NO_DESTRUCTIVE.test(c.command)), false);
  },
);

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

Deno.test(
  "root on a plain md array protects every member disk", // leak-allow(decision D3)
  async () => {
    const tree = JSON.stringify({
      blockdevices: [
        {
          name: "sda",
          path: "/dev/sda",
          type: "disk",
          fstype: null,
          children: [{
            name: "md0",
            path: "/dev/md0",
            type: "raid1",
            fstype: null,
            children: [{
              name: "md0p1",
              path: "/dev/md0p1",
              type: "part",
              fstype: "ext4",
              mountpoint: "/",
            }],
          }],
        },
        {
          name: "sdb",
          path: "/dev/sdb",
          type: "disk",
          fstype: null,
          children: [{
            name: "md0",
            path: "/dev/md0",
            type: "raid1",
            fstype: null,
          }],
        },
      ],
    });
    const { session, calls } = routedSession((opts) => {
      if (opts.command === listByIdCommand()) {
        return { code: 0, stdout: "sdb-SN0001\n", stderr: "" };
      }
      if (opts.command.startsWith("readlink -f '/dev/disk/by-id/")) {
        return { code: 0, stdout: "/dev/sdb\n", stderr: "" };
      }
      if (opts.command === lsblkCommand()) {
        return { code: 0, stdout: tree, stderr: "" };
      }
      if (opts.command === "findmnt -rno SOURCE,TARGET") {
        return { code: 0, stdout: "/dev/md0p1 /\n", stderr: "" };
      }
      if (opts.command.startsWith("findmnt --fstab")) {
        return { code: 1, stdout: "", stderr: "" };
      }
      if (opts.command.startsWith("readlink -f '/dev/md0p1'")) {
        return { code: 0, stdout: "/dev/md0p1\n", stderr: "" };
      }
      return undefined;
    });
    await assertRejects(
      () =>
        wipeDiskToRaw({ ...deps, session }, {
          dataDevices: [{ serial: "SN0001" }],
          excludeDevices: [],
        }),
      PhaseError,
      "boot-protected",
    );
    assertEquals(calls.some((c) => NO_DESTRUCTIVE.test(c.command)), false);
  },
);

Deno.test(
  "root on LVM over md protects the md device and its members", // leak-allow(decision D3)
  async () => {
    const tree = JSON.stringify({
      blockdevices: [
        {
          name: "sda",
          path: "/dev/sda",
          type: "disk",
          fstype: null,
          children: [{
            name: "md0",
            path: "/dev/md0",
            type: "raid1",
            fstype: null,
            children: [{
              name: "dm-0",
              path: "/dev/dm-0",
              type: "lvm",
              fstype: "ext4",
            }],
          }],
        },
        {
          name: "sdb",
          path: "/dev/sdb",
          type: "disk",
          fstype: null,
          children: [{
            name: "md0",
            path: "/dev/md0",
            type: "raid1",
            fstype: null,
          }],
        },
      ],
    });
    const { session, calls } = routedSession((opts) => {
      if (opts.command === listByIdCommand()) {
        return { code: 0, stdout: "sdb-SN0001\n", stderr: "" };
      }
      if (opts.command.startsWith("readlink -f '/dev/disk/by-id/")) {
        return { code: 0, stdout: "/dev/sdb\n", stderr: "" };
      }
      if (opts.command === lsblkCommand()) {
        return { code: 0, stdout: tree, stderr: "" };
      }
      if (opts.command === "findmnt -rno SOURCE,TARGET") {
        return { code: 0, stdout: "/dev/mapper/vg-root /\n", stderr: "" };
      }
      if (opts.command.startsWith("findmnt --fstab")) {
        return { code: 1, stdout: "", stderr: "" };
      }
      if (opts.command.startsWith("readlink -f '/dev/mapper/vg-root'")) {
        return { code: 0, stdout: "/dev/dm-0\n", stderr: "" };
      }
      return undefined;
    });
    await assertRejects(
      () =>
        wipeDiskToRaw({ ...deps, session }, {
          dataDevices: [{ serial: "SN0001" }],
          excludeDevices: [],
        }),
      PhaseError,
      "boot-protected",
    );
    assertEquals(calls.some((c) => NO_DESTRUCTIVE.test(c.command)), false);
  },
);
