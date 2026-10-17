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
    target: { host, user: "admin" },
    controlPath: null,
    run: (opts) => {
      calls.push(opts);
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
