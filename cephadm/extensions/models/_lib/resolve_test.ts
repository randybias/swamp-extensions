import { assertEquals, assertRejects } from "jsr:@std/assert@1.0.19";
import { PhaseError } from "./errors.ts";
import {
  candidateNames,
  distinctDevices,
  isPartitionLink,
  listByIdCommand,
  matchesSerial,
  readlinkCommand,
  resolveSerial,
} from "./resolve.ts";
import type { CommandResult, RunOptions, SshSession } from "./ssh_session.ts";

function fakeSession(
  route: (opts: RunOptions) => CommandResult,
  host = "192.0.2.10",
): { session: SshSession; calls: RunOptions[] } {
  const calls: RunOptions[] = [];
  const session: SshSession = {
    target: { host, port: 22 },
    run: (opts) => {
      calls.push(opts);
      return Promise.resolve(route(opts));
    },
    close: () => Promise.resolve({ closed: false, detail: "not multiplexed" }),
  };
  return { session, calls };
}

Deno.test(
  "a serial matches only a whole trailing segment", // leak-allow(decision D4)
  () => {
    assertEquals(matchesSerial("ata-MODEL_SN0001", "SN0001"), true);
    assertEquals(matchesSerial("scsi-SATA_MODEL-SN0001", "SN0001"), true);
    assertEquals(matchesSerial("nvme-MODEL_SN0001_1", "SN0001"), true);
    assertEquals(matchesSerial("nvme-MODEL_SN0001_12", "SN0001"), true);
    // A prefix/suffix of another serial must not match.
    assertEquals(matchesSerial("nvme-MODEL_SN00012", "SN0001"), false);
    assertEquals(matchesSerial("nvme-SN0001-MODEL", "SN0001"), false);
  },
);

Deno.test(
  "candidates drop partitions and non-charset names", // leak-allow(decision D6)
  () => {
    assertEquals(isPartitionLink("nvme-MODEL_SN0001-part1"), true);
    const names = [
      "nvme-MODEL_SN0001",
      "nvme-MODEL_SN0001-part1",
      "wwn-0x5000_SN0001",
      "bad name SN0001",
      "bad$SN0001",
      "nvme-MODEL_SN0001_1",
    ];
    assertEquals(candidateNames(names, "SN0001"), [
      "nvme-MODEL_SN0001",
      "wwn-0x5000_SN0001",
      "nvme-MODEL_SN0001_1",
    ]);
  },
);

Deno.test("distinctDevices deduplicates and sorts", () => {
  assertEquals(distinctDevices("/dev/sdb\n/dev/sda\n/dev/sdb\n\n"), [
    "/dev/sda",
    "/dev/sdb",
  ]);
});

Deno.test(
  "the listing command carries no serial and no serial glob", // leak-allow(decision D3)
  () => {
    const listing = listByIdCommand();
    assertEquals(listing.includes("by-id"), true);
    assertEquals(listing.includes("*"), true); // a bare /dev/disk/by-id/* glob is fine
    assertEquals(listing.includes("SN"), false);
    const readlink = readlinkCommand([
      "/dev/disk/by-id/a",
      "/dev/disk/by-id/b",
    ]);
    assertEquals(readlink.startsWith("readlink -f"), true);
    assertEquals(readlink.includes("sort -u"), true);
    assertEquals(readlink.includes("*"), false);
    assertEquals(readlink.includes("'/dev/disk/by-id/a'"), true);
  },
);

Deno.test(
  "one link resolves to a path and a device in exactly two calls", // leak-allow(decision D5)
  async () => {
    const { session, calls } = fakeSession((opts) => {
      if (opts.command === listByIdCommand()) {
        return { code: 0, stdout: "nvme-MODEL_SN000000000A\n", stderr: "" };
      }
      if (opts.command.startsWith("readlink")) {
        return { code: 0, stdout: "/dev/nvme0n1\n", stderr: "" };
      }
      throw new Error(`unexpected ${opts.command}`);
    });
    const result = await resolveSerial(session, "SN000000000A", "wipe.resolve");
    assertEquals(result, {
      path: "/dev/disk/by-id/nvme-MODEL_SN000000000A",
      device: "/dev/nvme0n1",
    });
    assertEquals(calls.length, 2);
    assertEquals(calls[0].sudo ?? false, false);
    assertEquals(calls[0].command.includes("SN000000000A"), false);
    assertEquals(
      calls[1].command.includes("'/dev/disk/by-id/nvme-MODEL_SN000000000A'"),
      true,
    );
  },
);

Deno.test(
  "an invalid serial is refused before any ssh call", // leak-allow(decision D3)
  async () => {
    const { session, calls } = fakeSession(() => {
      throw new Error("should not be called");
    });
    await assertRejects(
      () => resolveSerial(session, "SN*", "wipe.resolve"),
      PhaseError,
      "validate",
    );
    await assertRejects(
      () => resolveSerial(session, "SN; id", "wipe.resolve"),
      PhaseError,
    );
    assertEquals(calls.length, 0);
  },
);

Deno.test("zero matches is a caller-phase failure", async () => {
  const { session } = fakeSession(() => ({ code: 0, stdout: "", stderr: "" }));
  await assertRejects(
    () => resolveSerial(session, "SN0001", "wipe.resolve"),
    PhaseError,
    "serial resolved to zero devices",
  );
});

Deno.test("two matching links onto two devices is ambiguous", async () => {
  const { session } = fakeSession((opts) => {
    if (opts.command === listByIdCommand()) {
      return {
        code: 0,
        stdout: "ata-MODEL_SN0001\nscsi-SATA_MODEL_SN0001\n",
        stderr: "",
      };
    }
    return { code: 0, stdout: "/dev/sda\n/dev/sdb\n", stderr: "" };
  });
  await assertRejects(
    () => resolveSerial(session, "SN0001", "cephApplyOsd:gate-resolve"),
    PhaseError,
    "several devices",
  );
});

Deno.test("partition links are ignored and several links onto one device resolve smallest", async () => {
  const { session, calls } = fakeSession((opts) => {
    if (opts.command === listByIdCommand()) {
      return {
        code: 0,
        stdout:
          "scsi-SN0001\nata-SN0001\nnvme-SN0001-part1\nnvme-SN0001-part2\n",
        stderr: "",
      };
    }
    return { code: 0, stdout: "/dev/nvme0n1\n", stderr: "" };
  });
  const result = await resolveSerial(session, "SN0001", "wipe.resolve");
  assertEquals(result.path, "/dev/disk/by-id/ata-SN0001");
  const readlink = calls.find((c) => c.command.startsWith("readlink"))!;
  assertEquals(readlink.command.includes("-part"), false);
});

Deno.test(
  "an implausible resolved device is refused", // leak-allow(decision D6)
  async () => {
    const { session } = fakeSession((opts) => {
      if (opts.command === listByIdCommand()) {
        return { code: 0, stdout: "nvme-SN0001\n", stderr: "" };
      }
      return { code: 0, stdout: "; rm -rf /\n", stderr: "" };
    });
    await assertRejects(
      () => resolveSerial(session, "SN0001", "wipe.resolve"),
      PhaseError,
      "not a plausible device path",
    );
  },
);

Deno.test("posix device names are accepted unchanged", async () => {
  for (const device of ["/dev/nvme0n1", "/dev/sda", "/dev/md0", "/dev/dm-0"]) {
    const { session } = fakeSession((opts) => {
      if (opts.command === listByIdCommand()) {
        return { code: 0, stdout: "nvme-SN0001\n", stderr: "" };
      }
      return { code: 0, stdout: `${device}\n`, stderr: "" };
    });
    assertEquals(
      (await resolveSerial(session, "SN0001", "wipe.resolve")).device,
      device,
    );
  }
});
