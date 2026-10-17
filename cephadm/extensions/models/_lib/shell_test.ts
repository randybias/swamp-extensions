import {
  assertEquals,
  assertRejects,
  assertThrows,
} from "jsr:@std/assert@1.0.19";
import { PhaseError } from "./errors.ts";
import type { CommandResult, RunOptions, SshSession } from "./ssh.ts";
import {
  cephScriptBody,
  parseCephJson,
  parseMktempDir,
  randomHex,
  runCeph,
  shellRunCommand,
  writeScriptCommand,
} from "./shell.ts";

function fakeSession(
  route: (opts: RunOptions) => CommandResult,
): { session: SshSession; calls: RunOptions[] } {
  const calls: RunOptions[] = [];
  const session: SshSession = {
    target: { host: "192.0.2.10", user: "admin", strictHostKeyChecking: "yes" },
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

Deno.test("randomHex returns the requested length of hex characters", () => {
  const hex = randomHex(() => 0.5, 12);
  assertEquals(hex.length, 12);
  assertEquals(/^[0-9a-f]{12}$/.test(hex), true);
});

Deno.test(
  "the script body carries the interpreter contract and never bash -c", // leak-allow(decision D7)
  () => {
    const body = cephScriptBody("orch ls", true);
    assertEquals(body.startsWith("#!/bin/bash\nset -euo pipefail\n"), true);
    assertEquals(body.includes("ceph orch ls -f json"), true);
    assertEquals(cephScriptBody("fsid", false).includes("ceph fsid\n"), true);
    const run = shellRunCommand("/tmp/x", "/tmp/x/run.sh");
    assertEquals(
      run.startsWith("cephadm shell --mount '/tmp/x:/tmp/x' -- bash"),
      true,
    );
    assertEquals(run.includes("bash -c"), false);
    const write = writeScriptCommand("/tmp/x/run.sh");
    assertEquals(write.includes("cat > '/tmp/x/run.sh'"), true);
    assertEquals(write.includes("chmod '0700' '/tmp/x/run.sh'"), true);
  },
);

Deno.test("the lone not-reported line parses as an empty list", () => {
  assertEquals(parseCephJson("No services reported", "x"), []);
  assertEquals(parseCephJson('{"a":1}', "x"), { a: 1 });
  assertEquals(parseCephJson("[1,2]", "x"), [1, 2]);
  try {
    parseCephJson("not json at all", "wipe");
    throw new Error("should throw");
  } catch (e) {
    assertEquals(e instanceof PhaseError, true);
    assertEquals((e as PhaseError).phase, "wipe.json");
  }
});

Deno.test(
  "a shell call writes a private script, runs it mounted and removes the dir", // leak-allow(decision D7)
  async () => {
    const warns: string[] = [];
    const { session, calls } = fakeSession((opts) => {
      if (opts.command.startsWith("mktemp -d")) {
        return { code: 0, stdout: "/tmp/cephadm-shell.ABCDEF\n", stderr: "" };
      }
      if (opts.command.startsWith("umask 022")) {
        return { code: 0, stdout: "", stderr: "" };
      }
      if (opts.command.startsWith("cephadm shell")) {
        return { code: 0, stdout: '{"ok":true}', stderr: "" };
      }
      if (opts.command.startsWith("rm -rf")) {
        return { code: 0, stdout: "", stderr: "" };
      }
      throw new Error(`unexpected ${opts.command}`);
    });
    const out = await runCeph(deps, session, "orch ls", {
      json: true,
      phase: "x",
    }, {
      warn: (m) => warns.push(m),
    });
    assertEquals(out.json, { ok: true });
    const write = calls.find((c) => c.command.startsWith("umask 022"))!;
    assertEquals(
      /\/tmp\/cephadm-shell\.ABCDEF\/run-[0-9a-f]{12}\.sh/.test(write.command),
      true,
    );
    assertEquals(
      write.stdin?.startsWith("#!/bin/bash\nset -euo pipefail\n"),
      true,
    );
    const run = calls.find((c) => c.command.startsWith("cephadm shell"))!;
    assertEquals(run.sudo, true);
    assertEquals(calls.some((c) => c.command.startsWith("rm -rf")), true);
    assertEquals(warns.length, 0);
  },
);

Deno.test("the cephadm-shell budget floor is raised and warned", async () => {
  const warns: string[] = [];
  const { session, calls } = fakeSession((opts) => {
    if (opts.command.startsWith("mktemp -d")) {
      return { code: 0, stdout: "/tmp/cephadm-shell.ABCDEX\n", stderr: "" };
    }
    if (opts.command.startsWith("umask 022")) {
      return { code: 0, stdout: "", stderr: "" };
    }
    if (opts.command.startsWith("cephadm shell")) {
      return { code: 0, stdout: "[]", stderr: "" };
    }
    return { code: 0, stdout: "", stderr: "" };
  });
  await runCeph(deps, session, "fsid", { phase: "x", budgetMs: 30_000 }, {
    warn: (m) => warns.push(m),
  });
  const run = calls.find((c) => c.command.startsWith("cephadm shell"))!;
  assertEquals(run.budgetMs, 5 * 60 * 1000);
  assertEquals(warns.length, 1);

  const { session: s2, calls: c2 } = fakeSession((opts) => {
    if (opts.command.startsWith("mktemp -d")) {
      return { code: 0, stdout: "/tmp/cephadm-shell.ABCDEY\n", stderr: "" };
    }
    if (opts.command.startsWith("umask 022")) {
      return { code: 0, stdout: "", stderr: "" };
    }
    if (opts.command.startsWith("cephadm shell")) {
      return { code: 0, stdout: "[]", stderr: "" };
    }
    return { code: 0, stdout: "", stderr: "" };
  });
  await runCeph(deps, s2, "fsid", { phase: "x", budgetMs: 10 * 60 * 1000 });
  assertEquals(
    c2.find((c) => c.command.startsWith("cephadm shell"))!.budgetMs,
    600_000,
  );
});

Deno.test("a removal failure warns and does not mask the command result", async () => {
  const warns: string[] = [];
  const { session } = fakeSession((opts) => {
    if (opts.command.startsWith("mktemp -d")) {
      return { code: 0, stdout: "/tmp/cephadm-shell.ABCDEZ\n", stderr: "" };
    }
    if (opts.command.startsWith("umask 022")) {
      return { code: 0, stdout: "", stderr: "" };
    }
    if (opts.command.startsWith("cephadm shell")) {
      return { code: 0, stdout: "[]", stderr: "" };
    }
    if (opts.command.startsWith("rm -rf")) throw new Error("connection lost");
    return { code: 0, stdout: "", stderr: "" };
  });
  const out = await runCeph(deps, session, "fsid", { json: true, phase: "x" }, {
    warn: (m) => warns.push(m),
  });
  assertEquals(out.json, []);
  assertEquals(warns.length, 1);
});

Deno.test("a non-JSON shell read fails with a phase-attributed error", async () => {
  const { session } = fakeSession((opts) => {
    if (opts.command.startsWith("mktemp -d")) {
      return { code: 0, stdout: "/tmp/cephadm-shell.ABCDEQ\n", stderr: "" };
    }
    if (opts.command.startsWith("umask 022")) {
      return { code: 0, stdout: "", stderr: "" };
    }
    if (opts.command.startsWith("cephadm shell")) {
      return { code: 0, stdout: "nonsense", stderr: "" };
    }
    return { code: 0, stdout: "", stderr: "" };
  });
  await assertRejects(
    () => runCeph(deps, session, "orch ls", { json: true, phase: "pkgsource" }),
    PhaseError,
    "pkgsource.json",
  );
});

Deno.test(
  "mktemp output must be one directory under the fixed prefix", // leak-allow(decision D7)
  () => {
    assertEquals(
      parseMktempDir("/tmp/cephadm-shell.ABCDEF\n", "x"),
      "/tmp/cephadm-shell.ABCDEF",
    );
    for (
      const bad of [
        "/home/admin\n",
        "/tmp/cephadm-shell.ABCDEF\n/tmp/other\n",
        "/tmp/evil.ABCDEF\n",
        "/tmp/cephadm-shell.\n",
        "/tmp/cephadm-shell.AB\n",
        "",
      ]
    ) {
      assertThrows(() => parseMktempDir(bad, "x"), PhaseError);
    }
  },
);
