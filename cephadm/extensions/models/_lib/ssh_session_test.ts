/**
 * Tests for the cephadm session layer: error classification, the default
 * timeout, the mutually-exclusive key sources, and TOFU pin persistence.
 *
 * @module
 */

import {
  assertEquals,
  assertRejects,
  assertThrows,
} from "jsr:@std/assert@1.0.19";
import type { CommandRunner, RunOptions } from "./ssh.ts";
import { LocalRefusalError, PhaseError } from "./errors.ts";
import {
  openSession,
  type SessionContext,
  type SshDeps,
  toTarget,
} from "./ssh_session.ts";
import { runStep } from "./ssh_session.ts";

const BLOB = "AAAAC3NzaC1lZDI1NTE5AAAAIFakeKey";
const KEY_LINE = `192.0.2.10 ssh-ed25519 ${BLOB}`;

interface Call {
  cmd: string;
  args: string[];
  options: RunOptions;
}

function fakeRunner(
  handler: (cmd: string, args: string[], options: RunOptions) => {
    code: number;
    stdout: string;
    stderr: string;
  },
): { run: CommandRunner; calls: Call[] } {
  const calls: Call[] = [];
  const run: CommandRunner = (cmd, args, options = {}) => {
    calls.push({ cmd, args, options });
    return Promise.resolve(handler(cmd, args, options));
  };
  return { run, calls };
}

function storeContext(): {
  context: SessionContext;
  written: { specName: string; name: string; data: Record<string, unknown> }[];
} {
  const store = new Map<string, Record<string, unknown>>();
  const written: {
    specName: string;
    name: string;
    data: Record<string, unknown>;
  }[] = [];
  return {
    written,
    context: {
      readResource: (name) => Promise.resolve(store.get(name) ?? null),
      writeResource: (specName, name, data) => {
        written.push({ specName, name, data });
        store.set(name, data);
        return Promise.resolve({});
      },
    },
  };
}

const REQUEST = {
  host: "192.0.2.10",
  sshUser: "admin",
  port: null,
  keyPath: null,
  privateKey: null,
  host_key_policy: "insecure_tofu" as const,
  host_keys: null,
};

Deno.test("a mid-session reset or auth failure is outcome-unknown and not re-sent", async () => {
  for (
    const stderr of [
      "Read from remote host 192.0.2.10: Connection reset by peer",
      "client_loop: send disconnect: Connection reset by peer",
      "admin@192.0.2.10: Permission denied (publickey).",
    ]
  ) {
    const fake = fakeRunner((cmd) =>
      cmd === "ssh"
        ? { code: 255, stdout: "", stderr }
        : { code: 0, stdout: "", stderr: "" }
    );
    const deps: SshDeps = {
      run: fake.run,
      now: () => 0,
      sleep: () => Promise.resolve(),
    };
    const { context } = storeContext();
    const session = await openSession(
      deps,
      toTarget({
        ...REQUEST,
        host_key_policy: "strict",
        host_keys: [KEY_LINE],
      }),
      context,
    );
    let error: unknown;
    try {
      await runStep(
        { sleep: deps.sleep },
        session,
        { command: "true", phase: "t", resend: "dropped" },
      );
    } catch (e) {
      error = e;
    }
    assertEquals(error instanceof PhaseError, true, stderr);
    assertEquals(
      fake.calls.filter((c) => c.cmd === "ssh").length,
      1,
      "exactly one ssh spawn",
    );
  }
});

Deno.test("a call without budgetMs keeps the 30s + 5s default timeout", async () => {
  const fake = fakeRunner(() => ({ code: 0, stdout: "", stderr: "" }));
  const deps: SshDeps = {
    run: fake.run,
    now: () => 0,
    sleep: () => Promise.resolve(),
  };
  const { context } = storeContext();
  const session = await openSession(
    deps,
    toTarget({ ...REQUEST, host_key_policy: "strict", host_keys: [KEY_LINE] }),
    context,
  );
  await session.run({ command: "true" });
  assertEquals(fake.calls[0].options.timeoutMs, 35_000);
  await session.run({ command: "true", budgetMs: 1_000 });
  assertEquals(fake.calls[1].options.timeoutMs, 6_000);
});

Deno.test("toTarget refuses keyPath and privateKey together", () => {
  assertThrows(
    () =>
      toTarget({
        ...REQUEST,
        keyPath: "/home/admin/.ssh/id",
        privateKey: "KEY\n",
      }),
    LocalRefusalError,
    "exactly one",
  );
  assertThrows(
    () => toTarget({ ...REQUEST, host_key_policy: undefined as never }),
    LocalRefusalError,
    "host_key_policy",
  );
});

Deno.test("openSession learns once, persists after the first run, then reuses", async () => {
  const fake = fakeRunner((cmd, args) => {
    if (cmd === "ssh-keyscan") {
      return {
        code: 0,
        stdout: `${args.at(-1)} ssh-ed25519 ${BLOB}\n`,
        stderr: "",
      };
    }
    return { code: 0, stdout: "ok", stderr: "" };
  });
  const deps: SshDeps = {
    run: fake.run,
    now: () => 0,
    sleep: () => Promise.resolve(),
  };
  const { context, written } = storeContext();
  const session = await openSession(deps, toTarget(REQUEST), context);
  assertEquals(written.length, 0, "nothing persisted before the run");
  const res = await session.run({ command: "true" });
  assertEquals(res.stdout, "ok");
  assertEquals(fake.calls.filter((c) => c.cmd === "ssh-keyscan").length, 1);
  assertEquals(written.length, 1);
  assertEquals(written[0].name, "hostkeys-192.0.2.10-22");
  // The second session reads the persisted pin and makes no keyscan.
  const session2 = await openSession(deps, toTarget(REQUEST), context);
  await session2.run({ command: "true" });
  assertEquals(fake.calls.filter((c) => c.cmd === "ssh-keyscan").length, 1);
});

Deno.test("openSession refuses a bare pin before any connection", async () => {
  const fake = fakeRunner(() => ({ code: 0, stdout: "", stderr: "" }));
  const deps: SshDeps = {
    run: fake.run,
    now: () => 0,
    sleep: () => Promise.resolve(),
  };
  const { context } = storeContext();
  await assertRejects(
    () =>
      openSession(
        deps,
        toTarget({
          ...REQUEST,
          host_key_policy: "strict",
          host_keys: [`ssh-ed25519 ${BLOB}`],
        }),
        context,
      ),
    LocalRefusalError,
    "must name its host",
  );
  assertEquals(fake.calls.length, 0);
});
