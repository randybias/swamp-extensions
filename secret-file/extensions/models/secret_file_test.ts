import {
  assert,
  assertEquals,
  assertRejects,
  assertThrows,
} from "jsr:@std/assert@1.0.19";
import { z } from "npm:zod@4.3.6";
import {
  type CommandResult,
  type CommandRunner,
  type RunOptions,
  sha256Hex,
  SshConfigError,
  type SshDeps,
  SshError,
} from "./_lib/ssh.ts";
import {
  chownSpec,
  createModel,
  type MethodContext,
  model,
  renderEntries,
  resolveContent,
  secretInstanceName,
  stageWriteScript,
} from "./secret_file.ts";

const HOST = "192.0.2.10";
const PATH = "/etc/example/secret.env";
const SECRET = "SUPER-SECRET-VALUE";
const KEY_LINE = `${HOST} ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeKey`;

const BASE = {
  host: HOST,
  port: 22,
  user: "root",
  host_key_policy: "strict" as const,
  host_keys: [KEY_LINE],
  connect_timeout_s: 15,
};

const WRITE = {
  ...BASE,
  path: PATH,
  content: SECRET,
  mode: "0600",
};

interface Call {
  cmd: string;
  command: string;
  stdin?: Uint8Array | string;
}

/** A fake runner that routes on the SSH remote command. */
function fakeRun(
  handler: (command: string, stdin?: Uint8Array | string) => CommandResult,
): { run: CommandRunner; calls: Call[] } {
  const calls: Call[] = [];
  const run: CommandRunner = (cmd, args, options: RunOptions = {}) => {
    const command = args.at(-1) ?? "";
    calls.push({ cmd, command, stdin: options.stdin });
    return Promise.resolve(handler(command, options.stdin));
  };
  return { run, calls };
}

/**
 * A runner for the staged write flow: probe, stage write, chown, rename, then a
 * final stat and sha read. `present` controls whether the destination exists.
 */
function stagedRunner(options: {
  sha: string;
  present?: boolean;
  statLine?: string;
  failStat?: boolean;
  onWrite?: (stdin?: Uint8Array | string) => void;
}): (command: string, stdin?: Uint8Array | string) => CommandResult {
  return (command, stdin) => {
    if (command.includes("DIRECTORY") || command.includes("MISSING")) {
      return { code: 0, stdout: "MISSING\n", stderr: "" };
    }
    if (command.includes("'test'")) {
      if (command.includes("'-L'") || command.includes("'-d'")) {
        return { code: 1, stdout: "", stderr: "" };
      }
      return { code: options.present ? 0 : 1, stdout: "", stderr: "" };
    }
    if (command.includes("mktemp")) {
      options.onWrite?.(stdin);
      return { code: 0, stdout: `${options.sha} 600\n`, stderr: "" };
    }
    if (command.includes("'chown'") || command.includes("'mv'")) {
      return { code: 0, stdout: "", stderr: "" };
    }
    if (command.includes("'stat'")) {
      return options.failStat
        ? { code: 1, stdout: "", stderr: "permission denied" }
        : {
          code: 0,
          stdout: options.statLine ?? "600 root root 0 0 18\n",
          stderr: "",
        };
    }
    if (command.includes("'sha256sum'")) {
      return { code: 0, stdout: `${options.sha}  ${PATH}\n`, stderr: "" };
    }
    if (command.includes("'rm'")) {
      return { code: 0, stdout: "", stderr: "" };
    }
    return { code: 0, stdout: "", stderr: "" };
  };
}

function deps(run: CommandRunner): SshDeps {
  let t = 0;
  return {
    run,
    now: () => t,
    sleep: (ms: number) => {
      t += ms;
      return Promise.resolve();
    },
  };
}

interface Written {
  specName: string;
  name: string;
  data: Record<string, unknown>;
}

function testContext(): { context: MethodContext; written: Written[] } {
  const written: Written[] = [];
  return {
    context: {
      logger: { info: () => {}, warn: () => {} },
      writeResource: (specName, name, data) => {
        written.push({ specName, name, data });
        return Promise.resolve({
          name,
          specName,
          kind: "resource",
          dataId: "d0",
          version: 1,
          size: 0,
        });
      },
    },
    written,
  };
}

function isSensitive(schema: z.ZodType): boolean {
  let current: z.ZodType | undefined = schema;
  for (let depth = 0; current; depth++) {
    if (current.meta()?.sensitive) return true;
    current = (current as unknown as { def?: { innerType?: z.ZodType } }).def
      ?.innerType;
    if (depth > 5) throw new Error("unexpected wrapper nesting");
  }
  return false;
}

Deno.test("model contract: empty globals, close to strict-only, three methods", () => {
  assertEquals(model.type, "@randybias/secret-file");
  assertEquals(model.globalArguments.safeParse({}).success, true);
  assertEquals(Object.keys(model.methods).sort(), [
    "remove",
    "verify",
    "write",
  ]);
  assertEquals(model.methods.write.kind, "action");
  assertEquals(model.methods.remove.kind, "action");
  assert(model.methods.verify.description.startsWith("READ-ONLY."));
  assertEquals(Object.keys(model.resources).sort(), ["secretFile"]);
  // Only strict is offered; insecure_tofu is not a value.
  const shape = (model.methods.write.arguments as z.ZodObject)
    .shape as Record<string, z.ZodType>;
  assertEquals(shape.host_key_policy.safeParse("insecure_tofu").success, false);
  assertEquals(shape.host_key_policy.safeParse("strict").success, true);
  assertEquals(
    model.methods.write.arguments.safeParse({ ...WRITE, host_keys: [] })
      .success,
    false,
  );
});

Deno.test("schemas are strict and mark every secret field sensitive", () => {
  const shape = (model.methods.write.arguments as z.ZodObject)
    .shape as Record<string, z.ZodType>;
  for (
    const field of [
      "content",
      "content_base64",
      "entries",
      "private_key",
      "password",
      "hmac_key",
    ]
  ) {
    assertEquals(isSensitive(shape[field]), true, field);
  }
  assertEquals(
    model.methods.write.arguments.safeParse({ ...WRITE, extra: 1 }).success,
    false,
  );
  assertEquals(
    model.methods.remove.arguments.safeParse({ ...BASE, path: "/a/../b" })
      .success,
    false,
  );
  assertEquals(
    model.methods.write.arguments.safeParse({ ...WRITE, owner: "root;id" })
      .success,
    false,
  );
});

Deno.test("resolveContent accepts exactly one content form", () => {
  assertEquals(
    new TextDecoder().decode(resolveContent({ content: "a" })),
    "a",
  );
  assertEquals(
    new TextDecoder().decode(resolveContent({ entries: { A: "1", B: "2" } })),
    "A='1'\nB='2'\n",
  );
  assertEquals(
    new TextDecoder().decode(resolveContent({ content_base64: "QUJD" })),
    "ABC",
  );
  assertThrows(() => resolveContent({}), SshConfigError, "exactly one");
  assertThrows(
    () => resolveContent({ content: "a", entries: {} }),
    SshConfigError,
    "exactly one",
  );
});

Deno.test("renderEntries quotes values, escapes quotes and caps size", () => {
  assertEquals(renderEntries({}), "");
  assertEquals(renderEntries({ A: "a b#c$d" }), "A='a b#c$d'\n");
  assertEquals(renderEntries({ A: "it's" }), "A='it'\\''s'\n");
  assertThrows(() => renderEntries({ "bad key": "1" }), SshConfigError);
  assertThrows(() => renderEntries({ A: "line1\nline2" }), SshConfigError);
  assertThrows(() => renderEntries({ "1A": "x" }), SshConfigError);
  const many: Record<string, string> = {};
  for (let i = 0; i < 257; i++) many[`K${i}`] = "v";
  assertThrows(() => renderEntries(many), SshConfigError, "at most");
});

Deno.test("chownSpec builds owner, group and owner:group forms", () => {
  assertEquals(chownSpec(undefined, undefined), undefined);
  assertEquals(chownSpec("svc", undefined), "svc");
  assertEquals(chownSpec(undefined, "svc"), ":svc");
  assertEquals(chownSpec("svc", "svc"), "svc:svc");
});

Deno.test("instance keys are SHA-256 and separate similar paths", async () => {
  const a = await secretInstanceName(HOST, 22, "root", "/a_b");
  const b = await secretInstanceName(HOST, 22, "root", "/a/b");
  assertEquals(a === b, false);
  assert(a.startsWith("secret-"));
  assertEquals(a.length, "secret-".length + 32);
});

Deno.test("write uploads over stdin, never on argv, and stores no value", async () => {
  const sha = await sha256Hex(SECRET);
  let seen: Uint8Array | string | undefined;
  const { run, calls } = fakeRun(stagedRunner({
    sha,
    present: false,
    onWrite: (stdin) => {
      seen = stdin;
    },
  }));
  const m = createModel(deps(run));
  const { context, written } = testContext();
  const result = await m.methods.write.execute(
    { ...WRITE, hmac_key: "HMAC-KEY" },
    context,
  );
  assertEquals((result.result as { changed: boolean }).changed, true);
  assertEquals(new TextDecoder().decode(seen as Uint8Array), SECRET);
  for (const call of calls) {
    assertEquals(call.command.includes(SECRET), false, "secret on argv");
  }
  const state = written[0].data;
  assertEquals(state.status, "present");
  assertEquals(state.bytes, SECRET.length);
  assertEquals("content" in state, false);
  assert(typeof state.content_hmac === "string", "a keyed HMAC is stored");
  assertEquals(
    JSON.stringify(state).includes(SECRET),
    false,
    "state must not carry the value",
  );
});

Deno.test("stageWriteScript writes, chmods, chowns and renames atomically", () => {
  const script = stageWriteScript(PATH, "0600", "1000:svc");
  assert(script.includes("set -euo pipefail"));
  assert(script.includes("mktemp"));
  assert(script.includes("trap 'rm -f"));
  assert(script.includes('cat > "$t"'));
  assert(script.includes(`chmod '0600' "$t"`));
  assert(script.includes(`chown -h '1000:svc' "$t"`));
  assert(script.includes('mv -T "$t"'));
  assert(script.includes("trap - EXIT"));
  assertEquals(stageWriteScript(PATH, "0640").includes("chown"), false);
});

Deno.test("write streams the secret into one sh -c script, not upload commands", async () => {
  const sha = await sha256Hex(SECRET);
  const { run, calls } = fakeRun(stagedRunner({
    sha,
    present: false,
    statLine: "600 svc svc 1000 1000 18\n",
  }));
  const m = createModel(deps(run));
  const { context } = testContext();
  await m.methods.write.execute(
    { ...WRITE, owner: "1000", group: "svc" },
    context,
  );
  const write = calls.find((c) => c.command.includes("mktemp"));
  assert(write, "the write stage ran");
  assertEquals(write.command.includes("'sh' '-c'"), true, "one sh -c command");
  assertEquals(write.command.includes("chown -h"), true);
  assertEquals(write.command.includes("1000:svc"), true);
  assertEquals(write.command.includes("trap"), true);
  assertEquals(
    new TextDecoder().decode(write.stdin as Uint8Array),
    SECRET,
    "the secret rides on stdin",
  );
  // No separate argv chown/mv commands remain.
  assertEquals(
    calls.filter((c) =>
      c.command.includes("'chown'") || c.command.includes("'mv'")
    ).length,
    0,
  );
});

Deno.test("write is idempotent when the remote bytes, mode and owner match", async () => {
  const sha = await sha256Hex(SECRET);
  const { run, calls } = fakeRun(stagedRunner({
    sha,
    present: true,
    statLine: "600 svc svc 1000 1000 18\n",
  }));
  const m = createModel(deps(run));
  const { context, written } = testContext();
  const result = await m.methods.write.execute(
    { ...WRITE, owner: "1000", group: "svc" },
    context,
  );
  assertEquals((result.result as { changed: boolean }).changed, false);
  assertEquals(calls.some((c) => c.command.includes("mktemp")), false);
  assertEquals(calls.some((c) => c.command.includes("'chown'")), false);
  assertEquals(written[0].data.changed, false);
});

Deno.test("write re-chowns only when the live owner differs", async () => {
  const sha = await sha256Hex(SECRET);
  let chowned = false;
  const { run, calls } = fakeRun((command) => {
    if (command.includes("DIRECTORY") || command.includes("MISSING")) {
      return { code: 0, stdout: "MISSING\n", stderr: "" };
    }
    if (command.includes("'test'")) {
      return {
        code: command.includes("'-L'") || command.includes("'-d'") ? 1 : 0,
        stdout: "",
        stderr: "",
      };
    }
    if (command.includes("mktemp")) {
      // The write is now one sh -c script that chowns inside it.
      chowned = command.includes("chown -h");
      return { code: 0, stdout: `${sha} 600\n`, stderr: "" };
    }
    if (command.includes("'stat'")) {
      return {
        code: 0,
        stdout: chowned
          ? "600 svc svc 1000 1000 18\n"
          : "600 root root 0 0 18\n",
        stderr: "",
      };
    }
    if (command.includes("'sha256sum'")) {
      return { code: 0, stdout: `${sha}  ${PATH}\n`, stderr: "" };
    }
    return { code: 0, stdout: "", stderr: "" };
  });
  const m = createModel(deps(run));
  const { context } = testContext();
  const result = await m.methods.write.execute(
    { ...WRITE, owner: "1000", group: "svc" },
    context,
  );
  const chown = calls.find((c) => c.command.includes("chown -h"));
  assert(chown, "chown must run");
  assert(chown.command.includes("-h"), "chown must not follow a symlink");
  assertEquals((result.result as { changed: boolean }).changed, true);
});

Deno.test("write fails closed without state when a live stat fails", async () => {
  const sha = await sha256Hex(SECRET);
  const { run } = fakeRun(stagedRunner({ sha, present: true, failStat: true }));
  const m = createModel(deps(run));
  const { context, written } = testContext();
  await assertRejects(
    () => m.methods.write.execute(WRITE, context),
    Error,
    "stat",
  );
  assertEquals(written.length, 0);
});

Deno.test("verify compares metadata and content without storing a hash", async () => {
  const sha = await sha256Hex(SECRET);
  const { run } = fakeRun(stagedRunner({
    sha,
    present: true,
    statLine: "600 svc svc 1000 1000 18\n",
  }));
  const m = createModel(deps(run));
  const { context, written } = testContext();
  const result = await m.methods.verify.execute(
    {
      ...BASE,
      path: PATH,
      content: SECRET,
      mode: "0600",
      owner: "1000",
      group: "svc",
    },
    context,
  );
  assertEquals((result.result as { matches: boolean }).matches, true);
  assertEquals(written[0].data.matches, true);
  assertEquals(JSON.stringify(written[0].data).includes(sha), false);
});

Deno.test("verify rejects two content forms and absent files", async () => {
  const sha = await sha256Hex(SECRET);
  const { run } = fakeRun(stagedRunner({ sha, present: true }));
  const m = createModel(deps(run));
  const { context, written } = testContext();
  await assertRejects(
    () =>
      m.methods.verify.execute(
        { ...BASE, path: PATH, content: "a", content_base64: "YQ==" },
        context,
      ),
    SshConfigError,
    "at most one",
  );
  assertEquals(written.length, 0);

  const absent = createModel(
    deps(fakeRun(stagedRunner({ sha, present: false })).run),
  );
  const absentCtx = testContext();
  const result = await absent.methods.verify.execute(
    { ...BASE, path: PATH, content: SECRET },
    absentCtx.context,
  );
  assertEquals((result.result as { present: boolean }).present, false);
  assertEquals(absentCtx.written[0].data.status, "not_found");
});

Deno.test("remove is a clean no-op when the file is gone", async () => {
  const sha = await sha256Hex(SECRET);
  const { run, calls } = fakeRun(stagedRunner({ sha, present: false }));
  const m = createModel(deps(run));
  const { context, written } = testContext();
  const result = await m.methods.remove.execute(
    { ...BASE, path: PATH },
    context,
  );
  assertEquals((result.result as { removed: boolean }).removed, false);
  assertEquals(calls.some((c) => c.command.includes("'rm'")), false);
  assertEquals(written[0].data.status, "not_found");
});

Deno.test("remove deletes and proves it is gone", async () => {
  const sha = await sha256Hex(SECRET);
  let removed = false;
  const { run, calls } = fakeRun((command) => {
    if (command.includes("'rm'")) {
      removed = true;
      return { code: 0, stdout: "", stderr: "" };
    }
    if (command.includes("'test'")) {
      return { code: removed ? 1 : 0, stdout: "", stderr: "" };
    }
    return { code: 0, stdout: "", stderr: "" };
  });
  const m = createModel(deps(run));
  const { context, written } = testContext();
  const result = await m.methods.remove.execute(
    { ...BASE, path: PATH },
    context,
  );
  assertEquals((result.result as { removed: boolean }).removed, true);
  assertEquals(calls.some((c) => c.command.includes("'rm'")), true);
  assertEquals(written[0].data.status, "removed");
  assertEquals(sha.length, 64);
});

Deno.test("a strict policy without pinned keys is refused before any command", async () => {
  const { run, calls } = fakeRun(() => ({ code: 0, stdout: "", stderr: "" }));
  const m = createModel(deps(run));
  const { context } = testContext();
  await assertRejects(
    () =>
      m.methods.write.execute(
        { ...WRITE, host_keys: undefined },
        context,
      ),
    SshConfigError,
    "host_keys is required",
  );
  assertEquals(calls.length, 0);
});

Deno.test("the factory returns an independent model", () => {
  const { run } = fakeRun(() => ({ code: 0, stdout: "", stderr: "" }));
  const m = createModel(deps(run));
  assertEquals(m.type, model.type);
  assert(m !== model);
  assertEquals(typeof m.methods.write.execute, "function");
});

Deno.test("write refuses a symlink destination without following it", async () => {
  const { run, calls } = fakeRun((command) =>
    command.includes("'test'") && command.includes("'-L'")
      ? { code: 0, stdout: "", stderr: "" }
      : { code: 0, stdout: "", stderr: "" }
  );
  const m = createModel(deps(run));
  const { context, written } = testContext();
  await assertRejects(
    () => m.methods.write.execute(WRITE, context),
    SshError,
    "symlink",
  );
  assertEquals(calls.some((c) => c.command.includes("mktemp")), false);
  assertEquals(written.length, 0);
});

Deno.test("write refuses a directory destination", async () => {
  const { run, calls } = fakeRun((command) => {
    if (command.includes("'test'") && command.includes("'-L'")) {
      return { code: 1, stdout: "", stderr: "" };
    }
    if (command.includes("'test'") && command.includes("'-d'")) {
      return { code: 0, stdout: "", stderr: "" };
    }
    return { code: 0, stdout: "", stderr: "" };
  });
  const m = createModel(deps(run));
  const { context, written } = testContext();
  await assertRejects(
    () => m.methods.write.execute(WRITE, context),
    SshError,
    "directory",
  );
  assertEquals(calls.some((c) => c.command.includes("mktemp")), false);
  assertEquals(written.length, 0);
});
