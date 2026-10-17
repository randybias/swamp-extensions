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
} from "./_lib/ssh.ts";
import {
  chownSpec,
  createModel,
  type MethodContext,
  model,
  renderEntries,
  resolveContent,
  secretInstanceName,
} from "./secret_file.ts";

const HOST = "192.0.2.10";
const PATH = "/etc/example/secret.env";
const SECRET = "SUPER-SECRET-VALUE";

const BASE = {
  host: HOST,
  port: 22,
  user: "root",
  host_key_policy: "insecure_tofu" as const,
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

/** Deps with an advancing clock. */
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

Deno.test("model contract: empty globals, action write/remove, read-only verify", () => {
  assertEquals(model.type, "@randybias/secret-file");
  assertEquals(model.globalArguments.safeParse({}).success, true);
  assertEquals(
    model.globalArguments.safeParse({ host: HOST }).success,
    false,
  );
  assertEquals(Object.keys(model.methods).sort(), [
    "remove",
    "verify",
    "write",
  ]);
  assertEquals(model.methods.write.kind, "action");
  assertEquals(model.methods.remove.kind, "action");
  assert(model.methods.verify.description.startsWith("READ-ONLY."));
  assertEquals(Object.keys(model.resources).sort(), ["secretFile"]);
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
  assertEquals(
    model.methods.write.arguments.safeParse({ ...WRITE, port: 70000 }).success,
    false,
  );
});

Deno.test("resolveContent accepts exactly one content form", () => {
  assertEquals(
    new TextDecoder().decode(
      resolveContent({ path: PATH, content: "a", mode: "0600" }),
    ),
    "a",
  );
  assertEquals(
    new TextDecoder().decode(
      resolveContent({
        path: PATH,
        entries: { A: "1", B: "2" },
        mode: "0600",
      }),
    ),
    "A=1\nB=2\n",
  );
  assertEquals(
    new TextDecoder().decode(
      resolveContent({ path: PATH, content_base64: "QUJD", mode: "0600" }),
    ),
    "ABC",
  );
  assertThrows(
    () => resolveContent({ path: PATH, mode: "0600" }),
    SshConfigError,
    "exactly one",
  );
  assertThrows(
    () =>
      resolveContent({ path: PATH, content: "a", entries: {}, mode: "0600" }),
    SshConfigError,
    "exactly one",
  );
});

Deno.test("renderEntries refuses bad keys and newline values", () => {
  assertEquals(renderEntries({}), "");
  assertThrows(() => renderEntries({ "bad key": "1" }), SshConfigError);
  assertThrows(() => renderEntries({ A: "line1\nline2" }), SshConfigError);
  assertThrows(() => renderEntries({ "1A": "x" }), SshConfigError);
});

Deno.test("chownSpec builds owner, group and owner:group forms", () => {
  assertEquals(chownSpec(undefined, undefined), undefined);
  assertEquals(chownSpec("svc", undefined), "svc");
  assertEquals(chownSpec(undefined, "svc"), ":svc");
  assertEquals(chownSpec("svc", "svc"), "svc:svc");
});

Deno.test("instance keys separate a path with a slash from one with an underscore", () => {
  assert(
    secretInstanceName(HOST, 22, "root", "/a_b") !==
      secretInstanceName(HOST, 22, "root", "/a/b"),
  );
  assert(secretInstanceName(HOST, 22, "root", PATH).includes("-p22-"));
});

Deno.test("write uploads over stdin, never on argv, and stores no value", async () => {
  const { run, calls } = fakeRun((command) => {
    if (command.includes("mktemp")) return { code: 0, stdout: "", stderr: "" };
    return { code: 0, stdout: "MISSING\n", stderr: "" };
  });
  const m = createModel(deps(run));
  const { context, written } = testContext();
  const result = await m.methods.write.execute(
    { ...WRITE, hmac_key: "HMAC-KEY" },
    context,
  );
  assertEquals((result.result as { changed: boolean }).changed, true);
  const writeCall = calls.find((c) => c.command.includes("mktemp"));
  assert(writeCall, "a write must happen");
  assertEquals(
    new TextDecoder().decode(writeCall.stdin as Uint8Array),
    SECRET,
  );
  for (const call of calls) {
    assertEquals(call.command.includes(SECRET), false, "secret on argv");
  }
  const state = written[0].data;
  assertEquals(state.path, PATH);
  assertEquals(state.status, "present");
  assertEquals(state.bytes, SECRET.length);
  assertEquals("content" in state, false);
  assertEquals("content_base64" in state, false);
  assert(typeof state.content_hmac === "string", "a keyed HMAC is stored");
  assertEquals(
    JSON.stringify(state).includes(SECRET),
    false,
    "state must not carry the value",
  );
});

Deno.test("write is idempotent when the remote bytes and mode match", async () => {
  const sha = await sha256Hex(SECRET);
  const { run, calls } = fakeRun(() => ({
    code: 0,
    stdout: `${sha} 600\n`,
    stderr: "",
  }));
  const m = createModel(deps(run));
  const { context, written } = testContext();
  const result = await m.methods.write.execute(WRITE, context);
  assertEquals((result.result as { changed: boolean }).changed, false);
  assertEquals(calls.some((c) => c.command.includes("mktemp")), false);
  assertEquals(written[0].data.changed, false);
  assertEquals("content_hmac" in written[0].data, false);
});

Deno.test("write converges owner and group when they differ", async () => {
  const { run, calls } = fakeRun((command) => {
    if (command.includes("mktemp")) return { code: 0, stdout: "", stderr: "" };
    if (command.includes("stat")) {
      return { code: 0, stdout: "600 root root 10\n", stderr: "" };
    }
    if (command.includes("chown")) return { code: 0, stdout: "", stderr: "" };
    return { code: 0, stdout: "MISSING\n", stderr: "" };
  });
  const m = createModel(deps(run));
  const { context } = testContext();
  const result = await m.methods.write.execute(
    { ...WRITE, owner: "svc", group: "svc" },
    context,
  );
  const chown = calls.find((c) => c.command.includes("chown"));
  assert(chown, "chown must run");
  assert(chown.command.includes("svc:svc"), chown.command);
  assertEquals((result.result as { changed: boolean }).changed, true);
});

Deno.test("verify compares metadata and content without storing a hash", async () => {
  const sha = await sha256Hex(SECRET);
  const { run } = fakeRun((command) => {
    if (command.includes("sha256sum")) {
      return { code: 0, stdout: `${sha}  ${PATH}\n`, stderr: "" };
    }
    return { code: 0, stdout: "600 svc svc 18\n", stderr: "" };
  });
  const m = createModel(deps(run));
  const { context, written } = testContext();
  const result = await m.methods.verify.execute(
    { ...WRITE, mode: "0600", owner: "svc", group: "svc" },
    context,
  );
  assertEquals((result.result as { matches: boolean }).matches, true);
  assertEquals(written[0].data.matches, true);
  assertEquals(JSON.stringify(written[0].data).includes(sha), false);
});

Deno.test("verify records not_found when the file is absent", async () => {
  const { run } = fakeRun(() => ({ code: 1, stdout: "", stderr: "" }));
  const m = createModel(deps(run));
  const { context, written } = testContext();
  const result = await m.methods.verify.execute(WRITE, context);
  assertEquals((result.result as { present: boolean }).present, false);
  assertEquals(written[0].data.status, "not_found");
});

Deno.test("remove is a clean no-op when the file is gone", async () => {
  const { run, calls } = fakeRun((command) =>
    command.includes("test")
      ? { code: 1, stdout: "", stderr: "" }
      : { code: 0, stdout: "", stderr: "" }
  );
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
  let removed = false;
  const { run, calls } = fakeRun((command) => {
    if (command.includes("'rm'")) {
      removed = true;
      return { code: 0, stdout: "", stderr: "" };
    }
    if (command.includes("test")) {
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
});

Deno.test("a strict policy without pinned keys is refused before any command", async () => {
  const { run, calls } = fakeRun(() => ({ code: 0, stdout: "", stderr: "" }));
  const m = createModel(deps(run));
  const { context } = testContext();
  await assertRejects(
    () =>
      m.methods.write.execute(
        { ...WRITE, host_key_policy: "strict", host_keys: undefined },
        context,
      ),
    SshConfigError,
    "strict requires",
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
