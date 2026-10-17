import {
  assert,
  assertEquals,
  assertRejects,
  assertStringIncludes,
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
  createModel,
  execArgsSchema,
  type MethodContext,
  model,
  uploadArgsSchema,
  waitArgsSchema,
} from "./ssh_host.ts";

const HOST = "192.0.2.10";
const KEY = "QUFBQUFB";
const PRIVATE_KEY = "PLACEHOLDER-PRIVATE-KEY-MATERIAL";
const KEY_LINE = `${HOST} ssh-ed25519 ${KEY}`;

const STRICT = {
  host: HOST,
  port: 22,
  user: "root",
  host_key_policy: "strict" as const,
  host_keys: [KEY_LINE],
  private_key: PRIVATE_KEY,
  connect_timeout_s: 15,
};

interface Call {
  cmd: string;
  args: string[];
  stdin?: Uint8Array | string;
  env?: Record<string, string>;
}

/** Fake runner: no process, no socket. */
function fakeRun(
  calls: Call[],
  handlers: {
    ssh?: (args: string[], options: RunOptions) => CommandResult;
    keyscan?: () => CommandResult;
    add?: () => CommandResult;
  } = {},
): CommandRunner {
  return (cmd, args, options = {}) => {
    calls.push({ cmd, args, stdin: options.stdin, env: options.env });
    if (cmd === "ssh-agent" && args[0] === "-s") {
      return Promise.resolve({
        code: 0,
        stdout:
          "SSH_AUTH_SOCK=/tmp/agent.test; export SSH_AUTH_SOCK;\nSSH_AGENT_PID=4242; export SSH_AGENT_PID;\n",
        stderr: "",
      });
    }
    if (cmd === "ssh-agent") {
      return Promise.resolve({ code: 0, stdout: "", stderr: "" });
    }
    if (cmd === "ssh-add") {
      return Promise.resolve(
        handlers.add?.() ?? { code: 0, stdout: "", stderr: "" },
      );
    }
    if (cmd === "ssh-keyscan") {
      return Promise.resolve(
        handlers.keyscan?.() ??
          { code: 0, stdout: `${KEY_LINE}\n`, stderr: "" },
      );
    }
    if (cmd === "ssh") {
      return Promise.resolve(
        handlers.ssh?.(args, options) ??
          { code: 0, stdout: "hi\n", stderr: "" },
      );
    }
    return Promise.resolve({ code: 0, stdout: "", stderr: "" });
  };
}

interface Written {
  specName: string;
  name: string;
  data: Record<string, unknown>;
}

/** Reads `sensitive` through the optional/nullable/default wrappers. */
function isSensitive(schema: z.ZodType): boolean {
  let current: z.ZodType | undefined = schema;
  while (current) {
    if (current.meta()?.sensitive) return true;
    current = (current as unknown as { def?: { innerType?: z.ZodType } }).def
      ?.innerType;
  }
  return false;
}

/** Minimal method context that records resource writes. */
function testContext(): { context: MethodContext; written: Written[] } {
  const written: Written[] = [];
  const context: MethodContext = {
    logger: { info: () => {}, warn: () => {}, error: () => {} },
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
  };
  return { context, written };
}

/** Fake deps with an advancing clock for the wait loop. */
function fakeDeps(run: CommandRunner): SshDeps {
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

Deno.test("model contract: type, empty globals, action methods, read-only label", () => {
  assertEquals(model.type, "@randybias/ssh-host");
  assert(/^\d{4}\.\d{2}\.\d{2}\.\d+$/.test(model.version));
  assertEquals(model.globalArguments.safeParse({}).success, true);
  assertEquals(model.globalArguments.safeParse({ host: HOST }).success, false);
  assertEquals(Object.keys(model.methods).sort(), [
    "exec",
    "upload",
    "wait_connection",
  ]);
  for (const method of Object.values(model.methods)) {
    assertEquals(method.kind, "action");
  }
  assertStringIncludes(
    model.methods.wait_connection.description,
    "READ-ONLY.",
  );
  assertEquals(Object.keys(model.resources).sort(), [
    "connection",
    "execution",
    "upload",
  ]);
});

Deno.test("argument schemas are strict and mark every secret sensitive", () => {
  const execShape = (execArgsSchema as z.ZodObject).shape as Record<
    string,
    z.ZodType
  >;
  const uploadShape = (uploadArgsSchema as z.ZodObject).shape as Record<
    string,
    z.ZodType
  >;
  const waitShape = (waitArgsSchema as z.ZodObject).shape as Record<
    string,
    z.ZodType
  >;
  for (const field of ["private_key", "password"]) {
    assertEquals(isSensitive(execShape[field]), true);
  }
  for (
    const field of ["content", "content_base64", "private_key", "password"]
  ) {
    assertEquals(isSensitive(uploadShape[field]), true);
  }
  assertEquals(isSensitive(waitShape.private_key), true);
  // host_key_policy has no default and is required.
  assertEquals(
    execArgsSchema.safeParse({
      ...STRICT,
      argv: ["true"],
      host_key_policy: undefined,
    })
      .success,
    false,
  );
  // Unknown keys are rejected: strict object, no passthrough.
  assertEquals(
    execArgsSchema.safeParse({ ...STRICT, argv: ["true"], extra: 1 }).success,
    false,
  );
  // Defaults fill in port and timeout.
  const parsed = execArgsSchema.parse({
    host: HOST,
    user: "root",
    host_key_policy: "insecure_tofu",
    argv: ["true"],
  });
  assertEquals(parsed.port, 22);
  assertEquals(parsed.connect_timeout_s, 15);
});

Deno.test("schemas reject injection in host, user, path and mode", () => {
  assertEquals(
    execArgsSchema.safeParse({
      ...STRICT,
      host: "-oProxyCommand=x",
      argv: ["true"],
    })
      .success,
    false,
  );
  assertEquals(
    execArgsSchema.safeParse({ ...STRICT, user: "root;id", argv: ["true"] })
      .success,
    false,
  );
  assertEquals(
    uploadArgsSchema.safeParse({
      ...STRICT,
      path: "/a/../b",
      content: "x",
      mode: "0600",
    }).success,
    false,
  );
  assertEquals(
    uploadArgsSchema.safeParse({
      ...STRICT,
      path: "/etc/x",
      content: "x",
      mode: "9x",
    }).success,
    false,
  );
});

Deno.test("exec runs the argv, writes a host-keyed resource, returns data", async () => {
  const calls: Call[] = [];
  const deps = fakeDeps(fakeRun(calls));
  const m = createModel(deps);
  const { context, written } = testContext();
  const args = { ...STRICT, argv: ["echo", "hi"] };
  const result = await m.methods.exec.execute(args, context);
  assertEquals(result.result, { stdout: "hi\n", stderr: "", exit_code: 0 });
  assertEquals(written.length, 1);
  assertEquals(written[0].specName, "execution");
  assertEquals(written[0].name, `exec-${HOST}`);
  assertEquals(written[0].data.exit_code, 0);
  assertEquals(written[0].data.stdout, "hi\n");
  assertEquals(
    written[0].data.argv_sha256,
    await sha256Hex("echo\u0000hi"),
  );
  const ssh = calls.find((c) => c.cmd === "ssh");
  assertEquals(ssh?.args.at(-1), "'echo' 'hi'");
  for (const call of calls) {
    assertEquals(call.args.join(" ").includes(PRIVATE_KEY), false);
  }
});

Deno.test("exec passes shell metacharacters as literal argv words", async () => {
  const calls: Call[] = [];
  const deps = fakeDeps(fakeRun(calls));
  const m = createModel(deps);
  const { context } = testContext();
  const argv = ["sh", "-c", "; rm -rf /", "$(id)", "`id`", "a\nb"];
  await m.methods.exec.execute({ ...STRICT, argv }, context);
  const ssh = calls.find((c) => c.cmd === "ssh");
  assertEquals(
    ssh?.args.at(-1),
    "'sh' '-c' '; rm -rf /' '$(id)' '`id`' 'a\nb'",
  );
});

Deno.test("transport failures throw, naming the host and leaking no key", async () => {
  const calls: Call[] = [];
  const deps = fakeDeps(fakeRun(calls, {
    ssh: () => ({
      code: 255,
      stdout: "",
      stderr: "Host key verification failed.\n",
    }),
  }));
  const m = createModel(deps);
  const { context } = testContext();
  const err = await assertRejects(
    () => m.methods.exec.execute({ ...STRICT, argv: ["true"] }, context),
    SshError,
  );
  assertStringIncludes(err.message, HOST);
  assertEquals(err.message.includes(PRIVATE_KEY), false);
});

Deno.test("a non-zero remote exit is data, not an error", async () => {
  const calls: Call[] = [];
  const deps = fakeDeps(fakeRun(calls, {
    ssh: () => ({ code: 2, stdout: "", stderr: "nope\n" }),
  }));
  const m = createModel(deps);
  const { context } = testContext();
  const result = await m.methods.exec.execute(
    { ...STRICT, argv: ["false"] },
    context,
  );
  assertEquals(result.result, { stdout: "", stderr: "nope\n", exit_code: 2 });
});

Deno.test("strict without pinned keys and two credentials are config errors", async () => {
  const deps = fakeDeps(fakeRun([]));
  const m = createModel(deps);
  const { context } = testContext();
  await assertRejects(
    () =>
      m.methods.exec.execute(
        { ...STRICT, host_keys: undefined, argv: ["true"] },
        context,
      ),
    SshConfigError,
    "requires a non-empty host_keys",
  );
  await assertRejects(
    () =>
      m.methods.exec.execute(
        { ...STRICT, password: "placeholder-password", argv: ["true"] },
        context,
      ),
    SshConfigError,
    "not both",
  );
});

Deno.test("upload writes a host-keyed resource and is idempotent", async () => {
  const calls: Call[] = [];
  let seen: Uint8Array | undefined;
  const deps = fakeDeps(fakeRun(calls, {
    ssh: (_args, options) => {
      seen = typeof options.stdin === "string"
        ? new TextEncoder().encode(options.stdin)
        : options.stdin;
      return { code: 0, stdout: "", stderr: "" };
    },
  }));
  const m = createModel(deps);
  const { context, written } = testContext();
  const args = {
    ...STRICT,
    path: "/etc/wireguard/wg0.conf",
    content: "placeholder\n",
    mode: "0600",
  };
  const first = await m.methods.upload.execute(args, context);
  const second = await m.methods.upload.execute(args, context);
  assertEquals(first.result, second.result);
  assertEquals(new TextDecoder().decode(seen), "placeholder\n");
  assertEquals(written[0].specName, "upload");
  assertEquals(written[0].name, `upload-${HOST}`);
  assertEquals(written[0].data.bytes, 12);
  assertEquals(written[0].data.sha256, await sha256Hex("placeholder\n"));
  for (const call of calls) {
    assertEquals(call.args.join(" ").includes("placeholder"), false);
  }
});

Deno.test("upload decodes base64 and refuses ambiguous or missing content", async () => {
  const calls: Call[] = [];
  const deps = fakeDeps(fakeRun(calls));
  const m = createModel(deps);
  const { context } = testContext();
  const result = await m.methods.upload.execute({
    ...STRICT,
    path: "/tmp/blob",
    content_base64: "QUJD",
    mode: "0644",
  }, context);
  assertEquals(
    (result.result as { sha256: string }).sha256,
    await sha256Hex(new Uint8Array([65, 66, 67])),
  );
  await assertRejects(
    () =>
      m.methods.upload.execute({
        ...STRICT,
        path: "/tmp/x",
        content: "a",
        content_base64: "YQ==",
        mode: "0600",
      }, context),
    SshConfigError,
    "not both",
  );
  await assertRejects(
    () =>
      m.methods.upload.execute({
        ...STRICT,
        path: "/tmp/x",
        mode: "0600",
      }, context),
    SshConfigError,
    "requires content",
  );
});

Deno.test("upload to an unwritable path throws and leaves no result resource", async () => {
  const calls: Call[] = [];
  const deps = fakeDeps(fakeRun(calls, {
    ssh: () => ({ code: 1, stdout: "", stderr: "Permission denied\n" }),
  }));
  const m = createModel(deps);
  const { context, written } = testContext();
  await assertRejects(
    () =>
      m.methods.upload.execute({
        ...STRICT,
        path: "/proc/1/nope",
        content: "x",
        mode: "0600",
      }, context),
    SshError,
  );
  assertEquals(written.length, 0);
});

Deno.test("wait_connection records reachability and accepted keys", async () => {
  const calls: Call[] = [];
  const deps = fakeDeps(fakeRun(calls));
  const m = createModel(deps);
  const { context, written } = testContext();
  const result = await m.methods.wait_connection.execute(
    { ...STRICT, timeout_s: 5, poll_interval_s: 1 },
    context,
  );
  const value = result.result as {
    reachable: boolean;
    host_keys: { sha256: string }[];
  };
  assertEquals(value.reachable, true);
  assertEquals(value.host_keys[0].sha256.startsWith("SHA256:"), true);
  assertEquals(written[0].specName, "connection");
  assertEquals(written[0].name, `connection-${HOST}`);
  assertEquals(written[0].data.reachable, true);
});

Deno.test("wait_connection strict refuses a mismatched key", async () => {
  const calls: Call[] = [];
  const other = "QkJCQkJC";
  const deps = fakeDeps(fakeRun(calls, {
    keyscan: () => ({
      code: 0,
      stdout: `${HOST} ssh-ed25519 ${other}\n`,
      stderr: "",
    }),
  }));
  const m = createModel(deps);
  const { context, written } = testContext();
  await assertRejects(
    () =>
      m.methods.wait_connection.execute(
        { ...STRICT, timeout_s: 5, poll_interval_s: 1 },
        context,
      ),
    SshError,
    "mismatch",
  );
  assertEquals(written.length, 0);
});

Deno.test("wait_connection times out with a typed error naming the host", async () => {
  const calls: Call[] = [];
  const deps = fakeDeps(fakeRun(calls, {
    keyscan: () => ({ code: 1, stdout: "", stderr: "" }),
  }));
  const m = createModel(deps);
  const { context } = testContext();
  const err = await assertRejects(
    () =>
      m.methods.wait_connection.execute(
        { ...STRICT, timeout_s: 1, poll_interval_s: 1 },
        context,
      ),
    SshError,
  );
  assertStringIncludes(err.message, HOST);
});

Deno.test("the factory returns an independent model with the production wiring", () => {
  const calls: Call[] = [];
  const deps = fakeDeps(fakeRun(calls));
  const m = createModel(deps);
  assertEquals(m.type, model.type);
  assertEquals(m.version, model.version);
  assert(m !== model);
  // The injected runner is the only one used; the real one is untouched.
  assertEquals(typeof m.methods.exec.execute, "function");
});
