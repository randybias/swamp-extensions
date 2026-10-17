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
// Length-prefixed, labeled target key used for stored instance names.
const HOSTPORT = `h${HOST.length}-${HOST}-p22`;
const SUFFIX = `${HOSTPORT}-u4-root`;

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

/**
 * Reads `sensitive` through the optional/nullable/default wrappers. Fails
 * loudly rather than returning a false negative if zod's shape changes.
 */
function isSensitive(schema: z.ZodType): boolean {
  let current: z.ZodType | undefined = schema;
  for (let depth = 0; current; depth++) {
    if (typeof current.meta !== "function") {
      throw new Error("isSensitive: zod schema has no meta(); API changed");
    }
    if (current.meta()?.sensitive) return true;
    current = (current as unknown as { def?: { innerType?: z.ZodType } }).def
      ?.innerType;
    if (depth > 5) throw new Error("isSensitive: unexpected wrapper nesting");
  }
  return false;
}

/** Minimal method context that records writes and serves stored reads. */
function testContext(
  stored: Record<string, Record<string, unknown>> = {},
): { context: MethodContext; written: Written[] } {
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
    readResource: (name) => Promise.resolve(stored[name] ?? null),
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
  assertStringIncludes(model.methods.upload.description, "DESTRUCTIVE.");
  assertStringIncludes(model.methods.exec.description, "DESTRUCTIVE.");
  assert(model.description.length > 20);
  assertEquals(Object.keys(model.resources).sort(), [
    "connection",
    "execution",
    "upload",
  ]);
});

Deno.test("persisted exec output is sensitive-marked", () => {
  const shape = (model.resources.execution.schema as z.ZodObject)
    .shape as Record<string, z.ZodType>;
  assertEquals(isSensitive(shape.stdout), true);
  assertEquals(isSensitive(shape.stderr), true);
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
  // wait_connection only scans public keys, so it carries no credential fields.
  assertEquals("private_key" in waitShape, false);
  assertEquals("password" in waitShape, false);
  assertEquals("host_keys" in waitShape, true);
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
  assertEquals(parsed.max_output_bytes, 10485760);
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
  for (const path of ["/a/../b", "/etc/", "/a/./b"]) {
    assertEquals(
      uploadArgsSchema.safeParse({
        ...STRICT,
        path,
        content: "x",
        mode: "0600",
      }).success,
      false,
    );
  }
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
  // The result carries only exit code and output hashes by default; the raw
  // output stays in the sensitive-marked resource.
  const value = result.result as Record<string, unknown>;
  assertEquals(value.exit_code, 0);
  assertEquals(value.stdout_sha256, await sha256Hex("hi\n"));
  assertEquals(value.stderr_sha256, await sha256Hex(""));
  assertEquals("stdout" in value, false);
  assertEquals(written.length, 1);
  assertEquals(written[0].specName, "execution");
  assertEquals(written[0].name, `exec-${SUFFIX}`);
  assertEquals(written[0].data.exit_code, 0);
  // Raw output is not returned and not stored unless return_output is set.
  assertEquals("stdout" in written[0].data, false);
  assertEquals(written[0].data.stdout_sha256, await sha256Hex("hi\n"));
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

Deno.test("exec never returns raw output; return_output stores it sensitively", async () => {
  const calls: Call[] = [];
  const deps = fakeDeps(fakeRun(calls));
  const m = createModel(deps);
  const withContext = testContext();
  const withOutput = await m.methods.exec.execute(
    { ...STRICT, argv: ["printenv"], return_output: true },
    withContext.context,
  );
  const withResult = withOutput.result as Record<string, unknown>;
  assertEquals("stdout" in withResult, false);
  assertEquals(withResult.output_resource, `exec-${SUFFIX}`);
  assertEquals(withContext.written[0].data.stdout, "hi\n");

  const withoutContext = testContext();
  const withoutOutput = await m.methods.exec.execute(
    { ...STRICT, argv: ["printenv"] },
    withoutContext.context,
  );
  assertEquals("stdout" in (withoutOutput.result as object), false);
  assertEquals("stdout" in withoutContext.written[0].data, false);
});

Deno.test("schemas reject a NUL byte in argv", () => {
  assertEquals(
    execArgsSchema.safeParse({ ...STRICT, argv: ["echo", "a\u0000b"] }).success,
    false,
  );
  assertEquals(
    execArgsSchema.safeParse({ ...STRICT, argv: ["echo", "ok"] }).success,
    true,
  );
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

Deno.test("exec surfaces the output capture cap as a typed error", async () => {
  const calls: Call[] = [];
  const deps = fakeDeps(fakeRun(calls, {
    ssh: () => ({ code: 0, stdout: "0123456789", stderr: "" }),
  }));
  const m = createModel(deps);
  const { context } = testContext();
  await assertRejects(
    () =>
      m.methods.exec.execute(
        { ...STRICT, argv: ["true"], max_output_bytes: 4 },
        context,
      ),
    SshError,
    "capture limit",
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
  const value = result.result as Record<string, unknown>;
  assertEquals(value.exit_code, 2);
  assertEquals(value.stderr_sha256, await sha256Hex("nope\n"));
  assertEquals("stderr" in value, false);
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

Deno.test("upload writes once and the second run is a true no-op", async () => {
  const calls: Call[] = [];
  let seen: Uint8Array | undefined;
  let stored: { sha: string; mode: string } | null = null;
  const content = "placeholder\n";
  const contentSha = await sha256Hex(content);
  const deps = fakeDeps(fakeRun(calls, {
    ssh: (args, options) => {
      const remote = args.at(-1) ?? "";
      if (remote.includes("mktemp")) {
        seen = typeof options.stdin === "string"
          ? new TextEncoder().encode(options.stdin)
          : options.stdin;
        stored = { sha: contentSha, mode: "600" };
        return { code: 0, stdout: `${contentSha} 600\n`, stderr: "" };
      }
      // Convergence probe against the retained remote state.
      return stored
        ? { code: 0, stdout: `${stored.sha} ${stored.mode}\n`, stderr: "" }
        : { code: 0, stdout: "MISSING\n", stderr: "" };
    },
  }));
  const m = createModel(deps);
  const { context, written } = testContext();
  const args = {
    ...STRICT,
    path: "/etc/wireguard/wg0.conf",
    content,
    mode: "0600",
  };
  const first = await m.methods.upload.execute(args, context);
  const second = await m.methods.upload.execute(args, context);
  assertEquals((first.result as { changed: boolean }).changed, true);
  assertEquals((second.result as { changed: boolean }).changed, false);
  assertEquals(written.length, 1);
  assertEquals(new TextDecoder().decode(seen), content);
  assertEquals(written[0].specName, "upload");
  assertEquals(written[0].name, `upload-${SUFFIX}`);
  assertEquals(written[0].data.bytes, 12);
  assertEquals(written[0].data.sha256, contentSha);
  for (const call of calls) {
    assertEquals(call.args.join(" ").includes("placeholder"), false);
  }
});

Deno.test("upload writes no resource when the remote bytes are unchanged", async () => {
  const calls: Call[] = [];
  const content = "already current\n";
  const sha = await sha256Hex(content);
  const deps = fakeDeps(fakeRun(calls, {
    ssh: () => ({ code: 0, stdout: `${sha} 600\n`, stderr: "" }),
  }));
  const m = createModel(deps);
  const { context, written } = testContext();
  const result = await m.methods.upload.execute({
    ...STRICT,
    path: "/etc/x",
    content,
    mode: "0600",
  }, context);
  assertEquals((result.result as { changed: boolean }).changed, false);
  assertEquals(written.length, 0);
});

Deno.test("upload decodes base64 and refuses ambiguous or missing content", async () => {
  const calls: Call[] = [];
  const blobSha = await sha256Hex(new Uint8Array([65, 66, 67]));
  const deps = fakeDeps(fakeRun(calls, {
    ssh: (args) =>
      (args.at(-1) ?? "").includes("mktemp")
        ? { code: 0, stdout: `${blobSha} 644\n`, stderr: "" }
        : { code: 0, stdout: "", stderr: "" },
  }));
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
  assertEquals(written[0].name, `connection-${HOSTPORT}`);
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

Deno.test("insecure_tofu records the first keys and pins them on later runs", async () => {
  const args = {
    ...STRICT,
    host_key_policy: "insecure_tofu" as const,
    host_keys: undefined,
    argv: ["true"],
  };
  const calls: Call[] = [];
  const deps = fakeDeps(fakeRun(calls));
  const m = createModel(deps);
  const { context, written } = testContext();
  const first = await m.methods.exec.execute(args, context);
  assertEquals((first.result as { exit_code: number }).exit_code, 0);
  // First use scanned and recorded the keys, then pinned them for the run.
  assertEquals(calls.some((c) => c.cmd === "ssh-keyscan"), true);
  const connection = written.find((w) => w.specName === "connection");
  assertEquals(connection?.name, `connection-${HOSTPORT}`);
  const firstSsh = calls.filter((c) => c.cmd === "ssh").at(-1);
  assertEquals(firstSsh?.args.includes("StrictHostKeyChecking=yes"), true);
  assert(connection);

  // Second run reads the record: no scan, no new connection write, still pinned.
  const calls2: Call[] = [];
  const deps2 = fakeDeps(fakeRun(calls2));
  const m2 = createModel(deps2);
  const stored = { [`connection-${HOSTPORT}`]: connection.data };
  const { context: context2, written: written2 } = testContext(stored);
  await m2.methods.exec.execute(args, context2);
  assertEquals(calls2.some((c) => c.cmd === "ssh-keyscan"), false);
  assertEquals(
    calls2.find((c) => c.cmd === "ssh")?.args.includes(
      "StrictHostKeyChecking=yes",
    ),
    true,
  );
  assertEquals(written2.some((w) => w.specName === "connection"), false);
});

Deno.test("a first-use TOFU scan does not persist a pin when auth fails", async () => {
  const calls: Call[] = [];
  const deps = fakeDeps(fakeRun(calls, {
    ssh: () => ({
      code: 255,
      stdout: "",
      stderr: "root@192.0.2.10: Permission denied (publickey).\n",
    }),
  }));
  const m = createModel(deps);
  const { context, written } = testContext();
  await assertRejects(
    () =>
      m.methods.exec.execute({
        ...STRICT,
        host_key_policy: "insecure_tofu",
        host_keys: undefined,
        argv: ["true"],
      }, context),
    SshError,
    "authentication failed",
  );
  // The scan ran, but a failed operation left no durable trust behind.
  assertEquals(calls.some((c) => c.cmd === "ssh-keyscan"), true);
  assertEquals(written.length, 0);
});

Deno.test("a second user on a pinned host:port verifies against the shared pin", async () => {
  const calls: Call[] = [];
  const deps = fakeDeps(fakeRun(calls));
  const m = createModel(deps);
  const { context, written } = testContext({
    [`connection-${HOSTPORT}`]: {
      host_keys: [{ type: "ssh-ed25519", key: KEY }],
    },
  });
  await m.methods.exec.execute({
    ...STRICT,
    user: "deploy",
    host_key_policy: "insecure_tofu",
    host_keys: undefined,
    argv: ["true"],
  }, context);
  // The host:port pin is reused: no first-use scan and strict verification.
  assertEquals(calls.some((c) => c.cmd === "ssh-keyscan"), false);
  assertEquals(
    calls.find((c) => c.cmd === "ssh")?.args.includes(
      "StrictHostKeyChecking=yes",
    ),
    true,
  );
  // The second user does not rewrite the shared pin.
  assertEquals(written.some((w) => w.specName === "connection"), false);
});

Deno.test("a supplied pin that disagrees with the record is refused (live X5b)", async () => {
  const calls: Call[] = [];
  const deps = fakeDeps(fakeRun(calls));
  const m = createModel(deps);
  const { context } = testContext({
    [`connection-${HOSTPORT}`]: {
      host_keys: [{ type: "ssh-ed25519", key: KEY }],
    },
  });
  await assertRejects(
    () =>
      m.methods.exec.execute({
        ...STRICT,
        host_key_policy: "insecure_tofu",
        host_keys: [`ssh-ed25519 QkJCQkJC`],
        argv: ["true"],
      }, context),
    SshConfigError,
    "do not match",
  );
  assertEquals(calls.some((c) => c.cmd === "ssh"), false);
});

Deno.test("a supplied pin for another host is refused, not substituted (live X7b)", async () => {
  const calls: Call[] = [];
  const deps = fakeDeps(fakeRun(calls));
  const m = createModel(deps);
  const { context } = testContext({
    [`connection-${HOSTPORT}`]: {
      host_keys: [{ type: "ssh-ed25519", key: KEY }],
    },
  });
  await assertRejects(
    () =>
      m.methods.exec.execute({
        ...STRICT,
        host_key_policy: "insecure_tofu",
        host_keys: [`other.example.com ssh-ed25519 ${KEY}`],
        argv: ["true"],
      }, context),
    SshConfigError,
    "none apply",
  );
  assertEquals(calls.some((c) => c.cmd === "ssh"), false);
});

Deno.test("a supplied pin that agrees with the record proceeds strictly", async () => {
  const calls: Call[] = [];
  const deps = fakeDeps(fakeRun(calls));
  const m = createModel(deps);
  const { context } = testContext({
    [`connection-${HOSTPORT}`]: {
      host_keys: [{ type: "ssh-ed25519", key: KEY }],
    },
  });
  await m.methods.exec.execute({
    ...STRICT,
    host_key_policy: "insecure_tofu",
    host_keys: [`ssh-ed25519 ${KEY}`],
    argv: ["true"],
  }, context);
  assertEquals(
    calls.find((c) => c.cmd === "ssh")?.args.includes(
      "StrictHostKeyChecking=yes",
    ),
    true,
  );
});

Deno.test("insecure_tofu refuses a changed key on a later run", async () => {
  const calls: Call[] = [];
  const deps = fakeDeps(fakeRun(calls, {
    ssh: () => ({
      code: 255,
      stdout: "",
      stderr: "Host key verification failed.\n",
    }),
  }));
  const m = createModel(deps);
  const { context } = testContext({
    [`connection-${HOSTPORT}`]: {
      host_keys: [{ type: "ssh-ed25519", key: "QkJCQkJC" }],
    },
  });
  await assertRejects(
    () =>
      m.methods.exec.execute({
        ...STRICT,
        host_key_policy: "insecure_tofu",
        host_keys: undefined,
        argv: ["true"],
      }, context),
    SshError,
    "host key",
  );
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
