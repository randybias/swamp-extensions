import {
  assert,
  assertEquals,
  assertRejects,
  assertStringIncludes,
  assertThrows,
} from "jsr:@std/assert@1.0.19";
import {
  assertHost,
  assertMode,
  assertRemotePath,
  assertUser,
  base64Decode,
  buildKnownHosts,
  buildRemoteCommand,
  checkHostKeys,
  type CommandResult,
  type CommandRunner,
  denoDeps,
  denoRunner,
  exec,
  execPipeline,
  fingerprint,
  type HostKey,
  keysForHost,
  MAX_EXEC_TIMEOUT_MS,
  parseHostKeys,
  posixQuote,
  quoteArgv,
  type RemoteOperator,
  type RunOptions,
  scanHostKeys,
  sha256Hex,
  SshConfigError,
  type SshDeps,
  SshError,
  upload,
  waitConnection,
} from "./ssh.ts";
import * as sshModule from "./ssh.ts";

const KEY: HostKey = {
  type: "ssh-ed25519",
  key: "QUFBQUFB",
};
const OTHER: HostKey = {
  type: "ssh-ed25519",
  key: "QkJCQkJC",
};
const PRIVATE_KEY = "PLACEHOLDER-PRIVATE-KEY-MATERIAL";
const HOST = "192.0.2.10";

interface Call {
  cmd: string;
  args: string[];
  stdin?: Uint8Array | string;
  env?: Record<string, string>;
  timeoutMs?: number;
  truncate?: boolean;
}

/** A fake runner that answers ssh-agent/ssh-add and delegates ssh/keyscan. */
function fakeRun(
  calls: Call[],
  handlers: {
    ssh?: (args: string[], options: RunOptions) => CommandResult;
    keyscan?: (args: string[]) => CommandResult;
    add?: () => CommandResult;
  } = {},
): CommandRunner {
  return (cmd, args, options = {}) => {
    calls.push({
      cmd,
      args,
      stdin: options.stdin,
      env: options.env,
      timeoutMs: options.timeoutMs,
      truncate: options.truncate,
    });
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
        handlers.keyscan?.(args) ?? { code: 0, stdout: "", stderr: "" },
      );
    }
    if (cmd === "ssh") {
      return Promise.resolve(
        handlers.ssh?.(args, options) ??
          { code: 0, stdout: "ok\n", stderr: "" },
      );
    }
    return Promise.resolve({ code: 0, stdout: "", stderr: "" });
  };
}

/** Fake deps with an advancing clock for wait loops. */
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

const STRICT_TARGET = {
  host: HOST,
  port: 22,
  user: "root",
  host_key_policy: "strict" as const,
  host_keys: [`${HOST} ${KEY.type} ${KEY.key}`],
  private_key: PRIVATE_KEY,
};

Deno.test("posixQuote makes one literal word of every metacharacter", () => {
  assertEquals(posixQuote("simple"), "'simple'");
  assertEquals(posixQuote(""), "''");
  assertEquals(posixQuote("a'b"), "'a'\\''b'");
  for (
    const evil of [
      "; rm -rf /",
      "$(id)",
      "`id`",
      "a\nb",
      "$HOME",
      "*",
      "a && b",
      "a | b",
      "> /etc/passwd",
    ]
  ) {
    const quoted = posixQuote(evil);
    assertEquals(quoted.startsWith("'"), true);
    assertEquals(quoted.endsWith("'"), true);
    // Stripping the outer quotes leaves the value untouched; no shell runs.
    assertEquals(quoted.slice(1, -1).replaceAll("'\\''", "'"), evil);
    assertEquals(/^'[^']*(?:'\\''[^']*)*'$/.test(quoted), true);
  }
});

Deno.test("parseHostKeys reads keyscan and bare lines, skipping comments", () => {
  const keys = parseHostKeys(
    `# ${HOST}:22 SSH-2.0-OpenSSH\n${HOST} ${KEY.type} ${KEY.key}\n${OTHER.type} ${OTHER.key}\n`,
  );
  assertEquals(keys, [{ host: HOST, ...KEY }, OTHER]);
});

Deno.test("parseHostKeys accepts non-ssh algorithm names on bare lines", () => {
  const sk = {
    type: "sk-ed25519",
    key: "QkJCQkJC",
  };
  assertEquals(parseHostKeys(`${sk.type} ${sk.key}\n`), [sk]);
});

Deno.test("keysForHost accepts both host and [host]:22 pins on port 22", () => {
  assertEquals(
    keysForHost([{ host: `[${HOST}]:22`, ...KEY }], HOST, 22),
    [{ host: `[${HOST}]:22`, ...KEY }],
  );
});

Deno.test("the public surface exposes no raw command-string entry point", () => {
  assertEquals("runRemote" in sshModule, false);
  assertEquals(typeof sshModule.exec, "function");
  assertEquals(typeof sshModule.execPipeline, "function");
  assertEquals(typeof sshModule.quoteArgv, "function");
  assertEquals(typeof sshModule.buildRemoteCommand, "function");
});

Deno.test("execPipeline runs quoted stages joined by an allowlisted operator", async () => {
  const calls: Call[] = [];
  const deps = fakeDeps(fakeRun(calls));
  await execPipeline(deps, STRICT_TARGET, [
    ["wg", "show"],
    ["grep", "peer"],
  ], ["|"] as RemoteOperator[]);
  assertEquals(
    calls.find((c) => c.cmd === "ssh")?.args.at(-1),
    "'wg' 'show' | 'grep' 'peer'",
  );
});

Deno.test("quoteArgv and buildRemoteCommand only emit quoted words", () => {
  assertEquals(quoteArgv(["echo", "; rm -rf /"]), "'echo' '; rm -rf /'");
  assertEquals(
    buildRemoteCommand([
      ["wg", "show"],
      ["grep", "-c", "handshake"],
    ], ["|"] as RemoteOperator[]),
    "'wg' 'show' | 'grep' '-c' 'handshake'",
  );
  assertEquals(
    buildRemoteCommand([["true"], ["false"]], ["&&"] as RemoteOperator[]),
    "'true' && 'false'",
  );
  assertThrows(() => quoteArgv([]), SshConfigError);
  assertThrows(() => quoteArgv(["a", 1 as unknown as string]), SshConfigError);
  assertThrows(
    () => quoteArgv(["echo", "a\u0000b"]),
    SshConfigError,
    "NUL",
  );
  assertThrows(
    () => buildRemoteCommand([["a"], ["b"]], []),
    SshConfigError,
    "operator",
  );
  assertThrows(
    () => buildRemoteCommand([["a"], ["b"]], ["$(id)" as RemoteOperator]),
    SshConfigError,
    "unsupported",
  );
});

Deno.test("keysForHost honours the host field and the port", () => {
  const keys = parseHostKeys(
    `${HOST},server.example.com ${KEY.type} ${KEY.key}\n` +
      `[${HOST}]:2222 ${OTHER.type} ${OTHER.key}\n` +
      `198.51.100.7 ${OTHER.type} ${OTHER.key}\n` +
      `${OTHER.type} ${OTHER.key}\n`,
  );
  assertEquals(keysForHost(keys, HOST, 22).map((k) => k.key), [
    KEY.key,
    OTHER.key,
  ]);
  assertEquals(keysForHost(keys, HOST, 2222).length, 2);
  assertEquals(
    keysForHost(keys, "203.0.113.9", 22).every((k) => k.host === undefined),
    true,
  );
});

Deno.test("checkHostKeys strict matches, ignores unpinned types, refuses otherwise", () => {
  const RSA: HostKey = {
    type: "ssh-rsa",
    key: "Q0NDQ0ND",
  };
  assertEquals(checkHostKeys([KEY], "strict", [KEY, OTHER]), [KEY]);
  assertEquals(checkHostKeys([RSA, KEY], "strict", [KEY]), [KEY]);
  assertThrows(
    () => checkHostKeys([OTHER], "strict", [KEY]),
    SshError,
    "mismatch",
  );
  assertThrows(
    () => checkHostKeys([KEY], "strict", []),
    SshConfigError,
    "requires",
  );
  assertThrows(
    () => checkHostKeys([], "strict", [KEY]),
    SshError,
    "no host keys",
  );
  assertThrows(
    () => checkHostKeys([RSA], "strict", [KEY]),
    SshError,
    "is pinned",
  );
});

Deno.test("checkHostKeys trusts freely only on a tofu first use", () => {
  assertEquals(checkHostKeys([OTHER], "insecure_tofu"), [OTHER]);
  assertEquals(checkHostKeys([], "insecure_tofu"), []);
  // A recorded pin is verified under either policy.
  assertEquals(checkHostKeys([KEY], "insecure_tofu", [KEY]), [KEY]);
  assertThrows(
    () => checkHostKeys([OTHER], "insecure_tofu", [KEY]),
    SshError,
    "mismatch",
  );
});

Deno.test("buildKnownHosts renders the host field and port", () => {
  assertEquals(
    buildKnownHosts(HOST, 22, [KEY]),
    `${HOST} ${KEY.type} ${KEY.key}\n`,
  );
  assertEquals(
    buildKnownHosts(HOST, 2222, [KEY]),
    `[${HOST}]:2222 ${KEY.type} ${KEY.key}\n`,
  );
  assertEquals(buildKnownHosts(HOST, 22, []), "");
});

Deno.test("fingerprint matches ssh-keygen's SHA256 format", async () => {
  assertEquals(
    await fingerprint(KEY.key),
    "SHA256:adxsMhDiXmLFk4/06EHoHOPH0s3lg1U0eKd9f8s4nzA",
  );
});

Deno.test("sha256Hex and base64Decode round-trip known values", async () => {
  assertEquals(
    await sha256Hex("abc"),
    "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
  );
  assertEquals(Array.from(base64Decode("QUJD")), [65, 66, 67]);
  assertThrows(() => base64Decode("not base64!"), SshConfigError);
});

Deno.test("input grammars reject injection attempts", () => {
  for (
    const bad of ["a;b", "$(id)", "host name", "a`b`", "-oProxyCommand=x"]
  ) {
    assertThrows(() => assertHost(bad), SshConfigError);
  }
  for (const bad of ["root;id", "-l", "a b", ".root", "a'b"]) {
    assertThrows(() => assertUser(bad), SshConfigError);
  }
  for (
    const bad of [
      "relative/path",
      "/tmp/x'; rm -rf /",
      "/a/../etc/passwd",
      "/tmp/$(id)",
      "/tmp/a b",
      "/etc/",
      "/etc/.",
      "/a/./b",
    ]
  ) {
    assertThrows(() => assertRemotePath(bad), SshConfigError);
  }
  assertEquals(assertUser("Deploy.User"), undefined);
  for (const bad of ["999", "08", "u+rw", "77777"]) {
    assertThrows(() => assertMode(bad), SshConfigError);
  }
  assertHost("192.0.2.10");
  assertHost("server-1.example.com");
  assertHost("2001:db8::1");
  assertUser("root");
  assertRemotePath("/etc/wireguard/wg0.conf");
  assertMode("0640");
});

Deno.test("exec quotes the argv and never puts the key on the command line", async () => {
  const calls: Call[] = [];
  const deps = fakeDeps(fakeRun(calls));
  const result = await exec(deps, STRICT_TARGET, ["echo", "; rm -rf /"]);
  assertEquals(result, {
    stdout: "ok\n",
    stderr: "",
    exit_code: 0,
    truncated: false,
    duration_ms: 0,
  });

  const ssh = calls.find((c) => c.cmd === "ssh");
  assert(ssh);
  assertEquals(ssh.args.at(-1), "'echo' '; rm -rf /'");
  assertEquals(ssh.args.includes("StrictHostKeyChecking=yes"), true);
  assertEquals(ssh.args.includes("IdentityAgent=/tmp/agent.test"), true);
  assertEquals(ssh.args.some((a) => a.startsWith("UserKnownHostsFile=")), true);
  assertEquals(ssh.args.includes("GlobalKnownHostsFile=/dev/null"), true);
  assertEquals(ssh.args.slice(0, 2), ["-F", "/dev/null"]);
  // The key travels over stdin to ssh-add and appears nowhere in any argv.
  const add = calls.find((c) => c.cmd === "ssh-add");
  assertEquals(add?.stdin, `${PRIVATE_KEY}\n`);
  for (const call of calls) {
    assertEquals(call.args.join(" ").includes(PRIVATE_KEY), false);
  }
  // The agent is always torn down.
  assertEquals(calls.at(-1)?.cmd, "ssh-agent");
  assertEquals(calls.at(-1)?.args, ["-k"]);
});

Deno.test("exec refusal modes name the host and leak no key material", async () => {
  for (
    const [stderr, message] of [
      ["Host key verification failed.", "host key verification failed"],
      [
        "root@192.0.2.10: Permission denied (publickey).",
        "authentication failed",
      ],
      [
        "ssh: connect to host 192.0.2.10 port 22: Connection refused",
        "could not connect",
      ],
    ] as const
  ) {
    const calls: Call[] = [];
    const deps = fakeDeps(fakeRun(calls, {
      ssh: () => ({ code: 255, stdout: "", stderr }),
    }));
    const err = await assertRejects(
      () => exec(deps, STRICT_TARGET, ["true"]),
      SshError,
    );
    assertStringIncludes(err.message, message);
    assertStringIncludes(err.message, HOST);
    assertEquals(err.message.includes(PRIVATE_KEY), false);
  }
});

Deno.test("exec returns a non-zero remote exit as data, not an error", async () => {
  const calls: Call[] = [];
  const deps = fakeDeps(fakeRun(calls, {
    ssh: () => ({ code: 1, stdout: "", stderr: "boom\n" }),
  }));
  assertEquals(await exec(deps, STRICT_TARGET, ["false"]), {
    stdout: "",
    stderr: "boom\n",
    exit_code: 1,
    truncated: false,
    duration_ms: 0,
  });
});

Deno.test("exec enforces the output capture cap with a typed error", async () => {
  const calls: Call[] = [];
  const deps = fakeDeps(fakeRun(calls, {
    ssh: () => ({ code: 0, stdout: "0123456789", stderr: "" }),
  }));
  await assertRejects(
    () => exec(deps, { ...STRICT_TARGET, max_output_bytes: 4 }, ["true"]),
    SshError,
    "capture limit",
  );
});

Deno.test("exec treats any ssh exit 255 as a transport error, not data", async () => {
  const calls: Call[] = [];
  const deps = fakeDeps(fakeRun(calls, {
    ssh: () => ({ code: 255, stdout: "", stderr: "remote said no\n" }),
  }));
  await assertRejects(
    () => exec(deps, STRICT_TARGET, ["./script"]),
    SshError,
    "transport failed",
  );
});

/**
 * The exact ssh argv a no-options exec produced before the options extension,
 * with the transport-internal random known_hosts path masked.
 */
const GOLDEN_EXEC_ARGS = [
  "-F",
  "/dev/null",
  "-o",
  "IdentityFile=none",
  "-o",
  "StrictHostKeyChecking=yes",
  "-o",
  "UserKnownHostsFile=<tmp>",
  "-o",
  "GlobalKnownHostsFile=/dev/null",
  "-o",
  "ConnectTimeout=15",
  "-o",
  "ServerAliveInterval=5",
  "-o",
  "ServerAliveCountMax=2",
  "-o",
  "IdentityAgent=/tmp/agent.test",
  "-o",
  "BatchMode=yes",
  "-o",
  "PreferredAuthentications=publickey",
  "-p",
  "22",
  "-l",
  "root",
  HOST,
  "'echo' 'hi'",
];

Deno.test("exec without options spawns the byte-identical pre-extension argv", async () => {
  const calls: Call[] = [];
  const deps = fakeDeps(fakeRun(calls));
  const result = await exec(deps, STRICT_TARGET, ["echo", "hi"]);
  assertEquals(result, {
    stdout: "ok\n",
    stderr: "",
    exit_code: 0,
    truncated: false,
    duration_ms: 0,
  });
  const ssh = calls.find((c) => c.cmd === "ssh");
  assert(ssh);
  assertEquals(
    ssh.args.map((a) =>
      a.startsWith("UserKnownHostsFile=") ? "UserKnownHostsFile=<tmp>" : a
    ),
    GOLDEN_EXEC_ARGS,
  );
  assertEquals(ssh.stdin, undefined);
  assertEquals(ssh.timeoutMs, undefined);
  assertEquals(ssh.truncate, undefined);
});

Deno.test("exec streams stdin byte-exact, including NUL, and never on argv", async () => {
  const payload = new Uint8Array([0, 1, 2, 255, 0, 65, 0, 10]);
  const calls: Call[] = [];
  const deps = fakeDeps(fakeRun(calls));
  await exec(deps, STRICT_TARGET, ["sha256sum"], { stdin: payload });
  const ssh = calls.find((c) => c.cmd === "ssh");
  assert(ssh);
  assert(ssh.stdin instanceof Uint8Array);
  assertEquals([...(ssh.stdin as Uint8Array)], [...payload]);
  for (const call of calls) {
    assertEquals(call.args.join(" ").includes("\u0000"), false);
  }
});

Deno.test("exec streams a large stdin payload byte-exact", async () => {
  const payload = new Uint8Array(256 * 1024);
  for (let i = 0; i < payload.length; i++) payload[i] = i % 256;
  const calls: Call[] = [];
  const deps = fakeDeps(fakeRun(calls));
  await exec(deps, STRICT_TARGET, ["cat"], { stdin: payload });
  const ssh = calls.find((c) => c.cmd === "ssh");
  assert(ssh);
  const sent = ssh.stdin as Uint8Array;
  assertEquals(sent.byteLength, payload.byteLength);
  assertEquals(sent[255], 255);
  assertEquals(sent[256], 0);
});

Deno.test("exec timeout kills ssh and raises a typed timeout", async () => {
  const calls: Call[] = [];
  const deps = fakeDeps(fakeRun(calls, {
    ssh: () => ({ code: -1, stdout: "partial", stderr: "", timedOut: true }),
  }));
  const err = await assertRejects(
    () => exec(deps, STRICT_TARGET, ["sleep", "5"], { timeoutMs: 50 }),
    SshError,
  ) as SshError;
  assertEquals(err.kind, "timeout");
  assertStringIncludes(err.message, "timed out");
  assertEquals(calls.find((c) => c.cmd === "ssh")?.timeoutMs, 50);
});

Deno.test("exec truncates and flags instead of throwing when maxOutputBytes is set", async () => {
  const calls: Call[] = [];
  const deps = fakeDeps(fakeRun(calls, {
    ssh: () => ({ code: 0, stdout: "0123", stderr: "", truncated: true }),
  }));
  const result = await exec(deps, STRICT_TARGET, ["true"], {
    maxOutputBytes: 4,
  });
  assertEquals(result, {
    stdout: "0123",
    stderr: "",
    exit_code: 0,
    truncated: true,
    duration_ms: 0,
  });
  assertEquals(calls.find((c) => c.cmd === "ssh")?.truncate, true);
});

Deno.test("a secret in stdin never appears on argv or in a transport error", async () => {
  const secret = "PLACEHOLDER-SECRET-VALUE";
  const calls: Call[] = [];
  const deps = fakeDeps(fakeRun(calls, {
    ssh: () => ({ code: 255, stdout: "", stderr: "Connection refused" }),
  }));
  const err = await assertRejects(
    () => exec(deps, STRICT_TARGET, ["cat"], { stdin: secret }),
    SshError,
  ) as SshError;
  assertEquals(err.message.includes(secret), false);
  for (const call of calls) {
    assertEquals(call.args.join(" ").includes(secret), false);
  }
});

Deno.test("exec rejects invalid maxOutputBytes and timeoutMs before connecting", async () => {
  const calls: Call[] = [];
  const deps = fakeDeps(fakeRun(calls));
  const target = { ...STRICT_TARGET, max_output_bytes: 1000 };
  for (const bad of [NaN, Infinity, -Infinity, 0, -1, 1.5, 1001]) {
    await assertRejects(
      () => exec(deps, target, ["true"], { maxOutputBytes: bad }),
      SshConfigError,
      "maxOutputBytes",
    );
  }
  for (const bad of [NaN, Infinity, 0, -1, 1.5, MAX_EXEC_TIMEOUT_MS + 1]) {
    await assertRejects(
      () => exec(deps, target, ["true"], { timeoutMs: bad }),
      SshConfigError,
      "timeoutMs",
    );
  }
  // Nothing was spawned for any rejected option.
  assertEquals(calls.length, 0);
  const ok = await exec(deps, target, ["true"], {
    maxOutputBytes: 1000,
    timeoutMs: 1,
  });
  assertEquals(ok.exit_code, 0);
});

Deno.test("denoRunner streams a multi-megabyte stdin while stderr floods", async () => {
  const big = new Uint8Array(4 * 1024 * 1024);
  for (let i = 0; i < big.length; i++) big[i] = i % 256;
  const res = await denoRunner(
    "sh",
    [
      "-c",
      "i=0; while [ $i -lt 2000 ]; do echo flood >&2; i=$((i+1)); done; wc -c",
    ],
    { stdin: big, maxOutputBytes: 1024 * 1024 },
  );
  assertEquals(res.code, 0);
  assertEquals(res.stdout.trim(), String(big.length));
  assertEquals(res.truncated, false);
});

Deno.test("denoRunner truncates at the cap and returns without draining", async () => {
  const started = Date.now();
  const res = await denoRunner("sh", ["-c", "yes"], {
    maxOutputBytes: 128,
    truncate: true,
  });
  const elapsed = Date.now() - started;
  assertEquals(res.truncated, true);
  assertEquals(res.stdout.length, 128);
  assert(elapsed < 5000, `truncation took ${elapsed}ms`);
});

Deno.test("denoRunner caps without truncation by throwing", async () => {
  await assertRejects(
    () => denoRunner("sh", ["-c", "printf 0123456789"], { maxOutputBytes: 4 }),
    SshError,
    "capture limit",
  );
});

Deno.test("denoRunner times out a large stdin write and leaves no child", async () => {
  const big = new Uint8Array(4 * 1024 * 1024);
  const started = Date.now();
  const res = await denoRunner("sh", ["-c", "exec sleep 10"], {
    stdin: big,
    timeoutMs: 300,
    maxOutputBytes: 1024 * 1024,
  });
  const elapsed = Date.now() - started;
  assertEquals(res.timedOut, true);
  assert(elapsed < 5000, `timeout took ${elapsed}ms`);
});

Deno.test("strict needs pinned keys and rejects two credentials at once", async () => {
  const deps = fakeDeps(fakeRun([]));
  await assertRejects(
    () => exec(deps, { ...STRICT_TARGET, host_keys: undefined }, ["true"]),
    SshConfigError,
    "requires host_keys",
  );
  await assertRejects(
    () =>
      exec(deps, { ...STRICT_TARGET, password: "notsecret" }, [
        "true",
      ]),
    SshConfigError,
    "not both",
  );
});

Deno.test("password auth uses askpass, never argv", async () => {
  const calls: Call[] = [];
  const password = "placeholder-password";
  const deps = fakeDeps(fakeRun(calls));
  await exec(deps, {
    host: HOST,
    port: 22,
    user: "root",
    host_key_policy: "insecure_tofu",
    password,
  }, ["true"]);
  const ssh = calls.find((c) => c.cmd === "ssh");
  assert(ssh);
  assertEquals(ssh.args.includes("StrictHostKeyChecking=accept-new"), true);
  assertEquals(ssh.args.some((a) => a.startsWith("SSH_ASKPASS")), false);
  assert(ssh.env);
  assertEquals(ssh.env.SSH_ASKPASS_SECRET, password);
  assert(ssh.env.SSH_ASKPASS);
  for (const call of calls) {
    assertEquals(call.args.join(" ").includes(password), false);
  }
});

Deno.test("upload streams bytes over stdin and renames atomically", async () => {
  const calls: Call[] = [];
  const contentSha = await sha256Hex("placeholder config\n");
  let seen: Uint8Array | undefined;
  const deps = fakeDeps(fakeRun(calls, {
    ssh: (args, options) => {
      const remote = args.at(-1) ?? "";
      if (remote.includes("mktemp")) {
        seen = typeof options.stdin === "string"
          ? new TextEncoder().encode(options.stdin)
          : options.stdin;
        // The remote prints the destination's hash and mode; the expected hash
        // is never sent.
        return { code: 0, stdout: `${contentSha} 640\n`, stderr: "" };
      }
      return { code: 0, stdout: "", stderr: "" };
    },
  }));
  const result = await upload(deps, STRICT_TARGET, {
    path: "/etc/wireguard/wg0.conf",
    content: "placeholder config\n",
    mode: "0640",
  });
  assertEquals(result.path, "/etc/wireguard/wg0.conf");
  assertEquals(result.bytes, 19);
  assertEquals(result.sha256, contentSha);
  assertEquals(result.changed, true);
  assertEquals(new TextDecoder().decode(seen), "placeholder config\n");
  const sshCalls = calls.filter((c) => c.cmd === "ssh");
  // First the idempotence probe, then the write.
  assertEquals(sshCalls.length, 2);
  assertStringIncludes(sshCalls[0].args.at(-1) ?? "", "sha256sum");
  assertEquals(sshCalls[0].stdin, undefined);
  const remote = sshCalls[1].args.at(-1) ?? "";
  assertStringIncludes(remote, "mktemp");
  assertStringIncludes(remote, "chmod '0640'");
  assertStringIncludes(remote, `f='/etc/wireguard/wg0.conf'`);
  // No-target-directory rename on Linux only, then a post-move printf.
  assertStringIncludes(remote, "mv -T");
  assertStringIncludes(remote, "printf");
  assertEquals(remote.includes("mv -f "), false);
  for (const call of calls) {
    assertEquals(call.args.join(" ").includes("placeholder config"), false);
  }
});

Deno.test("upload never puts the content hash on a spawned argv or in script text", async () => {
  const calls: Call[] = [];
  const contentSha = await sha256Hex("low-entropy-secret\n");
  const deps = fakeDeps(fakeRun(calls, {
    ssh: (args) => {
      const remote = args.at(-1) ?? "";
      return remote.includes("mktemp")
        ? { code: 0, stdout: `${contentSha} 600\n`, stderr: "" }
        : { code: 0, stdout: "", stderr: "" };
    },
  }));
  await upload(deps, STRICT_TARGET, {
    path: "/etc/wireguard/secret.key",
    content: "low-entropy-secret\n",
  });
  for (const call of calls) {
    const text = call.args.join(" ");
    assertEquals(
      text.includes(contentSha),
      false,
      `expected hash on argv: ${text}`,
    );
    assertEquals(
      (text.match(/[0-9a-f]{64}/g) ?? []).length,
      0,
      `no 64-hex string may appear on argv or in script text: ${text}`,
    );
  }
});

Deno.test("upload is idempotent: matching bytes and mode mean no write", async () => {
  const calls: Call[] = [];
  const content = "already there\n";
  const sha = await sha256Hex(content);
  const deps = fakeDeps(fakeRun(calls, {
    ssh: () => ({ code: 0, stdout: `${sha} 600\n`, stderr: "" }),
  }));
  const result = await upload(deps, STRICT_TARGET, {
    path: "/etc/x",
    content,
  });
  assertEquals(result.changed, false);
  const sshCalls = calls.filter((c) => c.cmd === "ssh");
  assertEquals(sshCalls.length, 1);
  assertEquals(sshCalls[0].stdin, undefined);
});

Deno.test("upload replaces through the temp path on a mode-only difference", async () => {
  const calls: Call[] = [];
  const content = "same bytes\n";
  const sha = await sha256Hex(content);
  const deps = fakeDeps(fakeRun(calls, {
    ssh: (args) =>
      (args.at(-1) ?? "").includes("mktemp")
        ? { code: 0, stdout: `${sha} 600\n`, stderr: "" }
        : { code: 0, stdout: `${sha} 644\n`, stderr: "" },
  }));
  const result = await upload(deps, STRICT_TARGET, {
    path: "/etc/x",
    content,
    mode: "0600",
  });
  assertEquals(result.changed, true);
  const sshCalls = calls.filter((c) => c.cmd === "ssh");
  assertEquals(sshCalls.length, 2);
  const remote = sshCalls[1].args.at(-1) ?? "";
  assertStringIncludes(remote, "mktemp");
  assertStringIncludes(remote, "chmod '0600'");
  assertStringIncludes(remote, "mv -T");
  // Never a chmod-in-place on the destination.
  assertEquals(remote.includes("chmod '0600' '/etc/x'"), false);
  assertEquals(sshCalls[1].stdin !== undefined, true);
});

Deno.test("upload refuses a symlink destination without following it", async () => {
  const calls: Call[] = [];
  const deps = fakeDeps(fakeRun(calls, {
    ssh: () => ({ code: 0, stdout: "SYMLINK\n", stderr: "" }),
  }));
  await assertRejects(
    () => upload(deps, STRICT_TARGET, { path: "/etc/x", content: "x" }),
    SshError,
    "symlink",
  );
  assertEquals(calls.filter((c) => c.cmd === "ssh").length, 1);
});

Deno.test("upload fails closed on a target without a no-target-directory rename", async () => {
  const calls: Call[] = [];
  const marker = "ssh-host: upload requires a Linux target with mv -T";
  const deps = fakeDeps(fakeRun(calls, {
    ssh: (args) => {
      const remote = args.at(-1) ?? "";
      return remote.includes("mktemp")
        ? { code: 1, stdout: `${marker}\n`, stderr: "" }
        : { code: 0, stdout: "MISSING\n", stderr: "" };
    },
  }));
  await assertRejects(
    () => upload(deps, STRICT_TARGET, { path: "/etc/x", content: "x" }),
    SshConfigError,
    "Linux target",
  );
});

Deno.test("upload refuses a destination that is a directory", async () => {
  const calls: Call[] = [];
  const deps = fakeDeps(fakeRun(calls, {
    ssh: () => ({ code: 0, stdout: "DIRECTORY\n", stderr: "" }),
  }));
  await assertRejects(
    () => upload(deps, STRICT_TARGET, { path: "/etc", content: "x" }),
    SshError,
    "is a directory",
  );
  assertEquals(calls.filter((c) => c.cmd === "ssh").length, 1);
});

Deno.test("upload to an unwritable path is a typed error", async () => {
  const calls: Call[] = [];
  const deps = fakeDeps(fakeRun(calls, {
    ssh: () => ({ code: 1, stdout: "", stderr: "mktemp: Permission denied\n" }),
  }));
  await assertRejects(
    () => upload(deps, STRICT_TARGET, { path: "/proc/1/nope", content: "x" }),
    SshError,
    "/proc/1/nope",
  );
});

Deno.test("upload validates the destination and mode before connecting", async () => {
  const deps = fakeDeps(fakeRun([]));
  await assertRejects(
    () => upload(deps, STRICT_TARGET, { path: "/a/../b", content: "x" }),
    SshConfigError,
  );
  await assertRejects(
    () =>
      upload(deps, STRICT_TARGET, { path: "/ok", content: "x", mode: "9x" }),
    SshConfigError,
  );
});

Deno.test("scanHostKeys passes the host and port as separate arguments", async () => {
  let seen: string[] = [];
  const run: CommandRunner = (_cmd, args) => {
    seen = args;
    return Promise.resolve({
      code: 0,
      stdout: `${HOST} ${KEY.type} ${KEY.key}\n`,
      stderr: "",
    });
  };
  assertEquals(await scanHostKeys(run, HOST, 2222), [{ host: HOST, ...KEY }]);
  assertEquals(seen, ["-T", "5", "-p", "2222", HOST]);
});

Deno.test("waitConnection strict returns the matched keys with fingerprints", async () => {
  const calls: Call[] = [];
  const deps = fakeDeps(fakeRun(calls, {
    keyscan: () => ({
      code: 0,
      stdout: `${HOST} ${KEY.type} ${KEY.key}\n`,
      stderr: "",
    }),
  }));
  const result = await waitConnection(deps, STRICT_TARGET, { timeout_s: 5 });
  assertEquals(result.reachable, true);
  assertEquals(result.host_keys.length, 1);
  assertEquals(result.host_keys[0].type, KEY.type);
  assertEquals(
    result.host_keys[0].sha256,
    "SHA256:adxsMhDiXmLFk4/06EHoHOPH0s3lg1U0eKd9f8s4nzA",
  );
});

Deno.test("waitConnection strict refuses a mismatched key", async () => {
  const calls: Call[] = [];
  const deps = fakeDeps(fakeRun(calls, {
    keyscan: () => ({
      code: 0,
      stdout: `${HOST} ${OTHER.type} ${OTHER.key}\n`,
      stderr: "",
    }),
  }));
  await assertRejects(
    () => waitConnection(deps, STRICT_TARGET, { timeout_s: 5 }),
    SshError,
    "mismatch",
  );
});

Deno.test("waitConnection times out on a host that never answers", async () => {
  const calls: Call[] = [];
  const deps = fakeDeps(fakeRun(calls, {
    keyscan: () => ({ code: 1, stdout: "", stderr: "" }),
  }));
  const err = await assertRejects(
    () =>
      waitConnection(deps, STRICT_TARGET, { timeout_s: 1, poll_interval_s: 1 }),
    SshError,
  );
  assertStringIncludes(err.message, HOST);
});

Deno.test("waitConnection insecure_tofu accepts the first keys observed", async () => {
  const calls: Call[] = [];
  const deps = fakeDeps(fakeRun(calls, {
    keyscan: () => ({
      code: 0,
      stdout: `${HOST} ${OTHER.type} ${OTHER.key}\n`,
      stderr: "",
    }),
  }));
  const result = await waitConnection(deps, {
    host: HOST,
    port: 22,
    user: "root",
    host_key_policy: "insecure_tofu",
  });
  assertEquals(result.host_keys[0].key, OTHER.key);
});

Deno.test("a supplied pin that matches no host refuses instead of accept-new", async () => {
  const deps = fakeDeps(fakeRun([]));
  await assertRejects(
    () =>
      exec(deps, {
        ...STRICT_TARGET,
        host_key_policy: "insecure_tofu",
        host_keys: [
          `other.example.com ${KEY.type} ${KEY.key}`,
        ],
      }, ["true"]),
    SshConfigError,
    "none apply",
  );
  // The same supplied set also refuses in waitConnection.
  const waitDeps = fakeDeps(fakeRun([]));
  await assertRejects(
    () =>
      waitConnection(waitDeps, {
        host: HOST,
        port: 22,
        user: "root",
        host_key_policy: "strict",
        host_keys: [`other.example.com ${KEY.type} ${KEY.key}`],
      }, { timeout_s: 1 }),
    SshConfigError,
    "none apply",
  );
});

Deno.test("waitConnection verifies a recorded tofu pin and refuses a change", async () => {
  const calls: Call[] = [];
  const good = fakeDeps(fakeRun(calls, {
    keyscan: () => ({
      code: 0,
      stdout: `${HOST} ${KEY.type} ${KEY.key}\n`,
      stderr: "",
    }),
  }));
  const result = await waitConnection(good, {
    host: HOST,
    port: 22,
    user: "root",
    host_key_policy: "insecure_tofu",
    host_keys: [`${KEY.type} ${KEY.key}`],
  });
  assertEquals(result.host_keys[0].key, KEY.key);

  const bad = fakeDeps(fakeRun([], {
    keyscan: () => ({
      code: 0,
      stdout: `${HOST} ${OTHER.type} ${OTHER.key}\n`,
      stderr: "",
    }),
  }));
  await assertRejects(
    () =>
      waitConnection(bad, {
        host: HOST,
        port: 22,
        user: "root",
        host_key_policy: "insecure_tofu",
        host_keys: [`${KEY.type} ${KEY.key}`],
      }),
    SshError,
    "mismatch",
  );
});

Deno.test("denoDeps is the production wiring", () => {
  assertEquals(typeof denoDeps.run, "function");
  assertEquals(typeof denoDeps.now, "function");
  assertEquals(typeof denoDeps.sleep, "function");
});
