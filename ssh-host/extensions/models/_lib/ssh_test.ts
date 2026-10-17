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
  exec,
  fingerprint,
  type HostKey,
  keysForHost,
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
  assertEquals(typeof sshModule.quoteArgv, "function");
  assertEquals(typeof sshModule.buildRemoteCommand, "function");
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
  assertEquals(result, { stdout: "ok\n", stderr: "", exit_code: 0 });

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
  });
});

Deno.test("exec returns an unexplained 255 as data", async () => {
  const calls: Call[] = [];
  const deps = fakeDeps(fakeRun(calls, {
    ssh: () => ({ code: 255, stdout: "", stderr: "remote said no\n" }),
  }));
  assertEquals((await exec(deps, STRICT_TARGET, ["./script"])).exit_code, 255);
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
  let seen: Uint8Array | undefined;
  const deps = fakeDeps(fakeRun(calls, {
    ssh: (_args, options) => {
      seen = typeof options.stdin === "string"
        ? new TextEncoder().encode(options.stdin)
        : options.stdin;
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
  assertEquals(
    result.sha256,
    await sha256Hex("placeholder config\n"),
  );
  assertEquals(result.changed, true);
  assertEquals(new TextDecoder().decode(seen), "placeholder config\n");
  const sshCalls = calls.filter((c) => c.cmd === "ssh");
  // First the idempotence probe, then the write.
  assertEquals(sshCalls.length, 2);
  assertStringIncludes(sshCalls[0].args.at(-1) ?? "", "sha256sum");
  assertEquals(sshCalls[0].stdin, undefined);
  const remote = sshCalls[1].args.at(-1) ?? "";
  assertStringIncludes(remote, "mktemp");
  assertStringIncludes(remote, "chmod 0640");
  assertStringIncludes(remote, `mv -f \"$t\" '/etc/wireguard/wg0.conf'`);
  for (const call of calls) {
    assertEquals(call.args.join(" ").includes("placeholder config"), false);
  }
});

Deno.test("upload is idempotent: matching bytes mean no write", async () => {
  const calls: Call[] = [];
  const content = "already there\n";
  const sha = await sha256Hex(content);
  const deps = fakeDeps(fakeRun(calls, {
    ssh: () => ({ code: 0, stdout: `${sha}  /etc/x\n`, stderr: "" }),
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
