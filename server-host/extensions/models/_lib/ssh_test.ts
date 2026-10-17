import {
  assertEquals,
  assertMatch,
  assertNotMatch,
  assertRejects,
  assertThrows,
} from "jsr:@std/assert@1.0.19";
import {
  assertHost,
  assertMode,
  assertRemotePath,
  assertUser,
  baseSshArgs,
  type CommandResult,
  type CommandRunner,
  exec,
  parseHostKeys,
  parseKeyscan,
  posixQuote,
  quoteArgv,
  renderKnownHosts,
  type SshDeps,
  SshError,
  type Target,
  upload,
  UPLOAD_SCRIPT,
  verifyHostKeys,
  waitConnection,
  withSession,
} from "./ssh.ts";

const KEY1 = "AAAAC3NzaC1lZDI1NTE5AAAAIFakeKeyOne";
const KEY2 = "AAAAC3NzaC1lZDI1NTE5AAAAIFakeKeyTwo";
const PEM =
  "-----BEGIN OPENSSH PRIVATE KEY-----\nZmFrZS1rZXktbWF0ZXJpYWw=\n-----END OPENSSH PRIVATE KEY-----";

interface Call {
  cmd: string;
  args: string[];
  stdin?: string;
  env?: Record<string, string>;
}

/** A fake spawner: ssh-agent and ssh-add succeed; `ssh` returns `sshResult`. */
function fakeDeps(
  sshResult: Partial<CommandResult> = {},
  keyscan = "",
) {
  const calls: Call[] = [];
  const files = new Map<string, string>();
  const removed: string[] = [];
  let clock = 0;
  const run: CommandRunner = (cmd, args, options) => {
    calls.push({
      cmd,
      args,
      stdin: options?.stdin
        ? new TextDecoder().decode(options.stdin)
        : undefined,
      env: options?.env,
    });
    if (cmd === "ssh-agent" && args[0] === "-s") {
      return Promise.resolve({
        code: 0,
        stdout:
          "SSH_AUTH_SOCK=/tmp/agent.sock; export SSH_AUTH_SOCK;\nSSH_AGENT_PID=4242; export SSH_AGENT_PID;\n",
        stderr: "",
      });
    }
    if (cmd === "ssh-keyscan") {
      return Promise.resolve({ code: 0, stdout: keyscan, stderr: "" });
    }
    if (cmd === "ssh") {
      return Promise.resolve({ code: 0, stdout: "", stderr: "", ...sshResult });
    }
    return Promise.resolve({ code: 0, stdout: "", stderr: "" });
  };
  const deps: SshDeps = {
    run,
    makeTempDir: () => Promise.resolve("/tmp/ssh-host-test"),
    writeFile: (p, t) => {
      files.set(p, t);
      return Promise.resolve();
    },
    removeDir: (p) => {
      removed.push(p);
      return Promise.resolve();
    },
    now: () => clock,
    sleep: (ms) => {
      clock += ms;
      return Promise.resolve();
    },
  };
  return { deps, calls, files, removed };
}

const T: Target = {
  host: "192.0.2.10",
  port: 22,
  user: "ops",
  hostKeyPolicy: "strict",
  hostKeys: [`192.0.2.10 ssh-ed25519 ${KEY1}`],
  privateKey: PEM,
  connectTimeoutS: 15,
};

// 1. schema / grammar

Deno.test("host, user, port, path and mode grammars reject hostile values", () => {
  for (const h of ["", "-oProxyCommand=x", "a b", "host;rm", "$(x)", "h\nx"]) {
    assertThrows(() => assertHost(h), SshError, "Invalid host");
  }
  assertHost("example.com");
  assertHost("192.0.2.1");
  assertHost("2001:db8::1");
  for (const u of ["", "Root", "a b", "x;y", "-l", "a\nb", "$(id)"]) {
    assertThrows(() => assertUser(u), SshError);
  }
  assertUser("ops_1");
  for (
    const p of [
      "relative",
      "/a/../b",
      "/a b",
      "/a;b",
      "/a$(x)",
      "/a\nb",
      "/dir/",
      "/a'b",
      "",
    ]
  ) {
    assertThrows(() => assertRemotePath(p), SshError);
  }
  assertRemotePath("/etc/app/config.yaml");
  for (const m of ["", "999", "7777x", "0o644", "64", "-1"]) {
    assertThrows(() => assertMode(m), SshError);
  }
  assertMode("0600");
});

// 2. pure mapping

Deno.test("posixQuote makes every element one literal word", () => {
  assertEquals(posixQuote("plain"), "'plain'");
  assertEquals(posixQuote("it's"), `'it'\\''s'`);
  assertThrows(() => posixQuote("a\0b"), SshError);
  assertEquals(quoteArgv(["echo", "a b"]), "'echo' 'a b'");
  assertThrows(() => quoteArgv([]), SshError);
  assertThrows(() => quoteArgv([""]), SshError);
});

const HOSTILE = [
  "; rm -rf /",
  "$(touch /tmp/pwn)",
  "`touch /tmp/pwn`",
  "a\nb; echo owned",
  'it\'s "quoted" \\ back',
  "&& echo owned",
  "| cat /etc/passwd",
  "> /tmp/pwn",
  "-n",
  "*",
  "$HOME ${IFS}",
];

Deno.test("quoted argv survives a real POSIX shell as literal words", async () => {
  for (const h of HOSTILE) {
    const cmd = quoteArgv(["printf", "%s|", h, h + "x"]);
    const out = await new Deno.Command("sh", { args: ["-c", cmd] }).output();
    assertEquals(
      new TextDecoder().decode(out.stdout),
      `${h}|${h}x|`,
      `element ${JSON.stringify(h)} must stay one literal word`,
    );
    assertEquals(out.code, 0);
  }
});

Deno.test("the upload script survives a real POSIX shell with hostile paths refused earlier", async () => {
  const dir = await Deno.makeTempDir();
  try {
    const dest = `${dir}/out.txt`;
    const run = async (body: string) => {
      const cmd = new Deno.Command("sh", {
        args: ["-c", UPLOAD_SCRIPT, "sh", dest, "0640"],
        stdin: "piped",
        stdout: "piped",
        stderr: "piped",
      }).spawn();
      const w = cmd.stdin.getWriter();
      await w.write(new TextEncoder().encode(body));
      await w.close();
      const o = await cmd.output();
      return { code: o.code, out: new TextDecoder().decode(o.stdout) };
    };
    const first = await run("hello\n");
    assertEquals(first.code, 0);
    const sum =
      "5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03";
    assertEquals(first.out.trim(), `${sum} 6 1`);
    assertEquals(await Deno.readTextFile(dest), "hello\n");
    assertEquals((await Deno.stat(dest)).mode! & 0o777, 0o640);
    // idempotent re-run: same bytes, reported unchanged
    assertEquals((await run("hello\n")).out.trim(), `${sum} 6 0`);
    // changed content replaces atomically, no temp file left behind
    assertEquals((await run("bye\n")).out.trim().endsWith(" 4 1"), true);
    assertEquals(await Deno.readTextFile(dest), "bye\n");
    assertEquals([...Deno.readDirSync(dir)].map((e) => e.name), ["out.txt"]);
    // unwritable destination directory: non-zero, nothing left behind
    const bad = new Deno.Command("sh", {
      args: ["-c", UPLOAD_SCRIPT, "sh", `${dir}/missing/out.txt`, "0640"],
      stdin: "piped",
      stdout: "null",
      stderr: "null",
    }).spawn();
    const bw = bad.stdin.getWriter();
    await bw.write(new TextEncoder().encode("x")).catch(() => {});
    await bw.close().catch(() => {});
    assertEquals((await bad.output()).code !== 0, true);
    assertEquals([...Deno.readDirSync(dir)].map((e) => e.name), ["out.txt"]);
  } finally {
    await Deno.remove(dir, { recursive: true });
  }
});

Deno.test("host-key parsing accepts keyscan lines and rejects known_hosts syntax", () => {
  assertEquals(
    parseHostKeys([
      `# comment`,
      `192.0.2.10 ssh-ed25519 ${KEY1} root@box`,
      `ssh-ed25519 ${KEY2}`,
      ``,
    ]),
    [
      { type: "ssh-ed25519", key: KEY1 },
      { type: "ssh-ed25519", key: KEY2 },
    ],
  );
  for (
    const bad of [
      `@cert-authority * ssh-ed25519 ${KEY1}`,
      `|1|abc|def ssh-ed25519 ${KEY1}`,
      `192.0.2.10 ssh-bogus ${KEY1}`,
      `192.0.2.10 ssh-ed25519 ${KEY1}\nother ssh-rsa ${KEY2}`,
      `a b c ssh-ed25519 ${KEY1}`,
      `ssh-ed25519`,
      `192.0.2.10 ssh-ed25519 !!notbase64`,
    ]
  ) {
    assertThrows(() => parseHostKeys([bad]), SshError);
  }
});

Deno.test("known_hosts is generated for the target, whatever the pinned host field", () => {
  const keys = parseHostKeys([`other.example.com ssh-ed25519 ${KEY1}`]);
  assertEquals(
    renderKnownHosts(keys, "192.0.2.10", 22),
    `192.0.2.10 ssh-ed25519 ${KEY1}\n`,
  );
  assertEquals(
    renderKnownHosts(keys, "192.0.2.10", 2222),
    `[192.0.2.10]:2222 ssh-ed25519 ${KEY1}\n`,
  );
});

Deno.test("verifyHostKeys follows OpenSSH: mismatch refuses, unpinned types ignored", () => {
  const pinned = [{ type: "ssh-ed25519", key: KEY1 }];
  const rsa = { type: "ssh-rsa", key: "AAAAB3NzaC1yc2EAAAADAQABFake" };
  assertEquals(
    verifyHostKeys([rsa, { type: "ssh-ed25519", key: KEY1 }], pinned, "h"),
    pinned,
  );
  assertThrows(
    () => verifyHostKeys([{ type: "ssh-ed25519", key: KEY2 }], pinned, "h"),
    SshError,
    "mismatch",
  );
  assertThrows(() => verifyHostKeys([rsa], pinned, "h"), SshError, "matches");
  assertThrows(() => verifyHostKeys([], pinned, "h"), SshError);
  assertThrows(() => verifyHostKeys([rsa], [], "h"), SshError, "requires");
});

Deno.test("parseKeyscan reads keyscan output and skips comments", () => {
  assertEquals(
    parseKeyscan(
      `# 192.0.2.10:22 SSH-2.0-OpenSSH\n192.0.2.10 ssh-ed25519 ${KEY1}\njunk\n`,
    ),
    [{ type: "ssh-ed25519", key: KEY1 }],
  );
});

Deno.test("ssh argv: strict pins, no config, no secret, no shell metacharacters", () => {
  const strict = baseSshArgs(T, "/tmp/s.sock", "/tmp/kh");
  assertEquals(strict.includes("StrictHostKeyChecking=yes"), true);
  assertEquals(strict.includes("UserKnownHostsFile=/tmp/kh"), true);
  assertEquals(strict.includes("GlobalKnownHostsFile=/dev/null"), true);
  assertEquals(strict.includes("IdentityFile=none"), true);
  assertEquals(strict.includes("BatchMode=yes"), true);
  assertEquals(strict.slice(0, 2), ["-F", "/dev/null"]);
  assertEquals(strict.join(" ").includes("BEGIN"), false);
  assertEquals(strict.includes("StrictHostKeyChecking=accept-new"), false);
  assertEquals(strict.includes("StrictHostKeyChecking=no"), false);
});

// session / exec

Deno.test("exec: key on ssh-add stdin only, never argv; session torn down", async () => {
  const f = fakeDeps({ code: 0, stdout: "out\n", stderr: "" });
  const r = await exec(f.deps, T, ["uname", "-a"]);
  assertEquals(r.exit_code, 0);
  assertEquals(r.stdout, "out\n");
  const add = f.calls.find((c) => c.cmd === "ssh-add")!;
  assertMatch(add.stdin!, /BEGIN OPENSSH PRIVATE KEY/);
  assertEquals(add.args, ["-q", "-"]);
  for (const c of f.calls) {
    assertNotMatch(JSON.stringify(c.args), /PRIVATE KEY|ZmFrZS1rZXk/);
    assertNotMatch(JSON.stringify(c.env ?? {}), /PRIVATE KEY|ZmFrZS1rZXk/);
  }
  const ssh = f.calls.find((c) => c.cmd === "ssh")!;
  assertEquals(ssh.args.slice(-3), ["--", "192.0.2.10", "'uname' '-a'"]);
  assertEquals(
    f.files.get("/tmp/ssh-host-test/known_hosts"),
    `192.0.2.10 ssh-ed25519 ${KEY1}\n`,
  );
  assertEquals(f.calls.at(-1)!.cmd, "ssh-agent");
  assertEquals(f.calls.at(-1)!.args, ["-k"]);
  assertEquals(f.removed, ["/tmp/ssh-host-test"]);
});

Deno.test("exec: a non-zero remote exit is data, not an error", async () => {
  const f = fakeDeps({ code: 3, stdout: "", stderr: "boom\n" });
  const r = await exec(f.deps, T, ["false"]);
  assertEquals(r.exit_code, 3);
  assertEquals(r.stderr, "boom\n");
});

Deno.test("exec: injection attempts reach ssh as one quoted word each", async () => {
  for (const h of HOSTILE) {
    const f = fakeDeps();
    await exec(f.deps, T, ["echo", h]);
    const cmd = f.calls.find((c) => c.cmd === "ssh")!.args.at(-1)!;
    assertEquals(cmd, `'echo' ${posixQuote(h)}`);
  }
});

Deno.test("exec: trust-on-first-use is not offered; the policy must be strict", async () => {
  const f = fakeDeps();
  for (const policy of ["insecure_tofu", "accept-new", "none"]) {
    await assertRejects(
      () =>
        exec(f.deps, {
          ...T,
          hostKeyPolicy: policy as never,
          hostKeys: undefined,
        }, [
          "id",
        ]),
      SshError,
      "must be strict",
    );
  }
  assertEquals(f.calls.length, 0);
});

Deno.test("exec: strict without host_keys refuses before spawning anything", async () => {
  const f = fakeDeps();
  await assertRejects(
    () => exec(f.deps, { ...T, hostKeys: [] }, ["id"]),
    SshError,
    "requires host_keys",
  );
  assertEquals(f.calls.length, 0);
});

Deno.test("exec: bad target fields refuse before spawning anything", async () => {
  const f = fakeDeps();
  for (
    const bad of [
      { host: "-oProxyCommand=evil" },
      { host: "h;id" },
      { user: "root; id" },
      { port: 0 },
      { port: 70000 },
      { connectTimeoutS: 0 },
      { privateKey: "not a key" },
      {
        privateKey:
          "-----BEGIN OPENSSH PRIVATE KEY-----\nx\n-----END OPENSSH PRIVATE KEY-----\n; id",
      },
    ]
  ) {
    await assertRejects(() => exec(f.deps, { ...T, ...bad }, ["id"]), SshError);
  }
  assertEquals(f.calls.length, 0);
});

Deno.test("exec: failure classes are typed, name the host, and leak nothing", async () => {
  const cases: [string, string, boolean][] = [
    ["Connection timed out during banner exchange", "unreachable", false],
    [
      "ssh: connect to host 192.0.2.10 port 22: Connection refused",
      "unreachable",
      false,
    ],
    ["Permission denied (publickey).", "auth", false],
    ["Host key verification failed.", "host_key", false],
    ["WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!", "host_key", false],
    ["something odd", "transport", false],
    ["", "timeout", true],
  ];
  for (const [stderr, kind, timedOut] of cases) {
    const f = fakeDeps(
      timedOut ? { code: -1, timedOut: true } : { code: 255, stderr },
    );
    const e = await assertRejects(() => exec(f.deps, T, ["id"]), SshError);
    assertEquals(e.kind, kind);
    assertMatch(e.message, /192\.0\.2\.10/);
    assertNotMatch(e.message, /PRIVATE KEY|ZmFrZS1rZXk|'id'/);
    assertEquals(f.removed.length, 1, "temp dir removed even on failure");
    assertEquals(f.calls.at(-1)!.args, ["-k"], "agent killed even on failure");
  }
});

Deno.test("exec: an unreachable host (192.0.2.1) is a typed error", async () => {
  const f = fakeDeps({
    code: 255,
    stderr: "ssh: connect to host 192.0.2.1 port 22: Connection timed out",
  });
  const e = await assertRejects(
    () => exec(f.deps, { ...T, host: "192.0.2.1" }, ["id"]),
    SshError,
  );
  assertEquals(e.kind, "unreachable");
});

Deno.test("exec: ssh-agent or ssh-add failure is a config error and still cleans up", async () => {
  const f = fakeDeps();
  const base = f.deps.run;
  f.deps.run = (cmd, args, o) =>
    cmd === "ssh-add"
      ? Promise.resolve({ code: 1, stdout: "", stderr: "Bad passphrase" })
      : base(cmd, args, o);
  const e = await assertRejects(() => exec(f.deps, T, ["id"]), SshError);
  assertEquals(e.kind, "config");
  assertNotMatch(e.message, /passphrase/);
  assertEquals(f.removed.length, 1);
});

Deno.test("exec: output is capped and flagged", async () => {
  const f = fakeDeps({ code: 0, stdout: "x".repeat(2_000_000) });
  const r = await exec(f.deps, T, ["cat", "big"]);
  assertEquals(r.stdout.length, 1048576);
  assertEquals(r.truncated, true);
});

// upload

Deno.test("upload: content goes over ssh stdin; path and mode are quoted argv words", async () => {
  const content = new TextEncoder().encode("hello\n");
  const sum =
    "5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03";
  const f = fakeDeps({ code: 0, stdout: `${sum} 6 1\n` });
  const r = await upload(f.deps, T, "/etc/app/conf.yaml", content, "0600");
  assertEquals(r, {
    path: "/etc/app/conf.yaml",
    bytes: 6,
    sha256: sum,
    changed: true,
  });
  const ssh = f.calls.find((c) => c.cmd === "ssh")!;
  assertEquals(ssh.stdin, "hello\n");
  const cmd = ssh.args.at(-1)!;
  assertEquals(cmd.endsWith(`'sh' '/etc/app/conf.yaml' '0600'`), true);
  assertEquals(cmd.includes("hello"), false);
});

Deno.test("upload: identical re-run reports changed false with the same sha", async () => {
  const sum =
    "5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03";
  const f = fakeDeps({ code: 0, stdout: `${sum} 6 0\n` });
  const r = await upload(
    f.deps,
    T,
    "/etc/x",
    new TextEncoder().encode("hello\n"),
  );
  assertEquals(r.changed, false);
  assertEquals(r.sha256, sum);
});

Deno.test("upload: a checksum or size mismatch from the remote is an error", async () => {
  for (const out of [`${"0".repeat(64)} 6 1\n`, `garbage\n`, ""]) {
    const f = fakeDeps({ code: 0, stdout: out });
    await assertRejects(
      () => upload(f.deps, T, "/etc/x", new TextEncoder().encode("hello\n")),
      SshError,
      "could not be verified",
    );
  }
  const sum =
    "5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03";
  const f = fakeDeps({ code: 0, stdout: `${sum} 7 1\n` });
  await assertRejects(
    () => upload(f.deps, T, "/etc/x", new TextEncoder().encode("hello\n")),
    SshError,
    "could not be verified",
  );
});

Deno.test("upload: unwritable path is a typed remote error; bad path/mode refuse locally", async () => {
  const f = fakeDeps({ code: 1, stderr: "mktemp: failed to create file" });
  const e = await assertRejects(
    () => upload(f.deps, T, "/root/x", new Uint8Array([1])),
    SshError,
  );
  assertEquals(e.kind, "remote");
  assertMatch(e.message, /nothing was written/);
  const g = fakeDeps();
  for (const p of ["rel", "/a;b", "/a/../b", "/a\nb", "/x'y"]) {
    await assertRejects(
      () => upload(g.deps, T, p, new Uint8Array([1])),
      SshError,
    );
  }
  await assertRejects(
    () => upload(g.deps, T, "/x", new Uint8Array([1]), "0o9"),
    SshError,
  );
  assertEquals(g.calls.length, 0);
});

Deno.test("upload: transport failures are typed", async () => {
  const f = fakeDeps({ code: 255, stderr: "Permission denied (publickey)." });
  const e = await assertRejects(
    () => upload(f.deps, T, "/x", new Uint8Array([1])),
    SshError,
  );
  assertEquals(e.kind, "auth");
});

// wait_connection

const WT = {
  host: "192.0.2.10",
  port: 22,
  hostKeyPolicy: "strict" as const,
  hostKeys: [`192.0.2.10 ssh-ed25519 ${KEY1}`],
  connectTimeoutS: 5,
};

Deno.test("waitConnection: reachable with pinned keys; no key needed, nothing authenticated", async () => {
  const f = fakeDeps({}, `192.0.2.10 ssh-ed25519 ${KEY1}\n`);
  const r = await waitConnection(f.deps, WT, 60, 5);
  assertEquals(r.reachable, true);
  assertEquals(r.host_keys, [`192.0.2.10 ssh-ed25519 ${KEY1}`]);
  assertEquals(f.calls.map((c) => c.cmd), ["ssh-keyscan"]);
});

Deno.test("waitConnection: strict mismatch never reports reachable, polls to the deadline", async () => {
  const f = fakeDeps({}, `192.0.2.10 ssh-ed25519 ${KEY2}\n`);
  const r = await waitConnection(f.deps, WT, 20, 5);
  assertEquals(r.reachable, false);
  assertEquals(r.host_keys, []);
  assertMatch(r.reason!, /mismatch/);
  assertEquals(r.attempts > 1, true);
});

Deno.test("waitConnection: unreachable host times out cleanly", async () => {
  const f = fakeDeps({}, "");
  const r = await waitConnection(f.deps, { ...WT, host: "192.0.2.1" }, 10, 5);
  assertEquals(r.reachable, false);
  assertMatch(r.reason!, /did not present/);
});

Deno.test("waitConnection: strict without pins refuses, and so does any other policy", async () => {
  const f = fakeDeps({}, `192.0.2.10 ssh-ed25519 ${KEY2}\n`);
  await assertRejects(
    () =>
      waitConnection(
        f.deps,
        { ...WT, hostKeyPolicy: "insecure_tofu" as never, hostKeys: undefined },
        10,
        5,
      ),
    SshError,
    "must be strict",
  );
  await assertRejects(
    () => waitConnection(f.deps, { ...WT, hostKeys: [] }, 10, 5),
    SshError,
    "requires host_keys",
  );
  await assertRejects(
    () => waitConnection(f.deps, { ...WT, host: "h;id" }, 10, 5),
    SshError,
  );
});

Deno.test("withSession validates before touching the filesystem", async () => {
  const f = fakeDeps();
  await assertRejects(
    () => withSession(f.deps, { ...T, user: "x y" }, () => Promise.resolve(1)),
    SshError,
  );
  assertEquals(f.files.size + f.calls.length + f.removed.length, 0);
});
