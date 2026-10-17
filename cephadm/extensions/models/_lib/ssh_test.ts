import {
  assertEquals,
  assertRejects,
  assertThrows,
} from "jsr:@std/assert@1.0.19";
import {
  LocalRefusalError,
  PhaseError,
  RemoteExitError,
  SudoPolicyError,
  TransportError,
} from "./errors.ts";
import {
  connectTimeoutSeconds,
  controlSocketPath,
  DEFAULT_BUDGET_MS,
  describeTransport,
  ensureControlSocketDir,
  openSession,
  runStep,
  type Spawner,
  type SshDeps,
  toTarget,
} from "./ssh.ts";

const encoder = new TextEncoder();
const decoder = new TextDecoder();

interface SpawnRecord {
  cmd: string;
  args: string[];
  stdin: string;
  stdinClosed: boolean;
}

type Handler = (
  args: string[],
  stdin: string,
) =>
  | { code: number; stdout: string; stderr: string }
  | Promise<
    { code: number; stdout: string; stderr: string }
  >;

/** A scripted spawner; records argv and stdin for every call. */
function fakeSpawner(
  handler: Handler,
  onSpawn?: (args: string[], record: SpawnRecord) => void,
): { spawn: Spawner; records: SpawnRecord[] } {
  const records: SpawnRecord[] = [];
  const spawn: Spawner = (cmd, args) => {
    const record: SpawnRecord = { cmd, args, stdin: "", stdinClosed: false };
    records.push(record);
    onSpawn?.(args, record);
    return {
      stdin: new WritableStream<Uint8Array>({
        write(chunk) {
          record.stdin += decoder.decode(chunk);
        },
        close() {
          record.stdinClosed = true;
        },
      }),
      output: async () => {
        const r = await handler(args, record.stdin);
        return {
          code: r.code,
          stdout: encoder.encode(r.stdout),
          stderr: encoder.encode(r.stderr),
        };
      },
      kill: () => {},
    };
  };
  return { spawn, records };
}

function deps(spawn: Spawner, extra: Partial<SshDeps> = {}): SshDeps {
  return {
    spawn,
    now: () => 0,
    sleep: () => Promise.resolve(),
    ...extra,
  };
}

const TARGET = toTarget({
  strictHostKeyChecking: "yes",
  host: "192.0.2.10",
  sshUser: "admin",
});

Deno.test("argv carries key-only auth, the port and a trailing command", () => {
  const f = fakeSpawner(() => ({ code: 0, stdout: "OK\n", stderr: "" }));
  // The call is synchronous through the fake; resolve the session first.
  return (async () => {
    const session = await openSession(deps(f.spawn), TARGET, {
      multiplex: false,
    });
    await session.run({ command: "ceph -s" });
    const { cmd, args } = f.records[0];
    assertEquals(cmd, "ssh");
    assertEquals(args.slice(0, 2), ["-p", "22"]);
    assertEquals(args.includes("BatchMode=yes"), true);
    assertEquals(args.includes("PreferredAuthentications=publickey"), true);
    assertEquals(args.slice(-3), ["--", "admin@192.0.2.10", "ceph -s"]);
    assertEquals(args.some((a) => a.toLowerCase().includes("password")), false);
  })();
});

Deno.test("an explicit port is dialled and stdin is delivered then closed", async () => {
  const f = fakeSpawner(() => ({ code: 0, stdout: "", stderr: "" }));
  const session = await openSession(
    deps(f.spawn),
    toTarget({
      strictHostKeyChecking: "yes",
      host: "node1.example.com",
      sshUser: "admin",
      port: 2222,
    }),
    { multiplex: false },
  );
  await session.run({ command: "read x", stdin: "exact content\nsecond line" });
  assertEquals(f.records[0].args.slice(0, 2), ["-p", "2222"]);
  assertEquals(f.records[0].stdin, "exact content\nsecond line");
  assertEquals(f.records[0].stdinClosed, true);
});

Deno.test(
  "a non-zero remote exit throws by default and is returned when allowed", // leak-allow(decision D8)
  async () => {
    const f = fakeSpawner(() => ({ code: 1, stdout: "out", stderr: "boom" }));
    const session = await openSession(deps(f.spawn), TARGET, {
      multiplex: false,
    });
    try {
      await session.run({ command: "false" });
      throw new Error("should have thrown");
    } catch (e) {
      assertEquals(e instanceof RemoteExitError, true);
      assertEquals((e as Error).message.includes("192.0.2.10"), true);
      assertEquals((e as RemoteExitError).code, 1);
    }
    const allowed = await session.run({ command: "false", allowNonZero: true });
    assertEquals(allowed.code, 1);
    assertEquals(allowed.stderr, "boom");
    assertEquals(allowed instanceof TransportError, false);
  },
);

Deno.test(
  "exit 255 with allow-non-zero is still a typed transport error", // leak-allow(decision D8)
  async () => {
    const f = fakeSpawner(() => ({
      code: 255,
      stdout: "",
      stderr: "admin@192.0.2.10: Permission denied (publickey).\n",
    }));
    const session = await openSession(deps(f.spawn), TARGET, {
      multiplex: false,
    });
    await assertRejects(
      () => session.run({ command: "true", allowNonZero: true }),
      TransportError,
    );
  },
);

Deno.test(
  "identity selection: a key path adds -i and IdentitiesOnly, neither adds nothing", // leak-allow(decision D2)
  async () => {
    const f = fakeSpawner(() => ({ code: 0, stdout: "", stderr: "" }));
    const s1 = await openSession(
      deps(f.spawn),
      toTarget({
        strictHostKeyChecking: "yes",
        host: "192.0.2.10",
        sshUser: "admin",
        keyPath: "/home/admin/.ssh/id_ed25519",
      }),
      { multiplex: false },
    );
    await s1.run({ command: "true" });
    assertEquals(f.records[0].args.includes("-i"), true);
    assertEquals(f.records[0].args.includes("IdentitiesOnly=yes"), true);
    const f2 = fakeSpawner(() => ({ code: 0, stdout: "", stderr: "" }));
    const s2 = await openSession(deps(f2.spawn), TARGET, { multiplex: false });
    await s2.run({ command: "true" });
    assertEquals(f2.records[0].args.includes("-i"), false);
    assertEquals(f2.records[0].args.includes("IdentitiesOnly=yes"), false);
  },
);

Deno.test(
  "inline key content is a 0600 file in a 0700 dir with one trailing newline", // leak-allow(decision D2)
  async () => {
    const key =
      "-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----";
    let observedDir: string | null = null;
    let observedMode = 0;
    let observedContent = "";
    const f = fakeSpawner(
      () => ({ code: 0, stdout: "", stderr: "" }),
      (args) => {
        const i = args.indexOf("-i");
        const file = args[i + 1];
        observedMode = (Deno.statSync(file).mode ?? 0) & 0o777;
        observedDir = file.slice(0, file.lastIndexOf("/"));
        observedContent = Deno.readTextFileSync(file);
        assertEquals((Deno.statSync(observedDir).mode ?? 0) & 0o777, 0o700);
      },
    );
    const session = await openSession(
      deps(f.spawn),
      toTarget({
        strictHostKeyChecking: "yes",
        host: "192.0.2.10",
        sshUser: "admin",
        privateKey: key,
      }),
      { multiplex: false },
    );
    await session.run({ command: "true" });
    assertEquals(observedMode, 0o600);
    assertEquals(observedContent, `${key}\n`);
    assertEquals(
      f.records[0].args.some((a) => a.includes("PRIVATE KEY")),
      false,
    );
    assertThrows(() => Deno.statSync(observedDir as string));
  },
);

Deno.test("the inline key file is removed after a failure", async () => {
  let dir: string | null = null;
  const f = fakeSpawner(
    () => ({
      code: 255,
      stdout: "",
      stderr: "kex_exchange_identification: Connection closed\n",
    }),
    (args) => {
      const i = args.indexOf("-i");
      const file = args[i + 1];
      dir = file.slice(0, file.lastIndexOf("/"));
    },
  );
  const session = await openSession(
    deps(f.spawn),
    toTarget({
      strictHostKeyChecking: "yes",
      host: "192.0.2.10",
      sshUser: "admin",
      privateKey: "KEY\n",
    }),
    { multiplex: false },
  );
  await assertRejects(() => session.run({ command: "true" }), TransportError);
  assertThrows(() => Deno.statSync(dir as string));
});

Deno.test("both identities are refused at conversion and at the transport", async () => {
  const f = fakeSpawner(() => ({ code: 0, stdout: "", stderr: "" }));
  assertThrows(
    () =>
      toTarget({
        strictHostKeyChecking: "yes",
        host: "192.0.2.10",
        sshUser: "admin",
        keyPath: "/k",
        privateKey: "KEY\n",
      }),
    LocalRefusalError,
  );
  const raw = {
    host: "192.0.2.10",
    user: "admin",
    strictHostKeyChecking: "yes" as const,
    keyPath: "/k",
    privateKey: "KEY\n",
  };
  await assertRejects(
    () => openSession(deps(f.spawn), raw, { multiplex: false }),
    LocalRefusalError,
  );
  assertEquals(f.records.length, 0);
});

Deno.test("a NUL byte is refused locally with zero spawns", async () => {
  const f = fakeSpawner(() => ({ code: 0, stdout: "", stderr: "" }));
  const session = await openSession(deps(f.spawn), TARGET, {
    multiplex: false,
  });
  await assertRejects(
    () => session.run({ command: "echo \0" }),
    LocalRefusalError,
  );
  await assertRejects(
    () => session.run({ command: "cat", stdin: "a\0b" }),
    LocalRefusalError,
  );
  assertEquals(f.records.length, 0);
});

Deno.test(
  "host-key policy defaults to strict and no is explicit with /dev/null", // leak-allow(decision D9)
  async () => {
    const f = fakeSpawner(() => ({ code: 0, stdout: "", stderr: "" }));
    await (await openSession(deps(f.spawn), TARGET, { multiplex: false })).run({
      command: "true",
    });
    assertEquals(f.records[0].args.includes("StrictHostKeyChecking=yes"), true);
    assertEquals(
      f.records[0].args.includes("UserKnownHostsFile=/dev/null"),
      false,
    );
    const f2 = fakeSpawner(() => ({ code: 0, stdout: "", stderr: "" }));
    await (await openSession(
      deps(f2.spawn),
      toTarget({
        host: "192.0.2.10",
        sshUser: "admin",
        strictHostKeyChecking: "no",
      }),
      { multiplex: false },
    )).run({ command: "true" });
    assertEquals(f2.records[0].args.includes("StrictHostKeyChecking=no"), true);
    assertEquals(
      f2.records[0].args.includes("UserKnownHostsFile=/dev/null"),
      true,
    );
    assertEquals(
      f2.records[0].args.includes("GlobalKnownHostsFile=/dev/null"),
      true,
    );
  },
);

Deno.test("sudo prefixes one simple command and refuses a password prompt", async () => {
  const f = fakeSpawner(() => ({ code: 0, stdout: "", stderr: "" }));
  const session = await openSession(deps(f.spawn), TARGET, {
    multiplex: false,
  });
  await session.run({ command: "apt-get install -y chrony", sudo: true });
  assertEquals(
    f.records[0].args.at(-1),
    "sudo -n -- apt-get install -y chrony",
  );
  const f2 = fakeSpawner(() => ({
    code: 1,
    stdout: "",
    stderr: "sudo: a password is required\n",
  }));
  const s2 = await openSession(deps(f2.spawn), TARGET, { multiplex: false });
  await assertRejects(
    () => s2.run({ command: "true", sudo: true, allowNonZero: true }),
    SudoPolicyError,
  );
});

Deno.test("ConnectTimeout is derived from the budget, capped at 30", () => {
  assertEquals(connectTimeoutSeconds(10_000), 10);
  assertEquals(connectTimeoutSeconds(1_000), 1);
  assertEquals(connectTimeoutSeconds(1), 1);
  assertEquals(connectTimeoutSeconds(900_000), 30);
  assertEquals(connectTimeoutSeconds(DEFAULT_BUDGET_MS), 30);
  assertEquals(connectTimeoutSeconds(30_001), 30);
});

Deno.test("a killed session is an aborted transport error", async () => {
  let killed = false;
  const spawn: Spawner = () => {
    let resolveKill: (() => void) | null = null;
    return {
      stdin: new WritableStream<Uint8Array>({}),
      output: () =>
        new Promise((resolve) => {
          resolveKill = () =>
            resolve({
              code: 143,
              stdout: new Uint8Array(),
              stderr: new Uint8Array(),
            });
        }),
      kill: () => {
        killed = true;
        resolveKill?.();
      },
    };
  };
  const session = await openSession(
    deps(spawn, { killGraceMs: 5 }),
    TARGET,
    { multiplex: false },
  );
  try {
    await session.run({ command: "sleep 100", budgetMs: 5 });
    throw new Error("should have thrown");
  } catch (e) {
    assertEquals(e instanceof TransportError, true);
    assertEquals((e as TransportError).kind, "aborted");
    assertEquals((e as TransportError).sessionCause, null);
    assertEquals(killed, true);
  }
});

Deno.test("changed and absent host keys are explained precisely", () => {
  const changed = describeTransport(
    "@@@ WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED! @@@\nHost key verification failed.\n",
    "192.0.2.10",
    22,
    "admin",
  );
  assertEquals(changed.message.includes("re-imaged"), true);
  assertEquals(changed.message.includes("ssh-keygen -R"), true);
  assertEquals(changed.message.includes("not a bad credential"), true);
  const absent = describeTransport(
    "Host key verification failed.\n",
    "192.0.2.10",
    22,
    "admin",
  );
  assertEquals(absent.message.includes("known_hosts"), true);
  assertEquals(absent.message.includes("re-imaged"), false);
});

Deno.test(
  "pre-session causes are anchored and mid-session drops are never re-sent", // leak-allow(decision D8)
  () => {
    assertEquals(
      describeTransport(
        "ssh: connect to host 192.0.2.10 port 22: Connection refused\n",
        "192.0.2.10",
        22,
        "admin",
      ).cause,
      "connect-refused",
    );
    assertEquals(
      describeTransport(
        "ssh: Could not resolve hostname x: Name or service not known\n",
        "x",
        22,
        "admin",
      ).cause,
      "name-resolution",
    );
    assertEquals(
      describeTransport(
        "admin@192.0.2.10: Permission denied (publickey).\n",
        "192.0.2.10",
        22,
        "admin",
      ).cause,
      "auth",
    );
    const dropped = describeTransport(
      "kex_exchange_identification: Connection closed by remote host\n",
      "192.0.2.10",
      22,
      "admin",
    );
    assertEquals(dropped.kind, "dropped-before-auth");
    assertEquals(dropped.message.includes("before the command ran"), true);
    const mid = describeTransport(
      "client_loop: send disconnect: Broken pipe\n",
      "192.0.2.10",
      22,
      "admin",
    );
    assertEquals(mid.kind, "other");
    assertEquals(mid.message.includes("MAY HAVE RUN"), true);
    // A remote tool echoing the marker mid-line is not a pre-authentication drop.
    const echoed = describeTransport(
      "E: connection reset by peer (kex_exchange_identification)\n",
      "192.0.2.10",
      22,
      "admin",
    );
    assertEquals(echoed.kind, "other");
    assertEquals(echoed.message.includes("MAY HAVE RUN"), true);
  },
);

Deno.test("control socket paths are stable and differ per identity", async () => {
  const env = () => "/run/user/1000";
  const a = await controlSocketPath(
    toTarget({
      strictHostKeyChecking: "yes",
      host: "192.0.2.10",
      sshUser: "admin",
    }),
    env,
  );
  const b = await controlSocketPath(
    toTarget({
      strictHostKeyChecking: "yes",
      host: "192.0.2.10",
      sshUser: "admin",
    }),
    env,
  );
  assertEquals(a.path, b.path);
  assertEquals(a.path.endsWith(".sock"), true);
  const user = await controlSocketPath(
    toTarget({
      strictHostKeyChecking: "yes",
      host: "192.0.2.10",
      sshUser: "other",
    }),
    env,
  );
  const host = await controlSocketPath(
    toTarget({
      strictHostKeyChecking: "yes",
      host: "198.51.100.9",
      sshUser: "admin",
    }),
    env,
  );
  const port = await controlSocketPath(
    toTarget({
      strictHostKeyChecking: "yes",
      host: "192.0.2.10",
      sshUser: "admin",
      port: 2222,
    }),
    env,
  );
  assertEquals(new Set([a.path, user.path, host.path, port.path]).size, 4);
  const long = await controlSocketPath(
    toTarget({
      strictHostKeyChecking: "yes",
      host: "192.0.2.10",
      sshUser: "admin",
    }),
    () => `/${"a".repeat(200)}`,
  );
  assertEquals(long.path.startsWith("/tmp/"), true);
});

Deno.test("the control socket directory must not be group or world reachable", async () => {
  const created: { path: string; mode: number }[] = [];
  const mkdir = (path: string, mode: number) => {
    created.push({ path, mode });
    return Promise.resolve();
  };
  await ensureControlSocketDir(
    "/run/x",
    () => Promise.resolve({ mode: 0o40700 } as Deno.FileInfo),
    mkdir,
  );
  assertEquals(created[0].mode, 0o700);
  await assertRejects(
    () =>
      ensureControlSocketDir(
        "/run/x",
        () => Promise.resolve({ mode: 0o40777 } as Deno.FileInfo),
        mkdir,
      ),
    LocalRefusalError,
  );
});

Deno.test(
  "multiplexing adds the master options and closes with one -O exit", // leak-allow(decision D18)
  async () => {
    const f = fakeSpawner(() => ({ code: 0, stdout: "", stderr: "" }));
    const session = await openSession(
      deps(f.spawn),
      TARGET,
      { multiplex: true, env: () => "/tmp", persistSeconds: 120 },
    );
    await session.run({ command: "true" });
    const args = f.records[0].args;
    assertEquals(args.includes("ControlMaster=auto"), true);
    assertEquals(args.some((a) => a.startsWith("ControlPath=")), true);
    assertEquals(args.includes("ControlPersist=120"), true);
    assertEquals(args.includes("ServerAliveInterval=15"), true);
    assertEquals(args.includes("ServerAliveCountMax=3"), true);
    const closed = await session.close();
    assertEquals(closed.closed, true);
    const closeCall = f.records.at(-1)!;
    assertEquals(closeCall.args.includes("-O"), true);
    assertEquals(closeCall.args.includes("exit"), true);
    assertEquals(closeCall.args.at(-1), "admin@192.0.2.10");
  },
);

Deno.test("close without multiplexing spawns nothing", async () => {
  const f = fakeSpawner(() => ({ code: 0, stdout: "", stderr: "" }));
  const session = await openSession(deps(f.spawn), TARGET, {
    multiplex: false,
  });
  const closed = await session.close();
  assertEquals(closed.closed, false);
  assertEquals(closed.detail.includes("multiplex off"), true);
  assertEquals(f.records.length, 0);
});

Deno.test(
  "control-master options are absent when multiplexing is off", // leak-allow(decision D18)
  async () => {
    const f = fakeSpawner(() => ({ code: 0, stdout: "", stderr: "" }));
    await (await openSession(deps(f.spawn), TARGET, { multiplex: false })).run({
      command: "true",
    });
    assertEquals(
      f.records[0].args.some((a) => a.startsWith("ControlMaster")),
      false,
    );
    assertEquals(
      f.records[0].args.some((a) => a.startsWith("ControlPath")),
      false,
    );
  },
);

Deno.test(
  "a write is re-sent only after a dropped-before-auth failure", // leak-allow(decision D8)
  async () => {
    let calls = 0;
    const f = fakeSpawner(() => {
      calls++;
      if (calls === 1) {
        return {
          code: 255,
          stdout: "",
          stderr: "kex_exchange_identification: Connection closed\n",
        };
      }
      return { code: 0, stdout: "done", stderr: "" };
    });
    const warns: string[] = [];
    const session = await openSession(deps(f.spawn), TARGET, {
      multiplex: false,
    });
    const result = await runStep(
      deps(f.spawn),
      session,
      { command: "install", phase: "hostprep.packages", resend: "dropped" },
      { warn: (m) => warns.push(m) },
    );
    assertEquals(result.stdout, "done");
    assertEquals(calls, 2);
    assertEquals(warns.length, 1);
  },
);

Deno.test(
  "a write lost mid-session is not re-sent and ends -outcome-unknown", // leak-allow(decision D8)
  async () => {
    let calls = 0;
    const f = fakeSpawner(() => {
      calls++;
      return {
        code: 255,
        stdout: "",
        stderr: "client_loop: send disconnect: Broken pipe\n",
      };
    });
    const session = await openSession(deps(f.spawn), TARGET, {
      multiplex: false,
    });
    try {
      await runStep(deps(f.spawn), session, {
        command: "install",
        phase: "wipe.signatures",
        resend: "dropped",
      });
      throw new Error("should have thrown");
    } catch (e) {
      assertEquals(e instanceof PhaseError, true);
      assertEquals((e as PhaseError).phase, "wipe.signatures-outcome-unknown");
    }
    assertEquals(calls, 1);
  },
);

Deno.test(
  "host-key policy is required and never silently defaulted", // leak-allow(decision D9)
  () => {
    assertThrows(() => toTarget({ host: "192.0.2.10", sshUser: "admin" }));
    assertThrows(() =>
      toTarget({
        host: "192.0.2.10",
        sshUser: "admin",
        strictHostKeyChecking: null,
      })
    );
    assertEquals(
      toTarget({
        host: "192.0.2.10",
        sshUser: "admin",
        strictHostKeyChecking: "no",
      })
        .strictHostKeyChecking,
      "no",
    );
  },
);

Deno.test(
  "control sockets are isolated by host-key policy and credential", // leak-allow(decision D18)
  async () => {
    const env = () => "/run/user/1000";
    const strict = await controlSocketPath(
      toTarget({
        host: "192.0.2.10",
        sshUser: "admin",
        strictHostKeyChecking: "yes",
      }),
      env,
    );
    const insecure = await controlSocketPath(
      toTarget({
        host: "192.0.2.10",
        sshUser: "admin",
        strictHostKeyChecking: "no",
      }),
      env,
    );
    const pathKey = await controlSocketPath(
      toTarget({
        host: "192.0.2.10",
        sshUser: "admin",
        strictHostKeyChecking: "yes",
        keyPath: "/home/admin/.ssh/id_ed25519",
      }),
      env,
    );
    const inlineKey = await controlSocketPath(
      toTarget({
        host: "192.0.2.10",
        sshUser: "admin",
        strictHostKeyChecking: "yes",
        privateKey: "KEY\n",
      }),
      env,
    );
    assertEquals(
      new Set([strict.path, insecure.path, pathKey.path, inlineKey.path]).size,
      4,
    );
  },
);

Deno.test("private key content cannot influence the control socket or argv", async () => {
  const env = () => "/tmp";
  const a = await controlSocketPath(
    toTarget({
      host: "192.0.2.10",
      sshUser: "admin",
      strictHostKeyChecking: "yes",
      privateKey: "KEY-A\n",
    }),
    env,
  );
  const b = await controlSocketPath(
    toTarget({
      host: "192.0.2.10",
      sshUser: "admin",
      strictHostKeyChecking: "yes",
      privateKey: "KEY-B\n",
    }),
    env,
  );
  // Same process and target: the socket name must not vary with the key bytes.
  assertEquals(a.path, b.path);
  const f = fakeSpawner(() => ({ code: 0, stdout: "", stderr: "" }));
  const session = await openSession(
    deps(f.spawn),
    toTarget({
      host: "192.0.2.10",
      sshUser: "admin",
      strictHostKeyChecking: "yes",
      privateKey: "KEY-A\n",
    }),
    { multiplex: true, env },
  );
  await session.run({ command: "true" });
  const args = f.records[0].args;
  assertEquals(args.some((x) => x.includes("KEY-A")), false);
  const controlPath = args.find((x) => x.startsWith("ControlPath="));
  assertEquals(controlPath !== undefined, true);
  assertEquals(controlPath?.includes("KEY-A"), false);
});
