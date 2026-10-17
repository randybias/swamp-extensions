import {
  assert,
  assertEquals,
  assertExists,
  assertRejects,
  assertStringIncludes,
} from "jsr:@std/assert@1.0.19";
import { createModelTestContext } from "jsr:@swamp-club/swamp-testing@0.20261014.55";
import { z } from "npm:zod@4.3.6";
import { fullMesh, hubSelf, hubSpoke, key } from "./_lib/fixtures.ts";
import {
  applyScript,
  type SshTarget,
  sshTransport,
  type Transport,
  TransportError,
  type TransportResult,
} from "./_lib/push.ts";
import { type CommandRunner, quoteArgv, type SshDeps } from "./_lib/ssh.ts";
import { MeshSchema } from "./_lib/render.ts";
import { createModel, model, type as modelType } from "./wireguard_mesh.ts";

const PRIV = key("P");
const SSH = {
  host: "198.51.100.20",
  user: "root",
  port: 22,
  host_key_policy: "strict" as const,
  host_keys: [
    "198.51.100.20 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEXAMPLE",
  ],
};
const NOW = new Date("2026-10-17T00:00:00Z");

/** A transport stub that records what the node would receive. */
function stub(result: Partial<TransportResult> = {}) {
  const calls: { script: string; stdin?: string; target: SshTarget }[] = [];
  const m = createModel({
    now: () => NOW,
    transport: (target): Transport => (script, stdin) => {
      calls.push({ script, stdin, target });
      return Promise.resolve({
        code: 0,
        stdout: "changed=1\nrb=/etc/wireguard/.wg0.rollback.TESTRUN\n",
        stderr: "",
        ...result,
      });
    },
  });
  return { m, calls };
}

const applyArgs = () => ({ ...hubSpoke(), private_key: PRIV, ssh: SSH });
const targetArgs = { node: "spoke-1", interface: "wg0", ssh: SSH };
const deleteArgs = { ...targetArgs, acknowledge_reachability_risk: true };

Deno.test("render writes the config keyed by node name, with no private key", async () => {
  const { context, getWrittenResources } = createModelTestContext({
    globalArgs: {},
  });
  await model.methods.render.execute(hubSpoke(), context);
  const [w] = getWrittenResources();
  const data = w.data as {
    node: string;
    config: string;
    config_sha256: string;
  };
  assertEquals(w.name, "spoke-1");
  assertEquals(data.config_sha256.length, 64);
  assertEquals(data.config.includes("PrivateKey"), false);
  assertEquals(JSON.stringify(data).includes(PRIV), false);
});

Deno.test("render accepts and ignores ssh, so one input file serves render and apply", async () => {
  type RenderInput = Parameters<typeof model.methods.render.execute>[0];
  const run = async (args: RenderInput) => {
    const { context, getWrittenResources } = createModelTestContext({
      globalArgs: {},
    });
    await model.methods.render.execute(args, context);
    const data = getWrittenResources()[0].data;
    assertEquals(JSON.stringify(data).includes(PRIV), false);
    return JSON.stringify(data);
  };
  const oneFile = { ...hubSpoke(), private_key: PRIV, ssh: SSH };
  assertEquals(await run(oneFile), await run(hubSpoke()));
});

Deno.test("render is repeatable: same inputs, same stored bytes", async () => {
  const run = async () => {
    const { context, getWrittenResources } = createModelTestContext({
      globalArgs: {},
    });
    await model.methods.render.execute(fullMesh(), context);
    return JSON.stringify(getWrittenResources()[0].data);
  };
  assertEquals(await run(), await run());
});

Deno.test("render rejects a peer off the allowlist before anything is written", async () => {
  const { context, getWrittenResources } = createModelTestContext({
    globalArgs: {},
  });
  const m = hubSpoke();
  m.peers_allowlist = ["hub"];
  await assertRejects(
    () => model.methods.render.execute(m, context),
    Error,
    "peer spoke-1 is not on peers_allowlist",
  );
  assertEquals(getWrittenResources().length, 0);
});

Deno.test("apply sends the key and config on stdin only, and stores no secret", async () => {
  const { m, calls } = stub();
  const { context, getWrittenResources } = createModelTestContext({
    globalArgs: {},
  });
  await m.methods.apply.execute(applyArgs(), context);
  // First a mutation over one connection, then a confirmation over a fresh one.
  assertEquals(calls.length, 2);
  const [applyCall, confirmCall] = calls;
  assertEquals(applyCall.script.includes(PRIV), false);
  assertEquals(applyCall.stdin!.startsWith(`${PRIV}\n# Managed by`), true);
  assertEquals(
    applyCall.stdin!.indexOf(PRIV),
    applyCall.stdin!.lastIndexOf(PRIV),
  );
  assertEquals(applyCall.target.host, "198.51.100.20");
  assertEquals("private_key" in applyCall.target, false);
  assertEquals(confirmCall.stdin, undefined);
  assertStringIncludes(confirmCall.script, 'touch "$rb/disarm"');
  const w = getWrittenResources()[0];
  assertEquals(w.name, "spoke-1");
  assertEquals(JSON.stringify(w.data).includes(PRIV), false);
  assertEquals((w.data as { status: string }).status, "applied");
});

Deno.test("apply is idempotent: a no-change run writes no new state", async () => {
  const { m } = stub({ stdout: "changed=0\n" });
  const { context, getWrittenResources } = createModelTestContext({
    globalArgs: {},
  });
  await m.methods.apply.execute(applyArgs(), context);
  assertEquals(getWrittenResources().length, 0);
});

Deno.test("apply to an unreachable node surfaces the typed transport error", async () => {
  const m = createModel({
    transport: () => () =>
      Promise.reject(new TransportError("unreachable", "ssh failed")),
  });
  const { context, getWrittenResources } = createModelTestContext({
    globalArgs: {},
  });
  const e = await assertRejects(
    () => m.methods.apply.execute(applyArgs(), context),
    TransportError,
  );
  assertEquals(e.reason, "unreachable");
  assertEquals(getWrittenResources().length, 0);
});

Deno.test("apply leaves the rollback armed when the fresh confirmation fails", async () => {
  let calls = 0;
  const m = createModel({
    now: () => NOW,
    transport: (): Transport => () => {
      calls++;
      if (calls === 1) {
        return Promise.resolve({
          code: 0,
          stdout: "changed=1\nrb=/etc/wireguard/.wg0.rollback.TESTRUN\n",
          stderr: "",
        });
      }
      return Promise.reject(
        new TransportError("unreachable", "fresh connection failed"),
      );
    },
  });
  const { context, getWrittenResources } = createModelTestContext({
    globalArgs: {},
  });
  const e = await assertRejects(
    () => m.methods.apply.execute(applyArgs(), context),
    TransportError,
  );
  assertEquals(e.reason, "unreachable");
  assertEquals(calls, 2);
  assertEquals(getWrittenResources().length, 0);
});

Deno.test("a failing remote script is a typed error that carries no stderr or key", async () => {
  const { m } = stub({ code: 3, stderr: `boom ${PRIV}` });
  const { context } = createModelTestContext({ globalArgs: {} });
  const e = await assertRejects(
    () => m.methods.apply.execute(applyArgs(), context),
    TransportError,
    "exit 3",
  );
  assertEquals(e.message.includes(PRIV), false);
});

Deno.test("apply validates before connecting: bad key, allowlist, interface", async () => {
  const { m, calls } = stub();
  const { context } = createModelTestContext({ globalArgs: {} });
  const bad: Record<string, unknown>[] = [
    { private_key: "not-a-key" },
    { private_key: PRIV + "\nrm -rf /" },
    { interface: "wg0; reboot" },
    { interface: "../etc" },
    { peers_allowlist: [] },
    { ssh: { ...SSH, user: "root; id" } },
  ];
  for (const b of bad) {
    await assertRejects(
      () => m.methods.apply.execute({ ...applyArgs(), ...b }, context),
      Error,
    );
  }
  assertEquals(calls.length, 0);
});

Deno.test("get parses wg show dump and drops the interface line", async () => {
  const dump = [
    `${PRIV}\t${key("Q")}\t51820\toff`,
    `${
      key("H")
    }\t(none)\t198.51.100.10:51820\t192.0.2.1/32,192.0.2.3/32\t1760659200\t10\t20\t25`,
    `${key("B")}\t(none)\t(none)\t(none)\t0\t0\t0\toff`,
  ].join("\n");
  const { m } = stub({ stdout: dump });
  const { context, getWrittenResources } = createModelTestContext({
    globalArgs: {},
  });
  await m.methods.get.execute(targetArgs, context);
  const live = getWrittenResources()[0].data as {
    peers: { public_key: string; latest_handshake: number }[];
  };
  assertEquals(JSON.stringify(live).includes(PRIV), false);
  assertEquals(live.peers.map((p) => p.latest_handshake), [0, 1760659200]);
});

Deno.test("render echoes the node's own endpoint for other nodes to use", async () => {
  const none = createModelTestContext({ globalArgs: {} });
  await model.methods.render.execute(hubSpoke(), none.context);
  assertEquals(
    (none.getWrittenResources()[0].data as Record<string, unknown>)
      .node_endpoint,
    undefined,
  );
  const some = createModelTestContext({ globalArgs: {} });
  await model.methods.render.execute(hubSelf(), some.context);
  assertEquals(
    (some.getWrittenResources()[0].data as Record<string, unknown>)
      .node_endpoint,
    "198.51.100.10:51820",
  );
});

Deno.test("get never returns or persists the interface private key", async () => {
  const dump = [
    `${PRIV}\t${key("Q")}\t51820\toff`,
    `${key("H")}\t(none)\t(none)\t(none)\t0\t0\t0\toff`,
  ].join("\n");
  const { m } = stub({ stdout: dump });
  const { context, getWrittenResources } = createModelTestContext({
    globalArgs: {},
  });
  await m.methods.get.execute(targetArgs, context);
  const data = getWrittenResources()[0].data as Record<string, unknown>;
  const text = JSON.stringify(data);
  assertEquals(text.includes(PRIV), false);
  assertEquals(text.includes("PrivateKey"), false);
  assertEquals("private_key" in data, false);
});

Deno.test("delete is an action, requires the risk acknowledgement, and is a clean no-op", async () => {
  assertEquals(model.methods.delete.kind, "action");
  const { m, calls } = stub();
  const { context, getWrittenResources } = createModelTestContext({
    globalArgs: {},
  });
  // Refuses without the acknowledgement, before connecting. The schema type
  // requires it, so pass the incomplete object through an unchecked cast.
  const withoutAck = targetArgs as unknown as Record<string, unknown>;
  await assertRejects(
    () => m.methods.delete.execute(withoutAck as never, context),
    Error,
    "acknowledge_reachability_risk",
  );
  assertEquals(calls.length, 0);
  await m.methods.delete.execute(deleteArgs, context);
  // Delete mutates over one connection and confirms over a fresh one.
  assertEquals(calls.length, 2);
  const w = getWrittenResources()[0];
  assertEquals(w.name, "spoke-1");
  assertEquals((w.data as { status: string }).status, "deleted");
  // A remote script that reports no change must not write a new version.
  const { m: noopModel } = stub({ stdout: "changed=0\n" });
  const noop = createModelTestContext({ globalArgs: {} });
  await noopModel.methods.delete.execute(deleteArgs, noop.context);
  assertEquals(noop.getWrittenResources().length, 0);
});

const ACCEPT_NEW = {
  ...SSH,
  host_key_policy: "insecure_tofu" as const,
  host_keys: [],
};
const ACCEPTED_HOSTKEY =
  "198.51.100.20 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFIRSTHOSTKEY";

Deno.test("insecure_tofu is real TOFU: the first key is accepted, pinned, and enforced later", async () => {
  const first = stub({
    stdout: "changed=0\n",
    known_hosts: `${ACCEPTED_HOSTKEY}\n`,
  });
  const ctx1 = createModelTestContext({ globalArgs: {} });
  await first.m.methods.apply.execute(
    { ...applyArgs(), ssh: ACCEPT_NEW },
    ctx1.context,
  );
  assertEquals(first.calls[0].target.host_key_policy, "insecure_tofu");
  const recorded = ctx1.getWrittenResources().find((r) =>
    r.name === "spoke-1-hostkeys-198.51.100.20-22"
  );
  assertExists(recorded);
  assertEquals(
    (recorded.data as { host_keys: unknown[] }).host_keys,
    [ACCEPTED_HOSTKEY],
  );

  const second = stub({ stdout: "changed=0\n" });
  const ctx2 = createModelTestContext({
    globalArgs: {},
    storedResources: {
      "spoke-1-hostkeys-198.51.100.20-22": {
        node: "spoke-1",
        host: "198.51.100.20",
        port: 22,
        host_keys: [ACCEPTED_HOSTKEY],
        observed_at: NOW.toISOString(),
      },
    },
  });
  await second.m.methods.apply.execute(
    { ...applyArgs(), ssh: ACCEPT_NEW },
    ctx2.context,
  );
  assertEquals(second.calls[0].target.host_key_policy, "strict");
  assertEquals(second.calls[0].target.host_keys, [ACCEPTED_HOSTKEY]);
});

Deno.test("strict never records host keys", async () => {
  const { m } = stub({ known_hosts: `${ACCEPTED_HOSTKEY}\n` });
  const { context, getWrittenResources } = createModelTestContext({
    globalArgs: {},
  });
  await m.methods.apply.execute({ ...applyArgs(), ssh: SSH }, context);
  assertEquals(
    getWrittenResources().some((r) => r.name.endsWith("-hostkeys")),
    false,
  );
});

Deno.test("schema bounds ssh host keys and relay lists", () => {
  const tooManyKeys = Array.from(
    { length: 65 },
    (_, i) => `198.51.100.20 ssh-ed25519 AAAAkey${i}`,
  );
  assertEquals(
    model.methods.apply.arguments.safeParse({
      ...applyArgs(),
      ssh: { ...SSH, host_keys: tooManyKeys },
    }).success,
    false,
  );
  const tooManyNames = Array.from({ length: 513 }, (_, i) => `peer-${i}`);
  const mesh = hubSpoke();
  mesh.relay_exclusion = [{ exclude: tooManyNames, for_nodes: ["*"] }];
  assertEquals(MeshSchema.safeParse(mesh).success, false);
});

Deno.test("the private key arguments are marked sensitive; globals are empty and strict", () => {
  const applyShape = model.methods.apply.arguments.shape;
  assertEquals(applyShape.private_key.meta()?.sensitive, true);
  const ssh = applyShape.ssh.shape;
  assertEquals(ssh.private_key.unwrap().meta()?.sensitive, true);
  assertEquals(model.globalArguments.safeParse({}).success, true);
  assertEquals(model.globalArguments.safeParse({ x: 1 }).success, false);
});

Deno.test("methods carry the documented description prefixes", () => {
  assertStringIncludes(model.methods.render.description, "READ-ONLY.");
  assertStringIncludes(model.methods.get.description, "READ-ONLY.");
  assertStringIncludes(model.methods.delete.description, "DESTRUCTIVE.");
  assertStringIncludes(model.description, "WireGuard");
  assertEquals(model.version, "2026.10.17.6");
  assertEquals(model.type, modelType);
});

Deno.test("packaging: the manifest and license describe this extension", async () => {
  const manifest = await Deno.readTextFile(
    new URL("../../manifest.yaml", import.meta.url),
  );
  assertStringIncludes(manifest, 'name: "@randybias/wireguard-mesh"');
  assertStringIncludes(manifest, "license: Apache-2.0");
  assertStringIncludes(manifest, 'version: "2026.10.17.6"');
  assertStringIncludes(manifest, "README.md");
  assertStringIncludes(manifest, "LICENSE.txt");
  const license = await Deno.readTextFile(
    new URL("../../LICENSE.txt", import.meta.url),
  );
  assertStringIncludes(license, "Apache License");
});

/** Records ssh invocations and answers the canonical upload/exec probes. */
function recordSsh(): {
  deps: SshDeps;
  calls: { cmd: string; args: string[]; stdin?: string; timeoutMs?: number }[];
} {
  const calls: {
    cmd: string;
    args: string[];
    stdin?: string;
    timeoutMs?: number;
  }[] = [];
  const run: CommandRunner = (cmd, args, _o = {}) => {
    const stdin = typeof _o.stdin === "string"
      ? _o.stdin
      : _o.stdin instanceof Uint8Array
      ? new TextDecoder().decode(_o.stdin)
      : undefined;
    calls.push({ cmd, args, stdin, timeoutMs: _o.timeoutMs });
    if (cmd === "ssh-agent") {
      return Promise.resolve(
        args[0] === "-s"
          ? {
            code: 0,
            stdout:
              "SSH_AUTH_SOCK=/tmp/a.sock;\nexport SSH_AUTH_SOCK;\nSSH_AGENT_PID=1;\nexport SSH_AGENT_PID;\n",
            stderr: "",
          }
          : { code: 0, stdout: "", stderr: "" },
      );
    }
    if (cmd === "ssh-add") {
      return Promise.resolve({ code: 0, stdout: "", stderr: "" });
    }
    if (cmd !== "ssh") {
      return Promise.resolve({ code: 0, stdout: "", stderr: "" });
    }
    return Promise.resolve({
      code: 0,
      stdout: "changed=1\nrb=/etc/wireguard/.wg0.rollback.X\n",
      stderr: "",
    });
  };
  return {
    deps: { run, now: () => 0, sleep: () => Promise.resolve() },
    calls,
  };
}

const STRICT_TARGET: SshTarget = {
  host: "198.51.100.20",
  user: "root",
  port: 22,
  host_key_policy: "strict",
  host_keys: [
    "198.51.100.20 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEXAMPLE",
  ],
};

Deno.test("sshTransport streams stdin into the remote command, never on argv", async () => {
  const rec = recordSsh();
  const t = sshTransport(STRICT_TARGET, rec.deps);
  const res = await t("echo hi", "TOPSECRET\n");
  assertEquals(res.code, 0);
  const ssh = rec.calls.find((c) => c.cmd === "ssh")!;
  // The secret is on the ssh process's stdin, never on any argv, and no
  // remote temp file is ever named.
  assertEquals(ssh.stdin, "TOPSECRET\n");
  for (const c of rec.calls) {
    const line = c.args.join(" ");
    assert(!line.includes("TOPSECRET"), c.cmd);
    assert(!line.includes("ssh-host-upload"), c.cmd);
    assert(!line.includes("mktemp"), c.cmd);
    assert(!line.includes("exec 3<"), c.cmd);
  }
  // The remote command is exactly `sh -c <script>`; no wrapper or temp file.
  assertEquals(ssh.args.at(-1), "'sh' '-c' 'echo hi'");
  // A per-command deadline is set so a hung session is killed.
  assert((ssh.timeoutMs ?? 0) > 0);
  // A supplied pin that applies to no host is refused, not silently accepted.
  const bad = sshTransport(
    { ...STRICT_TARGET, host_keys: ["203.0.113.9 ssh-ed25519 AAAA"] },
    rec.deps,
  );
  const e = await assertRejects(() => bad("echo hi"), TransportError);
  assertEquals(e.reason, "host-key");
});

Deno.test("the canonical transport: ssh 255 is typed, the key goes to ssh-add stdin", async () => {
  const seen: { cmd: string; args: string[]; stdin?: string }[] = [];
  const run: CommandRunner = (cmd, args, o = {}) => {
    seen.push({
      cmd,
      args,
      stdin: typeof o.stdin === "string" ? o.stdin : undefined,
    });
    if (cmd === "ssh-agent" && args[0] === "-s") {
      return Promise.resolve({
        code: 0,
        stdout:
          "SSH_AUTH_SOCK=/tmp/agent.sock;\nexport SSH_AUTH_SOCK;\nSSH_AGENT_PID=42;\nexport SSH_AGENT_PID;\n",
        stderr: "",
      });
    }
    if (cmd === "ssh") {
      return Promise.resolve({
        code: 255,
        stdout: "",
        stderr:
          "ssh: connect to host 198.51.100.20 port 22: Connection timed out",
      });
    }
    return Promise.resolve({ code: 0, stdout: "", stderr: "" });
  };
  const m = createModel({
    ssh: { run, now: () => 0, sleep: () => Promise.resolve() },
  });
  const { context } = createModelTestContext({ globalArgs: {} });
  const e = await assertRejects(
    () =>
      m.methods.apply.execute(
        { ...applyArgs(), ssh: { ...SSH, private_key: key("S") } },
        context,
      ),
    TransportError,
  );
  assertEquals(e.reason, "unreachable");
  const add = seen.find((s) => s.cmd === "ssh-add")!;
  assertEquals(add.stdin, key("S") + "\n");
  for (const s of seen) {
    assertEquals(s.args.join(" ").includes(key("S")), false, s.cmd);
    assertEquals(s.args.join(" ").includes(PRIV), false, s.cmd);
  }
  assertEquals(seen.at(-1)!.args, ["-k"]);
  await assertRejects(
    () =>
      m.methods.get.execute(
        { ...targetArgs, ssh: { ...SSH, host_keys: [] } },
        context,
      ),
    TransportError,
    "pinned",
  );
});

Deno.test("first-use TOFU: the confirmation connection is pinned to the key the apply accepted", async () => {
  const targets: SshTarget[] = [];
  const m = createModel({
    now: () => NOW,
    transport: (target): Transport => (script) => {
      targets.push(target);
      return Promise.resolve(
        script.includes("confirmed")
          ? { code: 0, stdout: "confirmed\n", stderr: "" }
          : {
            code: 0,
            stdout: "changed=1\nrb=/etc/wireguard/.wg0.rollback.TESTRUN\n",
            stderr: "",
            known_hosts: `${ACCEPTED_HOSTKEY}\n`,
          },
      );
    },
  });
  const { context } = createModelTestContext({ globalArgs: {} });
  await m.methods.apply.execute(
    { ...applyArgs(), ssh: ACCEPT_NEW },
    context,
  );
  assertEquals(targets.length, 2);
  assertEquals(targets[0].host_key_policy, "insecure_tofu");
  // The second step may not trust a fresh key: it must match the first.
  assertEquals(targets[1].host_key_policy, "strict");
  assertEquals(targets[1].host_keys, [ACCEPTED_HOSTKEY]);
});

Deno.test("a confirmation the node refuses means the change was undone: nothing is recorded", async () => {
  for (
    const [code, text] of [[3, "was undone"], [4, "superseded"], [
      75,
      "could not be confirmed",
    ]] as const
  ) {
    const m = createModel({
      now: () => NOW,
      transport: (): Transport => (script) =>
        Promise.resolve(
          script.includes("confirmed") ? { code, stdout: "", stderr: "" } : {
            code: 0,
            stdout: "changed=1\nrb=/etc/wireguard/.wg0.rollback.TESTRUN\n",
            stderr: "",
          },
        ),
    });
    for (const run of ["apply", "delete"] as const) {
      const { context, getWrittenResources } = createModelTestContext({
        globalArgs: {},
      });
      const e = await assertRejects(
        () =>
          run === "apply"
            ? m.methods.apply.execute(applyArgs(), context)
            : m.methods.delete.execute(deleteArgs, context),
        TransportError,
        text,
      );
      assertEquals(e.reason, "remote");
      assertEquals(getWrittenResources().length, 0, `${run} ${code}`);
    }
  }
});

Deno.test("first-use TOFU with no recorded key refuses to continue on trust", async () => {
  const m = createModel({
    now: () => NOW,
    transport: (): Transport => () =>
      Promise.resolve({
        code: 0,
        stdout: "changed=1\nrb=/etc/wireguard/.wg0.rollback.TESTRUN\n",
        stderr: "",
        known_hosts: "",
      }),
  });
  const { context } = createModelTestContext({ globalArgs: {} });
  const e = await assertRejects(
    () => m.methods.apply.execute({ ...applyArgs(), ssh: ACCEPT_NEW }, context),
    TransportError,
  );
  assertEquals(e.reason, "host-key");
});

Deno.test("insecure_tofu on a non-22 port pins [host]:port and reuses it strictly", async () => {
  const scans: string[] = [];
  const runs: string[] = [];
  const run: CommandRunner = (cmd, args, _o = {}) => {
    if (cmd === "ssh-keyscan") {
      scans.push(args.join(" "));
      return Promise.resolve({
        code: 0,
        stdout: "[198.51.100.20]:2222 ssh-ed25519 AAAASCAN\n",
        stderr: "",
      });
    }
    if (cmd === "ssh-agent") {
      return Promise.resolve(
        args[0] === "-s"
          ? {
            code: 0,
            stdout:
              "SSH_AUTH_SOCK=/tmp/a.sock;\nexport SSH_AUTH_SOCK;\nSSH_AGENT_PID=1;\nexport SSH_AGENT_PID;\n",
            stderr: "",
          }
          : { code: 0, stdout: "", stderr: "" },
      );
    }
    if (cmd === "ssh-add") {
      return Promise.resolve({ code: 0, stdout: "", stderr: "" });
    }
    if (cmd === "ssh") {
      runs.push(args.join(" "));
      return Promise.resolve({ code: 0, stdout: "", stderr: "" });
    }
    return Promise.resolve({ code: 0, stdout: "", stderr: "" });
  };
  const deps: SshDeps = { run, now: () => 0, sleep: () => Promise.resolve() };
  const toTarget = {
    host: "198.51.100.20",
    user: "root",
    port: 2222,
    host_key_policy: "insecure_tofu" as const,
    host_keys: [] as string[],
  };
  const first = await sshTransport(toTarget, deps)("true");
  assertEquals(
    first.known_hosts,
    "[198.51.100.20]:2222 ssh-ed25519 AAAASCAN\n",
  );
  // The learned pin applies on the next run: strict with that exact line works.
  const pin = "[198.51.100.20]:2222 ssh-ed25519 AAAASCAN";
  const second = await sshTransport({
    ...toTarget,
    host_key_policy: "strict",
    host_keys: [pin],
  }, deps)("true");
  assertEquals(second.code, 0);
  assertEquals(scans.length > 0, true);
  assertEquals(runs.every((r) => !r.includes("AAAASCAN")), true);
});

Deno.test("transport command diff: a secret never reaches a remote temp file (old vs new)", async () => {
  const rec = recordSsh();
  const script = applyScript("wg0");
  await sshTransport(STRICT_TARGET, rec.deps)(
    script,
    "PRIVATEKEY\n[Interface]\n",
  );
  const commands = rec.calls.filter((c) => c.cmd === "ssh")
    .map((c) => c.args.at(-1) ?? "");
  // The transport this replaced issued these; none may appear now.
  const OLD_TEMP_FILE_COMMANDS = [
    "'mktemp' '-d' '-p' '/tmp' 'wgmesh.XXXXXXXX'",
    ".ssh-host-upload",
    "exec 3<'",
    "rm -f -- '/tmp/wgmesh.",
  ];
  for (const marker of OLD_TEMP_FILE_COMMANDS) {
    assertEquals(commands.some((c) => c.includes(marker)), false, marker);
  }
  // New: exactly one remote command, the unchanged script, and the secret on
  // the ssh process's stdin.
  assertEquals(commands.length, 1);
  assertEquals(commands[0], quoteArgv(["sh", "-c", script]));
  const ssh = rec.calls.find((c) => c.cmd === "ssh")!;
  assertEquals(ssh.stdin, "PRIVATEKEY\n[Interface]\n");
  assert((ssh.timeoutMs ?? 0) > 0);
});

Deno.test("legacy ssh inputs are migrated: object host_keys, accept-new, insecure", () => {
  const args = model.methods.apply.arguments;
  const ok = args.parse({
    ...applyArgs(),
    ssh: { ...SSH, host_keys: [{ type: "ssh-ed25519", key: "AAAAEXAMPLE" }] },
  }) as { ssh: { host_keys: string[] } };
  assertEquals(ok.ssh.host_keys, ["ssh-ed25519 AAAAEXAMPLE"]);
  assertEquals(
    (args.parse({
      ...applyArgs(),
      ssh: { ...SSH, host_key_policy: "accept-new" },
    }) as {
      ssh: { host_key_policy: string };
    }).ssh.host_key_policy,
    "insecure_tofu",
  );
  const bad = args.safeParse({
    ...applyArgs(),
    ssh: { ...SSH, host_key_policy: "insecure" },
  });
  assertEquals(bad.success, false);
  if (!bad.success) {
    assertEquals(
      bad.error.issues.some((i) => i.message.includes("insecure_tofu")),
      true,
    );
  }
});

Deno.test("ssh host_keys lines are grammar-checked", () => {
  const args = model.methods.apply.arguments;
  for (
    const good of [
      "198.51.100.20 ssh-ed25519 AAAAEXAMPLE",
      "ssh-ed25519 AAAAEXAMPLE",
      "[198.51.100.20]:2222 ssh-ed25519 AAAAEXAMPLE",
    ]
  ) {
    assertEquals(
      args.safeParse({ ...applyArgs(), ssh: { ...SSH, host_keys: [good] } })
        .success,
      true,
      good,
    );
  }
  for (
    const bad of [
      "198.51.100.20 ssh-ed25519",
      "198.51.100.20 ssh-ed25519 AAAA extra",
      "ssh-ed25519 has spaces in blob",
      "; rm -rf /",
    ]
  ) {
    assertEquals(
      args.safeParse({ ...applyArgs(), ssh: { ...SSH, host_keys: [bad] } })
        .success,
      false,
      bad,
    );
  }
});

Deno.test("a legacy {type,key} hostkeys record is migrated to a port-aware line", async () => {
  const targets: SshTarget[] = [];
  const m = createModel({
    now: () => NOW,
    transport: (target): Transport => (script) => {
      targets.push(target);
      return Promise.resolve(
        script.includes("confirmed")
          ? { code: 0, stdout: "confirmed\n", stderr: "" }
          : { code: 0, stdout: "changed=0\n", stderr: "" },
      );
    },
  });
  const ctx = createModelTestContext({
    globalArgs: {},
    storedResources: {
      "spoke-1-hostkeys": {
        node: "spoke-1",
        host: "198.51.100.20",
        port: 2222,
        host_keys: [{ type: "ssh-ed25519", key: "AAAAEXAMPLE" }],
        observed_at: NOW.toISOString(),
      },
    },
  });
  await m.methods.apply.execute({
    ...applyArgs(),
    ssh: {
      ...SSH,
      port: 2222,
      host_key_policy: "insecure_tofu",
      host_keys: [],
    },
  }, ctx.context);
  const line = "[198.51.100.20]:2222 ssh-ed25519 AAAAEXAMPLE";
  assertEquals(targets[0].host_key_policy, "strict");
  assertEquals(targets[0].host_keys, [line]);
  const rewritten = ctx.getWrittenResources().find((r) =>
    r.name === "spoke-1-hostkeys-198.51.100.20-2222"
  );
  assertExists(rewritten);
  assertEquals((rewritten.data as { host_keys: string[] }).host_keys, [line]);
});

Deno.test("a failed remote command is typed and leaves no remote temp file", async () => {
  const calls: string[] = [];
  const run: CommandRunner = (cmd, args) => {
    if (cmd !== "ssh") {
      return Promise.resolve({ code: 0, stdout: "", stderr: "" });
    }
    const remote = args[args.length - 1] ?? "";
    calls.push(remote);
    return Promise.resolve({ code: 3, stdout: "", stderr: "wg failed" });
  };
  const deps: SshDeps = { run, now: () => 0, sleep: () => Promise.resolve() };
  const res = await sshTransport(STRICT_TARGET, deps)("echo hi", "SECRET\n");
  assertEquals(res.code, 3);
  assertEquals(calls.length, 1);
  assertEquals(
    calls.some((c) => c.includes("mktemp") || c.includes("rm -f")),
    false,
  );
});

Deno.test("a stored hostkey record that cannot be normalized fails closed", async () => {
  const m = createModel({
    now: () => NOW,
    transport: (): Transport => () =>
      Promise.resolve({ code: 0, stdout: "changed=0\n", stderr: "" }),
  });
  const ctx = createModelTestContext({
    globalArgs: {},
    storedResources: {
      "spoke-1-hostkeys": {
        node: "spoke-1",
        host: "198.51.100.20",
        port: 22,
        host_keys: [{ type: "ssh-rsa", key: "A".repeat(3000) }],
        observed_at: NOW.toISOString(),
      },
    },
  });
  await assertRejects(
    () =>
      m.methods.apply.execute({
        ...applyArgs(),
        ssh: { ...SSH, host_key_policy: "insecure_tofu", host_keys: [] },
      }, ctx.context),
    TransportError,
    "delete it to re-learn",
  );
});

Deno.test("model type describe: the ssh schema still renders its enum and item shape", () => {
  const schema = z.toJSONSchema(
    model.methods.apply.arguments,
  ) as unknown as {
    properties: {
      ssh: {
        properties: {
          host_key_policy: { enum?: string[]; description?: string };
          host_keys: {
            items?: { type?: string };
            anyOf?: { items?: { type?: string } }[];
          };
        };
      };
    };
  };
  const ssh = schema.properties.ssh.properties;
  assertEquals(ssh.host_key_policy.enum, ["strict", "insecure_tofu"]);
  assertEquals(typeof ssh.host_key_policy.description, "string");
  const items = ssh.host_keys.items ?? ssh.host_keys.anyOf?.[0]?.items;
  assertEquals(items?.type, "string");
});

const TOFU = (port: number) => ({
  ...SSH,
  port,
  host_key_policy: "insecure_tofu" as const,
  host_keys: [],
});
const keyFor = (port: number) =>
  `[198.51.100.20]:${port} ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPORT${port}`;
const line22 = "198.51.100.20 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPORT22";

Deno.test("TOFU pins are per host and port: :22 then :2222 then :22 stays pinned", async () => {
  // One persistent store shared by three runs, like the real data store.
  const store: Record<string, Record<string, unknown>> = {};
  const run = async (port: number, known?: string) => {
    const s = stub({ stdout: "changed=0\n", known_hosts: known });
    const ctx = createModelTestContext({
      globalArgs: {},
      storedResources: structuredClone(store),
    });
    await s.m.methods.apply.execute(
      { ...applyArgs(), ssh: TOFU(port) },
      ctx.context,
    );
    for (const w of ctx.getWrittenResources()) {
      store[w.name] = w.data as Record<string, unknown>;
    }
    return s.calls[0].target;
  };
  // :22 learns and pins.
  const first = await run(22, `${line22}\n`);
  assertEquals(first.host_key_policy, "insecure_tofu");
  // :2222 is a new endpoint: it learns, and does not touch the :22 pin.
  const other = await run(2222, `${keyFor(2222)}\n`);
  assertEquals(other.host_key_policy, "insecure_tofu");
  assertEquals(
    Object.keys(store).filter((k) => k.includes("hostkeys")).sort(),
    [
      "spoke-1-hostkeys-198.51.100.20-2222",
      "spoke-1-hostkeys-198.51.100.20-22",
    ].sort(),
  );
  // Back on :22: still pinned to the key learned the first time.
  const again = await run(22);
  assertEquals(again.host_key_policy, "strict");
  assertEquals(again.host_keys, [line22]);
  const back = await run(2222);
  assertEquals(back.host_key_policy, "strict");
  assertEquals(back.host_keys, [keyFor(2222)]);
});

Deno.test("a legacy per-node record pins its own endpoint only and is never overwritten by another", async () => {
  const s = stub({ stdout: "changed=0\n", known_hosts: `${keyFor(2222)}\n` });
  const legacy = {
    node: "spoke-1",
    host: "198.51.100.20",
    port: 22,
    host_keys: [line22],
    observed_at: NOW.toISOString(),
  };
  const ctx = createModelTestContext({
    globalArgs: {},
    storedResources: { "spoke-1-hostkeys": legacy },
  });
  // A different port is a new endpoint (TOFU) and the legacy record stays.
  await s.m.methods.apply.execute(
    { ...applyArgs(), ssh: TOFU(2222) },
    ctx.context,
  );
  assertEquals(s.calls[0].target.host_key_policy, "insecure_tofu");
  assertEquals(
    ctx.getWrittenResources().some((r) => r.name === "spoke-1-hostkeys"),
    false,
  );
  // The legacy endpoint itself is still pinned, and moves to its keyed record.
  const s2 = stub({ stdout: "changed=0\n" });
  const ctx2 = createModelTestContext({
    globalArgs: {},
    storedResources: { "spoke-1-hostkeys": legacy },
  });
  await s2.m.methods.apply.execute(
    { ...applyArgs(), ssh: TOFU(22) },
    ctx2.context,
  );
  assertEquals(s2.calls[0].target.host_key_policy, "strict");
  assertEquals(s2.calls[0].target.host_keys, [line22]);
  assertExists(
    ctx2.getWrittenResources().find((r) =>
      r.name === "spoke-1-hostkeys-198.51.100.20-22"
    ),
  );
});

Deno.test("records only tampering could produce fail closed instead of re-learning", async () => {
  const keyed = "spoke-1-hostkeys-198.51.100.20-22";
  const base = {
    node: "spoke-1",
    host: "198.51.100.20",
    port: 22,
    host_keys: [line22],
    observed_at: NOW.toISOString(),
  };
  const bad: [string, string, Record<string, unknown>][] = [
    ["empty host_keys", keyed, { ...base, host_keys: [] }],
    ["port as a string", keyed, { ...base, port: "22" }],
    ["host mismatch inside the keyed record", keyed, {
      ...base,
      host: "203.0.113.9",
    }],
    ["unparseable keys", keyed, { ...base, host_keys: ["not a key line"] }],
    ["an unreadable legacy record", "spoke-1-hostkeys", {
      ...base,
      port: "22",
    }],
  ];
  for (const [label, name, record] of bad) {
    const s = stub({ stdout: "changed=0\n", known_hosts: `${line22}\n` });
    const ctx = createModelTestContext({
      globalArgs: {},
      storedResources: { [name]: record },
    });
    await assertRejects(
      () =>
        s.m.methods.apply.execute(
          { ...applyArgs(), ssh: TOFU(22) },
          ctx.context,
        ),
      TransportError,
      "delete it to re-learn",
      label,
    );
    assertEquals(s.calls.length, 0, label);
    assertEquals(ctx.getWrittenResources().length, 0, label);
  }
});

Deno.test("legacy host key objects must be exactly {type, key} strings", () => {
  const parse = (host_keys: unknown) =>
    model.methods.apply.arguments.safeParse({
      ...applyArgs(),
      ssh: { ...SSH, host_keys },
    }).success;
  assertEquals(parse([{ type: "ssh-ed25519", key: "AAAAEXAMPLE" }]), true);
  assertEquals(
    parse([{ type: "ssh-ed25519", key: "AAAAEXAMPLE", extra: 1 }]),
    false,
  );
  assertEquals(parse([{ type: 5, key: "AAAAEXAMPLE" }]), false);
  assertEquals(
    parse([{ type: "ssh-ed25519", key: { toString: () => "x" } }]),
    false,
  );
  assertEquals(parse([{ type: "ssh-ed25519" }]), false);
});
