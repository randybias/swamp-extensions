import {
  assertEquals,
  assertExists,
  assertRejects,
  assertStringIncludes,
} from "jsr:@std/assert@1.0.19";
import { createModelTestContext } from "jsr:@swamp-club/swamp-testing@0.20261014.55";
import { fullMesh, hubSelf, hubSpoke, key } from "./_lib/fixtures.ts";
import {
  type CommandResult,
  sshArgv,
  type SshTarget,
  type Transport,
  TransportError,
  type TransportResult,
} from "./_lib/push.ts";
import { MeshSchema } from "./_lib/render.ts";
import { createModel, model, type as modelType } from "./wireguard_mesh.ts";

const PRIV = key("P");
const SSH = {
  host: "198.51.100.20",
  user: "root",
  port: 22,
  host_key_policy: "strict" as const,
  host_keys: [{ type: "ssh-ed25519", key: "AAAAC3NzaC1lZDI1NTE5AAAAIEXAMPLE" }],
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
  host_key_policy: "accept-new" as const,
  host_keys: [],
};
const ACCEPTED_HOSTKEY = {
  type: "ssh-ed25519",
  key: "AAAAC3NzaC1lZDI1NTE5AAAAIFIRSTHOSTKEY",
};

Deno.test("accept-new is real TOFU: the first key is accepted, pinned, and enforced later", async () => {
  const first = stub({
    stdout: "changed=0\n",
    known_hosts:
      `198.51.100.20 ${ACCEPTED_HOSTKEY.type} ${ACCEPTED_HOSTKEY.key}\n`,
  });
  const ctx1 = createModelTestContext({ globalArgs: {} });
  await first.m.methods.apply.execute(
    { ...applyArgs(), ssh: ACCEPT_NEW },
    ctx1.context,
  );
  assertEquals(first.calls[0].target.host_key_policy, "accept-new");
  const recorded = ctx1.getWrittenResources().find((r) =>
    r.name === "spoke-1-hostkeys"
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
      "spoke-1-hostkeys": {
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

Deno.test("insecure never records host keys", async () => {
  const { m } = stub({
    known_hosts:
      `198.51.100.20 ${ACCEPTED_HOSTKEY.type} ${ACCEPTED_HOSTKEY.key}\n`,
  });
  const { context, getWrittenResources } = createModelTestContext({
    globalArgs: {},
  });
  await m.methods.apply.execute(
    {
      ...applyArgs(),
      ssh: { ...SSH, host_key_policy: "insecure", host_keys: [] },
    },
    context,
  );
  assertEquals(
    getWrittenResources().some((r) => r.name.endsWith("-hostkeys")),
    false,
  );
});

Deno.test("schema bounds ssh host keys and relay lists", () => {
  const tooManyKeys = Array.from({ length: 65 }, (_, i) => ({
    type: "ssh-ed25519",
    key: `key${i}`,
  }));
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
  assertEquals(model.version, "2026.10.17.4");
  assertEquals(model.type, modelType);
});

Deno.test("packaging: the manifest and license describe this extension", async () => {
  const manifest = await Deno.readTextFile(
    new URL("../../manifest.yaml", import.meta.url),
  );
  assertStringIncludes(manifest, 'name: "@randybias/wireguard-mesh"');
  assertStringIncludes(manifest, "license: Apache-2.0");
  assertStringIncludes(manifest, 'version: "2026.10.17.4"');
  assertStringIncludes(manifest, "README.md");
  assertStringIncludes(manifest, "LICENSE.txt");
  const license = await Deno.readTextFile(
    new URL("../../LICENSE.txt", import.meta.url),
  );
  assertStringIncludes(license, "Apache License");
});

Deno.test("ssh argv: host-key policy, no secret, no option injection", () => {
  const kh = "/tmp/kh";
  const a = sshArgv(SSH, "script", kh);
  assertEquals(a.includes("StrictHostKeyChecking=yes"), true);
  assertEquals(a.includes(`UserKnownHostsFile=${kh}`), true);
  assertEquals(a.at(-2), "198.51.100.20");
  assertEquals(a.indexOf("--") < a.indexOf("198.51.100.20"), true);
  const ins = sshArgv({ ...SSH, host_key_policy: "insecure" }, "s", kh);
  assertEquals(ins.includes("StrictHostKeyChecking=no"), true);
  for (const host of ["-oProxyCommand=x", "a b", "h;x", "h$(x)"]) {
    try {
      sshArgv({ ...SSH, host }, "s", kh);
      throw new Error(`accepted ${host}`);
    } catch (e) {
      assertEquals(e instanceof TransportError, true, host);
    }
  }
});

Deno.test("the real ssh transport: strict needs pinned keys, ssh 255 is typed, key goes to ssh-add stdin", async () => {
  const seen: { cmd: string; args: string[]; stdin?: string }[] = [];
  const spawn = (
    cmd: string,
    args: string[],
    o?: { stdin?: string },
  ): Promise<CommandResult> => {
    seen.push({ cmd, args, stdin: o?.stdin });
    if (cmd === "ssh-agent" && args[0] === "-s") {
      return Promise.resolve({
        code: 0,
        stdout:
          "SSH_AUTH_SOCK=/tmp/agent.sock; export SSH_AUTH_SOCK;\nSSH_AGENT_PID=42; export SSH_AGENT_PID;\n",
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
  const m = createModel({ spawn });
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
            known_hosts:
              `198.51.100.20 ${ACCEPTED_HOSTKEY.type} ${ACCEPTED_HOSTKEY.key}\n`,
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
  assertEquals(targets[0].host_key_policy, "accept-new");
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
