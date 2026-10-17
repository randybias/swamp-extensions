/**
 * Tests for the k0s-multinode methods (fake transport, no network).
 *
 * @module
 */

import { assertEquals, assertRejects } from "jsr:@std/assert@1.0.19";
import { createModelTestContext } from "jsr:@swamp-club/swamp-testing@0.20261014.55";
import type { ExecResult } from "./_lib/ssh.ts";
import type { SshTransport } from "./_lib/transport.ts";
import {
  createModel,
  DetachRefusedError,
  DrainBlockedError,
  VaultUnavailableError,
  WaitTimeoutError,
} from "./k0s_multinode.ts";

const SSH = {
  host: "192.0.2.10",
  user: "root",
  host_key_policy: "strict" as const,
  host_keys: ["192.0.2.10 ssh-ed25519 PLACEHOLDER-HOST-KEY"],
  private_key: "PLACEHOLDER-PRIVATE-KEY-NOT-REAL",
};

const NODE_JSON = JSON.stringify({
  items: [
    {
      metadata: {
        name: "ctrl-1",
        labels: { "node.k0sproject.io/role": "control-plane" },
      },
      spec: {},
      status: {
        nodeInfo: { kubeletVersion: "v1.31.2" },
        conditions: [{ type: "Ready", status: "True" }],
      },
    },
  ],
});

/** Builds a real-shaped `k0s token create` payload: base64(gzip(kubeconfig)). */
async function fakeJoinToken(id: string): Promise<string> {
  const yaml =
    `apiVersion: v1\nkind: Config\nusers:\n- name: k0s\n  user:\n    token: ${id}.0123456789abcdef\n`;
  const stream = new Blob([new TextEncoder().encode(yaml)]).stream()
    .pipeThrough(new CompressionStream("gzip"));
  const bytes = new Uint8Array(await new Response(stream).arrayBuffer());
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function makeTransport(
  handler: (argv: string[]) => Partial<ExecResult> | undefined,
): SshTransport {
  return {
    exec: (_target, argv) => {
      const r = handler(argv) ?? {};
      return Promise.resolve({
        stdout: r.stdout ?? "",
        stderr: r.stderr ?? "",
        exit_code: r.exit_code ?? 0,
      });
    },
    upload: () => Promise.reject(new Error("upload not used")),
    learnHostKeys: () => Promise.resolve([]),
  };
}

function deps(
  transport: SshTransport,
  nowMs = Date.parse("2026-10-17T00:00:00Z"),
) {
  let t = nowMs;
  return {
    transport,
    now: () => new Date(t),
    sleep: () => {
      t += 10_000;
      return Promise.resolve();
    },
  };
}

Deno.test("mint_join_token stores the token in vault and returns only its id", async () => {
  let lists = 0;
  const joinTokenValue = await fakeJoinToken("abc123");
  const transport = makeTransport((argv) => {
    if (argv[1] === "token" && argv[2] === "list") {
      lists += 1;
      return {
        stdout: lists === 1
          ? "ID Role Expiry\n"
          : "ID Role Expiry\nabc123 worker 2026-10-18T00:00:00Z\n",
      };
    }
    if (argv[1] === "token" && argv[2] === "create") {
      return { stdout: `${joinTokenValue}\n` };
    }
    return undefined;
  });
  const model = createModel(deps(transport));
  const puts: [string, string, string][] = [];
  const { context, getWrittenResources, getLogs } = createModelTestContext();
  // deno-lint-ignore no-explicit-any
  (context as any).vaultService = {
    put: (v: string, k: string, value: string) => {
      puts.push([v, k, value]);
      return Promise.resolve();
    },
  };
  const args = model.methods.mint_join_token.arguments.parse({
    cluster_name: "k0s-lab",
    ssh: SSH,
    role: "worker",
    token_expiry: "1h",
    token_vault: { vault: "cluster", key: "join-worker-1" },
  });
  const out = await model.methods.mint_join_token.execute(args, context);
  assertEquals(puts, [["cluster", "join-worker-1", joinTokenValue]]);
  assertEquals(out.result.token_id, "abc123");
  assertEquals(out.result.role, "worker");
  assertEquals("token" in out.result, false);
  const tokens = getWrittenResources().find((r) => r.specName === "tokens")!
    .data as Record<string, unknown>;
  const seen = JSON.stringify([out.result, tokens, getLogs()]);
  assertEquals(seen.includes(joinTokenValue), false);
  assertEquals(seen.includes("join-worker-1"), true);
});

Deno.test("mint_join_token refuses without a vault service and never mints", async () => {
  let created = false;
  const transport = makeTransport((argv) => {
    if (argv[2] === "create") created = true;
    return undefined;
  });
  const model = createModel(deps(transport));
  const args = model.methods.mint_join_token.arguments.parse({
    cluster_name: "k0s-lab",
    ssh: SSH,
    role: "worker",
    token_vault: { vault: "cluster", key: "k" },
  });
  await assertRejects(
    () =>
      model.methods.mint_join_token.execute(
        args,
        createModelTestContext().context,
      ),
    VaultUnavailableError,
    "vault service",
  );
  assertEquals(created, false);
});

Deno.test("invalidate_join_token tombstones the vault key and is idempotent", async () => {
  const transport = makeTransport((argv) =>
    argv[2] === "invalidate" ? {} : undefined
  );
  const model = createModel(deps(transport));
  const puts: [string, string, string][] = [];
  const { context } = createModelTestContext();
  // deno-lint-ignore no-explicit-any
  (context as any).vaultService = {
    put: (v: string, k: string, value: string) => {
      puts.push([v, k, value]);
      return Promise.resolve();
    },
  };
  const args = model.methods.invalidate_join_token.arguments.parse({
    cluster_name: "k0s-lab",
    ssh: SSH,
    token_id: "abc123",
    token_vault: { vault: "cluster", key: "join-worker-1" },
  });
  const out = await model.methods.invalidate_join_token.execute(args, context);
  assertEquals(out.result.invalidated, true);
  assertEquals(puts[0][2].includes("invalidated"), true);
});

Deno.test("wait_joined returns on a Ready node", async () => {
  const transport = makeTransport((argv) => {
    if (argv[2] === "get") return { stdout: NODE_JSON };
    return undefined;
  });
  const model = createModel(deps(transport));
  const args = model.methods.wait_joined.arguments.parse({
    cluster_name: "k0s-lab",
    ssh: SSH,
    node: "ctrl-1",
    role: "worker",
    timeout_s: 60,
    poll_interval_s: 1,
  });
  const out = await model.methods.wait_joined.execute(
    args,
    createModelTestContext().context,
  );
  assertEquals(out.result.joined, true);
  assertEquals(out.result.ready, true);
});

Deno.test("wait_joined times out when the node never appears", async () => {
  const transport = makeTransport((argv) =>
    argv[2] === "get" ? { stdout: JSON.stringify({ items: [] }) } : undefined
  );
  const model = createModel(deps(transport));
  const args = model.methods.wait_joined.arguments.parse({
    cluster_name: "k0s-lab",
    ssh: SSH,
    node: "worker-9",
    role: "worker",
    timeout_s: 60,
    poll_interval_s: 1,
  });
  await assertRejects(
    () =>
      model.methods.wait_joined.execute(
        args,
        createModelTestContext().context,
      ),
    WaitTimeoutError,
    "did not join",
  );
});

Deno.test("drain_node reports a PodDisruptionBudget block as a typed error", async () => {
  const transport = makeTransport((argv) => {
    if (argv[2] === "get") return { stdout: JSON.stringify({ items: [] }) };
    if (argv[2] === "drain") {
      return {
        exit_code: 1,
        stderr:
          "Cannot evict pod as it would violate the pod's disruption budget.",
      };
    }
    return undefined;
  });
  const model = createModel(deps(transport));
  const args = model.methods.drain_node.arguments.parse({
    cluster_name: "k0s-lab",
    ssh: SSH,
    node: "worker-1",
    drain_timeout_s: 60,
  });
  await assertRejects(
    () =>
      model.methods.drain_node.execute(args, createModelTestContext().context),
    DrainBlockedError,
    "PodDisruptionBudget",
  );
});

Deno.test("detach_node refuses an undrained node without confirm", async () => {
  const transport = makeTransport((argv) =>
    argv[2] === "get" ? { stdout: NODE_JSON } : undefined
  );
  const model = createModel(deps(transport));
  const args = model.methods.detach_node.arguments.parse({
    cluster_name: "k0s-lab",
    ssh: SSH,
    node: "ctrl-1",
  });
  await assertRejects(
    () =>
      model.methods.detach_node.execute(args, createModelTestContext().context),
    DetachRefusedError,
    "not drained",
  );
});

Deno.test("detach_node leaves etcd for a cordoned controller with confirm", async () => {
  const cordoned = JSON.stringify({
    items: [{
      metadata: {
        name: "ctrl-1",
        labels: { "node.k0sproject.io/role": "control-plane" },
      },
      spec: { unschedulable: true },
      status: { conditions: [{ type: "Ready", status: "True" }] },
    }],
  });
  const members = JSON.stringify({
    members: {
      "ctrl-1": "https://192.0.2.11:2380",
      "ctrl-2": "https://192.0.2.12:2380",
      "ctrl-3": "https://192.0.2.13:2380",
      "ctrl-4": "https://192.0.2.14:2380",
    },
  });
  const execs: string[][] = [];
  const transport = makeTransport((argv) => {
    execs.push(argv);
    if (argv[3] === "pods") return { stdout: JSON.stringify({ items: [] }) };
    if (argv[3] === "nodes") return { stdout: cordoned };
    if (argv[1] === "etcd") return { stdout: members };
    return undefined;
  });
  const model = createModel(deps(transport));
  const args = model.methods.detach_node.arguments.parse({
    cluster_name: "k0s-lab",
    ssh: SSH,
    node: "ctrl-1",
    confirm: "ctrl-1",
  });
  const out = await model.methods.detach_node.execute(
    args,
    createModelTestContext().context,
  );
  assertEquals(out.result.detached, true);
  assertEquals(out.result.etcd_left, true);
  assertEquals(
    execs.some((a) => a[1] === "etcd" && a[2] === "leave"),
    true,
  );
  assertEquals(
    execs.some((a) => a[3] === "controlnode" && a[4] === "ctrl-1"),
    true,
  );
});

Deno.test("detach_node refuses a 3->2 controller removal without confirm", async () => {
  const cordoned = JSON.stringify({
    items: [{
      metadata: {
        name: "ctrl-1",
        labels: { "node.k0sproject.io/role": "control-plane" },
      },
      spec: { unschedulable: true },
      status: { conditions: [{ type: "Ready", status: "True" }] },
    }],
  });
  const members = JSON.stringify({
    members: {
      "ctrl-1": "https://192.0.2.11:2380",
      "ctrl-2": "https://192.0.2.12:2380",
      "ctrl-3": "https://192.0.2.13:2380",
    },
  });
  const transport = makeTransport((argv) => {
    if (argv[3] === "pods") return { stdout: JSON.stringify({ items: [] }) };
    if (argv[3] === "nodes") return { stdout: cordoned };
    if (argv[1] === "etcd") return { stdout: members };
    return undefined;
  });
  const model = createModel(deps(transport));
  const args = model.methods.detach_node.arguments.parse({
    cluster_name: "k0s-lab",
    ssh: SSH,
    node: "ctrl-1",
  });
  await assertRejects(
    () =>
      model.methods.detach_node.execute(args, createModelTestContext().context),
    DetachRefusedError,
    "etcd members",
  );
});

Deno.test("get and sync report live membership and flag an unknown node", async () => {
  const transport = makeTransport((argv) => {
    if (argv[2] === "get") return { stdout: NODE_JSON };
    if (argv[1] === "etcd") {
      return {
        stdout: JSON.stringify({
          members: {
            "ctrl-1": "https://192.0.2.11:2380",
          },
        }),
      };
    }
    if (argv[2] === "list") return { stdout: "ID Role Expiry\n" };
    return undefined;
  });
  const model = createModel(deps(transport));
  const getArgs = model.methods.get.arguments.parse({
    cluster_name: "k0s-lab",
    ssh: SSH,
  });
  const got = await model.methods.get.execute(
    getArgs,
    createModelTestContext().context,
  );
  assertEquals(got.result.nodes.length, 1);
  assertEquals(got.result.etcd_members.length, 1);

  const { context } = createModelTestContext({
    storedResources: {
      "k0s-lab": {
        cluster_name: "k0s-lab",
        operation: "create",
        nodes: [{ name: "worker-1", role: "worker" }],
        steps: [],
        observed_at: "2026-01-01T00:00:00Z",
      },
    },
  } as never);
  const syncArgs = model.methods.sync.arguments.parse({
    cluster_name: "k0s-lab",
    ssh: SSH,
  });
  const synced = await model.methods.sync.execute(syncArgs, context);
  assertEquals(synced.result.in_sync, false);
  assertEquals(
    (synced.result.diffs as string[]).some((d) => d.includes("unknown node")),
    true,
  );
  assertEquals(
    (synced.result.diffs as string[]).some((d) => d.includes("worker-1")),
    true,
  );
});
