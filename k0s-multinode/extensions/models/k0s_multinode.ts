/**
 * Swamp extension model for a multi-node k0s cluster.
 *
 * Cluster-scope work that no single node owns — topology planning, join tokens,
 * membership, drain/detach and upgrade ordering — runs through a controller
 * over SSH. Per-node work is delegated to `@randybias/k0s-cluster`; this model
 * holds no kubeconfig. Join token values live only in memory and a caller-named
 * vault key; state and output carry token IDs, roles and expiry only.
 *
 * @module
 */

import { z } from "npm:zod@4.3.6";
import {
  controlNodeListArgs,
  cordonArgs,
  deleteControlNodeArgs,
  deleteNodeArgs,
  drainArgs,
  etcdLeaveArgs,
  type EtcdMember,
  etcdMemberListArgs,
  hasNonDaemonSetPods,
  type JoinToken,
  joinTokenIdFromCreate,
  newTokenIds,
  nodeListArgs,
  nodePodListArgs,
  ok,
  parseClusterNodes,
  parseEtcdMembers,
  parseItemNames,
  parseJoinTokens,
  TOKEN_TOMBSTONE,
  tokenCreateArgs,
  tokenInvalidateArgs,
  tokenListArgs,
  uncordonArgs,
} from "./_lib/cluster.ts";
import {
  type ExecResult,
  HOST_RE,
  type SshTarget,
  USER_RE,
} from "./_lib/ssh.ts";
import { createSshTransport, type SshTransport } from "./_lib/transport.ts";
import {
  durationMinutes,
  inferOperation,
  IP_RE,
  type NodeSpec,
  plan,
  type PlanInput,
  PlanInputSchema,
  planRemove,
  type PlanStep,
  SUBDOMAIN_RE,
} from "./_lib/plan.ts";

// deno-lint-ignore no-explicit-any
type Ctx = any;

const GlobalArgsSchema = z.strictObject({});

const NAME = z.string().regex(
  /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/,
  "not a DNS-1123 label",
);

/** SSH transport block, mirroring `@randybias/k0s-cluster`. */
const SSH = z.strictObject({
  host: z.string().regex(HOST_RE).max(255).describe(
    "Controller host reached over SSH; every cluster-scope command runs here.",
  ),
  user: z.string().regex(USER_RE).describe("Remote user, typically root."),
  port: z.number().int().min(1).max(65535).default(22).describe("SSH port."),
  host_key_policy: z.enum(["strict"]).describe(
    "strict pins host_keys and refuses a mismatch; this model offers no trust-on-first-use, so keys must be pinned up front.",
  ),
  host_keys: z.array(z.string().max(4096)).min(1).max(64).describe(
    "Pinned host keys in ssh-keyscan format; required.",
  ),
  private_key: z.string().max(32768).meta({ sensitive: true }).describe(
    "PEM private key, delivered to ssh-agent over stdin; never placed on a command line.",
  ),
  connect_timeout_s: z.number().int().min(1).max(120).default(15).describe(
    "SSH connection timeout in seconds.",
  ),
});

/** A caller-named vault key. */
const VaultRefSchema = z.strictObject({
  vault: z.string().regex(/^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$/).describe(
    "Name of an existing swamp vault.",
  ),
  key: z.string().regex(/^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$/).describe(
    "Secret key to write the join token to.",
  ),
});

const ROLE = z.enum(["controller", "worker"]).describe(
  "Role the token joins as; a controller_worker joins as controller.",
);
const TOKEN_ID = z.string().regex(/^[a-z0-9]{6}$/, "not a k0s token id")
  .describe(
    "Public token ID returned by mint_join_token.",
  );
const TOKEN_EXPIRY = z.string().regex(/^\d{1,3}(m|h)$/, "not a Go duration")
  .refine((value) => {
    const minutes = value.endsWith("h")
      ? Number(value.slice(0, -1)) * 60
      : Number(value.slice(0, -1));
    return minutes >= 5 && minutes <= 24 * 60;
  }, "must be between 5m and 24h").describe(
    "Join-token lifetime, bounded 5m to 24h.",
  );

const ClusterArgs = z.strictObject({
  cluster_name: NAME.describe("Cluster name; keys every state record."),
  ssh: SSH,
});
const MintArgs = ClusterArgs.extend({
  role: ROLE,
  token_expiry: TOKEN_EXPIRY.default("1h"),
  token_vault: VaultRefSchema,
});
const InvalidateArgs = ClusterArgs.extend({
  token_id: TOKEN_ID.nullish().describe(
    "Token ID to invalidate; when omitted, the newest live token for token_vault is used.",
  ),
  token_vault: VaultRefSchema,
});
const WaitArgs = ClusterArgs.extend({
  node: z.string().max(253).regex(SUBDOMAIN_RE, "not a DNS-1123 subdomain")
    .describe("Node name to wait for."),
  role: z.enum(["controller", "worker"]).describe("Role it joins as."),
  timeout_s: z.number().int().min(10).max(7200).default(600),
  poll_interval_s: z.number().int().min(1).max(300).default(10),
});
const DrainArgs = ClusterArgs.extend({
  node: z.string().max(253).regex(SUBDOMAIN_RE, "not a DNS-1123 subdomain")
    .describe("Node name to drain."),
  drain_timeout_s: z.number().int().min(30).max(3600).default(300),
});
const UncordonArgs = ClusterArgs.extend({
  node: z.string().max(253).regex(SUBDOMAIN_RE, "not a DNS-1123 subdomain")
    .describe("Node name to uncordon."),
});
const DetachArgs = ClusterArgs.extend({
  node: z.string().max(253).regex(SUBDOMAIN_RE, "not a DNS-1123 subdomain")
    .describe("Node name to detach."),
  peer_address: z.string().max(45).regex(IP_RE, "not an IP address").nullish()
    .describe(
      "The leaving controller's etcd peer address; derived from etcd member-list when omitted.",
    ),
  confirm: z.string().nullish().describe(
    "Must equal the node name to detach an undrained node or a quorum-critical controller.",
  ),
});

const StepSchema = z.strictObject({
  kind: z.string(),
  node: z.string().optional(),
  role: z.string().optional(),
  reason: z.string(),
});

const RecordedNodeSchema = z.strictObject({
  name: z.string(),
  role: z.enum(["controller", "controller_worker", "worker"]),
});

const PlanStateSchema = z.strictObject({
  cluster_name: z.string(),
  operation: z.enum(["create", "add", "remove", "upgrade"]),
  nodes: z.array(RecordedNodeSchema),
  steps: z.array(StepSchema),
  observed_at: z.string(),
});
/** Stored plan of one cluster. */
export type PlanState = z.infer<typeof PlanStateSchema>;

const ClusterNodeViewSchema = z.strictObject({
  name: z.string(),
  role: z.enum(["controller", "worker", "unknown"]),
  ready: z.boolean(),
  cordoned: z.boolean(),
  kubelet_version: z.string().nullable(),
  k0s_version: z.string().nullable(),
});

const EtcdMemberViewSchema = z.strictObject({
  name: z.string(),
  peer_urls: z.array(z.string()),
  client_urls: z.array(z.string()),
});

const StatusSchema = z.strictObject({
  cluster_name: z.string(),
  nodes: z.array(ClusterNodeViewSchema),
  etcd_members: z.array(EtcdMemberViewSchema),
  tokens: z.array(
    z.strictObject({
      id: z.string(),
      role: z.enum(["controller", "worker", "unknown"]),
      expiry: z.string().nullable(),
    }),
  ),
  observed_at: z.string(),
});

const TokensStateSchema = z.strictObject({
  cluster_name: z.string(),
  tokens: z.array(
    z.strictObject({
      token_id: z.string(),
      role: ROLE,
      expires_at: z.string(),
      vault: z.string(),
      key: z.string(),
      invalidated_at: z.string().nullable(),
    }),
  ),
  observed_at: z.string(),
});

/** Overridable dependencies (SSH, clock, sleep) for the methods. */
export interface Deps {
  /** SSH transport; tests replace this to avoid spawning ssh. */
  transport: SshTransport;
  /** Current time. */
  now: () => Date;
  /** Sleep, for polling loops. */
  sleep: (ms: number) => Promise<void>;
}

/** A remote command that must succeed but did not. */
export class ClusterCommandError extends Error {
  /** Creates a typed error naming the failed argv head and exit code. */
  constructor(argv: string[], result: ExecResult) {
    super(
      `k0s command failed on the controller (${
        argv.slice(0, 3).join(" ")
      }, exit ${result.exit_code}): ${
        result.stderr.trim().slice(0, 400) || "no stderr"
      }`,
    );
    this.name = "ClusterCommandError";
  }
}

/** A join token could not be minted safely. */
export class TokenError extends Error {
  /** Creates a typed token error. */
  constructor(message: string) {
    super(message);
    this.name = "TokenError";
  }
}

/** The vault service was unavailable, so a token cannot be stored safely. */
export class VaultUnavailableError extends Error {
  /** Creates a typed vault error. */
  constructor(message: string) {
    super(message);
    this.name = "VaultUnavailableError";
  }
}

/** A node left the cluster only on explicit confirmation. */
export class DetachRefusedError extends Error {
  /** Creates a typed detach refusal. */
  constructor(message: string) {
    super(message);
    this.name = "DetachRefusedError";
  }
}

/** A drain was blocked, most often by a PodDisruptionBudget. */
export class DrainBlockedError extends Error {
  /** Creates a typed drain error. */
  constructor(message: string) {
    super(message);
    this.name = "DrainBlockedError";
  }
}

/** A node did not join within the timeout. */
export class WaitTimeoutError extends Error {
  /** Creates a typed wait error. */
  constructor(message: string) {
    super(message);
    this.name = "WaitTimeoutError";
  }
}

/** The SSH block, narrowed to a transport target. */
function targetOf(ssh: z.infer<typeof SSH>): SshTarget {
  return {
    host: ssh.host,
    port: ssh.port,
    user: ssh.user,
    host_key_policy: ssh.host_key_policy,
    host_keys: ssh.host_keys,
    private_key: ssh.private_key,
    connect_timeout_s: ssh.connect_timeout_s,
  };
}

/** Runs one argv on the controller and throws when it fails. */
async function run(
  deps: Deps,
  target: SshTarget,
  argv: string[],
): Promise<ExecResult> {
  const result = await deps.transport.exec(target, argv);
  if (!ok(result)) throw new ClusterCommandError(argv, result);
  return result;
}

/** Refuses when the vault service is absent, before any token is minted. */
function requireVault(context: Ctx): void {
  if (typeof context.vaultService?.put !== "function") {
    throw new VaultUnavailableError(
      "this swamp version does not expose a vault service to methods; refusing to mint a token that could not be stored safely",
    );
  }
}

/** Writes a value to a vault key; the caller must have checked the service. */
async function vaultPut(
  context: Ctx,
  ref: z.infer<typeof VaultRefSchema>,
  value: string,
): Promise<void> {
  requireVault(context);
  await context.vaultService.put(ref.vault, ref.key, value);
}

/** Adds `duration` (a Go-style minutes/hours string) to a base time. */
function expiresAt(base: Date, duration: string): string {
  return new Date(base.getTime() + durationMinutes(duration) * 60_000)
    .toISOString();
}

/** The host part of the first etcd peer URL. */
function peerHostOf(member: EtcdMember | undefined): string | null {
  const url = member?.peer_urls[0];
  if (!url) return null;
  try {
    return new URL(url).hostname || null;
  } catch {
    return null;
  }
}

/** Builds the model with overridable dependencies. */
export function createModel(deps: Partial<Deps> = {}) {
  const d: Deps = {
    transport: deps.transport ?? createSshTransport(),
    now: deps.now ?? (() => new Date()),
    sleep: deps.sleep ??
      ((ms) => new Promise((resolve) => setTimeout(resolve, ms))),
  };
  const store = async (
    context: Ctx,
    input: PlanInput,
    operation: PlanState["operation"],
    steps: PlanStep[],
  ) => {
    const handle = await context.writeResource("plan", input.cluster_name, {
      cluster_name: input.cluster_name,
      operation,
      nodes: input.nodes.map((n) => ({ name: n.name, role: n.role })),
      steps,
      observed_at: d.now().toISOString(),
    });
    return { dataHandles: [handle] };
  };

  /** Lists tokens per role; k0s refuses a role-less `token list`. */
  const listTokens = async (target: SshTarget): Promise<JoinToken[]> => [
    ...parseJoinTokens(
      (await run(d, target, tokenListArgs("controller"))).stdout,
    ),
    ...parseJoinTokens(
      (await run(d, target, tokenListArgs("worker"))).stdout,
    ),
  ];

  /** Reads the live cluster in one pass. */
  const observe = async (target: SshTarget) => {
    const nodes = parseClusterNodes(
      (await run(d, target, nodeListArgs())).stdout,
    );
    const etcd_members = parseEtcdMembers(
      (await run(d, target, etcdMemberListArgs())).stdout,
    );
    const tokens = await listTokens(target);
    return { nodes, etcd_members, tokens };
  };

  /** Writes the live status record. */
  const writeStatus = async (
    context: Ctx,
    clusterName: string,
    target: SshTarget,
  ) => {
    const live = await observe(target);
    const handle = await context.writeResource(
      "status",
      `${clusterName}-status`,
      {
        cluster_name: clusterName,
        nodes: live.nodes,
        etcd_members: live.etcd_members,
        tokens: live.tokens,
        observed_at: d.now().toISOString(),
      },
    );
    return { handle, live };
  };

  /** Polls until `node` is joined and healthy. */
  const waitJoined = async (
    target: SshTarget,
    clusterName: string,
    nodeName: string,
    role: "controller" | "worker",
    timeoutS: number,
    pollS: number,
  ) => {
    const deadline = d.now().getTime() + timeoutS * 1000;
    for (;;) {
      const nodes = parseClusterNodes(
        (await run(d, target, nodeListArgs())).stdout,
      );
      const observed = nodes.find((n) => n.name === nodeName);
      if (role === "controller") {
        // A dedicated controller may have no Node object; membership is the
        // etcd member list plus the ControlNode, not a Ready Node.
        const members = parseEtcdMembers(
          (await run(d, target, etcdMemberListArgs())).stdout,
        );
        const controlNodes = parseItemNames(
          (await run(d, target, controlNodeListArgs())).stdout,
        );
        if (
          members.some((m) => m.name === nodeName) &&
          controlNodes.includes(nodeName)
        ) {
          return {
            joined: true,
            ready: observed?.ready ?? true,
            roles: "controller" as const,
            kubelet_version: observed?.kubelet_version ?? null,
          };
        }
      } else if (observed?.ready === true) {
        return {
          joined: true,
          ready: true,
          roles: observed.role,
          kubelet_version: observed.kubelet_version,
        };
      }
      if (d.now().getTime() >= deadline) {
        throw new WaitTimeoutError(
          `${nodeName} did not join cluster ${clusterName} as ${role} within ${timeoutS}s`,
        );
      }
      await d.sleep(pollS * 1000);
    }
  };

  return {
    type: "@randybias/k0s-multinode",
    version: "2026.10.17.1",
    description:
      "Plan and operate a multi-node k0s cluster over SSH in the k0sctl style: a short-lived join token per node written to a vault key, ordered controller and worker joins, drain/detach before reset, and safe rolling upgrades. Per-node install, reset and upgrade are delegated to @randybias/k0s-cluster; no join token value ever appears in state or output.",
    upgrades: [],
    globalArguments: GlobalArgsSchema,
    resources: {
      plan: {
        description: "Ordered step list for one cluster operation",
        schema: PlanStateSchema,
        lifetime: "infinite" as const,
        garbageCollection: 10,
      },
      status: {
        description: "Last observed cluster membership",
        schema: StatusSchema,
        lifetime: "infinite" as const,
        garbageCollection: 10,
      },
      tokens: {
        description: "Outstanding join tokens; IDs, roles and expiry only",
        schema: TokensStateSchema,
        lifetime: "infinite" as const,
        garbageCollection: 10,
      },
    },
    methods: {
      plan: {
        description:
          "READ-ONLY. Return the ordered step list for creating, adding to, or upgrading the cluster, enforcing the ordering invariants; the same inputs give the same list. Tokens are never minted here.",
        arguments: PlanInputSchema,
        execute: async (
          args: z.input<typeof PlanInputSchema>,
          context: Ctx,
        ) => {
          const input = PlanInputSchema.parse(args);
          return await store(
            context,
            input,
            inferOperation(input),
            plan(input),
          );
        },
      },
      plan_remove: {
        description:
          "READ-ONLY. Return the drain -> detach -> reset step list for removing one node, refusing a detach that would lose etcd quorum without confirm.",
        arguments: PlanInputSchema.extend({
          node: z.string().describe("Name of the node to remove."),
        }),
        execute: async (
          args: z.input<typeof PlanInputSchema> & { node: string },
          context: Ctx,
        ) => {
          const parsed = PlanInputSchema.extend({
            node: z.string().regex(SUBDOMAIN_RE, "not a DNS-1123 subdomain"),
          }).parse(args);
          const { node, ...rest } = parsed;
          const input = PlanInputSchema.parse(rest);
          return await store(context, input, "remove", planRemove(input, node));
        },
      },
      mint_join_token: {
        kind: "action" as const,
        description:
          "On a controller, mint a short-lived join token, write it to a caller-named vault key and return only its ID, role and expiry. Refuses to proceed without a vault service, so the token never falls back into the output.",
        arguments: MintArgs,
        execute: async (args: z.input<typeof MintArgs>, context: Ctx) => {
          const parsed = MintArgs.parse(args);
          requireVault(context);
          const target = targetOf(parsed.ssh);
          const before = parseJoinTokens(
            (await run(d, target, tokenListArgs(parsed.role))).stdout,
          );
          const created = await run(
            d,
            target,
            tokenCreateArgs(parsed.role, parsed.token_expiry),
          );
          const token = created.stdout.trim();
          const tokenId = await joinTokenIdFromCreate(token);
          if (!tokenId) {
            throw new TokenError(
              "k0s token create did not return a kubeconfig carrying a token; nothing was stored",
            );
          }
          // Corroborate the minted id with the token list; never trust the
          // raw payload text, and invalidate on any doubt.
          let after: JoinToken[];
          try {
            after = parseJoinTokens(
              (await run(d, target, tokenListArgs(parsed.role))).stdout,
            );
          } catch (error) {
            await d.transport.exec(target, tokenInvalidateArgs(tokenId));
            throw error;
          }
          const fresh = newTokenIds(before, after);
          if (fresh.length > 0 && !fresh.includes(tokenId)) {
            await d.transport.exec(target, tokenInvalidateArgs(tokenId));
            throw new TokenError(
              "k0s token list did not corroborate the minted token; invalidated it",
            );
          }
          try {
            await vaultPut(context, parsed.token_vault, token);
          } catch (error) {
            await d.transport.exec(target, tokenInvalidateArgs(tokenId));
            throw error;
          }
          const expires_at =
            after.find((entry) => entry.id === tokenId)?.expiry ??
              expiresAt(d.now(), parsed.token_expiry);
          const record = await context.readResource(
            `${parsed.cluster_name}-tokens`,
          );
          const existing: unknown[] = Array.isArray(record?.tokens)
            ? record.tokens
            : [];
          const handle = await context.writeResource(
            "tokens",
            `${parsed.cluster_name}-tokens`,
            {
              cluster_name: parsed.cluster_name,
              tokens: [
                ...existing,
                {
                  token_id: tokenId,
                  role: parsed.role,
                  expires_at,
                  vault: parsed.token_vault.vault,
                  key: parsed.token_vault.key,
                  invalidated_at: null,
                },
              ],
              observed_at: d.now().toISOString(),
            },
          );
          context.logger.info(
            "Minted a {role} join token {id} for {cluster}, expiring {expires}",
            {
              role: parsed.role,
              id: tokenId,
              cluster: parsed.cluster_name,
              expires: expires_at,
            },
          );
          return {
            dataHandles: [handle],
            result: {
              token_id: tokenId,
              role: parsed.role,
              expires_at,
              vault: parsed.token_vault,
            },
          };
        },
      },
      invalidate_join_token: {
        kind: "action" as const,
        description:
          "Invalidate a join token by ID and overwrite its vault key with a non-secret tombstone. Idempotent: an unknown or already-expired ID is a no-op on the cluster side.",
        arguments: InvalidateArgs,
        execute: async (args: z.input<typeof InvalidateArgs>, context: Ctx) => {
          const parsed = InvalidateArgs.parse(args);
          const record = await context.readResource(
            `${parsed.cluster_name}-tokens`,
          );
          const stored: {
            token_id: string;
            vault: string;
            key: string;
            invalidated_at: string | null;
          }[] = Array.isArray(record?.tokens) ? record.tokens : [];
          const ids = parsed.token_id
            ? [parsed.token_id]
            : stored.filter((entry) =>
              entry.vault === parsed.token_vault.vault &&
              entry.key === parsed.token_vault.key &&
              entry.invalidated_at === null
            ).map((entry) => entry.token_id);
          if (ids.length === 0) {
            return {
              dataHandles: [],
              result: {
                token_id: null,
                invalidated: false,
                vault: parsed.token_vault,
              },
            };
          }
          for (const id of ids) {
            await run(d, parsed.ssh, tokenInvalidateArgs(id));
          }
          const invalidated = true;
          await vaultPut(context, parsed.token_vault, TOKEN_TOMBSTONE);
          const done = new Set(ids);
          const tokens = stored.map((entry) =>
            done.has(entry.token_id)
              ? { ...entry, invalidated_at: d.now().toISOString() }
              : entry
          );
          const handle = await context.writeResource(
            "tokens",
            `${parsed.cluster_name}-tokens`,
            {
              cluster_name: parsed.cluster_name,
              tokens,
              observed_at: d.now().toISOString(),
            },
          );
          return {
            dataHandles: [handle],
            result: {
              token_id: ids[0],
              invalidated,
              vault: parsed.token_vault,
            },
          };
        },
      },
      wait_joined: {
        description:
          "READ-ONLY. Poll a controller until the named node is Ready (worker) or is an etcd member with a ControlNode (controller).",
        arguments: WaitArgs,
        execute: async (args: z.input<typeof WaitArgs>, _context: Ctx) => {
          const parsed = WaitArgs.parse(args);
          return {
            dataHandles: [],
            result: await waitJoined(
              targetOf(parsed.ssh),
              parsed.cluster_name,
              parsed.node,
              parsed.role,
              parsed.timeout_s,
              parsed.poll_interval_s,
            ),
          };
        },
      },
      drain_node: {
        kind: "action" as const,
        description:
          "Cordon and drain a node, honoring PodDisruptionBudgets (never --disable-eviction). Idempotent. A budget block is a typed error and the node stays cordoned.",
        arguments: DrainArgs,
        execute: async (args: z.input<typeof DrainArgs>, _context: Ctx) => {
          const parsed = DrainArgs.parse(args);
          const target = targetOf(parsed.ssh);
          const before = parseItemNames(
            (await run(d, target, nodePodListArgs(parsed.node))).stdout,
          ).length;
          await run(d, target, cordonArgs(parsed.node));
          const argv = drainArgs(parsed.node, parsed.drain_timeout_s);
          const drain = await d.transport.exec(target, argv);
          if (!ok(drain)) {
            const text = `${drain.stderr}\n${drain.stdout}`;
            if (/PodDisruptionBudget|disruption budget/i.test(text)) {
              throw new DrainBlockedError(
                `${parsed.node} is blocked by a PodDisruptionBudget; it stays cordoned and nothing was evicted forcibly`,
              );
            }
            throw new ClusterCommandError(argv, drain);
          }
          const remaining = parseItemNames(
            (await run(d, target, nodePodListArgs(parsed.node))).stdout,
          ).length;
          return {
            dataHandles: [],
            result: {
              node: parsed.node,
              evicted: Math.max(before - remaining, 0),
              remaining_pods: remaining,
            },
          };
        },
      },
      uncordon_node: {
        kind: "action" as const,
        description: "Uncordon a node, returning it to service. Idempotent.",
        arguments: UncordonArgs,
        execute: async (args: z.input<typeof UncordonArgs>, _context: Ctx) => {
          const parsed = UncordonArgs.parse(args);
          await run(d, targetOf(parsed.ssh), uncordonArgs(parsed.node));
          return {
            dataHandles: [],
            result: { node: parsed.node, cordoned: false },
          };
        },
      },
      detach_node: {
        kind: "action" as const,
        description:
          "DESTRUCTIVE. Remove a drained node from the cluster: for a controller an etcd leave plus ControlNode delete, for a worker a Node delete. Refuses an undrained node or a controller removal that would lose etcd quorum unless confirm is the node name. Does not touch the host.",
        arguments: DetachArgs,
        execute: async (args: z.input<typeof DetachArgs>, _context: Ctx) => {
          const parsed = DetachArgs.parse(args);
          const target = targetOf(parsed.ssh);
          const nodes = parseClusterNodes(
            (await run(d, target, nodeListArgs())).stdout,
          );
          const node = nodes.find((n) => n.name === parsed.node);
          const members = parseEtcdMembers(
            (await run(d, target, etcdMemberListArgs())).stdout,
          );
          const controlNodes = parseItemNames(
            (await run(d, target, controlNodeListArgs())).stdout,
          );
          const member = members.find((m) => m.name === parsed.node);
          // Controller-ness comes from the cluster (etcd membership and the
          // ControlNode), not the Node label: a dedicated controller has no
          // Node object at all.
          const isController = member !== undefined ||
            controlNodes.includes(parsed.node);
          if (member !== undefined && node?.role === "worker") {
            throw new DetachRefusedError(
              `${parsed.node} is an etcd member but is labelled a worker; refusing`,
            );
          }
          if (!node && !isController) {
            return {
              dataHandles: [],
              result: { node: parsed.node, detached: false },
            };
          }
          if (parsed.confirm !== parsed.node) {
            if (node && !node.cordoned) {
              throw new DetachRefusedError(
                `${parsed.node} is not drained; set confirm to ${parsed.node} to detach it anyway`,
              );
            }
            let schedulable = false;
            try {
              schedulable = hasNonDaemonSetPods(
                (await run(d, target, nodePodListArgs(parsed.node))).stdout,
              );
            } catch {
              schedulable = true;
            }
            if (schedulable) {
              throw new DetachRefusedError(
                `${parsed.node} still has schedulable pods; drain it or set confirm to ${parsed.node}`,
              );
            }
          }
          let etcdLeft = false;
          if (isController) {
            if (members.length <= 1) {
              throw new DetachRefusedError(
                "cannot remove the last controller; use reset-cluster",
              );
            }
            if (members.length <= 3 && parsed.confirm !== parsed.node) {
              throw new DetachRefusedError(
                `removing controller ${parsed.node} would leave ${
                  members.length - 1
                } etcd members; set confirm to ${parsed.node}`,
              );
            }
            if (member !== undefined) {
              const memberPeer = peerHostOf(member);
              if (
                parsed.peer_address && memberPeer &&
                parsed.peer_address !== memberPeer
              ) {
                throw new DetachRefusedError(
                  `peer_address ${parsed.peer_address} is not ${parsed.node}'s etcd peer`,
                );
              }
              const peer = parsed.peer_address ?? memberPeer;
              if (!peer) {
                throw new DetachRefusedError(
                  `cannot find the etcd peer address for ${parsed.node}; pass peer_address`,
                );
              }
              if (peer === target.host) {
                throw new DetachRefusedError(
                  `refusing to detach ${parsed.node} through its own host ${target.host}; run through a surviving controller`,
                );
              }
              await run(d, target, etcdLeaveArgs(peer));
              etcdLeft = true;
            }
            await run(d, target, deleteControlNodeArgs(parsed.node));
          }
          await run(d, target, deleteNodeArgs(parsed.node));
          return {
            dataHandles: [],
            result: {
              node: parsed.node,
              detached: true,
              etcd_left: etcdLeft,
            },
          };
        },
      },
      get: {
        description:
          "READ-ONLY. Report nodes (role, Ready, cordoned, kubelet and k0s version), etcd members and outstanding join tokens; refreshes the stored status record. No token value is returned.",
        arguments: ClusterArgs,
        execute: async (args: z.input<typeof ClusterArgs>, context: Ctx) => {
          const parsed = ClusterArgs.parse(args);
          const { handle, live } = await writeStatus(
            context,
            parsed.cluster_name,
            targetOf(parsed.ssh),
          );
          return {
            dataHandles: [handle],
            result: {
              cluster_name: parsed.cluster_name,
              nodes: live.nodes,
              etcd_members: live.etcd_members,
              tokens: live.tokens.map((token) => ({
                id: token.id,
                role: token.role,
                expiry: token.expiry,
              })),
            },
          };
        },
      },
      sync: {
        description:
          "READ-ONLY. Reconcile the recorded membership with the live cluster and flag drift (unknown nodes, lost nodes or members, role changes); refreshes the stored status record.",
        arguments: ClusterArgs,
        execute: async (args: z.input<typeof ClusterArgs>, context: Ctx) => {
          const parsed = ClusterArgs.parse(args);
          const { handle, live } = await writeStatus(
            context,
            parsed.cluster_name,
            targetOf(parsed.ssh),
          );
          const recorded = await context.readResource(parsed.cluster_name);
          const diffs: string[] = [];
          if (!recorded) {
            diffs.push("no recorded plan; run plan first");
          } else {
            const recordedNodes: NodeSpec[] = Array.isArray(recorded.nodes)
              ? recorded.nodes as NodeSpec[]
              : [];
            const recordedNames = new Set(recordedNodes.map((n) => n.name));
            const liveNames = new Set(live.nodes.map((n) => n.name));
            for (const n of live.nodes) {
              if (!recordedNames.has(n.name)) {
                diffs.push(`unknown node ${n.name} is in the cluster`);
              }
            }
            const memberNames = new Set(
              live.etcd_members.map((m) => m.name),
            );
            for (const n of recordedNodes) {
              if (n.role === "worker") {
                if (!liveNames.has(n.name)) {
                  diffs.push(`recorded worker ${n.name} is missing`);
                }
                continue;
              }
              // A dedicated controller has no Node object; membership is the
              // etcd member list.
              if (!memberNames.has(n.name)) {
                diffs.push(
                  `recorded controller ${n.name} is not an etcd member`,
                );
              }
            }
          }
          return {
            dataHandles: [handle],
            result: {
              cluster_name: parsed.cluster_name,
              in_sync: diffs.length === 0,
              diffs,
            },
          };
        },
      },
    },
  };
}

/** Model definition for `@randybias/k0s-multinode`. */
export const model = createModel();
