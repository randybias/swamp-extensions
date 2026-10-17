/**
 * Pure cluster-scope planning for `@randybias/k0s-multinode`.
 *
 * Given a desired topology and an optional observed membership, `plan` returns
 * the ordered step list for create / add / remove / upgrade. It is
 * deterministic and enforces the ordering invariants in the spec:
 *
 * 1. the first controller is up and Ready before any token is minted;
 * 2. an HA endpoint is configured before tokens are minted (tokens embed the
 *    API address);
 * 3. controllers join one at a time;
 * 4. upgrades go controller by controller, then workers (drain -> upgrade ->
 *    Ready -> uncordon), one Kubernetes minor at a time;
 * 5. removal drains, detaches, then resets, and refuses a detach that would
 *    lose etcd quorum without `confirm`;
 * 6. every mint is paired with an invalidate.
 *
 * No I/O, no clock, no token value.
 *
 * @module
 */

import { z } from "npm:zod@4.3.6";

/** DNS-1123 label (cluster and namespace names). */
export const LABEL_RE = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
/** DNS-1123 subdomain (node names). */
export const SUBDOMAIN_RE = /^[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?$/;
const HOST_RE =
  /^(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$|^[0-9a-fA-F:.]{2,45}$/;
const VERSION_RE = /^v?\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$/;
const DURATION_RE = /^\d{1,3}(m|h)$/;
export const IP_RE = /^(?:(?:\d{1,3}\.){3}\d{1,3}|[0-9a-fA-F:]{2,45})$/;

/** A node as the caller describes it. */
const NodeSpecSchema = z.strictObject({
  name: z.string().regex(SUBDOMAIN_RE, "not a DNS-1123 subdomain").describe(
    "Node name, e.g. ctrl-1.",
  ),
  ssh_host: z.string().regex(HOST_RE, "not a host or IP").describe(
    "SSH host or IP for this node.",
  ),
  role: z.enum(["controller", "controller_worker", "worker"]).describe(
    "Node role.",
  ),
  private_address: z.string().regex(IP_RE, "not an IP address").describe(
    "Node's private or mesh address used for peer traffic.",
  ),
});

/** An observed node from `get`/`sync`, compared against the desired set. */
const ObservedNodeSchema = z.strictObject({
  name: z.string(),
  role: z.enum(["controller", "worker"]).nullable(),
  ready: z.boolean(),
});

/** The desired cluster and, optionally, what the cluster currently has. */
export const PlanInputSchema = z.strictObject({
  cluster_name: z.string().regex(LABEL_RE, "not a DNS-1123 label"),
  nodes: z.array(NodeSpecSchema).min(1).max(50),
  k0s_version: z.string().regex(VERSION_RE, "not a k0s version"),
  target_version: z.string().regex(VERSION_RE, "not a k0s version")
    .nullish(),
  ha_mode: z.enum(["none", "external_lb", "cplb_vip", "node_local_lb"]).default(
    "none",
  ),
  external_address: z.string().max(253).nullish(),
  observed: z.array(ObservedNodeSchema).default([]),
  allow_even_controllers: z.boolean().default(false),
  token_expiry: z.string().regex(DURATION_RE, "not a Go duration").default(
    "1h",
  ),
  confirm: z.string().nullish(),
});
/** Minutes in a k0s Go duration string such as `5m` or `2h`. */
export function durationMinutes(value: string): number {
  return value.endsWith("h")
    ? Number(value.slice(0, -1)) * 60
    : Number(value.slice(0, -1));
}

/** Validated plan input. */
export type PlanInput = z.infer<typeof PlanInputSchema>;
/** One desired node. */
export type NodeSpec = z.infer<typeof NodeSpecSchema>;

/** A step in a plan; `kind` names the operation the workflow performs. */
export interface PlanStep {
  /** Operation. */
  kind:
    | "install_first_controller"
    | "install_with_token"
    | "mint_token"
    | "invalidate_token"
    | "wait_joined"
    | "drain"
    | "detach"
    | "reset"
    | "upgrade"
    | "uncordon";
  /** Node the step acts on, when it is node-scoped. */
  node?: string;
  /** Role a token is minted for. */
  role?: "controller" | "worker";
  /** Human-readable reason, for receipts. */
  reason: string;
}

/** A plan that cannot be built from the inputs. */
export class PlanError extends Error {
  /** Creates a typed plan error. */
  constructor(message: string) {
    super(message);
    this.name = "PlanError";
  }
}

/** The operation a plan describes. */
type PlanOperation = "create" | "add" | "remove" | "upgrade";

/** The token role a node joins as (a controller_worker is a controller). */
function tokenRole(node: NodeSpec): "controller" | "worker" {
  return node.role === "worker" ? "worker" : "controller";
}

/** The mint -> install -> wait -> invalidate sequence that joins one node. */
function joinSteps(fromController: string, node: NodeSpec): PlanStep[] {
  const role = tokenRole(node);
  return [
    {
      kind: "mint_token",
      node: fromController,
      role,
      reason: `mint a ${role} token for ${node.name} from ${fromController}`,
    },
    {
      kind: "install_with_token",
      node: node.name,
      role,
      reason: `join ${node.name} as ${node.role}`,
    },
    {
      kind: "wait_joined",
      node: node.name,
      reason: `${node.name} must be Ready before the next node joins`,
    },
    {
      kind: "invalidate_token",
      node: fromController,
      role,
      reason: `invalidate the token used by ${node.name}`,
    },
  ];
}

/** Infers the operation; `plan` has no explicit selector input. */
export function inferOperation(input: PlanInput): PlanOperation {
  if (input.target_version) return "upgrade";
  return input.observed.length > 0 ? "add" : "create";
}

function minorOf(version: string): number {
  const m = /^v?(\d+)\.(\d+)\./.exec(version);
  if (!m) throw new PlanError(`cannot read a Kubernetes minor from ${version}`);
  return Number(m[1]) * 1000 + Number(m[2]);
}

function assertTopology(input: PlanInput): NodeSpec[] {
  const names = new Set<string>();
  const addrs = new Set<string>();
  for (const n of input.nodes) {
    if (names.has(n.name)) throw new PlanError(`duplicate node name ${n.name}`);
    if (addrs.has(n.private_address)) {
      throw new PlanError(`duplicate private address ${n.private_address}`);
    }
    names.add(n.name);
    addrs.add(n.private_address);
  }
  const controllers = input.nodes.filter((n) => n.role !== "worker").length;
  if (controllers < 1) {
    throw new PlanError("a cluster needs at least one controller");
  }
  if (
    controllers > 1 && controllers % 2 === 0 && !input.allow_even_controllers
  ) {
    throw new PlanError(
      `${controllers} controllers is an even count; set allow_even_controllers to accept a non-quorate cluster`,
    );
  }
  if (controllers > 1 && input.ha_mode === "none" && !input.external_address) {
    throw new PlanError(
      "more than one controller needs an HA endpoint (ha_mode or external_address) before tokens are minted",
    );
  }
  if (
    (input.ha_mode === "external_lb" || input.ha_mode === "cplb_vip") &&
    !input.external_address
  ) {
    throw new PlanError(
      `${input.ha_mode} requires external_address before tokens are minted`,
    );
  }
  return input.nodes;
}

function byRoleOrder(nodes: NodeSpec[]): NodeSpec[] {
  const rank = { controller: 0, controller_worker: 1, worker: 2 } as const;
  return [...nodes].sort((a, b) => rank[a.role] - rank[b.role]);
}

/** Builds the ordered steps for a cluster that does not exist yet. */
function createPlan(nodes: NodeSpec[]): PlanStep[] {
  const [first, ...rest] = byRoleOrder(nodes);
  if (!first) throw new PlanError("no nodes");
  return [
    {
      kind: "install_first_controller",
      node: first.name,
      reason: `first ${first.role} ${first.name} up before any token is minted`,
    },
    {
      kind: "wait_joined",
      node: first.name,
      reason: "the first controller must be Ready before the next node joins",
    },
    ...rest.flatMap((n) => joinSteps(first.name, n)),
  ];
}

/** Builds add-node steps for nodes observed to be absent. */
function addPlan(input: PlanInput, nodes: NodeSpec[]): PlanStep[] {
  const present = new Set(input.observed.map((o) => o.name));
  const missing = nodes.filter((n) => !present.has(n.name));
  if (missing.length === 0) {
    return [{
      kind: "wait_joined",
      reason: "every desired node is already present",
    }];
  }
  const controller =
    input.observed.find((o) => o.role === "controller")?.name ??
      nodes.find((n) => n.role !== "worker")?.name;
  if (!controller) throw new PlanError("no controller to mint from");
  return byRoleOrder(missing).flatMap((n) => joinSteps(controller, n));
}

/** Builds remove-node steps: drain, detach, reset. */
function removePlan(input: PlanInput, node: NodeSpec): PlanStep[] {
  const controllers =
    input.observed.filter((o) => o.role === "controller").length ||
    input.nodes.filter((n) => n.role !== "worker").length;
  if (node.role !== "worker") {
    if (controllers <= 1) {
      throw new PlanError(
        "cannot remove the last controller; use reset-cluster",
      );
    }
    if (controllers <= 3 && input.confirm !== node.name) {
      throw new PlanError(
        `removing controller ${node.name} would leave ${
          controllers - 1
        } etcd members and lose quorum; set confirm to the node name`,
      );
    }
  }
  return [
    {
      kind: "drain",
      node: node.name,
      reason: `drain ${node.name} before detaching`,
    },
    {
      kind: "detach",
      node: node.name,
      reason: `remove ${node.name} from the cluster`,
    },
    { kind: "reset", node: node.name, reason: `reset k0s on ${node.name}` },
  ];
}

/** Builds upgrade steps: controllers one at a time, then workers. */
function upgradePlan(input: PlanInput, nodes: NodeSpec[]): PlanStep[] {
  const from = input.k0s_version;
  const to = input.target_version;
  if (!to) throw new PlanError("upgrade needs target_version");
  const diff = minorOf(to) - minorOf(from);
  if (diff < 0) throw new PlanError(`refusing downgrade ${from} -> ${to}`);
  if (diff > 1) {
    throw new PlanError(
      `refusing to skip Kubernetes minors: ${from} -> ${to}`,
    );
  }
  const controllers = nodes.filter((n) => n.role !== "worker");
  const workers = nodes.filter((n) => n.role === "worker");
  const steps: PlanStep[] = [];
  for (const n of byRoleOrder(controllers)) {
    steps.push(
      {
        kind: "upgrade",
        node: n.name,
        reason: `upgrade controller ${n.name} to ${to}`,
      },
      {
        kind: "wait_joined",
        node: n.name,
        reason: `${n.name} healthy before the next controller`,
      },
    );
  }
  for (const n of byRoleOrder(workers)) {
    steps.push(
      { kind: "drain", node: n.name, reason: `drain worker ${n.name}` },
      {
        kind: "upgrade",
        node: n.name,
        reason: `upgrade worker ${n.name} to ${to}`,
      },
      {
        kind: "wait_joined",
        node: n.name,
        reason: `worker ${n.name} Ready after upgrade`,
      },
      { kind: "uncordon", node: n.name, reason: `return ${n.name} to service` },
    );
  }
  return steps;
}

/**
 * Returns the ordered step list for the requested operation. `operation` is
 * inferred when not given: no observed nodes means create; a `remove` node
 * means remove; a `target_version` means upgrade; otherwise add.
 */
export function plan(raw: z.input<typeof PlanInputSchema>): PlanStep[] {
  const input = PlanInputSchema.parse(raw);
  const nodes = assertTopology(input);
  switch (inferOperation(input)) {
    case "upgrade":
      return upgradePlan(input, nodes);
    case "add":
      return addPlan(input, nodes);
    default:
      return createPlan(nodes);
  }
}

/** Plans the removal of one node (drain -> detach -> reset). */
export function planRemove(
  raw: z.input<typeof PlanInputSchema>,
  nodeName: string,
): PlanStep[] {
  const input = PlanInputSchema.parse(raw);
  assertTopology(input);
  const node = input.nodes.find((n) => n.name === nodeName);
  if (!node) throw new PlanError(`unknown node ${nodeName}`);
  return removePlan(input, node);
}
