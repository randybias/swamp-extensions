/**
 * Cluster-scope k0s observations and command builders for `@randybias/k0s-multinode`.
 *
 * Everything here is pure: it builds argv (never a token value) and parses
 * sanitized command output. The cluster is read through a controller with
 * `k0s kubectl`, `k0s etcd` and `k0s token`, so no kubeconfig is needed.
 *
 * @module
 */

import type { ExecResult } from "./ssh.ts";

/** True when a remote command succeeded. */
export function ok(result: ExecResult): boolean {
  return result.exit_code === 0;
}

/** A node as the cluster reports it. */
export interface ClusterNode {
  /** Node name. */
  name: string;
  /** Role derived from the k0s role label. */
  role: "controller" | "worker" | "unknown";
  /** Whether the `Ready` condition is `True`. */
  ready: boolean;
  /** Whether the node is cordoned (`spec.unschedulable`). */
  cordoned: boolean;
  /** Kubelet version, e.g. `v1.31.2`. */
  kubelet_version: string | null;
  /** k0s version from the k0s node label, when present. */
  k0s_version: string | null;
}

/** One etcd cluster member. */
export interface EtcdMember {
  /** Member name (the control node name). */
  name: string;
  /** Peer URLs. */
  peer_urls: string[];
  /** Client URLs. */
  client_urls: string[];
}

/** One outstanding join token, as `k0s token list` reports it. */
export interface JoinToken {
  /** Public token ID (the part before the dot). */
  id: string;
  /** Role the token joins as. */
  role: "controller" | "worker" | "unknown";
  /** Expiry string as reported, e.g. an RFC 3339 timestamp. */
  expiry: string | null;
}

/** Fixed non-secret value that replaces a spent token in its vault key. */
export const TOKEN_TOMBSTONE = "invalidated-k0s-multinode";

/** `kubectl get nodes -o json`. */
export function nodeListArgs(): string[] {
  return ["k0s", "kubectl", "get", "nodes", "-o", "json"];
}

/** `k0s etcd member-list` (JSON encoded). */
export function etcdMemberListArgs(): string[] {
  return ["k0s", "etcd", "member-list"];
}

/** `k0s token list`, optionally filtered by role. */
export function tokenListArgs(
  role?: "controller" | "worker" | "unknown",
): string[] {
  return role === "controller" || role === "worker"
    ? ["k0s", "token", "list", "--role", role]
    : ["k0s", "token", "list"];
}

/** `k0s token create --role <role> --expiry <expiry>`. */
export function tokenCreateArgs(
  role: "controller" | "worker",
  expiry: string,
): string[] {
  return ["k0s", "token", "create", "--role", role, "--expiry", expiry];
}

/** `k0s token invalidate <id>`, idempotent with `--ignore-not-found`. */
export function tokenInvalidateArgs(id: string): string[] {
  return ["k0s", "token", "invalidate", id];
}

/** `k0s kubectl cordon <node>`. */
export function cordonArgs(node: string): string[] {
  return ["k0s", "kubectl", "cordon", node];
}

/** `k0s kubectl uncordon <node>`. */
export function uncordonArgs(node: string): string[] {
  return ["k0s", "kubectl", "uncordon", node];
}

/** `k0s kubectl drain`, evicting with the disruption budget respected. */
export function drainArgs(node: string, timeoutS: number): string[] {
  return [
    "k0s",
    "kubectl",
    "drain",
    node,
    "--ignore-daemonsets",
    "--delete-emptydir-data",
    `--timeout=${timeoutS}s`,
  ];
}

/** `k0s kubectl delete node <node>`, tolerant of an absent node. */
export function deleteNodeArgs(node: string): string[] {
  return ["k0s", "kubectl", "delete", "node", node, "--ignore-not-found"];
}

/** `k0s kubectl delete controlnode <name>`, tolerant of an absent one. */
export function deleteControlNodeArgs(name: string): string[] {
  return [
    "k0s",
    "kubectl",
    "delete",
    "controlnode",
    name,
    "--ignore-not-found",
  ];
}

/** `k0s etcd leave --peer-address <address>`; runs on a surviving controller. */
export function etcdLeaveArgs(peerAddress: string): string[] {
  return ["k0s", "etcd", "leave", "--peer-address", peerAddress];
}

/** `k0s kubectl get controlnodes -o json`. */
export function controlNodeListArgs(): string[] {
  return ["k0s", "kubectl", "get", "controlnodes", "-o", "json"];
}

/** `k0s kubectl get pods` on one node, across namespaces. */
export function nodePodListArgs(node: string): string[] {
  return [
    "k0s",
    "kubectl",
    "get",
    "pods",
    "--all-namespaces",
    "--field-selector",
    `spec.nodeName=${node}`,
    "-o",
    "json",
  ];
}

function isPlain(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function parseJson(text: string): unknown {
  try {
    return JSON.parse(text);
  } catch {
    return null;
  }
}

function stringOf(value: unknown): string {
  return typeof value === "string" ? value : "";
}

function labelOf(
  meta: Record<string, unknown> | undefined,
  key: string,
): string {
  const labels = meta?.labels;
  if (!isPlain(labels)) return "";
  return stringOf(labels[key]);
}

/** True when the label key is present, even with an empty value. */
function hasLabel(
  meta: Record<string, unknown> | undefined,
  key: string,
): boolean {
  const labels = meta?.labels;
  return isPlain(labels) && key in labels;
}

/** Role from the k0s role label, with a control-plane label fallback. */
function roleOf(
  meta: Record<string, unknown> | undefined,
): ClusterNode["role"] {
  const labelled = labelOf(meta, "node.k0sproject.io/role");
  if (labelled === "control-plane") return "controller";
  if (labelled === "worker") return "worker";
  if (hasLabel(meta, "node-role.kubernetes.io/control-plane")) {
    return "controller";
  }
  if (hasLabel(meta, "node-role.kubernetes.io/master")) {
    return "controller";
  }
  return "unknown";
}

/** Parses `kubectl get nodes -o json`; returns `[]` for unusable input. */
export function parseClusterNodes(text: string): ClusterNode[] {
  const parsed = parseJson(text);
  if (!isPlain(parsed) || !Array.isArray(parsed.items)) return [];
  return parsed.items.filter(isPlain).map((item) => {
    const meta = isPlain(item.metadata) ? item.metadata : undefined;
    const spec = isPlain(item.spec) ? item.spec : undefined;
    const status = isPlain(item.status) ? item.status : undefined;
    const info = isPlain(status?.nodeInfo) ? status.nodeInfo : undefined;
    const conditions = Array.isArray(status?.conditions)
      ? status.conditions.filter(isPlain)
      : [];
    return {
      name: stringOf(meta?.name),
      role: roleOf(meta),
      ready: conditions.some((c) => c.type === "Ready" && c.status === "True"),
      cordoned: spec?.unschedulable === true,
      kubelet_version: stringOf(info?.kubeletVersion) || null,
      k0s_version: labelOf(meta, "node.k0sproject.io/version") || null,
    };
  }).filter((node) => node.name !== "");
}

/**
 * Parses `k0s etcd member-list`. The command emits JSON; the members may be a
 * map keyed by name or an array. Shape variants are tolerated because the exact
 * envelope has changed between k0s releases.
 */
export function parseEtcdMembers(text: string): EtcdMember[] {
  const parsed = parseJson(text);
  const members = isPlain(parsed) && isPlain(parsed.members)
    ? parsed.members
    : parsed;
  if (!isPlain(members)) return [];
  // Real v1.36 output maps each member name to its peer URL string.
  return Object.entries(members)
    .filter(([, value]) => typeof value === "string")
    .map(([name, value]) => ({
      name,
      peer_urls: [value as string],
      client_urls: [],
    }))
    .filter((member) => member.name !== "");
}

/** A token ID is the part before the first dot, if a dotted token string. */
function tokenIdFromField(field: string): string {
  const dot = field.indexOf(".");
  return dot > 0 ? field.slice(0, dot) : field;
}

/** Role from a free-form `token list` role column. */
function tokenRoleOf(value: string): JoinToken["role"] {
  const role = value.trim().toLowerCase();
  if (role === "controller" || role.startsWith("control")) return "controller";
  if (role === "worker") return "worker";
  return "unknown";
}

/**
 * Parses `k0s token list`. Accepts a JSON array/map of token objects or the
 * tab/space separated table k0s prints, skipping the header row.
 */
export function parseJoinTokens(text: string): JoinToken[] {
  const tokens: JoinToken[] = [];
  for (const raw of text.split("\n")) {
    const line = raw.trim();
    if (line === "") continue;
    const fields = line.split(/\s+/);
    const id = tokenIdFromField(fields[0]);
    // Only a bare 6-character token id; the header and any JSON/token text
    // (which could carry a secret) are rejected.
    if (!TOKEN_ID_RE.test(id)) continue;
    tokens.push({
      id,
      role: tokenRoleOf(fields[1] ?? ""),
      expiry: fields[2] ?? null,
    });
  }
  return tokens;
}

/** Token IDs in `after` that were not in `before`. */
export function newTokenIds(
  before: JoinToken[],
  after: JoinToken[],
): string[] {
  const seen = new Set(before.map((token) => token.id));
  return after.map((token) => token.id).filter((id) => !seen.has(id));
}

/**
 * True when a pod list has a pod that is neither a mirror pod nor owned by a
 * DaemonSet, so a cordoned node is not yet fully drained.
 */
export function hasNonDaemonSetPods(text: string): boolean {
  const parsed = parseJson(text);
  if (!isPlain(parsed) || !Array.isArray(parsed.items)) {
    throw new Error("k0s-multinode: pod list was not a Kubernetes List");
  }
  return parsed.items.filter(isPlain).some((item) => {
    const meta = isPlain(item.metadata) ? item.metadata : undefined;
    const annotations = isPlain(meta?.annotations)
      ? meta.annotations
      : undefined;
    if (typeof annotations?.["kubernetes.io/config.mirror"] === "string") {
      return false;
    }
    const owners = Array.isArray(meta?.ownerReferences)
      ? meta.ownerReferences.filter(isPlain)
      : [];
    return !owners.some((o) => o.kind === "DaemonSet");
  });
}

/** Names from a `kubectl ... -o json` list. */
export function parseItemNames(text: string): string[] {
  const parsed = parseJson(text);
  if (!isPlain(parsed) || !Array.isArray(parsed.items)) return [];
  return parsed.items.filter(isPlain).map((item) => {
    const meta = isPlain(item.metadata) ? item.metadata : undefined;
    return stringOf(meta?.name);
  }).filter((name) => name !== "");
}

/** Token IDs k0s prints are a bare 6-character lowercase id. */
const TOKEN_ID_RE = /^[a-z0-9]{6}$/;

function base64Decode(value: string): Uint8Array {
  const binary = atob(value);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

/**
 * The token ID inside a `k0s token create` payload. The payload is a
 * base64-encoded gzipped kubeconfig, and the bootstrap token lives in
 * `users[].user.token` as `<id>.<secret>`. Returns null (never a raw-token
 * guess) when the payload is not a kubeconfig carrying such a token, so a
 * secret can never be mistaken for an ID.
 */
export async function joinTokenIdFromCreate(
  token: string,
): Promise<string | null> {
  let bytes: Uint8Array;
  try {
    bytes = base64Decode(token.trim());
  } catch {
    return null;
  }
  let text: string;
  try {
    const stream = new Blob([bytes as unknown as BlobPart]).stream()
      .pipeThrough(
        new DecompressionStream("gzip"),
      );
    text = new TextDecoder().decode(
      new Uint8Array(await new Response(stream).arrayBuffer()),
    );
  } catch {
    return null;
  }
  const match = /^\s*token:\s*(\S+)\s*$/m.exec(text);
  if (!match) return null;
  const id = match[1].split(".")[0];
  return TOKEN_ID_RE.test(id) ? id : null;
}
