/**
 * Pure mesh-to-config rendering: validates mesh inputs and renders one node's
 * WireGuard configuration. No I/O, no clock, no private key.
 *
 * @module
 */

import { z } from "npm:zod@4.3.6";
import { type Cidr, overlaps, parseCidr } from "./cidr.ts";

/** A name used in comments and error messages; no whitespace or newlines. */
export const NAME_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$/;
/** WireGuard interface name grammar (also used in remote paths). */
export const IFACE_RE = /^[a-z][a-z0-9_-]{0,14}$/;
const HOST_RE =
  /^(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$/;
const V4_RE = /^(?:(?:0|[1-9][0-9]{0,2})\.){3}(?:0|[1-9][0-9]{0,2})$/;
const V6_RE = /^[0-9A-Fa-f:]{2,39}$/;

/** True for `host:port`, `a.b.c.d:port` or `[v6]:port` with a valid port. */
export function isEndpoint(text: string): boolean {
  const m = /^(?:\[([^\]]+)\]|([^:\[\]]+)):([0-9]{1,5})$/.exec(text);
  if (!m) return false;
  const port = Number(m[3]);
  if (port < 1 || port > 65535) return false;
  if (m[1] !== undefined) return V6_RE.test(m[1]) && m[1].includes(":");
  const host = m[2];
  if (V4_RE.test(host)) return host.split(".").every((o) => Number(o) <= 255);
  return HOST_RE.test(host);
}

/** A WireGuard key: 32 bytes as 44 characters of base64. */
export const KeySchema = z.string().length(44).regex(
  /^[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]=$/,
  "must be a 44-character base64 WireGuard key",
);
const CidrSchema = z.string().refine((s) => parseCidr(s) !== null, {
  message: "must be a CIDR such as 192.0.2.0/24",
});
const NameSchema = z.string().regex(NAME_RE, "invalid name");
const EndpointSchema = z.string().refine(isEndpoint, {
  message: "must be host:port, a.b.c.d:port or [v6]:port",
});

/** The node being rendered. */
export const NodeSchema = z.strictObject({
  name: NameSchema.describe("Node name; also the state key."),
  address: CidrSchema.describe("The node's mesh address as a CIDR."),
  listen_port: z.number().int().min(1).max(65535).describe(
    "UDP port WireGuard listens on.",
  ),
  endpoint: EndpointSchema.optional().describe(
    "Public host:port; omit for a node reachable only through a relay.",
  ),
});

/** One mesh member as seen by every other node. */
export const PeerSchema = z.strictObject({
  name: NameSchema,
  public_key: KeySchema,
  allowed_ips: z.array(CidrSchema).min(1).max(256).describe(
    "Addresses routed to this peer.",
  ),
  endpoint: EndpointSchema.optional(),
  keepalive: z.number().int().min(0).max(65535).optional().describe(
    "PersistentKeepalive seconds; 0 or omitted disables it.",
  ),
});

/** Takes peers out of a node's direct set and routes them through a relay. */
export const RelayRuleSchema = z.strictObject({
  exclude: z.array(NameSchema).min(1).max(512).describe(
    "Peers removed from the direct peer set.",
  ),
  for_nodes: z.array(z.union([NameSchema, z.literal("*")])).min(1).max(512)
    .describe(
      'Nodes the rule applies to; "*" means every node except the relay.',
    ),
  via: NameSchema.optional().describe(
    "Relay peer that carries the excluded peers' addresses.",
  ),
});

/** Mesh inputs for one render. */
export const MeshSchema = z.strictObject({
  node: NodeSchema,
  peers: z.array(PeerSchema).max(512),
  peers_allowlist: z.array(z.string().min(1).max(64)).max(512).describe(
    "Peer names or public keys permitted in this mesh.",
  ),
  relay_exclusion: z.array(RelayRuleSchema).max(64).default([]),
  interface: z.string().regex(IFACE_RE).default("wg0").describe(
    "Interface name; names the config and key files.",
  ),
});

/** Validated mesh inputs. */
export type Mesh = z.infer<typeof MeshSchema>;

/** A peer as rendered into the node's config. */
export interface ResolvedPeer {
  /** Peer name. */
  name: string;
  /** Peer public key. */
  public_key: string;
  /** Sorted allowed IPs, including addresses carried for excluded peers. */
  allowed_ips: string[];
  /** Peer endpoint, if any. */
  endpoint?: string;
  /** Keepalive seconds, if enabled. */
  keepalive?: number;
  /** Names of excluded peers whose addresses this relay carries. */
  carries?: string[];
}

/** Result of a render. */
export interface Rendered {
  /** The wg-quick configuration text. */
  config: string;
  /** Peers in rendered order. */
  peers: ResolvedPeer[];
  /** Peers removed by relay exclusion, sorted. */
  excluded: string[];
  /** The node's own public endpoint, echoed back for other nodes to use. */
  node_endpoint?: string;
}

/** A peer that is not on the allowlist. */
export class PeerNotAllowedError extends Error {
  /** The rejected peer's name. */
  readonly peer: string;
  /** Creates the error. */
  constructor(peer: string) {
    super(`peer ${peer} is not on peers_allowlist`);
    this.name = "PeerNotAllowedError";
    this.peer = peer;
  }
}

/** Mesh data that parses but is inconsistent. */
export class MeshError extends Error {
  /** Creates the error. */
  constructor(message: string) {
    super(message);
    this.name = "MeshError";
  }
}

const cmp = (a: string, b: string) => (a < b ? -1 : a > b ? 1 : 0);

function cidrOf(text: string): Cidr {
  const c = parseCidr(text);
  if (!c) throw new MeshError(`invalid CIDR ${text}`);
  return c;
}

/** Throws when two peers share a name, a key, or an overlapping address. */
function checkUnique(node: Mesh["node"], peers: Mesh["peers"]): void {
  const names = new Set<string>();
  const keys = new Set<string>();
  const nets: { owner: string; text: string; cidr: Cidr }[] = [];
  for (const p of peers) {
    if (names.has(p.name)) throw new MeshError(`duplicate peer name ${p.name}`);
    if (keys.has(p.public_key)) {
      throw new MeshError(`peer ${p.name} repeats another peer's public key`);
    }
    names.add(p.name);
    keys.add(p.public_key);
    for (const t of p.allowed_ips) {
      const cidr = cidrOf(t);
      for (const o of nets) {
        if (overlaps(o.cidr, cidr)) {
          throw new MeshError(
            `allowed_ips ${t} of peer ${p.name} overlaps ${o.text} of peer ${o.owner}`,
          );
        }
      }
      nets.push({ owner: p.name, text: t, cidr });
    }
  }
  const own = cidrOf(node.address);
  for (const o of nets) {
    if (o.owner !== node.name && overlaps(o.cidr, own)) {
      throw new MeshError(
        `allowed_ips ${o.text} of peer ${o.owner} overlaps node address ${node.address}`,
      );
    }
  }
}

/**
 * Renders one node's wg-quick config from already-validated mesh data.
 * Deterministic: the same inputs give the same bytes. The returned text never
 * contains a private key; the config loads it from a key file instead.
 */
export function renderNode(mesh: Mesh): Rendered {
  const { node } = mesh;
  const allowed = new Set(mesh.peers_allowlist);
  // Sorted so the peer named in the error does not depend on input order.
  for (const p of [...mesh.peers].sort((a, b) => cmp(a.name, b.name))) {
    if (!allowed.has(p.name) && !allowed.has(p.public_key)) {
      throw new PeerNotAllowedError(p.name);
    }
  }
  checkUnique(node, mesh.peers);

  const byName = new Map(mesh.peers.map((p) => [p.name, p]));
  const excluded = new Set<string>();
  const carried = new Map<string, Set<string>>(); // relay -> excluded names
  for (const rule of mesh.relay_exclusion) {
    for (const n of [...rule.exclude, ...(rule.via ? [rule.via] : [])]) {
      if (!byName.has(n)) {
        throw new MeshError(`relay_exclusion names unknown peer ${n}`);
      }
    }
    for (const n of rule.for_nodes) {
      if (n !== "*" && n !== node.name && !byName.has(n)) {
        throw new MeshError(
          `relay_exclusion for_nodes names unknown node ${n}`,
        );
      }
    }
    if (rule.via && rule.exclude.includes(rule.via)) {
      throw new MeshError(`relay ${rule.via} cannot exclude itself`);
    }
    if (rule.via && rule.for_nodes.includes(rule.via)) {
      throw new MeshError(`relay ${rule.via} cannot be excluded for itself`);
    }
    const applies = rule.for_nodes.includes(node.name) ||
      (rule.for_nodes.includes("*") && node.name !== rule.via);
    if (!applies) continue;
    for (const n of rule.exclude) {
      if (n === node.name) continue;
      excluded.add(n);
      if (rule.via) {
        const set = carried.get(rule.via) ?? new Set<string>();
        set.add(n);
        carried.set(rule.via, set);
      }
    }
  }
  for (const via of carried.keys()) {
    if (excluded.has(via)) {
      throw new MeshError(`relay ${via} is excluded on node ${node.name}`);
    }
  }

  const resolved: ResolvedPeer[] = [];
  for (const p of mesh.peers) {
    if (p.name === node.name || excluded.has(p.name)) continue;
    const ips = new Set(p.allowed_ips);
    const carries = [...(carried.get(p.name) ?? [])].sort(cmp);
    for (const n of carries) {
      for (const ip of byName.get(n)!.allowed_ips) ips.add(ip);
    }
    resolved.push({
      name: p.name,
      public_key: p.public_key,
      allowed_ips: [...ips].sort(cmp),
      ...(p.endpoint ? { endpoint: p.endpoint } : {}),
      ...(p.keepalive ? { keepalive: p.keepalive } : {}),
      ...(carries.length ? { carries } : {}),
    });
  }
  resolved.sort((a, b) => cmp(a.name, b.name));

  const lines = [
    "# Managed by @randybias/wireguard-mesh; changes are overwritten.",
    "[Interface]",
    `Address = ${node.address}`,
    `ListenPort = ${node.listen_port}`,
    `PostUp = wg set '%i' private-key '/etc/wireguard/%i.key'`,
  ];
  for (const p of resolved) {
    lines.push("", `# ${p.name}`, "[Peer]", `PublicKey = ${p.public_key}`);
    lines.push(`AllowedIPs = ${p.allowed_ips.join(", ")}`);
    if (p.endpoint) lines.push(`Endpoint = ${p.endpoint}`);
    if (p.keepalive) lines.push(`PersistentKeepalive = ${p.keepalive}`);
  }
  return {
    config: lines.join("\n") + "\n",
    peers: resolved,
    excluded: [...excluded].sort(cmp),
    ...(node.endpoint ? { node_endpoint: node.endpoint } : {}),
  };
}

/** Validates raw mesh input once, then renders it (the public entry point). */
export function renderMesh(input: z.input<typeof MeshSchema>): Rendered {
  return renderNode(MeshSchema.parse(input));
}
