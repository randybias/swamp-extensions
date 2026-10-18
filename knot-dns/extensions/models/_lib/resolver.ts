/**
 * Knot Resolver 6 configuration: schema, grammar and a deterministic
 * `config.yaml` renderer.
 *
 * Listen addresses are rendered as `addr@port` and forwarding rules are
 * rendered per subtree. Everything is structural, so a value cannot break out
 * of its YAML scalar (all strings are emitted double-quoted and escaped).
 *
 * @module
 */

import { z } from "npm:zod@4.3.6";
import { FqdnSchema, isIpv4, isIpv6 } from "./zone.ts";

const ServerAddress = z.string().min(1).max(64).refine(
  (s) => isIpv4(s) || isIpv6(s),
  "an upstream server must be an IP address",
);

/** One `ADDR[@port]` listen address. */
export const ListenAddressSchema = z.string().min(1).max(64).refine(
  (s) => {
    const at = s.lastIndexOf("@");
    const host = at === -1 ? s : s.slice(0, at);
    const port = at === -1 ? "53" : s.slice(at + 1);
    if (!(isIpv4(host) || isIpv6(host))) return false;
    return /^\d{1,5}$/.test(port) && Number(port) >= 1 && Number(port) <= 65535;
  },
  "listen must be ADDR or ADDR@port",
);

/** A CIDR or bare address for an access-control rule. */
export const CidrSchema = z.string().min(1).max(64).refine(
  (s) => {
    const slash = s.indexOf("/");
    const addr = slash === -1 ? s : s.slice(0, slash);
    const prefix = slash === -1 ? undefined : s.slice(slash + 1);
    if (!(isIpv4(addr) || isIpv6(addr))) return false;
    if (prefix === undefined) return true;
    if (!/^\d{1,3}$/.test(prefix)) return false;
    const max = isIpv4(addr) ? 32 : 128;
    return Number(prefix) >= 0 && Number(prefix) <= max;
  },
  "not a CIDR or address",
);

/** One forwarding rule. */
export const ForwardSchema = z.strictObject({
  subtree: z.union([z.literal("."), FqdnSchema]),
  servers: z.array(ServerAddress).min(1).max(16),
  transport: z.enum(["udp", "tls"]).default("udp"),
  tls_hostname: FqdnSchema.optional(),
  authoritative: z.boolean().default(false),
  dnssec: z.boolean().default(false),
}).refine(
  (f) => !(f.authoritative && f.transport === "tls"),
  "an authoritative upstream cannot use TLS",
);

/** The resolver inputs. */
export const ResolverSchema = z.strictObject({
  listen: z.array(ListenAddressSchema).min(1).max(16),
  cache_size_mb: z.number().int().min(16).max(65536).default(100),
  forwards: z.array(ForwardSchema).max(64).default([]),
  allow_query_from: z.array(CidrSchema).max(64).optional(),
  listen_any_ack: z.boolean().default(false).describe(
    "Acknowledge binding a wildcard address (0.0.0.0/::).",
  ),
  test_name: FqdnSchema.optional().describe(
    "Name the self-test asks the resolver for (SOA). Default: chosen from the forwards and the zones served on the host.",
  ),
});

/** Parsed resolver inputs. */
export type ResolverInput = z.infer<typeof ResolverSchema>;

/** Splits `ADDR[@port]` into host and port. */
export function splitListen(s: string): { host: string; port: number } {
  const at = s.lastIndexOf("@");
  const host = at === -1 ? s : s.slice(0, at);
  const port = at === -1 ? 53 : Number(s.slice(at + 1));
  return { host, port };
}

/** True for a wildcard listen address. */
export function isWildcard(host: string): boolean {
  return host === "0.0.0.0" || host === "::";
}

/** The loopback address a wildcard listen is tested on (`kdig` cannot use `::`). */
export function wildcardTestHost(host: string): string {
  return host === "::" ? "::1" : "127.0.0.1";
}

/** Parses a validated IPv4 literal to an unsigned integer. */
function ipv4ToInt(s: string): number {
  return s.split(".").reduce((n, o) => (n << 8) | Number(o), 0) >>> 0;
}

/** Expands a validated IPv6 literal to eight 16-bit groups. */
function ipv6Groups(s: string): number[] {
  const dbl = s.indexOf("::");
  if (dbl === -1) return s.split(":").map((g) => parseInt(g, 16));
  const head = s.slice(0, dbl).split(":").filter((g) => g !== "");
  const tail = s.slice(dbl + 2).split(":").filter((g) => g !== "");
  return [
    ...head.map((g) => parseInt(g, 16)),
    ...new Array(8 - head.length - tail.length).fill(0),
    ...tail.map((g) => parseInt(g, 16)),
  ];
}

/** An IP literal as a big-endian integer (32 or 128 bits). */
function ipToNumber(s: string): bigint {
  if (isIpv4(s)) return BigInt(ipv4ToInt(s));
  let v = 0n;
  for (const g of ipv6Groups(s)) v = (v << 16n) | BigInt(g);
  return v;
}

/** True when `addr` (a validated literal) is inside `cidr` of the same family. */
export function cidrContains(cidr: string, addr: string): boolean {
  const slash = cidr.indexOf("/");
  const base = slash === -1 ? cidr : cidr.slice(0, slash);
  if (isIpv4(base) !== isIpv4(addr)) return false;
  const width = isIpv4(base) ? 32 : 128;
  const bits = slash === -1 ? width : Number(cidr.slice(slash + 1));
  if (!Number.isInteger(bits) || bits < 0 || bits > width) return false;
  const shift = BigInt(width - bits);
  return (ipToNumber(base) >> shift) === (ipToNumber(addr) >> shift);
}

/**
 * The access-control list actually rendered. The spec's default is loopback
 * plus the listen addresses: a resolver that listens on an address but refuses
 * its own queries can never pass its self-test. The listen host is added as a
 * host route (`/32` or `/128`), the narrowest reading of "the listen subnets",
 * so the default never opens a wider network than the resolver itself.
 */
export function effectiveAllowQueryFrom(input: ResolverInput): string[] {
  if (input.allow_query_from) return input.allow_query_from;
  const out = ["127.0.0.0/8", "::1/128"];
  for (const listen of input.listen) {
    const { host } = splitListen(listen);
    if (isWildcard(host)) continue;
    if (!out.some((c) => cidrContains(c, host))) {
      out.push(`${host}/${isIpv4(host) ? 32 : 128}`);
    }
  }
  return out;
}

/**
 * Picks the listen address the apply self-test should query: the first one the
 * access-control list permits (a wildcard is tested on loopback, where the
 * script sends it). Returns null when `allow_query_from` excludes every listen
 * address, so the caller can refuse instead of swapping in an untestable
 * configuration.
 */
export function pickTestListen(input: ResolverInput): string | null {
  const allow = effectiveAllowQueryFrom(input);
  for (const listen of input.listen) {
    const { host } = splitListen(listen);
    const probe = isWildcard(host) ? wildcardTestHost(host) : host;
    if (allow.some((c) => cidrContains(c, probe))) return listen;
  }
  return null;
}

/** Quotes one YAML scalar. */
function yamlString(s: string): string {
  return JSON.stringify(s);
}

/**
 * Renders the Knot Resolver 6 `config.yaml`. Access control defaults to the
 * listen subnets plus loopback; a wildcard listen without `listen_any_ack`
 * must be refused by the caller before this point.
 */
export function renderResolverYaml(input: ResolverInput): string {
  const lines: string[] = ["---"];
  lines.push("network:");
  lines.push("  listen:");
  for (const addr of input.listen) {
    const { host, port } = splitListen(addr);
    lines.push(`    - interface: ${yamlString(host)}`);
    lines.push(`      port: ${port}`);
  }
  lines.push("cache:");
  lines.push(`  size-max: ${input.cache_size_mb}M`);
  if (input.forwards.length > 0) {
    lines.push("forward:");
    for (const f of input.forwards) {
      lines.push(`  - subtree: ${yamlString(f.subtree)}`);
      lines.push("    servers:");
      for (const s of f.servers) {
        lines.push(`      - address: ${yamlString(s)}`);
        if (f.transport === "tls") {
          lines.push("        transport: tls");
          if (f.tls_hostname) {
            lines.push(`        hostname: ${yamlString(f.tls_hostname)}`);
          }
        }
      }
      // dnssec is always written: Knot Resolver 6 validates by default, which
      // turns a private or locally signed forward into SERVFAIL.
      lines.push("    options:");
      lines.push(`      dnssec: ${f.dnssec ? "true" : "false"}`);
      if (f.authoritative) lines.push("      authoritative: true");
    }
  }
  const allow = effectiveAllowQueryFrom(input);
  lines.push("views:");
  lines.push("  - subnets:");
  for (const cidr of allow) lines.push(`      - ${yamlString(cidr)}`);
  lines.push("    answer: allow");
  lines.push("  - subnets:");
  lines.push('      - "0.0.0.0/0"');
  lines.push('      - "::/0"');
  lines.push("    answer: refused");
  return `${lines.join("\n")}\n`;
}

/** True when `name` is `zone` or below it (both fully qualified). */
function isAtOrBelow(name: string, zone: string): boolean {
  if (zone === ".") return true;
  return name === zone || name.endsWith(`.${zone}`);
}

/**
 * Picks the self-test name so a correct configuration never fails its own
 * test. A forward to an authoritative server answers REFUSED (a resolver turns
 * that into SERVFAIL) for any name outside the zones that server serves, so
 * the name must be one it serves: the caller's `test_name`, else the forwarded
 * subtree itself or a zone served on this host below it. A forward that no
 * served zone overlaps is external: its subtree is asked as before.
 */
export function pickTestQuery(
  input: ResolverInput,
  servedApexes: string[],
): string {
  if (input.test_name) return input.test_name;
  for (const f of input.forwards) {
    if (f.subtree === ".") continue;
    const served = servedApexes.find((apex) => apex === f.subtree) ??
      servedApexes.find((apex) => isAtOrBelow(apex, f.subtree));
    if (served) return served;
  }
  return input.forwards[0]?.subtree ?? ".";
}
