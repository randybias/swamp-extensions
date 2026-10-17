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
  lines.push("listen:");
  for (const addr of input.listen) {
    lines.push(`  - ${yamlString(addr)}`);
  }
  lines.push("cache:");
  lines.push(`  size-max: ${input.cache_size_mb}MB`);
  if (input.forwards.length > 0) {
    lines.push("forward:");
    for (const f of input.forwards) {
      lines.push(`  - subtree: ${yamlString(f.subtree)}`);
      lines.push("    servers:");
      for (const s of f.servers) lines.push(`      - ${yamlString(s)}`);
      const options: string[] = [];
      if (f.transport === "tls") options.push("      transport: tls");
      if (f.tls_hostname) {
        options.push(`      tls_hostname: ${yamlString(f.tls_hostname)}`);
      }
      if (f.authoritative) options.push("      authoritative: true");
      if (f.dnssec) options.push("      dnssec: true");
      if (options.length > 0) {
        lines.push("    options:");
        lines.push(...options);
      }
    }
  }
  const allow = input.allow_query_from ?? ["127.0.0.0/8", "::1/128"];
  lines.push("view:");
  lines.push("  - subnets:");
  for (const cidr of allow) lines.push(`      - ${yamlString(cidr)}`);
  lines.push("    answer: allow");
  lines.push("  - subnets:");
  lines.push('      - "0.0.0.0/0"');
  lines.push('      - "::/0"');
  lines.push("    answer: deny");
  return `${lines.join("\n")}\n`;
}
