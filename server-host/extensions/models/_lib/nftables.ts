/**
 * Deterministic nftables ruleset renderer for one host's managed table.
 *
 * The ruleset is pure data: given the same inputs it renders byte for byte the
 * same text, with CIDRs and ports sorted, so a SHA-256 of the output is a
 * stable idempotency key. The ruleset owns one table (`inet server_host`) and
 * begins with `destroy table` so `nft -f` replaces it atomically and succeeds
 * whether or not the table already exists.
 *
 * @module
 */

import { HostConfigError, isEffectivelyAnywhere } from "./validate.ts";

/** Everything that determines the rendered ruleset. */
export interface FirewallRules {
  /** CIDRs allowed to reach the SSH port. Sorted and deduped when rendered. */
  managementCidrs: string[];
  /** TCP ports open to every source, excluding the SSH port. */
  allowTcp: number[];
  /** UDP ports open to every source. */
  allowUdp: number[];
  /** Policy of the input chain; the output chain is always accept. */
  defaultPolicy: "drop" | "accept";
  /** Port the SSH allow rules target. */
  sshPort: number;
  /** When true, allow the SSH port from any source and ignore the CIDR list. */
  allowSshFromAnywhere: boolean;
}

const HEADER =
  "# Managed by @randybias/server-host. Edit the model inputs, not this file.";

/** The name of the single nftables table this extension owns. */
export const TABLE = "server_host";

function portSet(ports: number[]): string {
  return `{ ${ports.join(", ")} }`;
}

function addrSet(cidrs: string[]): string {
  return `{ ${cidrs.join(", ")} }`;
}

/** Splits CIDRs into IPv4 and IPv6 groups, sorted and deduped within each. */
export function splitCidrs(cidrs: string[]): { v4: string[]; v6: string[] } {
  const v4: string[] = [];
  const v6: string[] = [];
  for (const c of [...new Set(cidrs)].sort()) {
    if (c.includes(":")) v6.push(c);
    else v4.push(c);
  }
  return { v4, v6 };
}

/**
 * Renders `rules` as an nftables script. The order of rules is fixed and the
 * two port sets always exclude the SSH port, so an SSH allow can only come
 * from the dedicated SSH rules.
 */
export function renderRuleset(rules: FirewallRules): string {
  const lines: string[] = [
    HEADER,
    `destroy table inet ${TABLE}`,
    `table inet ${TABLE} {`,
  ];
  lines.push(`\tchain input {`);
  lines.push(
    `\t\ttype filter hook input priority filter; policy ${rules.defaultPolicy};`,
  );
  lines.push(`\t\tct state established,related accept`);
  lines.push(`\t\tiifname "lo" accept`);
  lines.push(`\t\tip protocol icmp accept`);
  lines.push(`\t\tip6 nexthdr ipv6-icmp accept`);
  const { v4, v6 } = splitCidrs(rules.managementCidrs);
  if (rules.allowSshFromAnywhere) {
    lines.push(`\t\ttcp dport ${rules.sshPort} accept`);
  } else {
    if (v4.length > 0) {
      lines.push(
        `\t\tip saddr ${addrSet(v4)} tcp dport ${rules.sshPort} accept`,
      );
    }
    if (v6.length > 0) {
      lines.push(
        `\t\tip6 saddr ${addrSet(v6)} tcp dport ${rules.sshPort} accept`,
      );
    }
  }
  const tcp = [...new Set(rules.allowTcp)].filter((p) => p !== rules.sshPort)
    .sort((a, b) => a - b);
  if (tcp.length > 0) lines.push(`\t\ttcp dport ${portSet(tcp)} accept`);
  const udp = [...new Set(rules.allowUdp)].filter((p) => p !== rules.sshPort)
    .sort((a, b) => a - b);
  if (udp.length > 0) lines.push(`\t\tudp dport ${portSet(udp)} accept`);
  lines.push(`\t}`);
  lines.push(`\tchain forward {`);
  lines.push(`\t\ttype filter hook forward priority filter; policy drop;`);
  lines.push(`\t}`);
  lines.push(`\tchain output {`);
  lines.push(`\t\ttype filter hook output priority filter; policy accept;`);
  lines.push(`\t}`);
  lines.push(`}`);
  return lines.join("\n") + "\n";
}

/** The SHA-256 hex digest of `text`, used as the ruleset idempotency key. */
export async function rulesetSha256(text: string): Promise<string> {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(text),
  );
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

/**
 * Extracts the managed table (header line through the matching column-zero
 * closing brace) from a rendered script or `nft list ruleset` output, so the
 * two representations can be compared without their comments or wrappers.
 */
export function managedTableText(text: string): string {
  const lines = text.split("\n");
  const start = lines.findIndex((l) =>
    l.trimStart().startsWith(`table inet ${TABLE} {`)
  );
  if (start < 0) return "";
  const end = lines.findIndex((l, i) => i > start && l === "}");
  return lines.slice(start, end < 0 ? lines.length : end + 1).join("\n");
}

/**
 * The canonical form of a table for comparison: whitespace removed, comments
 * and the `destroy table` wrapper already excluded by
 * {@link managedTableText}. Two representations of the same ruleset have the
 * same canonical form even when nft reformats them.
 */
export function canonicalTable(text: string): string {
  return managedTableText(text).replace(/\s+/g, "");
}

/** The SHA-256 of the canonical managed table, the value drift compares. */
export async function managedTableSha256(text: string): Promise<string> {
  return await rulesetSha256(canonicalTable(text));
}

/**
 * Cross-field firewall checks a schema cannot express: every management CIDR
 * is well formed, no /0 network hides unless it was acknowledged, and an
 * unacknowledged rule set leaves SSH reachable from somewhere.
 */
export function assertFirewallRules(rules: FirewallRules): void {
  if (
    !rules.allowSshFromAnywhere && rules.managementCidrs.length > 0 &&
    isEffectivelyAnywhere(rules.managementCidrs)
  ) {
    throw new HostConfigError(
      "management_cidrs may not open SSH to (nearly) everyone, whether by a /0, a network wider than /8 (IPv4) or /16 (IPv6), or CIDRs that together cover every address, unless allow_ssh_from_anywhere is true",
    );
  }
  if (!rules.allowSshFromAnywhere && rules.managementCidrs.length === 0) {
    throw new HostConfigError(
      "management_cidrs must name at least one CIDR, or allow_ssh_from_anywhere must be true",
    );
  }
}
