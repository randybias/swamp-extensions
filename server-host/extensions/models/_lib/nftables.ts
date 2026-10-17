/**
 * Deterministic nftables ruleset renderer for one host's managed table.
 *
 * The ruleset is pure data: given the same inputs it renders byte for byte the
 * same text, with CIDRs and ports sorted, so a SHA-256 of the output is a
 * stable idempotency key. The ruleset owns one table (`inet server_host`) and
 * begins with `add table` and `delete table` so `nft -f` replaces it atomically and succeeds
 * whether or not the table already exists.
 *
 * @module
 */

import {
  assertIfacePattern,
  HostConfigError,
  isEffectivelyAnywhere,
  parseCidr,
} from "./validate.ts";

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
  /**
   * Interfaces whose traffic is trusted: accepted into the host (input) and
   * through it (forward, both directions). Names or `prefix*` patterns. Unset or
   * empty renders exactly the ruleset of earlier versions.
   */
  trustedInterfaces?: string[];
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
    // `add` then `delete` in one batch is the idiom that works on every kernel:
    // `destroy` needs 6.3 or later.
    `add table inet ${TABLE}`,
    `delete table inet ${TABLE}`,
    `table inet ${TABLE} {`,
  ];
  lines.push(`\tchain input {`);
  lines.push(
    `\t\ttype filter hook input priority filter; policy ${rules.defaultPolicy};`,
  );
  lines.push(`\t\tct state established,related accept`);
  lines.push(`\t\tiifname "lo" accept`);
  const trusted = [...new Set(rules.trustedInterfaces ?? [])].sort();
  for (const i of trusted) lines.push(`\t\tiifname "${i}" accept`);
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
  for (const i of trusted) {
    lines.push(`\t\tiifname "${i}" accept`);
    lines.push(`\t\toifname "${i}" accept`);
  }
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

/** A rule, a chain or a table in nftables' JSON form (`nft -j list ...`). */
type Json = Record<string, unknown>;

/** One chain of the managed table in normalized form. */
export interface NormChain {
  /** Chain name. */
  name: string;
  /** Base-chain type, hook and priority, and policy. */
  base: string;
  /** Rules in order, each as a normalized string. */
  rules: string[];
}

/** The managed table in a form that does not depend on how nft prints it. */
export interface NormTable {
  /** Chains sorted by name. */
  chains: NormChain[];
  /** Table flags such as `dormant`; none are expected. */
  flags: string[];
  /** Any set, map or other object of the table besides chains and rules. */
  extras: string[];
}

const bitsOf = (family: 4 | 6) => (family === 4 ? 32 : 128);

/** Sorts normalized elements: numbers first by value, then everything else. */
function sortElems(elems: string[]): string[] {
  const num = (e: string) => (e.startsWith("n:") ? Number(e.slice(2)) : NaN);
  return [...elems].sort((a, b) => {
    const x = num(a);
    const y = num(b);
    if (!Number.isNaN(x) && !Number.isNaN(y)) return x - y;
    if (!Number.isNaN(x)) return -1;
    if (!Number.isNaN(y)) return 1;
    // `family:hexnetwork/prefix`: order by family, then numerically.
    const m = /^([46]):([0-9a-f]+)\/(\d+)$/;
    const pa = m.exec(a);
    const pb = m.exec(b);
    if (pa && pb) {
      if (pa[1] !== pb[1]) return Number(pa[1]) - Number(pb[1]);
      const na = BigInt(`0x${pa[2]}`);
      const nb = BigInt(`0x${pb[2]}`);
      if (na !== nb) return na < nb ? -1 : 1;
      return Number(pa[3]) - Number(pb[3]);
    }
    return a < b ? -1 : a > b ? 1 : 0;
  });
}

function stable(v: unknown): string {
  if (Array.isArray(v)) return `[${v.map(stable).join(",")}]`;
  if (v && typeof v === "object") {
    const o = v as Json;
    return `{${
      Object.keys(o).sort().map((k) => `${JSON.stringify(k)}:${stable(o[k])}`)
        .join(",")
    }}`;
  }
  return JSON.stringify(v);
}

function leftKey(left: unknown): { key: string; family?: 4 | 6 } {
  const l = left as Json;
  if (l?.ct) return { key: `ct.${(l.ct as Json).key}` };
  if (l?.meta) return { key: `meta.${(l.meta as Json).key}` };
  if (l?.payload) {
    const pl = l.payload as Json;
    const fam = pl.protocol === "ip"
      ? 4
      : pl.protocol === "ip6"
      ? 6
      : undefined;
    return { key: `${pl.protocol}.${pl.field}`, family: fam };
  }
  return { key: `raw:${stable(left)}` };
}

function elem(v: unknown): string {
  if (typeof v === "number") return `n:${v}`;
  if (typeof v === "string") return `s:${v}`;
  return `raw:${stable(v)}`;
}

interface Span {
  lo: bigint;
  hi: bigint;
}

/** The addresses an element covers: a bare address, a prefix or a range. */
function span(family: 4 | 6, v: unknown): Span | null {
  const bits = bitsOf(family);
  const addr = (t: unknown): bigint | null =>
    typeof t === "string" ? parseCidr(`${t}/${bits}`)?.network ?? null : null;
  if (typeof v === "string") {
    const a = addr(v);
    return a === null ? null : { lo: a, hi: a };
  }
  const o = v as Json;
  if (o?.prefix) {
    const p = o.prefix as Json;
    const a = addr(p.addr);
    const len = Number(p.len);
    if (a === null || !(len >= 0 && len <= bits)) return null;
    const lo = (a >> BigInt(bits - len)) << BigInt(bits - len);
    return { lo, hi: lo + (1n << BigInt(bits - len)) - 1n };
  }
  if (Array.isArray(o?.range) && o.range.length === 2) {
    const lo = addr(o.range[0]);
    const hi = addr(o.range[1]);
    return lo === null || hi === null || lo > hi ? null : { lo, hi };
  }
  return null;
}

/**
 * Merges address elements into the sorted list of intervals they cover. nft
 * merges overlapping and adjacent entries of a set itself and prints a union
 * that is not aligned to a prefix as a range, so only the covered addresses
 * are comparable. Null when an element is not an address.
 */
function mergedSpans(family: 4 | 6, set: unknown[]): string[] | null {
  const spans: Span[] = [];
  for (const e of set) {
    const sp = span(family, e);
    if (!sp) return null;
    spans.push(sp);
  }
  spans.sort((a, b) => (a.lo < b.lo ? -1 : a.lo > b.lo ? 1 : 0));
  const merged: Span[] = [];
  for (const sp of spans) {
    const last = merged.at(-1);
    if (last && sp.lo <= last.hi + 1n) {
      if (sp.hi > last.hi) last.hi = sp.hi;
    } else merged.push({ ...sp });
  }
  return merged.map((m) =>
    `a${family}:${m.lo.toString(16)}-${m.hi.toString(16)}`
  );
}

/** One rule's expressions as a normalized string. */
function normRule(expr: Json[]): string {
  return expr.map((e) => {
    if (e.match) {
      const m = e.match as Json;
      const { key, family } = leftKey(m.left);
      const r = m.right;
      const set = Array.isArray(r)
        ? r
        : r && typeof r === "object" && (r as Json).set
        ? (r as Json).set as unknown[]
        : [r];
      const op = m.op === "==" || m.op === "in" ? "in" : String(m.op);
      const spans = family !== undefined && /\.[sd]addr$/.test(key)
        ? mergedSpans(family, set)
        : null;
      return `${key} ${op} ${
        (spans ?? sortElems(set.map((x) => elem(x)))).join(",")
      }`;
    }
    if ("accept" in e) return "accept";
    if ("drop" in e) return "drop";
    return `raw:${stable(e)}`;
  }).join(" ; ");
}

/**
 * Normalizes the managed table out of `nft -j list ruleset` (or `list table`)
 * output. Handles, ids and the metainfo are dropped, one-element sets read the
 * same as bare values, a /32 or /128 reads the same as the address, and set
 * elements are ordered numerically. Returns null when the table is absent.
 */
export function normalizeListing(jsonText: string): NormTable | null {
  const doc = JSON.parse(jsonText) as { nftables?: Json[] };
  const objs = doc.nftables ?? [];
  const mine = (o: Json) => o.family === "inet" && o.table === TABLE;
  const hasTable = objs.some((o) => {
    const t = o.table as Json | undefined;
    return t && t.family === "inet" && t.name === TABLE;
  });
  if (!hasTable) return null;
  const meta = objs.map((o) => o.table as Json | undefined).find((t) =>
    t && t.family === "inet" && t.name === TABLE
  )!;
  const flags = [meta.flags ?? []].flat().map(String).sort();
  const extras: string[] = [];
  for (const o of objs) {
    for (const [kind, body] of Object.entries(o)) {
      if (["table", "chain", "rule", "metainfo"].includes(kind)) continue;
      const b = body as Json;
      if (b && mine(b)) {
        const { handle: _h, ...rest } = b;
        extras.push(`${kind}:${stable(rest)}`);
      }
    }
  }
  extras.sort();
  const chains = new Map<string, NormChain>();
  for (const o of objs) {
    const c = o.chain as Json | undefined;
    if (c && mine(c)) {
      chains.set(String(c.name), {
        name: String(c.name),
        base: c.type ? `${c.type} ${c.hook} ${c.prio} ${c.policy}` : "regular",
        rules: [],
      });
    }
  }
  for (const o of objs) {
    const r = o.rule as Json | undefined;
    if (r && mine(r)) {
      chains.get(String(r.chain))?.rules.push(normRule(r.expr as Json[]));
    }
  }
  return {
    chains: [...chains.values()].sort((a, b) => a.name < b.name ? -1 : 1),
    flags,
    extras,
  };
}

const match = (left: Json, right: unknown, op = "==") => ({
  match: { op, left, right },
});
const payload = (protocol: string, field: string) => ({
  payload: { protocol, field },
});

/** The managed table as nftables would list it for `rules` (JSON shape, no handles). */
export function expectedListing(rules: FirewallRules): string {
  const out: Json[] = [{ table: { family: "inet", name: TABLE } }];
  const chain = (name: string, hook: string, policy: string) =>
    out.push({
      chain: {
        family: "inet",
        table: TABLE,
        name,
        type: "filter",
        hook,
        prio: 0,
        policy,
      },
    });
  const ruleIn = (chain: string, ...expr: Json[]) =>
    out.push({ rule: { family: "inet", table: TABLE, chain, expr } });
  const rule = (...expr: Json[]) => ruleIn("input", ...expr);
  chain("input", "input", rules.defaultPolicy);
  chain("forward", "forward", "drop");
  chain("output", "output", "accept");
  rule(
    match({ ct: { key: "state" } }, ["established", "related"], "in"),
    { accept: null },
  );
  rule(match({ meta: { key: "iifname" } }, "lo"), { accept: null });
  const trusted = [...new Set(rules.trustedInterfaces ?? [])].sort();
  for (const i of trusted) {
    rule(match({ meta: { key: "iifname" } }, i), { accept: null });
    ruleIn("forward", match({ meta: { key: "iifname" } }, i), { accept: null });
    ruleIn("forward", match({ meta: { key: "oifname" } }, i), { accept: null });
  }
  rule(match(payload("ip", "protocol"), "icmp"), { accept: null });
  rule(match(payload("ip6", "nexthdr"), "ipv6-icmp"), { accept: null });
  const ssh = match(payload("tcp", "dport"), rules.sshPort);
  const prefix = (c: string) => {
    const [addr, len] = c.split("/");
    return { prefix: { addr, len: Number(len) } };
  };
  if (rules.allowSshFromAnywhere) {
    rule(ssh, { accept: null });
  } else {
    const { v4, v6 } = splitCidrs(rules.managementCidrs);
    if (v4.length > 0) {
      rule(match(payload("ip", "saddr"), { set: v4.map(prefix) }), ssh, {
        accept: null,
      });
    }
    if (v6.length > 0) {
      rule(match(payload("ip6", "saddr"), { set: v6.map(prefix) }), ssh, {
        accept: null,
      });
    }
  }
  const ports = (list: number[]) =>
    [...new Set(list)].filter((p) => p !== rules.sshPort);
  for (
    const [proto, list] of [["tcp", rules.allowTcp], [
      "udp",
      rules.allowUdp,
    ]] as const
  ) {
    const p = ports(list);
    if (p.length > 0) {
      rule(match(payload(proto, "dport"), { set: p }), { accept: null });
    }
  }
  return JSON.stringify({ nftables: out });
}

/** SHA-256 of an `nft -j list ruleset` document with handles and metainfo removed. */
export async function listingSha256(jsonText: string): Promise<string> {
  const strip = (v: unknown): unknown => {
    if (Array.isArray(v)) {
      return v.filter((x) => !(x && typeof x === "object" && "metainfo" in x))
        .map(strip);
    }
    if (v && typeof v === "object") {
      return Object.fromEntries(
        Object.entries(v as Json).filter(([k]) => k !== "handle").map((
          [k, x],
        ) => [k, strip(x)]),
      );
    }
    return v;
  };
  return await rulesetSha256(stable(strip(JSON.parse(jsonText))));
}

/** The managed-table hash `rules` should produce once applied. */
export async function expectedManagedSha256(
  rules: FirewallRules,
): Promise<string> {
  return await managedSha256(normalizeListing(expectedListing(rules)));
}

/** The hash of a normalized table; an absent table hashes as the empty string. */
export async function managedSha256(t: NormTable | null): Promise<string> {
  return await rulesetSha256(t ? stable(t) : "");
}

/**
 * Throws unless the live table equals what `rules` should produce: same
 * chains, same policies, and every rule present in the same order, compared as
 * normalized structures rather than text.
 */
export function assertListingMatches(
  rules: FirewallRules,
  liveJson: string,
): void {
  const live = normalizeListing(liveJson);
  const want = normalizeListing(expectedListing(rules))!;
  if (!live) throw new HostConfigError(`table inet ${TABLE} is not present`);
  if (stable(live.flags) !== stable(want.flags)) {
    throw new HostConfigError(`table inet ${TABLE} has unexpected flags`);
  }
  if (stable(live.extras) !== stable(want.extras)) {
    throw new HostConfigError(
      `table inet ${TABLE} holds sets or other objects that were not rendered`,
    );
  }
  const names = new Set([
    ...live.chains.map((c) => c.name),
    ...want.chains.map((c) => c.name),
  ]);
  for (const n of [...names].sort()) {
    const a = live.chains.find((c) => c.name === n);
    const b = want.chains.find((c) => c.name === n);
    if (!a || !b) {
      throw new HostConfigError(`chain ${n} differs from the rendered ruleset`);
    }
    if (a.base !== b.base) {
      throw new HostConfigError(`chain ${n} has a different type or policy`);
    }
    const missing = b.rules.find((r) => !a.rules.includes(r));
    if (missing !== undefined) {
      throw new HostConfigError(
        `rendered rule is missing from chain ${n}: ${missing}`,
      );
    }
    if (stable(a.rules) !== stable(b.rules)) {
      throw new HostConfigError(`chain ${n} has extra or reordered rules`);
    }
  }
}

/**
 * Cross-field firewall checks a schema cannot express: every management CIDR
 * is well formed, no /0 network hides unless it was acknowledged, and an
 * unacknowledged rule set leaves SSH reachable from somewhere.
 */
export function assertFirewallRules(rules: FirewallRules): void {
  for (const i of rules.trustedInterfaces ?? []) assertIfacePattern(i);
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
