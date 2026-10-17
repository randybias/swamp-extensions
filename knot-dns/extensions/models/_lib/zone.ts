/**
 * Knot DNS zone model: grammars, schemas, semantic rules and the canonical
 * zone-file renderer.
 *
 * Everything here is pure and deterministic: the same declaration always
 * produces the same bytes, so the rendered file's sha256 is a stable identity
 * for idempotency. Owner names are rendered absolute (no `$ORIGIN`) and every
 * record type is rendered from validated, typed data, so nothing in a name,
 * rdata or TTL can smuggle a zone-file directive.
 *
 * @module
 */

import { z } from "npm:zod@4.3.6";

/** A DNS label: LDH, lowercased, 1-63 octets. */
const LABEL_RE = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/;
/** A service-owner label (`_sip._tcp`) is the only place a leading `_` is allowed. */
const SERVICE_LABEL_RE = /^_[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/;
/** A single label of an apex owner, with `_` allowed. */
const APEX_LABEL_RE = /^[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?$/;

/** True for a valid DNS label (no underscore). */
export const isLabel = (s: string): boolean => LABEL_RE.test(s);
/** True for a valid service-owner label (one leading underscore). */
export const isServiceLabel = (s: string): boolean => SERVICE_LABEL_RE.test(s);

/** Lowercases and strips one trailing dot. */
export function stripDot(s: string): string {
  return s.replace(/\.$/, "").toLowerCase();
}

/** True for a valid (lowercased) zone apex, at most 253 octets. */
export function isApex(s: string): boolean {
  const name = stripDot(s);
  if (name.length === 0 || name.length > 253) return false;
  return name.split(".").every((l) => APEX_LABEL_RE.test(l));
}

/** Normalizes an apex to lowercased, fully-qualified form with a trailing dot. */
export function normalizeApex(s: string): string {
  const name = stripDot(s);
  if (!isApex(name)) {
    throw new Error("invalid zone apex");
  }
  return `${name}.`;
}

/** True for a valid (lowercased) fully-qualified domain name. */
export function isFqdn(s: string): boolean {
  const name = stripDot(s);
  if (name.length === 0 || name.length > 253) return false;
  return !name.split(".").some((l) => !isLabel(l));
}

/** A fully-qualified domain name, A-labels only, no control characters. */
export const FqdnSchema = z.string().min(1).max(253).refine(
  isFqdn,
  "not a fully-qualified domain name",
);

/**
 * Compresses one IPv6 literal to RFC 5952 form (lowercase, longest zero run as
 * `::`), so a declaration and a tool read-back compare equal.
 */
export function canonicalIpv6(s: string): string {
  if (!isIpv6(s)) return s;
  const [head, tail] = s.includes("::")
    ? [s.slice(0, s.indexOf("::")), s.slice(s.indexOf("::") + 2)]
    : [s, undefined];
  const groups = head === "" ? [] : head.split(":");
  const tailGroups = tail === undefined || tail === "" ? [] : tail.split(":");
  const full = [
    ...groups.map((g) => parseInt(g, 16)),
    ...(tail !== undefined
      ? new Array(Math.max(0, 8 - groups.length - tailGroups.length)).fill(0)
      : []),
    ...tailGroups.map((g) => parseInt(g, 16)),
  ];
  // Find the longest run of two or more zeros.
  let bestStart = -1;
  let bestLen = 0;
  let runStart = -1;
  for (let i = 0; i <= full.length; i++) {
    if (full[i] === 0) {
      if (runStart === -1) runStart = i;
    } else if (runStart !== -1) {
      const len = i - runStart;
      if (len > bestLen) {
        bestLen = len;
        bestStart = runStart;
      }
      runStart = -1;
    }
  }
  if (bestLen < 2) return full.map((g) => g.toString(16)).join(":");
  const left = full.slice(0, bestStart).map((g) => g.toString(16)).join(":");
  const right = full.slice(bestStart + bestLen).map((g) => g.toString(16)).join(
    ":",
  );
  return `${left}::${right}`;
}

/**
 * Resolves an owner (`@`, a relative name, a `*` wildcard, or an in-zone FQDN)
 * to an absolute owner inside `apex`, or throws when it is outside the zone.
 */
export function ownerFqdn(apex: string, name: string): string {
  const zone = normalizeApex(apex);
  const zoneNoDot = stripDot(zone);
  if (name === "@") return zone;
  const raw = stripDot(name);
  if (raw === "") throw new Error("owner name must not be empty");
  const labels = raw.split(".");
  labels.forEach((l, i) => {
    if (i === 0 && l === "*") return;
    // A leading underscore is allowed on any label (service owners such as
    // `_sip._tcp`, `_443._tcp.www` and `_dmarc`).
    if (isServiceLabel(l)) return;
    if (!isLabel(l)) throw new Error("invalid owner label");
  });
  let fqdn: string;
  const absolute = name.endsWith(".") && name !== ".";
  if (absolute) {
    if (raw !== zoneNoDot && !raw.endsWith(`.${zoneNoDot}`)) {
      throw new Error("owner name is outside the zone");
    }
    fqdn = `${raw}.`;
  } else {
    fqdn = `${raw}.${zone}`;
  }
  return fqdn;
}

/** True for an IPv4 dotted quad. */
export function isIpv4(s: string): boolean {
  const parts = s.split(".");
  if (parts.length !== 4) return false;
  return parts.every((p) =>
    /^\d{1,3}$/.test(p) && Number(p) >= 0 && Number(p) <= 255 &&
    !(p.length > 1 && p.startsWith("0"))
  );
}

/** True for an IPv6 literal (no zone id). */
export function isIpv6(s: string): boolean {
  if (!/^[0-9a-fA-F:]+$/.test(s) || !s.includes(":")) return false;
  const double = s.indexOf("::");
  if (double !== -1 && s.indexOf("::", double + 1) !== -1) return false;
  const groups = double === -1 ? s.split(":") : [
    ...s.slice(0, double).split(":"),
    ...s.slice(double + 2).split(":"),
  ];
  const nonEmpty = groups.filter((g) => g !== "");
  if (nonEmpty.some((g) => !/^[0-9a-fA-F]{1,4}$/.test(g))) return false;
  return double === -1 ? nonEmpty.length === 8 : nonEmpty.length < 8;
}

/** Printable-ASCII TXT chunk, at most 255 octets. */
const TXT_CHUNK = z.string().min(1).max(255).regex(
  /^[\u0020-\u007e]+$/,
  "TXT strings must be printable ASCII",
);

const Owner = z.string().min(1).max(253);
const Ttl = z.number().int().min(1).max(604800);

const ARecord = z.object({
  name: Owner,
  ttl: Ttl.optional(),
  type: z.literal("A"),
  data: z.string().refine(isIpv4, "not an IPv4 address"),
});
const AaaaRecord = z.object({
  name: Owner,
  ttl: Ttl.optional(),
  type: z.literal("AAAA"),
  data: z.string().refine(isIpv6, "not an IPv6 address"),
});
const CnameRecord = z.object({
  name: Owner,
  ttl: Ttl.optional(),
  type: z.literal("CNAME"),
  data: FqdnSchema,
});
const MxRecord = z.object({
  name: Owner,
  ttl: Ttl.optional(),
  type: z.literal("MX"),
  data: z.object({
    preference: z.number().int().min(0).max(65535),
    exchange: FqdnSchema,
  }),
});
const TxtRecord = z.object({
  name: Owner,
  ttl: Ttl.optional(),
  type: z.literal("TXT"),
  data: z.array(TXT_CHUNK).min(1).max(255),
});
const SrvRecord = z.object({
  name: Owner,
  ttl: Ttl.optional(),
  type: z.literal("SRV"),
  data: z.object({
    priority: z.number().int().min(0).max(65535),
    weight: z.number().int().min(0).max(65535),
    port: z.number().int().min(0).max(65535),
    target: FqdnSchema,
  }),
});
const CaaRecord = z.object({
  name: Owner,
  ttl: Ttl.optional(),
  type: z.literal("CAA"),
  data: z.object({
    flags: z.number().int().min(0).max(255),
    tag: z.enum(["issue", "issuewild", "iodef"]),
    value: z.string().min(1).max(255).regex(
      /^[\u0020-\u007e]+$/,
      "CAA value must be printable ASCII",
    ),
  }),
});
const NsRecord = z.object({
  name: Owner,
  ttl: Ttl.optional(),
  type: z.literal("NS"),
  data: FqdnSchema,
});
const DsRecord = z.object({
  name: Owner,
  ttl: Ttl.optional(),
  type: z.literal("DS"),
  data: z.object({
    key_tag: z.number().int().min(0).max(65535),
    algorithm: z.number().int().min(0).max(255),
    digest_type: z.number().int().min(0).max(255),
    digest: z.string().regex(/^[0-9a-fA-F]{40,96}$/, "invalid DS digest"),
  }).refine((d) => d.digest.length % 2 === 0, "digest must be even-length hex"),
});
const PtrRecord = z.object({
  name: Owner,
  ttl: Ttl.optional(),
  type: z.literal("PTR"),
  data: FqdnSchema,
});
const SshfpRecord = z.object({
  name: Owner,
  ttl: Ttl.optional(),
  type: z.literal("SSHFP"),
  data: z.object({
    algorithm: z.number().int().min(0).max(255),
    fp_type: z.number().int().min(0).max(255),
    fingerprint: z.string().min(8).max(128).regex(
      /^[0-9a-fA-F]+$/,
      "SSHFP fingerprint must be hex",
    ),
  }),
});
const TlsaRecord = z.object({
  name: Owner,
  ttl: Ttl.optional(),
  type: z.literal("TLSA"),
  data: z.object({
    usage: z.number().int().min(0).max(3),
    selector: z.number().int().min(0).max(1),
    matching_type: z.number().int().min(0).max(2),
    certificate: z.string().min(2).max(4096).regex(
      /^[0-9a-fA-F]+$/,
      "TLSA certificate association data must be hex",
    ),
  }),
});

/** Record types the signer owns; refused as input. */
export const REFUSED_TYPES = [
  "DNSKEY",
  "RRSIG",
  "NSEC",
  "NSEC3",
  "NSEC3PARAM",
  "CDS",
  "CDNSKEY",
  "SOA",
] as const;

/** One zone record; discriminated on `type`, strict in every branch. */
export const RecordSchema = z.discriminatedUnion("type", [
  ARecord,
  AaaaRecord,
  CnameRecord,
  MxRecord,
  TxtRecord,
  SrvRecord,
  CaaRecord,
  NsRecord,
  DsRecord,
  PtrRecord,
  SshfpRecord,
  TlsaRecord,
]);

/** A parsed zone record. */
export type ZoneRecord = z.infer<typeof RecordSchema>;

/** A record whose type the signer owns; accepted only so it can be refused. */
export const RefusedRecordSchema = z.union([
  RecordSchema,
  z.strictObject({
    name: Owner,
    ttl: Ttl.optional(),
    type: z.enum(REFUSED_TYPES),
    data: z.unknown().optional(),
  }),
]);

/** True when no record uses a signer-owned type. */
export function noSignerOwned(
  records: { type: string }[],
): boolean {
  const refused = new Set<string>(REFUSED_TYPES);
  return !records.some((r) => refused.has(r.type));
}

const DNSSEC_ALGORITHMS = [
  "ecdsap256sha256",
  "ecdsap384sha384",
  "ed25519",
] as const;

/** DNSSEC signing policy for one zone. */
export const DnssecSchema = z.strictObject({
  algorithm: z.enum(DNSSEC_ALGORITHMS).default("ecdsap256sha256").describe(
    "Signing algorithm.",
  ),
  nsec3: z.boolean().default(false).describe("Use NSEC3 instead of NSEC."),
  ksk_lifetime: z.string().regex(/^\d+[dhwmy]$/).optional().describe(
    "KSK lifetime, e.g. 365d.",
  ),
  zsk_lifetime: z.string().regex(/^\d+[dhwmy]$/).optional().describe(
    "ZSK lifetime, e.g. 90d.",
  ),
  parent_ds_check: z.array(z.enum(["ipv4", "ipv6"])).max(2).optional()
    .describe("Families to check the parent DS over."),
});

/** SOA fields; the serial is Knot's. */
export const SoaSchema = z.strictObject({
  primary_ns: FqdnSchema,
  contact: FqdnSchema.describe(
    "RNAME form, e.g. hostmaster.example.com.",
  ),
  refresh: z.number().int().min(1).max(2147483647),
  retry: z.number().int().min(1).max(2147483647),
  expire: z.number().int().min(1).max(2147483647),
  minimum: z.number().int().min(1).max(2147483647),
});

function recordKey(r: ZoneRecord): string {
  return `${r.name}|${r.type}|${renderRdata(r)}`;
}

/** True when the rdata names a domain (kept for reference by callers). */
export function targetOf(r: ZoneRecord): string | undefined {
  switch (r.type) {
    case "CNAME":
    case "NS":
    case "PTR":
      return r.data;
    case "MX":
      return r.data.exchange;
    case "SRV":
      return r.data.target;
    default:
      return undefined;
  }
}

/** Renders one record's rdata in canonical zone-file syntax. */
export function renderRdata(r: ZoneRecord): string {
  switch (r.type) {
    case "A":
      return r.data;
    case "AAAA":
      return canonicalIpv6(r.data);
    case "CNAME":
    case "NS":
    case "PTR":
      return `${stripDot(r.data)}.`;
    case "MX":
      return `${r.data.preference} ${stripDot(r.data.exchange)}.`;
    case "TXT":
      return r.data.map(quoteTxt).join(" ");
    case "SRV":
      return `${r.data.priority} ${r.data.weight} ${r.data.port} ${
        stripDot(r.data.target)
      }.`;
    case "CAA":
      return `${r.data.flags} ${r.data.tag} ${quoteTxt(r.data.value)}`;
    case "DS":
      return `${r.data.key_tag} ${r.data.algorithm} ${r.data.digest_type} ${r.data.digest.toUpperCase()}`;
    case "SSHFP":
      return `${r.data.algorithm} ${r.data.fp_type} ${r.data.fingerprint.toUpperCase()}`;
    case "TLSA":
      return `${r.data.usage} ${r.data.selector} ${r.data.matching_type} ${r.data.certificate.toUpperCase()}`;
  }
}

/**
 * Normalizes one rdata string for comparison, so a formatting difference
 * (case, trailing dot, IPv6 compression, whitespace) is not mistaken for
 * drift.
 */
export function normalizeServedRdata(type: string, data: string): string {
  const t = type.toUpperCase();
  const d = data.trim().replace(/\s+/g, " ");
  if (t === "DS" || t === "SSHFP" || t === "TLSA") return d.toUpperCase();
  if (t === "TXT" || t === "CAA") return d;
  if (t === "A") return d;
  if (t === "AAAA") return canonicalIpv6(d);
  return d.split(" ").map((part) => {
    if (/^[0-9]+$/.test(part) || part.startsWith('"')) return part;
    return `${stripDot(part)}.`;
  }).join(" ");
}

/** Quotes and escapes one character string for a zone file. */
export function quoteTxt(s: string): string {
  return `"${s.replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"`;
}

const TYPE_ORDER: Record<string, number> = {
  A: 1,
  NS: 2,
  CNAME: 5,
  PTR: 12,
  MX: 15,
  TXT: 16,
  AAAA: 28,
  SRV: 33,
  DS: 43,
  SSHFP: 44,
  TLSA: 52,
  CAA: 257,
};

/** Canonical DNS name order (RFC 4034 section 6.1). */
export function canonicalNameCompare(a: string, b: string): number {
  const al = stripDot(a).split(".").reverse();
  const bl = stripDot(b).split(".").reverse();
  const n = Math.min(al.length, bl.length);
  for (let i = 0; i < n; i++) {
    if (al[i] !== bl[i]) return al[i] < bl[i] ? -1 : 1;
  }
  return al.length - bl.length;
}

/**
 * Enforces every semantic rule the spec requires and returns the records
 * deduplicated and in canonical order. Throws with a fixed reason otherwise.
 */
export function canonicalRecords(
  apex: string,
  soa: z.infer<typeof SoaSchema>,
  records: ZoneRecord[],
): ZoneRecord[] {
  const zone = normalizeApex(apex);
  const resolved = records.map((r) => ({
    ...r,
    name: ownerFqdn(zone, r.name),
    ttl: r.ttl ?? soa.minimum,
  }));
  const seen = new Set<string>();
  const unique: typeof resolved = [];
  for (const r of resolved) {
    const key = recordKey(r);
    if (seen.has(key)) continue;
    seen.add(key);
    unique.push(r);
  }
  // No CNAME at the apex; no other data at a CNAME owner.
  for (const r of unique) {
    if (r.type === "CNAME" && stripDot(r.name) === stripDot(zone)) {
      throw new Error("CNAME is not allowed at the zone apex");
    }
  }
  const cnameOwners = new Set(
    unique.filter((r) => r.type === "CNAME").map((r) => r.name),
  );
  for (const r of unique) {
    if (r.type !== "CNAME" && cnameOwners.has(r.name)) {
      throw new Error("a CNAME owner may not hold other data");
    }
  }
  // RRset TTLs must agree.
  const ttlBySet = new Map<string, number>();
  for (const r of unique) {
    const setKey = `${r.name}|${r.type}`;
    const existing = ttlBySet.get(setKey);
    if (existing !== undefined && existing !== r.ttl) {
      throw new Error("records in one RRset must share a TTL");
    }
    ttlBySet.set(setKey, r.ttl);
  }
  // In-zone glue is checked by kzonecheck, not here: NS/MX/SRV targets may
  // legitimately point outside the zone (a reverse zone's NS, for example).
  unique.sort((a, b) => {
    const byName = canonicalNameCompare(a.name, b.name);
    if (byName !== 0) return byName;
    const byType = (TYPE_ORDER[a.type] ?? 999) - (TYPE_ORDER[b.type] ?? 999);
    if (byType !== 0) return byType;
    const ar = renderRdata(a);
    const br = renderRdata(b);
    return ar < br ? -1 : ar > br ? 1 : 0;
  });
  return unique;
}

/** SOA serial rendered into the file; Knot owns the live serial. */
export const PLACEHOLDER_SERIAL = 1;

/**
 * Renders the whole zone file: absolute owner names, explicit TTLs, one
 * `IN <type> <rdata>` line per record, canonical order. No `$ORIGIN`,
 * `$TTL` or `$INCLUDE` directive is ever emitted.
 */
export function canonicalZoneFile(
  apex: string,
  soa: z.infer<typeof SoaSchema>,
  records: ZoneRecord[],
): string {
  const zone = normalizeApex(apex);
  const ordered = canonicalRecords(zone, soa, records);
  const defaultTtl = soa.minimum;
  const lines: string[] = [];
  lines.push(
    `${zone}\t${defaultTtl}\tIN\tSOA\t${stripDot(soa.primary_ns)}. ${
      stripDot(soa.contact)
    }. ( ${PLACEHOLDER_SERIAL} ${soa.refresh} ${soa.retry} ${soa.expire} ${soa.minimum} )`,
  );
  for (const r of ordered) {
    lines.push(
      `${r.name}\t${r.ttl}\tIN\t${r.type}\t${renderRdata(r)}`,
    );
  }
  return `${lines.join("\n")}\n`;
}

/** The comment stamped at the top of every model-managed zone file. */
export const MANAGED_HEADER =
  "; managed by @randybias/knot-dns; edits are overwritten on the next apply\n";

/** The full rendered bytes of a managed zone file. */
export function renderZoneFile(
  apex: string,
  soa: z.infer<typeof SoaSchema>,
  records: ZoneRecord[],
): string {
  return MANAGED_HEADER + canonicalZoneFile(apex, soa, records);
}

/** Inputs that decide the zone's config fragment. */
export interface ZoneConfigInput {
  apex: string;
  file: string;
  signed: boolean;
  dnssec: z.infer<typeof DnssecSchema>;
  notifySecondaries: string[];
  allowTransfer: string[];
  tsigKeyNames: string[];
}

/** A short deterministic hash for building unique config ids. */
function shortHash(s: string): string {
  let h = 5381;
  for (let i = 0; i < s.length; i++) {
    h = ((h << 5) + h + s.charCodeAt(i)) >>> 0;
  }
  return h.toString(16).padStart(8, "0").slice(0, 8);
}

/**
 * Renders the top-level `policy:`/`remote:`/`acl:` sections and the `zone:`
 * entry for one managed zone. Notify targets get one `remote:` each (several
 * addresses in one remote are alternatives, not a fan-out), and an ACL with
 * no TSIG key omits `key:` entirely.
 */
export function renderZoneConfig(input: ZoneConfigInput): string {
  const zone = normalizeApex(input.apex);
  const slug = stripDot(zone).replace(/[^A-Za-z0-9-]/g, "-");
  const base = `managed-${slug}-${shortHash(zone)}`;
  const lines: string[] = [];
  if (input.signed) {
    lines.push("policy:");
    lines.push(`  - id: ${base}`);
    lines.push(`    algorithm: ${input.dnssec.algorithm}`);
    lines.push(`    nsec3: ${input.dnssec.nsec3 ? "on" : "off"}`);
    if (input.dnssec.ksk_lifetime) {
      lines.push(`    ksk-lifetime: ${input.dnssec.ksk_lifetime}`);
    }
    if (input.dnssec.zsk_lifetime) {
      lines.push(`    zsk-lifetime: ${input.dnssec.zsk_lifetime}`);
    }
  }
  const remoteIds: string[] = [];
  if (input.notifySecondaries.length > 0) {
    lines.push("remote:");
    input.notifySecondaries.forEach((addr, i) => {
      const id = `${base}-notify-${i}`;
      remoteIds.push(id);
      lines.push(`  - id: ${id}`);
      lines.push(`    address: ${JSON.stringify(addr)}`);
    });
  }
  const wantsTransfer = input.allowTransfer.length > 0 ||
    input.tsigKeyNames.length > 0;
  if (wantsTransfer) {
    lines.push("acl:");
    lines.push(`  - id: ${base}-transfer`);
    for (const addr of input.allowTransfer) {
      lines.push(`    address: ${JSON.stringify(addr)}`);
    }
    lines.push("    action: transfer");
    if (input.tsigKeyNames.length === 1) {
      lines.push(`    key: ${input.tsigKeyNames[0]}`);
    } else if (input.tsigKeyNames.length > 1) {
      lines.push(`    key: [${input.tsigKeyNames.join(", ")}]`);
    }
  }
  lines.push("zone:");
  lines.push(`  - domain: ${zone}`);
  lines.push(`    file: ${JSON.stringify(input.file)}`);
  lines.push("    zonefile-sync: -1");
  lines.push("    zonefile-load: difference-no-serial");
  lines.push("    journal-content: all");
  lines.push("    serial-policy: unixtime");
  lines.push(`    dnssec-signing: ${input.signed ? "on" : "off"}`);
  if (input.signed) lines.push(`    dnssec-policy: ${base}`);
  if (remoteIds.length > 0) {
    lines.push(`    notify: [${remoteIds.join(", ")}]`);
  }
  if (wantsTransfer) lines.push(`    acl: ${base}-transfer`);
  return `${lines.join("\n")}\n`;
}

/** A `(name, type, rdata)` tuple from a served-vs-declared diff. */
export interface DiffEntry {
  name: string;
  type: string;
  data: string;
}

/** The three-way diff between a served zone and the declared set. */
export interface ZoneDiff {
  added: DiffEntry[];
  removed: DiffEntry[];
}

/** A `(name, type, rdata)` tuple from a served-vs-declared diff. */
export interface DiffEntry {
  name: string;
  type: string;
  data: string;
}

/** The three-way diff between a served zone and the declared set. */
export interface ZoneDiff {
  added: DiffEntry[];
  removed: DiffEntry[];
}

/** The declared records as canonical `(name, type, rdata)` tuples. */
export function declaredTuples(
  apex: string,
  soa: z.infer<typeof SoaSchema>,
  records: ZoneRecord[],
): DiffEntry[] {
  return canonicalRecords(apex, soa, records).map((r) => ({
    name: r.name,
    type: r.type,
    data: normalizeServedRdata(r.type, renderRdata(r)),
  }));
}

function tupleKey(t: DiffEntry): string {
  return `${t.name}|${t.type}|${t.data}`;
}

/**
 * Compares the declared tuples with what `knotc zone-read` served. Only record
 * classes the model owns are considered; the caller excludes the SOA and
 * signer-owned types before calling.
 */
export function diffDeclared(
  declared: DiffEntry[],
  served: DiffEntry[],
): ZoneDiff {
  const want = new Set(declared.map(tupleKey));
  const have = new Set(served.map(tupleKey));
  const added = declared.filter((t) => !have.has(tupleKey(t)));
  const removed = served.filter((t) => !want.has(tupleKey(t)));
  const cmp = (a: DiffEntry, b: DiffEntry) =>
    tupleKey(a) < tupleKey(b) ? -1 : tupleKey(a) > tupleKey(b) ? 1 : 0;
  added.sort(cmp);
  removed.sort(cmp);
  return { added, removed };
}
