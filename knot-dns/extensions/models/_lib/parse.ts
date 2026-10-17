/**
 * Parser for `knotc zone-read` output.
 *
 * The served set is compared with the declared set as canonical
 * `(name, type, rdata)` tuples. Signer-owned types and the SOA are ignored
 * here; the diff caller decides what it owns. Rdata is normalized so a
 * formatting difference (case, trailing dot, whitespace) is not mistaken for
 * drift, while a different value still shows up.
 *
 * @module
 */

import type { DiffEntry } from "./zone.ts";
import { ownerFqdn, stripDot } from "./zone.ts";

/** Types the signer owns and the model never declares. */
const IGNORED = new Set([
  "SOA",
  "RRSIG",
  "NSEC",
  "NSEC3",
  "NSEC3PARAM",
  "DNSKEY",
  "CDS",
  "CDNSKEY",
]);

/** Normalizes one rdata string for comparison. */
export function normalizeServedRdata(type: string, data: string): string {
  const t = type.toUpperCase();
  const d = data.trim().replace(/\s+/g, " ");
  if (t === "DS" || t === "SSHFP" || t === "TLSA") return d.toUpperCase();
  if (t === "TXT" || t === "CAA") return d;
  // Domain-bearing types: lowercase and ensure a trailing dot on the target.
  if (t === "A" || t === "AAAA") return d;
  return d.split(" ").map((part) => {
    if (/^[0-9]+$/.test(part)) return part;
    if (part.startsWith('"')) return part;
    return `${stripDot(part)}.`;
  }).join(" ");
}

/**
 * Parses `knotc zone-read` output into canonical tuples, resolving relative
 * owner names against `apex`.
 */
export function parseZoneRead(text: string, apex: string): DiffEntry[] {
  const out: DiffEntry[] = [];
  for (const raw of text.split("\n")) {
    const line = raw.trim();
    if (!line || line.startsWith(";") || line.startsWith("$")) continue;
    const parts = line.split(/\s+/);
    if (parts.length < 5) continue;
    const owner = parts[0];
    const cls = parts[2].toUpperCase();
    const type = parts[3].toUpperCase();
    const data = parts.slice(4).join(" ");
    if (cls !== "IN" || IGNORED.has(type)) continue;
    out.push({
      name: ownerFqdn(apex, owner),
      type,
      data: normalizeServedRdata(type, data),
    });
  }
  return out;
}

/** Parses `keymgr <zone> ds` output into DS presentation strings. */
export function parseDsLines(text: string): string[] {
  const out: string[] = [];
  for (const raw of text.split("\n")) {
    const line = raw.trim();
    if (!line || line.startsWith(";")) continue;
    if (/\bDS\b/i.test(line)) out.push(line);
  }
  return out;
}
