/**
 * Parser for `knotc zone-read` output.
 *
 * Real `knotc zone-read <zone>` prints one record per line with no class
 * column: `owner ttl TYPE rdata` (some builds prefix the zone in brackets).
 * Signer-owned types and the SOA are ignored here; the diff caller decides
 * what it owns. Rdata is normalized (IPv6 compressed, hex uppercased, targets
 * dotted) so a formatting difference is not mistaken for drift.
 *
 * @module
 */

import type { DiffEntry } from "./zone.ts";
import { normalizeServedRdata, ownerFqdn } from "./zone.ts";

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

/**
 * Parses `knotc zone-read` output into canonical tuples, resolving relative
 * owner names against `apex` and tolerating an optional `IN` class column.
 */
export function parseZoneRead(text: string, apex: string): DiffEntry[] {
  const out: DiffEntry[] = [];
  for (const raw of text.split("\n")) {
    let line = raw.trim();
    if (!line || line.startsWith(";") || line.startsWith("$")) continue;
    if (line.startsWith("[")) {
      const end = line.indexOf("]");
      if (end !== -1) line = line.slice(end + 1).trim();
    }
    const parts = line.split(/\s+/);
    if (parts.length < 4) continue;
    let i = 0;
    const owner = parts[i++];
    i++; // ttl
    if (parts[i]?.toUpperCase() === "IN") i++;
    const type = (parts[i++] ?? "").toUpperCase();
    const data = parts.slice(i).join(" ");
    if (!type || IGNORED.has(type)) continue;
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
