/**
 * Read-only parsing of Kea DHCPv4 leases.
 *
 * Two sources are supported: the memfile CSV (`kea-leases4.csv` plus the `.2`
 * file written during cleanup), and the `lease_cmds` hook's JSON answer. Both
 * parsers are pure; neither ever writes a lease.
 *
 * @module
 */

import { KeaInputError } from "./grammar.ts";

/** One lease row, normalized. */
export interface Lease {
  /** Lease address. */
  ip_address: string;
  /** Client MAC address, lowercased, or empty for a client-id-only lease. */
  hw_address: string;
  /** Client hostname, when present. */
  hostname?: string;
  /** Subnet id that owns the address. */
  subnet_id: number;
  /** Absolute expiry, ISO 8601. */
  expires_at: string;
  /** Lease state. */
  state: "default" | "declined" | "expired-reclaimed" | "unknown";
}

/** A filter for {@link filterLeases}. */
export interface LeaseFilter {
  /** Keep only this subnet id. */
  subnet_id?: number;
  /** Keep only this address. */
  ip_address?: string;
  /** Keep only this MAC address. */
  hw_address?: string;
}

const HEADER = "address,hwaddr,client_id,valid_lifetime,expire,subnet_id";

/** Maps Kea's numeric lease state to a stable name. */
function stateName(value: string): Lease["state"] {
  switch (value.trim()) {
    case "0":
      return "default";
    case "1":
      return "declined";
    case "2":
      return "expired-reclaimed";
    default:
      return "unknown";
  }
}

/** Parses one memfile CSV into rows, newest last. */
export function parseLeaseCsv(text: string): Lease[] {
  const leases: Lease[] = [];
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (line === "" || line.startsWith("#") || line.startsWith(HEADER)) {
      continue;
    }
    const fields = line.split(",");
    if (fields.length < 6) continue;
    const [address, hwaddr, , , expire, subnet] = fields;
    const epoch = Number(expire);
    const subnetId = Number(subnet);
    if (!Number.isFinite(epoch) || !Number.isInteger(subnetId)) continue;
    leases.push({
      ip_address: address,
      hw_address: hwaddr.toLowerCase(),
      hostname: fields[8] ? fields[8] : undefined,
      subnet_id: subnetId,
      expires_at: new Date(epoch * 1000).toISOString(),
      state: fields.length > 9 ? stateName(fields[9]) : "default",
    });
  }
  return leases;
}

/**
 * Collapses the append log of one or more CSV files into the latest row per
 * address and drops rows already expired at `nowSeconds`.
 */
export function parseLeaseCsvFiles(
  texts: string[],
  nowSeconds: number,
): Lease[] {
  const latest = new Map<string, Lease>();
  for (const text of texts) {
    for (const lease of parseLeaseCsv(text)) {
      latest.set(lease.ip_address, lease);
    }
  }
  const now = nowSeconds * 1000;
  return [...latest.values()].filter((lease) =>
    Date.parse(lease.expires_at) > now
  ).sort((a, b) => a.ip_address.localeCompare(b.ip_address));
}

/** Extracts the lease array from a `lease_cmds` JSON answer. */
export function parseLeaseJson(body: unknown): Lease[] {
  if (!body || typeof body !== "object") {
    throw new KeaInputError("lease_cmds answer is not an object");
  }
  const record = body as Record<string, unknown>;
  const args = record.arguments && typeof record.arguments === "object"
    ? record.arguments as Record<string, unknown>
    : record;
  const rows = args.leases;
  if (!Array.isArray(rows)) {
    throw new KeaInputError("lease_cmds answer has no leases array");
  }
  return rows.flatMap((row) => {
    if (!row || typeof row !== "object") return [];
    const entry = row as Record<string, unknown>;
    const address = entry["ip-address"] ?? entry.ip_address;
    const subnet = entry["subnet-id"] ?? entry.subnet_id;
    const cltt = entry["cltt"] ?? entry.cltt;
    const validLft = entry["valid-lft"] ?? entry.valid_lft;
    const expire = entry.expire ?? entry["expire"];
    if (typeof address !== "string" || typeof subnet !== "number") return [];
    const epoch = typeof cltt === "number"
      ? cltt + (typeof validLft === "number" ? validLft : 3600)
      : (typeof expire === "number" ? expire : undefined);
    return [{
      ip_address: address,
      hw_address: typeof entry["hw-address"] === "string"
        ? entry["hw-address"].toLowerCase()
        : "",
      hostname: typeof entry.hostname === "string" ? entry.hostname : undefined,
      subnet_id: subnet,
      expires_at: new Date((epoch ?? 0) * 1000).toISOString(),
      state: "default" as const,
    }];
  });
}

/** Applies a lease filter. */
export function filterLeases(leases: Lease[], filter: LeaseFilter): Lease[] {
  return leases.filter((lease) =>
    (filter.subnet_id === undefined || lease.subnet_id === filter.subnet_id) &&
    (filter.ip_address === undefined ||
      lease.ip_address === filter.ip_address) &&
    (filter.hw_address === undefined ||
      lease.hw_address === filter.hw_address.toLowerCase())
  );
}
