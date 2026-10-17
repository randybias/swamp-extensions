/**
 * Strict CIDR parsing and overlap checks for IPv4 and IPv6.
 *
 * @module
 */

/** A parsed CIDR: address family, prefix length and the masked network. */
export interface Cidr {
  /** 4 or 6. */
  family: 4 | 6;
  /** Prefix length in bits. */
  prefix: number;
  /** Network address (host bits cleared) as an integer. */
  network: bigint;
}

const V4_OCTET = /^(0|[1-9][0-9]{0,2})$/;

function parseV4(text: string): bigint | null {
  const parts = text.split(".");
  if (parts.length !== 4) return null;
  let n = 0n;
  for (const p of parts) {
    if (!V4_OCTET.test(p) || Number(p) > 255) return null;
    n = (n << 8n) | BigInt(p);
  }
  return n;
}

function parseV6(text: string): bigint | null {
  if (!/^[0-9A-Fa-f:]+$/.test(text) || text.includes(":::")) return null;
  const halves = text.split("::");
  if (halves.length > 2) return null;
  const groups = (s: string) => (s === "" ? [] : s.split(":"));
  const head = groups(halves[0]);
  const tail = halves.length === 2 ? groups(halves[1]) : [];
  const total = head.length + tail.length;
  if (halves.length === 1 ? total !== 8 : total > 7) return null;
  const all = [
    ...head,
    ...Array(8 - total).fill("0"),
    ...tail,
  ];
  let n = 0n;
  for (const g of all) {
    if (!/^[0-9A-Fa-f]{1,4}$/.test(g)) return null;
    n = (n << 16n) | BigInt(parseInt(g, 16));
  }
  return n;
}

/** Parses `addr/prefix`; returns null when it is not a valid CIDR. */
export function parseCidr(text: string): Cidr | null {
  const m = /^([^/]+)\/(0|[1-9][0-9]{0,2})$/.exec(text);
  if (!m) return null;
  const v6 = m[1].includes(":");
  const bits = v6 ? 128 : 32;
  const prefix = Number(m[2]);
  if (prefix > bits) return null;
  const addr = v6 ? parseV6(m[1]) : parseV4(m[1]);
  if (addr === null) return null;
  const hostBits = BigInt(bits - prefix);
  return {
    family: v6 ? 6 : 4,
    prefix,
    network: (addr >> hostBits) << hostBits,
  };
}

/** True when two CIDRs of the same family share any address. */
export function overlaps(a: Cidr, b: Cidr): boolean {
  if (a.family !== b.family) return false;
  const bits = a.family === 4 ? 32 : 128;
  const shift = BigInt(bits - Math.min(a.prefix, b.prefix));
  return (a.network >> shift) === (b.network >> shift);
}
