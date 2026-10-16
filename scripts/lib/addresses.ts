/** Kinds of network identifier the scanners look for. */
export type AddrKind = "ipv4" | "ipv6" | "mac";

/** One address literal found in a text. */
export interface AddrHit {
  kind: AddrKind;
  value: string;
  /** 1-based line number. */
  line: number;
  /** True when the value is in a documentation or placeholder range. */
  documentation: boolean;
}

const IPV4 = /(?<![\d.])(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(?!\d|\.\d)/g;
const IPV6 = /(?<![0-9A-Za-z:])[0-9A-Fa-f:]*:[0-9A-Fa-f:]*(?![0-9A-Za-z:])/g;
const MAC =
  /(?<![0-9A-Fa-f:-])[0-9A-Fa-f]{2}([:-])(?:[0-9A-Fa-f]{2}\1){4}[0-9A-Fa-f]{2}(?![0-9A-Fa-f:-])/g;

function toInt(o: number[]): number {
  return ((o[0] << 24) | (o[1] << 16) | (o[2] << 8) | o[3]) >>> 0;
}

function inCidr(o: number[], base: number[], bits: number): boolean {
  const mask = bits === 0 ? 0 : (~0 << (32 - bits)) >>> 0;
  return ((toInt(o) & mask) >>> 0) === ((toInt(base) & mask) >>> 0);
}

/** True for RFC 1918, CGNAT (100.64/10) and link-local (169.254/16) IPv4. */
export function isPrivateIpv4(value: string): boolean {
  const o = value.split(".").map(Number);
  return inCidr(o, [10, 0, 0, 0], 8) || inCidr(o, [172, 16, 0, 0], 12) ||
    inCidr(o, [192, 168, 0, 0], 16) || inCidr(o, [100, 64, 0, 0], 10) ||
    inCidr(o, [169, 254, 0, 0], 16);
}

/** True for IPv6 unique-local (fc00::/7) and link-local (fe80::/10) addresses. */
export function isPrivateIpv6(value: string): boolean {
  const l = value.toLowerCase();
  return /^f[cd][0-9a-f]{0,2}:/.test(l) || /^fe[89ab][0-9a-f]?:/.test(l);
}

function ipv4Doc(o: number[]): boolean {
  const v = o.join(".");
  return inCidr(o, [192, 0, 2, 0], 24) || inCidr(o, [198, 51, 100, 0], 24) ||
    inCidr(o, [203, 0, 113, 0], 24) || inCidr(o, [127, 0, 0, 0], 8) ||
    v === "0.0.0.0" || v === "255.255.255.255";
}

function validIpv6(v: string): boolean {
  if (!v.includes("::") && (v.match(/:/g) ?? []).length !== 7) return false;
  try {
    new URL(`http://[${v}]`);
    return true;
  } catch {
    return false;
  }
}

function ipv6Doc(v: string): boolean {
  const l = v.toLowerCase();
  return l === "::1" || l === "::" || /^2001:0?db8:/.test(l);
}

function macDoc(v: string): boolean {
  const l = v.toLowerCase().replaceAll("-", ":");
  return l.startsWith("00:00:5e:00:53:") || l.startsWith("02:00:00:");
}

/** Find every IPv4, IPv6 and MAC literal in `text`, classified as documentation-safe or not. */
export function findAddresses(text: string): AddrHit[] {
  const hits: AddrHit[] = [];
  text.split("\n").forEach((src, i) => {
    const line = i + 1;
    const found: { at: number; hit: AddrHit }[] = [];
    for (const m of src.matchAll(IPV4)) {
      const o = [m[1], m[2], m[3], m[4]].map(Number);
      if (o.some((x) => x > 255)) continue;
      found.push({
        at: m.index,
        hit: { kind: "ipv4", value: m[0], line, documentation: ipv4Doc(o) },
      });
    }
    for (const m of src.matchAll(MAC)) {
      found.push({
        at: m.index,
        hit: { kind: "mac", value: m[0], line, documentation: macDoc(m[0]) },
      });
    }
    for (const m of src.matchAll(IPV6)) {
      if (!validIpv6(m[0])) continue;
      found.push({
        at: m.index,
        hit: { kind: "ipv6", value: m[0], line, documentation: ipv6Doc(m[0]) },
      });
    }
    found.sort((a, b) => a.at - b.at).forEach((f) => hits.push(f.hit));
  });
  return hits;
}
