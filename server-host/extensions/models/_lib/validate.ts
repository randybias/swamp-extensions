/**
 * Grammar validators for every caller-supplied value that reaches a remote
 * command. Each is pure and total: it returns a boolean for schemas and throws
 * {@link HostConfigError} from the `assert*` forms. Values that pass are still
 * passed to the transport as separate argv words, never interpolated into a
 * shell string, so a metacharacter that slips a grammar is still quoted.
 *
 * @module
 */

/** A caller input that fails its allowlist grammar or a cross-field rule. */
export class HostConfigError extends Error {
  /** Creates a configuration error with a message safe to show a caller. */
  constructor(message: string) {
    super(message);
    this.name = "HostConfigError";
  }
}

const V4_OCTET = "(?:25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)";
const ADDR_V4 = new RegExp(`^(?:${V4_OCTET}\\.){3}${V4_OCTET}$`);
/** Grammar for Debian package names. */
export const PACKAGE_RE = /^[a-z0-9][a-z0-9+.-]{0,63}(?::[a-z0-9-]{1,32})?$/;
/** Grammar for conventional POSIX account names. */
export const USER_RE = /^[a-z_][a-z0-9_-]{0,31}$/;
/** Grammar for a dotted sysctl key. */
export const SYSCTL_KEY_RE = /^[a-z][a-z0-9_]*(?:\.[a-z0-9_]+)*$/;
/** Grammar for a shell-free sysctl value. */
export const SYSCTL_VALUE_RE = /^[A-Za-z0-9][A-Za-z0-9 ._:/-]{0,127}$/;
/** Grammar for an IANA time zone name or `UTC`. */
export const TIMEZONE_RE =
  /^[A-Za-z][A-Za-z0-9_+-]{0,31}(?:\/[A-Za-z0-9_+-]{1,31})?$/;
const KEY_TYPE =
  "(?:ssh-ed25519|ssh-rsa|ssh-dss|ecdsa-sha2-nistp(?:256|384|521)|sk-ssh-ed25519@openssh\\.com|sk-ecdsa-sha2-nistp256@openssh\\.com)";
/** Grammar for one authorized_keys line with no options prefix. */
export const AUTHORIZED_KEY_RE = new RegExp(
  `^${KEY_TYPE} [A-Za-z0-9+/]{16,}={0,3}(?: [^\\r\\n]{0,255})?$`,
);
/**
 * Grammar for a trusted interface pattern: an interface name of up to 15
 * characters, optionally ending in one `*` wildcard (nft's `iifname "cali*"`).
 * At least one literal character must precede the wildcard, so `*` alone,
 * which would trust every interface, is not accepted.
 */
export const IFACE_PATTERN_RE =
  /^[A-Za-z0-9_.-]{1,14}\*$|^[A-Za-z0-9_.-]{1,15}$/;
const MAX_TEXT = 4096;

/** A parsed CIDR: family, prefix length and the masked network address. */
export interface ParsedCidr {
  /** Address family. */
  family: 4 | 6;
  /** Prefix length in bits. */
  prefix: number;
  /** Network address (host bits cleared) as an integer. */
  network: bigint;
}

function parseV4(addr: string): bigint | null {
  if (!ADDR_V4.test(addr)) return null;
  return addr.split(".").reduce((n, o) => (n << 8n) | BigInt(o), 0n);
}

const HEX_GROUP = /^[0-9A-Fa-f]{1,4}$/;

/** Strict IPv6 grammar: hex groups, at most one `::`, optional trailing dotted IPv4. */
function parseV6(addr: string): bigint | null {
  if (!/^[0-9A-Fa-f:.]+$/.test(addr)) return null;
  const halves = addr.split("::");
  if (halves.length > 2) return null;
  const words = (part: string): number[] | null => {
    if (part === "") return [];
    const out: number[] = [];
    const groups = part.split(":");
    for (let i = 0; i < groups.length; i++) {
      const g = groups[i];
      if (g.includes(".")) {
        // A dotted IPv4 tail is only valid as the very last group.
        const v4 = i === groups.length - 1 ? parseV4(g) : null;
        if (v4 === null) return null;
        out.push(Number(v4 >> 16n), Number(v4 & 0xffffn));
      } else if (HEX_GROUP.test(g)) {
        out.push(parseInt(g, 16));
      } else {
        return null;
      }
    }
    return out;
  };
  const head = words(halves[0]);
  const tail = halves.length === 2 ? words(halves[1]) : [];
  if (head === null || tail === null) return null;
  if (halves.length === 2 && halves[0].includes(".")) return null;
  const total = head.length + tail.length;
  if (halves.length === 1 ? total !== 8 : total > 7) return null;
  const all = [...head, ...Array(8 - total).fill(0), ...tail];
  return all.reduce((n, w) => (n << 16n) | BigInt(w), 0n);
}

/** Parses a CIDR with a strict grammar; null when it is not one. */
export function parseCidr(s: string): ParsedCidr | null {
  const m = /^([0-9A-Fa-f:.]+)\/(\d{1,3})$/.exec(s);
  if (!m) return null;
  const v6 = m[1].includes(":");
  const bits = v6 ? 128 : 32;
  const prefix = Number(m[2]);
  if (prefix > bits) return null;
  const addr = v6 ? parseV6(m[1]) : parseV4(m[1]);
  if (addr === null) return null;
  const host = BigInt(bits - prefix);
  return { family: v6 ? 6 : 4, prefix, network: (addr >> host) << host };
}

/** True when `s` is a syntactically valid IPv4 or IPv6 CIDR block. */
export function isCidr(s: string): boolean {
  return parseCidr(s) !== null;
}

/**
 * True when the CIDR has a numerically zero prefix, so it covers every address
 * of its family whatever the spelling (`0.0.0.0/0`, `::/0`, `0:0:0:0:0:0:0:0/00`,
 * `192.0.2.0/0`). Assumes `s` already passed {@link isCidr}.
 */
export function isDefaultRoute(s: string): boolean {
  return parseCidr(s)?.prefix === 0;
}

/** Shortest prefixes accepted without acknowledging "SSH from anywhere". */
export const MIN_PREFIX = { 4: 8, 6: 16 } as const;

/**
 * True when `cidrs` open the SSH port to (nearly) everyone: any network wider
 * than {@link MIN_PREFIX}, or a family whose networks together cover the whole
 * address space, such as `0.0.0.0/1` plus `128.0.0.0/1`.
 */
export function isEffectivelyAnywhere(cidrs: readonly string[]): boolean {
  const parsed = cidrs.map(parseCidr).filter((c): c is ParsedCidr =>
    c !== null
  );
  if (parsed.some((c) => c.prefix < MIN_PREFIX[c.family])) return true;
  for (const family of [4, 6] as const) {
    const bits = family === 4 ? 32 : 128;
    const spans = parsed.filter((c) => c.family === family).map((c) => ({
      lo: c.network,
      hi: c.network + (1n << BigInt(bits - c.prefix)) - 1n,
    })).sort((a, b) => (a.lo < b.lo ? -1 : a.lo > b.lo ? 1 : 0));
    let next = 0n;
    for (const sp of spans) {
      if (sp.lo > next) break;
      if (sp.hi + 1n > next) next = sp.hi + 1n;
    }
    if (spans.length > 0 && next >= (1n << BigInt(bits))) return true;
  }
  return false;
}

/** Throws unless `s` is a valid CIDR block. */
export function assertCidr(s: string): void {
  if (!isCidr(s)) throw new HostConfigError(`Not a CIDR block: ${s}`);
}

/** True when `n` is an integer TCP/UDP port in 1-65535. */
export function isPort(n: number): boolean {
  return Number.isInteger(n) && n >= 1 && n <= 65535;
}

/** Throws unless `n` is an integer port in 1-65535. */
export function assertPort(n: number): void {
  if (!isPort(n)) throw new HostConfigError(`Not a port: ${n}`);
}

/** Throws unless `s` is a valid Debian package name. */
export function assertPackage(s: string): void {
  if (!PACKAGE_RE.test(s)) {
    throw new HostConfigError(`Not a package name: ${s}`);
  }
}

/** Throws unless `s` is a conventional POSIX account name. */
export function assertUser(s: string): void {
  if (!USER_RE.test(s)) throw new HostConfigError(`Not a user name: ${s}`);
}

/** Throws unless `s` is a dotted sysctl key such as `net.ipv4.ip_forward`. */
export function assertSysctlKey(s: string): void {
  if (!SYSCTL_KEY_RE.test(s)) {
    throw new HostConfigError(`Not a sysctl key: ${s}`);
  }
}

/** Throws unless `s` is a sysctl value free of shell and newline characters. */
export function assertSysctlValue(s: string): void {
  if (s.length > 128 || !SYSCTL_VALUE_RE.test(s)) {
    throw new HostConfigError(`Not a sysctl value: ${s}`);
  }
}

/** Throws unless `s` is an IANA time zone name or `UTC`. */
export function assertTimezone(s: string): void {
  if (s.length > 64 || !TIMEZONE_RE.test(s)) {
    throw new HostConfigError(`Not a time zone: ${s}`);
  }
}

/** Throws unless `s` is one authorized_keys line with no options prefix. */
export function assertAuthorizedKey(s: string): void {
  if (s.length > MAX_TEXT || !AUTHORIZED_KEY_RE.test(s)) {
    throw new HostConfigError("Not an SSH public key line");
  }
}

/** Returns a new array with duplicates removed and a stable sort applied. */
export function dedupeSorted(values: readonly string[]): string[] {
  return [...new Set(values)].sort();
}

/** Returns `values` with duplicates removed and a stable numeric sort applied. */
export function dedupeSortedNumbers(values: readonly number[]): number[] {
  return [...new Set(values)].sort((a, b) => a - b);
}

/** Throws unless `s` is a valid trusted interface pattern. */
export function assertIfacePattern(s: string): void {
  if (!IFACE_PATTERN_RE.test(s) || s.startsWith("-")) {
    throw new HostConfigError(`Not an interface name or pattern: ${s}`);
  }
}
