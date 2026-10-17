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
const CIDR_RE = /^(.+)\/(\d{1,3})$/;
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
const MAX_TEXT = 4096;

/** True when `s` is a syntactically valid IPv4 or IPv6 CIDR block. */
export function isCidr(s: string): boolean {
  const m = CIDR_RE.exec(s);
  if (!m) return false;
  const bits = Number(m[2]);
  const addr = m[1];
  if (addr.includes(":")) {
    if (bits > 128) return false;
    try {
      new URL(`http://[${addr}]`);
      return true;
    } catch {
      return false;
    }
  }
  return bits <= 32 && ADDR_V4.test(addr);
}

/** True when the CIDR covers every address (`0.0.0.0/0` or `::/0`). */
export function isDefaultRoute(s: string): boolean {
  return s === "0.0.0.0/0" || s === "::/0";
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
