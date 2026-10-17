/**
 * Grammar validators for every caller-supplied value that reaches `virsh`.
 * Each is pure and total. Values that pass are still passed to the transport
 * as separate argv words, never interpolated into a shell string, so a
 * metacharacter that slips a grammar is still quoted.
 *
 * @module
 */

/** A caller input that fails its allowlist grammar or a cross-field rule. */
export class LibvirtConfigError extends Error {
  /** Creates a configuration error with a message safe to show a caller. */
  constructor(message: string) {
    super(message);
    this.name = "LibvirtConfigError";
  }
}

/** Grammar for a libvirt object name: domain, network, pool or volume. */
export const NAME_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$/;
const MAC_RE = /^(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$/;
const IPV4_RE =
  /^(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$/;
const CIDR_SCHEME =
  "(?:qemu|qemu\\+ssh|qemu\\+tls|qemu\\+unix|xen|xen\\+ssh|vbox|bhyve|lxc|lxc\\+ssh|test)";
/** Grammar for an accepted libvirt connection URI. */
export const URI_RE = new RegExp(
  `^${CIDR_SCHEME}://[A-Za-z0-9._~:@%/?=&#\\[\\]-]{0,200}$`,
);
/** Grammar for a colon-separated MAC address. */
export const MAC_ADDRESS_RE = MAC_RE;
/** Grammar for a dotted-quad IPv4 address. */
export const IPV4_ADDRESS_RE = IPV4_RE;

/** Libvirt connection URI schemes this extension accepts. */
export const URI_SCHEMES = [
  "qemu",
  "qemu+ssh",
  "qemu+tls",
  "qemu+unix",
  "xen",
  "xen+ssh",
  "vbox",
  "bhyve",
  "lxc",
  "lxc+ssh",
  "test",
] as const;

/** Forward modes accepted for a structured network definition. */
export const NETWORK_MODES = ["nat", "route", "bridge", "none"] as const;

/** Disk formats accepted for a rendered domain. */
export const DISK_FORMATS = ["qcow2", "raw"] as const;

/** Throws unless `s` is a valid libvirt object name. */
export function assertName(s: string, what = "name"): void {
  if (!NAME_RE.test(s)) {
    throw new LibvirtConfigError(`Not a valid ${what}: ${JSON.stringify(s)}`);
  }
}

/** Throws unless `s` is an accepted libvirt connection URI. */
export function assertUri(s: string): void {
  if (s.length > 240 || !URI_RE.test(s)) {
    throw new LibvirtConfigError(`Not a valid libvirt URI: ${s}`);
  }
}

/** Throws unless `s` is a colon-separated MAC address. */
export function assertMac(s: string): void {
  if (!MAC_RE.test(s)) {
    throw new LibvirtConfigError(`Not a MAC address: ${s}`);
  }
}

/** Throws unless `s` is a dotted-quad IPv4 address. */
export function assertIpv4(s: string): void {
  if (!IPV4_RE.test(s)) {
    throw new LibvirtConfigError(`Not an IPv4 address: ${s}`);
  }
}

/** True when `s` is a dotted-quad IPv4 address. */
export function isIpv4(s: string): boolean {
  return IPV4_RE.test(s);
}
