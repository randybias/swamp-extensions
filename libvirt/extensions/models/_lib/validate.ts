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
const URI_SCHEME_PATTERN = "(?:qemu|test|xen|lxc|vbox|bhyve)";
/**
 * Grammar for an accepted libvirt connection URI. Local connection schemes
 * only: a `+ssh`/`+tls` remote URI or a URI query parameter (`command=`,
 * `keyfile=`, `no_verify=`, a userinfo section) would make the remote libvirt
 * open a connection of its own, outside this extension's host-key policy, so
 * those are rejected here.
 */
export const URI_RE = new RegExp(
  `^${URI_SCHEME_PATTERN}:///[A-Za-z0-9._/-]{0,120}$`,
);
/** Grammar for a colon-separated MAC address. */
export const MAC_ADDRESS_RE = MAC_RE;
/** Grammar for a dotted-quad IPv4 address. */
export const IPV4_ADDRESS_RE = IPV4_RE;

/** Libvirt connection URI schemes this extension accepts (local only). */
export const URI_SCHEMES = [
  "qemu",
  "test",
  "xen",
  "lxc",
  "vbox",
  "bhyve",
] as const;

/** Guest architectures accepted for a rendered domain's `<type arch='...'>`. */
export const ARCHES = [
  "x86_64",
  "aarch64",
  "i686",
  "ppc64le",
  "s390x",
] as const;

/** Grammar for a DNS domain written into a network's DHCP block. */
export const DNS_NAME_RE =
  /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$/;

/** Forward modes accepted for a structured network definition. */
export const NETWORK_MODES = ["nat", "route", "bridge", "none"] as const;

/** Disk formats accepted for a rendered domain. */
export const DISK_FORMATS = ["qcow2", "raw"] as const;

/** Bus types accepted for a rendered domain disk. */
export const DISK_BUSES = ["virtio", "sata", "scsi", "ide"] as const;

/** Linux interface-name limit (IFNAMSIZ): a bridge name must fit in 15 chars. */
export const IFNAME_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,14}$/;

/** Grammar for an absolute backing-file path. */
const DISK_PATH_RE = /^\/[A-Za-z0-9._/-]{1,255}$/;

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

/** Throws unless `s` is one of the accepted guest architectures. */
export function assertArch(s: string): void {
  if (!(ARCHES as readonly string[]).includes(s)) {
    throw new LibvirtConfigError(
      `Not an accepted guest architecture: ${s} (expected one of ${
        ARCHES.join(", ")
      })`,
    );
  }
}

/** Throws unless `s` is a DNS name safe for a single-quoted XML attribute. */
export function assertDnsName(s: string): void {
  if (s.length > 253 || !DNS_NAME_RE.test(s)) {
    throw new LibvirtConfigError(`Not a DNS name: ${s}`);
  }
}

/** True when `s` is a dotted-quad IPv4 address. */
export function isIpv4(s: string): boolean {
  return IPV4_RE.test(s);
}

/** Throws unless `s` is a bridge interface name within the IFNAMSIZ limit. */
export function assertIfname(s: string, what = "bridge name"): void {
  if (!IFNAME_RE.test(s)) {
    throw new LibvirtConfigError(
      `Not a valid ${what} (max 15 chars): ${JSON.stringify(s)}`,
    );
  }
}

/** Throws unless `s` is an absolute backing-file path with no `..` component. */
export function assertDiskPath(s: string, what = "disk path"): void {
  if (
    !DISK_PATH_RE.test(s) || s.endsWith("/") ||
    s.split("/").includes("..")
  ) {
    throw new LibvirtConfigError(`Not a valid ${what}: ${JSON.stringify(s)}`);
  }
}

/** Throws unless `bus` is an accepted disk bus. */
export function assertDiskBus(bus: string): void {
  if (!(DISK_BUSES as readonly string[]).includes(bus)) {
    throw new LibvirtConfigError(
      `Not an accepted disk bus: ${bus} (expected one of ${
        DISK_BUSES.join(", ")
      })`,
    );
  }
}

/** Throws unless `format` is an accepted disk format. */
export function assertDiskFormat(format: string): void {
  if (!(DISK_FORMATS as readonly string[]).includes(format)) {
    throw new LibvirtConfigError(
      `Not an accepted disk format: ${format} (expected one of ${
        DISK_FORMATS.join(", ")
      })`,
    );
  }
}
