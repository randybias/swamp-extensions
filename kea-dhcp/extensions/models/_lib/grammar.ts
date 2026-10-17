/**
 * Input grammars for the Kea DHCPv4 extension.
 *
 * Pure, dependency-free predicates and canonicalizers shared by the model
 * schema, the config renderer and the host-side scripts. Values are IPv4
 * literals, CIDRs, MAC addresses, interface names, option payloads and a
 * canonical target key; no host, network or MAC is baked in.
 *
 * @module
 */

/** A rejected input; retrying will not fix it. */
export class KeaInputError extends Error {
  /** Creates a Kea input error. */
  constructor(message: string) {
    super(message);
    this.name = "KeaInputError";
  }
}

const IPV4_RE = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
const CIDR_RE = /^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\/(\d{1,2})$/;
const MAC_RE = /^[0-9a-f]{2}(?::[0-9a-f]{2}){5}$/;
const IFACE_RE = /^[A-Za-z][A-Za-z0-9_.-]{0,14}$/;
const LABEL_RE = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$/;

/** Parses an IPv4 literal to an unsigned 32-bit integer, or null. */
export function parseIpv4(value: string): number | null {
  const match = IPV4_RE.exec(value);
  if (match === null) return null;
  const parts = match.slice(1).map(Number);
  if (parts.some((part) => part > 255)) return null;
  return ((parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]) >>>
    0;
}

/** Renders an unsigned 32-bit integer as a dotted-quad IPv4 literal. */
export function ipv4ToString(value: number): string {
  const n = value >>> 0;
  return `${(n >>> 24) & 255}.${(n >>> 16) & 255}.${(n >>> 8) & 255}.${
    n & 255
  }`;
}

/** True when `value` is a dotted-quad IPv4 literal. */
export function isIpv4(value: string): boolean {
  return parseIpv4(value) !== null;
}

/** A parsed IPv4 CIDR with its network, broadcast and mask. */
export interface Cidr {
  /** The value as written, canonicalized to `network/prefix`. */
  text: string;
  /** Prefix length, 8-30. */
  prefix: number;
  /** Network address as a 32-bit integer. */
  network: number;
  /** Broadcast address as a 32-bit integer. */
  broadcast: number;
  /** Netmask as a 32-bit integer. */
  mask: number;
}

/** Throws unless `value` is an IPv4 literal. */
export function assertIpv4(value: string, field: string): void {
  if (!isIpv4(value)) {
    throw new KeaInputError(`${field} must be an IPv4 address`);
  }
}

/** Parses an IPv4 CIDR in network form with prefix /8-/30, or null. */
export function parseCidr(value: string): Cidr | null {
  const match = CIDR_RE.exec(value);
  if (match === null) return null;
  const base = parseIpv4(match[1]);
  const prefix = Number(match[2]);
  if (base === null || !Number.isInteger(prefix) || prefix < 8 || prefix > 30) {
    return null;
  }
  const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
  const network = (base & mask) >>> 0;
  if (network !== base) return null; // host bits set: not network form
  const broadcast = (network | (~mask >>> 0)) >>> 0;
  return { text: `${match[1]}/${prefix}`, prefix, network, broadcast, mask };
}

/** True when `value` is a canonical IPv4 CIDR (network form, /8-/30). */
export function isCidr(value: string): boolean {
  return parseCidr(value) !== null;
}

/** Throws unless `value` is a canonical IPv4 CIDR. */
export function assertCidr(value: string, field: string): Cidr {
  const cidr = parseCidr(value);
  if (cidr === null) {
    throw new KeaInputError(
      `${field} must be an IPv4 CIDR in network form with a prefix from /8 to /30`,
    );
  }
  return cidr;
}

/** True when `cidr` contains `ip`. */
export function cidrContains(cidr: Cidr, ip: number): boolean {
  return ((ip & cidr.mask) >>> 0) === cidr.network;
}

/** True when two CIDRs overlap. */
export function cidrsOverlap(a: Cidr, b: Cidr): boolean {
  return a.network <= b.broadcast && b.network <= a.broadcast;
}

/** True when `value` is a lowercase unicast MAC address. */
export function isMac(value: string): boolean {
  if (!MAC_RE.test(value)) return false;
  const first = parseInt(value.slice(0, 2), 16);
  return (first & 1) === 0; // not multicast
}

/** Throws unless `value` is a lowercase unicast MAC address. */
export function assertMac(value: string, field: string): void {
  if (!isMac(value)) {
    throw new KeaInputError(
      `${field} must be a lowercase unicast MAC address`,
    );
  }
}

/** True when `value` is a usable network-interface name. */
export function isInterfaceName(value: string): boolean {
  return typeof value === "string" && IFACE_RE.test(value) &&
    !value.includes("*");
}

/** Parses an interface spec `name` or `name/ipv4`, returning its parts. */
export function parseInterface(
  value: string,
): { name: string; address?: string } | null {
  const slash = value.indexOf("/");
  if (slash < 0) {
    return isInterfaceName(value) ? { name: value } : null;
  }
  const name = value.slice(0, slash);
  const address = value.slice(slash + 1);
  if (!isInterfaceName(name) || !isIpv4(address)) return null;
  return { name, address };
}

/** True when `value` is an RFC 1123 host label (<= 63 octets). */
export function isLabel(value: string): boolean {
  return LABEL_RE.test(value) && value.length <= 63;
}

/** True when `value` is an RFC 1123 FQDN (<= 253 octets). */
export function isFqdn(value: string): boolean {
  if (typeof value !== "string" || value.length > 253 || value.endsWith(".")) {
    return false;
  }
  const labels = value.split(".");
  return labels.length >= 1 && labels.every(isLabel);
}

/** A parsed DHCP pool range. */
export interface Pool {
  /** First address, as written. */
  start: string;
  /** Last address, as written. */
  end: string;
  /** First address as an integer. */
  startInt: number;
  /** Last address as an integer. */
  endInt: number;
}

/** Parses `a - b` or `cidr` into a pool inside `subnet`, or null. */
export function parsePool(value: string, subnet: Cidr): Pool | null {
  const range =
    /^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s*-\s*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/
      .exec(value);
  let start: number;
  let end: number;
  let startText: string;
  let endText: string;
  if (range !== null) {
    const a = parseIpv4(range[1]);
    const b = parseIpv4(range[2]);
    if (a === null || b === null || a > b) return null;
    start = a;
    end = b;
    startText = range[1];
    endText = range[2];
  } else {
    const cidr = parseCidr(value);
    if (cidr === null || cidr.prefix > 30) return null;
    start = cidr.network;
    end = cidr.broadcast;
    startText = ipv4ToString(start);
    endText = ipv4ToString(end);
  }
  if (!cidrContains(subnet, start) || !cidrContains(subnet, end)) return null;
  if (start <= subnet.network || end >= subnet.broadcast) return null;
  return { start: startText, end: endText, startInt: start, endInt: end };
}

/** True when two integer ranges overlap. */
export function rangesOverlap(
  aStart: number,
  aEnd: number,
  bStart: number,
  bEnd: number,
): boolean {
  return aStart <= bEnd && bStart <= aEnd;
}

/** Canonical instance key for a target: host lowercased, port and user. */
export function targetKey(host: string, port: number, user: string): string {
  const h = host.toLowerCase();
  return `h${h.length}-${h}-p${port}-u${user.length}-${user}`;
}

/** The typed DHCP options this extension renders. */
export interface OptionValue {
  /** Option name from the allowlist. */
  name: string;
  /** Rendered option data string. */
  data: string;
}

const IPV4_LIST_OPTIONS = new Set([
  "routers",
  "domain-name-servers",
  "ntp-servers",
]);

/**
 * True when `name` is in the closed option allowlist.
 *
 * `classless-static-route` (option 121) is deliberately absent: the stock Kea
 * 2.4 option dictionary has no definition for it, so `kea-dhcp4 -t` refuses a
 * config that names it. Supporting it would require an `option-def` and the
 * record data format, which is out of scope for this release.
 */
export function isKnownOption(name: string): boolean {
  return IPV4_LIST_OPTIONS.has(name) || name === "domain-name" ||
    name === "domain-search" || name === "interface-mtu";
}

const HOOK_BASENAME_RE = /^libdhcp_[A-Za-z0-9_.-]+\.so$/;

/**
 * True when `value` names a Kea hook library in a hooks directory.
 *
 * The value must be absolute, free of `..` and whitespace, live in a path
 * segment named `hooks`, and have the packaged `libdhcp_*.so` basename. The
 * exact directory is confirmed against the host in the model, because loading a
 * hook runs its code as root during `kea-dhcp4 -t`.
 */
export function isHookLibraryPath(value: string): boolean {
  if (typeof value !== "string" || value.length < 2 || value.length > 4096) {
    return false;
  }
  if (!value.startsWith("/") || value.includes("..") || /\s/.test(value)) {
    return false;
  }
  if (!value.includes("/hooks/")) return false;
  const base = value.slice(value.lastIndexOf("/") + 1);
  return HOOK_BASENAME_RE.test(base);
}

/**
 * Renders one typed option value to Kea's option-data string. Throws on an
 * unknown name or a malformed value; `subnet` is required for `routers`.
 */
export function renderOption(
  input: { name: string; value: unknown },
  subnet?: Cidr,
): OptionValue {
  const { name, value } = input;
  if (!isKnownOption(name)) {
    throw new KeaInputError(`unknown DHCP option: ${name}`);
  }
  if (name === "domain-name") {
    if (typeof value !== "string" || !isFqdn(value)) {
      throw new KeaInputError("domain-name must be an FQDN");
    }
    return { name, data: value };
  }
  if (name === "interface-mtu") {
    if (typeof value !== "number" || value < 576 || value > 9216) {
      throw new KeaInputError("interface-mtu must be 576-9216");
    }
    return { name, data: String(value) };
  }
  if (name === "domain-search") {
    if (!Array.isArray(value) || value.length === 0) {
      throw new KeaInputError("domain-search must be a non-empty FQDN list");
    }
    const values = value.map((entry) => {
      if (typeof entry !== "string" || !isFqdn(entry)) {
        throw new KeaInputError("domain-search entries must be FQDNs");
      }
      return entry;
    });
    return { name, data: values.join(", ") };
  }
  // IPv4 list options.
  if (!Array.isArray(value) || value.length === 0) {
    throw new KeaInputError(`${name} must be a non-empty IPv4 list`);
  }
  const addresses = value.map((entry) => {
    const ip = typeof entry === "string" ? parseIpv4(entry) : null;
    if (ip === null) throw new KeaInputError(`${name} entries must be IPv4`);
    if (
      name === "routers" && subnet !== undefined && !cidrContains(subnet, ip)
    ) {
      throw new KeaInputError(`${name} must be inside its subnet`);
    }
    return entry as string;
  });
  return { name, data: addresses.join(", ") };
}
