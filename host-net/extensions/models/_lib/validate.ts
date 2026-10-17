/**
 * Grammar and cross-field validation for `@randybias/host-net`. Every
 * caller-supplied value that reaches a host script is checked here before any
 * remote call, and each value is still passed as a quoted argv word or script
 * literal.
 *
 * @module
 */

/** A configuration value that fails its grammar or a cross-field rule. */
export class HostNetConfigError extends Error {
  /** Creates a configuration error safe to show a caller. */
  constructor(message: string) {
    super(message);
    this.name = "HostNetConfigError";
  }
}

/** Kernel interface name: 1-15 chars, no `/ :` or whitespace. */
export const IFACE_RE = /^[A-Za-z][A-Za-z0-9_.-]{0,14}$/;
/** Lowercase unicast MAC. */
export const MAC_RE = /^[0-9a-f]{2}(:[0-9a-f]{2}){5}$/;
/** Placeholder token used inside host scripts. */
export const TOKEN_RE = /^[0-9a-f]{16}$/;

/** True when `name` is a valid interface or bridge name. */
export function isIface(name: string): boolean {
  if (name === "." || name === "..") return false;
  return IFACE_RE.test(name);
}

/** Throws unless `name` is a valid interface or bridge name. */
export function assertIface(name: string, what = "interface"): void {
  if (!isIface(name)) {
    throw new HostNetConfigError(
      `not a valid ${what} name: ${JSON.stringify(name)}`,
    );
  }
}

/** Throws unless `mac` is a lowercase unicast MAC. */
export function assertMac(mac: string, what = "MAC"): void {
  if (!MAC_RE.test(mac)) {
    throw new HostNetConfigError(`not a ${what}: ${JSON.stringify(mac)}`);
  }
  if ((parseInt(mac.slice(0, 2), 16) & 1) === 1) {
    throw new HostNetConfigError(`not a unicast ${what}: ${mac}`);
  }
}

/** Throws unless `id` is a usable VLAN id. */
export function assertVlanId(id: number): void {
  if (!Number.isInteger(id) || id < 1 || id > 4094) {
    throw new HostNetConfigError(`VLAN id out of range: ${id}`);
  }
}

/** Throws unless `mtu` is in the supported range. */
export function assertMtu(mtu: number): void {
  if (!Number.isInteger(mtu) || mtu < 1280 || mtu > 9216) {
    throw new HostNetConfigError(`MTU out of range: ${mtu}`);
  }
}

/** A parsed CIDR. */
export interface Cidr {
  /** Original text. */
  text: string;
  /** Bare address. */
  address: string;
  /** Prefix length. */
  prefix: number;
  /** 4 or 6. */
  family: 4 | 6;
  /** Network address as a 32- or 128-bit big integer. */
  network: bigint;
}

const IPV4_RE =
  /^(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$/;

function ipv4ToInt(address: string): bigint {
  return address.split(".").reduce(
    (acc, octet) => (acc << 8n) | BigInt(Number(octet)),
    0n,
  );
}

function parseIpv6(address: string): bigint {
  if (!/^[0-9a-fA-F:]+$/.test(address)) {
    throw new HostNetConfigError(`not an IPv6 address: ${address}`);
  }
  const parts = address.split("::");
  if (parts.length > 2) {
    throw new HostNetConfigError(`not an IPv6 address: ${address}`);
  }
  const head = parts[0] === "" ? [] : parts[0].split(":");
  const tail = parts.length === 2 && parts[1] !== "" ? parts[1].split(":") : [];
  const groups: string[] = [...head];
  if (parts.length === 2) {
    const missing = 8 - head.length - tail.length;
    if (missing < 1) {
      throw new HostNetConfigError(`not an IPv6 address: ${address}`);
    }
    for (let i = 0; i < missing; i++) groups.push("0");
  }
  groups.push(...tail);
  if (groups.length !== 8) {
    throw new HostNetConfigError(`not an IPv6 address: ${address}`);
  }
  return groups.reduce((acc, group) => {
    if (!/^[0-9a-fA-F]{1,4}$/.test(group)) {
      throw new HostNetConfigError(`not an IPv6 address: ${address}`);
    }
    return (acc << 16n) | BigInt(parseInt(group, 16));
  }, 0n);
}

/** Parses a strict host CIDR; refuses prefix 0 and shell metacharacters. */
export function parseCidr(text: string): Cidr {
  if (/[\]\[#@%]/.test(text) || /\s/.test(text)) {
    throw new HostNetConfigError(`not a CIDR: ${text}`);
  }
  const slash = text.indexOf("/");
  if (slash < 0) throw new HostNetConfigError(`not a CIDR: ${text}`);
  const address = text.slice(0, slash);
  const prefixText = text.slice(slash + 1);
  if (!/^\d{1,3}$/.test(prefixText)) {
    throw new HostNetConfigError(`not a CIDR: ${text}`);
  }
  const prefix = Number(prefixText);
  if (IPV4_RE.test(address)) {
    if (prefix < 1 || prefix > 32) {
      throw new HostNetConfigError(`bad IPv4 prefix: ${text}`);
    }
    const value = ipv4ToInt(address);
    const mask = ((1n << BigInt(prefix)) - 1n) << BigInt(32 - prefix);
    return {
      text,
      address,
      prefix,
      family: 4,
      network: value & mask,
    };
  }
  const value = parseIpv6(address);
  if (prefix < 1 || prefix > 128) {
    throw new HostNetConfigError(`bad IPv6 prefix: ${text}`);
  }
  const mask = ((1n << BigInt(prefix)) - 1n) << BigInt(128 - prefix);
  return { text, address, prefix, family: 6, network: value & mask };
}

/** True when two CIDRs overlap. */
export function cidrOverlaps(a: Cidr, b: Cidr): boolean {
  if (a.family !== b.family) return false;
  const prefix = a.prefix <= b.prefix ? a.prefix : b.prefix;
  const bits = a.family === 4 ? 32n : 128n;
  const mask = ((1n << BigInt(prefix)) - 1n) << (bits - BigInt(prefix));
  return (a.network & mask) === (b.network & mask);
}

/** One physical NIC the config touches. */
export interface EthernetSpec {
  /** Interface name. */
  name: string;
  /** Match by MAC instead of name, when given. */
  matchMac?: string;
  /** MTU to set. */
  mtu?: number;
}

/** One VLAN-tagged storage subinterface. */
export interface VlanSpec {
  /** VLAN id. */
  id: number;
  /** Parent interface name. */
  link: string;
  /** Interface name; defaults to `<link>.<id>`. */
  name?: string;
  /** MTU to set. */
  mtu?: number;
  /** Addresses in host CIDR form. */
  addresses: string[];
  /** Render as an optional device. */
  optional: boolean;
}

/** One bridge (Linux or OVS). */
export interface BridgeSpec {
  /** Bridge name. */
  name: string;
  /** Member interfaces (VLANs or ethernets). */
  interfaces: string[];
  /** MTU to set. */
  mtu?: number;
  /** Addresses in host CIDR form. */
  addresses: string[];
  /** STP, Linux bridges only. */
  stp?: boolean;
}

/** The whole desired network configuration. */
export interface NetConfig {
  /** Config backend. */
  backend: "netplan" | "networkd";
  /** Bridge implementation. */
  bridgeType: "linux" | "ovs";
  /** Whether the change may move management addressing. */
  mode: "additive" | "takeover";
  /** Name of the interface carrying the SSH session and default route. */
  managementInterface: string;
  /** Physical NICs. */
  ethernets: EthernetSpec[];
  /** VLANs. */
  vlans: VlanSpec[];
  /** Zero or one bridge. */
  bridge?: BridgeSpec;
}

/** A device with a resolved name and MTU, in graph order. */
export interface DeviceNode {
  /** Kind of device. */
  kind: "ethernet" | "vlan" | "bridge";
  /** Resolved name. */
  name: string;
  /** Lower device name, or "". */
  parent: string;
  /** MTU, or 0 when unset. */
  mtu: number;
}

/** Resolves the default name of a VLAN. */
export function vlanName(vlan: VlanSpec): string {
  return vlan.name ?? `${vlan.link}.${vlan.id}`;
}

/**
 * Validates a whole configuration. Throws {@link HostNetConfigError} on the
 * first violation; cross-field rules (MTU chain, uniqueness, storage-plane
 * routing, address overlap) all run here before any remote call.
 */
export function validateConfig(cfg: NetConfig): void {
  assertIface(cfg.managementInterface, "management interface");
  if (cfg.backend === "networkd" && cfg.bridgeType !== "linux") {
    throw new HostNetConfigError(
      "backend networkd supports only linux bridges",
    );
  }
  const names = new Set<string>();
  const claim = (name: string): void => {
    if (names.has(name)) {
      throw new HostNetConfigError(`duplicate device name: ${name}`);
    }
    names.add(name);
  };
  for (const eth of cfg.ethernets) {
    assertIface(eth.name, "ethernet name");
    claim(eth.name);
    if (eth.matchMac !== undefined) assertMac(eth.matchMac, "match MAC");
    if (eth.mtu !== undefined) assertMtu(eth.mtu);
  }
  const ethByName = new Map(cfg.ethernets.map((e) => [e.name, e]));
  const vlanByLinkId = new Set<string>();
  for (const vlan of cfg.vlans) {
    assertVlanId(vlan.id);
    const name = vlanName(vlan);
    assertIface(name, "VLAN name");
    claim(name);
    if (vlan.mtu !== undefined) assertMtu(vlan.mtu);
    if (!ethByName.has(vlan.link) && vlan.link !== cfg.managementInterface) {
      throw new HostNetConfigError(
        `VLAN ${name} link ${vlan.link} is not a declared ethernet`,
      );
    }
    const linkEth = ethByName.get(vlan.link);
    if (
      linkEth?.mtu !== undefined && vlan.mtu !== undefined &&
      vlan.mtu > linkEth.mtu
    ) {
      throw new HostNetConfigError(
        `VLAN ${name} MTU ${vlan.mtu} exceeds link MTU ${linkEth.mtu}`,
      );
    }
    const key = `${vlan.link}/${vlan.id}`;
    if (vlanByLinkId.has(key)) {
      throw new HostNetConfigError(`duplicate VLAN ${key}`);
    }
    vlanByLinkId.add(key);
    if (vlan.addresses.length === 0) {
      throw new HostNetConfigError(`VLAN ${name} has no address`);
    }
    for (const cidr of vlan.addresses) parseCidr(cidr);
  }
  if (cfg.bridge !== undefined) {
    const bridge = cfg.bridge;
    assertIface(bridge.name, "bridge name");
    claim(bridge.name);
    if (bridge.mtu !== undefined) assertMtu(bridge.mtu);
    if (bridge.interfaces.length === 0) {
      throw new HostNetConfigError("bridge has no member interfaces");
    }
    if (bridge.stp !== undefined && cfg.bridgeType === "ovs") {
      throw new HostNetConfigError("stp is only valid for a linux bridge");
    }
    const smallest = bridge.interfaces.reduce((min, member) => {
      const eth = ethByName.get(member);
      const vlan = cfg.vlans.find((v) => vlanName(v) === member);
      const mtu = eth?.mtu ?? vlan?.mtu ?? 1500;
      return Math.min(min, mtu);
    }, 9216);
    if (bridge.mtu !== undefined && bridge.mtu > smallest) {
      throw new HostNetConfigError(
        `bridge MTU ${bridge.mtu} exceeds the smallest port MTU ${smallest}`,
      );
    }
    for (const cidr of bridge.addresses) parseCidr(cidr);
  }
}

/**
 * Throws when a storage-plane CIDR overlaps any management address, so a
 * storage plane can never shadow the path the operator is using.
 */
export function assertNoManagementOverlap(
  storage: string[],
  management: string[],
): void {
  const storageCidrs = storage.map(parseCidr);
  const managementCidrs = management.map(parseCidr);
  for (const a of storageCidrs) {
    for (const b of managementCidrs) {
      if (cidrOverlaps(a, b)) {
        throw new HostNetConfigError(
          `storage address ${a.text} overlaps management address ${b.text}`,
        );
      }
    }
  }
}

/** Builds the device graph: ethernets, VLANs then the bridge, in that order. */
export function deviceGraph(cfg: NetConfig): DeviceNode[] {
  const nodes: DeviceNode[] = [];
  for (const eth of cfg.ethernets) {
    nodes.push({
      kind: "ethernet",
      name: eth.name,
      parent: "",
      mtu: eth.mtu ?? 0,
    });
  }
  for (const vlan of cfg.vlans) {
    nodes.push({
      kind: "vlan",
      name: vlanName(vlan),
      parent: vlan.link,
      mtu: vlan.mtu ?? 0,
    });
  }
  if (cfg.bridge !== undefined) {
    nodes.push({
      kind: "bridge",
      name: cfg.bridge.name,
      parent: "",
      mtu: cfg.bridge.mtu ?? 0,
    });
  }
  return nodes;
}
