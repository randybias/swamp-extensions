/**
 * Deterministic renderer for a Kea DHCPv4 configuration.
 *
 * The renderer is pure: it turns validated inputs into the exact JSON written
 * to `/etc/kea/kea-dhcp4.conf`, its SHA-256 and the ordered apply plan. Keys,
 * subnet ids, pools, reservations and options are emitted in a stable order, so
 * the same inputs always produce the same bytes.
 *
 * @module
 */

import {
  assertCidr,
  assertIpv4,
  assertMac,
  type Cidr,
  cidrContains,
  cidrsOverlap,
  KeaInputError,
  type OptionValue,
  parseInterface,
  parseIpv4,
  parsePool,
  type Pool,
  rangesOverlap,
  renderOption,
} from "./grammar.ts";

/** One host reservation. */
export interface ReservationInput {
  /** Lowercase unicast MAC address. */
  hw_address: string;
  /** Address inside the subnet. */
  ip_address: string;
  /** Optional RFC 1123 hostname. */
  hostname?: string;
}

/** One typed DHCP option. */
export interface OptionInput {
  /** Allowlisted option name. */
  name: string;
  /** Typed value. */
  value: unknown;
}

/** One subnet. */
export interface SubnetInput {
  /** Explicit subnet id, 1-4294967294. */
  id: number;
  /** IPv4 CIDR in network form, /8-/30. */
  subnet: string;
  /** Pool ranges or CIDRs. */
  pools: string[];
  /** Host reservations. */
  reservations: ReservationInput[];
  /** Per-subnet options. */
  options: OptionInput[];
  /** Per-subnet valid lifetime. */
  valid_lifetime_s?: number;
  /** Relay addresses that select this subnet. */
  relay_addresses?: string[];
}

/** Validated inputs the renderer consumes. */
export interface RenderInput {
  /** Interfaces to listen on, optionally pinned to an address. */
  interfaces: string[];
  /** Socket type. */
  socket_type: "raw" | "udp";
  /** Global valid lifetime in seconds. */
  valid_lifetime_s: number;
  /** Optional renew timer. */
  renew_timer_s?: number;
  /** Optional rebind timer. */
  rebind_timer_s?: number;
  /** Global options. */
  options: OptionInput[];
  /** Subnets. */
  subnets: SubnetInput[];
  /** Enable the lease_cmds hook for live lease queries. */
  lease_api?: boolean;
  /** Absolute path of the lease_cmds hook library, when lease_api is set. */
  lease_cmds_path?: string;
  /** Control socket path. */
  control_socket?: string;
  /** Lease file path. */
  lease_file?: string;
}

/** The rendered result. */
export interface RenderResult {
  /** The Kea configuration object. */
  config: Record<string, unknown>;
  /** The exact bytes written to the config file. */
  json: string;
  /** Reservation IPs that also fall inside a pool (a warning, not an error). */
  warnings: string[];
}

/** The ordered logical steps of an apply. */
export type ApplyStep =
  | "validate"
  | "refuse-active"
  | "snapshot"
  | "arm"
  | "write"
  | "config-set"
  | "verify";

/** The apply plan; `arm` and the revert record precede every write. */
export const APPLY_PLAN: readonly ApplyStep[] = [
  "validate",
  "refuse-active",
  "snapshot",
  "arm",
  "write",
  "config-set",
  "verify",
];

/** Default control socket path. */
export const DEFAULT_CONTROL_SOCKET = "/run/kea/kea4-ctrl-socket";
/** Default lease file path. */
export const DEFAULT_LEASE_FILE = "/var/lib/kea/kea-leases4.csv";

/** Validates the interface list and refuses the wildcard. */
function interfaceList(values: string[]): string[] {
  if (values.length < 1 || values.length > 8) {
    throw new KeaInputError("interfaces must have 1-8 entries");
  }
  const names = values.map((value) => {
    const parsed = parseInterface(value);
    if (parsed === null) {
      throw new KeaInputError(
        `interface must be a name or name/ipv4 with no wildcard: ${value}`,
      );
    }
    return parsed.name;
  });
  if (new Set(names).size !== names.length) {
    throw new KeaInputError("interfaces must be unique");
  }
  return names;
}

/** Renders global and per-subnet options, sorted by name. */
function optionData(
  options: OptionInput[],
  subnet?: Cidr,
): OptionValue[] {
  const seen = new Set<string>();
  const rendered: OptionValue[] = [];
  for (
    const option of [...options].sort((a, b) => a.name.localeCompare(b.name))
  ) {
    if (seen.has(option.name)) {
      throw new KeaInputError(`duplicate option: ${option.name}`);
    }
    seen.add(option.name);
    rendered.push(renderOption(option, subnet));
  }
  return rendered;
}

/** Renders one subnet object. */
function subnetBody(subnet: SubnetInput): Record<string, unknown> {
  const cidr = assertCidr(subnet.subnet, "subnet");
  const pools: Pool[] = subnet.pools.map((pool) => {
    const parsed = parsePool(pool, cidr);
    if (parsed === null) {
      throw new KeaInputError(
        `pool is outside subnet ${subnet.subnet}: ${pool}`,
      );
    }
    return parsed;
  });
  pools.sort((a, b) => a.startInt - b.startInt || a.endInt - b.endInt);
  for (let i = 0; i < pools.length; i++) {
    for (let j = i + 1; j < pools.length; j++) {
      if (
        rangesOverlap(
          pools[i].startInt,
          pools[i].endInt,
          pools[j].startInt,
          pools[j].endInt,
        )
      ) {
        throw new KeaInputError(
          `pools overlap in subnet ${subnet.subnet}: ${subnet.pools[i]} and ${
            subnet.pools[j]
          }`,
        );
      }
    }
  }
  const reservations = [...subnet.reservations].sort((a, b) => {
    const ai = parseIpv4(a.ip_address) ?? 0;
    const bi = parseIpv4(b.ip_address) ?? 0;
    return ai - bi || a.hw_address.localeCompare(b.hw_address);
  });
  const macs = new Set<string>();
  const ips = new Set<string>();
  for (const reservation of reservations) {
    assertMac(reservation.hw_address, "hw_address");
    assertIpv4(reservation.ip_address, "ip_address");
    const ip = parseIpv4(reservation.ip_address) as number;
    if (
      !cidrContains(cidr, ip) || ip === cidr.network || ip === cidr.broadcast
    ) {
      throw new KeaInputError(
        `reservation ${reservation.ip_address} is not usable in subnet ${subnet.subnet}`,
      );
    }
    if (macs.has(reservation.hw_address)) {
      throw new KeaInputError(
        `duplicate MAC in subnet: ${reservation.hw_address}`,
      );
    }
    if (ips.has(reservation.ip_address)) {
      throw new KeaInputError(
        `duplicate reservation IP: ${reservation.ip_address}`,
      );
    }
    macs.add(reservation.hw_address);
    ips.add(reservation.ip_address);
  }
  const body: Record<string, unknown> = {
    id: subnet.id,
    subnet: cidr.text,
    pools: pools.map((pool) => ({ pool: `${pool.start} - ${pool.end}` })),
    "option-data": optionData(subnet.options, cidr),
    reservations: reservations.map((reservation) => ({
      "hw-address": reservation.hw_address,
      "ip-address": reservation.ip_address,
      ...(reservation.hostname ? { hostname: reservation.hostname } : {}),
    })),
  };
  if (subnet.valid_lifetime_s !== undefined) {
    body["valid-lifetime"] = subnet.valid_lifetime_s;
  }
  if (subnet.relay_addresses && subnet.relay_addresses.length > 0) {
    body.relay = { "ip-addresses": subnet.relay_addresses };
  }
  return body;
}

/** Renders the Kea configuration; throws on any invalid combination. */
export function renderConfig(input: RenderInput): RenderResult {
  const interfaces = [...interfaceList(input.interfaces)].sort();
  if (input.subnets.length < 1 || input.subnets.length > 64) {
    throw new KeaInputError("subnets must have 1-64 entries");
  }
  const subnets = [...input.subnets].sort((a, b) => a.id - b.id);
  const ids = new Set<number>();
  const cidrs: { id: number; cidr: Cidr }[] = [];
  for (const subnet of subnets) {
    if (ids.has(subnet.id)) {
      throw new KeaInputError(`duplicate subnet id: ${subnet.id}`);
    }
    ids.add(subnet.id);
    cidrs.push({ id: subnet.id, cidr: assertCidr(subnet.subnet, "subnet") });
  }
  for (let i = 0; i < cidrs.length; i++) {
    for (let j = i + 1; j < cidrs.length; j++) {
      if (cidrsOverlap(cidrs[i].cidr, cidrs[j].cidr)) {
        throw new KeaInputError(
          `subnets overlap: id ${cidrs[i].id} and id ${cidrs[j].id}`,
        );
      }
    }
  }
  if (input.renew_timer_s !== undefined && input.rebind_timer_s !== undefined) {
    if (
      !(input.renew_timer_s < input.rebind_timer_s &&
        input.rebind_timer_s < input.valid_lifetime_s)
    ) {
      throw new KeaInputError(
        "renew_timer_s < rebind_timer_s < valid_lifetime_s is required",
      );
    }
  }
  if (input.lease_api === true && !input.lease_cmds_path) {
    throw new KeaInputError(
      "lease_api requires lease_cmds_path; discover it with install",
    );
  }
  const dhcp4: Record<string, unknown> = {
    "interfaces-config": {
      interfaces,
      "dhcp-socket-type": input.socket_type,
    },
    "control-socket": {
      "socket-type": "unix",
      "socket-name": input.control_socket ?? DEFAULT_CONTROL_SOCKET,
    },
    "lease-database": {
      type: "memfile",
      persist: true,
      name: input.lease_file ?? DEFAULT_LEASE_FILE,
      "lfc-interval": 3600,
    },
    "valid-lifetime": input.valid_lifetime_s,
  };
  if (input.renew_timer_s !== undefined) {
    dhcp4["renew-timer"] = input.renew_timer_s;
  }
  if (input.rebind_timer_s !== undefined) {
    dhcp4["rebind-timer"] = input.rebind_timer_s;
  }
  const globalOptions = optionData(input.options);
  if (globalOptions.length > 0) dhcp4["option-data"] = globalOptions;
  dhcp4["subnet4"] = subnets.map(subnetBody);
  if (input.lease_api === true) {
    dhcp4["hooks-libraries"] = [{ library: input.lease_cmds_path }];
  }
  const config = { Dhcp4: dhcp4 };
  const json = `${JSON.stringify(config, null, 2)}\n`;

  // A reservation inside a pool is allowed but warned about.
  const warnings: string[] = [];
  for (const subnet of subnets) {
    const cidr = assertCidr(subnet.subnet, "subnet");
    const pools = subnet.pools
      .map((pool) => parsePool(pool, cidr))
      .filter((pool): pool is Pool => pool !== null);
    for (const reservation of subnet.reservations) {
      const ip = parseIpv4(reservation.ip_address);
      if (ip === null) continue;
      if (
        pools.some((pool) => rangesOverlap(ip, ip, pool.startInt, pool.endInt))
      ) {
        warnings.push(
          `reservation ${reservation.ip_address} is inside a pool in subnet ${subnet.subnet}`,
        );
      }
    }
  }
  return { config, json, warnings };
}
