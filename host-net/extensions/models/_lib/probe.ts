/**
 * Live-state probing: the argv vectors the model runs on the host and the
 * parsers for their JSON. A failed or truncated probe throws, and is never
 * persisted.
 *
 * @module
 */

import { HostNetConfigError } from "./validate.ts";

/** One link as reported by `ip -d -j link`. */
export interface LiveLink {
  /** Interface name. */
  name: string;
  /** MTU. */
  mtu: number;
  /** Kernel link kind, e.g. `vlan`, `bridge`, `ether`. */
  kind: string;
  /** Object state, e.g. `UP`. */
  state: string;
  /** VLAN id, when a VLAN. */
  vlanId: number;
  /** Master device, when enslaved. */
  master: string;
  /** MAC address, lowercased. */
  mac: string;
}

/** One address as reported by `ip -j addr`. */
export interface LiveAddr {
  /** Interface name. */
  ifname: string;
  /** `inet` or `inet6`. */
  family: string;
  /** Address. */
  local: string;
  /** Prefix length. */
  prefixlen: number;
}

/** The live probe result. */
export interface LiveState {
  /** Links. */
  links: LiveLink[];
  /** Addresses. */
  addrs: LiveAddr[];
  /** Default route as a canonical string. */
  defaultRoute: string;
  /** Interface carrying the route to the SSH client. */
  managementInterface: string;
  /** Estimated management addresses from the route lookup, when present. */
  managementAddrs: string[];
  /** netplan is present. */
  hasNetplan: boolean;
  /** systemd-networkd is present. */
  hasNetworkd: boolean;
  /** ovs-vsctl is present. */
  hasOvs: boolean;
}

/** The argv vectors a probe runs, in order. */
export function probeCommands(): string[][] {
  return [
    ["ip", "-d", "-j", "link"],
    ["ip", "-j", "addr"],
    ["ip", "-j", "route", "show", "default"],
    ["sh", "-c", 'set -- $SSH_CONNECTION; ip -j route get "$1"'],
    ["sh", "-c", "command -v netplan >/dev/null 2>&1 && echo yes || echo no"],
    [
      "sh",
      "-c",
      "command -v networkctl >/dev/null 2>&1 && echo yes || echo no",
    ],
    ["sh", "-c", "command -v ovs-vsctl >/dev/null 2>&1 && echo yes || echo no"],
  ];
}

function asArray(json: unknown): Record<string, unknown>[] {
  if (!Array.isArray(json)) {
    throw new HostNetConfigError("probe output is not a JSON array");
  }
  return json as Record<string, unknown>[];
}

/** Parses `ip -d -j link` output. */
export function parseLinks(text: string): LiveLink[] {
  let json: unknown;
  try {
    json = JSON.parse(text);
  } catch {
    throw new HostNetConfigError("link probe returned non-JSON");
  }
  return asArray(json).map((entry) => {
    const linkinfo = entry.linkinfo as Record<string, unknown> | undefined;
    const info = linkinfo?.info_data as Record<string, unknown> | undefined;
    const kind = typeof linkinfo?.info_kind === "string"
      ? linkinfo.info_kind
      : "ether";
    return {
      name: String(entry.ifname ?? ""),
      mtu: Number(entry.mtu ?? 0),
      kind,
      state: String(entry.operstate ?? ""),
      vlanId: kind === "vlan" && typeof info?.id === "number" ? info.id : 0,
      master: typeof entry.master === "string" ? entry.master : "",
      mac: typeof entry.address === "string" ? entry.address.toLowerCase() : "",
    };
  });
}

/** Parses `ip -j addr` output. */
export function parseAddrs(text: string): LiveAddr[] {
  let json: unknown;
  try {
    json = JSON.parse(text);
  } catch {
    throw new HostNetConfigError("addr probe returned non-JSON");
  }
  const out: LiveAddr[] = [];
  for (const entry of asArray(json)) {
    const ifname = String(entry.ifname ?? "");
    const addrInfo = entry.addr_info;
    if (!Array.isArray(addrInfo)) continue;
    for (const addr of addrInfo as Record<string, unknown>[]) {
      if (typeof addr.local !== "string") continue;
      out.push({
        ifname,
        family: String(addr.family ?? ""),
        local: addr.local,
        prefixlen: Number(addr.prefixlen ?? 0),
      });
    }
  }
  return out;
}

/** Parses `ip -j route show default` into a canonical string. */
export function parseDefaultRoute(text: string): string {
  let json: unknown;
  try {
    json = JSON.parse(text);
  } catch {
    throw new HostNetConfigError("route probe returned non-JSON");
  }
  const routes = asArray(json).map((r) =>
    `default via ${r.gateway ?? ""} dev ${r.dev ?? ""} metric ${r.metric ?? ""}`
      .replace(/\s+/g, " ").trim()
  );
  return routes.sort().join("; ");
}

/** Parses `ip -j route get <client>` into the first device name. */
export function parseRouteGet(text: string): string {
  let json: unknown;
  try {
    json = JSON.parse(text);
  } catch {
    throw new HostNetConfigError("route-get probe returned non-JSON");
  }
  const first = asArray(json)[0];
  return first !== undefined && typeof first.dev === "string" ? first.dev : "";
}

/** The addresses on the management interface, as CIDRs. */
export function managementCidrs(
  addrs: LiveAddr[],
  iface: string,
): string[] {
  return addrs
    .filter((a) => a.ifname === iface && a.family === "inet")
    .map((a) => `${a.local}/${a.prefixlen}`);
}
