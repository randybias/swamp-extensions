/**
 * Deterministic renderers for the netplan and networkd backends. The same
 * inputs always produce the same bytes, so the config sha256 is a stable
 * identity and a differing live config is detectable as drift.
 *
 * @module
 */

import { sha256Hex } from "./ssh.ts";
import {
  type BridgeSpec,
  deviceGraph,
  type EthernetSpec,
  type NetConfig,
  validateConfig,
  vlanName,
  type VlanSpec,
} from "./validate.ts";

/** One file the backend writes. */
export interface RenderedFile {
  /** Absolute path. */
  path: string;
  /** Octal mode. */
  mode: string;
  /** File contents. */
  content: string;
}

/** The result of rendering a configuration. */
export interface RenderResult {
  /** Files to write, in a stable order. */
  files: RenderedFile[];
  /** Every device the config manages. */
  managed: string[];
  /** Only the virtual devices this change creates (revert deletes these). */
  created: string[];
  /** SHA-256 over path, mode and content of every file. */
  sha256: string;
}

const NETPLAN_FILE = "/etc/netplan/90-host-net.yaml";
const CLOUD_INIT_DROP_IN =
  "/etc/cloud/cloud.cfg.d/99-disable-network-config.cfg";
/** Prefix for every networkd file this model owns. */
export const NETWORKD_PREFIX = "90-host-net-";
const NETWORKD_DIR = "/etc/systemd/network";

function yamlScalar(value: string): string {
  return `"${value.replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"`;
}

function renderEthernet(eth: EthernetSpec): string[] {
  const lines: string[] = [`    ${yamlScalar(eth.name)}:`];
  if (eth.matchMac !== undefined) {
    lines.push(
      "      match:",
      `        macaddress: ${yamlScalar(eth.matchMac)}`,
    );
  }
  if (eth.mtu !== undefined) lines.push(`      mtu: ${eth.mtu}`);
  return lines;
}

function renderVlan(vlan: VlanSpec): string[] {
  const name = vlanName(vlan);
  const lines: string[] = [
    `    ${yamlScalar(name)}:`,
    `      id: ${vlan.id}`,
    `      link: ${yamlScalar(vlan.link)}`,
  ];
  if (vlan.mtu !== undefined) lines.push(`      mtu: ${vlan.mtu}`);
  lines.push("      addresses:");
  for (const cidr of vlan.addresses) {
    lines.push(`        - ${yamlScalar(cidr)}`);
  }
  lines.push("      accept-ra: false");
  if (vlan.optional) lines.push("      optional: true");
  return lines;
}

function renderBridge(cfg: NetConfig, bridge: BridgeSpec): string[] {
  const lines: string[] = [
    `    ${yamlScalar(bridge.name)}:`,
    "      interfaces:",
  ];
  for (const member of bridge.interfaces) {
    lines.push(`        - ${yamlScalar(member)}`);
  }
  if (bridge.mtu !== undefined) lines.push(`      mtu: ${bridge.mtu}`);
  if (bridge.addresses.length > 0) {
    lines.push("      addresses:");
    for (const cidr of bridge.addresses) {
      lines.push(`        - ${yamlScalar(cidr)}`);
    }
  }
  if (cfg.bridgeType === "ovs") {
    lines.push("      openvswitch: {}");
  } else if (bridge.stp !== undefined) {
    lines.push("      parameters:", `        stp: ${bridge.stp}`);
  }
  return lines;
}

/** Renders the netplan YAML document. */
export function renderNetplanYaml(cfg: NetConfig): string {
  const lines: string[] = [
    "network:",
    "  version: 2",
    "  renderer: networkd",
  ];
  if (cfg.ethernets.length > 0) {
    lines.push("  ethernets:");
    for (const eth of cfg.ethernets) lines.push(...renderEthernet(eth));
  }
  if (cfg.vlans.length > 0) {
    lines.push("  vlans:");
    for (const vlan of cfg.vlans) lines.push(...renderVlan(vlan));
  }
  if (cfg.bridge !== undefined) {
    lines.push("  bridges:");
    lines.push(...renderBridge(cfg, cfg.bridge));
  }
  return lines.join("\n") + "\n";
}

function networkdMatch(name: string): string[] {
  return ["[Match]", `Name=${name}`, ""];
}

/** Renders the networkd `.netdev`/`.network` file set (Linux bridge only). */
export function renderNetworkdFiles(cfg: NetConfig): RenderedFile[] {
  const files: RenderedFile[] = [];
  // VLAN .netdev units.
  for (const vlan of cfg.vlans) {
    const name = vlanName(vlan);
    files.push({
      path: `${NETWORKD_DIR}/${NETWORKD_PREFIX}${name}.netdev`,
      mode: "0644",
      content: [
        "[NetDev]",
        `Name=${name}`,
        "Kind=vlan",
        "",
        "[VLAN]",
        `Id=${vlan.id}`,
        "",
      ].join("\n"),
    });
  }
  if (cfg.bridge !== undefined) {
    files.push({
      path: `${NETWORKD_DIR}/${NETWORKD_PREFIX}${cfg.bridge.name}.netdev`,
      mode: "0644",
      content: [
        "[NetDev]",
        `Name=${cfg.bridge.name}`,
        "Kind=bridge",
        "",
      ].join("\n"),
    });
  }
  const bridgeMembers = new Set(cfg.bridge?.interfaces ?? []);
  const unit = (
    name: string,
    mtu: number | undefined,
    network: string[],
  ): string[] => {
    const body: string[] = [...networkdMatch(name)];
    if (mtu !== undefined) body.push("[Link]", `MTUBytes=${mtu}`, "");
    body.push("[Network]", ...network, "");
    return body;
  };
  // Ethernet .network units.
  for (const eth of cfg.ethernets) {
    const network: string[] = [];
    for (const vlan of cfg.vlans) {
      if (vlan.link === eth.name) network.push(`VLAN=${vlanName(vlan)}`);
    }
    if (bridgeMembers.has(eth.name)) {
      network.push(`Bridge=${cfg.bridge!.name}`);
    }
    files.push({
      path: `${NETWORKD_DIR}/${NETWORKD_PREFIX}${eth.name}.network`,
      mode: "0644",
      content: unit(eth.name, eth.mtu, network).join("\n"),
    });
  }
  // VLAN .network units.
  for (const vlan of cfg.vlans) {
    const name = vlanName(vlan);
    const network: string[] = vlan.addresses.map((cidr) => `Address=${cidr}`);
    if (bridgeMembers.has(name)) network.push(`Bridge=${cfg.bridge!.name}`);
    if (vlan.optional) network.push("RequiredForOnline=no");
    files.push({
      path: `${NETWORKD_DIR}/${NETWORKD_PREFIX}${name}.network`,
      mode: "0644",
      content: unit(name, vlan.mtu, network).join("\n"),
    });
  }
  if (cfg.bridge !== undefined) {
    const bridge = cfg.bridge;
    const network: string[] = bridge.addresses.map((cidr) => `Address=${cidr}`);
    if (bridge.stp) network.push("STP=yes");
    files.push({
      path: `${NETWORKD_DIR}/${NETWORKD_PREFIX}${bridge.name}.network`,
      mode: "0644",
      content: unit(bridge.name, bridge.mtu, network).join("\n"),
    });
  }
  return files.sort((a, b) => a.path < b.path ? -1 : 1);
}

/** Renders the files, the managed set, the created set and the config digest. */
export async function renderConfig(cfg: NetConfig): Promise<RenderResult> {
  validateConfig(cfg);
  const files: RenderedFile[] = [];
  if (cfg.backend === "netplan") {
    files.push({
      path: NETPLAN_FILE,
      mode: "0600",
      content: renderNetplanYaml(cfg),
    });
    if (cfg.mode === "takeover") {
      files.push({
        path: CLOUD_INIT_DROP_IN,
        mode: "0644",
        content: "network: {config: disabled}\n",
      });
    }
  } else {
    files.push(...renderNetworkdFiles(cfg));
  }
  const managed = deviceGraph(cfg).map((n) => n.name);
  const created = [
    ...cfg.vlans.map(vlanName),
    ...(cfg.bridge !== undefined ? [cfg.bridge.name] : []),
  ];
  const digestInput = files
    .slice()
    .sort((a, b) => a.path < b.path ? -1 : 1)
    .map((f) => `${f.path}\0${f.mode}\0${f.content}`)
    .join("\0");
  return {
    files,
    managed,
    created,
    sha256: await sha256Hex(digestInput),
  };
}
