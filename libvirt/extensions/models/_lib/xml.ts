/**
 * Deterministic renderers for libvirt network and domain XML, and the parsers
 * for the `virsh` text a caller reads back. Rendering is pure and stable, so
 * the same inputs always produce the same bytes and the network projection of
 * a re-render compares cleanly with `virsh net-dumpxml`.
 *
 * @module
 */

import {
  assertArch,
  assertDiskBus,
  assertDiskPath,
  assertDnsName,
  assertIfname,
  assertIpv4,
  assertMac,
  assertName,
  NETWORK_MODES,
} from "./validate.ts";

/** Structured inputs for a rendered network. */
export interface NetworkSpec {
  /** Network name. */
  name: string;
  /** Forward mode. */
  mode: (typeof NETWORK_MODES)[number];
  /** Bridge device name; defaults to `virbr-<name>` for nat/route. */
  bridge?: string;
  /** Gateway address, when the network carries an IP block. */
  gateway?: string;
  /** Prefix length for the gateway block. */
  prefix?: number;
  /** DHCP range start, with `dhcpEnd`. */
  dhcpStart?: string;
  /** DHCP range end, with `dhcpStart`. */
  dhcpEnd?: string;
  /** DNS domain served by the DHCP block. */
  domain?: string;
}

/** One disk attached to a rendered domain. */
export interface DomainDiskSpec {
  /** Absolute path of the backing file or ISO. */
  path: string;
  /** qemu driver format, e.g. `qcow2` or `raw`. */
  format: string;
  /** Target device name, e.g. `vda` or `sda`. */
  target: string;
  /** Bus, e.g. `virtio` or `sata`. */
  bus: string;
  /** `disk` or `cdrom`. */
  device: "disk" | "cdrom";
  /** Attach read-only media. */
  readonly: boolean;
}

/** Structured inputs for a rendered domain. */
export interface DomainSpec {
  /** Domain name. */
  name: string;
  /** Virtual CPU count. */
  vcpus: number;
  /** Memory in MiB. */
  memoryMib: number;
  /** Guest architecture. */
  arch: string;
  /** Disks to attach, the first being the boot disk. */
  disks: DomainDiskSpec[];
  /** libvirt network to attach, or `bridge` for a host bridge. */
  network?: string;
  /** Host bridge to attach, or `network` for a libvirt network. */
  bridge?: string;
  /** Fixed MAC address for the interface. */
  mac?: string;
}

function escapeXmlAttribute(value: string): string {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&apos;");
}

function indent(depth: number): string {
  return "  ".repeat(depth);
}

/** A deterministic bridge name that fits IFNAMSIZ for any network name. */
export function defaultBridgeName(name: string): string {
  let hash = 0x811c9dc5;
  for (let i = 0; i < name.length; i++) {
    hash ^= name.charCodeAt(i);
    hash = Math.imul(hash, 0x01000193) >>> 0;
  }
  return `vb-${hash.toString(16).padStart(8, "0")}`;
}

/** Renders a deterministic `<network>` definition from structured inputs. */
export function renderNetworkXml(spec: NetworkSpec): string {
  assertName(spec.name, "network name");
  if (spec.bridge !== undefined) assertIfname(spec.bridge);
  if (spec.domain !== undefined) assertDnsName(spec.domain);
  const lines: string[] = ["<network>"];
  lines.push(`${indent(1)}<name>${escapeXmlAttribute(spec.name)}</name>`);
  if (spec.mode !== "none") {
    lines.push(`${indent(1)}<forward mode='${spec.mode}'/>`);
  }
  const bridge = spec.bridge ??
    (spec.mode === "nat" || spec.mode === "route"
      ? defaultBridgeName(spec.name)
      : undefined);
  if (bridge !== undefined) {
    assertIfname(bridge);
    lines.push(`${indent(1)}<bridge name='${bridge}'/>`);
  }
  // `<domain>` is a direct child of `<network>`, not a child of `<dhcp>`.
  if (spec.domain !== undefined) {
    lines.push(
      `${indent(1)}<domain name='${
        escapeXmlAttribute(spec.domain)
      }' localOnly='yes'/>`,
    );
  }
  if (spec.gateway !== undefined) {
    assertIpv4(spec.gateway);
    const prefix = spec.prefix ?? 24;
    lines.push(`${indent(1)}<ip address='${spec.gateway}' prefix='${prefix}'>`);
    if (spec.dhcpStart !== undefined || spec.dhcpEnd !== undefined) {
      if (spec.dhcpStart === undefined || spec.dhcpEnd === undefined) {
        throw new Error("dhcpStart and dhcpEnd must be given together");
      }
      assertIpv4(spec.dhcpStart);
      assertIpv4(spec.dhcpEnd);
      lines.push(`${indent(2)}<dhcp>`);
      lines.push(
        `${indent(3)}<range start='${spec.dhcpStart}' end='${spec.dhcpEnd}'/>`,
      );
      lines.push(`${indent(2)}</dhcp>`);
    }
    lines.push(`${indent(1)}</ip>`);
  }
  lines.push("</network>");
  return lines.join("\n") + "\n";
}

/** Renders a deterministic KVM `<domain>` that boots from a resolved path. */
export function renderDomainXml(spec: DomainSpec): string {
  assertName(spec.name, "domain name");
  assertArch(spec.arch);
  if (spec.mac !== undefined) assertMac(spec.mac);
  if (spec.disks.length === 0) {
    throw new Error("a rendered domain needs at least one disk");
  }
  const lines: string[] = [
    "<domain type='kvm'>",
    `${indent(1)}<name>${escapeXmlAttribute(spec.name)}</name>`,
    `${indent(1)}<memory unit='MiB'>${spec.memoryMib}</memory>`,
    `${indent(1)}<vcpu>${spec.vcpus}</vcpu>`,
    `${indent(1)}<os>`,
    `${indent(2)}<type arch='${spec.arch}'>hvm</type>`,
    `${indent(2)}<boot dev='hd'/>`,
    `${indent(1)}</os>`,
    // Without ACPI the guest starts with acpi=off and ignores the ACPI power
    // button, so `virsh shutdown` never powers it off.
    `${indent(1)}<features>`,
    `${indent(2)}<acpi/>`,
    `${indent(2)}<apic/>`,
    `${indent(1)}</features>`,
    `${indent(1)}<devices>`,
  ];
  for (const disk of spec.disks) {
    assertDiskPath(disk.path);
    assertName(disk.target, "disk target");
    assertDiskBus(disk.bus);
    // `type='file'` with the resolved path, never `type='volume'`: on a stock
    // Ubuntu host virt-aa-helper grants AppArmor access to an explicit file but
    // not to a volume reference, so qemu gets Permission denied.
    lines.push(`${indent(2)}<disk type='file' device='${disk.device}'>`);
    lines.push(`${indent(3)}<driver name='qemu' type='${disk.format}'/>`);
    lines.push(
      `${indent(3)}<source file='${escapeXmlAttribute(disk.path)}'/>`,
    );
    lines.push(`${indent(3)}<target dev='${disk.target}' bus='${disk.bus}'/>`);
    if (disk.readonly) lines.push(`${indent(3)}<readonly/>`);
    lines.push(`${indent(2)}</disk>`);
  }
  if (spec.network !== undefined && spec.bridge !== undefined) {
    throw new Error("give network or bridge, not both");
  }
  if (spec.network !== undefined) {
    assertName(spec.network, "network name");
    lines.push(`${indent(2)}<interface type='network'>`);
    lines.push(`${indent(3)}<source network='${spec.network}'/>`);
    if (spec.mac !== undefined) {
      lines.push(`${indent(3)}<mac address='${spec.mac}'/>`);
    }
    lines.push(`${indent(3)}<model type='virtio'/>`);
    lines.push(`${indent(2)}</interface>`);
  } else if (spec.bridge !== undefined) {
    assertName(spec.bridge, "bridge name");
    lines.push(`${indent(2)}<interface type='bridge'>`);
    lines.push(`${indent(3)}<source bridge='${spec.bridge}'/>`);
    if (spec.mac !== undefined) {
      lines.push(`${indent(3)}<mac address='${spec.mac}'/>`);
    }
    lines.push(`${indent(3)}<model type='virtio'/>`);
    lines.push(`${indent(2)}</interface>`);
  }
  // A pty serial plus console is what makes `virsh console` usable.
  lines.push(
    `${indent(2)}<serial type='pty'>`,
    `${indent(3)}<target type='isa-serial' port='0'/>`,
    `${indent(2)}</serial>`,
    `${indent(2)}<console type='pty'>`,
    `${indent(3)}<target type='serial' port='0'/>`,
    `${indent(2)}</console>`,
    `${indent(1)}</devices>`,
    "</domain>",
  );
  return lines.join("\n") + "\n";
}

/** Removes XML comments so a commented-out tag cannot satisfy a lookup. */
function stripXmlComments(xml: string): string {
  return xml.replace(/<!--[\s\S]*?-->/g, "");
}

export function firstTagText(xml: string, tag: string): string {
  const m = new RegExp(`<${tag}(?:\\s[^>]*)?>([^<]*)</${tag}>`).exec(
    stripXmlComments(xml),
  );
  return m ? m[1].trim() : "";
}

function firstTagAttr(xml: string, tag: string, attr: string): string {
  const clean = stripXmlComments(xml);
  const m = new RegExp(`<${tag}\\b[^>]*\\b${attr}='([^']*)'`).exec(clean);
  if (m) return m[1];
  const d = new RegExp(`<${tag}\\b[^>]*\\b${attr}="([^"]*)"`).exec(clean);
  return d ? d[1] : "";
}

/**
 * A stable projection of the fields a structured network sets, so a
 * re-render can be compared with `virsh net-dumpxml` output regardless of
 * attribute order or indentation.
 */
export function networkProjection(xml: string): string {
  return JSON.stringify({
    name: firstTagText(xml, "name"),
    forward: firstTagAttr(xml, "forward", "mode") || "none",
    bridge: firstTagAttr(xml, "bridge", "name"),
    domain: firstTagAttr(xml, "domain", "name"),
    ip: firstTagAttr(xml, "ip", "address"),
    prefix: firstTagAttr(xml, "ip", "prefix") ||
      firstTagAttr(xml, "ip", "netmask"),
    dhcpStart: firstTagAttr(xml, "range", "start"),
    dhcpEnd: firstTagAttr(xml, "range", "end"),
  });
}

/**
 * Parses `virsh ... info` output (`Key: value` lines) into a lower-cased-key
 * record. Only the first colon splits, so values may contain colons.
 */
export function parseKeyValues(text: string): Record<string, string> {
  const out: Record<string, string> = {};
  for (const raw of text.split("\n")) {
    const match = /^([^:]+):\s*(.*)$/.exec(raw.trim());
    if (match) out[match[1].trim().toLowerCase()] = match[2].trim();
  }
  return out;
}

/** Parses the one-name-per-line output of `virsh ... --name`. */
export function parseNameList(text: string): string[] {
  return text.split("\n").map((l) => l.trim()).filter((l) => l !== "");
}

/** Parses `virsh vol-list` rows into name/path pairs, skipping the header. */
export function parseVolList(text: string): { name: string; path: string }[] {
  const out: { name: string; path: string }[] = [];
  for (const raw of text.split("\n")) {
    const line = raw.trim();
    if (line === "" || line.startsWith("-") || /^name\b/i.test(line)) continue;
    const parts = line.split(/\s+/);
    if (parts.length >= 2) out.push({ name: parts[0], path: parts[1] });
  }
  return out;
}

/** One disk reference parsed from domain XML or `domblklist`. */
export interface DomainDiskRef {
  /** `disk` or `cdrom`. */
  device: string;
  /** Backing file path. */
  path: string;
  /** Whether the media is read-only. */
  readonly: boolean;
}

function tagAttribute(openTag: string, name: string): string {
  const m = new RegExp(`\\b${name}=(['\"])(.*?)\\1`).exec(openTag);
  return m ? m[2] : "";
}

/** Parses the disks out of a domain XML, ignoring comments. */
export function parseDomainDisks(xml: string): DomainDiskRef[] {
  const clean = stripXmlComments(xml);
  const out: DomainDiskRef[] = [];
  for (const match of clean.matchAll(/<disk\b([^>]*)>([\s\S]*?)<\/disk>/g)) {
    const device = tagAttribute(match[1], "device");
    const sourceTag = /<source\b[^>]*>/.exec(match[2])?.[0] ?? "";
    const path = tagAttribute(sourceTag, "file");
    if (path !== "") {
      out.push({ device, path, readonly: /<readonly\b/.test(match[2]) });
    }
  }
  return out;
}

/** One `virsh domblklist --details` row. */
export interface BlkListEntry {
  /** Block type, e.g. `file`. */
  type: string;
  /** Device type, e.g. `disk` or `cdrom`. */
  device: string;
  /** Target device name, e.g. `vda`. */
  target: string;
  /** Backing source path. */
  source: string;
}

/** Parses `virsh domblklist --details` rows, skipping header and separator. */
export function parseBlkListDetails(text: string): BlkListEntry[] {
  const out: BlkListEntry[] = [];
  for (const raw of text.split("\n")) {
    const line = raw.trim();
    if (line === "" || line.startsWith("-") || /^type\b/i.test(line)) continue;
    const parts = line.split(/\s+/);
    if (parts.length >= 4) {
      out.push({
        type: parts[0],
        device: parts[1],
        target: parts[2],
        source: parts[3],
      });
    }
  }
  return out;
}

/** The `type` attribute of the first `<format>` in a volume XML, or "". */
export function parseVolumeFormat(xml: string): string {
  const clean = stripXmlComments(xml);
  const match = /<format\b[^>]*\btype=(["'])(.*?)\1/.exec(clean);
  return match ? match[2] : "";
}

/** Reads the domain state out of `virsh dominfo` key-values, lower-cased. */
export function domainState(info: Record<string, string>): string {
  return (info["state"] ?? "unknown").toLowerCase();
}

/** Converts `Max memory: 2097152 KiB` to MiB, or undefined when absent. */
export function memoryMib(info: Record<string, string>): number | undefined {
  const raw = info["max memory"] ?? info["used memory"];
  if (!raw) return undefined;
  const match = /^(\d+)\s*(\w+)?/.exec(raw);
  if (!match) return undefined;
  const value = Number(match[1]);
  const unit = (match[2] ?? "KiB").toLowerCase();
  if (unit === "mib" || unit === "mb") return value;
  if (unit === "gib" || unit === "gb") return Math.round(value * 1024);
  if (unit === "kib" || unit === "kb") return Math.round(value / 1024);
  return undefined;
}

/** True when a domain state means the domain is powered on. */
export function isRunningState(state: string): boolean {
  return state === "running" || state === "blocked" || state === "idle";
}

/** True when a domain state means the domain is paused. */
export function isPausedState(state: string): boolean {
  return state === "paused" || state === "pmsuspended";
}

/** A domain is "off" when it is shut off or has crashed. */
export function isOffState(state: string): boolean {
  return state === "shut off" || state === "crashed" ||
    state === "unknown";
}
