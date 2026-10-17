/**
 * Protected block devices: which disks a destructive tool must never touch.
 *
 * A pure module. It runs no command and reads no file: it takes the raw
 * output of a fixed set of host probes, each with its exit status, and returns
 * either the set of device paths that back the running or bootable system, or
 * a typed refusal. Every ambiguity is a refusal. A probe that failed, produced
 * nothing, produced something unparseable, or named a device that cannot be
 * resolved never yields "nothing is protected".
 *
 * What is protected is everything that is, contains, is a member of, or is an
 * ancestor of anything backing: the mounted root and boot filesystems, every
 * mount, every `/etc/fstab` entry (mounted or not), every swap device, every
 * member of an md array that backs any of those (including an inactive,
 * degraded or dropped-out member, matched by array UUID), every physical volume
 * of a volume group that holds a protected logical volume, and every vdev of a
 * ZFS pool that backs one. Device-mapper and md devices that sit on several
 * disks protect all of them.
 *
 * The module imports nothing, so it can be copied unchanged into another
 * extension.
 *
 * @module
 */

/** The output of one command and its exit status. */
export interface CommandProbe {
  /** Exit status; 127 means the command is not installed. */
  code: number;
  /** Standard output. */
  stdout: string;
}

/** The result of reading one file. */
export type FileProbe =
  | { state: "ok"; text: string }
  /** The file does not exist, established by an explicit not-exists result. */
  | { state: "absent" }
  /** Any other failure to read it. */
  | { state: "error"; detail?: string };

/** The raw probe outputs the module judges. */
export interface ProbeInputs {
  /** {@link LSBLK_COMMAND}. */
  lsblk: CommandProbe;
  /** {@link FINDMNT_COMMAND}. */
  findmnt: CommandProbe;
  /** The text of `/etc/fstab`. */
  fstab: FileProbe;
  /** The text of `/proc/swaps`. */
  swaps: FileProbe;
  /** The text of `/proc/mdstat`. */
  mdstat: FileProbe;
  /** {@link LINKS_COMMAND}. */
  links: CommandProbe;
  /** {@link BLKID_COMMAND}; used only for a spec lsblk cannot resolve. */
  blkid: CommandProbe;
  /** {@link ZPOOL_COMMAND}; code 127 when ZFS is not installed. */
  zpool: CommandProbe;
  /** {@link PVS_COMMAND}; code 127 when LVM is not installed. */
  pvs: CommandProbe;
  /** `mdadm --examine <path>` for every path in {@link examineTargets}. */
  mdExamine: Record<string, CommandProbe>;
}

/** Why a device is protected. */
export type ProtectedDevices = Record<string, string[]>;

/** The protected set, serializable so it can be carried across re-reads. */
export interface ProtectedSet {
  /** Protected device path to the reasons it is protected. */
  devices: ProtectedDevices;
  /** Volume groups holding a protected logical volume. */
  volumeGroups: string[];
  /** Normalized UUIDs of md arrays backing something protected. */
  arrayUuids: string[];
  /** ZFS pools backing something protected. */
  pools: string[];
}

/** Why the module refused. */
export type RefusalCode = "unverifiable" | "protected";

/** A typed refusal: the caller must not proceed. */
export interface Refusal {
  /** `unverifiable`: the host could not be read safely. `protected`: a candidate is protected. */
  code: RefusalCode;
  /** One-line explanation, free of any secret. */
  message: string;
  /** Structured detail for the caller's error. */
  detail: Record<string, unknown>;
}

/** The module's verdict. */
export type Assessment =
  | { ok: true; set: ProtectedSet }
  | { ok: false; refusal: Refusal };

/** Probe that lists block devices with the columns the module needs. */
export const LSBLK_COMMAND =
  "lsblk -J -b -o NAME,PATH,PKNAME,TYPE,FSTYPE,UUID,PARTUUID,LABEL,MOUNTPOINTS";
/** Probe for live mounts. */
export const FINDMNT_COMMAND = "findmnt -J";
/** Probe that resolves every device symlink: one `<link> <target>` per line. */
export const LINKS_COMMAND =
  `find /dev -xdev -maxdepth 3 -type l -exec sh -c 'for l; do printf "%s %s\\n" "$l" "$(readlink -f "$l")"; done' sh {} +`;
/** Udev-less fallback that prints identifiers per device. */
export const BLKID_COMMAND = "blkid";
/** Probe for ZFS pool membership with full device paths. */
export const ZPOOL_COMMAND = "zpool status -P";
/** Probe for LVM physical volumes and their volume groups. */
export const PVS_COMMAND = "pvs --noheadings -o pv_name,vg_name";
/** Probe run for each path from {@link examineTargets}. */
export function mdExamineCommand(path: string): string {
  return `mdadm --examine -- '${path.replace(/'/g, "'\\''")}'`;
}

/** Filesystem types that are not backed by a local block device. */
const NON_BLOCK_FS = new Set([
  "tmpfs",
  "ramfs",
  "proc",
  "sysfs",
  "devpts",
  "devtmpfs",
  "cgroup",
  "cgroup2",
  "overlay",
  "nfs",
  "nfs4",
  "cifs",
  "smb3",
  "smbfs",
  "9p",
  "virtiofs",
  "debugfs",
  "tracefs",
  "securityfs",
  "pstore",
  "bpf",
  "mqueue",
  "hugetlbfs",
  "fusectl",
  "configfs",
  "binfmt_misc",
  "autofs",
  "rpc_pipefs",
  "efivarfs",
  "squashfs",
  "ceph",
  "glusterfs",
  "swap",
]);

/** Filesystems that can span several block devices under one UUID. */
const MULTI_DEVICE_FS = new Set(["btrfs", "bcachefs"]);

/** mdadm's own answers for a device that is simply not an array member. */
const NOT_A_MEMBER = /No md superblock|not an md|does not appear to be an md/i;

/** A refusal builder. */
function refuse(
  code: RefusalCode,
  message: string,
  detail: Record<string, unknown> = {},
): { ok: false; refusal: Refusal } {
  return { ok: false, refusal: { code, message, detail } };
}

/** Thrown internally to unwind to a refusal. */
class Unverifiable extends Error {
  readonly detail: Record<string, unknown>;
  constructor(message: string, detail: Record<string, unknown> = {}) {
    super(message);
    this.detail = detail;
  }
}

function unverifiable(
  message: string,
  detail: Record<string, unknown> = {},
): never {
  throw new Unverifiable(message, detail);
}

/** One block device from lsblk. */
interface Node {
  path: string;
  name: string;
  type: string;
  fstype: string;
  uuid: string;
  partuuid: string;
  label: string;
  mounts: string[];
  parents: Set<string>;
  children: Set<string>;
}

interface Graph {
  nodes: Map<string, Node>;
  byName: Map<string, Node>;
}

function str(value: unknown): string {
  return typeof value === "string" ? value : "";
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** Parses lsblk JSON into a graph, merging a device listed under several parents. */
function parseLsblkGraph(probe: CommandProbe): Graph {
  if (probe.code !== 0) {
    unverifiable("lsblk failed", { exit: probe.code });
  }
  if (probe.stdout.trim() === "") unverifiable("lsblk printed nothing");
  let parsed: unknown;
  try {
    parsed = JSON.parse(probe.stdout);
  } catch {
    unverifiable("lsblk did not return JSON");
  }
  const roots = isRecord(parsed) ? parsed.blockdevices : undefined;
  if (!Array.isArray(roots) || roots.length === 0) {
    unverifiable("lsblk listed no block devices");
  }
  const nodes = new Map<string, Node>();
  const byName = new Map<string, Node>();
  const pknames: [Node, string][] = [];
  const visit = (raw: unknown, parent: Node | null): void => {
    if (!isRecord(raw)) unverifiable("lsblk returned a malformed device");
    const name = str(raw.name);
    const path = str(raw.path) || (name ? `/dev/${name}` : "");
    if (!name || !path.startsWith("/dev/")) {
      unverifiable("lsblk returned a device without a name or path");
    }
    let node = nodes.get(path);
    if (!node) {
      node = {
        path,
        name,
        type: str(raw.type),
        fstype: str(raw.fstype),
        uuid: str(raw.uuid),
        partuuid: str(raw.partuuid),
        label: str(raw.label),
        mounts: [],
        parents: new Set(),
        children: new Set(),
      };
      nodes.set(path, node);
      byName.set(name, node);
    }
    const mounts = Array.isArray(raw.mountpoints)
      ? raw.mountpoints
      : raw.mountpoint
      ? [raw.mountpoint]
      : [];
    for (const m of mounts) {
      if (typeof m === "string" && m !== "" && !node.mounts.includes(m)) {
        node.mounts.push(m);
      }
    }
    if (str(raw.pkname)) pknames.push([node, str(raw.pkname)]);
    if (parent) {
      node.parents.add(parent.path);
      parent.children.add(node.path);
    }
    if (raw.children !== undefined) {
      if (!Array.isArray(raw.children)) {
        unverifiable("lsblk returned malformed children");
      }
      for (const child of raw.children) visit(child, node);
    }
  };
  for (const root of roots) visit(root, null);
  for (const [node, pk] of pknames) {
    const parent = byName.get(pk);
    if (parent && parent !== node) {
      node.parents.add(parent.path);
      parent.children.add(node.path);
    }
  }
  return { nodes, byName };
}

/** Lowercase hex with separators removed, so mdadm and blkid UUIDs compare. */
export function normalizeUuid(uuid: string): string {
  return uuid.toLowerCase().replace(/[^0-9a-f]/g, "");
}

/** Decodes a device-mapper name `vg--a-lv--b` into its volume group. */
export function volumeGroupOf(dmName: string): string | null {
  const parts = dmName.split(/(?<!-)-(?!-)/);
  if (parts.length !== 2 || parts[0] === "" || parts[1] === "") return null;
  return parts[0].replace(/--/g, "-");
}

/** Resolves device names and symlinks to lsblk paths. */
class Resolver {
  private readonly links = new Map<string, string>();
  private readonly aliases = new Map<string, string>();

  constructor(private readonly graph: Graph, links: CommandProbe) {
    if (links.code !== 0) {
      unverifiable("link probe failed", { exit: links.code });
    }
    for (const line of links.stdout.split("\n")) {
      const at = line.indexOf(" ");
      if (at < 1) continue;
      const link = line.slice(0, at);
      const target = line.slice(at + 1).trim();
      if (!link.startsWith("/dev/") || !target.startsWith("/dev/")) continue;
      this.links.set(link, target);
      // /dev/mapper/vg-lv is lsblk's path; /dev/dm-3 is where it points.
      if (graph.nodes.has(link) && !graph.nodes.has(target)) {
        this.aliases.set(target, link);
      }
    }
  }

  /** The lsblk path for `path`, or null when it cannot be resolved. */
  resolve(path: string): string | null {
    const clean = path.replace(/\[[^\]]*\]$/, "");
    const direct = this.lookup(clean);
    if (direct) return direct;
    const linked = this.links.get(clean);
    return linked ? this.lookup(linked) : null;
  }

  private lookup(path: string): string | null {
    if (this.graph.nodes.has(path)) return path;
    return this.aliases.get(path) ?? null;
  }
}

/** All descendants of a path, including itself. */
function subtree(graph: Graph, path: string): string[] {
  const out: string[] = [];
  const seen = new Set<string>();
  const stack = [path];
  while (stack.length > 0) {
    const current = stack.pop()!;
    if (seen.has(current)) continue;
    seen.add(current);
    out.push(current);
    for (const child of graph.nodes.get(current)?.children ?? []) {
      stack.push(child);
    }
  }
  return out;
}

/** The connected component of a path in the undirected device graph. */
function component(graph: Graph, path: string): string[] {
  const out: string[] = [];
  const seen = new Set<string>();
  const stack = [path];
  while (stack.length > 0) {
    const current = stack.pop()!;
    if (seen.has(current)) continue;
    seen.add(current);
    out.push(current);
    const node = graph.nodes.get(current);
    for (const next of [...(node?.parents ?? []), ...(node?.children ?? [])]) {
      stack.push(next);
    }
  }
  return out;
}

/** The md and swap and zfs lines of the probes, parsed. */
interface MdArray {
  name: string;
  members: string[];
}

/** Parses `/proc/mdstat`; member flag groups such as `sdc1[2](W)(F)` are handled. */
export function parseMdstat(text: string): MdArray[] {
  const arrays: MdArray[] = [];
  for (const line of text.split("\n")) {
    const head = /^(md[A-Za-z0-9_]*)\s*:\s*(.*)$/.exec(line);
    if (!head) continue;
    const members: string[] = [];
    const re = /([A-Za-z0-9_./-]+?)\[(\d+)\]((?:\([A-Za-z]\))*)/g;
    let m: RegExpExecArray | null;
    while ((m = re.exec(head[2])) !== null) members.push(m[1]);
    arrays.push({ name: head[1], members });
  }
  return arrays;
}

/** Reads the `Array UUID` (or legacy `UUID`) of `mdadm --examine` output. */
export function parseExamineUuid(text: string): string | null {
  const arr = /^\s*Array UUID\s*:\s*(\S+)/im.exec(text);
  if (arr) return normalizeUuid(arr[1]);
  const legacy = /^\s*UUID\s*:\s*(\S+)/im.exec(text);
  return legacy ? normalizeUuid(legacy[1]) : null;
}

interface FstabEntry {
  spec: string;
  target: string;
  fstype: string;
  options: string;
}

function parseFstab(text: string): FstabEntry[] {
  const out: FstabEntry[] = [];
  for (const raw of text.split("\n")) {
    const line = raw.trim();
    if (line === "" || line.startsWith("#")) continue;
    const f = line.split(/\s+/);
    if (f.length < 3) {
      unverifiable("an /etc/fstab line cannot be parsed", { line });
    }
    out.push({ spec: f[0], target: f[1], fstype: f[2], options: f[3] ?? "" });
  }
  return out;
}

interface Mount {
  target: string;
  source: string;
  fstype: string;
}

function parseFindmnt(probe: CommandProbe): Mount[] {
  if (probe.code !== 0) unverifiable("findmnt failed", { exit: probe.code });
  if (probe.stdout.trim() === "") unverifiable("findmnt printed nothing");
  let parsed: unknown;
  try {
    parsed = JSON.parse(probe.stdout);
  } catch {
    unverifiable("findmnt did not return JSON");
  }
  const roots = isRecord(parsed) ? parsed.filesystems : undefined;
  if (!Array.isArray(roots)) unverifiable("findmnt listed no filesystems");
  const mounts: Mount[] = [];
  const visit = (raw: unknown): void => {
    if (!isRecord(raw)) unverifiable("findmnt returned a malformed entry");
    mounts.push({
      target: str(raw.target),
      source: str(raw.source),
      fstype: str(raw.fstype),
    });
    if (Array.isArray(raw.children)) { for (const c of raw.children) visit(c); }
  };
  for (const r of roots) visit(r);
  return mounts;
}

/** Parses `blkid` lines into path to identifiers. */
function parseBlkid(probe: CommandProbe): Map<string, Record<string, string>> {
  const out = new Map<string, Record<string, string>>();
  if (probe.code !== 0) return out;
  for (const line of probe.stdout.split("\n")) {
    const head = /^(\/dev\/[^:\s]+):\s*(.*)$/.exec(line);
    if (!head) continue;
    const ids: Record<string, string> = {};
    const re = /([A-Z_]+)="([^"]*)"/g;
    let m: RegExpExecArray | null;
    while ((m = re.exec(head[2])) !== null) ids[m[1]] = m[2];
    out.set(head[1], ids);
  }
  return out;
}

/** Pools to their vdev device names, from `zpool status -P`. */
export function parseZpoolStatus(text: string): Map<string, string[]> {
  const pools = new Map<string, string[]>();
  let pool: string | null = null;
  let inConfig = false;
  const structural =
    /^(mirror|raidz[123]?|draid[123]?|spare|spares|logs|cache|special|dedup|replacing|NAME)(-\d+)?(:\d+.*)?$/;
  for (const raw of text.split("\n")) {
    const header = /^\s*pool:\s*(\S+)/.exec(raw);
    if (header) {
      pool = header[1];
      pools.set(pool, []);
      inConfig = false;
      continue;
    }
    if (pool === null) continue;
    if (/^\s*config:/.test(raw)) {
      inConfig = true;
      continue;
    }
    if (/^\s*errors:/.test(raw)) {
      inConfig = false;
      continue;
    }
    if (!inConfig) continue;
    const token = raw.trim().split(/\s+/)[0];
    if (!token || token === pool || structural.test(token)) continue;
    pools.get(pool)!.push(token);
  }
  return pools;
}

/** Whether a spec is a device reference rather than a network or pseudo source. */
function deviceReference(spec: string): boolean {
  return spec.startsWith("/dev/") ||
    /^(UUID|LABEL|PARTUUID|PARTLABEL|ID)=/.test(spec);
}

/** Collects protected devices with reasons. */
class Collector {
  readonly devices: ProtectedDevices = {};
  readonly volumeGroups = new Set<string>();
  readonly arrayUuids = new Set<string>();
  readonly pools = new Set<string>();

  constructor(private readonly graph: Graph) {}

  /** Protects the whole connected stack around `path`. */
  protect(path: string, reason: string): void {
    for (const p of component(this.graph, path)) {
      const list = (this.devices[p] ??= []);
      const why = p === path
        ? reason
        : `part of the stack of ${path}: ${reason}`;
      if (!list.includes(why)) list.push(why);
    }
  }
}

/** Resolves an fstab spec to lsblk paths, using lsblk then blkid. */
function resolveSpec(
  spec: string,
  graph: Graph,
  resolver: Resolver,
  blkid: Map<string, Record<string, string>>,
): string[] {
  if (spec.startsWith("/dev/")) {
    const path = resolver.resolve(spec);
    return path ? [path] : [];
  }
  const eq = spec.indexOf("=");
  const key = spec.slice(0, eq);
  const value = spec.slice(eq + 1).replace(/^"|"$/g, "");
  const wantUuid = normalizeUuid(value);
  const field: Record<string, (n: Node) => boolean> = {
    UUID: (n) => n.uuid !== "" && normalizeUuid(n.uuid) === wantUuid,
    PARTUUID: (n) =>
      n.partuuid !== "" && n.partuuid.toLowerCase() === value.toLowerCase(),
    LABEL: (n) => n.label === value,
  };
  const matches: string[] = [];
  const test = field[key];
  if (test) {
    for (const node of graph.nodes.values()) {
      if (test(node)) matches.push(node.path);
    }
  }
  if (matches.length > 0) return matches;
  // Udev-less host: lsblk could not label it, blkid may still know the device.
  const idName = key === "ID" ? "" : key;
  for (const [path, ids] of blkid) {
    const have = ids[idName];
    if (
      have !== undefined &&
      (idName === "UUID" || idName === "PARTUUID"
        ? normalizeUuid(have) === wantUuid
        : have === value)
    ) {
      const resolved = resolver.resolve(path);
      if (resolved) matches.push(resolved);
    }
  }
  if (matches.length > 0) return matches;
  // by-* names resolve through the link table.
  const byDir: Record<string, string> = {
    UUID: "by-uuid",
    PARTUUID: "by-partuuid",
    LABEL: "by-label",
    PARTLABEL: "by-partlabel",
    ID: "by-id",
  };
  const dir = byDir[key];
  if (dir) {
    const path = resolver.resolve(`/dev/disk/${dir}/${value}`);
    if (path) return [path];
  }
  return [];
}

/** Computes the protected set from the probes, or throws {@link Unverifiable}. */
function compute(input: ProbeInputs): ProtectedSet {
  const graph = parseLsblkGraph(input.lsblk);
  const resolver = new Resolver(graph, input.links);
  const mounts = parseFindmnt(input.findmnt);
  const collector = new Collector(graph);
  const blkid = parseBlkid(input.blkid);

  const mdEvidence = [...graph.nodes.values()].some((n) =>
    n.fstype === "linux_raid_member" || n.path.startsWith("/dev/md")
  );
  let mdArrays: MdArray[] = [];
  if (input.mdstat.state === "error") {
    unverifiable("/proc/mdstat could not be read", {
      detail: input.mdstat.detail,
    });
  } else if (input.mdstat.state === "absent") {
    if (mdEvidence) {
      unverifiable("md devices exist but /proc/mdstat is absent");
    }
  } else {
    mdArrays = parseMdstat(input.mdstat.text);
  }

  let fstab: FstabEntry[] = [];
  if (input.fstab.state === "error") {
    unverifiable("/etc/fstab could not be read", {
      detail: input.fstab.detail,
    });
  } else if (input.fstab.state === "ok") {
    fstab = parseFstab(input.fstab.text);
  }

  if (input.swaps.state !== "ok") {
    unverifiable("/proc/swaps could not be read");
  }

  const zfsPools = new Set<string>();

  /** Protects the stack behind `sourcePath`, using mdstat for an inactive array. */
  const seedDevice = (source: string, reason: string): void => {
    const path = resolver.resolve(source);
    if (path) {
      collector.protect(path, reason);
      return;
    }
    // An md array that is not assembled has no lsblk row but is in mdstat.
    const mdName =
      /^\/dev\/(md[A-Za-z0-9_]*)$/.exec(source.replace(/\[[^\]]*\]$/, ""))
        ?.[1] ??
        /^\/dev\/md\/(.+)$/.exec(source)?.[1];
    const array = mdArrays.find((a) => a.name === mdName);
    if (array && array.members.length > 0) {
      for (const member of array.members) {
        const m = resolver.resolve(`/dev/${member}`);
        if (!m) {
          unverifiable("an md array member cannot be resolved", {
            array: array.name,
            member,
          });
        }
        collector.protect(m, `${reason} (inactive array ${array.name})`);
      }
      return;
    }
    unverifiable("a mounted or configured device cannot be resolved", {
      source,
      reason,
    });
  };

  const noteZfs = (spec: string): void => {
    const pool = spec.split("/")[0];
    if (pool) zfsPools.add(pool);
  };

  // 1. Live mounts: / must exist and be understood.
  const root = mounts.find((m) => m.target === "/");
  if (!root || root.source === "") {
    unverifiable('"/" is not in the live mount table');
  }
  for (const m of mounts) {
    const strict = m.target === "/" || m.target === "/boot" ||
      m.target.startsWith("/boot/");
    if (m.fstype === "zfs") {
      noteZfs(m.source);
      continue;
    }
    if (NON_BLOCK_FS.has(m.fstype) && !strict) continue;
    if (!m.source.startsWith("/dev/")) {
      if (strict) {
        unverifiable("a root or boot mount has no block device source", {
          target: m.target,
          source: m.source,
        });
      }
      continue;
    }
    seedDevice(m.source, `mounted at ${m.target}`);
  }

  // 2. Every fstab entry, mounted or not.
  for (const entry of fstab) {
    if (entry.fstype === "zfs") {
      noteZfs(entry.spec);
      continue;
    }
    if (!deviceReference(entry.spec)) {
      const bind = /(^|,)r?bind(,|$)/.test(entry.options);
      if (
        NON_BLOCK_FS.has(entry.fstype) || entry.fstype.startsWith("fuse") ||
        bind || (entry.fstype === "swap" && !entry.spec.startsWith("/dev/"))
      ) {
        continue;
      }
      unverifiable("an /etc/fstab source cannot be classified", {
        spec: entry.spec,
        fstype: entry.fstype,
      });
    }
    const found = resolveSpec(entry.spec, graph, resolver, blkid);
    if (found.length === 0) {
      const mdName = /^\/dev\/(md[A-Za-z0-9_]*)$/.exec(entry.spec)?.[1];
      if (mdName && mdArrays.some((a) => a.name === mdName)) {
        seedDevice(entry.spec, `listed in /etc/fstab for ${entry.target}`);
        continue;
      }
      unverifiable("an /etc/fstab device cannot be resolved", {
        spec: entry.spec,
        target: entry.target,
      });
    }
    for (const p of found) {
      collector.protect(p, `listed in /etc/fstab for ${entry.target}`);
    }
  }

  // 3. Active swap.
  if (input.swaps.state === "ok") {
    const lines = input.swaps.text.split("\n").slice(1);
    for (const line of lines) {
      const f = line.trim().split(/\s+/);
      if (f.length < 2 || f[0] === "") continue;
      if (f[1] === "file") continue; // lives on a mounted filesystem
      if (!f[0].startsWith("/dev/")) {
        unverifiable("a swap device cannot be classified", { swap: f[0] });
      }
      seedDevice(f[0], "active swap");
    }
  }

  // 3b. A multi-device filesystem is reported under one device in the mount
  // table but lives on every device carrying its UUID.
  for (const path of Object.keys(collector.devices)) {
    const node = graph.nodes.get(path);
    if (!node || !node.uuid || !MULTI_DEVICE_FS.has(node.fstype)) continue;
    for (const other of graph.nodes.values()) {
      if (
        other.path !== path && other.fstype === node.fstype &&
        other.uuid === node.uuid
      ) {
        collector.protect(
          other.path,
          `shares ${node.fstype} filesystem ${node.uuid} with ${path}`,
        );
      }
    }
  }

  // 4. md arrays: members from mdstat (any flag), and by array UUID.
  const protectedNow = (): string[] => Object.keys(collector.devices);
  for (const array of mdArrays) {
    const arrayPath = resolver.resolve(`/dev/${array.name}`);
    const backing = (arrayPath && collector.devices[arrayPath]) ||
      array.members.some((m) => {
        const p = resolver.resolve(`/dev/${m}`);
        return p !== null && collector.devices[p] !== undefined;
      });
    if (!backing) continue;
    for (const member of array.members) {
      const p = resolver.resolve(`/dev/${member}`);
      if (!p) {
        unverifiable("an md array member cannot be resolved", {
          array: array.name,
          member,
        });
      }
      collector.protect(p, `member of protected array ${array.name}`);
    }
  }
  for (const [path, probe] of Object.entries(input.mdExamine)) {
    if (probe.code === 0) continue;
    // Only mdadm's explicit "not a member" answer is a clean negative. A
    // missing binary, a permission or I/O error says nothing about the device.
    if (probe.code === 127 || !NOT_A_MEMBER.test(probe.stdout)) {
      unverifiable("mdadm could not examine a device", {
        device: path,
        exit: probe.code,
      });
    }
  }
  const examineFor = (path: string): string | null => {
    const probe = input.mdExamine[path];
    if (!probe) return null;
    if (probe.code !== 0) return null;
    return parseExamineUuid(probe.stdout);
  };
  for (const path of protectedNow()) {
    const node = graph.nodes.get(path);
    if (!node || node.fstype !== "linux_raid_member") continue;
    const probe = input.mdExamine[path];
    if (!probe) {
      unverifiable("a protected md member was not examined", { device: path });
    }
    const uuid = examineFor(path);
    if (!uuid) {
      unverifiable("mdadm could not identify a protected md member", {
        device: path,
        exit: probe.code,
      });
    }
    collector.arrayUuids.add(uuid);
    if (node.uuid) collector.arrayUuids.add(normalizeUuid(node.uuid));
  }
  // Any other member of a protected array, assembled or not.
  for (const node of graph.nodes.values()) {
    if (collector.devices[node.path]) continue;
    const examined = examineFor(node.path);
    const lsblkUuid = node.fstype === "linux_raid_member" && node.uuid
      ? normalizeUuid(node.uuid)
      : null;
    if (
      (examined && collector.arrayUuids.has(examined)) ||
      (lsblkUuid && collector.arrayUuids.has(lsblkUuid))
    ) {
      collector.protect(node.path, "member of a protected md array (by UUID)");
    }
  }

  // 5. LVM: a protected logical volume protects every PV of its volume group.
  for (const path of protectedNow()) {
    const node = graph.nodes.get(path);
    if (node?.type !== "lvm") continue;
    const vg = volumeGroupOf(node.name);
    if (!vg) {
      unverifiable("a protected logical volume has an unreadable name", {
        device: path,
      });
    }
    collector.volumeGroups.add(vg);
  }
  if (collector.volumeGroups.size > 0) {
    if (input.pvs.code !== 0 || input.pvs.stdout.trim() === "") {
      unverifiable("the LVM physical volumes could not be listed", {
        exit: input.pvs.code,
      });
    }
    for (const line of input.pvs.stdout.split("\n")) {
      const f = line.trim().split(/\s+/);
      if (f.length < 2 || !collector.volumeGroups.has(f[1])) continue;
      const pv = resolver.resolve(f[0]);
      if (!pv) {
        unverifiable(
          "a physical volume of a protected group cannot be resolved",
          {
            volumeGroup: f[1],
            device: f[0],
          },
        );
      }
      collector.protect(
        pv,
        `physical volume of protected volume group ${f[1]}`,
      );
    }
  }

  // 6. ZFS: every vdev of a pool behind a protected mount.
  const zfsPresent = zfsPools.size > 0 ||
    [...graph.nodes.values()].some((n) => n.fstype === "zfs_member");
  if (zfsPools.size > 0 || zfsPresent) {
    if (input.zpool.code === 127 && zfsPools.size === 0) {
      // ZFS is not installed and nothing mounted uses it: nothing to protect.
    } else {
      if (input.zpool.code !== 0) {
        unverifiable("zpool status failed", { exit: input.zpool.code });
      }
      const status = parseZpoolStatus(input.zpool.stdout);
      for (const pool of zfsPools) {
        const vdevs = status.get(pool);
        if (!vdevs) {
          unverifiable("a ZFS pool behind a mount is not in zpool status", {
            pool,
          });
        }
        if (vdevs.length === 0) {
          unverifiable("a ZFS pool behind a mount lists no devices", { pool });
        }
        collector.pools.add(pool);
        for (const vdev of vdevs) {
          const path = resolver.resolve(
            vdev.startsWith("/") ? vdev : `/dev/${vdev}`,
          );
          if (!path) {
            unverifiable("a ZFS vdev cannot be resolved to a device", {
              pool,
              vdev,
            });
          }
          collector.protect(path, `vdev of ZFS pool ${pool}`);
        }
      }
      // A member whose label names a protected pool is protected even when
      // zpool printed it under a name this host cannot resolve.
      for (const node of graph.nodes.values()) {
        if (node.fstype === "zfs_member" && collector.pools.has(node.label)) {
          collector.protect(node.path, `member of ZFS pool ${node.label}`);
        }
      }
    }
  }

  return {
    devices: collector.devices,
    volumeGroups: [...collector.volumeGroups].sort(),
    arrayUuids: [...collector.arrayUuids].sort(),
    pools: [...collector.pools].sort(),
  };
}

/**
 * The paths whose `mdadm --examine` output the module needs: every md member
 * lsblk lists, plus the disk and each partition of every candidate. Returns an
 * empty list when lsblk cannot be read; {@link assess} then refuses.
 */
export function examineTargets(
  lsblk: CommandProbe,
  candidates: string[],
): string[] {
  let graph: Graph;
  try {
    graph = parseLsblkGraph(lsblk);
  } catch {
    return [];
  }
  const out = new Set<string>();
  for (const node of graph.nodes.values()) {
    if (node.fstype === "linux_raid_member") out.add(node.path);
  }
  for (const c of candidates) {
    for (const p of subtree(graph, c)) {
      const t = graph.nodes.get(p)?.type;
      if (t === "disk" || t === "part") out.add(p);
    }
  }
  return [...out].sort();
}

/** Merges two protected sets; a device protected by either stays protected. */
export function unionProtected(a: ProtectedSet, b: ProtectedSet): ProtectedSet {
  const devices: ProtectedDevices = {};
  for (const src of [a.devices, b.devices]) {
    for (const [path, reasons] of Object.entries(src)) {
      const list = (devices[path] ??= []);
      for (const r of reasons) if (!list.includes(r)) list.push(r);
    }
  }
  const merge = (x: string[], y: string[]) => [...new Set([...x, ...y])].sort();
  return {
    devices,
    volumeGroups: merge(a.volumeGroups, b.volumeGroups),
    arrayUuids: merge(a.arrayUuids, b.arrayUuids),
    pools: merge(a.pools, b.pools),
  };
}

/** Checks candidates against a set using the current device graph. */
function conflict(
  set: ProtectedSet,
  input: ProbeInputs,
  candidates: string[],
): Refusal | null {
  const graph = parseLsblkGraph(input.lsblk);
  const resolver = new Resolver(graph, input.links);
  const pvs = new Map<string, string>();
  if (input.pvs.code === 0) {
    for (const line of input.pvs.stdout.split("\n")) {
      const f = line.trim().split(/\s+/);
      if (f.length >= 2) {
        const pv = resolver.resolve(f[0]);
        if (pv) pvs.set(pv, f[1]);
      }
    }
  }
  const uuids = new Set(set.arrayUuids);
  const vgs = new Set(set.volumeGroups);
  const pools = new Set(set.pools);
  for (const candidate of candidates) {
    const path = resolver.resolve(candidate);
    if (!path) {
      return {
        code: "unverifiable",
        message: "a candidate device is not in lsblk, so its safety is unknown",
        detail: { device: candidate },
      };
    }
    for (const p of subtree(graph, path)) {
      const reasons = set.devices[p];
      if (reasons) {
        return {
          code: "protected",
          message: p === path
            ? "the device backs the running or bootable system"
            : "something on the device backs the running or bootable system",
          detail: { device: path, protectedDevice: p, reasons },
        };
      }
      const node = graph.nodes.get(p)!;
      const probe = input.mdExamine[p];
      if (probe && probe.code === 0) {
        const uuid = parseExamineUuid(probe.stdout);
        if (uuid && uuids.has(uuid)) {
          return {
            code: "protected",
            message:
              "the device is a member of an md array that backs the system",
            detail: { device: path, member: p, arrayUuid: uuid },
          };
        }
      }
      if (node.fstype === "linux_raid_member" && node.uuid) {
        if (uuids.has(normalizeUuid(node.uuid))) {
          return {
            code: "protected",
            message:
              "the device is a member of an md array that backs the system",
            detail: { device: path, member: p },
          };
        }
      }
      const vg = pvs.get(p);
      if (vg && vgs.has(vg)) {
        return {
          code: "protected",
          message:
            "the device is a physical volume of a protected volume group",
          detail: { device: path, member: p, volumeGroup: vg },
        };
      }
      if (node.fstype === "zfs_member" && pools.has(node.label)) {
        return {
          code: "protected",
          message: "the device is a member of a protected ZFS pool",
          detail: { device: path, member: p, pool: node.label },
        };
      }
    }
  }
  return null;
}

/**
 * Builds the protected set from the probes and judges the candidates against
 * it. Pass `previous` on a re-read so the result is never smaller than the
 * set already established. The candidates are canonical device paths.
 */
export function assess(
  input: ProbeInputs,
  candidates: string[],
  previous?: ProtectedSet,
): Assessment {
  try {
    if (candidates.length === 0) {
      unverifiable("no candidate devices were given");
    }
    let set = compute(input);
    if (previous) set = unionProtected(previous, set);
    const hit = conflict(set, input, candidates);
    if (hit) return { ok: false, refusal: hit };
    return { ok: true, set };
  } catch (e) {
    if (e instanceof Unverifiable) {
      return refuse("unverifiable", e.message, e.detail);
    }
    throw e;
  }
}
