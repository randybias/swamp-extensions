/**
 * Disk wiping: tear down LVM, md-RAID, filesystem and partition state on
 * disks named by serial, leaving them raw for Ceph OSDs, while keeping the
 * host's boot RAID configuration intact.
 *
 * Before anything destructive, an explicit protected-device set is built from
 * the mounted root and boot filesystems, the configured mounts, and the member
 * devices of any array that backs them. A selected disk that is part of, or is
 * the disk behind, a boot or root array is refused even when the array is
 * unmounted, inactive or degraded. Every gate re-reads the host; a device
 * missing from a read is never reported raw. Root-owned files are written only
 * through `tee` on stdin, validated, then moved into place atomically.
 *
 * @module
 */

import { fail, TransportError } from "./errors.ts";
import type { CommandResult, SshSession } from "./ssh.ts";
import { isSudoRefusal } from "./ssh.ts";
import { assertMdArrayPath, assertVgName, quote } from "./validate.ts";
import { type ResolvedDevice, resolveSerial } from "./resolve.ts";
import type { PrepDeps } from "./hostprep.ts";

/** One disk selected by serial. */
export interface DataDevice {
  /** Device serial. */
  serial: string;
  /** Informational size hint; never used for selection. */
  sizeBytes?: number;
  /** Informational kernel-name hint; never used for selection. */
  devHint?: string;
}

/** One disk that must never be touched. */
export interface ExcludedDevice {
  /** Device serial. */
  serial: string;
  /** Why it is excluded. */
  reason?: string;
}

/** Arguments for a wipe. */
export interface WipeArgs {
  /** Disks to wipe. */
  dataDevices: DataDevice[];
  /** Never-touch list; required even when empty. */
  excludeDevices: ExcludedDevice[];
  /** Plan only, run nothing destructive. */
  dryRun?: boolean | null;
}

/** The record a wipe writes. */
export interface WipeRecord {
  /** Target host. */
  host: string;
  /** Whether this was a dry run. */
  dryRun: boolean;
  /** Capture time. */
  capturedAt: string;
  /** True when every selected disk was already raw, so nothing was changed. */
  alreadyRaw?: boolean;
  /** Dry-run plan. */
  plannedDevices?: { serial: string; device: string }[];
  /** Dry-run exclusions. */
  excludedDevices?: { serial: string; device: string }[];
  /** Real-run wiped disks. */
  wiped?: { serial: string; device: string }[];
  /** Whether `/etc/mdadm/mdadm.conf` exists. */
  mdadmConfPresent?: boolean;
  /** Stable backup path, or null when the file was absent. */
  backupPath?: string | null;
  /** Removed volume groups. */
  removedVolumeGroups?: string[];
  /** Stopped md arrays. */
  stoppedArrays?: string[];
  /** Whether the md config was rewritten. */
  mdConfigRewritten?: boolean;
  /** Whether the initramfs was rebuilt. */
  initramfsRebuilt?: boolean;
  /** `mdadm --detail --scan` before teardown. */
  preTeardownMdadmScan?: string;
  /** SHA-256 of the captured `/etc/fstab`, never its contents. */
  preTeardownFstabSha256?: string;
  /** Number of non-blank `/etc/fstab` lines captured. */
  preTeardownFstabEntries?: number;
}

interface LsblkNode {
  name?: string;
  path?: string;
  mountpoint?: string | null;
  type?: string;
  fstype?: string | null;
  children?: LsblkNode[];
}

const MDADM_CONF = "/etc/mdadm/mdadm.conf";
const MDADM_BACKUP = "/etc/mdadm/mdadm.conf.cephadm.bak";

/** Command used by every teardown step that must re-read the tree. */
export function lsblkCommand(): string {
  return "lsblk -J -o NAME,PATH,MOUNTPOINT,TYPE,FSTYPE";
}

/** Parses lsblk JSON or throws the phase error the wipe owns. */
export function parseLsblk(stdout: string): LsblkNode[] {
  let parsed: unknown;
  try {
    parsed = JSON.parse(stdout);
  } catch {
    fail("wipe.lsblk-invalid", "lsblk did not return JSON");
  }
  const devices = (parsed as { blockdevices?: LsblkNode[] }).blockdevices;
  if (!Array.isArray(devices)) {
    fail("wipe.lsblk-invalid", "lsblk JSON has no blockdevices");
  }
  return devices;
}

/** Finds the node whose `path` equals `device`. */
export function findNode(nodes: LsblkNode[], device: string): LsblkNode | null {
  for (const node of nodes) {
    if (node.path === device) return node;
    const found = node.children ? findNode(node.children, device) : null;
    if (found) return found;
  }
  return null;
}

/** Finds the top-level disk node that contains `device`. */
export function findTopLevel(
  nodes: LsblkNode[],
  device: string,
): LsblkNode | null {
  for (const node of nodes) {
    if (node.path === device || findNode([node], device)) return node;
  }
  return null;
}

/** The paths of a node and every descendant. */
export function subtreePaths(node: LsblkNode): string[] {
  const out: string[] = [];
  if (node.path) out.push(node.path);
  for (const child of node.children ?? []) out.push(...subtreePaths(child));
  return out;
}

/** All mountpoints anywhere in a node's subtree. */
export function subtreeMounts(node: LsblkNode): string[] {
  const out: string[] = [];
  if (node.mountpoint) out.push(node.mountpoint);
  for (const child of node.children ?? []) out.push(...subtreeMounts(child));
  return out;
}

/** Child types present anywhere in a node's subtree. */
export function subtreeTypes(node: LsblkNode): string[] {
  const out: string[] = [];
  for (const child of node.children ?? []) {
    if (child.type) out.push(child.type);
    out.push(...subtreeTypes(child));
  }
  return out;
}

/** The basename of an md array path, e.g. `md0` for `/dev/md0`. */
export function arrayBasename(arrayPath: string): string {
  const at = arrayPath.lastIndexOf("/");
  return at < 0 ? arrayPath : arrayPath.slice(at + 1);
}

/** The array path on an `ARRAY ...` line, or null. */
export function parseArrayScanLine(line: string): string | null {
  const m = line.trim().match(/^ARRAY\s+(\S+)/);
  return m ? m[1] : null;
}

/** The first `ARRAY` path in `mdadm --examine --scan` output, or null. */
export function firstArrayPath(stdout: string): string | null {
  for (const line of stdout.split("\n")) {
    const path = parseArrayScanLine(line);
    if (path) return path;
  }
  return null;
}

/** Removes only the anchored line for exactly `arrayPath` from md config text. */
export function removeArrayLine(text: string, arrayPath: string): string {
  const escaped = arrayPath.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const re = new RegExp(`^ARRAY\\s+${escaped}(\\s|$)`);
  return text.split("\n").filter((line) => !re.test(line)).join("\n");
}

/** Appends a scan line for `arrayPath` only when no anchored line exists. */
export function ensureArrayLine(
  text: string,
  arrayPath: string,
  scanLine: string,
): string {
  const escaped = arrayPath.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const re = new RegExp(`^ARRAY\\s+${escaped}(\\s|$)`);
  if (text.split("\n").some((line) => re.test(line))) return text;
  const base = text.replace(/\n+$/, "");
  return `${base}${base === "" ? "" : "\n"}${scanLine.trim()}\n`;
}

/** The complete new md config after removals and boot-line restoration. */
export function editMdConfig(
  text: string,
  stopped: string[],
  scan: string,
): string {
  let next = text;
  for (const array of stopped) next = removeArrayLine(next, array);
  let nextScan = scan;
  for (const array of stopped) nextScan = removeArrayLine(nextScan, array);
  for (const line of nextScan.split("\n")) {
    const path = parseArrayScanLine(line);
    if (path) next = ensureArrayLine(next, path, line);
  }
  const collapsed = next.split("\n").filter((l, i, all) =>
    !(l === "" && i === all.length - 1)
  );
  const joined = collapsed.join("\n");
  return joined.endsWith("\n") ? joined : `${joined}\n`;
}

/** The languages of protection a disk can have. */
export interface ProtectedSet {
  /** Canonical device paths that must not be touched. */
  devices: Set<string>;
  /** md array paths that back the root or boot filesystem. */
  arrays: Set<string>;
}

/** True for a mount target that is the root or part of the boot tree. */
function isBootTarget(target: string): boolean {
  return target === "/" || target === "/boot" || target === "/boot/efi" ||
    target.startsWith("/boot/");
}

/** Finds a node whose path or kernel name is one of `candidates`. */
export function findNodeByAny(
  nodes: LsblkNode[],
  candidates: Set<string>,
): LsblkNode | null {
  for (const node of nodes) {
    if (
      (node.path && candidates.has(node.path)) ||
      (node.name && candidates.has(node.name))
    ) {
      return node;
    }
    const found = node.children
      ? findNodeByAny(node.children, candidates)
      : null;
    if (found) return found;
  }
  return null;
}

/**
 * Builds the protected-device set from the mounted and configured root/boot
 * filesystems. It walks the whole storage dependency graph in both directions
 * from each source, so a root on LVM over md protects the md device and every
 * physical member behind it, and a root on a plain partition protects the
 * whole disk. md devices anywhere in the graph are recorded so an inactive
 * array is still caught by serial membership. Runs before any mutation and is
 * not recomputed from a later tree.
 */
export async function detectProtectedSet(
  session: SshSession,
  tree: LsblkNode[],
): Promise<ProtectedSet> {
  const devices = new Set<string>();
  const arrays = new Set<string>();

  // Undirected adjacency keyed by path; duplicate md nodes under each member
  // merge because the key is the path.
  const adjacency = new Map<string, Set<string>>();
  const edge = (a: string, b: string): void => {
    if (!adjacency.has(a)) adjacency.set(a, new Set());
    if (!adjacency.has(b)) adjacency.set(b, new Set());
    adjacency.get(a)!.add(b);
    adjacency.get(b)!.add(a);
  };
  const index = (node: LsblkNode): void => {
    for (const child of node.children ?? []) {
      if (node.path && child.path) edge(node.path, child.path);
      index(child);
    }
  };
  for (const node of tree) index(node);

  const protectComponent = (seed: string): void => {
    const queue = [seed];
    const seen = new Set([seed]);
    while (queue.length > 0) {
      const path = queue.shift()!;
      devices.add(path);
      if (path.startsWith("/dev/md")) arrays.add(path);
      for (const neighbour of adjacency.get(path) ?? []) {
        if (!seen.has(neighbour)) {
          seen.add(neighbour);
          queue.push(neighbour);
        }
      }
    }
  };

  const addSource = async (source: string): Promise<void> => {
    if (!source.startsWith("/dev/")) return;
    const resolved = (
      await session.run({
        command: `readlink -f ${quote(source)}`,
        allowNonZero: true,
      })
    ).stdout.trim();
    const device = resolved || source;
    const candidates = new Set(
      [
        source,
        device,
        source.split("/").at(-1) ?? "",
        device.split("/").at(-1) ?? "",
      ]
        .filter((c) => c !== ""),
    );
    const node = findNodeByAny(tree, candidates);
    protectComponent(node?.path ?? device);
  };

  const readMounts = async (command: string): Promise<void> => {
    const r = await session.run({ command, allowNonZero: true });
    for (const line of r.stdout.split("\n")) {
      const [source, target] = line.trim().split(/\s+/);
      if (!source || !target) continue;
      if (isBootTarget(target)) await addSource(source);
    }
  };
  // Actual mounts, then the configured ones (which catch an inactive array).
  await readMounts("findmnt -rno SOURCE,TARGET");
  await readMounts("findmnt --fstab -rno SOURCE,TARGET --evaluate");
  return { devices, arrays };
}

/** A full wipe run's dependencies. */
export interface WipeDeps extends PrepDeps {
  /** The SSH session. */
  session: SshSession;
}

/** Runs one command as root, returning its result, and refusing a sudo refusal. */
async function root(
  session: SshSession,
  command: string,
  opts: { allowNonZero?: boolean; stdin?: string } = {},
): Promise<CommandResult> {
  const r = await session.run({
    command,
    sudo: true,
    allowNonZero: true,
    ...(opts.stdin !== undefined ? { stdin: opts.stdin } : {}),
  });
  if (r.code !== 0 && isSudoRefusal(r.stderr)) {
    fail("wipe.sudo", "passwordless sudo is required");
  }
  if (!opts.allowNonZero && r.code !== 0) {
    fail("wipe.step", `command failed: ${command}`, {
      code: r.code,
      stderr: r.stderr.slice(0, 300),
    });
  }
  return r;
}

/** The volume group a device is a physical volume of, or "". */
async function pvsVg(session: SshSession, device: string): Promise<string> {
  const r = await root(
    session,
    `pvs --noheadings -o vg_name -- ${quote(device)}`,
    {
      allowNonZero: true,
    },
  );
  return r.stdout.trim();
}

/** The md array a device belongs to, or null. */
async function examineArray(
  session: SshSession,
  device: string,
): Promise<string | null> {
  const r = await root(session, `mdadm --examine --scan -- ${quote(device)}`, {
    allowNonZero: true,
  });
  return firstArrayPath(r.stdout);
}

/** A read-only poll of `/proc/mdstat` until an array's line disappears. */
async function arrayStillPresent(
  deps: WipeDeps,
  basename: string,
): Promise<boolean> {
  for (let i = 0; i < 10; i++) {
    const status = await deps.session.run({
      command: "cat /proc/mdstat",
      allowNonZero: true,
    });
    const present = status.stdout.split("\n").some((l) =>
      l.startsWith(`${basename} :`)
    );
    if (!present) return false;
    await deps.sleep(1000);
  }
  return true;
}

/** Reads the lsblk tree once, mapping parse failures to the wipe's phase. */
async function readLsblk(session: SshSession): Promise<LsblkNode[]> {
  const r = await session.run({ command: lsblkCommand(), allowNonZero: true });
  return parseLsblk(r.stdout);
}

/** True when one device is already raw: no signature, no children, no array, no PV. */
async function deviceIsRaw(
  session: SshSession,
  tree: LsblkNode[],
  device: string,
): Promise<boolean> {
  const node = findNode(tree, device);
  if (!node) return false;
  if (node.fstype) return false;
  if ((node.children ?? []).length > 0) return false;
  if (subtreeMounts(node).length > 0) return false;
  if ((await pvsVg(session, device)) !== "") return false;
  if ((await examineArray(session, device)) !== null) return false;
  return true;
}

/** SHA-256 hex of a string. */
async function sha256Hex(text: string): Promise<string> {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(text),
  );
  return Array.from(new Uint8Array(digest)).map((b) =>
    b.toString(16).padStart(2, "0")
  ).join("");
}

/**
 * Runs a full wipe: gates, optional dry run, teardown, config repair and raw
 * verification. Returns the record the method should store.
 */
export async function wipeDiskToRaw(
  deps: WipeDeps,
  args: WipeArgs,
  log?: {
    info: (m: string, p?: Record<string, unknown>) => void;
    warn: (m: string, p?: Record<string, unknown>) => void;
  },
): Promise<WipeRecord> {
  const session = deps.session;
  const host = session.target.host;
  const dryRun = args.dryRun ?? false;

  // Gate 1: conflict, with zero ssh calls.
  const dataSerials = new Set(args.dataDevices.map((d) => d.serial));
  for (const ex of args.excludeDevices) {
    if (dataSerials.has(ex.serial)) {
      fail(
        "wipe.conflict",
        "a serial appears in both dataDevices and excludeDevices",
        {
          serial: ex.serial,
        },
      );
    }
  }

  // Gate 2: resolve every serial.
  const resolved = new Map<string, ResolvedDevice>();
  for (const d of args.dataDevices) {
    resolved.set(
      d.serial,
      await resolveSerial(session, d.serial, "wipe.resolve"),
    );
  }
  const excluded = new Map<string, ResolvedDevice>();
  for (const e of args.excludeDevices) {
    excluded.set(
      e.serial,
      await resolveSerial(session, e.serial, "wipe.resolve"),
    );
  }

  // Gate 3: in use.
  const tree = await readLsblk(session);
  for (const d of args.dataDevices) {
    const device = resolved.get(d.serial)!;
    const node = findNode(tree, device.device);
    if (!node) {
      fail(
        "wipe.in-use",
        "data device is absent from lsblk, so its safety cannot be verified",
        {
          host,
          serial: d.serial,
          device: device.device,
        },
      );
    }
    const mounts = subtreeMounts(node);
    if (mounts.length > 0) {
      fail(
        "wipe.in-use",
        "a data device, or something in its subtree, is mounted",
        {
          host,
          serial: d.serial,
          device: device.device,
          mountpoints: mounts,
        },
      );
    }
  }

  // Gate 3b: never eat the boot or root array, even when it is unmounted and
  // inactive. Built once, before anything destructive.
  const protectedSet = await detectProtectedSet(session, tree);
  for (const d of args.dataDevices) {
    const device = resolved.get(d.serial)!;
    if (protectedSet.devices.has(device.device)) {
      fail(
        "wipe.boot-protected",
        "the disk backs the root or boot filesystem",
        {
          host,
          serial: d.serial,
          device: device.device,
        },
      );
    }
    const array = await examineArray(session, device.device);
    if (array !== null && protectedSet.arrays.has(array)) {
      fail(
        "wipe.boot-protected",
        "the disk is a member of an array that backs root or boot",
        {
          host,
          serial: d.serial,
          device: device.device,
          array,
        },
      );
    }
  }

  // Gate 4: a data device aliasing an excluded disk.
  for (const d of args.dataDevices) {
    const device = resolved.get(d.serial)!;
    for (const e of args.excludeDevices) {
      if (excluded.get(e.serial)!.device === device.device) {
        fail(
          "wipe.excluded-path",
          "a data device is the same physical disk as an excluded one",
          {
            host,
            serial: d.serial,
            excludedSerial: e.serial,
            device: device.device,
          },
        );
      }
    }
  }

  const capturedAt = new Date(deps.now()).toISOString();
  if (dryRun) {
    log?.info("wipe dry run", { host, data: args.dataDevices.length });
    return {
      host,
      dryRun: true,
      capturedAt,
      plannedDevices: args.dataDevices.map((d) => ({
        serial: d.serial,
        device: resolved.get(d.serial)!.path,
      })),
      excludedDevices: args.excludeDevices.map((e) => ({
        serial: e.serial,
        device: excluded.get(e.serial)!.path,
      })),
    };
  }

  const devices = args.dataDevices.map((d) => resolved.get(d.serial)!);

  // Idempotency fast path: if every disk is already raw there is nothing to
  // mutate, so no backup is taken and no teardown command runs.
  let allRaw = true;
  for (const device of devices) {
    if (!(await deviceIsRaw(session, tree, device.device))) {
      allRaw = false;
      break;
    }
  }
  if (allRaw) {
    log?.info("wipe devices already raw", { host });
    return {
      host,
      dryRun: false,
      capturedAt,
      alreadyRaw: true,
      wiped: args.dataDevices.map((d) => ({
        serial: d.serial,
        device: resolved.get(d.serial)!.path,
      })),
      mdadmConfPresent: false,
      backupPath: null,
      removedVolumeGroups: [],
      stoppedArrays: [],
      mdConfigRewritten: false,
      initramfsRebuilt: false,
    };
  }

  // Step 0: recovery capture and one stable, idempotent backup.
  log?.info("wipe phase recovery-capture", { host });
  const conf = await session.run({
    command: `test -e ${MDADM_CONF}`,
    allowNonZero: true,
  });
  const mdadmConfPresent = conf.code === 0;
  let backupPath: string | null = null;
  if (mdadmConfPresent) {
    backupPath = MDADM_BACKUP;
    const existing = await session.run({
      command: `test -e ${quote(MDADM_BACKUP)}`,
      allowNonZero: true,
    });
    if (existing.code !== 0) {
      const backup = await root(
        session,
        `cp -a -- ${quote(MDADM_CONF)} ${quote(MDADM_BACKUP)}`,
        {
          allowNonZero: true,
        },
      );
      if (backup.code !== 0) {
        fail("wipe.backup", "could not back up the md config", {
          path: MDADM_CONF,
        });
      }
    }
  }
  const scanBefore = (
    await root(session, "mdadm --detail --scan", { allowNonZero: true })
  ).stdout;
  const fstab =
    (await session.run({ command: "cat /etc/fstab", allowNonZero: true }))
      .stdout;
  const fstabSha256 = await sha256Hex(fstab);
  const fstabEntries = fstab.split("\n").filter((l) => l.trim() !== "").length;

  // Step 1: LVM teardown, deduplicated.
  log?.info("wipe phase lvm", { host });
  const removedVolumeGroups: string[] = [];
  const pvs: string[] = [];
  for (const device of devices) {
    const vg = await pvsVg(session, device.device);
    if (vg === "") continue;
    assertVgName("volumeGroup", vg);
    pvs.push(device.device);
    if (!removedVolumeGroups.includes(vg)) {
      await root(session, `vgchange -an -- ${quote(vg)}`, {
        allowNonZero: true,
      });
      await root(session, `lvremove -f -- ${quote(vg)}`, {
        allowNonZero: true,
      });
      await root(session, `vgremove -f -- ${quote(vg)}`, {
        allowNonZero: true,
      });
      removedVolumeGroups.push(vg);
    }
  }
  for (const device of pvs) {
    await root(session, `pvremove -ff -y -- ${quote(device)}`, {
      allowNonZero: true,
    });
  }

  // Step 2: LVM gate, only when a PV was found.
  if (pvs.length > 0) {
    const tree2 = await readLsblk(session);
    for (const device of devices) {
      const node = findNode(tree2, device.device);
      const vg = await pvsVg(session, device.device);
      const lvmChildren = node
        ? subtreeTypes(node).filter((t) => t === "lvm")
        : [];
      if (vg !== "" || lvmChildren.length > 0) {
        fail(
          "wipe.lvm-held",
          "LVM still claims the disk; this is LVM, not md",
          {
            host,
            device: device.device,
            volumeGroup: vg || undefined,
            lvmChildren,
            removedVolumeGroups,
          },
        );
      }
      if (!node && vg === "") {
        fail(
          "wipe.lvm-unobservable",
          "cannot observe whether an LVM volume is still stacked",
          {
            host,
            device: device.device,
          },
        );
      }
    }
  }

  // Step 3: md stop, deduplicated.
  log?.info("wipe phase md-stop", { host });
  const stoppedArrays: string[] = [];
  for (const device of devices) {
    const arrayPath = await examineArray(session, device.device);
    if (!arrayPath || stoppedArrays.includes(arrayPath)) continue;
    assertMdArrayPath("array", arrayPath);
    await root(session, `mdadm --stop -- ${quote(arrayPath)}`, {
      allowNonZero: true,
    });
    if (await arrayStillPresent(deps, arrayBasename(arrayPath))) {
      fail(
        "wipe.md-stop",
        "an md array is still present after stop; something holds it",
        {
          host,
          array: arrayPath,
        },
      );
    }
    stoppedArrays.push(arrayPath);
  }

  // Step 4: zero superblocks.
  log?.info("wipe phase zero-superblock", { host });
  for (const device of devices) {
    let done = false;
    for (let attempt = 0; attempt < 5 && !done; attempt++) {
      let result: CommandResult;
      try {
        result = await root(
          session,
          `mdadm --zero-superblock -- ${quote(device.device)}`,
          {
            allowNonZero: true,
          },
        );
      } catch (e) {
        if (e instanceof TransportError) {
          if (e.kind === "dropped-before-auth") continue; // safe to retry
          fail(
            "wipe.zero-superblock-unknown",
            "the session was lost; the command may have run",
            {
              host,
              device: device.device,
            },
          );
        }
        throw e;
      }
      if (result.code === 0) {
        done = true;
        break;
      }
      const out = `${result.stdout}\n${result.stderr}`;
      if (/no md superblock|unrecognised md component|not an md/i.test(out)) {
        done = true;
        break;
      }
      const busy = /couldn't open|not zeroing|busy|device or resource busy/i
        .test(out);
      if (!busy) {
        fail("wipe.zero-superblock", "mdadm failed to zero the superblock", {
          host,
          device: device.device,
          stderr: out.slice(0, 300),
        });
      }
      const rebuilt = await examineArray(session, device.device);
      if (rebuilt) {
        assertMdArrayPath("array", rebuilt);
        await root(session, `mdadm --stop -- ${quote(rebuilt)}`, {
          allowNonZero: true,
        });
      }
      await root(session, "udevadm settle", { allowNonZero: true });
      await deps.sleep(1000);
    }
    if (!done) {
      const holders = await measureHolders(session, device.device);
      fail(
        "wipe.zero-superblock-held",
        "the device is HELD by something other than a reforming array",
        {
          host,
          device: device.device,
          holders: holders.lsblk,
          deviceMapper: holders.dmsetup,
        },
      );
    }
  }

  // Step 5: signatures.
  log?.info("wipe phase signatures", { host });
  for (const device of devices) {
    const wiped = await root(session, `wipefs -a -- ${quote(device.device)}`, {
      allowNonZero: true,
    });
    if (wiped.code !== 0) {
      fail("wipe.signatures", "wipefs failed", {
        host,
        device: device.device,
        stderr: wiped.stderr.slice(0, 300),
      });
    }
  }

  // Step 6: partition table.
  log?.info("wipe phase partitions", { host });
  for (const device of devices) {
    await root(session, `sgdisk --zap-all -- ${quote(device.device)}`, {
      allowNonZero: true,
    });
    const probed = await root(session, `partprobe -- ${quote(device.device)}`, {
      allowNonZero: true,
    });
    if (probed.code !== 0) {
      fail("wipe.partprobe", "partprobe failed", {
        host,
        device: device.device,
        stderr: probed.stderr.slice(0, 300),
      });
    }
  }

  // Steps 7-9: md config edit, atomic write, rebuild and boot-safety read-back.
  let mdConfigRewritten = false;
  let initramfsRebuilt = false;
  if (mdadmConfPresent) {
    log?.info("wipe phase md-config", { host });
    const current = (
      await session.run({ command: `cat ${MDADM_CONF}`, allowNonZero: true })
    ).stdout;
    const next = editMdConfig(current, stoppedArrays, scanBefore);
    if (stoppedArrays.length > 0 || next !== current) {
      const temp = `${MDADM_CONF}.new.${
        (await sha256Hex(String(deps.now()))).slice(0, 12)
      }`;
      try {
        const written = await root(session, `tee ${quote(temp)}`, {
          stdin: next,
          allowNonZero: true,
        });
        if (written.code !== 0) {
          fail("wipe.md-config-write", "could not write the new md config", {
            path: temp,
          });
        }
        const rereadTemp = (
          await session.run({
            command: `cat ${quote(temp)}`,
            allowNonZero: true,
          })
        ).stdout;
        if (rereadTemp !== next) {
          fail(
            "wipe.md-config-write",
            "the written md config did not read back byte-for-byte",
            {
              path: temp,
            },
          );
        }
        await root(session, "sync", { allowNonZero: true });
        await root(session, `mv -f -- ${quote(temp)} ${quote(MDADM_CONF)}`, {
          allowNonZero: false,
        });
        mdConfigRewritten = true;
        const rebuilt = await root(session, "update-initramfs -u", {
          allowNonZero: true,
        });
        if (rebuilt.code !== 0) {
          fail(
            "wipe.initramfs",
            "update-initramfs failed after the md config was rewritten",
            {
              code: rebuilt.code,
            },
          );
        }
        initramfsRebuilt = true;
      } catch (e) {
        // Restore the backup so a later boot is not left on a partial config.
        try {
          await root(
            session,
            `cp -a -- ${quote(MDADM_BACKUP)} ${quote(MDADM_CONF)}`,
            {
              allowNonZero: true,
            },
          );
        } catch { /* rollback is best effort */ }
        throw e;
      }
    }
    const reread = (
      await session.run({ command: `cat ${MDADM_CONF}`, allowNonZero: true })
    ).stdout;
    const scanNow = await root(session, "mdadm --detail --scan", {
      allowNonZero: true,
    });
    for (const line of scanNow.stdout.split("\n")) {
      const path = parseArrayScanLine(line);
      if (!path) continue;
      const re = new RegExp(
        `^ARRAY\\s+${path.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}(\\s|$)`,
      );
      if (!reread.split("\n").some((l) => re.test(l))) {
        fail(
          "wipe.boot-safety",
          "a still-active array lacks its line in the rewritten config",
          {
            host,
            array: path,
          },
        );
      }
    }
  }

  // Step 10: raw check.
  log?.info("wipe phase raw-check", { host });
  const finalTree = await readLsblk(session);
  for (const device of devices) {
    const node = findNode(finalTree, device.device);
    if (!node) {
      fail(
        "wipe.raw-unobservable",
        "the wiped device is absent from the final lsblk",
        {
          host,
          device: device.device,
        },
      );
    }
    const parts = subtreeTypes(node).filter((t) => t === "part");
    if (parts.length > 0) {
      fail(
        "wipe.raw-partitions",
        "the wiped device still has a stale in-kernel partition table",
        {
          host,
          device: device.device,
        },
      );
    }
  }

  return {
    host,
    dryRun: false,
    capturedAt,
    alreadyRaw: false,
    wiped: args.dataDevices.map((d) => ({
      serial: d.serial,
      device: resolved.get(d.serial)!.path,
    })),
    mdadmConfPresent,
    backupPath,
    removedVolumeGroups,
    stoppedArrays,
    mdConfigRewritten,
    initramfsRebuilt,
    preTeardownMdadmScan: scanBefore,
    preTeardownFstabSha256: fstabSha256,
    preTeardownFstabEntries: fstabEntries,
  };
}

/** Measures what holds a busy device, for the give-up error. */
async function measureHolders(
  session: SshSession,
  device: string,
): Promise<{ lsblk: string; dmsetup: string }> {
  const lsblk = await session.run({
    command: `lsblk -nro NAME,TYPE -- ${quote(device)}`,
    allowNonZero: true,
  });
  const dmsetup = await root(session, "dmsetup ls", { allowNonZero: true });
  return { lsblk: lsblk.stdout.trim(), dmsetup: dmsetup.stdout.trim() };
}
