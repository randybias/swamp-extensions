/**
 * Boot-disk safety for pool creation.
 *
 * `create_pool` is a disk-eating primitive, so before it runs it must know
 * which devices carry the running system. This module parses the host facts it
 * needs — `lsblk` JSON, `/proc/mounts`, `/proc/swaps`, `/etc/fstab`,
 * `/proc/mdstat`, and `zpool status -P` — and builds an explicit protected set:
 * every mounted device, every device named in `fstab`, every member of an md
 * array (active or degraded), every member of an existing ZFS pool, and every
 * whole disk and partition in those devices' families.
 *
 * A candidate vdev is refused when it shares a family with any protected
 * device. If the block-device tree cannot be read, the caller refuses rather
 * than guesses. Nothing here spawns a process; the model feeds it text.
 *
 * @module
 */

/** One node of the `lsblk -J` tree. */
export interface BlockDevice {
  /** Kernel name, e.g. `sda` or `sda1`. */
  name: string;
  /** Device path, e.g. `/dev/sda` or `/dev/mapper/vg-lv`. */
  path: string;
  /** `disk`, `part`, `lvm`, `crypt`, `raid0`, … */
  type: string;
  /** Mountpoint, or null when not mounted. */
  mountpoint: string | null;
  /** Filesystem type, or null. */
  fstype: string | null;
  /** Parent kernel name, or null for a top-level disk. */
  pkname: string | null;
  /** Filesystem UUID, or null. */
  uuid: string | null;
  /** Partition UUID, or null. */
  partuuid: string | null;
  /** Filesystem label, or null. */
  label: string | null;
  /** Child devices (partitions, dm layers). */
  children: BlockDevice[];
}

/** A mount or mount-like entry. */
export interface MountEntry {
  /** Source device or pseudo-source. */
  source: string;
  /** Mount target. */
  target: string;
  /** Filesystem type. */
  fstype: string;
}

function field(raw: Record<string, unknown>, key: string): string | null {
  const value = raw[key];
  return typeof value === "string" && value !== "" ? value : null;
}

function toDevice(raw: Record<string, unknown>): BlockDevice {
  const children = Array.isArray(raw.children)
    ? raw.children.filter((child): child is Record<string, unknown> =>
      typeof child === "object" && child !== null
    ).map(toDevice)
    : [];
  return {
    name: field(raw, "name") ?? "",
    path: field(raw, "path") ?? "",
    type: field(raw, "type") ?? "",
    mountpoint: field(raw, "mountpoint"),
    fstype: field(raw, "fstype"),
    pkname: field(raw, "pkname"),
    uuid: field(raw, "uuid"),
    partuuid: field(raw, "partuuid"),
    label: field(raw, "label"),
    children,
  };
}

/** Parses `lsblk -J` output into the top-level devices; throws on bad JSON. */
export function parseLsblk(json: string): BlockDevice[] {
  const parsed = JSON.parse(json) as Record<string, unknown>;
  const raw = parsed.blockdevices;
  if (!Array.isArray(raw)) {
    throw new Error("lsblk output has no blockdevices array");
  }
  return raw.filter((item): item is Record<string, unknown> =>
    typeof item === "object" && item !== null
  ).map(toDevice);
}

/** Flattens a device tree, parents before children. */
export function flattenDevices(devices: BlockDevice[]): BlockDevice[] {
  const out: BlockDevice[] = [];
  const visit = (device: BlockDevice): void => {
    out.push(device);
    for (const child of device.children) visit(child);
  };
  for (const device of devices) visit(device);
  return out;
}

/** Decodes the octal escapes `/proc/mounts` uses for spaces and newlines. */
function unescapeMount(value: string): string {
  return value.replace(
    /\\([0-7]{3})/g,
    (_, code: string) => String.fromCharCode(parseInt(code, 8)),
  );
}

/** Parses `/proc/mounts` or `/proc/swaps`-style whitespace columns. */
export function parseMounts(text: string): MountEntry[] {
  const out: MountEntry[] = [];
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (line === "" || line.startsWith("#") || /^Filename\b/.test(line)) {
      continue;
    }
    const parts = line.split(/\s+/);
    if (parts.length < 3) continue;
    out.push({
      source: unescapeMount(parts[0]),
      target: unescapeMount(parts[1]),
      fstype: parts[2],
    });
  }
  return out;
}

/** One `/etc/fstab` device field. */
export interface FstabEntry {
  /** Device, or `UUID=`/`PARTUUID=`/`LABEL=` identifier. */
  device: string;
  /** Mountpoint. */
  mountpoint: string;
  /** Filesystem type. */
  fstype: string;
}

/** Parses `/etc/fstab`, skipping comments and blanks. */
export function parseFstab(text: string): FstabEntry[] {
  const out: FstabEntry[] = [];
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (line === "" || line.startsWith("#")) continue;
    const parts = line.split(/\s+/);
    if (parts.length < 3) continue;
    out.push({ device: parts[0], mountpoint: parts[1], fstype: parts[2] });
  }
  return out;
}

/**
 * Extracts the member kernel names of every md array in `/proc/mdstat`,
 * including members of inactive or degraded arrays (`sdc1[0](S)`) and the
 * names a shape-based regex missed: `nvme0n1p2[0]`, `mmcblk0p1`, `dm-0`, and
 * whole-disk members (`sdb[0]`).
 */
export function parseMdstatMembers(text: string): string[] {
  const out = new Set<string>();
  for (const token of text.split(/\s+/)) {
    const match = /^([A-Za-z0-9._-]+)\[\d+\](?:\([A-Za-z]+\))?$/.exec(token);
    if (match) out.add(match[1]);
  }
  return [...out].sort();
}

/** Returns device paths under `/dev/` named by swap entries. */
export function parseSwapSources(text: string): string[] {
  return parseMounts(text).map((entry) => entry.source).filter((source) =>
    source.startsWith("/dev/")
  );
}

function familyOf(device: BlockDevice, flat: BlockDevice[]): string[] {
  const byName = new Map(flat.map((item) => [item.name, item]));
  const paths = new Set<string>([device.path]);
  let current = device;
  while (current.pkname) {
    const parent = byName.get(current.pkname);
    if (!parent) break;
    paths.add(parent.path);
    current = parent;
  }
  const visit = (node: BlockDevice): void => {
    paths.add(node.path);
    for (const child of node.children) visit(child);
  };
  visit(device);
  return [...paths];
}

/** Every device path in `device`'s family: itself, ancestors and descendants. */
export function deviceFamily(
  device: BlockDevice,
  flat: BlockDevice[],
): string[] {
  return familyOf(device, flat);
}

/** Every `/dev/` reference the protected set is built from, deduplicated. */
export function collectProtectedRefs(
  mounts: MountEntry[],
  fstab: FstabEntry[],
  zfsVdevs: string[],
  swapSources: string[],
): string[] {
  const refs = new Set<string>();
  for (const mount of mounts) {
    if (mount.source.startsWith("/dev/")) refs.add(mount.source);
  }
  for (const entry of fstab) {
    if (entry.device.startsWith("/dev/")) refs.add(entry.device);
  }
  for (const vdev of zfsVdevs) {
    if (vdev.startsWith("/dev/")) refs.add(vdev);
  }
  for (const source of swapSources) refs.add(source);
  return [...refs].sort();
}

/** Builds the explicit protected-device set for one host. */
export function computeProtectedDevices(
  devices: BlockDevice[],
  mounts: MountEntry[],
  fstab: FstabEntry[],
  mdMembers: string[],
  zfsVdevs: string[],
  swapSources: string[],
  resolvedLinks: Map<string, string> = new Map(),
): Set<string> {
  const flat = flattenDevices(devices);
  const byPath = new Map(flat.map((item) => [item.path, item]));
  const byName = new Map(flat.map((item) => [item.name, item]));
  const byUuid = new Map(
    flat.filter((item) => item.uuid).map((item) => [item.uuid as string, item]),
  );
  const byPartuuid = new Map(
    flat.filter((item) => item.partuuid).map((item) => [
      item.partuuid as string,
      item,
    ]),
  );
  const byLabel = new Map(
    flat.filter((item) => item.label).map((item) => [
      item.label as string,
      item,
    ]),
  );
  const protectedSet = new Set<string>();
  const protect = (device: BlockDevice | undefined): void => {
    if (!device) return;
    for (const path of familyOf(device, flat)) protectedSet.add(path);
  };
  const protectPath = (path: string): void => {
    // A `/dev/disk/by-id|by-uuid|by-partuuid/...` symlink is not an lsblk
    // path; try the raw path first (which is how `/dev/mapper/...` is
    // reported) and fall back to its resolved kernel path.
    for (const candidate of [path, resolvedLinks.get(path)]) {
      if (!candidate) continue;
      const normalized = candidate.replace(/\/\/+/g, "/").replace(/\/$/, "");
      const device = byPath.get(normalized) ??
        byName.get(normalized.replace(/^\/dev\//, ""));
      if (device) {
        protect(device);
        return;
      }
    }
  };

  for (const device of flat) {
    if (device.mountpoint) protect(device);
    // A member of an inactive or not-yet-assembled array carries the
    // raid/zfs member fstype even when mdstat no longer lists it.
    if (
      device.fstype === "linux_raid_member" || device.fstype === "zfs_member"
    ) {
      protect(device);
    }
  }
  for (const mount of mounts) {
    if (mount.source.startsWith("/dev/")) protectPath(mount.source);
  }
  for (const source of swapSources) protectPath(source);
  for (const entry of fstab) {
    const device = entry.device;
    if (device.startsWith("/dev/")) {
      protectPath(device);
    } else if (device.startsWith("UUID=")) {
      protect(byUuid.get(device.slice(5)));
    } else if (device.startsWith("PARTUUID=")) {
      protect(byPartuuid.get(device.slice(9)));
    } else if (device.startsWith("LABEL=")) {
      protect(byLabel.get(device.slice(6)));
    }
  }
  for (const member of mdMembers) {
    protect(byName.get(member) ?? byPath.get(member));
  }
  for (const vdev of zfsVdevs) protectPath(vdev);
  return protectedSet;
}

/**
 * Throws when a protected `/dev/` reference did not resolve to a known block
 * device, so a symlinked reference cannot silently protect nothing.
 */
export function assertProtectedRefsResolvable(
  refs: string[],
  resolvedLinks: Map<string, string>,
  devices: BlockDevice[],
): void {
  const flat = flattenDevices(devices);
  const byPath = new Map(flat.map((item) => [item.path, item]));
  const byName = new Map(flat.map((item) => [item.name, item]));
  for (const ref of refs) {
    const candidates = [ref, resolvedLinks.get(ref)].filter((
      value,
    ): value is string => Boolean(value));
    const found = candidates.some((candidate) => {
      const normalized = candidate.replace(/\/\/+/g, "/").replace(/\/$/, "");
      return byPath.has(normalized) ||
        byName.has(normalized.replace(/^\/dev\//, ""));
    });
    if (!found) {
      throw new Error(
        `protected device reference ${ref} did not resolve to a known block device; refusing to create a pool`,
      );
    }
  }
}

/**
 * Throws when a candidate vdev cannot be resolved, is not a known block
 * device, or shares a family with a protected device. `resolved` maps each
 * declared vdev (e.g. a `/dev/disk/by-id/...` symlink) to its kernel path.
 */
export function assertVdevsSafe(
  vdevs: string[],
  resolved: Map<string, string>,
  devices: BlockDevice[],
  protectedSet: Set<string>,
): void {
  const flat = flattenDevices(devices);
  const byPath = new Map(flat.map((item) => [item.path, item]));
  for (const vdev of vdevs) {
    const real = resolved.get(vdev);
    if (!real) {
      throw new Error(`could not resolve ${vdev}; refusing to create a pool`);
    }
    const device = byPath.get(real);
    if (!device) {
      throw new Error(
        `${vdev} (${real}) is not a known block device; refusing to create a pool`,
      );
    }
    const overlap = familyOf(device, flat).filter((path) =>
      protectedSet.has(path)
    );
    if (overlap.length > 0) {
      throw new Error(
        `refusing to use ${vdev}: it is part of the protected device set (${
          overlap.join(", ")
        })`,
      );
    }
  }
}
