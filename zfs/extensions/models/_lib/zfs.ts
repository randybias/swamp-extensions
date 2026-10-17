/**
 * Pure ZFS helpers for the `@randybias/zfs` model: name and property grammars,
 * `zpool`/`zfs` argument-vector builders, and parsers for the tab- and
 * column-oriented output the tools emit.
 *
 * Nothing here spawns a process or opens a socket, so the whole module is
 * exercised offline. The model in `zfs.ts` is a thin orchestration layer over
 * these functions plus the vendored SSH transport.
 *
 * @module
 */

/** Canonical SSH identity that state is keyed by. */
export interface ZfsIdentity {
  /** Hostname or IP literal. */
  host: string;
  /** SSH port. */
  port: number;
  /** Remote user. */
  user: string;
}

/** ZFS pool name: one component, no slash. */
export const POOL_RE = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$/;
/** Full dataset or zvol name: `/`-separated components. */
export const DATASET_RE =
  /^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}(?:\/[A-Za-z0-9][A-Za-z0-9._:-]{0,63})*$/;
/** Snapshot tag after `@`. */
export const SNAP_TAG_RE = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$/;
/** Device path under `/dev/`, no shell metacharacters. */
export const DEVICE_RE = /^\/dev\/[A-Za-z0-9][A-Za-z0-9._/-]{0,255}$/;
/** ZFS size literal, e.g. `10G`, `512M`, `1.5T`, `1073741824`. */
export const VOLSIZE_RE = /^\d+(?:\.\d+)?(?:[KMGTPEZ]i?B?)?$/i;
/** ZFS property name. */
export const PROPERTY_NAME_RE = /^[a-z][a-z0-9:_-]{0,63}$/;
/** ZFS property value made only of characters the tools accept unquoted. */
export const PROPERTY_VALUE_RE = /^[A-Za-z0-9][A-Za-z0-9._:/@-]{0,255}$/;

/** Dataset and zvol properties this model is willing to set. */
export const DATASET_PROPERTIES: ReadonlySet<string> = new Set([
  "aclinherit",
  "acltype",
  "atime",
  "canmount",
  "casesensitivity",
  "checksum",
  "compression",
  "copies",
  "dedup",
  "devices",
  "exec",
  "logbias",
  "mountpoint",
  "normalization",
  "primarycache",
  "quota",
  "readonly",
  "recordsize",
  "referenced",
  "refquota",
  "refreservation",
  "relatime",
  "secondarycache",
  "setuid",
  "sharenfs",
  "sharesmb",
  "snapdir",
  "sync",
  "utf8only",
  "volblocksize",
  "volmode",
  "xattr",
]);

/** Pool properties this model is willing to set at creation. */
export const ZPOOL_PROPERTIES: ReadonlySet<string> = new Set([
  "ashift",
  "autoexpand",
  "autotrim",
  "cachefile",
  "comment",
  "failmode",
  "multihost",
  "version",
]);

/** A pool as reported by `zpool list`. */
export interface PoolState {
  /** Pool name. */
  name: string;
  /** Health string, e.g. `ONLINE`. */
  health: string;
  /** Human-readable size. */
  size: string;
  /** Human-readable allocated bytes. */
  alloc: string;
  /** Human-readable free bytes. */
  free: string;
  /** Pool GUID. */
  guid: string;
}

/** A filesystem or volume as reported by `zfs list`. */
export interface DatasetState {
  /** Dataset or volume name. */
  name: string;
  /** `filesystem` or `volume`. */
  type: string;
  /** Used space. */
  used: string;
  /** Available space. */
  avail: string;
  /** Referenced space. */
  refer: string;
  /** Mountpoint, or `-` for a volume. */
  mountpoint: string;
}

/** A snapshot as reported by `zfs list -t snapshot`. */
export interface SnapshotState {
  /** Full `dataset@tag` name. */
  name: string;
  /** Dataset the snapshot belongs to. */
  dataset: string;
  /** Snapshot tag. */
  tag: string;
  /** Creation time, as `zfs list -p` reports it (seconds since epoch). */
  creation: string;
  /** Used space. */
  used: string;
  /** Referenced space. */
  refer: string;
}

/** Throws unless `name` is a single ZFS component. */
export function assertPoolName(name: string): void {
  if (!POOL_RE.test(name)) throw new Error(`invalid pool name: ${name}`);
}

/** Throws unless `name` is a full dataset name of at most 255 bytes. */
export function assertDatasetName(name: string): void {
  if (!DATASET_RE.test(name) || name.length > 255) {
    throw new Error(`invalid dataset name: ${name}`);
  }
}

/** Throws unless `tag` is a snapshot tag. */
export function assertSnapshotTag(tag: string): void {
  if (!SNAP_TAG_RE.test(tag)) throw new Error(`invalid snapshot tag: ${tag}`);
}

/** Throws unless `device` is a `/dev/` path of safe characters. */
export function assertDevicePath(device: string): void {
  if (
    !DEVICE_RE.test(device) || device.endsWith("/") ||
    device.split("/").includes("..")
  ) {
    throw new Error(`invalid device path: ${device}`);
  }
}

/** Throws unless `size` is a ZFS size literal. */
export function assertVolsize(size: string): void {
  if (!VOLSIZE_RE.test(size)) throw new Error(`invalid volume size: ${size}`);
}

/** Converts a ZFS size literal (`10G`, `1.5T`, `1073741824`) to bytes. */
export function volsizeToBytes(size: string): number {
  const match = /^(\d+(?:\.\d+)?)([KMGTPEZ])?i?B?$/i.exec(size);
  if (!match) throw new Error(`invalid volume size: ${size}`);
  const value = Number(match[1]);
  const unit = match[2]?.toUpperCase();
  const power: Record<string, number> = {
    K: 1,
    M: 2,
    G: 3,
    T: 4,
    P: 5,
    E: 6,
    Z: 7,
  };
  return value * 1024 ** (unit ? power[unit] : 0);
}

/** Throws unless every property is known and its value is safe. */
export function assertProperties(
  properties: Record<string, string>,
  allowed: ReadonlySet<string>,
  label: string,
): void {
  for (const [key, value] of Object.entries(properties)) {
    if (!PROPERTY_NAME_RE.test(key) || !allowed.has(key)) {
      throw new Error(`unknown ${label} property: ${key}`);
    }
    if (!PROPERTY_VALUE_RE.test(value)) {
      throw new Error(`invalid value for ${label} property ${key}`);
    }
  }
}

/** Normalizes a boolean or number property value to the string ZFS expects. */
export function propertyString(value: string | number | boolean): string {
  if (typeof value === "boolean") return value ? "on" : "off";
  return String(value);
}

function propertyOptions(properties: Record<string, string>): string[] {
  return Object.entries(properties).sort(([a], [b]) => a.localeCompare(b))
    .flatMap(([key, value]) => ["-o", `${key}=${value}`]);
}

/** Builds `zpool create`. */
export function poolCreateArgv(
  pool: string,
  vdevs: string[],
  properties: Record<string, string> = {},
): string[] {
  assertPoolName(pool);
  for (const vdev of vdevs) assertDevicePath(vdev);
  assertProperties(properties, ZPOOL_PROPERTIES, "pool");
  return ["zpool", "create", ...propertyOptions(properties), pool, ...vdevs];
}

/** Builds `zfs create` for a filesystem. */
export function datasetCreateArgv(
  name: string,
  properties: Record<string, string> = {},
): string[] {
  assertDatasetName(name);
  assertProperties(properties, DATASET_PROPERTIES, "dataset");
  return ["zfs", "create", ...propertyOptions(properties), name];
}

/** Builds `zfs create -s -V` for a sparse zvol. */
export function zvolCreateArgv(
  name: string,
  volsize: string,
  sparse: boolean,
  properties: Record<string, string> = {},
): string[] {
  assertDatasetName(name);
  assertVolsize(volsize);
  assertProperties(properties, DATASET_PROPERTIES, "dataset");
  return [
    "zfs",
    "create",
    ...(sparse ? ["-s"] : []),
    ...propertyOptions(properties),
    "-V",
    volsize,
    name,
  ];
}

/** Builds `zfs snapshot`. */
export function snapshotArgv(full: string, recursive: boolean): string[] {
  return ["zfs", "snapshot", ...(recursive ? ["-r"] : []), full];
}

/** Builds `zfs clone`. */
export function cloneArgv(
  source: string,
  target: string,
  properties: Record<string, string> = {},
): string[] {
  assertDatasetName(target);
  assertProperties(properties, DATASET_PROPERTIES, "dataset");
  return ["zfs", "clone", ...propertyOptions(properties), source, target];
}

/** Builds `zfs rollback`. */
export function rollbackArgv(full: string, destroyLater: boolean): string[] {
  return ["zfs", "rollback", ...(destroyLater ? ["-r"] : []), full];
}

/** Builds `zfs destroy`. */
export function destroyArgv(
  target: string,
  recursive: boolean,
  force: boolean,
): string[] {
  return [
    "zfs",
    "destroy",
    ...(recursive ? ["-r"] : []),
    ...(force ? ["-f"] : []),
    target,
  ];
}

/** Splits `dataset@tag`; returns null when there is no `@` or a part is bad. */
export function splitSnapshot(
  full: string,
): { dataset: string; tag: string } | null {
  const at = full.indexOf("@");
  if (at <= 0 || at === full.length - 1) return null;
  const dataset = full.slice(0, at);
  const tag = full.slice(at + 1);
  if (!DATASET_RE.test(dataset) || dataset.length > 255) return null;
  if (!SNAP_TAG_RE.test(tag)) return null;
  return { dataset, tag };
}

/** Splits `zfs list -H` output into rows of tab-separated fields. */
export function parseTabbed(stdout: string): string[][] {
  return stdout.split(/\r?\n/).map((line) => line.trimEnd()).filter((line) =>
    line !== ""
  ).map((line) => line.split("\t"));
}

/** Parses `zpool list -H -o name,size,alloc,free,health,guid`. */
export function parsePoolList(stdout: string): PoolState[] {
  return parseTabbed(stdout).flatMap((row) => {
    if (row.length < 6) return [];
    return [{
      name: row[0],
      size: row[1],
      alloc: row[2],
      free: row[3],
      health: row[4],
      guid: row[5],
    }];
  });
}

/** Parses `zfs list -H -o name,type,used,avail,refer,mountpoint`. */
export function parseDatasets(stdout: string): DatasetState[] {
  return parseTabbed(stdout).flatMap((row) => {
    if (row.length < 6) return [];
    return [{
      name: row[0],
      type: row[1],
      used: row[2],
      avail: row[3],
      refer: row[4],
      mountpoint: row[5],
    }];
  });
}

/** Parses `zfs list -H -t snapshot -o name,used,refer,creation`. */
export function parseSnapshots(stdout: string): SnapshotState[] {
  const out: SnapshotState[] = [];
  for (const row of parseTabbed(stdout)) {
    if (row.length < 4) continue;
    const split = splitSnapshot(row[0]);
    if (!split) continue;
    out.push({
      name: row[0],
      dataset: split.dataset,
      tag: split.tag,
      used: row[1],
      refer: row[2],
      creation: row[3],
    });
  }
  return out;
}

/**
 * Extracts every `/dev/...` member from the `config:` section of
 * `zpool status -P` output, across all pools it lists.
 */
export function parsePoolVdevs(statusText: string): string[] {
  const out = new Set<string>();
  let inConfig = false;
  for (const raw of statusText.split(/\r?\n/)) {
    if (/^\s*config:\s*$/.test(raw)) {
      inConfig = true;
      continue;
    }
    if (!inConfig) continue;
    // Each pool prints its own `config:` … `errors:` block; do not stop at the
    // first `errors:`, or every pool after the first is left unprotected.
    if (/^\s*errors:/.test(raw)) {
      inConfig = false;
      continue;
    }
    const trimmed = raw.trim();
    if (trimmed === "" || /^NAME\b/.test(trimmed)) continue;
    const token = trimmed.split(/\s+/)[0];
    if (token.startsWith("/dev/")) out.add(token);
  }
  return [...out].sort();
}

/** True when two device sets name the same members. */
export function vdevsMatch(existing: string[], desired: string[]): boolean {
  const a = new Set(existing);
  const b = new Set(desired);
  if (a.size !== b.size) return false;
  for (const value of a) if (!b.has(value)) return false;
  return true;
}

/** Splits wanted properties into those that differ and those already set. */
export function diffProperties(
  current: Record<string, string>,
  desired: Record<string, string>,
): { changed: Record<string, string>; unchanged: string[] } {
  const changed: Record<string, string> = {};
  const unchanged: string[] = [];
  for (const key of Object.keys(desired).sort()) {
    if (current[key] === desired[key]) unchanged.push(key);
    else changed[key] = desired[key];
  }
  return { changed, unchanged };
}

/** Snapshots of the target's dataset created strictly after `target`. */
export function laterSnapshots(
  snapshots: SnapshotState[],
  target: SnapshotState,
): SnapshotState[] {
  const threshold = Number(target.creation);
  return snapshots
    .filter((snapshot) =>
      snapshot.dataset === target.dataset &&
      Number(snapshot.creation) > threshold
    )
    .sort((a, b) => Number(a.creation) - Number(b.creation));
}

/** A stable, filesystem-safe state key for one identity and operand. */
export function instanceKey(identity: ZfsIdentity, name: string): string {
  const raw = `${identity.host}-${identity.port}-${identity.user}-${name}`;
  return raw.replace(/[^A-Za-z0-9._-]/g, "_").slice(0, 255);
}
