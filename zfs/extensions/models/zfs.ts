/**
 * Swamp extension model for ZFS on a Linux host reached over SSH.
 *
 * One definition serves any host: the SSH target and ZFS operands arrive with
 * every call, and state is keyed by the target's `{host, port, user}` plus the
 * pool or dataset name. The model manages a pool, datasets, sparse zvols,
 * snapshots, clones and rollback, and destroys them again. `create_pool` is a
 * disk-eating primitive, so it first builds an explicit protected-device set
 * from the host and refuses any vdev that is mounted, in `/etc/fstab`, or part
 * of an md or ZFS array — the boot device can never be taken.
 *
 * All remote work goes through the vendored `_lib/ssh.ts` transport, called
 * with argument vectors so no caller-supplied value is ever a shell string.
 *
 * @module
 */

import { z } from "npm:zod@4.3.6";
import {
  denoDeps,
  exec,
  HOST_RE,
  type SshDeps,
  type SshTarget,
  USER_RE,
} from "./_lib/ssh.ts";
import {
  assertDatasetName,
  assertDevicePath,
  assertPoolName,
  assertProperties,
  assertSnapshotTag,
  cloneArgv,
  commandReason,
  DATASET_PROPERTIES,
  DATASET_RE,
  datasetCreateArgv,
  type DatasetState,
  destroyArgv,
  DEVICE_RE,
  diffProperties,
  instanceKey,
  laterSnapshots,
  parseDatasets,
  parseFindmnt,
  parsePoolList,
  parsePoolVdevs,
  parseSize,
  parseSnapshots,
  parseSwaps,
  POOL_RE,
  poolBootfsArgv,
  poolCreateArgv,
  poolDescendantsArgv,
  poolDestroyArgv,
  poolExportArgv,
  type PoolState,
  poolVolumesArgv,
  PROPERTY_NAME_RE,
  propertyString,
  rollbackArgv,
  SNAP_TAG_RE,
  snapshotArgv,
  type SnapshotState,
  splitSnapshot,
  vdevsMatch,
  VOLSIZE_RE,
  volsizeToBytes,
  ZPOOL_PROPERTIES,
  zvolCreateArgv,
} from "./_lib/zfs.ts";
import { assessProtected } from "./_lib/safety.ts";

// deno-lint-ignore no-explicit-any
type Ctx = any;

const POOL = z.string().regex(POOL_RE).describe("ZFS pool name.");
const DATASET = z.string().regex(DATASET_RE).max(255).describe(
  "Dataset or zvol name, e.g. tank/data.",
);
const SNAP_TAG = z.string().regex(SNAP_TAG_RE).describe("Snapshot tag.");
const VOLSIZE = z.string().regex(VOLSIZE_RE).describe(
  "Volume size, e.g. 10G.",
);
const VDEV = z.string().regex(DEVICE_RE).refine(
  (value) => !value.endsWith("/") && !value.split("/").includes(".."),
  "device must be a /dev/ path with no trailing slash or ..",
).describe("Block device path, e.g. /dev/disk/by-id/ata-....");

const PROPERTIES = z.record(
  z.string().regex(PROPERTY_NAME_RE),
  z.union([z.string().max(256), z.number(), z.boolean()]),
).refine(
  (value) => Object.keys(value).length <= 32,
  "at most 32 properties",
).describe("Map of ZFS properties to set.");

const SSH = z.strictObject({
  host: z.string().regex(HOST_RE).max(253).describe(
    "Hostname or IP literal of the target.",
  ),
  port: z.number().int().min(1).max(65535).default(22).describe("SSH port."),
  user: z.string().regex(USER_RE).describe("Remote user name."),
  host_key_policy: z.literal("strict").describe(
    "Required, always strict. This model persists no learned keys, so trust-on-first-use is not offered.",
  ),
  host_keys: z.array(z.string().max(8192)).min(1).max(64).describe(
    "ssh-keyscan-format pinned host keys. Required and authoritative.",
  ),
  private_key: z.string().max(65536).meta({ sensitive: true }).nullish()
    .describe(
      "Private key text, loaded into a temporary ssh-agent over stdin. Wire a vault reference.",
    ),
  password: z.string().max(4096).meta({ sensitive: true }).nullish().describe(
    "Password, delivered through an askpass helper; prefer private_key.",
  ),
  connect_timeout_s: z.number().int().min(1).max(120).default(15).describe(
    "Connection timeout in seconds.",
  ),
});

const PoolStateSchema = z.strictObject({
  name: z.string(),
  health: z.string(),
  size: z.string(),
  alloc: z.string(),
  free: z.string(),
  guid: z.string(),
  vdevs: z.array(z.string()),
});

const DatasetStateSchema = z.strictObject({
  name: z.string(),
  type: z.string(),
  used: z.string(),
  avail: z.string(),
  refer: z.string(),
  mountpoint: z.string(),
});

const SnapshotStateSchema = z.strictObject({
  name: z.string(),
  dataset: z.string(),
  tag: z.string(),
  creation: z.string(),
  used: z.string(),
  refer: z.string(),
});

const StateSchema = z.strictObject({
  host: z.string(),
  port: z.number().int(),
  user: z.string(),
  kind: z.enum([
    "pool",
    "dataset",
    "zvol",
    "snapshot",
    "clone",
    "rollback",
    "destroy",
    "export",
  ]),
  name: z.string(),
  pool: z.string().nullable(),
  observed_at: z.string(),
  pool_state: PoolStateSchema.nullable(),
  datasets: z.array(DatasetStateSchema),
  snapshots: z.array(SnapshotStateSchema),
});

/** Dependencies of the model; replaceable in tests. */
export interface ZfsDeps {
  /** Vendored SSH transport dependencies (the spawner seam). */
  ssh: SshDeps;
  /** Current time in milliseconds. */
  now: () => number;
}

/** Production dependencies: the vendored transport and the wall clock. */
export const defaultZfsDeps: ZfsDeps = {
  ssh: denoDeps,
  now: () => Date.now(),
};

function iso(ms: number): string {
  return new Date(ms).toISOString();
}

interface TargetArgs {
  host: string;
  port: number;
  user: string;
  host_key_policy: "strict";
  host_keys: string[];
  private_key?: string | null;
  password?: string | null;
  connect_timeout_s: number;
}

function toTarget(args: TargetArgs): SshTarget {
  if (args.host_key_policy !== "strict" || args.host_keys.length === 0) {
    throw new Error(
      "strict host_key_policy with a non-empty host_keys is required",
    );
  }
  if (args.private_key && args.password) {
    throw new Error("pass private_key or password, not both");
  }
  return {
    host: args.host,
    port: args.port,
    user: args.user,
    host_key_policy: args.host_key_policy,
    host_keys: args.host_keys ?? undefined,
    private_key: args.private_key ?? undefined,
    password: args.password ?? undefined,
    connect_timeout_s: args.connect_timeout_s,
  };
}

function identity(
  target: SshTarget,
): { host: string; port: number; user: string } {
  return { host: target.host, port: target.port, user: target.user };
}

function nonEmptyLines(stdout: string): string[] {
  return stdout.split(/\r?\n/).map((line) => line.trim()).filter((line) =>
    line !== ""
  );
}

function requireOk(
  result: { exit_code: number; stdout: string; stderr?: string },
  what: string,
): { exit_code: number; stdout: string } {
  if (result.exit_code !== 0) {
    const reason = commandReason({
      stdout: result.stdout,
      stderr: result.stderr ?? "",
    });
    throw new Error(
      `${what} failed (exit ${result.exit_code})${reason ? `: ${reason}` : ""}`,
    );
  }
  return result;
}

/** zfs/zpool "absent" diagnostics; any other non-zero exit is an error. */
const MISSING_RE =
  /does not exist|no such dataset|no such pool|no such snapshot|dataset is not a snapshot/i;

/**
 * True when the named dataset, zvol or snapshot exists; false only when the
 * tool explicitly reports it missing. Any other failure throws, so an
 * operational error is never mistaken for an absent target.
 */
async function zfsExists(
  deps: ZfsDeps,
  target: SshTarget,
  name: string,
): Promise<boolean> {
  const probe = await exec(deps.ssh, target, [
    "zfs",
    "list",
    "-H",
    "-o",
    "name",
    name,
  ]);
  if (probe.exit_code === 0) return probe.stdout.trim() !== "";
  if (MISSING_RE.test(probe.stdout + probe.stderr)) return false;
  throw new Error(
    `could not check whether ${name} exists (exit ${probe.exit_code})` +
      (commandReason(probe) ? `: ${commandReason(probe)}` : ""),
  );
}

function toPropertyMap(
  properties: Record<string, string | number | boolean> | null | undefined,
): Record<string, string> {
  if (!properties) return {};
  return Object.fromEntries(
    Object.entries(properties).map(([key, value]) => [
      key,
      propertyString(value),
    ]),
  );
}

/** Resolves a validated `/dev/...` path to its kernel device path, or refuses. */
async function resolveDevice(
  deps: ZfsDeps,
  target: SshTarget,
  path: string,
): Promise<string> {
  assertDevicePath(path);
  const link = await exec(deps.ssh, target, ["readlink", "-f", path]);
  if (link.exit_code !== 0 || link.stdout.trim() === "") {
    throw new Error(
      `could not resolve ${path}; refusing to create a pool` +
        (commandReason(link) ? `: ${commandReason(link)}` : ""),
    );
  }
  return link.stdout.trim();
}

async function listPoolDescendants(
  deps: ZfsDeps,
  target: SshTarget,
  pool: string,
): Promise<string[]> {
  const result = await exec(deps.ssh, target, poolDescendantsArgv(pool));
  if (result.exit_code === 0) {
    return nonEmptyLines(result.stdout).filter((name) => name !== pool);
  }
  if (MISSING_RE.test(result.stdout + result.stderr)) return [];
  const reason = commandReason(result);
  throw new Error(
    `could not list pool ${pool} (exit ${result.exit_code})${
      reason ? `: ${reason}` : ""
    }`,
  );
}

/** A refusal to touch a pool that carries the running system. */
export class SystemPoolError extends Error {
  /** Stable code for callers. */
  readonly code = "system-pool";
  /** Builds the error. */
  constructor(message: string) {
    super(message);
    this.name = "SystemPoolError";
  }
}

/** Mount targets whose source must never be a pool we are about to touch. */
const SYSTEM_MOUNTS: ReadonlySet<string> = new Set([
  "/",
  "/boot",
  "/boot/efi",
  "/usr",
  "/var",
  "/var/lib",
  "/var/log",
]);

/** Strips findmnt's bind-mount `[...]` suffix; dataset names cannot contain `[`. */
function canonicalMountSource(source: string): string {
  const bracket = source.indexOf("[");
  return bracket >= 0 ? source.slice(0, bracket) : source;
}

/** True when `source` is a partition of the zvol device `dev`. */
function isPartitionOf(source: string, dev: string): boolean {
  return source.startsWith(`${dev}p`) &&
    /^[0-9]+$/.test(source.slice(dev.length + 1));
}

/**
 * True when a mount source belongs to the pool: a dataset of the pool, a
 * `/dev/zvol/<pool>/...` link, or the canonical `/dev/zdN` (or a `/dev/zdNpM`
 * partition) of one of the pool's zvols.
 */
function mountFromPool(
  source: string,
  pool: string,
  zvolDevices: ReadonlySet<string>,
): boolean {
  const clean = canonicalMountSource(source);
  if (clean === pool || clean.startsWith(`${pool}/`)) return true;
  if (clean.startsWith(`/dev/zvol/${pool}/`)) return true;
  for (const dev of zvolDevices) {
    if (clean === dev || isPartitionOf(clean, dev)) return true;
  }
  return false;
}

/** True when a device path is a zvol of the pool, or a partition of one. */
function isZvolDevice(
  device: string,
  zvolDevices: ReadonlySet<string>,
): boolean {
  for (const dev of zvolDevices) {
    if (device === dev || isPartitionOf(device, dev)) return true;
  }
  return false;
}

/**
 * Every device path a pool's zvols can appear as: the `/dev/zvol/<name>` link
 * and its canonical `/dev/zdN`. `mount(8)` reports the canonical form, not the
 * link. Any readlink failure or empty result fails closed.
 */
async function resolvePoolZvolDevices(
  deps: ZfsDeps,
  target: SshTarget,
  pool: string,
): Promise<Set<string>> {
  const zvols = await exec(deps.ssh, target, poolVolumesArgv(pool));
  if (zvols.exit_code !== 0) {
    throw new SystemPoolError(
      `refusing to touch pool ${pool}: could not list its volumes (exit ${zvols.exit_code})`,
    );
  }
  const devices = new Set<string>();
  for (const name of nonEmptyLines(zvols.stdout)) {
    const link = `/dev/zvol/${name}`;
    devices.add(link);
    const resolved = await exec(deps.ssh, target, ["readlink", "-f", link]);
    const canonical = resolved.stdout.trim();
    if (resolved.exit_code !== 0 || !/^\/dev\/zd\d+$/.test(canonical)) {
      throw new SystemPoolError(
        `refusing to touch pool ${pool}: zvol ${name} did not resolve to a /dev/zdN device (got ${
          canonical || `exit ${resolved.exit_code}`
        })`,
      );
    }
    devices.add(canonical);
  }
  return devices;
}

/**
 * Refuses to touch a pool that backs the running system: `bootfs` set, a
 * system mount (/, /boot, /boot/efi, /usr, /var, /var/lib, /var/log) sourced
 * from a dataset or zvol of the pool, or a zvol of the pool active as swap.
 * Every probe must succeed; an unreadable host fails closed. `recursive` never
 * overrides this. A `/var/*` mount outside the listed targets is a known limit
 * (a pool dedicated to /var/lib/docker is a legitimate target).
 */
/**
 * Refuses when `device` is stacked on a zvol of the pool through dm-crypt,
 * LVM or dm: `lsblk -s` prints the device and every ancestor, and any ancestor
 * that is one of the pool's zvols is a match. A failed lsblk fails closed.
 */
async function assertNoZvolAncestor(
  deps: ZfsDeps,
  target: SshTarget,
  pool: string,
  device: string,
  zvolDevices: ReadonlySet<string>,
): Promise<void> {
  const res = await exec(deps.ssh, target, [
    "lsblk",
    "-s",
    "-n",
    "-o",
    "PATH,TYPE",
    device,
  ]);
  if (res.exit_code !== 0) {
    throw new SystemPoolError(
      `refusing to touch pool ${pool}: could not resolve the ancestry of ${device} (exit ${res.exit_code})`,
    );
  }
  for (const line of nonEmptyLines(res.stdout)) {
    const path = line.split(/\s+/)[0];
    if (path === undefined || path === "") continue;
    if (
      isZvolDevice(path, zvolDevices) ||
      path.startsWith(`/dev/zvol/${pool}/`)
    ) {
      throw new SystemPoolError(
        `refusing to touch pool ${pool}: ${device} is stacked on zvol ${path}`,
      );
    }
  }
}

/**
 * Refuses when a swap *file* sits on storage this pool backs. A file can never
 * be a zvol, but its filesystem can: `findmnt -T` resolves the backing source,
 * which is then judged like any other mount source (a dataset of the pool, a
 * pool zvol, or a block device stacked on one). A failed or empty probe fails
 * closed.
 */
async function assertSwapFileNotFromPool(
  deps: ZfsDeps,
  target: SshTarget,
  pool: string,
  file: string,
  zvolDevices: ReadonlySet<string>,
): Promise<void> {
  const res = await exec(deps.ssh, target, [
    "findmnt",
    "-n",
    "-o",
    "SOURCE",
    "-T",
    file,
  ]);
  const source = canonicalMountSource(res.stdout.trim());
  if (res.exit_code !== 0 || source === "") {
    throw new SystemPoolError(
      `refusing to touch pool ${pool}: could not resolve the filesystem backing swap file ${file} (exit ${res.exit_code})`,
    );
  }
  if (mountFromPool(source, pool, zvolDevices)) {
    throw new SystemPoolError(
      `refusing to touch pool ${pool}: swap file ${file} lives on ${source}, backed by this pool`,
    );
  }
  if (source.startsWith("/dev/")) {
    await assertNoZvolAncestor(deps, target, pool, source, zvolDevices);
  }
}

async function assertNotSystemPool(
  deps: ZfsDeps,
  target: SshTarget,
  pool: string,
): Promise<void> {
  const reason = (r: { stdout: string; stderr?: string }) =>
    commandReason({ stdout: r.stdout, stderr: r.stderr ?? "" });
  const bootfs = await exec(deps.ssh, target, poolBootfsArgv(pool));
  if (bootfs.exit_code !== 0) {
    throw new SystemPoolError(
      `refusing to touch pool ${pool}: could not read bootfs (exit ${bootfs.exit_code})${
        reason(bootfs) ? `: ${reason(bootfs)}` : ""
      }`,
    );
  }
  const bootfsValue = bootfs.stdout.trim();
  if (bootfsValue !== "" && bootfsValue !== "-") {
    throw new SystemPoolError(
      `refusing to touch pool ${pool}: bootfs is ${bootfsValue}; this pool boots the system`,
    );
  }
  const zvolDevices = await resolvePoolZvolDevices(deps, target, pool);
  const findmnt = await exec(deps.ssh, target, ["sh", "-c", "findmnt -J"]);
  if (findmnt.exit_code !== 0) {
    throw new SystemPoolError(
      `refusing to touch pool ${pool}: could not read mounts (exit ${findmnt.exit_code})`,
    );
  }
  let mounts;
  try {
    mounts = parseFindmnt(findmnt.stdout);
  } catch {
    throw new SystemPoolError(
      `refusing to touch pool ${pool}: the mount list was unreadable`,
    );
  }
  for (const mount of mounts) {
    if (!SYSTEM_MOUNTS.has(mount.target)) continue;
    if (mountFromPool(mount.source, pool, zvolDevices)) {
      throw new SystemPoolError(
        `refusing to touch pool ${pool}: ${mount.target} is mounted from ${mount.source}`,
      );
    }
    const source = canonicalMountSource(mount.source);
    if (source.startsWith("/dev/")) {
      await assertNoZvolAncestor(deps, target, pool, source, zvolDevices);
    }
  }
  const swaps = await exec(deps.ssh, target, ["cat", "--", "/proc/swaps"]);
  if (swaps.exit_code !== 0) {
    throw new SystemPoolError(
      `refusing to touch pool ${pool}: could not read /proc/swaps (exit ${swaps.exit_code})`,
    );
  }
  for (const swap of parseSwaps(swaps.stdout)) {
    // `/swap.img` and similar files are the stock Ubuntu default; lsblk cannot
    // read a file, so a swap file is judged through its backing filesystem.
    if (swap.type === "file") {
      await assertSwapFileNotFromPool(
        deps,
        target,
        pool,
        swap.device,
        zvolDevices,
      );
      continue;
    }
    // A partition is a block device; judge it and its ancestry directly.
    if (swap.type === "partition") {
      if (
        isZvolDevice(swap.device, zvolDevices) ||
        swap.device.startsWith(`/dev/zvol/${pool}/`)
      ) {
        throw new SystemPoolError(
          `refusing to touch pool ${pool}: ${swap.device} is active swap backed by this pool`,
        );
      }
      await assertNoZvolAncestor(deps, target, pool, swap.device, zvolDevices);
      continue;
    }
    // Any other swap type is not understood, so it fails closed.
    throw new SystemPoolError(
      `refusing to touch pool ${pool}: unsupported swap type ${
        JSON.stringify(swap.type)
      } for ${swap.device}`,
    );
  }
}

async function listPools(deps: ZfsDeps, target: SshTarget): Promise<string[]> {
  const result = await exec(deps.ssh, target, [
    "zpool",
    "list",
    "-H",
    "-o",
    "name",
  ]);
  if (result.exit_code === 0) return nonEmptyLines(result.stdout);
  if (/no pools available/i.test(result.stdout + result.stderr)) return [];
  throw new Error(
    `could not list ZFS pools (exit ${result.exit_code})` +
      (commandReason(result) ? `: ${commandReason(result)}` : ""),
  );
}

/** Resolves the pool a read targets, validating an auto-discovered name. */
async function resolvePool(
  deps: ZfsDeps,
  target: SshTarget,
  requested: string | null | undefined,
): Promise<string> {
  const pool = requested ?? (await listPools(deps, target))[0];
  if (!pool) {
    throw new Error("no pool specified and the host has no ZFS pools");
  }
  assertPoolName(pool);
  return pool;
}

async function readPool(
  deps: ZfsDeps,
  target: SshTarget,
  pool: string,
): Promise<{ state: PoolState; vdevs: string[] }> {
  const list = await exec(deps.ssh, target, [
    "zpool",
    "list",
    "-H",
    "-p",
    "-o",
    "name,size,alloc,free,health,guid",
    pool,
  ]);
  requireOk(list, `zpool list ${pool}`);
  const state = parsePoolList(list.stdout)[0];
  if (!state) throw new Error(`zpool list returned no row for ${pool}`);
  const status = await exec(deps.ssh, target, ["zpool", "status", "-P", pool]);
  requireOk(status, `zpool status ${pool}`);
  return { state, vdevs: parsePoolVdevs(status.stdout) };
}

async function readDatasets(
  deps: ZfsDeps,
  target: SshTarget,
  root: string,
): Promise<DatasetState[]> {
  const result = await exec(deps.ssh, target, [
    "zfs",
    "list",
    "-H",
    "-p",
    "-r",
    "-t",
    "filesystem,volume",
    "-o",
    "name,type,used,avail,refer,mountpoint",
    root,
  ]);
  if (result.exit_code === 0) return parseDatasets(result.stdout);
  if (MISSING_RE.test(result.stdout + result.stderr)) return [];
  throw new Error(
    `zfs list failed (exit ${result.exit_code})` +
      (commandReason(result) ? `: ${commandReason(result)}` : ""),
  );
}

async function readSnapshots(
  deps: ZfsDeps,
  target: SshTarget,
  root: string,
): Promise<SnapshotState[]> {
  const result = await exec(deps.ssh, target, [
    "zfs",
    "list",
    "-H",
    "-p",
    "-r",
    "-t",
    "snapshot",
    "-o",
    "name,used,refer,creation",
    "-s",
    "creation",
    root,
  ]);
  if (result.exit_code === 0) return parseSnapshots(result.stdout);
  if (MISSING_RE.test(result.stdout + result.stderr)) return [];
  throw new Error(
    `zfs list failed (exit ${result.exit_code})` +
      (commandReason(result) ? `: ${commandReason(result)}` : ""),
  );
}

async function livePoolState(
  deps: ZfsDeps,
  target: SshTarget,
  pool: string,
  now: number,
): Promise<z.infer<typeof StateSchema>> {
  const { state, vdevs } = await readPool(deps, target, pool);
  return StateSchema.parse({
    ...identity(target),
    kind: "pool",
    name: pool,
    pool,
    observed_at: iso(now),
    pool_state: { ...state, vdevs },
    datasets: await readDatasets(deps, target, pool),
    snapshots: await readSnapshots(deps, target, pool),
  });
}

async function liveDatasetState(
  deps: ZfsDeps,
  target: SshTarget,
  dataset: string,
  now: number,
): Promise<z.infer<typeof StateSchema>> {
  const pool = dataset.split("/")[0];
  const datasets = await readDatasets(deps, target, dataset);
  return StateSchema.parse({
    ...identity(target),
    kind: "dataset",
    name: dataset,
    pool,
    observed_at: iso(now),
    pool_state: null,
    datasets,
    snapshots: await readSnapshots(deps, target, dataset),
  });
}

const CreatePoolArgs = z.strictObject({
  ssh: SSH,
  pool: POOL,
  vdevs: z.array(VDEV).min(1).max(64).describe(
    "Block devices that become the pool's top-level vdevs.",
  ),
  properties: PROPERTIES.nullish().describe(
    "Pool properties set at creation, e.g. {ashift: 12}.",
  ),
});
const CreateDatasetArgs = z.strictObject({
  ssh: SSH,
  name: DATASET,
  properties: PROPERTIES.nullish().describe(
    "Dataset properties, e.g. {compression: zstd, quota: 10G}.",
  ),
});
const CreateZvolArgs = z.strictObject({
  ssh: SSH,
  name: DATASET,
  volsize: VOLSIZE,
  sparse: z.boolean().default(true).describe(
    "Create a sparse (thin) volume; defaults to true.",
  ),
  properties: PROPERTIES.nullish(),
});
const SnapshotArgs = z.strictObject({
  ssh: SSH,
  name: DATASET,
  tag: SNAP_TAG,
  recursive: z.boolean().default(false).describe(
    "Snapshot descendant datasets too.",
  ),
});
const CloneArgs = z.strictObject({
  ssh: SSH,
  name: DATASET,
  tag: SNAP_TAG,
  target: DATASET,
  properties: PROPERTIES.nullish(),
});
const RollbackArgs = z.strictObject({
  ssh: SSH,
  name: DATASET,
  tag: SNAP_TAG,
  destroy_later_snapshots: z.boolean().default(false).describe(
    "Acknowledge destroying snapshots newer than the target.",
  ),
});
const DestroyArgs = z.strictObject({
  ssh: SSH,
  target: z.string().max(255).describe(
    "Dataset, zvol, or dataset@tag snapshot to destroy.",
  ),
  recursive: z.boolean().default(false),
  force: z.boolean().default(false),
});
const DestroyPoolArgs = z.strictObject({
  ssh: SSH,
  pool: POOL,
  recursive: z.boolean().default(false).describe(
    "Acknowledge destroying the pool's datasets, zvols and snapshots; required when any exist.",
  ),
});
const ExportPoolArgs = z.strictObject({
  ssh: SSH,
  pool: POOL,
  force: z.boolean().default(false).describe("Force a busy pool out."),
});
const GetArgs = z.strictObject({
  ssh: SSH,
  pool: POOL.nullish(),
  dataset: DATASET.nullish(),
});
const SyncArgs = z.strictObject({
  ssh: SSH,
  pool: POOL.nullish(),
  dataset: DATASET.nullish(),
});

function buildZfsModel(deps: ZfsDeps) {
  return {
    type: "@randybias/zfs",
    version: "2026.10.17.1",
    description:
      "Manage a ZFS pool, datasets, sparse zvols, snapshots, clones and rollback on a Linux host over SSH. One definition serves any host; state is keyed by the SSH identity plus the pool or dataset name, and create_pool refuses any device that carries the running system.",
    globalArguments: z.strictObject({}),
    resources: {
      state: {
        description: "Observed ZFS pool, dataset and snapshot state",
        schema: StateSchema,
        lifetime: "infinite" as const,
        garbageCollection: 10,
      },
    },
    methods: {
      create_pool: {
        kind: "action" as const,
        description:
          "DESTRUCTIVE. Create a pool from the named vdevs, refusing any device that is mounted, named in /etc/fstab, or part of an md or ZFS array. Idempotent: an existing pool with the same vdev set is a no-op. Returns the pool, its vdevs and its GUID.",
        arguments: CreatePoolArgs,
        execute: async (
          args: z.infer<typeof CreatePoolArgs>,
          context: Ctx,
        ) => {
          const target = toTarget(args.ssh);
          const requested = toPropertyMap(args.properties);
          assertProperties(requested, ZPOOL_PROPERTIES, "pool");
          const pools = await listPools(deps, target);
          if (pools.includes(args.pool)) {
            const requestedResolved: string[] = [];
            for (const vdev of args.vdevs) {
              requestedResolved.push(await resolveDevice(deps, target, vdev));
            }
            const { state, vdevs } = await readPool(deps, target, args.pool);
            // `zpool status -P` may print by-id paths; resolve both sides to
            // kernel paths so a by-id re-run is not a false diff.
            const existingResolved: string[] = [];
            for (const vdev of vdevs) {
              existingResolved.push(await resolveDevice(deps, target, vdev));
            }
            if (!vdevsMatch(existingResolved, requestedResolved)) {
              throw new Error(
                `pool ${args.pool} already exists with a different vdev set`,
              );
            }
            context.logger.info(
              "Pool {pool} already exists with the requested vdevs; no change",
              { pool: args.pool },
            );
            const handle = await context.writeResource(
              "state",
              instanceKey(identity(target), args.pool),
              StateSchema.parse({
                ...identity(target),
                kind: "pool",
                name: args.pool,
                pool: args.pool,
                observed_at: iso(deps.now()),
                pool_state: { ...state, vdevs },
                datasets: [],
                snapshots: [],
              }),
            );
            return {
              dataHandles: [handle],
              result: {
                pool: args.pool,
                vdevs: existingResolved,
                guid: state.guid,
                changed: false,
              },
            };
          }
          const previous = await assessProtected(deps.ssh, target, args.vdevs);
          context.logger.info(
            "Creating pool {pool} from {count} vdev(s) on {host}",
            { pool: args.pool, count: args.vdevs.length, host: target.host },
          );
          // Re-read immediately before the destructive step; the previous set
          // can only grow, never shrink.
          await assessProtected(deps.ssh, target, args.vdevs, previous);
          requireOk(
            await exec(
              deps.ssh,
              target,
              poolCreateArgv(args.pool, args.vdevs, requested),
            ),
            `zpool create ${args.pool}`,
          );
          const { state, vdevs } = await readPool(deps, target, args.pool);
          const handle = await context.writeResource(
            "state",
            instanceKey(identity(target), args.pool),
            StateSchema.parse({
              ...identity(target),
              kind: "pool",
              name: args.pool,
              pool: args.pool,
              observed_at: iso(deps.now()),
              pool_state: { ...state, vdevs },
              datasets: [],
              snapshots: [],
            }),
          );
          return {
            dataHandles: [handle],
            result: {
              pool: args.pool,
              vdevs,
              guid: state.guid,
              changed: true,
            },
          };
        },
      },

      create_dataset: {
        kind: "action" as const,
        description:
          "Create a dataset, or set only the properties that differ when it already exists. Idempotent by property diff. Returns the dataset name and the properties changed.",
        arguments: CreateDatasetArgs,
        execute: async (
          args: z.infer<typeof CreateDatasetArgs>,
          context: Ctx,
        ) => {
          const target = toTarget(args.ssh);
          assertDatasetName(args.name);
          const wanted = toPropertyMap(args.properties);
          assertProperties(wanted, DATASET_PROPERTIES, "dataset");
          const exists = await zfsExists(deps, target, args.name);
          let changed: string[] = [];
          if (!exists) {
            context.logger.info("Creating dataset {name} on {host}", {
              name: args.name,
              host: target.host,
            });
            requireOk(
              await exec(
                deps.ssh,
                target,
                datasetCreateArgv(args.name, wanted),
              ),
              `zfs create ${args.name}`,
            );
            changed = Object.keys(wanted).sort();
          } else {
            const current: Record<string, string> = {};
            const keys = Object.keys(wanted).sort();
            if (keys.length > 0) {
              const get = await exec(deps.ssh, target, [
                "zfs",
                "get",
                "-H",
                "-o",
                "property,value",
                keys.join(","),
                args.name,
              ]);
              if (get.exit_code === 0) {
                for (const row of get.stdout.split(/\r?\n/)) {
                  const [property, value] = row.split("\t");
                  if (property && value !== undefined) {
                    current[property] = value;
                  }
                }
              }
            }
            const { changed: diff } = diffProperties(current, wanted);
            changed = Object.keys(diff).sort();
            for (const property of changed) {
              requireOk(
                await exec(deps.ssh, target, [
                  "zfs",
                  "set",
                  `${property}=${wanted[property]}`,
                  args.name,
                ]),
                `zfs set ${property} on ${args.name}`,
              );
            }
            context.logger.info(
              "Dataset {name} exists; {count} property change(s)",
              { name: args.name, count: changed.length },
            );
          }
          const datasets = await readDatasets(deps, target, args.name);
          const handle = await context.writeResource(
            "state",
            instanceKey(identity(target), args.name),
            StateSchema.parse({
              ...identity(target),
              kind: "dataset",
              name: args.name,
              pool: args.name.split("/")[0],
              observed_at: iso(deps.now()),
              pool_state: null,
              datasets,
              snapshots: [],
            }),
          );
          return {
            dataHandles: [handle],
            result: { name: args.name, properties_changed: changed },
          };
        },
      },

      create_zvol: {
        kind: "action" as const,
        description:
          "Create a sparse zvol of the given size. Idempotent: the same size is a no-op; a different existing size is refused. Returns the name, size and that it is sparse.",
        arguments: CreateZvolArgs,
        execute: async (args: z.infer<typeof CreateZvolArgs>, context: Ctx) => {
          const target = toTarget(args.ssh);
          assertDatasetName(args.name);
          const wanted = toPropertyMap(args.properties);
          assertProperties(wanted, DATASET_PROPERTIES, "dataset");
          const probe = await exec(deps.ssh, target, [
            "zfs",
            "list",
            "-H",
            "-p",
            "-t",
            "volume",
            "-o",
            "name,volsize",
            args.name,
          ]);
          if (probe.exit_code === 0) {
            const row = probe.stdout.trim().split("\t");
            const currentBytes = parseSize(row[1] ?? "");
            if (currentBytes === null) {
              throw new Error(
                `could not parse the existing volsize of ${args.name}; refusing to treat it as a match`,
              );
            }
            if (currentBytes !== volsizeToBytes(args.volsize)) {
              throw new Error(
                `zvol ${args.name} exists with volsize ${
                  row[1]
                }, not ${args.volsize}`,
              );
            }
            context.logger.info("zvol {name} already exists; no change", {
              name: args.name,
            });
          } else if (MISSING_RE.test(probe.stdout + probe.stderr)) {
            requireOk(
              await exec(
                deps.ssh,
                target,
                zvolCreateArgv(args.name, args.volsize, args.sparse, wanted),
              ),
              `zfs create -V ${args.name}`,
            );
          } else {
            throw new Error(
              `could not check zvol ${args.name} (exit ${probe.exit_code})`,
            );
          }
          const datasets = await readDatasets(deps, target, args.name);
          const handle = await context.writeResource(
            "state",
            instanceKey(identity(target), args.name),
            StateSchema.parse({
              ...identity(target),
              kind: "zvol",
              name: args.name,
              pool: args.name.split("/")[0],
              observed_at: iso(deps.now()),
              pool_state: null,
              datasets,
              snapshots: [],
            }),
          );
          return {
            dataHandles: [handle],
            result: {
              name: args.name,
              volsize: args.volsize,
              sparse: args.sparse,
            },
          };
        },
      },

      snapshot: {
        kind: "action" as const,
        description:
          "Create a snapshot dataset@tag. Idempotent: an existing snapshot is a no-op. Returns the full snapshot name and whether it was created.",
        arguments: SnapshotArgs,
        execute: async (args: z.infer<typeof SnapshotArgs>, context: Ctx) => {
          const target = toTarget(args.ssh);
          const full = `${args.name}@${args.tag}`;
          if (!splitSnapshot(full)) {
            throw new Error(`invalid snapshot name: ${full}`);
          }
          let created = false;
          if (!(await zfsExists(deps, target, full))) {
            requireOk(
              await exec(
                deps.ssh,
                target,
                snapshotArgv(full, args.recursive),
              ),
              `zfs snapshot ${full}`,
            );
            created = true;
          }
          const snapshots = await readSnapshots(deps, target, args.name);
          const handle = await context.writeResource(
            "state",
            instanceKey(identity(target), full),
            StateSchema.parse({
              ...identity(target),
              kind: "snapshot",
              name: full,
              pool: args.name.split("/")[0],
              observed_at: iso(deps.now()),
              pool_state: null,
              datasets: [],
              snapshots,
            }),
          );
          return {
            dataHandles: [handle],
            result: { name: full, created },
          };
        },
      },

      clone: {
        kind: "action" as const,
        description:
          "Clone a snapshot to a new dataset or zvol. Idempotent: an existing clone of the same origin is a no-op; a different origin is refused. Returns the source and target.",
        arguments: CloneArgs,
        execute: async (args: z.infer<typeof CloneArgs>, context: Ctx) => {
          const sshTarget = toTarget(args.ssh);
          const source = `${args.name}@${args.tag}`;
          if (!splitSnapshot(source)) {
            throw new Error(`invalid snapshot name: ${source}`);
          }
          if (!(await zfsExists(deps, sshTarget, source))) {
            throw new Error(`snapshot ${source} does not exist`);
          }
          const wanted = toPropertyMap(args.properties);
          assertProperties(wanted, DATASET_PROPERTIES, "dataset");
          if (await zfsExists(deps, sshTarget, args.target)) {
            const origin = await exec(deps.ssh, sshTarget, [
              "zfs",
              "get",
              "-H",
              "-o",
              "value",
              "origin",
              args.target,
            ]);
            if (origin.stdout.trim() !== source) {
              throw new Error(
                `${args.target} already exists with origin ${origin.stdout.trim()}, not ${source}`,
              );
            }
            context.logger.info("Clone {target} already exists; no change", {
              target: args.target,
            });
          } else {
            requireOk(
              await exec(
                deps.ssh,
                sshTarget,
                cloneArgv(source, args.target, wanted),
              ),
              `zfs clone ${source} ${args.target}`,
            );
          }
          const datasets = await readDatasets(deps, sshTarget, args.target);
          const handle = await context.writeResource(
            "state",
            instanceKey(identity(sshTarget), args.target),
            StateSchema.parse({
              ...identity(sshTarget),
              kind: "clone",
              name: args.target,
              pool: args.name.split("/")[0],
              observed_at: iso(deps.now()),
              pool_state: null,
              datasets,
              snapshots: [],
            }),
          );
          return {
            dataHandles: [handle],
            result: { source, target: args.target },
          };
        },
      },

      rollback: {
        kind: "action" as const,
        description:
          "DESTRUCTIVE. Roll a dataset back to a snapshot. Refuses when later snapshots exist unless destroy_later_snapshots is set; with it, those snapshots are destroyed. Returns the snapshot and how many later snapshots were destroyed.",
        arguments: RollbackArgs,
        execute: async (args: z.infer<typeof RollbackArgs>, context: Ctx) => {
          const target = toTarget(args.ssh);
          const full = `${args.name}@${args.tag}`;
          if (!splitSnapshot(full)) {
            throw new Error(`invalid snapshot name: ${full}`);
          }
          const snapshots = await readSnapshots(deps, target, args.name);
          const snapshot = snapshots.find((item) => item.name === full);
          if (!snapshot) throw new Error(`snapshot ${full} does not exist`);
          const later = laterSnapshots(snapshots, snapshot);
          if (later.length > 0 && !args.destroy_later_snapshots) {
            throw new Error(
              `refusing to roll back to ${full}: ${later.length} later snapshot(s) exist; set destroy_later_snapshots to destroy them`,
            );
          }
          requireOk(
            await exec(
              deps.ssh,
              target,
              rollbackArgv(full, args.destroy_later_snapshots),
            ),
            `zfs rollback ${full}`,
          );
          const after = await readSnapshots(deps, target, args.name);
          const handle = await context.writeResource(
            "state",
            instanceKey(identity(target), full),
            StateSchema.parse({
              ...identity(target),
              kind: "rollback",
              name: full,
              pool: args.name.split("/")[0],
              observed_at: iso(deps.now()),
              pool_state: null,
              datasets: [],
              snapshots: after,
            }),
          );
          return {
            dataHandles: [handle],
            result: {
              name: full,
              destroyed_snapshots: args.destroy_later_snapshots
                ? later.length
                : 0,
            },
          };
        },
      },

      destroy: {
        kind: "action" as const,
        description:
          "DESTRUCTIVE. Destroy a dataset, zvol or snapshot. Idempotent: destroying an absent target is a clean no-op. Returns the target and whether it was destroyed.",
        arguments: DestroyArgs,
        execute: async (args: z.infer<typeof DestroyArgs>, context: Ctx) => {
          const sshTarget = toTarget(args.ssh);
          const split = splitSnapshot(args.target);
          if (split) {
            assertDatasetName(split.dataset);
            assertSnapshotTag(split.tag);
          } else {
            assertDatasetName(args.target);
          }
          let destroyed = false;
          if (await zfsExists(deps, sshTarget, args.target)) {
            requireOk(
              await exec(
                deps.ssh,
                sshTarget,
                destroyArgv(args.target, args.recursive, args.force),
              ),
              `zfs destroy ${args.target}`,
            );
            destroyed = true;
          } else {
            context.logger.info("{target} is absent; destroy is a no-op", {
              target: args.target,
            });
          }
          const handle = await context.writeResource(
            "state",
            instanceKey(identity(sshTarget), args.target),
            StateSchema.parse({
              ...identity(sshTarget),
              kind: "destroy",
              name: args.target,
              pool: (split?.dataset ?? args.target).split("/")[0],
              observed_at: iso(deps.now()),
              pool_state: null,
              datasets: [],
              snapshots: [],
            }),
          );
          return {
            dataHandles: [handle],
            result: { target: args.target, destroyed },
          };
        },
      },

      destroy_pool: {
        kind: "action" as const,
        description:
          "DESTRUCTIVE. Destroy a pool and everything in it, refusing while datasets, zvols or snapshots exist unless recursive is set. Destroying an absent pool is a clean no-op. Returns the pool and whether it was destroyed.",
        arguments: DestroyPoolArgs,
        execute: async (
          args: z.infer<typeof DestroyPoolArgs>,
          context: Ctx,
        ) => {
          const target = toTarget(args.ssh);
          assertPoolName(args.pool);
          const pools = await listPools(deps, target);
          let destroyed = false;
          if (!pools.includes(args.pool)) {
            context.logger.info("{pool} is absent; destroy_pool is a no-op", {
              pool: args.pool,
            });
          } else {
            await assertNotSystemPool(deps, target, args.pool);
            const descendants = await listPoolDescendants(
              deps,
              target,
              args.pool,
            );
            if (descendants.length > 0 && !args.recursive) {
              throw new Error(
                `refusing to destroy pool ${args.pool}: ${descendants.length} dataset(s), zvol(s) or snapshot(s) exist; set recursive to acknowledge destroying them`,
              );
            }
            requireOk(
              await exec(deps.ssh, target, poolDestroyArgv(args.pool)),
              `zpool destroy ${args.pool}`,
            );
            destroyed = true;
          }
          const handle = await context.writeResource(
            "state",
            instanceKey(identity(target), args.pool),
            StateSchema.parse({
              ...identity(target),
              kind: "destroy",
              name: args.pool,
              pool: args.pool,
              observed_at: iso(deps.now()),
              pool_state: null,
              datasets: [],
              snapshots: [],
            }),
          );
          return {
            dataHandles: [handle],
            result: { pool: args.pool, destroyed },
          };
        },
      },

      export_pool: {
        kind: "action" as const,
        description:
          "DESTRUCTIVE. Export a pool so it can be imported on another host, refusing a pool that carries the running system. Idempotent: exporting an absent pool is a clean no-op. Returns the pool and whether it was exported.",
        arguments: ExportPoolArgs,
        execute: async (
          args: z.infer<typeof ExportPoolArgs>,
          context: Ctx,
        ) => {
          const target = toTarget(args.ssh);
          assertPoolName(args.pool);
          const pools = await listPools(deps, target);
          let exported = false;
          if (!pools.includes(args.pool)) {
            context.logger.info("{pool} is absent; export_pool is a no-op", {
              pool: args.pool,
            });
          } else {
            await assertNotSystemPool(deps, target, args.pool);
            requireOk(
              await exec(
                deps.ssh,
                target,
                poolExportArgv(args.pool, args.force),
              ),
              `zpool export ${args.pool}`,
            );
            exported = true;
          }
          const handle = await context.writeResource(
            "state",
            instanceKey(identity(target), args.pool),
            StateSchema.parse({
              ...identity(target),
              kind: "export",
              name: args.pool,
              pool: args.pool,
              observed_at: iso(deps.now()),
              pool_state: null,
              datasets: [],
              snapshots: [],
            }),
          );
          return {
            dataHandles: [handle],
            result: { pool: args.pool, exported },
          };
        },
      },

      get: {
        description:
          "READ-ONLY. Report pool health and vdevs, datasets and snapshots for a pool, or a single dataset. Stores the observed state.",
        arguments: GetArgs,
        execute: async (args: z.infer<typeof GetArgs>, context: Ctx) => {
          const target = toTarget(args.ssh);
          const now = deps.now();
          const state = args.dataset
            ? await liveDatasetState(deps, target, args.dataset, now)
            : await livePoolState(
              deps,
              target,
              await resolvePool(deps, target, args.pool),
              now,
            );
          const handle = await context.writeResource(
            "state",
            instanceKey(identity(target), args.dataset ?? args.pool ?? "all"),
            state,
          );
          context.logger.info("Read ZFS state for {host}: {name}", {
            host: target.host,
            name: state.name,
          });
          return { dataHandles: [handle], result: state };
        },
      },

      sync: {
        description:
          "READ-ONLY. Compare recorded ZFS state with the live host and report drift, refreshing the stored state. Returns whether the record is in sync and each difference.",
        arguments: SyncArgs,
        execute: async (args: z.infer<typeof SyncArgs>, context: Ctx) => {
          const target = toTarget(args.ssh);
          const now = deps.now();
          const key = instanceKey(
            identity(target),
            args.dataset ?? args.pool ?? "all",
          );
          const state = args.dataset
            ? await liveDatasetState(deps, target, args.dataset, now)
            : await livePoolState(
              deps,
              target,
              await resolvePool(deps, target, args.pool),
              now,
            );
          const recorded = await context.readResource(key);
          const diffs: string[] = [];
          if (!recorded) {
            diffs.push("no recorded state; run get first");
          } else {
            const before = recorded as z.infer<typeof StateSchema>;
            if (before.pool_state?.health !== state.pool_state?.health) {
              diffs.push(
                `pool health ${before.pool_state?.health ?? "none"} -> ${
                  state.pool_state?.health ?? "none"
                }`,
              );
            }
            if (before.datasets.length !== state.datasets.length) {
              diffs.push(
                `datasets ${before.datasets.length} -> ${state.datasets.length}`,
              );
            }
            if (before.snapshots.length !== state.snapshots.length) {
              diffs.push(
                `snapshots ${before.snapshots.length} -> ${state.snapshots.length}`,
              );
            }
          }
          const handle = await context.writeResource("state", key, state);
          context.logger.info("Synced {host}: in_sync {inSync}", {
            host: target.host,
            inSync: diffs.length === 0,
          });
          return {
            dataHandles: [handle],
            result: { in_sync: diffs.length === 0, diffs },
          };
        },
      },
    },
  };
}

/** The shape of the zfs model definition. */
export type ZfsModel = ReturnType<typeof buildZfsModel>;

/** Builds the model with explicit dependencies; tests pass fakes. */
export function createModel(deps: ZfsDeps): ZfsModel {
  return buildZfsModel(deps);
}

/** Production model definition. */
export const model: ZfsModel = buildZfsModel(defaultZfsDeps);
