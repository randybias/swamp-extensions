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
  parsePoolList,
  parsePoolVdevs,
  parseSize,
  parseSnapshots,
  POOL_RE,
  poolCreateArgv,
  type PoolState,
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
import {
  assertProtectedRefsResolvable,
  assertVdevsSafe,
  collectProtectedRefs,
  computeProtectedDevices,
  parseFstab,
  parseLsblk,
  parseMdstatMembers,
  parseMounts,
  parseSwapSources,
} from "./_lib/safety.ts";

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
  host_key_policy: z.enum(["strict", "insecure_tofu"]).describe(
    "Required. strict verifies against host_keys; insecure_tofu trusts the host's keys for this call only. The model persists no learned keys, so supply host_keys to pin.",
  ),
  host_keys: z.array(z.string().max(8192)).max(64).nullish().describe(
    "ssh-keyscan-format lines. Required for strict.",
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
}).refine(
  (value) =>
    value.host_key_policy !== "strict" || (value.host_keys?.length ?? 0) > 0,
  "host_key_policy strict requires a non-empty host_keys",
);

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
  host_key_policy: "strict" | "insecure_tofu";
  host_keys?: string[] | null;
  private_key?: string | null;
  password?: string | null;
  connect_timeout_s: number;
}

function toTarget(args: TargetArgs): SshTarget {
  if (
    args.host_key_policy === "strict" && (args.host_keys?.length ?? 0) === 0
  ) {
    throw new Error("host_key_policy strict requires a non-empty host_keys");
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
  result: { exit_code: number; stdout: string },
  what: string,
): { exit_code: number; stdout: string } {
  if (result.exit_code !== 0) {
    throw new Error(`${what} failed (exit ${result.exit_code})`);
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
    `could not check whether ${name} exists (exit ${probe.exit_code})`,
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

/** Raw host facts the boot-disk guard is decided from. */
interface HostProbe {
  /** `lsblk -J` tree. */
  lsblk: string;
  /** `/proc/mounts`. */
  mounts: string;
  /** `/etc/fstab`, or empty when confirmed absent. */
  fstab: string;
  /** `/proc/mdstat`, or empty when confirmed absent. */
  mdstat: string;
  /** `/proc/swaps`. */
  swaps: string;
  /** `zpool status -P` (empty when no pools are available). */
  zpoolStatus: string;
  /** `blkid` output, to resolve tags on hosts without a udev db. */
  blkid: string;
  /** `mdadm --examine` per candidate vdev, for unassembled members. */
  mdadmExamine: { vdev: string; exit_code: number; stdout: string }[];
}

/** Reads a host file, allowing only an explicit not-exists to read as empty. */
async function readFileFact(
  deps: ZfsDeps,
  target: SshTarget,
  path: string,
): Promise<string> {
  const result = await exec(deps.ssh, target, ["cat", path]);
  if (result.exit_code === 0) return result.stdout;
  const exists = await exec(deps.ssh, target, ["test", "-e", path]);
  if (exists.exit_code === 0) {
    throw new Error(
      `could not read ${path} (exit ${result.exit_code}); refusing to create a pool`,
    );
  }
  // Only exit 1 from `test -e` means "does not exist"; 2/126/127 are probe
  // failures and must not be read as an absent file.
  if (exists.exit_code === 1) return "";
  throw new Error(
    `could not confirm whether ${path} exists (test -e exited ${exists.exit_code}); refusing to create a pool`,
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
    throw new Error(`could not resolve ${path}; refusing to create a pool`);
  }
  return link.stdout.trim();
}

/**
 * Runs every read the boot-disk guard needs. Each fact fails closed: a read
 * that cannot be performed refuses rather than reading as "nothing to protect".
 * `blkid` and per-candidate `mdadm --examine` are captured so the shared
 * protected-device module can resolve tags and unassembled array members.
 */
async function runHostProbes(
  deps: ZfsDeps,
  target: SshTarget,
  vdevs: string[],
): Promise<HostProbe> {
  const lsblk = await exec(deps.ssh, target, [
    "lsblk",
    "-J",
    "-o",
    "NAME,PATH,TYPE,MOUNTPOINT,FSTYPE,PKNAME,UUID,PARTUUID,LABEL",
  ]);
  if (lsblk.exit_code !== 0) {
    throw new Error(
      "could not read the block-device tree (lsblk); refusing to create a pool",
    );
  }
  const mounts = await exec(deps.ssh, target, ["cat", "/proc/mounts"]);
  if (mounts.exit_code !== 0) {
    throw new Error(
      `could not read /proc/mounts (exit ${mounts.exit_code}); refusing to create a pool`,
    );
  }
  const swaps = await exec(deps.ssh, target, ["cat", "/proc/swaps"]);
  if (swaps.exit_code !== 0) {
    throw new Error(
      `could not read /proc/swaps (exit ${swaps.exit_code}); refusing to create a pool`,
    );
  }
  const fstab = await readFileFact(deps, target, "/etc/fstab");
  const mdstat = await readFileFact(deps, target, "/proc/mdstat");
  const status = await exec(deps.ssh, target, ["zpool", "status", "-P"]);
  if (
    status.exit_code !== 0 &&
    !/no pools available/i.test(status.stdout + status.stderr)
  ) {
    throw new Error(
      `could not read the existing ZFS pools (exit ${status.exit_code}); refusing to create a pool`,
    );
  }
  const blkid = await exec(deps.ssh, target, ["blkid"]);
  const mdadmExamine: HostProbe["mdadmExamine"] = [];
  for (const vdev of vdevs) {
    const examine = await exec(deps.ssh, target, ["mdadm", "--examine", vdev]);
    mdadmExamine.push({
      vdev,
      exit_code: examine.exit_code,
      stdout: examine.stdout,
    });
  }
  return {
    lsblk: lsblk.stdout,
    mounts: mounts.stdout,
    fstab,
    mdstat,
    swaps: swaps.stdout,
    zpoolStatus: status.stdout,
    blkid: blkid.stdout,
    mdadmExamine,
  };
}

/** Refuses candidate vdevs that carry the running system. */
async function assertDevicesSafe(
  deps: ZfsDeps,
  target: SshTarget,
  vdevs: string[],
): Promise<Map<string, string>> {
  const probe = await runHostProbes(deps, target, vdevs);
  const devices = parseLsblk(probe.lsblk);
  const mounts = parseMounts(probe.mounts);
  const fstab = parseFstab(probe.fstab);
  const mdMembers = parseMdstatMembers(probe.mdstat);
  const swaps = parseSwapSources(probe.swaps);
  const zfsVdevs = parsePoolVdevs(probe.zpoolStatus);
  // Resolve every protected `/dev/` reference before building the set, so a
  // by-id/by-uuid vdev or fstab entry protects the disk behind it. The set is
  // computed once and every candidate is checked against it.
  const refs = collectProtectedRefs(mounts, fstab, zfsVdevs, swaps);
  const resolvedLinks = new Map<string, string>();
  for (const ref of refs) {
    resolvedLinks.set(ref, await resolveDevice(deps, target, ref));
  }
  assertProtectedRefsResolvable(refs, resolvedLinks, devices);
  const protectedSet = computeProtectedDevices(
    devices,
    mounts,
    fstab,
    mdMembers,
    zfsVdevs,
    swaps,
    resolvedLinks,
  );
  const resolved = new Map<string, string>();
  for (const vdev of vdevs) {
    resolved.set(vdev, await resolveDevice(deps, target, vdev));
  }
  assertVdevsSafe(vdevs, resolved, devices, protectedSet);
  return resolved;
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
  throw new Error(`could not list ZFS pools (exit ${result.exit_code})`);
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
  throw new Error(`zfs list failed (exit ${result.exit_code})`);
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
  throw new Error(`zfs list failed (exit ${result.exit_code})`);
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
          const resolved = await assertDevicesSafe(
            deps,
            target,
            args.vdevs,
          );
          context.logger.info(
            "Creating pool {pool} from {count} vdev(s) on {host}",
            { pool: args.pool, count: args.vdevs.length, host: target.host },
          );
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
              vdevs: [...resolved.values()],
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
