/**
 * `@randybias/cephadm`: install and operate a standalone Ceph cluster managed
 * by cephadm on Debian-family Linux hosts reached over SSH.
 *
 * One model type serves any number of hosts and clusters: every method takes
 * its own target as arguments and the global arguments are empty. The model is
 * built by a factory with overridable dependencies, so unit tests never open a
 * socket or touch a host; the production export is the factory called with no
 * overrides.
 *
 * @module
 */

import { z } from "npm:zod@4.3.6";
import { CEPH_ID_CREATE_RE } from "./_lib/validate.ts";
import { PhaseError } from "./_lib/errors.ts";
import {
  CEPHADM_PATH,
  cephadmUrlHost,
  classifyProbe,
  discoveryScript,
  type Endpoint,
  type EndpointOutcome,
  ensureCephadm,
  ensureTimeSync,
  findingFor,
  parseAptSources,
  parseProbeLine,
  probeScript,
  runPackagePhase,
  sanitizeProxyLine,
  splitSections,
} from "./_lib/hostprep.ts";
import {
  denoSpawner,
  openSession,
  type Spawner,
  type SshSession,
  toTarget,
} from "./_lib/ssh.ts";
import {
  CAPS_SCHEMA,
  CEPH_ID_REF_SCHEMA,
  CEPH_ID_SCHEMA,
  CEPHADM_VERSION_SCHEMA,
  CIDR_SCHEMA,
  CONTAINER_IMAGE_SCHEMA,
  DATA_DEVICE_SCHEMA,
  EXCLUDE_DEVICE_SCHEMA,
  FSID_SCHEMA,
  HOST_FIELD,
  HOSTNAME_SCHEMA,
  HTTP_URL_SCHEMA,
  IPV4_SCHEMA,
  OPTIONAL_HOST_SCHEMA,
  PACKAGE_SCHEMA,
  PLACEMENT_SCHEMA,
  SERIAL_SCHEMA,
  SSH_FIELDS,
  SSH_PUBKEY_SCHEMA,
  UNIT_SCHEMA,
} from "./_lib/schema.ts";
import {
  applyMon,
  applyPlacement,
  bootstrapCluster,
  distributeKeyToHost,
  type DistributeOutcome,
  distributeRecordKey,
  hostAdd,
} from "./_lib/lifecycle.ts";
import { applyOsd, validateOsdMode } from "./_lib/osd.ts";
import {
  createCsiUser,
  createFs,
  createPool,
  deleteFs,
  fetchCsiKey,
  getConnBundle,
  removeOsds,
} from "./_lib/dataplane.ts";
import {
  capacityReport,
  persistVerdict,
  verifyCsiUsers,
  verifyDisksRaw,
  verifyHealth,
  verifyHostNoout,
  verifyHostPrep,
  verifyKeyDistributed,
  verifyMgr,
  verifyMgrPlacement,
  verifyMonPlacement,
  verifyMonQuorum,
  verifyOsd,
  verifyOsdClaimable,
  verifyPool,
  verifyRbdSmoke,
} from "./_lib/verify.ts";
import { bucketInventory, ensureRgwUser } from "./_lib/rgw.ts";
import {
  bucketEnsure,
  bucketInspect,
  bucketPolicyEnsure,
  bucketVersioningEnsure,
  denoFetch,
  type FetchFn,
  isBucketName,
  isCredential,
  isEndpointOrigin,
  isRegion,
} from "./_lib/s3.ts";
import {
  checkHost,
  disableOrchestration,
  enterMaintenance,
  exitMaintenance,
  hostTornDown,
  maintenanceState,
  nooutClear,
  observeHost,
  okToStop,
  osdActivate,
  rmCluster,
  verifyClusterFsid,
} from "./_lib/maintenance.ts";
import { fail, TransportError } from "./_lib/errors.ts";
import { wipeDiskToRaw, type WipeRecord } from "./_lib/wipe.ts";

/** Model type version; must equal the manifest version. */
export const VERSION = "2026.10.17.1";

/**
 * The S3-plane methods: they open no SSH session, so they are excluded from
 * the `ssh-installed` pre-flight check's applies-to list.
 */
export const S3_METHODS: ReadonlySet<string> = new Set([
  "cephRgwBucketInspect",
  "cephRgwBucketEnsure",
  "cephRgwBucketPolicyEnsure",
  "cephRgwBucketVersioningEnsure",
]);

/** Replaceable dependencies of the model. */
export interface CephadmDeps {
  /** Spawns the ssh binary. */
  spawn: Spawner;
  /** Current time in milliseconds. */
  now: () => number;
  /** Sleeps for the given milliseconds. */
  sleep: (ms: number) => Promise<void>;
  /** Random value in [0, 1). */
  random: () => number;
  /** HTTP fetch, used by the S3-plane methods only. */
  fetch: FetchFn;
}

const productionDeps: CephadmDeps = {
  spawn: denoSpawner,
  now: () => Date.now(),
  sleep: (ms) => new Promise((resolve) => setTimeout(resolve, ms)),
  random: Math.random,
  fetch: denoFetch,
};

/** Minimal logger shape the methods use. */
interface Logger {
  /** Informational boundary log. */
  info: (message: string, props?: Record<string, unknown>) => void;
  /** Warning that does not stop the run. */
  warn: (message: string, props?: Record<string, unknown>) => void;
}

/** The parts of the method context the cephadm methods use. */
interface MethodContext {
  /** Structured logger. */
  logger: Logger;
  /** Writes a resource and returns its handle. */
  writeResource: (
    specName: string,
    name: string,
    data: Record<string, unknown>,
  ) => Promise<{ name: string }>;
}

const GlobalArgsSchema = z.strictObject({});

const VerifyResultSchema = z.strictObject({
  method: z.string(),
  host: z.string(),
  subject: z.string().optional(),
  pass: z.boolean(),
  expected: z.unknown(),
  actual: z.unknown(),
  detail: z.unknown(),
  capturedAt: z.string(),
});

const HostPrepResultSchema = z.strictObject({
  host: z.string(),
  packages: z.array(
    z.strictObject({
      name: z.string(),
      alreadyPresent: z.boolean(),
      installedVersion: z.string().optional(),
    }),
  ),
  cephadm: z.strictObject({
    alreadyPresent: z.boolean(),
    path: z.string(),
    version: z.string().nullable(),
    reinstalledBroken: z.boolean(),
  }),
  timeSync: z.strictObject({
    service: z.string(),
    wasActive: z.boolean(),
    active: z.boolean(),
  }),
  packagePhase: z.strictObject({
    installAttempts: z.number(),
    transportFailures: z.number(),
    droppedPreauth: z.number(),
    preSessionFailures: z.number(),
    busyWaits: z.number(),
    entries: z.number(),
    elapsedMs: z.number(),
    confirmedAfterTransportFailure: z.boolean(),
  }),
});

const WipeDeviceSchema = z.strictObject({
  serial: z.string(),
  device: z.string(),
});

const WipeDiskResultSchema = z.strictObject({
  host: z.string(),
  dryRun: z.boolean(),
  capturedAt: z.string(),
  alreadyRaw: z.boolean().optional(),
  plannedDevices: z.array(WipeDeviceSchema).optional(),
  excludedDevices: z.array(WipeDeviceSchema).optional(),
  wiped: z.array(WipeDeviceSchema).optional(),
  mdadmConfPresent: z.boolean().optional(),
  backupPath: z.string().nullable().optional(),
  removedVolumeGroups: z.array(z.string()).optional(),
  stoppedArrays: z.array(z.string()).optional(),
  mdConfigRewritten: z.boolean().optional(),
  initramfsRebuilt: z.boolean().optional(),
  preTeardownMdadmScan: z.string().optional(),
  preTeardownFstabSha256: z.string().optional(),
  preTeardownFstabEntries: z.number().optional(),
});

const HostPrepArgs = z.strictObject({
  host: HOST_FIELD.describe("Target host."),
  ...SSH_FIELDS,
  packages: z.array(PACKAGE_SCHEMA).min(1).max(64).describe(
    "Debian packages to ensure installed; the caller decides the list.",
  ),
  cephadmUrl: HTTP_URL_SCHEMA.describe("Where to download the cephadm binary."),
  cephadmVersion: CEPHADM_VERSION_SCHEMA.describe(
    "Pinned release; must equal the token parsed from cephadm version.",
  ),
  timeSyncService: UNIT_SCHEMA.describe(
    "systemd unit that provides time sync.",
  ),
  installRetryBudgetMs: z.number().int().min(0).max(86400000).nullish()
    .describe(
      "Total time the package phase may spend retrying; absent means no retry.",
    ),
});

const PackageSourceArgs = z.strictObject({
  host: HOST_FIELD.describe("Target host."),
  ...SSH_FIELDS,
  cephadmUrl: HTTP_URL_SCHEMA.describe(
    "The same pinned URL cephHostPrep will download.",
  ),
  throwOnFail: z.boolean().nullish().describe(
    "Throw after recording a failing result; defaults to true.",
  ),
});

const WipeArgsSchema = z.strictObject({
  host: HOST_FIELD.describe("Target host."),
  ...SSH_FIELDS,
  dataDevices: z.array(
    z.strictObject({
      serial: SERIAL_SCHEMA.describe("Disk serial to wipe."),
      sizeBytes: z.number().int().positive().optional().describe(
        "Informational size hint.",
      ),
      devHint: z.string().max(64).optional().describe(
        "Informational kernel name; never used.",
      ),
      acknowledgeBootPartitions: z.boolean().optional().describe(
        "DESTRUCTIVE. Allow wiping this disk's boot partitions (BIOS boot, EFI System): the host may not boot afterwards. Without it a disk holding one is refused. Never lifts a root, /boot, fstab, swap, md, LVM or ZFS protection.",
      ),
    }),
  ).min(1).max(128).describe("Disks to wipe, selected by serial."),
  excludeDevices: z.array(
    z.strictObject({
      serial: SERIAL_SCHEMA.describe("Never-touch serial."),
      reason: z.string().max(256).optional().describe("Why it is excluded."),
    }),
  ).max(256).describe("Never-touch list; required even when empty."),
  dryRun: z.boolean().nullish().describe(
    "Run every gate and report the plan; wipe nothing.",
  ),
});

const BootstrapArgs = z.strictObject({
  host: HOST_FIELD.describe("Host to bootstrap; also the SSH target."),
  ...SSH_FIELDS,
  monIp: IPV4_SCHEMA.describe("First monitor's IPv4 address."),
  publicNet: CIDR_SCHEMA.describe("Ceph public network, containing monIp."),
  clusterNet: CIDR_SCHEMA.describe("Ceph cluster network."),
  cephImage: CONTAINER_IMAGE_SCHEMA.describe("Image to bootstrap with."),
  timeoutMs: z.number().int().positive().max(3600000).nullish().describe(
    "SSH budget for the bootstrap command; defaults to 900000.",
  ),
});

const DistributeKeyArgs = z.strictObject({
  ...SSH_FIELDS,
  cephPubKey: SSH_PUBKEY_SCHEMA.describe("Cluster public key to install."),
  hosts: z.array(
    z.strictObject({
      host: HOST_FIELD.describe("Target host."),
      port: z.number().int().min(1).max(65535).describe(
        "That target's SSH port.",
      ),
    }),
  ).min(1).max(512).describe("Targets, each with its own port."),
});

const HostAddArgs = z.strictObject({
  adminHost: HOST_FIELD.describe("Where ceph runs."),
  ...SSH_FIELDS,
  fsid: FSID_SCHEMA.describe("Expected cluster fsid."),
  host: HOSTNAME_SCHEMA.describe("Name cephadm will register."),
  addr: IPV4_SCHEMA.describe("Address cephadm will use for the host."),
});

const ApplyMonArgs = z.strictObject({
  adminHost: HOST_FIELD.describe("Where ceph runs."),
  ...SSH_FIELDS,
  placement: PLACEMENT_SCHEMA.describe("Hosts that must run mons."),
  allowQuorumRisk: z.boolean().nullish().describe(
    "Proceed even if the quorum check fails or cannot run.",
  ),
});

const ApplyMgrArgs = z.strictObject({
  adminHost: HOST_FIELD.describe("Where ceph runs."),
  ...SSH_FIELDS,
  placement: PLACEMENT_SCHEMA.describe("Hosts that must run mgrs."),
});

const ApplyMdsArgs = z.strictObject({
  adminHost: HOST_FIELD.describe("Where ceph runs."),
  ...SSH_FIELDS,
  fsName: CEPH_ID_SCHEMA.describe(
    "Filesystem whose MDS placement to converge.",
  ),
  placement: PLACEMENT_SCHEMA.describe("Hosts that must run MDS daemons."),
});

const ApplyOsdArgs = z.strictObject({
  adminHost: HOST_FIELD.describe("Where ceph orch runs."),
  ...SSH_FIELDS,
  allAvailableDevices: z.boolean().nullish().describe(
    "Claim every empty device fleet-wide; needs excludeDevices.",
  ),
  targetHost: OPTIONAL_HOST_SCHEMA.describe(
    "Selector mode: the disk owner's registered name; empty means absent.",
  ),
  targetAddr: OPTIONAL_HOST_SCHEMA.describe(
    "How the control host reaches targetHost; empty means absent, defaulting to targetHost.",
  ),
  targetPort: z.number().int().min(1).max(65535).nullish().describe(
    "SSH port for targetAddr; defaults to port.",
  ),
  dataDevices: z.array(DATA_DEVICE_SCHEMA).max(128).nullish().describe(
    "Selector mode: disks to make OSDs; an empty list means absent.",
  ),
  excludeDevices: z.array(EXCLUDE_DEVICE_SCHEMA).max(256).nullish().describe(
    "Disks that must never be claimed; required in all-available mode.",
  ),
});

const ApplyOsdResultSchema = z.strictObject({
  serviceId: z.string(),
  allAvailableDevices: z.boolean(),
  targetHost: z.string().nullable(),
  dataDevices: z.array(z.strictObject({ serial: z.string() })),
  resolvedPaths: z.array(z.string()),
  excludeDevices: z.array(z.strictObject({ serial: z.string() })),
  applied: z.boolean(),
  staleServicesRemoved: z.array(z.string()),
  capturedAt: z.string(),
});

const ReadHostArgs = z.strictObject({
  host: HOST_FIELD.describe("Admin host."),
  ...SSH_FIELDS,
});

const CreatePoolArgs = z.strictObject({
  host: HOST_FIELD.describe("Admin host."),
  ...SSH_FIELDS,
  name: CEPH_ID_SCHEMA.describe("Pool name."),
  scheme: z.enum(["replicated", "erasure"]).describe("Redundancy scheme."),
  size: z.number().int().min(1).nullish().describe(
    "Replica count (replicated only).",
  ),
  erasureProfile: z.strictObject({
    k: z.number().int().min(1),
    m: z.number().int().min(1),
  }).nullish().describe("EC data and coding chunks (erasure only)."),
  application: CEPH_ID_SCHEMA.describe("Application tag."),
  failureDomain: CEPH_ID_SCHEMA.describe("CRUSH failure domain."),
});

const CreateFsArgs = z.strictObject({
  host: HOST_FIELD.describe("Admin host."),
  ...SSH_FIELDS,
  name: CEPH_ID_SCHEMA.describe("CephFS volume name."),
  placement: PLACEMENT_SCHEMA.describe("Hosts that must run MDS daemons."),
  timeoutMs: z.number().int().positive().max(3600000).nullish().describe(
    "Budget for the create and apply commands; defaults to 600000.",
  ),
});

const CsiCapsSchema = z.strictObject({
  mon: CAPS_SCHEMA.describe("mon caps."),
  mgr: CAPS_SCHEMA.describe("mgr caps."),
  osd: CAPS_SCHEMA.describe("osd caps."),
  mds: CAPS_SCHEMA.nullish().describe("mds caps (optional)."),
});

const CreateCsiUserArgs = z.strictObject({
  host: HOST_FIELD.describe("Admin host."),
  ...SSH_FIELDS,
  name: CEPH_ID_SCHEMA.describe(
    "Bare entity name, without the client. prefix.",
  ),
  caps: CsiCapsSchema.describe("Requested caps by subsystem."),
});

const FetchCsiKeyArgs = z.strictObject({
  host: HOST_FIELD.describe("Admin host."),
  ...SSH_FIELDS,
  userName: CEPH_ID_SCHEMA.describe(
    "Bare entity name, without the client. prefix.",
  ),
});

const DeleteFsArgs = z.strictObject({
  host: HOST_FIELD.describe("Admin host."),
  ...SSH_FIELDS,
  fsName: CEPH_ID_SCHEMA.describe("Volume to delete."),
  confirmFsName: z.string().min(1).max(128).describe(
    "The target named a second time.",
  ),
  maxPolls: z.number().int().positive().max(10000).nullish().describe(
    "MDS-removal poll budget.",
  ),
  pollIntervalMs: z.number().int().positive().max(3600000).nullish().describe(
    "Time between polls, in milliseconds.",
  ),
});

const RemoveOsdsArgs = z.strictObject({
  host: HOST_FIELD.describe("Admin host."),
  ...SSH_FIELDS,
  osdIds: z.array(z.number().int().min(0)).min(1).max(256).describe(
    "OSD ids to remove.",
  ),
  zap: z.boolean().nullish().describe(
    "Add --zap to the orchestrator removal; defaults to true.",
  ),
  maxPolls: z.number().int().positive().max(10000).nullish().describe(
    "Effect poll budget.",
  ),
  pollIntervalMs: z.number().int().positive().max(3600000).nullish().describe(
    "Time between polls, in milliseconds.",
  ),
});

const VerifyCommon = {
  host: HOST_FIELD.describe("Admin host."),
  ...SSH_FIELDS,
  throwOnFail: z.boolean().nullish().describe(
    "Throw after recording a failing verdict; defaults to true.",
  ),
};

const VerifyMonQuorumArgs = z.strictObject({
  ...VerifyCommon,
  expectedMonCount: z.number().int().min(1).describe(
    "Expected number of mons in the monmap.",
  ),
  quorumSettleMs: z.number().int().min(0).nullish().describe(
    "Settle budget in ms; 0 means one read.",
  ),
  quorumPollIntervalMs: z.number().int().min(1).nullish().describe(
    "Backoff ceiling in ms.",
  ),
});

const VerifyMgrArgs = z.strictObject({
  ...VerifyCommon,
  expectedCount: z.number().int().min(1).describe("Expected total mgr count."),
});

const VerifyOsdArgs = z.strictObject({
  ...VerifyCommon,
  expectedUp: z.number().int().min(0).describe("Expected OSD up count."),
  expectedIn: z.number().int().min(0).describe("Expected OSD in count."),
  expectedFailureDomain: CEPH_ID_SCHEMA.describe(
    "Expected CRUSH failure domain.",
  ),
  crushRuleName: CEPH_ID_SCHEMA.nullish().describe(
    "Rule name; default is the rule with rule_id 0.",
  ),
  osdSettleMs: z.number().int().min(0).nullish().describe(
    "Settle budget in ms; 0 means one read.",
  ),
  osdPollIntervalMs: z.number().int().min(1).nullish().describe(
    "Backoff ceiling in ms.",
  ),
});

const PoolErasureProfileSchema = z.strictObject({
  k: z.number().int().min(1),
  m: z.number().int().min(1),
  failureDomain: CEPH_ID_SCHEMA,
});

const VerifyPoolMdsSchema = z.strictObject({
  fsName: CEPH_ID_REF_SCHEMA,
  expectedActive: z.number().int().min(0),
  expectedStandby: z.number().int().min(0),
});

const VerifyPoolArgs = z.strictObject({
  ...VerifyCommon,
  poolName: CEPH_ID_REF_SCHEMA.describe(
    "Pool to check; a leading dot is allowed.",
  ),
  expectedSize: z.number().int().min(1).describe("Replica count, or k+m."),
  expectedMinSize: z.number().int().min(1).nullish().describe(
    "Durability floor to assert.",
  ),
  expectedErasureProfile: PoolErasureProfileSchema.nullish().describe(
    "EC shape to assert.",
  ),
  mds: VerifyPoolMdsSchema.nullish().describe("Optional MDS state assertion."),
  settleMs: z.number().int().min(0).nullish().describe("Settle budget in ms."),
  settlePollIntervalMs: z.number().int().min(1).nullish().describe(
    "Backoff ceiling in ms.",
  ),
});

const VerifyRbdSmokeArgs = z.strictObject({
  ...VerifyCommon,
  pool: CEPH_ID_REF_SCHEMA.describe(
    "Pool that has the rbd application enabled.",
  ),
});

const VerifyOsdClaimableArgs = z.strictObject({
  ...VerifyCommon,
  allAvailableDevices: z.boolean().nullish().describe(
    "Fleet-wide mode; needs excludeDevices.",
  ),
  excludeDevices: z.array(EXCLUDE_DEVICE_SCHEMA).max(256).nullish().describe(
    "Serials that must never be claimed.",
  ),
  targetHost: OPTIONAL_HOST_SCHEMA.describe(
    "Selector mode: the disk owner's name.",
  ),
  dataDevices: z.array(DATA_DEVICE_SCHEMA).max(128).nullish().describe(
    "Selector mode: disks intended for OSDs.",
  ),
});

const VerifyPlacementArgs = z.strictObject({
  ...VerifyCommon,
  placement: PLACEMENT_SCHEMA.describe(
    "Proposed host list to judge; applies nothing.",
  ),
});

const VerifyCsiUsersArgs = z.strictObject({
  ...VerifyCommon,
  expectedUserNames: z.array(CEPH_ID_SCHEMA).min(1).max(256).describe(
    "Bare entity names, without the client. prefix.",
  ),
});

const VerifyHealthArgs = z.strictObject({
  ...VerifyCommon,
  wantOk: z.boolean().describe(
    "true asserts healthy; false asserts not healthy.",
  ),
  allowedWarnings: z.array(z.string().regex(/^[A-Z0-9_]{1,64}$/)).max(64)
    .nullish().describe(
      "Health check names tolerated when wantOk is true.",
    ),
});

const VerifyHostNooutArgs = z.strictObject({
  ...VerifyCommon,
  hostName: HOSTNAME_SCHEMA.describe(
    "The Ceph host whose subtree flag is checked.",
  ),
  expectSet: z.boolean().describe(
    "true: the flag must be set; false: it must be clear.",
  ),
});

const VerifyHostPrepArgs = z.strictObject({
  ...VerifyCommon,
  expectedPackages: z.array(PACKAGE_SCHEMA).min(1).max(64).describe(
    "Packages that must be installed.",
  ),
  expectedCephadmVersion: CEPHADM_VERSION_SCHEMA.describe(
    "Exact cephadm version token expected.",
  ),
  expectedTimeSyncService: UNIT_SCHEMA.describe(
    "Time-sync service that must be active.",
  ),
});

const VerifyDisksRawArgs = z.strictObject({
  ...VerifyCommon,
  // The wipe workflow hands this method the same device list it gives the wipe,
  // so the wipe-only acknowledgement is accepted here and ignored.
  dataDevices: z.array(z.strictObject({
    serial: SERIAL_SCHEMA,
    acknowledgeBootPartitions: z.boolean().optional(),
  })).min(1).max(
    128,
  )
    .describe("Devices that must be raw, selected by serial."),
});

const VerifyKeyDistributedArgs = z.strictObject({
  ...SSH_FIELDS,
  throwOnFail: z.boolean().nullish().describe(
    "Throw after recording a failing verdict; defaults to true.",
  ),
  hosts: z.array(HOSTNAME_SCHEMA).min(1).max(512).describe(
    "Hosts the key was distributed to.",
  ),
  cephPubKey: SSH_PUBKEY_SCHEMA.describe("The public key to look for."),
});

const CapacityPoolSchema = z.strictObject({
  name: z.string(),
  id: z.number().nullable(),
  poolType: z.string(),
  size: z.number().nullable(),
  minSize: z.number().nullable(),
  minSizeMargin: z.number().nullable(),
  pgNum: z.number().nullable(),
  ecProfile: z.string().nullable(),
  storedBytes: z.number().nullable(),
  usedBytes: z.number().nullable(),
  percentUsed: z.number().nullable(),
  maxAvailBytes: z.number().nullable(),
  objects: z.number().nullable(),
  partial: z.boolean(),
});

const CapacityReportSchema = z.strictObject({
  host: z.string(),
  cluster: z.strictObject({
    totalBytes: z.number().nullable(),
    availBytes: z.number().nullable(),
    usedBytes: z.number().nullable(),
    rawUsedRatio: z.number().nullable(),
    numOsds: z.number().nullable(),
  }),
  pools: z.array(CapacityPoolSchema),
  poolCount: z.number(),
  partialCount: z.number(),
  atRiskPools: z.array(z.string()),
  unjudgedPools: z.array(z.string()),
  observedAt: z.string(),
});

const MaintenanceEnterArgs = z.strictObject({
  host: HOST_FIELD.describe("Admin host the ceph commands run on."),
  ...SSH_FIELDS,
  hostName: HOSTNAME_SCHEMA.describe("Ceph host to put into maintenance."),
  osdCount: z.number().int().min(1).describe("Number of OSDs on that host."),
  pollIntervalMs: z.number().int().min(1).max(3600000).nullish().describe(
    "Backoff ceiling.",
  ),
  pollTimeoutMs: z.number().int().min(1).max(86400000).nullish().describe(
    "Poll budget.",
  ),
});

const MaintenanceExitArgs = z.strictObject({
  host: HOST_FIELD.describe("Admin host."),
  ...SSH_FIELDS,
  hostName: HOSTNAME_SCHEMA.describe("Ceph host to take out of maintenance."),
  pollIntervalMs: z.number().int().min(1).max(3600000).nullish().describe(
    "Backoff ceiling.",
  ),
  pollTimeoutMs: z.number().int().min(1).max(86400000).nullish().describe(
    "Poll budget.",
  ),
});

const MaintenanceStateArgs = z.strictObject({
  host: HOST_FIELD.describe("Admin host."),
  ...SSH_FIELDS,
});

const HostNameArgs = z.strictObject({
  host: HOST_FIELD.describe("Admin host."),
  ...SSH_FIELDS,
  hostName: HOSTNAME_SCHEMA.describe("Ceph host to act on."),
});

const MaintenanceResultSchema = z.strictObject({
  method: z.string(),
  host: z.string(),
  hostName: z.string(),
  action: z.enum(["enter", "exit"]),
  didIssueCommand: z.boolean(),
  pollAttempts: z.number(),
  pollDurationMs: z.number(),
  hostInMaintenance: z.boolean().optional(),
  nooutFlagFound: z.boolean().optional(),
  hostOsdsDown: z.boolean().optional(),
  hostOsdsStayIn: z.boolean().optional(),
  hostExitedMaintenance: z.boolean().optional(),
  osdsRestored: z.boolean().optional(),
  numUpOsds: z.number(),
  numInOsds: z.number(),
  capturedAt: z.string(),
});

const MaintenanceStateResultSchema = z.strictObject({
  method: z.string(),
  host: z.string(),
  hosts: z.array(z.strictObject({
    hostname: z.string(),
    status: z.string(),
    nooutFlag: z.boolean(),
    out: z.boolean(),
  })),
  hostsOut: z.array(z.string()),
  numHosts: z.number(),
  numHostsOut: z.number(),
  capturedAt: z.string(),
});

const OkToStopResultSchema = z.strictObject({
  method: z.string(),
  host: z.string(),
  hostName: z.string(),
  safe: z.boolean(),
  reason: z.string(),
  daemons: z.array(z.string()),
  capturedAt: z.string(),
});

const CheckHostResultSchema = z.strictObject({
  method: z.string(),
  host: z.string(),
  hostName: z.string(),
  ok: z.boolean(),
  detail: z.string(),
  capturedAt: z.string(),
});

const NooutClearResultSchema = z.strictObject({
  method: z.string(),
  host: z.string(),
  hostName: z.string(),
  wasSet: z.boolean(),
  didIssueCommand: z.boolean(),
  nooutClearedObserved: z.boolean(),
  hostInMaintenance: z.boolean(),
  hostOsdIds: z.array(z.number()),
  downOsdIds: z.array(z.number()),
  elapsedMs: z.number(),
  capturedAt: z.string(),
});

const OsdActivateResultSchema = z.strictObject({
  method: z.string(),
  host: z.string(),
  hostName: z.string(),
  activated: z.array(z.number()),
  alreadyPresent: z.boolean(),
  capturedAt: z.string(),
});

const VerifyClusterFsidArgs = z.strictObject({
  host: HOST_FIELD.describe("Host to observe."),
  ...SSH_FIELDS,
  fsid: FSID_SCHEMA.describe("The cluster the caller intends to tear down."),
});

const DisableOrchArgs = z.strictObject({
  adminHost: HOST_FIELD.describe("Node used to reach the cluster."),
  ...SSH_FIELDS,
});

const RmClusterArgs = z.strictObject({
  host: HOST_FIELD.describe("Host to purge."),
  ...SSH_FIELDS,
  fsid: FSID_SCHEMA.describe(
    "Cluster to remove; any other fsid on the host refuses.",
  ),
  zapOsds: z.boolean().describe(
    "Add --zap-osds; destroys OSD device contents. Must be stated.",
  ),
  verifyTimeoutMs: z.number().int().min(1).max(86400000).nullish().describe(
    "Post-purge effect-poll budget.",
  ),
  verifyPollIntervalMs: z.number().int().min(1).max(3600000).nullish().describe(
    "Backoff ceiling.",
  ),
});

const VerifyHostTornDownArgs = z.strictObject({
  host: HOST_FIELD.describe("Host to check."),
  ...SSH_FIELDS,
  fsid: FSID_SCHEMA.describe("The cluster this verdict is about."),
});

const HostStateResultSchema = z.strictObject({
  host: z.string(),
  fsids: z.array(z.string()),
  cephUnits: z.array(z.string()),
  clusterUnits: z.array(z.string()),
  cephVolumeGroups: z.array(z.string()),
  cephLogicalVolumes: z.array(z.string()),
  mdArrays: z.array(z.string()),
  toolsSeen: z.strictObject({
    systemctl: z.boolean(),
    lvm: z.boolean(),
    mdstat: z.boolean(),
  }),
  sectionFailures: z.array(z.string()),
  capturedAt: z.string(),
});

const ClusterFsidResultSchema = z.strictObject({
  host: z.string(),
  fsid: z.string(),
  pass: z.boolean(),
  fsidsFound: z.array(z.string()),
  carriesNamedFsid: z.boolean(),
  capturedAt: z.string(),
});

const OrchestrationDisableResultSchema = z.strictObject({
  method: z.string(),
  adminHost: z.string(),
  outcome: z.enum(["disabled", "alreadyDisabled", "clusterUnreachable"]),
  enabledBefore: z.boolean().optional(),
  unreachableReason: z.string().optional(),
  capturedAt: z.string(),
});

const RmClusterResultSchema = z.strictObject({
  host: z.string(),
  fsid: z.string(),
  zapOsds: z.boolean(),
  purged: z.boolean(),
  alreadyAbsent: z.boolean(),
  cephadmStateAbsent: z.boolean().optional(),
  lvmResidue: z.array(z.string()),
  command: z.string().optional(),
  fsidsBefore: z.array(z.string()),
  fsidsAfter: z.array(z.string()),
  clusterUnitsBefore: z.array(z.string()),
  cephVolumeGroupsBefore: z.array(z.string()),
  mdArraysAfter: z.array(z.string()),
  capturedAt: z.string(),
});

const HostTornDownResultSchema = z.strictObject({
  host: z.string(),
  fsid: z.string(),
  fsids: z.array(z.string()),
  cephUnits: z.array(z.string()),
  clusterUnits: z.array(z.string()),
  cephVolumeGroups: z.array(z.string()),
  cephLogicalVolumes: z.array(z.string()),
  mdArrays: z.array(z.string()),
  toolsSeen: z.strictObject({
    systemctl: z.boolean(),
    lvm: z.boolean(),
    mdstat: z.boolean(),
  }),
  sectionFailures: z.array(z.string()),
  pass: z.boolean(),
  namedFsidGone: z.boolean(),
  findings: z.array(z.strictObject({ kind: z.string(), item: z.string() })),
  capturedAt: z.string(),
});

const RgwRealmSchema = z.string().max(128).refine(
  (v) => v === "" || CEPH_ID_CREATE_RE.test(v),
  "an RGW realm name, or empty",
).nullish();

const BucketInventoryArgs = z.strictObject({
  host: HOST_FIELD.describe("Admin host."),
  ...SSH_FIELDS,
  rgwRealm: RgwRealmSchema.describe(
    "RGW realm to read; empty means the default realm.",
  ),
});

const BucketInventoryResultSchema = z.strictObject({
  method: z.string(),
  host: z.string(),
  rgwRealm: z.string(),
  bucketCount: z.number(),
  buckets: z.array(z.strictObject({
    bucket: z.string(),
    owner: z.string(),
    numObjects: z.number(),
    sizeBytes: z.number(),
    sizeActualBytes: z.number(),
    placementRule: z.string(),
  })),
  unstattable: z.array(z.string()),
  pagesRead: z.number(),
  totalObjects: z.number(),
  totalSizeBytes: z.number(),
  totalSizeActualBytes: z.number(),
  capturedAt: z.string(),
});

function hasControlChars(value: string): boolean {
  for (const ch of value) {
    const code = ch.codePointAt(0) ?? 0;
    if (code < 0x20 || code === 0x7f) return true;
  }
  return false;
}

const RgwUserArgs = z.strictObject({
  host: HOST_FIELD.describe("Admin host."),
  ...SSH_FIELDS,
  uid: CEPH_ID_SCHEMA.describe("RGW uid."),
  displayName: z.string().min(1).max(512).refine(
    (v) => !hasControlChars(v),
    "no control characters",
  ).describe("Display name."),
  email: z.string().max(320).refine(
    (v) => v === "" || (/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(v) && !/\s/.test(v)),
    "a valid email address, or empty",
  ).nullish().describe("Email to converge; empty or null means not managed."),
  rotateKeys: z.boolean().nullish().describe(
    "Generate a fresh key pair even when one exists.",
  ),
});

const RgwUserResultSchema = z.strictObject({
  method: z.string(),
  host: z.string(),
  uid: z.string(),
  displayName: z.string(),
  email: z.string(),
  existedBefore: z.boolean(),
  changes: z.array(z.string()),
  accessKey: z.string().meta({ sensitive: true }).optional(),
  key: z.string().meta({ sensitive: true }).optional(),
  maxBuckets: z.number(),
  suspended: z.boolean(),
  secretDelivery: z.literal("generated"),
  capturedAt: z.string(),
});

const S3_ORIGIN_SCHEMA = (scheme: "https" | "http", what: string) =>
  z.string().min(1).max(2048).refine(
    (v) => isEndpointOrigin(v, scheme),
    `an ${scheme} origin (${what}) with no path, query, fragment or userinfo`,
  );

/** The S3 key grammar; each use marks the field sensitive on its own line. */
const S3_PRINTABLE_FIELD = z.string().min(1).max(512).refine(
  isCredential,
  "1-512 printable non-space ASCII characters",
);

/** The common S3-plane arguments. */
const S3_COMMON_FIELDS = {
  endpoint: S3_ORIGIN_SCHEMA("https", "RGW S3 endpoint").describe(
    "RGW S3 endpoint; https origin only.",
  ),
  region: z.string().min(1).max(64).refine(isRegion, "a zonegroup api name")
    .describe("Zonegroup api name; the SigV4 region."),
  bucket: z.string().min(3).max(63).refine(isBucketName, "an S3 bucket name")
    .describe("Bucket name."),
  accessKey: S3_PRINTABLE_FIELD.meta({ sensitive: true }).describe(
    "Owner's S3 access key id, from the vault.",
  ),
  secretKey: S3_PRINTABLE_FIELD.meta({ sensitive: true }).describe(
    "Owner's S3 secret, from the vault; used only to sign.",
  ),
  requestTimeoutMs: z.number().int().min(1000).max(300000).describe(
    "Timeout per request in milliseconds.",
  ),
};

const BucketInspectArgs = z.strictObject({ ...S3_COMMON_FIELDS });

const BucketEnsureArgs = z.strictObject({
  ...S3_COMMON_FIELDS,
  placementTarget: z.string().min(1).max(64).refine(
    isRegion,
    "a placement id",
  ).describe("Placement id in the zonegroup; cannot change afterwards."),
  skipObjectLeakProbe: z.boolean().nullish().describe(
    "True skips the object-leak probe; omitted or null runs it.",
  ),
});

const BucketPolicyArgs = z.strictObject({
  ...S3_COMMON_FIELDS,
  policyDocument: z.string().min(2).max(20480).describe(
    "Bucket policy JSON text, sent verbatim.",
  ),
  plainHttpEndpoint: S3_ORIGIN_SCHEMA("http", "plain-HTTP endpoint").nullish()
    .describe(
      "http origin to probe for the TLS-only proof; omitted means not-tested.",
    ),
});

const BucketVersioningArgs = z.strictObject({
  ...S3_COMMON_FIELDS,
  desired: z.enum(["Enabled", "Suspended"]).describe(
    "Target versioning state.",
  ),
});

const AclGrantResultSchema = z.strictObject({
  granteeType: z.string(),
  grantee: z.string(),
  permission: z.string(),
});

const PabResultSchema = z.strictObject({
  blockPublicAcls: z.boolean(),
  ignorePublicAcls: z.boolean(),
  blockPublicPolicy: z.boolean(),
  restrictPublicBuckets: z.boolean(),
});

const BucketInspectResultSchema = z.strictObject({
  method: z.string(),
  endpoint: z.string(),
  region: z.string(),
  bucket: z.string(),
  presence: z.string(),
  ownerId: z.string(),
  aclGrants: z.array(AclGrantResultSchema),
  aclPrivate: z.boolean(),
  hasPolicy: z.boolean(),
  policy: z.string(),
  policyCanonical: z.string(),
  versioning: z.string(),
  publicAccessBlock: PabResultSchema.nullable(),
  publicAccessBlockFull: z.boolean(),
  capturedAt: z.string(),
});

const BucketEnsureResultSchema = z.strictObject({
  method: z.string(),
  endpoint: z.string(),
  region: z.string(),
  bucket: z.string(),
  placementRequested: z.string(),
  existedBefore: z.boolean(),
  created: z.boolean(),
  ownerId: z.string(),
  aclGrantsBefore: z.array(AclGrantResultSchema),
  aclGrantsAfter: z.array(AclGrantResultSchema),
  aclChanged: z.boolean(),
  aclPrivate: z.boolean(),
  pabBefore: PabResultSchema.nullable(),
  pabAfter: PabResultSchema,
  pabChanged: z.boolean(),
  objectLeakProbe: z.string(),
  objectLeakProbeWriter: z.string(),
  objectLeakProbeKey: z.string(),
  objectAclStatus: z.number(),
  anonymousObjectStatus: z.number(),
  grantHeaderPutStatus: z.number(),
  grantHeaderAnonymousStatus: z.number(),
  controlStatus: z.number(),
  anonymousStatus: z.number(),
  capturedAt: z.string(),
});

const BucketPolicyResultSchema = z.strictObject({
  method: z.string(),
  endpoint: z.string(),
  region: z.string(),
  bucket: z.string(),
  hadPolicyBefore: z.boolean(),
  changed: z.boolean(),
  statementCount: z.number(),
  declaresSecureTransport: z.boolean(),
  canonicalPolicy: z.string(),
  controlStatus: z.number(),
  anonymousStatus: z.number(),
  pabLiftedForWrite: z.boolean(),
  plainHttp: z.string(),
  plainHttpStatus: z.number(),
  capturedAt: z.string(),
});

const BucketVersioningResultSchema = z.strictObject({
  method: z.string(),
  endpoint: z.string(),
  region: z.string(),
  bucket: z.string(),
  before: z.string(),
  after: z.string(),
  changed: z.boolean(),
  conditionalWritesUnsafe: z.boolean(),
  capturedAt: z.string(),
});

const PoolResultSchema = z.strictObject({
  name: z.string(),
  scheme: z.string(),
  application: z.string(),
  failureDomain: z.string(),
  size: z.number().optional(),
  crushRule: z.string().optional(),
  erasureCodeProfile: z.string().optional(),
  existed: z.boolean(),
  changed: z.array(z.string()),
  capturedAt: z.string(),
});

const FsResultSchema = z.strictObject({
  name: z.string(),
  mdsHosts: z.array(z.string()),
  creationPath: z.string(),
  existed: z.boolean(),
  capturedAt: z.string(),
});

const CsiUserResultSchema = z.strictObject({
  name: z.string(),
  caps: z.record(z.string(), z.string()),
  capturedAt: z.string(),
});

const ConnBundleResultSchema = z.strictObject({
  fsid: z.string(),
  monEndpoints: z.array(z.string()),
  pools: z.array(z.string()),
  filesystems: z.array(z.string()),
  csiUserNames: z.array(z.string()),
  capturedAt: z.string(),
});

const CsiKeySchema = z.strictObject({
  userName: z.string(),
  key: z.string().meta({ sensitive: true }),
});

const FsDeleteResultSchema = z.strictObject({
  fsName: z.string(),
  deleted: z.boolean(),
  alreadyAbsent: z.boolean(),
  mdsServiceRemoved: z.boolean(),
  poolsDeleted: z.array(z.string()),
  poolsRemaining: z.array(z.string()),
  gateRestored: z.boolean(),
  capturedAt: z.string(),
});

const OsdRemoveResultSchema = z.strictObject({
  requested: z.array(z.number()),
  removed: z.array(z.number()),
  skippedAbsent: z.array(z.number()),
  zap: z.boolean(),
  capturedAt: z.string(),
});

const BootstrapResultSchema = z.strictObject({
  host: z.string(),
  fsid: z.string(),
  cephPubKey: z.string(),
  adminKeyringRef: z.strictObject({ host: z.string(), path: z.string() }),
  bootstrapped: z.boolean(),
  recoveredAfterTransportError: z.boolean(),
  capturedAt: z.string(),
});

const DistributeKeyResultSchema = z.strictObject({
  hosts: z.array(
    z.strictObject({
      host: z.string(),
      port: z.number(),
      alreadyPresent: z.boolean(),
      backedUp: z.boolean(),
      verified: z.boolean(),
    }),
  ),
  capturedAt: z.string(),
});

const HostAddResultSchema = z.strictObject({
  host: z.string(),
  addr: z.string(),
  added: z.boolean(),
  capturedAt: z.string(),
});

const ApplyMonResultSchema = z.strictObject({
  placement: z.array(z.string()),
  applied: z.boolean(),
  replacedCountSpec: z.boolean(),
  previousCount: z.number().nullable(),
  quorumCheck: z.strictObject({
    evaluated: z.boolean(),
    pass: z.boolean().nullable(),
    overridden: z.boolean(),
    kept: z.number(),
    current: z.number(),
  }),
  capturedAt: z.string(),
});

const ApplyMgrResultSchema = z.strictObject({
  placement: z.array(z.string()),
  applied: z.boolean(),
  replacedCountSpec: z.boolean(),
  previousCount: z.number().nullable(),
  capturedAt: z.string(),
});

const ApplyMdsResultSchema = z.strictObject({
  fsName: z.string(),
  placement: z.array(z.string()),
  applied: z.boolean(),
  replacedCountSpec: z.boolean(),
  previousCount: z.number().nullable(),
  capturedAt: z.string(),
});

/**
 * Builds the cephadm model. Overrides replace the production dependencies and
 * are used by tests, so no test opens a socket or touches a host.
 */
export function createCephadmModel(overrides: Partial<CephadmDeps> = {}) {
  const deps: CephadmDeps = { ...productionDeps, ...overrides };

  const sessionFor = (
    a: {
      host: string;
      sshUser: string;
      port?: number | null;
      keyPath?: string | null;
      privateKey?: string | null;
      strictHostKeyChecking: "yes" | "no";
      multiplex?: boolean | null;
    },
  ) =>
    openSession(
      deps,
      toTarget({
        host: a.host,
        sshUser: a.sshUser,
        port: a.port,
        keyPath: a.keyPath,
        privateKey: a.privateKey,
        strictHostKeyChecking: a.strictHostKeyChecking,
      }),
      { multiplex: a.multiplex ?? false },
    );

  const methods = {
    cephHostPrep: {
      kind: "action" as const,
      description:
        "Ensure the named packages, the pinned cephadm binary (at the exact pinned version) and an active time-sync service on one host. Idempotent: a ready host issues no apt, download or enable call. Writes a hostPrepResult with per-package and phase evidence.",
      arguments: HostPrepArgs,
      execute: async (
        args: z.infer<typeof HostPrepArgs>,
        context: MethodContext,
      ) => {
        const target = toTarget({
          host: args.host,
          sshUser: args.sshUser,
          port: args.port,
          keyPath: args.keyPath,
          privateKey: args.privateKey,
          strictHostKeyChecking: args.strictHostKeyChecking,
        });
        const session = await openSession(deps, target, { multiplex: true });
        context.logger.info("Preparing host {host}", { host: args.host });
        try {
          const phase = await runPackagePhase(
            deps,
            session,
            {
              packages: args.packages,
              budgetMs: args.installRetryBudgetMs ?? 0,
            },
            context.logger,
          );
          const cephadm = await ensureCephadm(session, {
            url: args.cephadmUrl,
            version: args.cephadmVersion,
          });
          const timeSync = await ensureTimeSync(session, args.timeSyncService);
          const record = HostPrepResultSchema.parse({
            host: args.host,
            packages: phase.packages,
            cephadm: {
              alreadyPresent: cephadm.alreadyPresent,
              path: CEPHADM_PATH,
              version: cephadm.version,
              reinstalledBroken: cephadm.reinstalledBroken,
            },
            timeSync: {
              service: args.timeSyncService,
              wasActive: timeSync.wasActive,
              active: timeSync.active,
            },
            packagePhase: phase.evidence,
          });
          const handle = await context.writeResource(
            "hostPrepResult",
            `cephHostPrep-${args.host}`,
            record,
          );
          return { dataHandles: [handle] };
        } finally {
          const closed = await session.close();
          if (!closed.closed) {
            context.logger.warn("SSH control master not closed: {detail}", {
              detail: closed.detail,
            });
          }
        }
      },
    },

    cephVerifyPackageSource: {
      description:
        "READ-ONLY. From the host, check each apt mirror and the cephadm URL host: does the name resolve, and does anything answer. Records a verify result and, unless throwOnFail is false, throws after recording when any endpoint is not reached.",
      arguments: PackageSourceArgs,
      execute: async (
        args: z.infer<typeof PackageSourceArgs>,
        context: MethodContext,
      ) => {
        const target = toTarget({
          host: args.host,
          sshUser: args.sshUser,
          port: args.port,
          keyPath: args.keyPath,
          privateKey: args.privateKey,
          strictHostKeyChecking: args.strictHostKeyChecking,
        });
        const session = await openSession(deps, target, {
          multiplex: args.multiplex ?? false,
        });
        try {
          const result = await checkPackageSources(
            session,
            args.cephadmUrl,
            context.logger,
          );
          const handle = await context.writeResource(
            "cephVerifyResult",
            `cephVerifyPackageSource-${args.host}`,
            {
              method: "cephVerifyPackageSource",
              host: args.host,
              pass: result.pass,
              expected: result.expected,
              actual: result.actual,
              detail: result.detail,
              capturedAt: new Date(deps.now()).toISOString(),
            },
          );
          if (!result.pass && (args.throwOnFail ?? true)) {
            throw new PhaseError(
              "pkgsource.check",
              `package sources are not all reachable: ${
                result.findings.join("; ")
              }`,
            );
          }
          return { dataHandles: [handle] };
        } finally {
          await session.close();
        }
      },
    },

    wipeDiskToRaw: {
      kind: "action" as const,
      description:
        "DESTRUCTIVE. Tear down LVM, md-RAID, filesystem and partition state on disks named by serial, leaving them raw for Ceph OSDs, while keeping the host's boot RAID intact. Idempotent and re-runnable; dryRun runs every gate and reports the plan.",
      arguments: WipeArgsSchema,
      execute: async (
        args: z.infer<typeof WipeArgsSchema>,
        context: MethodContext,
      ) => {
        const target = toTarget({
          host: args.host,
          sshUser: args.sshUser,
          port: args.port,
          keyPath: args.keyPath,
          privateKey: args.privateKey,
          strictHostKeyChecking: args.strictHostKeyChecking,
        });
        const session = await openSession(deps, target, {
          multiplex: args.multiplex ?? false,
        });
        context.logger.info(
          "Wiping {count} device(s) on {host} (dryRun {dryRun})",
          {
            count: args.dataDevices.length,
            host: args.host,
            dryRun: args.dryRun ?? false,
          },
        );
        try {
          const record: WipeRecord = await wipeDiskToRaw(
            { ...deps, session },
            {
              dataDevices: args.dataDevices,
              excludeDevices: args.excludeDevices,
              dryRun: args.dryRun,
            },
            context.logger,
          );
          const handle = await context.writeResource(
            "wipeDiskResult",
            `wipeDiskToRaw-${args.host}`,
            record as unknown as Record<string, unknown>,
          );
          return { dataHandles: [handle] };
        } finally {
          const closed = await session.close();
          if (!closed.closed && session.controlPath !== null) {
            context.logger.warn("SSH control master not closed: {detail}", {
              detail: closed.detail,
            });
          }
        }
      },
    },

    cephBootstrap: {
      kind: "action" as const,
      description:
        "Bootstrap a new standalone cephadm cluster on one host, or do nothing when one already exists there. Idempotent; the result carries a path reference to the admin keyring, never its contents.",
      arguments: BootstrapArgs,
      execute: async (
        args: z.infer<typeof BootstrapArgs>,
        context: MethodContext,
      ) => {
        const target = toTarget({
          host: args.host,
          sshUser: args.sshUser,
          port: args.port,
          keyPath: args.keyPath,
          privateKey: args.privateKey,
          strictHostKeyChecking: args.strictHostKeyChecking,
        });
        const session = await openSession(deps, target, { multiplex: true });
        context.logger.info("Bootstrapping {host}", { host: args.host });
        try {
          const result = await bootstrapCluster(
            deps,
            session,
            {
              host: args.host,
              monIp: args.monIp,
              publicNet: args.publicNet,
              clusterNet: args.clusterNet,
              cephImage: args.cephImage,
              sshUser: args.sshUser,
              timeoutMs: args.timeoutMs ?? 900_000,
            },
            context.logger,
          );
          const record = BootstrapResultSchema.parse({
            host: args.host,
            fsid: result.fsid,
            cephPubKey: result.cephPubKey,
            adminKeyringRef: {
              host: args.host,
              path: "/etc/ceph/ceph.client.admin.keyring",
            },
            bootstrapped: result.bootstrapped,
            recoveredAfterTransportError: result.recoveredAfterTransportError,
            capturedAt: new Date(deps.now()).toISOString(),
          });
          const handle = await context.writeResource(
            "cephBootstrapResult",
            `cephBootstrap-${args.host}`,
            record,
          );
          return { dataHandles: [handle] };
        } finally {
          await session.close();
        }
      },
    },

    cephDistributeKey: {
      kind: "action" as const,
      description:
        "Append the cluster public key to sshUser's authorized_keys on every listed host, deduplicated, with a backup taken on every run. Idempotent; processes every host and fails at the end if any host did not verify.",
      arguments: DistributeKeyArgs,
      execute: async (
        args: z.infer<typeof DistributeKeyArgs>,
        context: MethodContext,
      ) => {
        const outcomes: DistributeOutcome[] = [];
        for (const entry of args.hosts) {
          const target = toTarget({
            host: entry.host,
            sshUser: args.sshUser,
            port: entry.port,
            keyPath: args.keyPath,
            privateKey: args.privateKey,
            strictHostKeyChecking: args.strictHostKeyChecking,
          });
          const session = await openSession(deps, target, {
            multiplex: args.multiplex ?? false,
          });
          try {
            outcomes.push(
              await distributeKeyToHost(
                deps,
                session,
                args.cephPubKey,
                entry.host,
                entry.port,
              ),
            );
          } catch (e) {
            outcomes.push({
              host: entry.host,
              port: entry.port,
              alreadyPresent: false,
              backedUp: false,
              verified: false,
              reason: e instanceof TransportError
                ? e.message
                : (e as Error).message,
            });
          } finally {
            await session.close();
          }
        }
        const failed = outcomes.filter((o) => !o.verified);
        // Persist the per-host outcomes even when some host failed, so the
        // evidence is not lost, then throw.
        const handle = await context.writeResource(
          "cephDistributeKeyResult",
          distributeRecordKey(args.hosts),
          {
            hosts: outcomes.map((o) => ({
              host: o.host,
              port: o.port,
              alreadyPresent: o.alreadyPresent,
              backedUp: o.backedUp,
              verified: o.verified,
            })),
            capturedAt: new Date(deps.now()).toISOString(),
          },
        );
        if (failed.length > 0) {
          throw new PhaseError(
            "cephDistributeKey",
            `the key is not present on ${failed.length} of ${outcomes.length} hosts`,
            {
              failures: failed.map((o) =>
                `${o.host}:${o.port} (${o.reason ?? "unverified"})`
              ),
            },
          );
        }
        return { dataHandles: [handle] };
      },
    },

    cephHostAdd: {
      kind: "action" as const,
      description:
        "Enrol a host with the orchestrator after confirming the admin host is attached to the expected cluster, then read the host list back. Idempotent; a host already registered at the same address is a no-op.",
      arguments: HostAddArgs,
      execute: async (
        args: z.infer<typeof HostAddArgs>,
        context: MethodContext,
      ) => {
        const session = await openSession(
          deps,
          toTarget({
            host: args.adminHost,
            sshUser: args.sshUser,
            port: args.port,
            keyPath: args.keyPath,
            privateKey: args.privateKey,
            strictHostKeyChecking: args.strictHostKeyChecking,
          }),
          { multiplex: args.multiplex ?? false },
        );
        try {
          const result = await hostAdd(
            deps,
            session,
            { fsid: args.fsid, host: args.host, addr: args.addr },
            context.logger,
          );
          const handle = await context.writeResource(
            "cephHostAddResult",
            `cephHostAdd-${args.host}`,
            {
              host: args.host,
              addr: args.addr,
              added: result.added,
              capturedAt: new Date(deps.now()).toISOString(),
            },
          );
          return { dataHandles: [handle] };
        } finally {
          await session.close();
        }
      },
    },

    cephApplyMon: {
      kind: "action" as const,
      description:
        "Converge mon placement to an explicit host list, refusing a change that would leave fewer than a strict majority of the current in-quorum mons unless allowQuorumRisk is set. Idempotent; a count-based spec is replaced.",
      arguments: ApplyMonArgs,
      execute: async (
        args: z.infer<typeof ApplyMonArgs>,
        context: MethodContext,
      ) => {
        const session = await openSession(
          deps,
          toTarget({
            host: args.adminHost,
            sshUser: args.sshUser,
            port: args.port,
            keyPath: args.keyPath,
            privateKey: args.privateKey,
            strictHostKeyChecking: args.strictHostKeyChecking,
          }),
          { multiplex: args.multiplex ?? false },
        );
        try {
          const result = await applyMon(
            deps,
            session,
            {
              placement: args.placement,
              allowQuorumRisk: args.allowQuorumRisk ?? false,
            },
            context.logger,
          );
          const handle = await context.writeResource(
            "cephApplyMonResult",
            `cephApplyMon-${args.adminHost}`,
            {
              placement: args.placement,
              applied: result.applied,
              replacedCountSpec: result.replacedCountSpec,
              previousCount: result.previousCount,
              quorumCheck: result.quorumCheck,
              capturedAt: new Date(deps.now()).toISOString(),
            },
          );
          return { dataHandles: [handle] };
        } finally {
          await session.close();
        }
      },
    },

    cephApplyMgr: {
      kind: "action" as const,
      description:
        "Converge mgr placement to an explicit host list, never a count. Idempotent; a count-based spec is replaced and recorded.",
      arguments: ApplyMgrArgs,
      execute: async (
        args: z.infer<typeof ApplyMgrArgs>,
        context: MethodContext,
      ) => {
        const session = await openSession(
          deps,
          toTarget({
            host: args.adminHost,
            sshUser: args.sshUser,
            port: args.port,
            keyPath: args.keyPath,
            privateKey: args.privateKey,
            strictHostKeyChecking: args.strictHostKeyChecking,
          }),
          { multiplex: args.multiplex ?? false },
        );
        try {
          const result = await applyPlacement(
            deps,
            session,
            {
              serviceName: "mgr",
              applyArgs: "mgr",
              requested: args.placement,
              phase: "cephApplyMgr",
            },
            context.logger,
          );
          const handle = await context.writeResource(
            "cephApplyMgrResult",
            `cephApplyMgr-${args.adminHost}`,
            {
              placement: args.placement,
              applied: result.applied,
              replacedCountSpec: result.replacedCountSpec,
              previousCount: result.previousCount,
              capturedAt: new Date(deps.now()).toISOString(),
            },
          );
          return { dataHandles: [handle] };
        } finally {
          await session.close();
        }
      },
    },

    cephApplyMds: {
      kind: "action" as const,
      description:
        "Converge one filesystem's MDS placement to an explicit host list. Idempotent; sets only where MDS daemons run, never max_mds or standby_count_wanted.",
      arguments: ApplyMdsArgs,
      execute: async (
        args: z.infer<typeof ApplyMdsArgs>,
        context: MethodContext,
      ) => {
        const session = await openSession(
          deps,
          toTarget({
            host: args.adminHost,
            sshUser: args.sshUser,
            port: args.port,
            keyPath: args.keyPath,
            privateKey: args.privateKey,
            strictHostKeyChecking: args.strictHostKeyChecking,
          }),
          { multiplex: args.multiplex ?? false },
        );
        try {
          const result = await applyPlacement(
            deps,
            session,
            {
              serviceName: `mds.${args.fsName}`,
              applyArgs: `mds ${args.fsName}`,
              requested: args.placement,
              phase: "cephApplyMds",
            },
            context.logger,
          );
          const handle = await context.writeResource(
            "cephApplyMdsResult",
            `cephApplyMds-${args.adminHost}-${args.fsName}`,
            {
              fsName: args.fsName,
              placement: args.placement,
              applied: result.applied,
              replacedCountSpec: result.replacedCountSpec,
              previousCount: result.previousCount,
              capturedAt: new Date(deps.now()).toISOString(),
            },
          );
          return { dataHandles: [handle] };
        } finally {
          await session.close();
        }
      },
    },

    cephApplyOsd: {
      kind: "action" as const,
      description:
        "Apply an OSD service: fleet-wide all-available devices, or one by-serial service per disk-owning host. All-available mode is presence-only: once the service exists, a changed exclude list or new disks never trigger a re-apply. Selector mode resolves every serial to a by-id path first, so a resolution failure leaves the cluster untouched.",
      arguments: ApplyOsdArgs,
      execute: async (
        args: z.infer<typeof ApplyOsdArgs>,
        context: MethodContext,
      ) => {
        // Mode rules are re-checked here, before any SSH call.
        const mode = validateOsdMode(args);
        const adminSession = await openSession(
          deps,
          toTarget({
            host: args.adminHost,
            sshUser: args.sshUser,
            port: args.port,
            keyPath: args.keyPath,
            privateKey: args.privateKey,
            strictHostKeyChecking: args.strictHostKeyChecking,
          }),
          { multiplex: args.multiplex ?? false },
        );
        let targetSession: SshSession | null = null;
        try {
          if (mode.mode === "selector") {
            targetSession = await openSession(
              deps,
              toTarget({
                host: args.targetAddr ?? mode.targetHost!,
                sshUser: args.sshUser,
                port: args.targetPort ?? args.port,
                keyPath: args.keyPath,
                privateKey: args.privateKey,
                strictHostKeyChecking: args.strictHostKeyChecking,
              }),
              { multiplex: args.multiplex ?? false },
            );
          }
          const result = await applyOsd(
            deps,
            adminSession,
            targetSession,
            args,
            context.logger,
          );
          const handle = await context.writeResource(
            "cephApplyOsdResult",
            `cephApplyOsd-${args.adminHost}-${result.serviceId}`,
            {
              serviceId: result.serviceId,
              allAvailableDevices: result.allAvailableDevices,
              targetHost: result.targetHost,
              dataDevices: result.dataDevices,
              resolvedPaths: result.resolvedPaths,
              excludeDevices: result.excludeDevices,
              applied: result.applied,
              staleServicesRemoved: result.staleServicesRemoved,
              capturedAt: new Date(deps.now()).toISOString(),
            },
          );
          return { dataHandles: [handle] };
        } finally {
          if (targetSession !== null) await targetSession.close();
          await adminSession.close();
        }
      },
    },

    cephCreatePool: {
      kind: "action" as const,
      description:
        "Ensure a replicated or erasure-coded pool exists with the requested redundancy, CRUSH failure domain and application. Idempotent; an existing pool that matches is left in place, and a mismatched pool is refused rather than converged.",
      arguments: CreatePoolArgs,
      execute: async (
        args: z.infer<typeof CreatePoolArgs>,
        context: MethodContext,
      ) => {
        const session = await openSession(
          deps,
          toTarget({
            host: args.host,
            sshUser: args.sshUser,
            port: args.port,
            keyPath: args.keyPath,
            privateKey: args.privateKey,
            strictHostKeyChecking: args.strictHostKeyChecking,
          }),
          { multiplex: args.multiplex ?? false },
        );
        try {
          const result = await createPool(deps, session, {
            name: args.name,
            scheme: args.scheme,
            size: args.size,
            erasureProfile: args.erasureProfile,
            application: args.application,
            failureDomain: args.failureDomain,
          }, context.logger);
          const handle = await context.writeResource(
            "poolResult",
            `cephCreatePool-${args.host}-${args.name}`,
            { ...result, capturedAt: new Date(deps.now()).toISOString() },
          );
          return { dataHandles: [handle] };
        } finally {
          await session.close();
        }
      },
    },

    cephCreateFs: {
      kind: "action" as const,
      description:
        "Ensure a CephFS volume exists and its MDS daemons are placed on an explicit host list, creating the volume or adopting pre-created pools. Idempotent; the MDS placement is re-applied on every run.",
      arguments: CreateFsArgs,
      execute: async (
        args: z.infer<typeof CreateFsArgs>,
        context: MethodContext,
      ) => {
        const session = await openSession(
          deps,
          toTarget({
            host: args.host,
            sshUser: args.sshUser,
            port: args.port,
            keyPath: args.keyPath,
            privateKey: args.privateKey,
            strictHostKeyChecking: args.strictHostKeyChecking,
          }),
          { multiplex: args.multiplex ?? false },
        );
        try {
          const result = await createFs(deps, session, {
            name: args.name,
            placement: args.placement,
            timeoutMs: args.timeoutMs,
          }, context.logger);
          const handle = await context.writeResource(
            "fsResult",
            `cephCreateFs-${args.host}-${args.name}`,
            { ...result, capturedAt: new Date(deps.now()).toISOString() },
          );
          return { dataHandles: [handle] };
        } finally {
          await session.close();
        }
      },
    },

    cephCreateCsiUser: {
      kind: "action" as const,
      description:
        "Create a Ceph client entity, or set an existing one's caps to exactly the request, then read the caps back. Idempotent; never returns a key.",
      arguments: CreateCsiUserArgs,
      execute: async (
        args: z.infer<typeof CreateCsiUserArgs>,
        context: MethodContext,
      ) => {
        const session = await openSession(
          deps,
          toTarget({
            host: args.host,
            sshUser: args.sshUser,
            port: args.port,
            keyPath: args.keyPath,
            privateKey: args.privateKey,
            strictHostKeyChecking: args.strictHostKeyChecking,
          }),
          { multiplex: args.multiplex ?? false },
        );
        try {
          const result = await createCsiUser(deps, session, {
            name: args.name,
            caps: args.caps,
          }, context.logger);
          const handle = await context.writeResource(
            "csiUserResult",
            `cephCreateCsiUser-${args.host}-${args.name}`,
            { ...result, capturedAt: new Date(deps.now()).toISOString() },
          );
          return { dataHandles: [handle] };
        } finally {
          await session.close();
        }
      },
    },

    cephGetConnBundle: {
      description:
        "READ-ONLY. Produce the non-secret connection facts a client needs: fsid, mon v2 endpoints, pool names, CephFS names and client entity names.",
      arguments: ReadHostArgs,
      execute: async (
        args: z.infer<typeof ReadHostArgs>,
        context: MethodContext,
      ) => {
        const session = await openSession(
          deps,
          toTarget({
            host: args.host,
            sshUser: args.sshUser,
            port: args.port,
            keyPath: args.keyPath,
            privateKey: args.privateKey,
            strictHostKeyChecking: args.strictHostKeyChecking,
          }),
          { multiplex: args.multiplex ?? false },
        );
        try {
          const result = await getConnBundle(deps, session, context.logger);
          const handle = await context.writeResource(
            "connBundleResult",
            `cephGetConnBundle-${args.host}`,
            { ...result, capturedAt: new Date(deps.now()).toISOString() },
          );
          return { dataHandles: [handle] };
        } finally {
          await session.close();
        }
      },
    },

    cephFetchCsiKey: {
      description:
        "SENSITIVE. Read one client entity's key into a sensitive field, which the platform stores in its vault. Each run writes a new version and 2 are kept.",
      arguments: FetchCsiKeyArgs,
      execute: async (
        args: z.infer<typeof FetchCsiKeyArgs>,
        context: MethodContext,
      ) => {
        const session = await openSession(
          deps,
          toTarget({
            host: args.host,
            sshUser: args.sshUser,
            port: args.port,
            keyPath: args.keyPath,
            privateKey: args.privateKey,
            strictHostKeyChecking: args.strictHostKeyChecking,
          }),
          { multiplex: args.multiplex ?? false },
        );
        try {
          const result = await fetchCsiKey(
            deps,
            session,
            args.userName,
            context.logger,
          );
          const handle = await context.writeResource(
            "csiKey",
            `cephFetchCsiKey-${args.host}-${args.userName}`,
            result,
          );
          return { dataHandles: [handle] };
        } finally {
          await session.close();
        }
      },
    },

    cephDeleteFs: {
      kind: "action" as const,
      description:
        "DESTRUCTIVE. Delete a CephFS volume and its backing pools, after a double confirmation, proven MDS removal and a pool-delete gate that is always closed again. A no-op when the volume is absent.",
      arguments: DeleteFsArgs,
      execute: async (
        args: z.infer<typeof DeleteFsArgs>,
        context: MethodContext,
      ) => {
        const session = await openSession(
          deps,
          toTarget({
            host: args.host,
            sshUser: args.sshUser,
            port: args.port,
            keyPath: args.keyPath,
            privateKey: args.privateKey,
            strictHostKeyChecking: args.strictHostKeyChecking,
          }),
          { multiplex: args.multiplex ?? false },
        );
        try {
          const result = await deleteFs(deps, session, {
            fsName: args.fsName,
            confirmFsName: args.confirmFsName,
            maxPolls: args.maxPolls,
            pollIntervalMs: args.pollIntervalMs,
          }, context.logger);
          const handle = await context.writeResource(
            "fsDeleteResult",
            `cephDeleteFs-${args.host}-${args.fsName}`,
            { ...result, capturedAt: new Date(deps.now()).toISOString() },
          );
          return { dataHandles: [handle] };
        } finally {
          await session.close();
        }
      },
    },

    cephRemoveOsds: {
      kind: "action" as const,
      description:
        "DESTRUCTIVE. Remove OSDs through the orchestrator (draining and, by default, zapping the disks) and prove they are gone from the OSD tree. Idempotent per id.",
      arguments: RemoveOsdsArgs,
      execute: async (
        args: z.infer<typeof RemoveOsdsArgs>,
        context: MethodContext,
      ) => {
        const session = await openSession(
          deps,
          toTarget({
            host: args.host,
            sshUser: args.sshUser,
            port: args.port,
            keyPath: args.keyPath,
            privateKey: args.privateKey,
            strictHostKeyChecking: args.strictHostKeyChecking,
          }),
          { multiplex: args.multiplex ?? false },
        );
        try {
          const result = await removeOsds(deps, session, {
            osdIds: args.osdIds,
            zap: args.zap,
            maxPolls: args.maxPolls,
            pollIntervalMs: args.pollIntervalMs,
          }, context.logger);
          const handle = await context.writeResource(
            "osdRemoveResult",
            `cephRemoveOsds-${args.host}-${result.requested.join("-")}`,
            { ...result, capturedAt: new Date(deps.now()).toISOString() },
          );
          return { dataHandles: [handle] };
        } finally {
          await session.close();
        }
      },
    },

    cephVerifyMonQuorum: {
      description:
        "READ-ONLY. Assert the monmap has exactly the expected number of mons and that every defined mon is in quorum. Writes the verdict before throwing, then throws when it fails unless throwOnFail is false.",
      arguments: VerifyMonQuorumArgs,
      execute: async (
        args: z.infer<typeof VerifyMonQuorumArgs>,
        context: MethodContext,
      ) => {
        const session = await openSession(
          deps,
          toTarget({
            host: args.host,
            sshUser: args.sshUser,
            port: args.port,
            keyPath: args.keyPath,
            privateKey: args.privateKey,
            strictHostKeyChecking: args.strictHostKeyChecking,
          }),
          { multiplex: args.multiplex ?? false },
        );
        try {
          const outcome = await verifyMonQuorum(deps, session, {
            expectedMonCount: args.expectedMonCount,
            quorumSettleMs: args.quorumSettleMs,
            quorumPollIntervalMs: args.quorumPollIntervalMs,
          }, context.logger);
          const handle = await persistVerdict(context, deps, {
            method: "cephVerifyMonQuorum",
            host: args.host,
            phase: "mon-quorum",
            key: `cephVerifyMonQuorum-${args.host}`,
            outcome,
            throwOnFail: args.throwOnFail ?? true,
          });
          return { dataHandles: [handle] };
        } finally {
          await session.close();
        }
      },
    },

    cephVerifyMgr: {
      description:
        "READ-ONLY. Assert the mgr daemon count and that one mgr is genuinely active. Writes the verdict before throwing, then throws when it fails unless throwOnFail is false.",
      arguments: VerifyMgrArgs,
      execute: async (
        args: z.infer<typeof VerifyMgrArgs>,
        context: MethodContext,
      ) => {
        const session = await openSession(
          deps,
          toTarget({
            host: args.host,
            sshUser: args.sshUser,
            port: args.port,
            keyPath: args.keyPath,
            privateKey: args.privateKey,
            strictHostKeyChecking: args.strictHostKeyChecking,
          }),
          { multiplex: args.multiplex ?? false },
        );
        try {
          const outcome = await verifyMgr(deps, session, {
            expectedCount: args.expectedCount,
          }, context.logger);
          const handle = await persistVerdict(context, deps, {
            method: "cephVerifyMgr",
            host: args.host,
            phase: "mgr",
            key: `cephVerifyMgr-${args.host}`,
            outcome,
            throwOnFail: args.throwOnFail ?? true,
          });
          return { dataHandles: [handle] };
        } finally {
          await session.close();
        }
      },
    },

    cephVerifyOsd: {
      description:
        "READ-ONLY. Assert the OSD up count and in count independently, and that a CRUSH rule's failure domain matches. Writes the verdict before throwing, then throws when it fails unless throwOnFail is false.",
      arguments: VerifyOsdArgs,
      execute: async (
        args: z.infer<typeof VerifyOsdArgs>,
        context: MethodContext,
      ) => {
        const session = await openSession(
          deps,
          toTarget({
            host: args.host,
            sshUser: args.sshUser,
            port: args.port,
            keyPath: args.keyPath,
            privateKey: args.privateKey,
            strictHostKeyChecking: args.strictHostKeyChecking,
          }),
          { multiplex: args.multiplex ?? false },
        );
        try {
          const outcome = await verifyOsd(deps, session, {
            expectedUp: args.expectedUp,
            expectedIn: args.expectedIn,
            expectedFailureDomain: args.expectedFailureDomain,
            crushRuleName: args.crushRuleName,
            osdSettleMs: args.osdSettleMs,
            osdPollIntervalMs: args.osdPollIntervalMs,
          }, context.logger);
          const handle = await persistVerdict(context, deps, {
            method: "cephVerifyOsd",
            host: args.host,
            phase: "osd",
            key: `cephVerifyOsd-${args.host}`,
            outcome,
            throwOnFail: args.throwOnFail ?? true,
          });
          return { dataHandles: [handle] };
        } finally {
          await session.close();
        }
      },
    },

    cephVerifyCsiUsers: {
      description:
        "READ-ONLY. Assert that every expected client entity exists and report its caps; keys are discarded. Writes the verdict before throwing, then throws when it fails unless throwOnFail is false.",
      arguments: VerifyCsiUsersArgs,
      execute: async (
        args: z.infer<typeof VerifyCsiUsersArgs>,
        context: MethodContext,
      ) => {
        const session = await openSession(
          deps,
          toTarget({
            host: args.host,
            sshUser: args.sshUser,
            port: args.port,
            keyPath: args.keyPath,
            privateKey: args.privateKey,
            strictHostKeyChecking: args.strictHostKeyChecking,
          }),
          { multiplex: args.multiplex ?? false },
        );
        try {
          const outcome = await verifyCsiUsers(
            deps,
            session,
            args.expectedUserNames,
            context.logger,
          );
          const handle = await persistVerdict(context, deps, {
            method: "cephVerifyCsiUsers",
            host: args.host,
            phase: "csi-users",
            key: `cephVerifyCsiUsers-${args.host}`,
            outcome,
            throwOnFail: args.throwOnFail ?? true,
          });
          return { dataHandles: [handle] };
        } finally {
          await session.close();
        }
      },
    },

    cephVerifyHealth: {
      description:
        "READ-ONLY. Assert cluster health in a stated direction, naming the checks responsible and refusing a warning with no named check. Writes the verdict before throwing, then throws when it fails unless throwOnFail is false.",
      arguments: VerifyHealthArgs,
      execute: async (
        args: z.infer<typeof VerifyHealthArgs>,
        context: MethodContext,
      ) => {
        const session = await openSession(
          deps,
          toTarget({
            host: args.host,
            sshUser: args.sshUser,
            port: args.port,
            keyPath: args.keyPath,
            privateKey: args.privateKey,
            strictHostKeyChecking: args.strictHostKeyChecking,
          }),
          { multiplex: args.multiplex ?? false },
        );
        try {
          const outcome = await verifyHealth(deps, session, {
            wantOk: args.wantOk,
            allowedWarnings: args.allowedWarnings,
          }, context.logger);
          const handle = await persistVerdict(context, deps, {
            method: "cephVerifyHealth",
            host: args.host,
            phase: "health",
            key: `cephVerifyHealth-${args.host}`,
            outcome,
            throwOnFail: args.throwOnFail ?? true,
          });
          return { dataHandles: [handle] };
        } finally {
          await session.close();
        }
      },
    },

    cephVerifyHostNoout: {
      description:
        "READ-ONLY. Check whether the host-subtree noout flag is set for one Ceph host, against an expectation the caller must state. Writes the verdict before throwing, then throws when it fails unless throwOnFail is false.",
      arguments: VerifyHostNooutArgs,
      execute: async (
        args: z.infer<typeof VerifyHostNooutArgs>,
        context: MethodContext,
      ) => {
        const session = await openSession(
          deps,
          toTarget({
            host: args.host,
            sshUser: args.sshUser,
            port: args.port,
            keyPath: args.keyPath,
            privateKey: args.privateKey,
            strictHostKeyChecking: args.strictHostKeyChecking,
          }),
          { multiplex: args.multiplex ?? false },
        );
        try {
          const outcome = await verifyHostNoout(deps, session, {
            hostName: args.hostName,
            expectSet: args.expectSet,
          }, context.logger);
          const handle = await persistVerdict(context, deps, {
            method: "cephVerifyHostNoout",
            host: args.host,
            phase: "host-noout",
            key: `cephVerifyHostNoout-${args.host}-${args.hostName}`,
            outcome,
            throwOnFail: args.throwOnFail ?? true,
          });
          return { dataHandles: [handle] };
        } finally {
          await session.close();
        }
      },
    },

    cephVerifyHostPrep: {
      description:
        "READ-ONLY. Assert the facts cephHostPrep establishes, without changing anything: packages installed, the pinned cephadm version present and a time-sync service active. Writes the verdict before throwing, then throws when it fails unless throwOnFail is false.",
      arguments: VerifyHostPrepArgs,
      execute: async (
        args: z.infer<typeof VerifyHostPrepArgs>,
        context: MethodContext,
      ) => {
        const session = await openSession(
          deps,
          toTarget({
            host: args.host,
            sshUser: args.sshUser,
            port: args.port,
            keyPath: args.keyPath,
            privateKey: args.privateKey,
            strictHostKeyChecking: args.strictHostKeyChecking,
          }),
          { multiplex: args.multiplex ?? false },
        );
        try {
          const outcome = await verifyHostPrep(deps, session, {
            expectedPackages: args.expectedPackages,
            expectedCephadmVersion: args.expectedCephadmVersion,
            expectedTimeSyncService: args.expectedTimeSyncService,
          }, context.logger);
          const handle = await persistVerdict(context, deps, {
            method: "cephVerifyHostPrep",
            host: args.host,
            phase: "host-prep",
            key: `cephVerifyHostPrep-${args.host}`,
            outcome,
            throwOnFail: args.throwOnFail ?? true,
          });
          return { dataHandles: [handle] };
        } finally {
          await session.close();
        }
      },
    },

    cephVerifyDisksRaw: {
      description:
        "READ-ONLY. Assert that each serial-resolved device is genuinely raw: no signature, no children and no mountpoint anywhere in its subtree. Writes the verdict before throwing, then throws when it fails unless throwOnFail is false.",
      arguments: VerifyDisksRawArgs,
      execute: async (
        args: z.infer<typeof VerifyDisksRawArgs>,
        context: MethodContext,
      ) => {
        const session = await openSession(
          deps,
          toTarget({
            host: args.host,
            sshUser: args.sshUser,
            port: args.port,
            keyPath: args.keyPath,
            privateKey: args.privateKey,
            strictHostKeyChecking: args.strictHostKeyChecking,
          }),
          { multiplex: args.multiplex ?? false },
        );
        try {
          const outcome = await verifyDisksRaw(
            deps,
            session,
            args.dataDevices,
            context.logger,
          );
          const handle = await persistVerdict(context, deps, {
            method: "cephVerifyDisksRaw",
            host: args.host,
            phase: "disks-raw",
            key: `cephVerifyDisksRaw-${args.host}`,
            outcome,
            throwOnFail: args.throwOnFail ?? true,
          });
          return { dataHandles: [handle] };
        } finally {
          await session.close();
        }
      },
    },

    cephVerifyKeyDistributed: {
      description:
        "READ-ONLY. Re-read each host's authorized_keys on a fresh connection and report per host whether the key is present, absent, unreadable or unreachable. Writes the record, then throws a typed transport error if any host was unreachable, whatever throwOnFail says.",
      arguments: VerifyKeyDistributedArgs,
      execute: async (
        args: z.infer<typeof VerifyKeyDistributedArgs>,
        context: MethodContext,
      ) => {
        const port = args.port ?? 22;
        const result = await verifyKeyDistributed(deps, {
          hosts: args.hosts,
          port,
          cephPubKey: args.cephPubKey,
          makeSession: (host) =>
            openSession(
              deps,
              toTarget({
                host,
                sshUser: args.sshUser,
                port,
                keyPath: args.keyPath,
                privateKey: args.privateKey,
                strictHostKeyChecking: args.strictHostKeyChecking,
              }),
              { multiplex: false },
            ),
        }, context.logger);
        const key = `cephVerifyKeyDistributed-${
          args.hosts.map((h) => `${h}:${port}`).sort().join(",")
        }`;
        const handle = await persistVerdict(context, deps, {
          method: "cephVerifyKeyDistributed",
          host: args.hosts.map((h) => `${h}:${port}`).sort().join(","),
          phase: "key-distributed",
          key,
          outcome: result.outcome,
          throwOnFail: false,
        });
        if (result.unreachable.length > 0) {
          throw new TransportError({
            host: result.unreachable[0].host,
            port,
            user: args.sshUser,
            kind: "other",
            cause: null,
            message: `unreachable hosts: ${
              result.unreachable.map((e) => e.host).join(", ")
            }`,
          });
        }
        if (!result.outcome.pass && (args.throwOnFail ?? true)) {
          fail("key-distributed", "verification failed", {
            expected: JSON.stringify(result.outcome.expected),
            actual: JSON.stringify(result.outcome.actual),
            recordKey: key,
          });
        }
        return { dataHandles: [handle] };
      },
    },

    cephCapacityReport: {
      description:
        "READ-ONLY. Report cluster and per-pool capacity with the durability margin. atRiskPools lists erasure-coded pools whose min_size margin is at most 1; unjudgedPools lists erasure-coded pools whose margin could not be read.",
      arguments: ReadHostArgs,
      execute: async (
        args: z.infer<typeof ReadHostArgs>,
        context: MethodContext,
      ) => {
        const session = await openSession(
          deps,
          toTarget({
            host: args.host,
            sshUser: args.sshUser,
            port: args.port,
            keyPath: args.keyPath,
            privateKey: args.privateKey,
            strictHostKeyChecking: args.strictHostKeyChecking,
          }),
          { multiplex: args.multiplex ?? false },
        );
        try {
          const report = await capacityReport(deps, session, context.logger);
          const handle = await context.writeResource(
            "cephCapacityReport",
            `cephCapacityReport-${args.host}`,
            {
              host: args.host,
              ...report,
              observedAt: new Date(deps.now()).toISOString(),
            },
          );
          return { dataHandles: [handle] };
        } finally {
          await session.close();
        }
      },
    },

    cephVerifyMonPlacement: {
      description:
        "READ-ONLY. Pre-approval check that judges a proposed mon host list against live quorum, the monmap and orchestrator mappings; applies nothing. Writes the verdict before throwing, then throws when it fails unless throwOnFail is false.",
      arguments: VerifyPlacementArgs,
      execute: async (
        args: z.infer<typeof VerifyPlacementArgs>,
        context: MethodContext,
      ) => {
        const session = await openSession(
          deps,
          toTarget({
            host: args.host,
            sshUser: args.sshUser,
            port: args.port,
            keyPath: args.keyPath,
            privateKey: args.privateKey,
            strictHostKeyChecking: args.strictHostKeyChecking,
          }),
          { multiplex: args.multiplex ?? false },
        );
        try {
          const outcome = await verifyMonPlacement(
            deps,
            session,
            args.placement,
            context.logger,
          );
          const handle = await persistVerdict(context, deps, {
            method: "cephVerifyMonPlacement",
            host: args.host,
            phase: "mon-placement",
            key: `cephVerifyMonPlacement-${args.host}`,
            outcome,
            throwOnFail: args.throwOnFail ?? true,
          });
          return { dataHandles: [handle] };
        } finally {
          await session.close();
        }
      },
    },

    cephVerifyMgrPlacement: {
      description:
        "READ-ONLY. Pre-approval check that judges a proposed mgr host list without applying it, reporting a mgr placed on the host of an active MDS. Writes the verdict before throwing, then throws when it fails unless throwOnFail is false.",
      arguments: VerifyPlacementArgs,
      execute: async (
        args: z.infer<typeof VerifyPlacementArgs>,
        context: MethodContext,
      ) => {
        const session = await openSession(
          deps,
          toTarget({
            host: args.host,
            sshUser: args.sshUser,
            port: args.port,
            keyPath: args.keyPath,
            privateKey: args.privateKey,
            strictHostKeyChecking: args.strictHostKeyChecking,
          }),
          { multiplex: args.multiplex ?? false },
        );
        try {
          const outcome = await verifyMgrPlacement(
            deps,
            session,
            args.placement,
            context.logger,
          );
          const handle = await persistVerdict(context, deps, {
            method: "cephVerifyMgrPlacement",
            host: args.host,
            phase: "mgr-placement",
            key: `cephVerifyMgrPlacement-${args.host}`,
            outcome,
            throwOnFail: args.throwOnFail ?? true,
          });
          return { dataHandles: [handle] };
        } finally {
          await session.close();
        }
      },
    },

    cephVerifyPool: {
      description:
        "READ-ONLY. Assert a pool exists at the expected size with every PG active+clean, optionally its min_size, erasure-code shape and MDS state. Writes the verdict before throwing, then throws when it fails unless throwOnFail is false.",
      arguments: VerifyPoolArgs,
      execute: async (
        args: z.infer<typeof VerifyPoolArgs>,
        context: MethodContext,
      ) => {
        const session = await openSession(
          deps,
          toTarget({
            host: args.host,
            sshUser: args.sshUser,
            port: args.port,
            keyPath: args.keyPath,
            privateKey: args.privateKey,
            strictHostKeyChecking: args.strictHostKeyChecking,
          }),
          { multiplex: args.multiplex ?? false },
        );
        try {
          const outcome = await verifyPool(deps, session, {
            poolName: args.poolName,
            expectedSize: args.expectedSize,
            expectedMinSize: args.expectedMinSize,
            expectedErasureProfile: args.expectedErasureProfile,
            mds: args.mds,
            settleMs: args.settleMs,
            settlePollIntervalMs: args.settlePollIntervalMs,
          }, context.logger);
          const handle = await persistVerdict(context, deps, {
            method: "cephVerifyPool",
            host: args.host,
            phase: "pool",
            key: `cephVerifyPool-${args.host}-${args.poolName}`,
            outcome,
            throwOnFail: args.throwOnFail ?? true,
          });
          return { dataHandles: [handle] };
        } finally {
          await session.close();
        }
      },
    },

    cephVerifyRbdSmoke: {
      kind: "action" as const,
      description:
        "Create and remove one tiny throwaway RBD image (prefix cephadm-smoke-), reading it back to prove name and size; it is the only verify method that writes anything. A name collision is refused and never overwritten; the image is always removed once created.",
      arguments: VerifyRbdSmokeArgs,
      execute: async (
        args: z.infer<typeof VerifyRbdSmokeArgs>,
        context: MethodContext,
      ) => {
        const session = await openSession(
          deps,
          toTarget({
            host: args.host,
            sshUser: args.sshUser,
            port: args.port,
            keyPath: args.keyPath,
            privateKey: args.privateKey,
            strictHostKeyChecking: args.strictHostKeyChecking,
          }),
          { multiplex: args.multiplex ?? false },
        );
        try {
          const outcome = await verifyRbdSmoke(
            deps,
            session,
            args.pool,
            context.logger,
          );
          const handle = await persistVerdict(context, deps, {
            method: "cephVerifyRbdSmoke",
            host: args.host,
            phase: "rbd-smoke",
            key: `cephVerifyRbdSmoke-${args.host}`,
            outcome,
            throwOnFail: args.throwOnFail ?? true,
          });
          return { dataHandles: [handle] };
        } finally {
          await session.close();
        }
      },
    },

    cephVerifyOsdClaimable: {
      description:
        "READ-ONLY. Pre-approval check that judges which disks cephadm would claim: fleet-wide available devices against an exclude list, or an explicit per-host selector. Applies nothing. Writes the verdict before throwing, then throws when it fails unless throwOnFail is false.",
      arguments: VerifyOsdClaimableArgs,
      execute: async (
        args: z.infer<typeof VerifyOsdClaimableArgs>,
        context: MethodContext,
      ) => {
        const session = await openSession(
          deps,
          toTarget({
            host: args.host,
            sshUser: args.sshUser,
            port: args.port,
            keyPath: args.keyPath,
            privateKey: args.privateKey,
            strictHostKeyChecking: args.strictHostKeyChecking,
          }),
          { multiplex: args.multiplex ?? false },
        );
        try {
          const outcome = await verifyOsdClaimable(deps, session, {
            allAvailableDevices: args.allAvailableDevices,
            excludeDevices: args.excludeDevices,
            targetHost: args.targetHost,
            dataDevices: args.dataDevices,
          }, context.logger);
          const handle = await persistVerdict(context, deps, {
            method: "cephVerifyOsdClaimable",
            host: args.host,
            phase: "osd-claimable",
            key: `cephVerifyOsdClaimable-${args.host}`,
            outcome,
            throwOnFail: args.throwOnFail ?? true,
          });
          return { dataHandles: [handle] };
        } finally {
          await session.close();
        }
      },
    },
    cephHostMaintenanceEnter: {
      kind: "action" as const,
      description:
        "Put one Ceph host into maintenance and prove the effect by polling host status, the host-subtree noout flag, OSD-down counts and that every OSD stayed in. Idempotent; a host already in maintenance issues nothing but is still fully verified.",
      arguments: MaintenanceEnterArgs,
      execute: async (
        args: z.infer<typeof MaintenanceEnterArgs>,
        context: MethodContext,
      ) => {
        const session = await sessionFor(args);
        try {
          const result = await enterMaintenance(deps, session, {
            host: args.host,
            hostName: args.hostName,
            osdCount: args.osdCount,
            pollIntervalMs: args.pollIntervalMs,
            pollTimeoutMs: args.pollTimeoutMs,
          }, context.logger);
          const handle = await context.writeResource(
            "cephMaintenanceResult",
            `cephHostMaintenanceEnter-${args.host}-${args.hostName}`,
            { ...result, capturedAt: new Date(deps.now()).toISOString() },
          );
          return { dataHandles: [handle] };
        } finally {
          await session.close();
        }
      },
    },

    cephHostMaintenanceExit: {
      kind: "action" as const,
      description:
        "Take one Ceph host out of maintenance and prove its OSDs are restored, retrying the exit at most once when check-host says the host looks OK. Idempotent; a host not in maintenance issues nothing but is still verified.",
      arguments: MaintenanceExitArgs,
      execute: async (
        args: z.infer<typeof MaintenanceExitArgs>,
        context: MethodContext,
      ) => {
        const session = await sessionFor(args);
        try {
          const result = await exitMaintenance(deps, session, {
            host: args.host,
            hostName: args.hostName,
            pollIntervalMs: args.pollIntervalMs,
            pollTimeoutMs: args.pollTimeoutMs,
          }, context.logger);
          const handle = await context.writeResource(
            "cephMaintenanceResult",
            `cephHostMaintenanceExit-${args.host}-${args.hostName}`,
            { ...result, capturedAt: new Date(deps.now()).toISOString() },
          );
          return { dataHandles: [handle] };
        } finally {
          await session.close();
        }
      },
    },

    cephHostMaintenanceState: {
      description:
        "READ-ONLY. Report which hosts are already out, by maintenance status or by the host-subtree noout flag, in one call. A host is out when either is true, so a partly failed window is still found.",
      arguments: MaintenanceStateArgs,
      execute: async (
        args: z.infer<typeof MaintenanceStateArgs>,
        context: MethodContext,
      ) => {
        const session = await sessionFor(args);
        try {
          const result = await maintenanceState(
            deps,
            session,
            args.host,
            context.logger,
          );
          const handle = await context.writeResource(
            "cephHostMaintenanceStateResult",
            `cephHostMaintenanceState-${args.host}`,
            { ...result, capturedAt: new Date(deps.now()).toISOString() },
          );
          return { dataHandles: [handle] };
        } finally {
          await session.close();
        }
      },
    },

    cephOsdOkToStop: {
      description:
        "READ-ONLY. Ask the orchestrator whether one host can be stopped safely, reporting the verdict, the cluster's verbatim reason on refusal, and the daemons it names. A refusal is a recorded result, never an error.",
      arguments: HostNameArgs,
      execute: async (
        args: z.infer<typeof HostNameArgs>,
        context: MethodContext,
      ) => {
        const session = await sessionFor(args);
        try {
          const result = await okToStop(
            deps,
            session,
            args.host,
            args.hostName,
            context.logger,
          );
          const handle = await context.writeResource(
            "cephOkToStopResult",
            `cephOsdOkToStop-${args.host}-${args.hostName}`,
            { ...result, capturedAt: new Date(deps.now()).toISOString() },
          );
          return { dataHandles: [handle] };
        } finally {
          await session.close();
        }
      },
    },

    cephCephadmCheckHost: {
      description:
        "READ-ONLY. Run ceph cephadm check-host for one host and classify the result as ok only on the tool's healthy result. A reported problem is a recorded result, not a thrown error.",
      arguments: HostNameArgs,
      execute: async (
        args: z.infer<typeof HostNameArgs>,
        context: MethodContext,
      ) => {
        const session = await sessionFor(args);
        try {
          const result = await checkHost(
            deps,
            session,
            args.hostName,
            context.logger,
          );
          const handle = await context.writeResource(
            "cephCheckHostResult",
            `cephCephadmCheckHost-${args.host}-${args.hostName}`,
            {
              method: "cephCephadmCheckHost",
              host: args.host,
              hostName: args.hostName,
              ...result,
              capturedAt: new Date(deps.now()).toISOString(),
            },
          );
          return { dataHandles: [handle] };
        } finally {
          await session.close();
        }
      },
    },

    cephHostNooutClear: {
      kind: "action" as const,
      description:
        "Clear an orphaned host-subtree noout flag for one host, or do nothing if it is already clear. Refuses an unknown host, a host in maintenance, or a host with any down OSD; there is no override.",
      arguments: MaintenanceExitArgs,
      execute: async (
        args: z.infer<typeof MaintenanceExitArgs>,
        context: MethodContext,
      ) => {
        const session = await sessionFor(args);
        try {
          const result = await nooutClear(deps, session, {
            host: args.host,
            hostName: args.hostName,
            pollIntervalMs: args.pollIntervalMs,
            pollTimeoutMs: args.pollTimeoutMs,
          }, context.logger);
          const handle = await context.writeResource(
            "cephNooutClearResult",
            `cephHostNooutClear-${args.host}-${args.hostName}`,
            { ...result, capturedAt: new Date(deps.now()).toISOString() },
          );
          return { dataHandles: [handle] };
        } finally {
          await session.close();
        }
      },
    },

    cephOsdActivate: {
      kind: "action" as const,
      description:
        "Re-create OSD daemons for existing OSD volumes on one host and parse the result; created and already-created are both success. Idempotent.",
      arguments: HostNameArgs,
      execute: async (
        args: z.infer<typeof HostNameArgs>,
        context: MethodContext,
      ) => {
        const session = await sessionFor(args);
        try {
          const result = await osdActivate(
            deps,
            session,
            args.host,
            args.hostName,
            context.logger,
          );
          const handle = await context.writeResource(
            "cephOsdActivateResult",
            `cephOsdActivate-${args.host}-${args.hostName}`,
            { ...result, capturedAt: new Date(deps.now()).toISOString() },
          );
          return { dataHandles: [handle] };
        } finally {
          await session.close();
        }
      },
    },

    cephHostClusterState: {
      description:
        "READ-ONLY. Report what Ceph state one host carries on its OS disk: fsid directories, cluster units, Ceph volume groups and logical volumes, md arrays and which tools were seen.",
      arguments: MaintenanceStateArgs,
      execute: async (
        args: z.infer<typeof MaintenanceStateArgs>,
        context: MethodContext,
      ) => {
        const session = await sessionFor(args);
        try {
          const state = await observeHost(deps, session, args.host);
          context.logger.info(
            "Host {host} carries {fsids} fsid(s), {units} cluster unit(s), {vgs} VG(s)",
            {
              host: args.host,
              fsids: state.fsids.length,
              units: state.clusterUnits.length,
              vgs: state.cephVolumeGroups.length,
            },
          );
          const handle = await context.writeResource(
            "cephHostClusterStateResult",
            `cephHostClusterState-${args.host}`,
            { ...state, capturedAt: new Date(deps.now()).toISOString() },
          );
          return { dataHandles: [handle] };
        } finally {
          await session.close();
        }
      },
    },
    cephVerifyClusterFsid: {
      description:
        "READ-ONLY. Refuse unless every fsid on the host is the named one, so a refusal leaves the cluster as it found it. Writes a pass record only when the host carries no foreign fsid.",
      arguments: VerifyClusterFsidArgs,
      execute: async (
        args: z.infer<typeof VerifyClusterFsidArgs>,
        context: MethodContext,
      ) => {
        const session = await sessionFor(args);
        try {
          const result = await verifyClusterFsid(
            deps,
            session,
            args.host,
            args.fsid,
            context.logger,
          );
          const handle = await context.writeResource(
            "cephClusterFsidResult",
            `cephVerifyClusterFsid-${args.host}`,
            { ...result, capturedAt: new Date(deps.now()).toISOString() },
          );
          return { dataHandles: [handle] };
        } finally {
          await session.close();
        }
      },
    },

    cephDisableOrchestration: {
      kind: "action" as const,
      description:
        "Disable the cephadm mgr module so the orchestrator stops deploying daemons, and prove it. An unreachable cluster is a recorded outcome, never a thrown error.",
      arguments: DisableOrchArgs,
      execute: async (
        args: z.infer<typeof DisableOrchArgs>,
        context: MethodContext,
      ) => {
        const session = await sessionFor({ ...args, host: args.adminHost });
        try {
          const result = await disableOrchestration(
            deps,
            args.adminHost,
            session,
            context.logger,
          );
          const handle = await context.writeResource(
            "cephOrchestrationDisableResult",
            `cephDisableOrchestration-${args.adminHost}`,
            { ...result, capturedAt: new Date(deps.now()).toISOString() },
          );
          return { dataHandles: [handle] };
        } finally {
          await session.close();
        }
      },
    },

    cephRmCluster: {
      kind: "action" as const,
      description:
        "DESTRUCTIVE. Purge a named cluster from one host, after refusing any foreign fsid, and prove that cephadm's state is gone. Re-runnable after a partial failure; LVM residue is recorded, not fatal here.",
      arguments: RmClusterArgs,
      execute: async (
        args: z.infer<typeof RmClusterArgs>,
        context: MethodContext,
      ) => {
        const session = await sessionFor(args);
        try {
          const result = await rmCluster(deps, session, {
            host: args.host,
            fsid: args.fsid,
            zapOsds: args.zapOsds,
            verifyTimeoutMs: args.verifyTimeoutMs,
            verifyPollIntervalMs: args.verifyPollIntervalMs,
          }, context.logger);
          const handle = await context.writeResource(
            "cephRmClusterResult",
            `cephRmCluster-${args.host}`,
            result,
          );
          return { dataHandles: [handle] };
        } finally {
          await session.close();
        }
      },
    },

    cephVerifyHostTornDown: {
      description:
        "READ-ONLY. Verify that the OS-disk plane of one host carries no Ceph cluster state. A dirty host is recorded with pass false and its findings; unobserved tools throw and write nothing.",
      arguments: VerifyHostTornDownArgs,
      execute: async (
        args: z.infer<typeof VerifyHostTornDownArgs>,
        context: MethodContext,
      ) => {
        const session = await sessionFor(args);
        try {
          const result = await hostTornDown(
            deps,
            session,
            args.host,
            args.fsid,
          );
          const handle = await context.writeResource(
            "cephHostTornDownResult",
            `cephVerifyHostTornDown-${args.host}`,
            { ...result, capturedAt: new Date(deps.now()).toISOString() },
          );
          return { dataHandles: [handle] };
        } finally {
          await session.close();
        }
      },
    },
    cephRgwBucketInventory: {
      description:
        "READ-ONLY. List every RGW bucket with owner, object count, logical and on-disk size and placement rule, plus cluster totals. Paged until exhausted; an unparseable answer is never an empty inventory.",
      arguments: BucketInventoryArgs,
      execute: async (
        args: z.infer<typeof BucketInventoryArgs>,
        context: MethodContext,
      ) => {
        const session = await sessionFor(args);
        const realm = args.rgwRealm ?? "";
        try {
          const record = await bucketInventory(
            deps,
            session,
            args.host,
            realm,
            context.logger,
          );
          const handle = await context.writeResource(
            "cephRgwBucketInventoryResult",
            realm === ""
              ? `rgwBucketInventory-${args.host}`
              : `rgwBucketInventory-${args.host}-${realm}`,
            { ...record, capturedAt: new Date(deps.now()).toISOString() },
          );
          return { dataHandles: [handle] };
        } finally {
          await session.close();
        }
      },
    },
    cephRgwUserEnsure: {
      kind: "action" as const,
      description:
        "Ensure an RGW user exists with the requested display name and email. Key material is always generated by RGW (--gen-access-key --gen-secret) and returned only in a sensitive, vaulted field; no caller-supplied secret ever reaches a command line. Idempotent; keys are not regenerated unless rotateKeys is set.",
      arguments: RgwUserArgs,
      execute: async (
        args: z.infer<typeof RgwUserArgs>,
        context: MethodContext,
      ) => {
        const session = await sessionFor(args);
        try {
          const result = await ensureRgwUser(deps, session, {
            host: args.host,
            uid: args.uid,
            displayName: args.displayName,
            email: args.email,
            rotateKeys: args.rotateKeys,
          }, context.logger);
          const handle = await context.writeResource(
            "cephRgwUserResult",
            `rgwUser-${args.uid}`,
            { ...result, capturedAt: new Date(deps.now()).toISOString() },
          );
          return { dataHandles: [handle] };
        } finally {
          await session.close();
        }
      },
    },
    cephRgwBucketInspect: {
      description:
        "READ-ONLY. Classify one bucket's presence and, when owned, read its ACL, policy, versioning and Public Access Block. Records the unowned classes without throwing; an unreadable presence throws and writes no record.",
      arguments: BucketInspectArgs,
      execute: async (
        args: z.infer<typeof BucketInspectArgs>,
        context: MethodContext,
      ) => {
        const record = await bucketInspect(deps, args);
        const handle = await context.writeResource(
          "cephRgwBucketInspectResult",
          `rgwBucketInspect-${args.region}-${args.bucket}`,
          { ...record, capturedAt: new Date(deps.now()).toISOString() },
        );
        return { dataHandles: [handle] };
      },
    },
    cephRgwBucketEnsure: {
      kind: "action" as const,
      description:
        "DESTRUCTIVE. Ensure the bucket exists, is owned, private and fully Public-Access-Blocked, and prove anonymous listing is refused; an existing ACL is reset to private, dropping any other grants. Iff the probe runs it also proves public object ACLs cannot leak through the fixed probe prefix, and a leaking or unprovable bucket throws and writes no record.",
      arguments: BucketEnsureArgs,
      execute: async (
        args: z.infer<typeof BucketEnsureArgs>,
        context: MethodContext,
      ) => {
        const record = await bucketEnsure(deps, args, context.logger);
        const handle = await context.writeResource(
          "cephRgwBucketResult",
          `rgwBucket-${args.region}-${args.bucket}`,
          { ...record, capturedAt: new Date(deps.now()).toISOString() },
        );
        return { dataHandles: [handle] };
      },
    },
    cephRgwBucketPolicyEnsure: {
      kind: "action" as const,
      description:
        "DESTRUCTIVE. Replace the bucket's policy with the caller's document, after refusing a public or self-locking policy before any request, and prove it with a canonical read-back and an anonymous-list probe. Rolls back on failure, lifting and restoring BlockPublicPolicy when needed, and writes no record on any failure.",
      arguments: BucketPolicyArgs,
      execute: async (
        args: z.infer<typeof BucketPolicyArgs>,
        context: MethodContext,
      ) => {
        const record = await bucketPolicyEnsure(deps, args, context.logger);
        const handle = await context.writeResource(
          "cephRgwBucketPolicyResult",
          `rgwBucketPolicy-${args.region}-${args.bucket}`,
          { ...record, capturedAt: new Date(deps.now()).toISOString() },
        );
        return { dataHandles: [handle] };
      },
    },
    cephRgwBucketVersioningEnsure: {
      kind: "action" as const,
      description:
        "Converge a bucket's versioning to Enabled or Suspended and re-read it. When the result is Enabled it flags conditional writes as unsafe and warns that an If-None-Match lock no longer excludes anything.",
      arguments: BucketVersioningArgs,
      execute: async (
        args: z.infer<typeof BucketVersioningArgs>,
        context: MethodContext,
      ) => {
        const record = await bucketVersioningEnsure(
          deps,
          args,
          context.logger,
        );
        const handle = await context.writeResource(
          "cephRgwBucketVersioningResult",
          `rgwBucketVersioning-${args.region}-${args.bucket}`,
          { ...record, capturedAt: new Date(deps.now()).toISOString() },
        );
        return { dataHandles: [handle] };
      },
    },
  };

  // The S3 plane opens no SSH session, so those methods are not in the
  // `ssh-installed` pre-flight check's applies-to list.
  const sshMethods = Object.keys(methods).filter((m) => !S3_METHODS.has(m));

  return {
    type: "@randybias/cephadm",
    // The consistency gate requires this literal; VERSION mirrors it.
    version: "2026.10.17.1",
    description:
      "Install and operate a standalone Ceph cluster managed by cephadm on Debian-family hosts reached over SSH. One model type serves any number of hosts and clusters; every method takes its own target.",
    upgrades: [
      {
        toVersion: VERSION,
        description: "First published version; no schema changes",
        upgradeAttributes: (old: Record<string, unknown>) => old,
      },
    ],
    globalArguments: GlobalArgsSchema,
    resources: {
      cephVerifyResult: {
        description:
          "A shared verify-result record: method, host, pass, expected, actual, detail and optional subject",
        schema: VerifyResultSchema,
        lifetime: "infinite" as const,
        garbageCollection: 10,
      },
      hostPrepResult: {
        description:
          "Host preparation evidence: packages, cephadm version and time sync",
        schema: HostPrepResultSchema,
        lifetime: "infinite" as const,
        garbageCollection: 10,
      },
      wipeDiskResult: {
        description: "Disk wipe evidence and, on a dry run, its plan",
        schema: WipeDiskResultSchema,
        lifetime: "infinite" as const,
        garbageCollection: 10,
      },
      cephBootstrapResult: {
        description:
          "Bootstrap evidence: fsid, public key and admin keyring reference",
        schema: BootstrapResultSchema,
        lifetime: "infinite" as const,
        garbageCollection: 10,
      },
      cephDistributeKeyResult: {
        description: "Per-host admin-key distribution evidence",
        schema: DistributeKeyResultSchema,
        lifetime: "infinite" as const,
        garbageCollection: 10,
      },
      cephHostAddResult: {
        description: "Host enrolment evidence",
        schema: HostAddResultSchema,
        lifetime: "infinite" as const,
        garbageCollection: 10,
      },
      cephApplyMonResult: {
        description: "Mon placement convergence and quorum-safety evidence",
        schema: ApplyMonResultSchema,
        lifetime: "infinite" as const,
        garbageCollection: 10,
      },
      cephApplyMgrResult: {
        description: "Mgr placement convergence evidence",
        schema: ApplyMgrResultSchema,
        lifetime: "infinite" as const,
        garbageCollection: 10,
      },
      cephApplyMdsResult: {
        description: "MDS placement convergence evidence",
        schema: ApplyMdsResultSchema,
        lifetime: "infinite" as const,
        garbageCollection: 10,
      },
      cephApplyOsdResult: {
        description: "OSD service application evidence",
        schema: ApplyOsdResultSchema,
        lifetime: "infinite" as const,
        garbageCollection: 10,
      },
      cephMaintenanceResult: {
        description: "Maintenance enter or exit evidence",
        schema: MaintenanceResultSchema,
        lifetime: "infinite" as const,
        garbageCollection: 10,
      },
      cephHostMaintenanceStateResult: {
        description:
          "Which hosts are out by maintenance status or subtree noout",
        schema: MaintenanceStateResultSchema,
        lifetime: "infinite" as const,
        garbageCollection: 10,
      },
      cephOkToStopResult: {
        description: "Orchestrator ok-to-stop verdict",
        schema: OkToStopResultSchema,
        lifetime: "infinite" as const,
        garbageCollection: 10,
      },
      cephCheckHostResult: {
        description: "cephadm check-host classification",
        schema: CheckHostResultSchema,
        lifetime: "infinite" as const,
        garbageCollection: 10,
      },
      cephNooutClearResult: {
        description: "Subtree noout clear evidence",
        schema: NooutClearResultSchema,
        lifetime: "infinite" as const,
        garbageCollection: 10,
      },
      cephOsdActivateResult: {
        description: "OSD activation evidence",
        schema: OsdActivateResultSchema,
        lifetime: "infinite" as const,
        garbageCollection: 10,
      },
      cephHostClusterStateResult: {
        description: "Ceph state carried on a host's OS disk",
        schema: HostStateResultSchema,
        lifetime: "infinite" as const,
        garbageCollection: 10,
      },
      cephClusterFsidResult: {
        description: "Per-host fsid gate evidence",
        schema: ClusterFsidResultSchema,
        lifetime: "infinite" as const,
        garbageCollection: 10,
      },
      cephOrchestrationDisableResult: {
        description: "Orchestration disable outcome",
        schema: OrchestrationDisableResultSchema,
        lifetime: "infinite" as const,
        garbageCollection: 10,
      },
      cephRmClusterResult: {
        description: "Cluster purge evidence",
        schema: RmClusterResultSchema,
        lifetime: "infinite" as const,
        garbageCollection: 10,
      },
      cephHostTornDownResult: {
        description: "OS-disk teardown verdict",
        schema: HostTornDownResultSchema,
        lifetime: "infinite" as const,
        garbageCollection: 10,
      },
      cephRgwBucketInventoryResult: {
        description: "RGW bucket inventory with placement and totals",
        schema: BucketInventoryResultSchema,
        lifetime: "infinite" as const,
        garbageCollection: 10,
      },
      cephRgwUserResult: {
        description: "RGW user convergence with a generated, sensitive key",
        schema: RgwUserResultSchema,
        lifetime: "infinite" as const,
        garbageCollection: 10,
      },
      cephRgwBucketInspectResult: {
        description:
          "One bucket's presence, ACL, policy, versioning and Public Access Block as seen by the owner's credentials",
        schema: BucketInspectResultSchema,
        lifetime: "infinite" as const,
        garbageCollection: 10,
      },
      cephRgwBucketResult: {
        description:
          "RGW bucket convergence: ownership, private ACL, full Public Access Block and live leak-probe evidence",
        schema: BucketEnsureResultSchema,
        lifetime: "infinite" as const,
        garbageCollection: 10,
      },
      cephRgwBucketPolicyResult: {
        description:
          "RGW bucket policy convergence: canonical form, anonymous probe and plain-HTTP probe evidence",
        schema: BucketPolicyResultSchema,
        lifetime: "infinite" as const,
        garbageCollection: 10,
      },
      cephRgwBucketVersioningResult: {
        description: "RGW bucket versioning state before and after convergence",
        schema: BucketVersioningResultSchema,
        lifetime: "infinite" as const,
        garbageCollection: 10,
      },
      cephCapacityReport: {
        description: "Cluster and per-pool capacity with the durability margin",
        schema: CapacityReportSchema,
        lifetime: "7d" as const,
        garbageCollection: 10,
      },
      poolResult: {
        description: "Pool creation and convergence evidence",
        schema: PoolResultSchema,
        lifetime: "infinite" as const,
        garbageCollection: 10,
      },
      fsResult: {
        description: "CephFS volume creation evidence",
        schema: FsResultSchema,
        lifetime: "infinite" as const,
        garbageCollection: 10,
      },
      csiUserResult: {
        description: "CSI client entity caps as read back",
        schema: CsiUserResultSchema,
        lifetime: "infinite" as const,
        garbageCollection: 10,
      },
      connBundleResult: {
        description: "Non-secret connection facts",
        schema: ConnBundleResultSchema,
        lifetime: "infinite" as const,
        garbageCollection: 10,
      },
      csiKey: {
        description:
          "One client entity's key, stored via a sensitive field in the vault",
        schema: CsiKeySchema,
        lifetime: "infinite" as const,
        garbageCollection: 2,
      },
      fsDeleteResult: {
        description: "CephFS deletion evidence",
        schema: FsDeleteResultSchema,
        lifetime: "infinite" as const,
        garbageCollection: 10,
      },
      osdRemoveResult: {
        description: "OSD removal evidence",
        schema: OsdRemoveResultSchema,
        lifetime: "infinite" as const,
        garbageCollection: 10,
      },
    },
    checks: {
      "ssh-installed": {
        description: "The ssh binary can be spawned",
        labels: ["live"],
        appliesTo: sshMethods,
        execute: async () => {
          try {
            const child = deps.spawn("ssh", ["-V"]);
            const writer = child.stdin.getWriter();
            await writer.close();
            await child.output();
            return { pass: true };
          } catch {
            return {
              pass: false,
              errors: ["the ssh binary could not be spawned"],
            };
          }
        },
      },
    },
    methods,
  };
}

/** Production model export. */
export const model = {
  ...createCephadmModel(),
  type: "@randybias/cephadm",
  version: "2026.10.17.1",
} satisfies ReturnType<typeof createCephadmModel>;

/** Outcome of the package-source check. */
interface PackageSourceResult {
  /** Whether every endpoint was reached and sources were found. */
  pass: boolean;
  /** Endpoints expected to answer, each with outcome `reached`. */
  expected: { name: string; scheme: string; origin: string; outcome: string }[];
  /** Endpoints actually observed, or null when nothing was observed. */
  actual: { name: string; scheme: string; outcome: string }[] | null;
  /** Structured detail. */
  detail: {
    endpoints: EndpointOutcome[];
    findings: string[];
    aptProxyConfig: string[];
    noSourcesFound: boolean;
  };
  /** Human findings, one per non-reached endpoint. */
  findings: string[];
}

/** Runs the two-script package-source check and returns the record fields. */
async function checkPackageSources(
  session: SshSession,
  cephadmUrl: string,
  log: Logger,
): Promise<PackageSourceResult> {
  const discovery = await session.run({
    command: "bash -s --",
    stdin: discoveryScript(),
    allowNonZero: true,
  });
  if (discovery.code !== 0) {
    throw new PhaseError("pkgsource.discover", "the discovery script failed", {
      code: discovery.code,
    });
  }
  const sections = splitSections(discovery.stdout);
  const aptEndpoints: Endpoint[] = [];
  for (const e of parseAptSources(sections.sources)) aptEndpoints.push(e);
  const ceph = cephadmUrlHost(cephadmUrl);
  const endpoints: Endpoint[] = [...aptEndpoints];
  if (
    !endpoints.some((e) => e.name === ceph.name && e.scheme === ceph.scheme)
  ) {
    endpoints.push(ceph);
  }
  const noSourcesFound = aptEndpoints.length === 0;
  const proxyLines = sections.proxy.split("\n").map((l) => l.trim()).filter((
    l,
  ) => l !== "").map(sanitizeProxyLine);
  if (proxyLines.length > 0) {
    log.warn("apt is configured with a proxy, so the probed route may differ");
  }

  const probe = await session.run({
    command: "bash -s --",
    stdin: probeScript(endpoints),
    allowNonZero: true,
  });
  if (probe.code !== 0) {
    throw new PhaseError("pkgsource.probe", "the probe script failed", {
      code: probe.code,
    });
  }

  const parsed = probe.stdout.split("\n")
    .map((l) => parseProbeLine(l.trim()))
    .filter((p): p is NonNullable<ReturnType<typeof parseProbeLine>> =>
      p !== null
    );
  const observed: EndpointOutcome[] = [];
  const findings: string[] = [];
  for (const e of endpoints) {
    const line = parsed.find((p) => p.name === e.name && p.scheme === e.scheme);
    if (!line) {
      findings.push(
        `${e.name} (${e.scheme}): NOT PROBED: nothing is known about it`,
      );
      continue;
    }
    const outcome = classifyProbe(line, e.origin);
    observed.push(outcome);
    if (outcome.outcome !== "reached") findings.push(findingFor(outcome));
  }
  if (noSourcesFound) {
    findings.push(
      "the host has no usable apt sources, so it cannot install packages",
    );
  }
  return {
    pass: findings.length === 0,
    expected: endpoints.map((e) => ({
      name: e.name,
      scheme: e.scheme,
      origin: e.origin,
      outcome: "reached",
    })),
    actual: observed.length > 0
      ? observed.map((o) => ({
        name: o.name,
        scheme: o.scheme,
        outcome: o.outcome,
      }))
      : null,
    detail: {
      endpoints: observed,
      findings,
      aptProxyConfig: proxyLines,
      noSourcesFound,
    },
    findings,
  };
}
