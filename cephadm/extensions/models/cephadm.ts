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
import { TransportError } from "./_lib/errors.ts";
import { wipeDiskToRaw, type WipeRecord } from "./_lib/wipe.ts";

/** Model type version; must equal the manifest version. */
export const VERSION = "2026.10.17.1";

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
}

const productionDeps: CephadmDeps = {
  spawn: denoSpawner,
  now: () => Date.now(),
  sleep: (ms) => new Promise((resolve) => setTimeout(resolve, ms)),
  random: Math.random,
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
  pass: z.boolean(),
  expected: z.unknown(),
  actual: z.unknown(),
  detail: z.unknown(),
  subject: z.string().optional(),
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

  const methods = {
    cephHostPrep: {
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
            "verifyResult",
            `cephVerifyPackageSource-${args.host}`,
            {
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
        return { dataHandles: [handle] };
      },
    },

    cephHostAdd: {
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
  };

  const sshMethods = Object.keys(methods);

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
      verifyResult: {
        description:
          "A verify-result record: pass, expected, actual, detail and subject",
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
export const model = createCephadmModel();

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
