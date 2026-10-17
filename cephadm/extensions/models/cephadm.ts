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
  CEPHADM_VERSION_SCHEMA,
  HOST_FIELD,
  HTTP_URL_SCHEMA,
  PACKAGE_SCHEMA,
  SERIAL_SCHEMA,
  SSH_FIELDS,
  UNIT_SCHEMA,
} from "./_lib/schema.ts";
import { wipeDiskToRaw, type WipeRecord } from "./_lib/wipe.ts";

/** Model type version; must equal the manifest version. */
export const VERSION = "2026.10.17.1";

/** HTTP fetch, used only by the S3 methods; injectable. */
export type FetchFn = (input: string, init?: RequestInit) => Promise<Response>;

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
  /** HTTP fetch, used only by the S3 bucket methods. */
  fetch: FetchFn;
}

const productionDeps: CephadmDeps = {
  spawn: denoSpawner,
  now: () => Date.now(),
  sleep: (ms) => new Promise((resolve) => setTimeout(resolve, ms)),
  random: Math.random,
  fetch: (input, init) => fetch(input, init),
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
  /** Reads a previously written resource by instance name. */
  readResource?: (
    name: string,
    version?: number,
  ) => Promise<Record<string, unknown> | null>;
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
  preTeardownFstab: z.string().optional(),
});

const HostPrepArgs = z.strictObject({
  host: HOST_FIELD.describe("Target host."),
  ...SSH_FIELDS,
  packages: z.array(PACKAGE_SCHEMA).min(1).describe(
    "Debian packages to ensure installed; the caller decides the list.",
  ),
  cephadmUrl: HTTP_URL_SCHEMA.describe("Where to download the cephadm binary."),
  cephadmVersion: CEPHADM_VERSION_SCHEMA.describe(
    "Pinned release; must equal the token parsed from cephadm version.",
  ),
  timeSyncService: UNIT_SCHEMA.describe(
    "systemd unit that provides time sync.",
  ),
  installRetryBudgetMs: z.number().int().min(0).nullish().describe(
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
  ).min(1).describe("Disks to wipe, selected by serial."),
  excludeDevices: z.array(
    z.strictObject({
      serial: SERIAL_SCHEMA.describe("Never-touch serial."),
      reason: z.string().max(256).optional().describe("Why it is excluded."),
    }),
  ).describe("Never-touch list; required even when empty."),
  dryRun: z.boolean().nullish().describe(
    "Run every gate and report the plan; wipe nothing.",
  ),
});

/** The four S3 bucket methods that do not use SSH. */
const S3_METHODS = new Set<string>([]);

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
        const session = await openSession(deps, target, { multiplex: false });
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
  };

  const sshMethods = Object.keys(methods).filter((m) => !S3_METHODS.has(m));

  return {
    type: "@randybias/cephadm",
    version: "2026.10.17.1",
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
  ) => l !== "");
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
