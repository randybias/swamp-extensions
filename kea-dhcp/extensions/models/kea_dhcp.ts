/**
 * Swamp extension model for an ISC Kea DHCPv4 server on one Linux host.
 *
 * The definition holds no host, network or MAC: every method takes its target
 * and DHCP inputs as arguments. A candidate configuration is rendered
 * deterministically, validated by Kea itself, written atomically and pushed to
 * the running server with `config-set` — never `config-reload` or a restart.
 * Because a bad DHCP change can strand every host that renews on the network it
 * serves, every apply or remove arms a host-side revert timer that restores the
 * previous configuration unless `commit` cancels it.
 *
 * The transport, schemas, host scripts and the mutating orchestration live in
 * `_lib/`; this module is the model definition, the read-only methods and the
 * public re-exports.
 *
 * @module
 */

import { z } from "npm:zod@4.3.6";
import { deps, type MethodContext, type MethodOutcome } from "./_lib/deps.ts";
import {
  ActionStateSchema,
  applyArgsSchema,
  type ConfigArgs,
  configArgsSchema,
  configName,
  type ConfigState,
  ConfigStateSchema,
  instanceKey,
  type LeaseArgs,
  leaseArgsSchema,
  leasesName,
  type LeaseState,
  LeaseStateSchema,
  type Observation,
  observationName,
  ObservationSchema,
  pendingName,
  type PendingState,
  PendingStateSchema,
  probeArgsSchema,
  renderName,
  type RenderState,
  RenderStateSchema,
  revertName,
  type RevertState,
  RevertStateSchema,
  type SshArgs,
  strictTargetArgsSchema,
  targetArgsSchema,
} from "./_lib/schemas.ts";
import {
  discardPending,
  runApply,
  runCommit,
  runRemove,
} from "./_lib/apply.ts";
import { runInstall } from "./_lib/install.ts";
import { probe } from "./_lib/probe.ts";
import {
  keaControl,
  readFiredMarkers,
  readRemoteText,
  renderAndHash,
  toTarget,
} from "./_lib/transport.ts";
import {
  APPLY_PLAN,
  type ApplyStep,
  DEFAULT_CONTROL_SOCKET,
  DEFAULT_LEASE_FILE,
} from "./_lib/render.ts";
import {
  filterLeases,
  type Lease,
  type LeaseFilter,
  parseLeaseCsvFiles,
  parseLeaseJson,
} from "./_lib/lease.ts";

/** `render`: the pure, host-free config render, persisted for visibility. */
async function runRender(
  rawArgs: unknown,
  context: MethodContext,
): Promise<MethodOutcome> {
  const args = rawArgs as ConfigArgs;
  const rendered = await renderAndHash(args);
  const plan = [...APPLY_PLAN] as ApplyStep[];
  const state: RenderState = {
    sha256: rendered.sha256,
    warnings: rendered.warnings,
    plan,
    config: rendered.config,
  };
  const handle = await context.writeResource(
    "render",
    renderName(rendered.sha256),
    RenderStateSchema.parse(state),
  );
  return {
    dataHandles: [handle],
    result: {
      config: rendered.config,
      sha256: rendered.sha256,
      warnings: rendered.warnings,
      plan,
    },
  };
}

/** `get`: probe the live server and persist the observation. */
async function runGet(
  rawArgs: unknown,
  context: MethodContext,
): Promise<MethodOutcome> {
  const args = rawArgs as SshArgs;
  const target = await toTarget(context, args);
  const observation = await probe(target, args, DEFAULT_CONTROL_SOCKET);
  const handle = await context.writeResource(
    "observation",
    observationName(instanceKey(args)),
    observation,
  );
  return { dataHandles: [handle], result: observation };
}

/** The drift lines between the committed record and a live observation. */
function driftOf(
  stored: ConfigState | null,
  observation: Observation,
): string[] {
  const drift: string[] = [];
  if (
    stored?.config_sha256 && observation.file_sha256 &&
    stored.config_sha256 !== observation.file_sha256
  ) {
    drift.push("file sha differs from the committed config");
  }
  if (
    stored?.kea_hash && observation.kea_hash &&
    stored.kea_hash !== observation.kea_hash
  ) {
    drift.push("running hash differs from the committed config");
  }
  return drift;
}

/** `sync`: re-probe, adopt any fired revert and report drift. */
async function runSync(
  rawArgs: unknown,
  context: MethodContext,
): Promise<MethodOutcome> {
  const args = rawArgs as SshArgs;
  const target = await toTarget(context, args);
  const key = instanceKey(args);
  const observation = await probe(target, args, DEFAULT_CONTROL_SOCKET);
  const committed = await context.readResource(configName(key)) as
    | ConfigState
    | null;
  const pending = await context.readResource(pendingName(key)) as
    | PendingState
    | null;
  // An in-flight apply is expected to differ; only a settled state can drift.
  const drift = pending !== null && pending.status === "pending"
    ? []
    : driftOf(committed, observation);
  for (const marker of await readFiredMarkers(target)) {
    const record = await context.readResource(
      revertName(key, marker.token),
    ) as RevertState | null;
    if (record && !record.fired_at) {
      await context.writeResource(
        "revert",
        revertName(key, marker.token),
        RevertStateSchema.parse({ ...record, fired_at: marker.firedAt }),
      );
    }
    // A fired revert discards the pending apply; it is not reported as drift.
    await discardPending(context, key);
  }
  const finalObservation = ObservationSchema.parse({ ...observation, drift });
  const handle = await context.writeResource(
    "observation",
    observationName(key),
    finalObservation,
  );
  return { dataHandles: [handle], result: finalObservation };
}

/** `leases`: query leases read-only and persist them. */
async function runLeases(
  rawArgs: unknown,
  context: MethodContext,
): Promise<MethodOutcome> {
  const args = rawArgs as LeaseArgs;
  const target = await toTarget(context, args);
  const filter: LeaseFilter = {
    subnet_id: args.subnet_id ?? undefined,
    ip_address: args.ip_address ?? undefined,
    hw_address: args.hw_address ?? undefined,
  };
  let source: LeaseState["source"] = "memfile";
  let leases: Lease[] = [];
  if (args.lease_api) {
    const answer = await keaControl(target, {
      command: "lease4-get-all",
      service: ["dhcp4"],
    }, DEFAULT_CONTROL_SOCKET);
    leases = parseLeaseJson(answer);
    source = "lease_cmds";
  } else {
    const now = Math.floor(deps.now() / 1000);
    const main = await readRemoteText(target, DEFAULT_LEASE_FILE) ?? "";
    const cleanup = await readRemoteText(target, `${DEFAULT_LEASE_FILE}.2`) ??
      "";
    leases = parseLeaseCsvFiles([main, cleanup], now);
  }
  leases = filterLeases(leases, filter);
  const state: LeaseState = {
    host: args.host,
    source,
    count: leases.length,
    leases,
    observed_at: new Date(deps.now()).toISOString(),
  };
  const handle = await context.writeResource(
    "leases",
    leasesName(instanceKey(args)),
    LeaseStateSchema.parse(state),
  );
  return { dataHandles: [handle], result: state };
}

/**
 * Swamp model definition for `@randybias/kea-dhcp`.
 *
 * The production export is a plain object literal, as the registry requires.
 */
export const model = {
  type: "@randybias/kea-dhcp",
  version: "2026.10.17.1",
  globalArguments: z.strictObject({}),
  resources: {
    config: {
      description: "Rendered config sha256, Kea's own hash and timestamps",
      schema: ConfigStateSchema,
      lifetime: "infinite" as const,
      garbageCollection: 10,
    },
    pending: {
      description: "The uncommitted apply: sha, Kea hash and status",
      schema: PendingStateSchema,
      lifetime: "infinite" as const,
      garbageCollection: 10,
    },
    revert: {
      description: "One armed revert: token, window and armed hash",
      schema: RevertStateSchema,
      lifetime: "infinite" as const,
      garbageCollection: 10,
    },
    observation: {
      description: "Last get/sync probe of the server",
      schema: ObservationSchema,
      lifetime: "infinite" as const,
      garbageCollection: 10,
    },
    leases: {
      description: "Last read-only lease query",
      schema: LeaseStateSchema,
      lifetime: "7d" as const,
      garbageCollection: 5,
    },
    render: {
      description: "Last rendered config, sha256, warnings and plan",
      schema: RenderStateSchema,
      lifetime: "infinite" as const,
      garbageCollection: 10,
    },
    action: {
      description: "Last outcome of each action method",
      schema: ActionStateSchema,
      lifetime: "infinite" as const,
      garbageCollection: 10,
    },
  },
  methods: {
    install: {
      kind: "action" as const,
      description:
        "DESTRUCTIVE. Install kea-dhcp4-server and socat (package state), capture the package's original config once, and leave the service disabled until the first apply. Idempotent.",
      arguments: targetArgsSchema,
      execute: runInstall,
    },

    render: {
      description:
        "READ-ONLY. Render the kea-dhcp4.conf JSON for these inputs, its sha256 and the ordered apply plan. Deterministic; touches no host.",
      arguments: configArgsSchema,
      execute: runRender,
    },

    apply: {
      kind: "action" as const,
      description:
        "DESTRUCTIVE. Network service change: validate, snapshot, arm the host-side revert, write the config file and config-set the same JSON, then verify. Idempotent: an identical live config arms nothing. Not permanent until commit.",
      arguments: applyArgsSchema,
      execute: runApply,
    },

    commit: {
      kind: "action" as const,
      description:
        "DESTRUCTIVE. Cancels the armed revert: gate on a passing verify, then take the revert lock, stop the host timer and clear the marker. Refuses when the revert already fired or its service started, the timer cannot be stopped, the revert record is missing, the live config drifted, or any verify check fails.",
      arguments: strictTargetArgsSchema,
      execute: runCommit,
    },

    get: {
      description:
        "READ-ONLY. Probe the recorded config and revert state plus the live server, then persist the observation.",
      arguments: probeArgsSchema,
      execute: runGet,
    },

    sync: {
      description:
        "READ-ONLY. Re-probe, adopt any fired revert into its record and report drift (file sha differs from the committed one). Never rewrites.",
      arguments: probeArgsSchema,
      execute: runSync,
    },

    leases: {
      description:
        "READ-ONLY. Query current DHCPv4 leases, optionally filtered by subnet, address or MAC, and persist them. Never writes a lease.",
      arguments: leaseArgsSchema,
      execute: runLeases,
    },

    remove: {
      kind: "action" as const,
      description:
        "DESTRUCTIVE. Stop and disable the server and converge it back to the package's original config under the armed-revert protocol; call commit to make the removal permanent. Idempotent.",
      arguments: strictTargetArgsSchema,
      execute: runRemove,
    },
  },
};

export { setDeps } from "./_lib/deps.ts";
export type { KeaDeps, MethodContext } from "./_lib/deps.ts";
export {
  claimScript,
  commitScript,
  groupScript,
  hookLibraryScript,
  installFileScript,
  managementScript,
  restoreScript,
} from "./_lib/host_scripts.ts";
export { configSetRequest, renderAndHash } from "./_lib/transport.ts";
export { toRenderInput } from "./_lib/schemas.ts";
export {
  applyArgsSchema,
  configArgsSchema,
  leaseArgsSchema,
  probeArgsSchema,
  strictTargetArgsSchema,
  targetArgsSchema,
};
