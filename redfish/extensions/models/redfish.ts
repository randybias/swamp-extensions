/**
 * Swamp extension model for a DMTF Redfish ComputerSystem.
 *
 * One definition serves any BMC: the endpoint, the system and the vault-wired
 * credentials are method arguments. Reads and actions go over HTTPS with an
 * explicit TLS policy; credentials travel only in a session token or an
 * `Authorization` header, never in a URL, log or stored state. `power` and
 * `set_boot` are actions; `get` and `sync` are read-only.
 *
 * @module
 */

import { z } from "npm:zod@4.3.6";
import {
  defaultDeps,
  type Deps,
  RedfishError,
  sha256Hex,
  type TlsPolicy,
} from "./_lib/http.ts";
import {
  BOOT_ENABLED,
  BOOT_TARGETS,
  desiredPowerState,
  isPowerNoop,
  isRestartAction,
  isSystemId,
  normalizeEndpoint,
  parseSystem,
  RESET_TYPES,
  type ResetType,
  type SystemState,
  withRedfish,
} from "./_lib/redfish.ts";

const TargetShape = {
  endpoint: z.string().min(8).max(2048).refine(
    (s) => {
      try {
        normalizeEndpoint(s);
        return true;
      } catch {
        return false;
      }
    },
    "invalid BMC endpoint",
  ).describe(
    "BMC endpoint as an https origin, e.g. https://bmc.example.com.",
  ),
  system_id: z.string().max(128).refine(isSystemId, "invalid system id")
    .optional().describe(
      "ComputerSystem id; omit to use the only one the BMC reports.",
    ),
  username: z.string().min(1).max(256).meta({ sensitive: true }).describe(
    "BMC username; wire with a vault.get(...) expression.",
  ),
  password: z.string().min(1).max(1024).meta({ sensitive: true }).describe(
    "BMC password; wire with a vault.get(...) expression.",
  ),
  tls_verify: z.enum(["strict", "insecure_skip_verify"]).describe(
    "TLS policy. strict: verify against the system trust store or ca_pem. insecure_skip_verify: do not verify the certificate. Required; there is no default.",
  ),
  ca_pem: z.string().max(65536).optional().describe(
    "PEM-encoded CA to additionally trust when tls_verify=strict; the system trust store is still used, so this is not an exclusive pin.",
  ),
  auth_mode: z.enum(["session", "basic"]).default("session").describe(
    "session: open and delete a Redfish SessionService session; basic: send Basic auth. Falls back to basic when the BMC has no SessionService.",
  ),
  allow_insecure_basic: z.boolean().default(false).describe(
    "Permit Basic auth (the password on every request) when tls_verify=insecure_skip_verify. Default false; strict TLS always allows Basic.",
  ),
};

const TargetArgs = z.strictObject(TargetShape);

const PowerArgs = z.strictObject({
  ...TargetShape,
  action: z.enum(RESET_TYPES).describe(
    "Reset action; validated against the system's AllowableValues.",
  ),
  timeout_seconds: z.number().int().min(5).max(1800).default(180).describe(
    "Give up waiting for the resulting power state after this many seconds.",
  ),
  poll_interval_seconds: z.number().int().min(1).max(60).default(5).describe(
    "Seconds between power-state polls.",
  ),
});

const SetBootArgs = z.strictObject({
  ...TargetShape,
  target: z.enum(BOOT_TARGETS).describe(
    "Boot device to override; validated against the system's AllowableValues when advertised.",
  ),
  enabled: z.enum(BOOT_ENABLED).default("Once").describe(
    "Once: next boot only. Continuous: every boot. Disabled: clear the override.",
  ),
});

const GlobalArgsSchema = z.strictObject({});

const StateSchema = z.strictObject({
  origin: z.string(),
  system_id: z.string(),
  name: z.string(),
  manufacturer: z.string().optional(),
  model: z.string().optional(),
  serial_number: z.string().optional(),
  uuid: z.string().optional(),
  power_state: z.string(),
  health: z.string().optional(),
  health_rollup: z.string().optional(),
  state: z.string().optional(),
  boot_target: z.string().optional(),
  boot_enabled: z.string().optional(),
  boot_mode: z.string().optional(),
  allowable_reset_types: z.array(z.string()).optional(),
  allowable_boot_targets: z.array(z.string()).optional(),
  etag: z.string().optional(),
  status: z.enum(["present", "not_found"]),
  observed_at: z.string(),
});

/** Stored state of one ComputerSystem; holds no credential. */
export type RedfishState = z.infer<typeof StateSchema>;

// deno-lint-ignore no-explicit-any
type Ctx = any;

let deps: Deps = defaultDeps();

/** Replaces the injected dependencies (fetch, TLS client, clock, sleep). */
export function setDeps(d: Partial<Deps>): Deps {
  const prev = deps;
  deps = { ...deps, ...d };
  return prev;
}

function target(a: z.infer<typeof TargetArgs>) {
  const tls: TlsPolicy = a.tls_verify === "insecure_skip_verify"
    ? { mode: "insecure_skip_verify" }
    : { mode: "strict", ...(a.ca_pem ? { caPem: a.ca_pem } : {}) };
  return {
    endpoint: normalizeEndpoint(a.endpoint),
    systemId: a.system_id,
    username: a.username,
    password: a.password,
    tls,
    authMode: a.auth_mode,
    allowInsecureBasic: a.allow_insecure_basic,
  };
}

/**
 * State instance name for a system: the endpoint host and system id plus a
 * digest of the origin and id, so two BMCs that share a hostname (or one BMC's
 * two systems) never collide.
 */
export async function systemInstance(
  origin: string,
  systemId: string,
): Promise<string> {
  const host = new URL(origin).host;
  const readable = `${host}_${systemId}`
    .replace(/[^A-Za-z0-9._-]+/g, "-")
    .replace(/^[.-]+|[.-]+$/g, "")
    .slice(0, 120);
  const digest = (await sha256Hex(`${origin}\0${systemId}`)).slice(0, 16);
  return `${readable === "" ? "system" : readable}_${digest}`;
}

/** Writes the system state and returns its handle. */
async function persist(context: Ctx, state: SystemState) {
  const name = await systemInstance(state.origin, state.system_id);
  return await context.writeResource("state", name, state);
}

function summary(s: SystemState) {
  return {
    system_id: s.system_id,
    name: s.name,
    power_state: s.power_state,
    boot_target: s.boot_target,
    boot_enabled: s.boot_enabled,
    health: s.health,
    status: s.status,
  };
}

/** Model definition for `@randybias/redfish`. */
export const model = {
  type: "@randybias/redfish",
  version: "2026.10.17.1",
  description:
    "Read and control a server's power and boot settings over the DMTF Redfish API, with vault-wired credentials and an explicit TLS policy.",
  globalArguments: GlobalArgsSchema,
  resources: {
    state: {
      description: "ComputerSystem metadata, power state and boot override",
      schema: StateSchema,
      lifetime: "infinite" as const,
      garbageCollection: 10,
    },
  },
  methods: {
    get: {
      description:
        "READ-ONLY. Read the ComputerSystem's power state, boot override and health. Never returns or stores a credential.",
      arguments: TargetArgs,
      execute: async (args: z.input<typeof TargetArgs>, context: Ctx) => {
        const a = TargetArgs.parse(args);
        const t = target(a);
        const state = await withRedfish(deps, t, async (api, origin) => {
          const found = await api.findSystem(a.system_id);
          return parseSystem(
            found.raw,
            origin,
            deps.now().toISOString(),
            "present",
            found.etag,
          );
        });
        const handle = await persist(context, state);
        return { dataHandles: [handle], result: summary(state) };
      },
    },

    sync: {
      description:
        "READ-ONLY. Refresh stored state from the BMC; a ComputerSystem that is gone is recorded as not_found instead of failing.",
      arguments: TargetArgs,
      execute: async (args: z.input<typeof TargetArgs>, context: Ctx) => {
        const a = TargetArgs.parse(args);
        const t = target(a);
        const state = await withRedfish(deps, t, async (api, origin) => {
          try {
            const found = await api.findSystem(a.system_id);
            return parseSystem(
              found.raw,
              origin,
              deps.now().toISOString(),
              "present",
              found.etag,
            );
          } catch (e) {
            if (e instanceof RedfishError && e.code === "not_found") {
              return parseSystem(
                { Id: a.system_id ?? "unknown" },
                origin,
                deps.now().toISOString(),
                "not_found",
              );
            }
            throw e;
          }
        });
        context.logger.info("System {id} status {status}", {
          id: state.system_id,
          status: state.status,
        });
        const handle = await persist(context, state);
        return { dataHandles: [handle], result: summary(state) };
      },
    },

    power: {
      kind: "action" as const,
      description:
        "DESTRUCTIVE. Power on, power off or restart the ComputerSystem, then wait until the resulting state is observed. On and the off actions are a no-op when the system is already there; a restart is accepted only after an observed state change or a completed Redfish task. Returns the observed state.",
      arguments: PowerArgs,
      execute: async (args: z.input<typeof PowerArgs>, context: Ctx) => {
        const a = PowerArgs.parse(args);
        const t = target(a);
        const action = a.action as ResetType;
        const deadline = deps.now().getTime() + a.timeout_seconds * 1000;
        const pollMs = a.poll_interval_seconds * 1000;
        const state = await withRedfish(deps, t, async (api, origin) => {
          const found = await api.findSystem(a.system_id);
          let current = parseSystem(
            found.raw,
            origin,
            deps.now().toISOString(),
            "present",
            found.etag,
          );
          if (isPowerNoop(action, current.power_state)) {
            context.logger.info("System {id} already {state}", {
              id: current.system_id,
              state: current.power_state,
            });
            return current;
          }
          const allowable = current.allowable_reset_types;
          if (allowable && !allowable.includes(action)) {
            throw new RedfishError(
              "invalid_input",
              `BMC does not allow ${action}; allowed: ${allowable.join(", ")}`,
            );
          }
          const initial = current.power_state;
          const restart = isRestartAction(action);
          const desired = desiredPowerState(action, initial);
          const reset = await api.resetSystem(found.raw, action);
          if (reset.taskLocation) {
            await api.awaitTask(reset.taskLocation, pollMs);
          }
          let sawTransition = false;
          while (deps.now().getTime() < deadline) {
            await deps.sleep(pollMs);
            const again = await api.readSystem();
            current = parseSystem(
              again.raw,
              origin,
              deps.now().toISOString(),
              "present",
              again.etag,
            );
            if (restart) {
              if (current.power_state !== initial) sawTransition = true;
              if (sawTransition && current.power_state === desired) {
                return current;
              }
            } else if (current.power_state === desired) {
              return current;
            }
          }
          throw new RedfishError(
            "timeout",
            `System ${current.system_id} did not reach ${desired} within ${a.timeout_seconds}s`,
          );
        }, deadline);
        const handle = await persist(context, state);
        return { dataHandles: [handle], result: summary(state) };
      },
    },

    set_boot: {
      kind: "action" as const,
      description:
        "DESTRUCTIVE. Set the one-time or continuous boot override and read it back to confirm. A continuous override can reboot the host into an installer on every boot. Returns the observed state.",
      arguments: SetBootArgs,
      execute: async (args: z.input<typeof SetBootArgs>, context: Ctx) => {
        const a = SetBootArgs.parse(args);
        const t = target(a);
        const state = await withRedfish(deps, t, async (api, origin) => {
          const found = await api.findSystem(a.system_id);
          let current = parseSystem(
            found.raw,
            origin,
            deps.now().toISOString(),
            "present",
            found.etag,
          );
          const wantedTarget = a.enabled === "Disabled" ? "None" : a.target;
          const allowable = current.allowable_boot_targets;
          if (
            a.enabled !== "Disabled" && allowable &&
            !allowable.includes(a.target)
          ) {
            throw new RedfishError(
              "invalid_input",
              `BMC does not allow boot target ${a.target}; allowed: ${
                allowable.join(", ")
              }`,
            );
          }
          if (
            current.boot_target === wantedTarget &&
            current.boot_enabled === a.enabled
          ) {
            context.logger.info("System {id} boot already {target}", {
              id: current.system_id,
              target: wantedTarget,
            });
            return current;
          }
          await api.patchBoot(a.target, a.enabled, found.etag);
          const again = await api.readSystem();
          current = parseSystem(
            again.raw,
            origin,
            deps.now().toISOString(),
            "present",
            again.etag,
          );
          if (
            current.boot_target !== wantedTarget ||
            current.boot_enabled !== a.enabled
          ) {
            throw new RedfishError(
              "redfish_failed",
              "BMC did not apply the boot override",
            );
          }
          return current;
        });
        const handle = await persist(context, state);
        return { dataHandles: [handle], result: summary(state) };
      },
    },
  },
};
