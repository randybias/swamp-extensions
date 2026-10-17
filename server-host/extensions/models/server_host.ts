/**
 * Swamp extension model for bringing a freshly provisioned Linux host to a
 * hardened baseline in three phases: base (packages, users, sysctl, time,
 * journald), firewall (an nftables ruleset rendered from inputs) and lockdown
 * (close public SSH to a management allowlist).
 *
 * One definition hardens any host: the SSH target and every phase input are
 * method arguments, so the type names no particular deployment. State is keyed
 * by the target host. The SSH key is named by a vault reference and read inside
 * the method, so no key material appears in arguments, logs or `--json`
 * output. The dangerous phases arm a host-side revert timer before they change
 * anything, so a locked-out operator recovers without console access unless
 * `commit` cancels the timer.
 *
 * @module
 */

import { z } from "npm:zod@4.3.6";
import { denoDeps, type SshDeps, type Target } from "./_lib/ssh.ts";
import {
  assertAuthorizedKey,
  assertCidr,
  assertPackage,
  assertSysctlKey,
  assertSysctlValue,
  assertTimezone,
  assertUser,
  AUTHORIZED_KEY_RE,
  HostConfigError,
  isCidr,
  PACKAGE_RE,
  SYSCTL_KEY_RE,
  SYSCTL_VALUE_RE,
  TIMEZONE_RE,
  USER_RE,
} from "./_lib/validate.ts";
import {
  assertFirewallRules,
  type FirewallRules,
  managedTableSha256,
  renderRuleset,
  rulesetSha256,
} from "./_lib/nftables.ts";
import {
  type EmittedStep,
  executePlan,
  planApplyBase,
  planCommit,
  planFirewallChange,
  probeState,
  renderSysctlConf,
} from "./_lib/plans.ts";
import { TOKEN_RE } from "./_lib/armed_revert.ts";

/** Reads one secret from a swamp vault. Implemented by the runtime. */
export interface VaultReader {
  /** Returns the secret's plaintext, or throws when it is missing. */
  get(vaultName: string, secretKey: string): Promise<string>;
}

/** The model's dependencies: transport, clock, revert token and secret seam. */
export interface HostDeps extends SshDeps {
  /** Returns a fresh, unpredictable revert token of 16-64 lowercase hex. */
  token: () => string;
  /**
   * Resolves a vault reference to its plaintext. Tests pass a fake; in
   * production it is left unset and the runtime's `context.vaultService` is
   * used instead.
   */
  resolveSecret?: (vaultName: string, secretKey: string) => Promise<string>;
}

function randomToken(): string {
  const bytes = new Uint8Array(8);
  crypto.getRandomValues(bytes);
  return [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
}

/** Production dependencies: the SSH transport, the clock, and a token source. */
export const denoHostDeps: HostDeps = { ...denoDeps, token: randomToken };

const GlobalArgsSchema = z.strictObject({});

const HostKeyPolicy = z.enum(["strict", "insecure_tofu"]).describe(
  "strict trusts only host_keys; insecure_tofu trusts whatever key the host presents on first contact and records nothing",
);

/** Vault name and secret key of the SSH private key. */
const SecretRef = z.strictObject({
  vault: z.string().min(1).max(128).describe("Vault that holds the key"),
  key: z.string().min(1).max(128).describe("Secret key name inside the vault"),
});

const SshFields = {
  host: z.string().min(1).max(255).describe(
    "Hostname or IP address; also the key under which this model records state",
  ),
  port: z.number().int().min(1).max(65535).default(22).describe("SSH port"),
  user: z.string().regex(USER_RE).describe("Remote login name"),
  host_key_policy: HostKeyPolicy,
  host_keys: z.array(z.string().max(2048)).max(16).optional().describe(
    "Pinned host keys in ssh-keyscan format, one per entry; required for strict",
  ),
  ssh_key_ref: SecretRef.describe(
    "Vault reference to the SSH private key; the key is read inside the method and never appears in arguments or logs",
  ),
  connect_timeout_s: z.number().int().min(1).max(120).default(15).describe(
    "Seconds to wait for the connection, 1-120",
  ),
  sudo: z.boolean().default(true).describe(
    "Run privileged commands as root through non-interactive sudo",
  ),
};

const FirewallFields = {
  management_cidrs: z.array(
    z.string().min(1).max(64).refine(isCidr, "not a CIDR block"),
  ).max(64).default([]).describe(
    "CIDRs allowed to reach the SSH port; a /0 needs allow_ssh_from_anywhere",
  ),
  allow_tcp: z.array(z.number().int().min(1).max(65535)).max(128).default([])
    .describe("TCP ports open to every source; the SSH port is excluded"),
  allow_udp: z.array(z.number().int().min(1).max(65535)).max(128).default([])
    .describe("UDP ports open to every source; the SSH port is excluded"),
  default_policy: z.literal("drop").default("drop").describe(
    "Policy of the input chain; it is always drop",
  ),
  ssh_port: z.number().int().min(1).max(65535).default(22).describe(
    "Port the SSH allow rules target",
  ),
  allow_ssh_from_anywhere: z.boolean().default(false).describe(
    "Acknowledge that the SSH port is reachable from any source",
  ),
};

const BaseFields = {
  packages: z.array(
    z.string().min(1).max(64).refine(
      (v) => PACKAGE_RE.test(v),
      "not a package name",
    ),
  ).max(128).default([]).describe("Debian package names to ensure installed"),
  admin_user: z.string().regex(USER_RE).describe(
    "Administrative account to ensure exists",
  ),
  authorized_keys: z.array(
    z.string().min(1).max(4096).refine(
      (v) => AUTHORIZED_KEY_RE.test(v),
      "not an SSH public key line",
    ),
  ).max(64).default([]).describe("Public keys to authorize for the account"),
  sysctl: z.record(
    z.string().max(128).regex(SYSCTL_KEY_RE),
    z.string().max(128).regex(SYSCTL_VALUE_RE),
  ).refine((v) => Object.keys(v).length <= 128, "at most 128 sysctl entries")
    .default({}).describe("Sysctl keys and values to write"),
  timezone: z.string().max(64).regex(TIMEZONE_RE).default("UTC").describe(
    "Time zone to set, e.g. UTC or Etc/UTC",
  ),
};

const RevertAfter = z.number().int().min(60).max(1800).default(300).describe(
  "Seconds the host waits before reverting, 60-1800",
);

const RenderArgs = z.strictObject({
  host: z.string().min(1).max(255).describe("Label for the recorded render"),
  ...FirewallFields,
});

const FirewallChangeArgs = z.strictObject({
  ...SshFields,
  ...FirewallFields,
  revert_after_s: RevertAfter,
});

const CommitArgs = z.strictObject({
  ...SshFields,
  // swamp-quality-ignore credentials-sensitive-field
  revert_token: z.string().regex(TOKEN_RE).optional().describe(
    "Opaque identifier of the armed revert; defaults to the recorded one",
  ),
});

const ApplyBaseArgs = z.strictObject({
  ...SshFields,
  ...BaseFields,
});

const ProbeArgs = z.strictObject({ ...SshFields });

const BaseStateSchema = z.strictObject({
  packages: z.array(z.string()),
  admin_user: z.string(),
  authorized_keys_sha256: z.string(),
  sysctl_sha256: z.string(),
  timezone: z.string(),
  applied_at: z.string(),
});

const FirewallStateSchema = z.strictObject({
  ruleset_sha256: z.string(),
  managed_sha256: z.string(),
  mode: z.enum(["firewall", "lockdown"]),
  ssh_exposure: z.enum(["management-only", "anywhere"]),
  applied_at: z.string(),
});

const HostStateSchema = z.strictObject({
  host: z.string(),
  base: BaseStateSchema.optional(),
  firewall: FirewallStateSchema.optional(),
  observed_at: z.string(),
});

const RevertSchema = z.strictObject({
  host: z.string(),
  // swamp-quality-ignore credentials-sensitive-field
  token: z.string(),
  phase: z.enum(["firewall", "lockdown"]),
  unit: z.string(),
  expires_at: z.string(),
  armed_at: z.string(),
  ruleset_sha256: z.string(),
  managed_sha256: z.string().optional(),
  committed_at: z.string().optional(),
});

const RenderStateSchema = z.strictObject({
  host: z.string(),
  ruleset: z.string(),
  ruleset_sha256: z.string(),
  managed_sha256: z.string(),
  observed_at: z.string(),
});

/** Stored phase state of one host. */
export type HostState = z.infer<typeof HostStateSchema>;
/** Stored record of one armed revert. */
export type Revert = z.infer<typeof RevertSchema>;

type Ctx = {
  logger: {
    info(msg: string, ...args: unknown[]): void;
    warning(msg: string, ...args: unknown[]): void;
  };
  writeResource: (
    spec: string,
    name: string,
    data: Record<string, unknown>,
  ) => Promise<{ name: string }>;
  readResource: (
    name: string,
    version?: number,
  ) => Promise<Record<string, unknown> | null>;
  vaultService?: () => Promise<VaultReader>;
};

/** Converts a host into a safe swamp data instance suffix. */
export function hostInstance(host: string): string {
  return host.replace(/[^A-Za-z0-9._-]/g, "_").replace(/\.\./g, "_");
}

function stateName(host: string): string {
  return `state-${hostInstance(host)}`;
}

function revertName(host: string): string {
  return `revert-${hostInstance(host)}`;
}

function renderName(host: string): string {
  return `render-${hostInstance(host)}`;
}

/** The recorded, uncommitted revert for `host`, if there is one. */
async function currentRevert(
  context: Ctx,
  host: string,
): Promise<Revert | null> {
  const record = await context.readResource(revertName(host)) as Revert | null;
  return record && record.committed_at === undefined ? record : null;
}

/**
 * Refuses a new destructive firewall change while a recorded revert is still
 * armed: a second timer would outlive the first commit and silently undo it.
 * A recorded revert whose timer already fired or was lost is stale and is
 * ignored; the caller overwrites it with the new one.
 */
async function assertNoActiveRevert(
  deps: HostDeps,
  t: Target,
  args: { sudo: boolean },
  record: Revert | null,
  host: string,
): Promise<void> {
  if (!record) return;
  const probe = await probeState(deps, t, {
    sudo: args.sudo,
    token: record.token,
  });
  if (probe.armed) {
    throw new HostConfigError(
      `An armed revert (${record.phase}, expires ${record.expires_at}) is still active on ${host}; commit it or let it fire before making another firewall change`,
    );
  }
}

/**
 * Reads the SSH private key named by `ref` inside the method. The key never
 * enters arguments or logs; tests inject `deps.resolveSecret`, production uses
 * the runtime's `context.vaultService`.
 */
async function resolvePrivateKey(
  deps: HostDeps,
  context: Ctx,
  ref: { vault: string; key: string },
): Promise<string> {
  if (deps.resolveSecret) {
    const value = await deps.resolveSecret(ref.vault, ref.key);
    if (typeof value !== "string" || value.length === 0) {
      throw new HostConfigError(
        `Vault ${ref.vault} returned no secret for ${ref.key}`,
      );
    }
    return value;
  }
  const factory = context.vaultService;
  if (typeof factory !== "function") {
    throw new HostConfigError(
      "No vault service is available to resolve ssh_key_ref; run with a vault",
    );
  }
  const service = await factory();
  if (!service || typeof service.get !== "function") {
    throw new HostConfigError("The vault service cannot read secrets");
  }
  const value = await service.get(ref.vault, ref.key);
  if (typeof value !== "string" || value.length === 0) {
    throw new HostConfigError(
      `Vault ${ref.vault} returned no secret for ${ref.key}`,
    );
  }
  return value;
}

function target(
  a: {
    host: string;
    port: number;
    user: string;
    host_key_policy: "strict" | "insecure_tofu";
    host_keys?: string[];
    connect_timeout_s: number;
  },
  privateKey: string,
): Target {
  return {
    host: a.host,
    port: a.port,
    user: a.user,
    hostKeyPolicy: a.host_key_policy,
    hostKeys: a.host_keys,
    privateKey,
    connectTimeoutS: a.connect_timeout_s,
  };
}

function rulesFrom(a: {
  management_cidrs: string[];
  allow_tcp: number[];
  allow_udp: number[];
  default_policy: "drop";
  ssh_port: number;
  allow_ssh_from_anywhere: boolean;
}): FirewallRules {
  const rules: FirewallRules = {
    managementCidrs: a.management_cidrs,
    allowTcp: a.allow_tcp,
    allowUdp: a.allow_udp,
    defaultPolicy: a.default_policy,
    sshPort: a.ssh_port,
    allowSshFromAnywhere: a.allow_ssh_from_anywhere,
  };
  assertFirewallRules(rules);
  return rules;
}

function sameStrings(a: readonly string[], b: readonly string[]): boolean {
  return a.length === b.length && a.every((v, i) => v === b[i]);
}

/** Builds the model with overridable dependencies (spawner, clock, token). */
export function createModel(overrides: Partial<HostDeps> = {}) {
  const deps: HostDeps = { ...denoHostDeps, ...overrides };
  return {
    type: "@randybias/server-host",
    version: "2026.10.17.1",
    description:
      "Harden a Linux host over SSH in three phases: base packages and users, an nftables firewall rendered from inputs, and an SSH lockdown. The SSH key is named by a vault reference and the firewall and lockdown phases arm a host-side revert timer before they change anything.",
    upgrades: [],
    globalArguments: GlobalArgsSchema,
    resources: {
      host_state: {
        description: "Recorded base and firewall phase state for one host",
        schema: HostStateSchema,
        lifetime: "infinite" as const,
        garbageCollection: 20,
      },
      revert: {
        description:
          "An armed host-side revert timer and the snapshot it restores",
        schema: RevertSchema,
        lifetime: "1d" as const,
        garbageCollection: 5,
      },
      firewall_render: {
        description: "A rendered nftables ruleset and its SHA-256",
        schema: RenderStateSchema,
        lifetime: "1d" as const,
        garbageCollection: 5,
      },
    },
    methods: {
      apply_base: {
        description:
          "DESTRUCTIVE. Idempotent. Install the named base packages, create the admin user and authorized keys, write sysctl and journald settings, then set the time zone and enable time sync. Replaces the managed authorized_keys file, so an empty list revokes the managed keys. Returns the operations applied and the ones whose inputs changed; an unchanged re-run emits no commands.",
        kind: "action" as const,
        arguments: ApplyBaseArgs,
        execute: async (
          args: z.infer<typeof ApplyBaseArgs>,
          context: Ctx,
        ) => {
          for (const p of args.packages) assertPackage(p);
          assertUser(args.admin_user);
          for (const k of args.authorized_keys) assertAuthorizedKey(k);
          for (const [k, v] of Object.entries(args.sysctl)) {
            assertSysctlKey(k);
            assertSysctlValue(v);
          }
          assertTimezone(args.timezone);
          const privateKey = await resolvePrivateKey(
            deps,
            context,
            args.ssh_key_ref,
          );
          const stored = await context.readResource(stateName(args.host)) as
            | HostState
            | null;
          const packages = [...args.packages].sort();
          const keys = [...args.authorized_keys];
          const sysctl_sha256 = await rulesetSha256(
            renderSysctlConf(args.sysctl),
          );
          const keys_sha256 = await rulesetSha256(keys.join("\n"));
          const prev = stored?.base;
          const changed: string[] = [];
          if (!prev || !sameStrings(prev.packages, packages)) {
            changed.push("packages");
          }
          if (!prev || prev.admin_user !== args.admin_user) {
            changed.push("admin_user");
          }
          if (!prev || prev.authorized_keys_sha256 !== keys_sha256) {
            changed.push("authorized_keys");
          }
          if (!prev || prev.sysctl_sha256 !== sysctl_sha256) {
            changed.push("sysctl");
          }
          if (!prev || prev.timezone !== args.timezone) {
            changed.push("timezone");
          }
          if (!prev) changed.push("journald", "time_sync");
          // A changed account must receive the managed keys even when the key
          // material itself is unchanged, or the new account has none.
          if (
            changed.includes("admin_user") && keys.length > 0 &&
            !changed.includes("authorized_keys")
          ) {
            changed.push("authorized_keys");
          }
          const steps = planApplyBase({
            sudo: args.sudo,
            packages,
            adminUser: args.admin_user,
            authorizedKeys: keys,
            sysctl: args.sysctl,
            timezone: args.timezone,
          }, changed);
          const emitted = await executePlan(
            deps,
            target(args, privateKey),
            steps,
          );
          context.logger.info("apply_base on {host}: {count} steps", {
            host: args.host,
            count: emitted.length,
          });
          const state: HostState = {
            host: args.host,
            base: {
              packages,
              admin_user: args.admin_user,
              authorized_keys_sha256: keys_sha256,
              sysctl_sha256,
              timezone: args.timezone,
              applied_at: new Date(deps.now()).toISOString(),
            },
            ...(stored?.firewall ? { firewall: stored.firewall } : {}),
            observed_at: new Date(deps.now()).toISOString(),
          };
          const handle = await context.writeResource(
            "host_state",
            stateName(args.host),
            state,
          );
          return {
            dataHandles: [handle],
            result: { host: args.host, applied: changed, changed },
          };
        },
      },
      render_firewall: {
        description:
          "READ-ONLY. Render the deterministic nftables ruleset for the given inputs, with CIDRs and ports sorted, and return its text and SHA-256. Makes no remote call.",
        arguments: RenderArgs,
        execute: async (
          args: z.infer<typeof RenderArgs>,
          context: Ctx,
        ) => {
          for (const c of args.management_cidrs) assertCidr(c);
          const ruleset = renderRuleset(rulesFrom(args));
          const ruleset_sha256 = await rulesetSha256(ruleset);
          const managed_sha256 = await managedTableSha256(ruleset);
          const handle = await context.writeResource(
            "firewall_render",
            renderName(args.host),
            {
              host: args.host,
              ruleset,
              ruleset_sha256,
              managed_sha256,
              observed_at: new Date(deps.now()).toISOString(),
            },
          );
          return {
            dataHandles: [handle],
            result: {
              host: args.host,
              ruleset,
              ruleset_sha256,
              managed_sha256,
            },
          };
        },
      },
      apply_firewall: {
        description:
          "DESTRUCTIVE. Snapshot the current ruleset, arm a host-side revert timer, then pre-check and apply the rendered ruleset with nft; a wrong ruleset can cut management access, so the host restores the snapshot unless commit cancels the timer. Idempotent: a matching ruleset that is still live is a no-op.",
        kind: "action" as const,
        arguments: FirewallChangeArgs,
        execute: async (
          args: z.infer<typeof FirewallChangeArgs>,
          context: Ctx,
        ) => {
          const privateKey = await resolvePrivateKey(
            deps,
            context,
            args.ssh_key_ref,
          );
          const ruleset = renderRuleset(rulesFrom(args));
          const ruleset_sha256 = await rulesetSha256(ruleset);
          const managed_sha256 = await managedTableSha256(ruleset);
          const t = target(args, privateKey);
          const stored = await context.readResource(stateName(args.host)) as
            | HostState
            | null;
          const record = await currentRevert(context, args.host);
          if (stored?.firewall?.ruleset_sha256 === ruleset_sha256) {
            const probe = await probeState(deps, t, {
              sudo: args.sudo,
              token: record?.token,
            });
            if (
              probe.managed_table && probe.managed_sha256 === managed_sha256
            ) {
              context.logger.info(
                "apply_firewall on {host}: ruleset already live, no-op",
                { host: args.host },
              );
              const stillArmed = record !== null && probe.armed;
              return {
                result: {
                  host: args.host,
                  ruleset_sha256,
                  managed_sha256,
                  revert_token: stillArmed ? record.token : null,
                  expires_at: stillArmed ? record.expires_at : null,
                  changed: false,
                },
              };
            }
          }
          await assertNoActiveRevert(deps, t, args, record, args.host);
          const token = deps.token();
          const expires_at = new Date(
            deps.now() + args.revert_after_s * 1000,
          ).toISOString();
          const steps = planFirewallChange({
            token,
            revertAfterS: args.revert_after_s,
            sudo: args.sudo,
            rulesText: ruleset,
          });
          const emitted: EmittedStep[] = await executePlan(deps, t, steps);
          const revertHandle = await context.writeResource(
            "revert",
            revertName(args.host),
            {
              host: args.host,
              token,
              phase: "firewall",
              unit: `server-host-revert-${token}`,
              expires_at,
              armed_at: new Date(deps.now()).toISOString(),
              ruleset_sha256,
              managed_sha256,
            },
          );
          const stateHandle = await writeFirewallState(
            context,
            stateName(args.host),
            args.host,
            stored,
            { ruleset_sha256, managed_sha256 },
            "firewall",
            args.allow_ssh_from_anywhere ? "anywhere" : "management-only",
            deps.now(),
          );
          context.logger.info(
            "apply_firewall on {host}: armed {token}, {count} steps",
            { host: args.host, token, count: emitted.length },
          );
          return {
            dataHandles: [revertHandle, stateHandle],
            result: {
              host: args.host,
              ruleset_sha256,
              managed_sha256,
              revert_token: token,
              expires_at,
              changed: true,
            },
          };
        },
      },
      lockdown: {
        description:
          "DESTRUCTIVE. Restrict the SSH port to management_cidrs, snapshotting the ruleset and arming a host-side revert timer before the change. Returns the revert token and expiry; unless commit cancels the timer the host restores the snapshot.",
        kind: "action" as const,
        arguments: FirewallChangeArgs,
        execute: async (
          args: z.infer<typeof FirewallChangeArgs>,
          context: Ctx,
        ) => {
          if (args.allow_ssh_from_anywhere) {
            throw new HostConfigError(
              "lockdown requires management_cidrs and never allows SSH from anywhere",
            );
          }
          for (const c of args.management_cidrs) assertCidr(c);
          const privateKey = await resolvePrivateKey(
            deps,
            context,
            args.ssh_key_ref,
          );
          const ruleset = renderRuleset(rulesFrom({
            ...args,
            allow_ssh_from_anywhere: false,
          }));
          const ruleset_sha256 = await rulesetSha256(ruleset);
          const managed_sha256 = await managedTableSha256(ruleset);
          const t = target(args, privateKey);
          const stored = await context.readResource(stateName(args.host)) as
            | HostState
            | null;
          const record = await currentRevert(context, args.host);
          if (stored?.firewall?.ruleset_sha256 === ruleset_sha256) {
            const probe = await probeState(deps, t, {
              sudo: args.sudo,
              token: record?.token,
            });
            if (
              probe.managed_table && probe.managed_sha256 === managed_sha256
            ) {
              context.logger.info(
                "lockdown on {host}: ruleset already live, no-op",
                { host: args.host },
              );
              const stillArmed = record !== null && probe.armed;
              return {
                result: {
                  host: args.host,
                  ruleset_sha256,
                  managed_sha256,
                  revert_token: stillArmed ? record.token : null,
                  expires_at: stillArmed ? record.expires_at : null,
                  changed: false,
                },
              };
            }
          }
          await assertNoActiveRevert(deps, t, args, record, args.host);
          const token = deps.token();
          const expires_at = new Date(
            deps.now() + args.revert_after_s * 1000,
          ).toISOString();
          const steps = planFirewallChange({
            token,
            revertAfterS: args.revert_after_s,
            sudo: args.sudo,
            rulesText: ruleset,
          });
          await executePlan(deps, t, steps);
          const revertHandle = await context.writeResource(
            "revert",
            revertName(args.host),
            {
              host: args.host,
              token,
              phase: "lockdown",
              unit: `server-host-revert-${token}`,
              expires_at,
              armed_at: new Date(deps.now()).toISOString(),
              ruleset_sha256,
              managed_sha256,
            },
          );
          const stateHandle = await writeFirewallState(
            context,
            stateName(args.host),
            args.host,
            stored,
            { ruleset_sha256, managed_sha256 },
            "lockdown",
            "management-only",
            deps.now(),
          );
          context.logger.info("lockdown on {host}: armed {token}", {
            host: args.host,
            token,
          });
          return {
            dataHandles: [revertHandle, stateHandle],
            result: {
              host: args.host,
              ruleset_sha256,
              managed_sha256,
              revert_token: token,
              expires_at,
            },
          };
        },
      },
      commit: {
        description:
          "Cancel the armed revert after confirming the host is still reachable. Probes that the timer is still active and the live ruleset still matches the armed revert, refuses when it does not, and treats a failed cancellation as fatal; only then is the revert recorded as committed.",
        kind: "action" as const,
        arguments: CommitArgs,
        execute: async (
          args: z.infer<typeof CommitArgs>,
          context: Ctx,
        ) => {
          const privateKey = await resolvePrivateKey(
            deps,
            context,
            args.ssh_key_ref,
          );
          const t = target(args, privateKey);
          const stored = await context.readResource(revertName(args.host)) as
            | Revert
            | null;
          if (!stored) {
            throw new HostConfigError(
              `No armed revert is recorded for ${args.host}`,
            );
          }
          if (
            args.revert_token !== undefined &&
            args.revert_token !== stored.token
          ) {
            throw new HostConfigError(
              `revert_token does not match the armed revert for ${args.host}`,
            );
          }
          if (stored.committed_at !== undefined) {
            throw new HostConfigError(
              `The armed revert for ${args.host} was already committed`,
            );
          }
          if (Date.parse(stored.expires_at) <= deps.now()) {
            throw new HostConfigError(
              `The armed revert for ${args.host} expired at ${stored.expires_at}; nothing to cancel`,
            );
          }
          const before = await probeState(deps, t, {
            sudo: args.sudo,
            token: stored.token,
          });
          if (!before.armed) {
            throw new HostConfigError(
              `The revert timer for ${args.host} is not active; it may already have fired or been lost to a reboot, so there is nothing to cancel`,
            );
          }
          if (
            stored.managed_sha256 !== undefined &&
            before.managed_sha256 !== stored.managed_sha256
          ) {
            throw new HostConfigError(
              `The live ruleset on ${args.host} no longer matches the armed revert; refusing to commit an unknown ruleset`,
            );
          }
          await executePlan(deps, t, planCommit(stored.token, args.sudo));
          const after = await probeState(deps, t, {
            sudo: args.sudo,
            token: stored.token,
          });
          if (after.armed) {
            throw new HostConfigError(
              `The revert timer for ${args.host} is still active after cancel; not recording a commit`,
            );
          }
          if (
            stored.managed_sha256 !== undefined &&
            after.managed_sha256 !== stored.managed_sha256
          ) {
            throw new HostConfigError(
              `The revert already restored the prior ruleset on ${args.host}; refusing to record a commit`,
            );
          }
          const revertHandle = await context.writeResource(
            "revert",
            revertName(args.host),
            { ...stored, committed_at: new Date(deps.now()).toISOString() },
          );
          const stateHandle = await context.writeResource(
            "host_state",
            stateName(args.host),
            mergeState(
              await context.readResource(stateName(args.host)) as
                | HostState
                | null,
              {
                host: args.host,
                observed_at: new Date(deps.now()).toISOString(),
              },
            ),
          );
          context.logger.info("commit on {host}: revert {token} cancelled", {
            host: args.host,
            token: stored.token,
          });
          return {
            dataHandles: [revertHandle, stateHandle],
            result: { host: args.host, committed: true },
          };
        },
      },
      get: {
        description:
          "READ-ONLY. Report the recorded phase state and probe the host for the active ruleset SHA-256 and whether a recorded revert timer is still armed. A failed probe is an error, not an observation.",
        arguments: ProbeArgs,
        execute: async (
          args: z.infer<typeof ProbeArgs>,
          context: Ctx,
        ) => {
          const privateKey = await resolvePrivateKey(
            deps,
            context,
            args.ssh_key_ref,
          );
          const stored = await context.readResource(stateName(args.host)) as
            | HostState
            | null;
          const revert = await context.readResource(revertName(args.host)) as
            | Revert
            | null;
          const active = revert && revert.committed_at === undefined
            ? revert
            : null;
          const probe = await probeState(deps, target(args, privateKey), {
            sudo: args.sudo,
            token: active?.token,
          });
          const handle = await context.writeResource(
            "host_state",
            stateName(args.host),
            mergeState(stored, {
              host: args.host,
              observed_at: probe.observed_at,
            }),
          );
          return {
            dataHandles: [handle],
            result: {
              host: args.host,
              base_applied: Boolean(stored?.base),
              admin_user: stored?.base?.admin_user ?? null,
              firewall_mode: stored?.firewall?.mode ?? null,
              ruleset_sha256: probe.ruleset_sha256,
              managed_sha256: probe.managed_sha256,
              managed_table: probe.managed_table,
              revert_armed: probe.armed,
              armed_revert: active
                ? {
                  token: active.token,
                  phase: active.phase,
                  expires_at: active.expires_at,
                }
                : null,
              ssh_exposure: stored?.firewall?.ssh_exposure ?? "unknown",
            },
          };
        },
      },
      sync: {
        description:
          "READ-ONLY. Probe the host and report drift between the recorded state and the live ruleset and revert timer. A failed probe is an error, not an observation.",
        arguments: ProbeArgs,
        execute: async (
          args: z.infer<typeof ProbeArgs>,
          context: Ctx,
        ) => {
          const privateKey = await resolvePrivateKey(
            deps,
            context,
            args.ssh_key_ref,
          );
          const stored = await context.readResource(stateName(args.host)) as
            | HostState
            | null;
          const revert = await context.readResource(revertName(args.host)) as
            | Revert
            | null;
          const active = revert && revert.committed_at === undefined
            ? revert
            : null;
          const probe = await probeState(deps, target(args, privateKey), {
            sudo: args.sudo,
            token: active?.token,
          });
          const drift: string[] = [];
          if (stored?.firewall) {
            if (
              stored.firewall.managed_sha256 !== undefined &&
              stored.firewall.managed_sha256 !== probe.managed_sha256
            ) {
              drift.push("ruleset");
            }
          } else if (probe.managed_table) {
            drift.push("firewall_unrecorded");
          }
          if (active && !probe.armed) drift.push("revert_fired");
          const handle = await context.writeResource(
            "host_state",
            stateName(args.host),
            mergeState(stored, {
              host: args.host,
              observed_at: probe.observed_at,
            }),
          );
          return {
            dataHandles: [handle],
            result: {
              host: args.host,
              ruleset_sha256: probe.ruleset_sha256,
              managed_sha256: probe.managed_sha256,
              managed_table: probe.managed_table,
              revert_armed: probe.armed,
              drift,
            },
          };
        },
      },
    },
  };
}

/** Merges `patch` into `stored`, dropping undefined values, with `host` set. */
function mergeState(
  stored: HostState | null,
  patch: Partial<HostState> & { host: string },
): HostState {
  const merged = { ...(stored ?? {}), ...patch };
  return {
    host: merged.host,
    ...(merged.base ? { base: merged.base } : {}),
    ...(merged.firewall ? { firewall: merged.firewall } : {}),
    observed_at: merged.observed_at ?? new Date().toISOString(),
  };
}

async function writeFirewallState(
  context: Ctx,
  name: string,
  host: string,
  stored: HostState | null,
  sha: { ruleset_sha256: string; managed_sha256: string },
  mode: "firewall" | "lockdown",
  sshExposure: "management-only" | "anywhere",
  now: number,
): Promise<{ name: string }> {
  return await context.writeResource("host_state", name, {
    host,
    ...(stored?.base ? { base: stored.base } : {}),
    firewall: {
      ruleset_sha256: sha.ruleset_sha256,
      managed_sha256: sha.managed_sha256,
      mode,
      ssh_exposure: sshExposure,
      applied_at: new Date(now).toISOString(),
    },
    observed_at: new Date(now).toISOString(),
  });
}

/** Production model: the factory with the registry-facing type and version. */
export const model = {
  ...createModel(),
  type: "@randybias/server-host",
  version: "2026.10.17.1",
};
