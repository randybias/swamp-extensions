/**
 * Zod schemas, inferred state types and the renderer input mapping.
 *
 * Every schema is strict (no passthrough) because these fields are exposed to
 * CEL and to the model arguments. `refineConfig` is shared by `render` and
 * `apply` so the two cannot drift.
 *
 * @module
 */

import { z } from "npm:zod@4.3.6";
import { HOST_RE, USER_RE } from "./ssh.ts";
import {
  isCidr,
  isFqdn,
  isHookLibraryPath,
  isInterfaceName,
  isIpv4,
  isLabel,
  isMac,
  targetKey,
} from "./grammar.ts";
import { renderConfig, type RenderInput } from "./render.ts";

const IPV4 = z.string().max(15).refine(isIpv4, "must be an IPv4 address");
const CIDR = z.string().max(18).refine(
  isCidr,
  "must be an IPv4 CIDR in network form",
);
const MAC = z.string().regex(/^[0-9a-f]{2}(?::[0-9a-f]{2}){5}$/).refine(
  (value) => isMac(value),
  "must be a lowercase unicast MAC address",
);
const FQDN = z.string().max(253).refine(isFqdn, "must be a DNS name");
const INTERFACE = z.string().max(20).refine(
  isInterfaceName,
  "must be a network interface name with no wildcard",
);
const HOSTNAME_OR_FQDN = z.string().max(253).refine(
  (value) => isLabel(value) || isFqdn(value),
  "must be an RFC 1123 hostname",
);

const ReservationSchema = z.strictObject({
  hw_address: MAC.describe("Lowercase unicast MAC address."),
  ip_address: IPV4.describe("Reserved IPv4 address inside the subnet."),
  hostname: HOSTNAME_OR_FQDN.nullish().describe("Optional hostname."),
});

const OptionSchema = z.discriminatedUnion("name", [
  z.strictObject({
    name: z.literal("routers"),
    value: z.array(IPV4).min(1).max(16),
  }),
  z.strictObject({
    name: z.literal("domain-name-servers"),
    value: z.array(IPV4).min(1).max(16),
  }),
  z.strictObject({
    name: z.literal("ntp-servers"),
    value: z.array(IPV4).min(1).max(16),
  }),
  z.strictObject({ name: z.literal("domain-name"), value: FQDN }),
  z.strictObject({
    name: z.literal("domain-search"),
    value: z.array(FQDN).min(1).max(16),
  }),
  z.strictObject({
    name: z.literal("interface-mtu"),
    value: z.number().int().min(576).max(9216),
  }),
]);

const SubnetSchema = z.strictObject({
  id: z.number().int().min(1).max(4294967294).describe("Explicit subnet id."),
  subnet: CIDR.describe("IPv4 subnet in network form, /8 to /30."),
  pools: z.array(z.string().max(40)).min(1).max(16).describe(
    "Pool ranges 'a.b.c.d - a.b.c.e' or CIDRs.",
  ),
  reservations: z.array(ReservationSchema).max(1024).describe(
    "Host reservations by MAC.",
  ),
  options: z.array(OptionSchema).max(32).describe("Per-subnet options."),
  valid_lifetime_s: z.number().int().min(60).max(604800).nullish().describe(
    "Per-subnet valid lifetime.",
  ),
  relay_addresses: z.array(IPV4).max(16).nullish().describe(
    "Relay addresses that select this subnet.",
  ),
});

const SshFields = {
  host: z.string().regex(HOST_RE).max(253).describe("Target host."),
  port: z.number().int().min(1).max(65535).default(22).describe("SSH port."),
  user: z.string().regex(USER_RE).describe(
    "Remote user; must be root (every step is privileged and no sudo is used).",
  ),
  host_key_policy: z.enum(["strict"]).describe(
    "Required; only strict is offered, so the host is verified against host_keys on every run.",
  ),
  host_keys: z.array(z.string().max(8192)).min(1).max(64).describe(
    "ssh-keyscan-format lines; the only accepted host keys.",
  ),
  ssh_key_ref: z.string().min(3).max(1024).meta({ sensitive: true }).describe(
    "Vault reference '<vault>/<key>' for the private key; delivered over stdin.",
  ),
  connect_timeout_s: z.number().int().min(1).max(120).default(15).describe(
    "SSH connection timeout in seconds.",
  ),
};

const DhcpFields = {
  interfaces: z.array(INTERFACE).min(1).max(8).describe(
    "Interfaces to serve, optionally pinned as name/ipv4. No wildcard.",
  ),
  socket_type: z.enum(["raw", "udp"]).default("raw").describe(
    "Socket type; use udp for relayed-only networks.",
  ),
  valid_lifetime_s: z.number().int().min(60).max(604800).default(3600).describe(
    "Global valid lease lifetime in seconds.",
  ),
  renew_timer_s: z.number().int().min(1).max(604800).nullish().describe(
    "Optional renew timer; must be below rebind and valid.",
  ),
  rebind_timer_s: z.number().int().min(1).max(604800).nullish().describe(
    "Optional rebind timer; must be below valid.",
  ),
  options: z.array(OptionSchema).max(32).default([]).describe(
    "Global DHCP options.",
  ),
  subnets: z.array(SubnetSchema).min(1).max(64).describe(
    "Subnets, each with an explicit id.",
  ),
  lease_api: z.boolean().default(false).describe(
    "Use the lease_cmds hook (requires lease_cmds_path).",
  ),
  lease_cmds_path: z.string().max(4096).refine(
    isHookLibraryPath,
    "must be an absolute libdhcp_*.so path under a hooks directory",
  ).nullish().describe(
    "Absolute path of the packaged lease_cmds hook library.",
  ),
  revert_after_s: z.number().int().min(120).max(3600).default(600).describe(
    "Seconds an uncommitted change stays armed before it reverts.",
  ),
  canary_hosts: z.array(IPV4).max(16).default([]).describe(
    "Addresses the Kea host must still reach for commit.",
  ),
  serve_on_management_ack: z.boolean().default(false).describe(
    "Acknowledge serving DHCP on the interface that carries this SSH session.",
  ),
};

const DhcpObject = z.strictObject({ ...DhcpFields });
type DhcpInput = z.infer<typeof DhcpObject>;

/** Cross-field checks shared by `render` and `apply`. */
function refineConfig(args: DhcpInput, ctx: z.RefinementCtx): void {
  try {
    renderConfig(toRenderInput(args));
  } catch (error) {
    ctx.addIssue({
      code: "custom",
      message: error instanceof Error ? error.message : String(error),
    });
  }
  if (args.lease_api && !args.lease_cmds_path) {
    ctx.addIssue({
      code: "custom",
      path: ["lease_cmds_path"],
      message: "lease_api requires lease_cmds_path",
    });
  }
  if (
    args.renew_timer_s != null && args.rebind_timer_s != null &&
    !(args.renew_timer_s < args.rebind_timer_s &&
      args.rebind_timer_s < args.valid_lifetime_s)
  ) {
    ctx.addIssue({
      code: "custom",
      path: ["renew_timer_s"],
      message: "renew_timer_s < rebind_timer_s < valid_lifetime_s required",
    });
  }
}

/** The configuration-bearing arguments, shared by render/apply. */
export const configArgsSchema = DhcpObject.superRefine(refineConfig);

/** Arguments for `apply`. */
export const applyArgsSchema = z.strictObject({
  ...SshFields,
  ...DhcpFields,
}).superRefine(refineConfig);

/** Arguments for `install`. */
export const targetArgsSchema = z.strictObject({ ...SshFields });

/** Arguments for `commit`/`remove`. */
export const strictTargetArgsSchema = z.strictObject({ ...SshFields });

/** Arguments for `get`/`sync`. */
export const probeArgsSchema = z.strictObject({ ...SshFields });

/** Arguments for `leases`. */
export const leaseArgsSchema = z.strictObject({
  ...SshFields,
  subnet_id: z.number().int().min(1).max(4294967294).nullish(),
  ip_address: IPV4.nullish(),
  hw_address: MAC.nullish(),
  lease_api: z.boolean().default(false),
});

const ConfigStateSchema = z.strictObject({
  host: z.string(),
  config_sha256: z.string(),
  kea_hash: z.string().optional(),
  committed_at: z.string(),
  applied_at: z.string(),
  subnets: z.number().int(),
});

const RevertStateSchema = z.strictObject({
  host: z.string(),
  token: z.string(),
  armed_at: z.string(),
  expires_at: z.string(),
  armed_sha256: z.string(),
  canaries: z.array(z.string()).optional(),
  intent: z.enum(["apply", "remove"]).optional(),
  prior_enabled: z.boolean().optional(),
  fired_at: z.string().optional(),
  cancelled_at: z.string().optional(),
});

const ObservationSchema = z.strictObject({
  host: z.string(),
  service_active: z.boolean(),
  kea_version: z.string().optional(),
  file_sha256: z.string().optional(),
  kea_hash: z.string().optional(),
  sockets: z.array(z.string()),
  revert_armed: z.boolean(),
  revert_token: z.string().optional(),
  revert_expires_at: z.string().optional(),
  drift: z.array(z.string()),
  observed_at: z.string(),
});

const LeaseStateSchema = z.strictObject({
  host: z.string(),
  source: z.enum(["memfile", "lease_cmds"]),
  count: z.number().int(),
  leases: z.array(z.strictObject({
    ip_address: z.string(),
    hw_address: z.string(),
    hostname: z.string().optional(),
    subnet_id: z.number().int(),
    expires_at: z.string(),
    state: z.enum(["default", "declined", "expired-reclaimed", "unknown"]),
  })),
  observed_at: z.string(),
});

const PendingStateSchema = z.strictObject({
  host: z.string(),
  config_sha256: z.string(),
  kea_hash: z.string().optional(),
  applied_at: z.string(),
  subnets: z.number().int(),
  status: z.enum(["pending", "discarded"]),
});

const RenderStateSchema = z.strictObject({
  sha256: z.string(),
  warnings: z.array(z.string()),
  plan: z.array(z.string()),
  config: z.unknown(),
});

const ActionStateSchema = z.strictObject({
  method: z.enum(["install", "apply", "commit", "remove"]),
  host: z.string(),
  at: z.string(),
  result: z.unknown(),
});

/** A persisted config record. */
export type ConfigState = z.infer<typeof ConfigStateSchema>;
/** A persisted revert record. */
export type RevertState = z.infer<typeof RevertStateSchema>;
/** A persisted observation record. */
export type Observation = z.infer<typeof ObservationSchema>;
/** A persisted lease query record. */
export type LeaseState = z.infer<typeof LeaseStateSchema>;
/** A pending (uncommitted) apply record. */
export type PendingState = z.infer<typeof PendingStateSchema>;
/** A persisted render output. */
export type RenderState = z.infer<typeof RenderStateSchema>;
/** A persisted action outcome. */
export type ActionState = z.infer<typeof ActionStateSchema>;
/** Validated render/apply arguments. */
export type ConfigArgs = z.infer<typeof configArgsSchema>;
/** Validated apply arguments. */
export type ApplyArgs = z.infer<typeof applyArgsSchema>;
/** Validated target-only arguments. */
export type SshArgs = z.infer<typeof targetArgsSchema>;
/** Validated lease arguments. */
export type LeaseArgs = z.infer<typeof leaseArgsSchema>;

/** One verify check outcome. */
export type VerifyField = "pass" | "fail" | "skipped";

/** The verify checks reported by `commit`. */
export interface VerifyResult {
  service: VerifyField;
  hash_match: VerifyField;
  file_match: VerifyField;
  sockets: VerifyField;
  fresh_connection: VerifyField;
  canaries: VerifyField;
}

/** The resource instance name for a target's committed config. */
export function configName(key: string): string {
  return `config-${key}`;
}

/** The resource instance name for a target's pending apply. */
export function pendingName(key: string): string {
  return `pending-${key}`;
}

/** The resource instance name for a target's observation. */
export function observationName(key: string): string {
  return `observation-${key}`;
}

/** The resource instance name for a target's lease query. */
export function leasesName(key: string): string {
  return `leases-${key}`;
}

/** The resource instance name for a rendered config, keyed by its sha256. */
export function renderName(sha256: string): string {
  return `render-${sha256}`;
}

/** The resource instance name for an action outcome. */
export function actionName(method: string, key: string): string {
  return `${method}-${key}`;
}

/** The resource instance name for one armed revert. */
export function revertName(key: string, token: string): string {
  return `revert-${key}-${token}`;
}

/** The stored-state key for a target: host, port and user. */
export function instanceKey(args: {
  host: string;
  port: number;
  user: string;
}): string {
  return targetKey(args.host, args.port, args.user);
}

/** Builds the renderer input from validated arguments. */
export function toRenderInput(args: DhcpInput): RenderInput {
  return {
    interfaces: args.interfaces,
    socket_type: args.socket_type,
    valid_lifetime_s: args.valid_lifetime_s,
    renew_timer_s: args.renew_timer_s ?? undefined,
    rebind_timer_s: args.rebind_timer_s ?? undefined,
    options: args.options,
    subnets: args.subnets.map((subnet) => ({
      id: subnet.id,
      subnet: subnet.subnet,
      pools: subnet.pools,
      reservations: subnet.reservations.map((reservation) => ({
        hw_address: reservation.hw_address,
        ip_address: reservation.ip_address,
        hostname: reservation.hostname ?? undefined,
      })),
      options: subnet.options,
      valid_lifetime_s: subnet.valid_lifetime_s ?? undefined,
      relay_addresses: subnet.relay_addresses ?? undefined,
    })),
    lease_api: args.lease_api,
    lease_cmds_path: args.lease_cmds_path ?? undefined,
  };
}

export {
  ActionStateSchema,
  ConfigStateSchema,
  LeaseStateSchema,
  ObservationSchema,
  PendingStateSchema,
  RenderStateSchema,
  RevertStateSchema,
};
