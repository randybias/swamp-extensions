/**
 * Zod schemas and inferred types for the `@randybias/apt-cache` model: argument
 * shapes, resource state and observations. Kept apart from the method
 * implementations so both the model registry and every method module share one
 * definition.
 *
 * @module
 */

import { z } from "npm:zod@4.3.6";
import { HOST_RE, USER_RE } from "./ssh.ts";
import {
  DEFAULT_CACHE_DIR,
  DEFAULT_PORT,
  DISTRO_KEY_RE,
  HTTPS_POLICIES,
  isIpv4,
  isIpv6,
} from "./apt.ts";

/** Empty global arguments: every input arrives per call. */
export const GlobalArgsSchema = z.strictObject({});

const VaultRef = z.strictObject({
  vault: z.string().min(1).max(128).describe("Vault instance name"),
  key: z.string().min(1).max(128).describe("Key inside the vault"),
});

const SSH = z.strictObject({
  host: z.string().regex(HOST_RE).max(253).describe(
    "Hostname or IP literal of the target.",
  ),
  port: z.number().int().min(1).max(65535).default(22).describe("SSH port."),
  user: z.string().regex(USER_RE).describe("Remote user name."),
  host_key_policy: z.literal("strict").describe(
    "Only 'strict' is accepted, with a non-empty host_keys list. The model pins the keys it is given and never trusts a key on first contact.",
  ),
  host_keys: z.array(z.string().max(8192)).min(1).max(64).describe(
    "Pinned host keys in ssh-keyscan format; required.",
  ),
  ssh_key_ref: VaultRef.meta({ sensitive: true }).describe(
    "Vault reference of the SSH private key; resolved inside the method and delivered only over stdin.",
  ),
  connect_timeout_s: z.number().int().min(1).max(120).default(15).describe(
    "Connection timeout in seconds.",
  ),
});

const IpAddress = z.string().max(45).refine(
  (s) => isIpv4(s) || isIpv6(s),
  "must be an IPv4 or IPv6 address",
);

const ServerFields = {
  listen: z.array(IpAddress).min(1).max(4).describe(
    "Addresses to listen on. A wildcard address needs listen_any_ack.",
  ),
  listen_any_ack: z.boolean().default(false).describe(
    "Acknowledge binding a wildcard address (0.0.0.0 or ::), which can expose an open proxy.",
  ),
  port: z.number().int().min(1024).max(65535).default(DEFAULT_PORT).describe(
    "TCP port.",
  ),
  https_policy: z.enum(HTTPS_POLICIES).describe(
    "Required HTTPS policy with no default: direct, passthrough or https_backends.",
  ),
  passthrough_hosts: z.array(z.string().max(253)).max(32).default([]).describe(
    "Hosts allowed to tunnel when https_policy is passthrough.",
  ),
  backends: z.record(
    z.string().regex(DISTRO_KEY_RE),
    z.array(z.string().max(512)).min(1).max(4),
  ).default({}).describe("Distribution key to mirror base URLs."),
  expire_days: z.number().int().min(1).max(90).default(4).describe(
    "ExThreshold in days.",
  ),
  cache_dir: z.string().max(255).default(DEFAULT_CACHE_DIR).describe(
    "Absolute cache directory.",
  ),
  admin_auth_ref: VaultRef.meta({ sensitive: true }).nullish().describe(
    "Vault reference of a user:password admin credential; uploaded over stdin.",
  ),
};

const ClientFields = {
  proxy_url: z.string().max(255).describe(
    "Proxy URL http://host:port; never https or with credentials.",
  ),
  https_policy: z.enum(HTTPS_POLICIES).describe(
    "Required HTTPS policy; must match the server's.",
  ),
  bypass_hosts: z.array(z.string().max(253)).max(64).default([]).describe(
    "Hosts that go DIRECT.",
  ),
  fallback_direct: z.boolean().default(false).describe(
    "Render the auto-detect script so apt works directly when the cache is down.",
  ),
  verify_update: z.boolean().default(true).describe(
    "Run apt-get update and require exit 0 after writing the snippet.",
  ),
  override_existing_ack: z.boolean().default(false).describe(
    "Acknowledge a conflicting proxy setting in another apt.conf.d file.",
  ),
  policy_check_ack: z.boolean().default(false).describe(
    "Acknowledge proceeding when the client HTTPS policy cannot be checked against a recorded server (no query API, or the query failed).",
  ),
};

/** Arguments for `install_server`. */
export const InstallServerArgsSchema = z.strictObject({ ssh: SSH });
/** Arguments for `render_server` (no target: deterministic render only). */
export const RenderServerArgsSchema = z.strictObject(ServerFields);
/** Arguments for `apply_server`. */
export const ApplyServerArgsSchema = z.strictObject({
  ssh: SSH,
  ...ServerFields,
});
/** Arguments for `remove_server`. */
export const RemoveServerArgsSchema = z.strictObject({
  ssh: SSH,
  confirm_host: z.string().describe(
    "Must equal the SSH host; guards against removing the wrong server.",
  ),
  purge_cache_ack: z.boolean().default(false).describe(
    "Acknowledge deleting the cache directory. Without it, apt-get remove runs and the cache is left in place.",
  ),
  cache_dir: z.string().max(255).default(DEFAULT_CACHE_DIR).describe(
    "Cache directory; deleted only with purge_cache_ack.",
  ),
});
/** Arguments for `get`. */
export const GetArgsSchema = z.strictObject({
  ssh: SSH,
  cache_dir: z.string().max(255).default(DEFAULT_CACHE_DIR),
});
/** Arguments for `sync`. */
export const SyncArgsSchema = z.strictObject({ ssh: SSH, ...ServerFields });
/** Arguments for `stats`. */
export const StatsArgsSchema = z.strictObject({
  ssh: SSH,
  window: z.string().min(1).max(32).default("today").describe(
    "Log window to read, e.g. today or 7 days.",
  ),
  cache_dir: z.string().max(255).default(DEFAULT_CACHE_DIR),
});
/** Arguments for `configure_client`. */
export const ConfigureClientArgsSchema = z.strictObject({
  ssh: SSH,
  ...ClientFields,
});
/** Arguments for `client_get`. */
export const ClientGetArgsSchema = z.strictObject({ ssh: SSH });
/** Arguments for `unconfigure_client`. */
export const UnconfigureClientArgsSchema = z.strictObject({ ssh: SSH });

/** Recorded server state. */
export const ServerStateSchema = z.strictObject({
  target: z.string(),
  host: z.string(),
  installed: z.boolean(),
  version: z.string().optional(),
  listen: z.array(z.string()).optional(),
  port: z.number().int().optional(),
  https_policy: z.enum(HTTPS_POLICIES).optional(),
  cache_dir: z.string().optional(),
  managed_files: z.record(z.string(), z.string()).optional(),
  config_sha256: z.string().optional(),
  applied_at: z.string().optional(),
  observed_at: z.string(),
});

/** Recorded client state. */
export const ClientStateSchema = z.strictObject({
  target: z.string(),
  host: z.string(),
  present: z.boolean(),
  proxy_url: z.string().optional(),
  https_policy: z.enum(HTTPS_POLICIES).optional(),
  snippet_sha256: z.string().optional(),
  verified: z.boolean().optional(),
  observed_at: z.string(),
});

/** A read-only observation (`get`, `sync`, `stats`, `client_get`). */
export const ObservationSchema = z.strictObject({
  target: z.string(),
  kind: z.enum(["get", "sync", "stats", "client_get"]),
  host: z.string(),
  observed_at: z.string(),
  installed: z.boolean().optional(),
  version: z.string().optional(),
  service_active: z.boolean().optional(),
  service_enabled: z.boolean().optional(),
  listen: z.array(z.string()).optional(),
  port: z.number().int().optional(),
  https_policy: z.string().optional(),
  config_sha256: z.string().optional(),
  expected_config_sha256: z.string().optional(),
  config_matches: z.boolean().optional(),
  passthrough_pattern: z.string().optional(),
  cache_bytes: z.number().int().optional(),
  fs_free_bytes: z.number().int().optional(),
  drift: z.array(z.string()).optional(),
  window: z.string().optional(),
  requests: z.number().int().optional(),
  hits: z.number().int().optional(),
  misses: z.number().int().optional(),
  bytes_from_cache: z.number().int().optional(),
  bytes_upstream: z.number().int().optional(),
  hit_ratio: z.number().optional(),
  proxy_values: z.record(z.string(), z.string()).optional(),
  managed_snippet_in_force: z.boolean().optional(),
  conflicts: z.array(z.string()).optional(),
});

/** Recorded render report (no host). */
export const RenderSchema = z.strictObject({
  listen: z.array(z.string()),
  port: z.number().int(),
  https_policy: z.enum(HTTPS_POLICIES),
  fragment_path: z.string(),
  fragment_sha256: z.string(),
  backends: z.array(z.strictObject({
    key: z.string(),
    path: z.string(),
    sha256: z.string(),
  })),
  observed_at: z.string(),
});

/** Arguments for `install_server`. */
export type InstallServerArgs = z.infer<typeof InstallServerArgsSchema>;
/** Arguments for `render_server`. */
export type RenderServerArgs = z.infer<typeof RenderServerArgsSchema>;
/** Arguments for `apply_server`. */
export type ApplyServerArgs = z.infer<typeof ApplyServerArgsSchema>;
/** Arguments for `remove_server`. */
export type RemoveServerArgs = z.infer<typeof RemoveServerArgsSchema>;
/** Arguments for `get`. */
export type GetArgs = z.infer<typeof GetArgsSchema>;
/** Arguments for `sync`. */
export type SyncArgs = z.infer<typeof SyncArgsSchema>;
/** Arguments for `stats`. */
export type StatsArgs = z.infer<typeof StatsArgsSchema>;
/** Arguments for `configure_client`. */
export type ConfigureClientArgs = z.infer<typeof ConfigureClientArgsSchema>;
/** Arguments for `client_get`. */
export type ClientGetArgs = z.infer<typeof ClientGetArgsSchema>;
/** Arguments for `unconfigure_client`. */
export type UnconfigureClientArgs = z.infer<
  typeof UnconfigureClientArgsSchema
>;

/** Stored server state. */
export type ServerState = z.infer<typeof ServerStateSchema>;
/** Stored client state. */
export type ClientState = z.infer<typeof ClientStateSchema>;
