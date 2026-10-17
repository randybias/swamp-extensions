/**
 * Swamp extension model for a caching apt proxy on one host and its clients.
 *
 * One definition serves any hypervisor or client: every method takes its SSH
 * target and operands, and state is keyed by the canonical `{host, port,
 * user}`. The model installs and configures Apt-Cacher NG on a server, renders
 * one managed `*.conf` fragment plus backend files, and writes one apt snippet
 * on each client. The HTTPS policy is a required input with no default and
 * there is no silent trust-on-first-use: `host_key_policy` is strict-only and
 * the private key is resolved from a vault reference inside the method.
 *
 * @module
 */

import { z } from "npm:zod@4.3.6";
import {
  denoDeps,
  exec,
  type ExecResult,
  HOST_RE,
  sha256Hex,
  type SshDeps,
  type SshTarget,
  upload,
  USER_RE,
} from "./_lib/ssh.ts";
import {
  ACNG_CONF_DIR,
  AptConfigError,
  assertCacheDir,
  assertPassthroughHost,
  CLIENT_SNIPPET_PATH,
  DEFAULT_CACHE_DIR,
  DEFAULT_PORT,
  DETECT_PATH,
  DISTRO_KEY_RE,
  DISTRO_KEYS,
  FRAGMENT_PATH,
  HTTPS_POLICIES,
  type HttpsPolicy,
  isBackendUrl,
  isIpv4,
  isIpv6,
  managedBackendName,
  managedBackendPath,
  parseCacheBytes,
  parseFsFree,
  parseProxyUrl,
  parseReportPage,
  renderBackendFile,
  renderClientSnippet,
  renderDetectScript,
  renderSecurityConf,
  renderServerFragment,
  SECURITY_CONF_PATH,
  type ServerRenderInput,
} from "./_lib/apt.ts";

/** A typed model failure with a stable code. */
export class AptCacheError extends Error {
  /** Stable machine-readable code. */
  readonly code: string;
  /** Creates a typed error. */
  constructor(code: string, message: string) {
    super(message);
    this.name = "AptCacheError";
    this.code = code;
  }
}

/** Reads one secret from a swamp vault. Implemented by the runtime. */
export interface VaultReader {
  /** Returns the secret's plaintext, or throws when it is missing. */
  get(vaultName: string, secretKey: string): Promise<string>;
}

/** The model's dependencies: the SSH transport, clock and secret seam. */
export interface AptCacheDeps extends SshDeps {
  /**
   * Resolves a vault reference to its plaintext. Tests pass a fake; in
   * production it is left unset and the runtime's `context.vaultService` is
   * used instead.
   */
  resolveSecret?: (vaultName: string, secretKey: string) => Promise<string>;
}

/** Production dependencies: the vendored transport and the wall clock. */
export const denoAptCacheDeps: AptCacheDeps = { ...denoDeps };

let deps: AptCacheDeps = denoAptCacheDeps;

/**
 * Replaces the model dependencies (tests only). Returns the previous set so a
 * test can restore it.
 */
export function setDeps(next: Partial<AptCacheDeps>): AptCacheDeps {
  const previous = deps;
  deps = { ...deps, ...next };
  return previous;
}

const GlobalArgsSchema = z.strictObject({});

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
};

const InstallServerArgs = z.strictObject({ ssh: SSH });
const RenderServerArgs = z.strictObject(ServerFields);
const ApplyServerArgs = z.strictObject({ ssh: SSH, ...ServerFields });
const RemoveServerArgs = z.strictObject({
  ssh: SSH,
  confirm_host: z.string().describe(
    "Must equal the SSH host; guards against removing the wrong server.",
  ),
  purge_cache_ack: z.boolean().default(false).describe(
    "Acknowledge deleting the cache directory.",
  ),
});
const GetArgs = z.strictObject({
  ssh: SSH,
  cache_dir: z.string().max(255).default(DEFAULT_CACHE_DIR),
});
const SyncArgs = z.strictObject({ ssh: SSH, ...ServerFields });
const StatsArgs = z.strictObject({
  ssh: SSH,
  window: z.string().min(1).max(32).default("today").describe(
    "Report-page period label to read, e.g. today.",
  ),
  cache_dir: z.string().max(255).default(DEFAULT_CACHE_DIR),
});
const ConfigureClientArgs = z.strictObject({ ssh: SSH, ...ClientFields });
const ClientGetArgs = z.strictObject({ ssh: SSH });
const UnconfigureClientArgs = z.strictObject({ ssh: SSH });

const ServerStateSchema = z.strictObject({
  target: z.string(),
  host: z.string(),
  installed: z.boolean(),
  version: z.string().optional(),
  listen: z.array(z.string()).optional(),
  port: z.number().int().optional(),
  https_policy: z.enum(HTTPS_POLICIES).optional(),
  config_sha256: z.string().optional(),
  applied_at: z.string().optional(),
  observed_at: z.string(),
});

const ClientStateSchema = z.strictObject({
  target: z.string(),
  host: z.string(),
  present: z.boolean(),
  proxy_url: z.string().optional(),
  https_policy: z.enum(HTTPS_POLICIES).optional(),
  snippet_sha256: z.string().optional(),
  verified: z.boolean().optional(),
  observed_at: z.string(),
});

const ObservationSchema = z.strictObject({
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

/** Stored server state. */
export type ServerState = z.infer<typeof ServerStateSchema>;
/** Stored client state. */
export type ClientState = z.infer<typeof ClientStateSchema>;

interface TargetArgs {
  host: string;
  port: number;
  user: string;
  host_key_policy: "strict";
  host_keys: string[];
  ssh_key_ref: { vault: string; key: string };
  connect_timeout_s: number;
}

function hostInstance(host: string): string {
  return host.replace(/[^A-Za-z0-9._-]/g, "_").replace(/\.\./g, "_");
}

/** The canonical `user@host:port` key for a target. */
export function targetKey(a: {
  host: string;
  port: number;
  user: string;
}): string {
  return `${a.user}@${a.host}:${a.port}`;
}

function serverName(host: string): string {
  return `server-${hostInstance(host)}`;
}

function clientName(host: string): string {
  return `client-${hostInstance(host)}`;
}

function observationName(kind: string, host: string): string {
  return `observation-${kind}-${hostInstance(host)}`;
}

async function resolveKey(
  context: { vaultService?: VaultReader },
  ref: { vault: string; key: string },
): Promise<string> {
  if (deps.resolveSecret) {
    const value = await deps.resolveSecret(ref.vault, ref.key);
    if (typeof value !== "string" || value.length === 0) {
      throw new AptCacheError(
        "vault_missing",
        `Vault ${ref.vault} returned no secret for ${ref.key}`,
      );
    }
    return value;
  }
  const service = context.vaultService;
  if (!service || typeof service.get !== "function") {
    throw new AptCacheError(
      "no_vault",
      "No vault service is available to resolve ssh_key_ref; run with a vault",
    );
  }
  const value = await service.get(ref.vault, ref.key);
  if (typeof value !== "string" || value.length === 0) {
    throw new AptCacheError(
      "vault_missing",
      `Vault ${ref.vault} returned no secret for ${ref.key}`,
    );
  }
  return value;
}

function targetOf(a: TargetArgs, privateKey: string): SshTarget {
  return {
    host: a.host,
    port: a.port,
    user: a.user,
    host_key_policy: a.host_key_policy,
    host_keys: a.host_keys,
    private_key: privateKey,
    connect_timeout_s: a.connect_timeout_s,
  };
}

function iso(ms: number): string {
  return new Date(ms).toISOString();
}

/** Strips control characters and collapses whitespace in remote output. */
function sanitize(text: string): string {
  let flattened = "";
  for (const ch of text) {
    const code = ch.codePointAt(0) ?? 0;
    flattened += code < 0x20 || code === 0x7f ? " " : ch;
  }
  return flattened.replace(/\s+/g, " ").trim().slice(0, 400);
}

function requireOk(res: ExecResult, what: string): ExecResult {
  if (res.exit_code !== 0) {
    const detail = sanitize(res.stderr || res.stdout);
    throw new AptCacheError(
      "remote_failed",
      `${what} failed (exit ${res.exit_code})${detail ? `: ${detail}` : ""}`,
    );
  }
  return res;
}

/** Reads a remote file, returning null when it is confirmed absent. */
async function readRemoteFile(
  run: SshDeps,
  t: SshTarget,
  path: string,
): Promise<string | null> {
  const res = await exec(run, t, ["cat", "--", path]);
  if (res.exit_code === 0) return res.stdout;
  const exists = await exec(run, t, ["test", "-e", path]);
  if (exists.exit_code === 1) return null;
  throw new AptCacheError(
    "remote_failed",
    `could not read ${path} (exit ${res.exit_code})`,
  );
}

/** Returns the remote SHA-256 of `path`, or null when it is absent. */
async function remoteSha(
  run: SshDeps,
  t: SshTarget,
  path: string,
): Promise<string | null> {
  const res = await exec(run, t, ["sha256sum", "--", path]);
  if (res.exit_code !== 0) return null;
  const match = /[0-9a-f]{64}/i.exec(res.stdout);
  return match ? match[0].toLowerCase() : null;
}

/** Uploads a file only when its bytes changed. Returns `true` when written. */
async function uploadIfChanged(
  run: SshDeps,
  t: SshTarget,
  path: string,
  content: string,
  mode: string,
): Promise<boolean> {
  const bytes = new TextEncoder().encode(content);
  const digest = await sha256Hex(bytes);
  if (await remoteSha(run, t, path) === digest) return false;
  await upload(run, t, { path, content: bytes, mode });
  return true;
}

/** The server render inputs from method arguments. */
function serverInput(args: {
  listen: string[];
  port: number;
  https_policy: HttpsPolicy;
  passthrough_hosts: string[];
  backends: Record<string, string[]>;
  expire_days: number;
  cache_dir: string;
}): ServerRenderInput {
  return {
    listen: args.listen,
    port: args.port,
    https_policy: args.https_policy,
    passthrough_hosts: args.passthrough_hosts,
    backends: args.backends,
    expire_days: args.expire_days,
    cache_dir: args.cache_dir,
  };
}

/**
 * Checks every cross-field server precondition in-method, because a workflow
 * gate can be bypassed. Throws a typed error naming the offending input.
 */
function assertServerArgs(args: {
  listen: string[];
  listen_any_ack: boolean;
  https_policy: HttpsPolicy;
  passthrough_hosts: string[];
  backends: Record<string, string[]>;
  cache_dir: string;
}): void {
  for (const address of args.listen) {
    if ((address === "0.0.0.0" || address === "::") && !args.listen_any_ack) {
      throw new AptCacheError(
        "wildcard_listen",
        `listen ${address} binds every interface; set listen_any_ack=true to accept that`,
      );
    }
  }
  assertCacheDir(args.cache_dir);
  if (args.https_policy === "passthrough") {
    if (args.passthrough_hosts.length === 0) {
      throw new AptCacheError(
        "config",
        "https_policy passthrough requires a non-empty passthrough_hosts list",
      );
    }
    for (const host of args.passthrough_hosts) assertPassthroughHost(host);
  }
  const scheme = args.https_policy === "https_backends" ? "https" : "http";
  for (const [key, urls] of Object.entries(args.backends)) {
    if (urls.length === 0) {
      throw new AptCacheError("config", `backend ${key} names no mirror`);
    }
    for (const url of urls) {
      if (!isBackendUrl(url, scheme)) {
        throw new AptCacheError(
          "config",
          `backend ${key} URL must be a plain ${scheme} mirror: ${url}`,
        );
      }
    }
  }
}

async function serverState(
  run: SshDeps,
  t: SshTarget,
  cacheDir: string,
  now: number,
): Promise<z.infer<typeof ObservationSchema>> {
  const active = await exec(run, t, [
    "systemctl",
    "is-active",
    "apt-cacher-ng",
  ]);
  const enabled = await exec(run, t, [
    "systemctl",
    "is-enabled",
    "apt-cacher-ng",
  ]);
  const installed = await readRemoteFile(run, t, "/usr/sbin/apt-cacher-ng") !==
    null;
  const listenOut = installed
    ? await exec(run, t, ["ss", "-ltn"])
    : { exit_code: 1, stdout: "", stderr: "" };
  const listening = listenOut.exit_code === 0
    ? parseSsListen(listenOut.stdout)
    : { listen: [], ports: [] };
  const configOut = await readRemoteFile(run, t, FRAGMENT_PATH);
  const passthrough = configOut === null
    ? undefined
    : /^PassThroughPattern:\s*(.*)$/m.exec(configOut)?.[1].trim();
  const cacheOut = installed
    ? await exec(run, t, ["du", "-sb", "--", cacheDir])
    : { exit_code: 1, stdout: "", stderr: "" };
  const dfOut = await exec(run, t, [
    "df",
    "-B1",
    "--output=avail",
    "--",
    cacheDir,
  ]);
  return ObservationSchema.parse({
    target: targetKey(t),
    kind: "get",
    host: t.host,
    installed,
    service_active: active.stdout.trim() === "active",
    service_enabled: enabled.stdout.trim() === "enabled",
    listen: installed ? listening.listen : undefined,
    port: listening.ports[0],
    passthrough_pattern: passthrough,
    cache_bytes: cacheOut.exit_code === 0
      ? parseCacheBytes(cacheOut.stdout)
      : undefined,
    fs_free_bytes: dfOut.exit_code === 0
      ? parseFsFree(dfOut.stdout)
      : undefined,
    observed_at: iso(now),
  });
}

function parseNameListOf(stdout: string): string[] {
  return stdout.split(/\r?\n/).map((l) => l.trim()).filter((l) => l !== "");
}

/** Extracts the listening address and port pairs from `ss -ltn` output. */
export function parseSsListen(stdout: string): {
  listen: string[];
  ports: number[];
} {
  const listen: string[] = [];
  const ports: number[] = [];
  for (const raw of stdout.split(/\r?\n/)) {
    const parts = raw.trim().split(/\s+/);
    if (parts[0] !== "LISTEN" || parts.length < 4) continue;
    const local = parts[3];
    const match = /^(\[.*\]|[^:]+):(\d+)$/.exec(local);
    if (!match) continue;
    const address = match[1].replace(/^\[|\]$/g, "");
    if (!listen.includes(address)) listen.push(address);
    const port = Number(match[2]);
    if (!ports.includes(port)) ports.push(port);
  }
  return { listen, ports };
}

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
  queryData?: (
    predicate: string,
    select?: string,
  ) => Promise<unknown[]>;
  vaultService?: VaultReader;
};

/** Production model definition. */
export const model = {
  type: "@randybias/apt-cache",
  version: "2026.10.17.1",
  description:
    "Install and configure an Apt-Cacher NG caching proxy on one host and point clients' apt at it over SSH, with a required HTTPS policy and one managed config fragment per side. State is keyed by the target's {host, port, user} and no credential is ever placed on argv.",
  globalArguments: GlobalArgsSchema,
  resources: {
    server: {
      description: "Recorded Apt-Cacher NG server state for one host",
      schema: ServerStateSchema,
      lifetime: "infinite" as const,
      garbageCollection: 10,
    },
    client: {
      description: "Recorded apt proxy client state for one host",
      schema: ClientStateSchema,
      lifetime: "infinite" as const,
      garbageCollection: 10,
    },
    observation: {
      description: "Last read-only observation for one host",
      schema: ObservationSchema,
      lifetime: "7d" as const,
      garbageCollection: 20,
    },
  },
  methods: {
    install_server: {
      kind: "action" as const,
      description:
        "Install apt-cacher-ng non-interactively with the HTTP-tunnel debconf prompt answered no. Idempotent: an already-installed package is adopted and its version read. Returns the host and version.",
      arguments: InstallServerArgs,
      execute: async (
        args: z.infer<typeof InstallServerArgs>,
        context: Ctx,
      ) => {
        const key = await resolveKey(context, args.ssh.ssh_key_ref);
        const t = targetOf(args.ssh, key);
        const status = await exec(deps, t, [
          "dpkg-query",
          "-W",
          "-f=${Status}",
          "apt-cacher-ng",
        ]);
        if (!/install ok installed/.test(status.stdout)) {
          context.logger.info("Installing apt-cacher-ng on {host}", {
            host: t.host,
          });
          requireOk(
            await exec(deps, t, [
              "sh",
              "-c",
              "set -e; " +
              "printf '%s\\n' 'apt-cacher-ng apt-cacher-ng/tunnelenable boolean false' | debconf-set-selections; " +
              "DEBIAN_FRONTEND=noninteractive apt-get install -y apt-cacher-ng",
            ]),
            "apt-get install apt-cacher-ng",
          );
        }
        const version = requireOk(
          await exec(deps, t, [
            "dpkg-query",
            "-W",
            "-f=${Version}",
            "apt-cacher-ng",
          ]),
          "dpkg-query apt-cacher-ng",
        ).stdout.trim();
        const now = deps.now();
        const handle = await context.writeResource(
          "server",
          serverName(t.host),
          ServerStateSchema.parse({
            target: targetKey(t),
            host: t.host,
            installed: true,
            version,
            observed_at: iso(now),
          }),
        );
        return {
          dataHandles: [handle],
          result: { host: t.host, version },
        };
      },
    },

    render_server: {
      description:
        "READ-ONLY. Render the managed server fragment and backend files with their SHA-256 and persist the render. Deterministic; no host is contacted.",
      arguments: RenderServerArgs,
      execute: async (
        args: z.infer<typeof RenderServerArgs>,
        context: Ctx,
      ) => {
        assertServerArgs(args);
        const input = serverInput(args);
        const fragment = renderServerFragment(input);
        const scheme = args.https_policy === "https_backends"
          ? "https"
          : "http";
        const backends = Object.keys(args.backends).sort().map((key) => {
          const text = renderBackendFile(args.backends[key], scheme);
          return { key, path: managedBackendPath(key), text };
        });
        const fragmentSha = await sha256Hex(
          new TextEncoder().encode(fragment),
        );
        const backendOut = await Promise.all(
          backends.map(async (b) => ({
            key: b.key,
            path: b.path,
            sha256: await sha256Hex(new TextEncoder().encode(b.text)),
          })),
        );
        const handle = await context.writeResource(
          "server",
          serverName(args.listen[0]),
          ServerStateSchema.parse({
            target: "",
            host: args.listen[0],
            installed: false,
            listen: args.listen,
            port: args.port,
            https_policy: args.https_policy,
            config_sha256: fragmentSha,
            observed_at: iso(deps.now()),
          }),
        );
        return {
          dataHandles: [handle],
          result: {
            fragment: {
              path: FRAGMENT_PATH,
              text: fragment,
              sha256: fragmentSha,
            },
            backends: backends.map((b, i) => ({
              key: b.key,
              path: b.path,
              text: b.text,
              sha256: backendOut[i].sha256,
            })),
          },
        };
      },
    },

    apply_server: {
      kind: "action" as const,
      description:
        "Write the managed fragment and backend files, restart apt-cacher-ng only when they changed, and verify the service, the listen socket and an HTTP fetch. Idempotent: identical bytes mean no write and no restart.",
      arguments: ApplyServerArgs,
      execute: async (args: z.infer<typeof ApplyServerArgs>, context: Ctx) => {
        assertServerArgs(args);
        const key = await resolveKey(context, args.ssh.ssh_key_ref);
        const t = targetOf(args.ssh, key);
        const input = serverInput(args);
        const fragment = renderServerFragment(input);
        const scheme = args.https_policy === "https_backends"
          ? "https"
          : "http";
        const backendFiles = Object.keys(args.backends).sort().map((k) => ({
          path: managedBackendPath(k),
          text: renderBackendFile(args.backends[k], scheme),
        }));
        let changed = false;
        if (await uploadIfChanged(deps, t, FRAGMENT_PATH, fragment, "0644")) {
          changed = true;
        }
        for (const file of backendFiles) {
          if (
            await uploadIfChanged(deps, t, file.path, file.text, "0644")
          ) {
            changed = true;
          }
        }
        if (args.admin_auth_ref) {
          const auth = await resolveKey(context, args.admin_auth_ref);
          const body = renderSecurityConf(auth);
          if (
            await uploadIfChanged(
              deps,
              t,
              SECURITY_CONF_PATH,
              body,
              "0600",
            )
          ) {
            changed = true;
          }
          requireOk(
            await exec(deps, t, [
              "chown",
              "apt-cacher-ng:apt-cacher-ng",
              SECURITY_CONF_PATH,
            ]),
            "chown security.conf",
          );
        }
        if (changed) {
          requireOk(
            await exec(deps, t, [
              "systemctl",
              "restart",
              "apt-cacher-ng",
            ]),
            "systemctl restart apt-cacher-ng",
          );
        }
        // Verify in-method: a workflow gate can be bypassed.
        const active = requireOk(
          await exec(deps, t, ["systemctl", "is-active", "apt-cacher-ng"]),
          "systemctl is-active apt-cacher-ng",
        ).stdout.trim();
        if (active !== "active") {
          throw new AptCacheError(
            "verify_failed",
            `apt-cacher-ng is ${active} after apply`,
          );
        }
        const listenOut = requireOk(
          await exec(deps, t, ["ss", "-ltn"]),
          "ss -ltn",
        ).stdout;
        for (const address of args.listen) {
          const port = `:${args.port}\\b`;
          if (
            !listenOut.includes(`${address}:${args.port}`) &&
            !new RegExp(port).test(listenOut)
          ) {
            throw new AptCacheError(
              "verify_failed",
              `apt-cacher-ng is not listening on ${address}:${args.port}`,
            );
          }
        }
        const fetch = await exec(deps, t, [
          "curl",
          "-fsS",
          "--max-time",
          "15",
          "-o",
          "/dev/null",
          `http://127.0.0.1:${args.port}/acng-report.html`,
        ]);
        if (fetch.exit_code !== 0) {
          throw new AptCacheError(
            "verify_failed",
            `the proxy did not answer on 127.0.0.1:${args.port}`,
          );
        }
        const now = deps.now();
        const fragmentSha = await sha256Hex(new TextEncoder().encode(fragment));
        const handle = await context.writeResource(
          "server",
          serverName(t.host),
          ServerStateSchema.parse({
            target: targetKey(t),
            host: t.host,
            installed: true,
            listen: args.listen,
            port: args.port,
            https_policy: args.https_policy,
            config_sha256: fragmentSha,
            applied_at: iso(now),
            observed_at: iso(now),
          }),
        );
        return {
          dataHandles: [handle],
          result: {
            host: t.host,
            changed,
            listen: args.listen,
            port: args.port,
            https_policy: args.https_policy,
          },
        };
      },
    },

    remove_server: {
      kind: "action" as const,
      description:
        "DESTRUCTIVE. Stop and disable apt-cacher-ng, remove the managed fragment and backend files, and purge the package; the cache directory is deleted only with purge_cache_ack. Re-running on a host with nothing installed is a clean no-op.",
      arguments: RemoveServerArgs,
      execute: async (args: z.infer<typeof RemoveServerArgs>, context: Ctx) => {
        if (args.confirm_host !== args.ssh.host) {
          throw new AptCacheError(
            "confirm",
            `confirm_host ${args.confirm_host} does not match the SSH host ${args.ssh.host}`,
          );
        }
        const key = await resolveKey(context, args.ssh.ssh_key_ref);
        const t = targetOf(args.ssh, key);
        const status = await exec(deps, t, [
          "dpkg-query",
          "-W",
          "-f=${Status}",
          "apt-cacher-ng",
        ]);
        const installed = /install ok installed/.test(status.stdout);
        if (!installed) {
          context.logger.info(
            "apt-cacher-ng is not installed on {host}; remove is a no-op",
            { host: t.host },
          );
          const handle = await context.writeResource(
            "server",
            serverName(t.host),
            ServerStateSchema.parse({
              target: targetKey(t),
              host: t.host,
              installed: false,
              observed_at: iso(deps.now()),
            }),
          );
          return {
            dataHandles: [handle],
            result: { host: t.host, removed: false, cache_purged: false },
          };
        }
        await exec(deps, t, ["systemctl", "stop", "apt-cacher-ng"]);
        await exec(deps, t, ["systemctl", "disable", "apt-cacher-ng"]);
        requireOk(
          await exec(deps, t, [
            "sh",
            "-c",
            "DEBIAN_FRONTEND=noninteractive apt-get purge -y apt-cacher-ng",
          ]),
          "apt-get purge apt-cacher-ng",
        );
        for (const name of listManagedConfNames()) {
          await exec(deps, t, ["rm", "-f", "--", `${ACNG_CONF_DIR}/${name}`]);
        }
        await exec(deps, t, ["rm", "-f", "--", SECURITY_CONF_PATH]);
        let cachePurged = false;
        if (args.purge_cache_ack) {
          requireOk(
            await exec(deps, t, ["rm", "-rf", "--", DEFAULT_CACHE_DIR]),
            "rm -rf cache",
          );
          cachePurged = true;
        }
        context.logger.info("Removed apt-cacher-ng from {host}", {
          host: t.host,
        });
        const handle = await context.writeResource(
          "server",
          serverName(t.host),
          ServerStateSchema.parse({
            target: targetKey(t),
            host: t.host,
            installed: false,
            observed_at: iso(deps.now()),
          }),
        );
        return {
          dataHandles: [handle],
          result: { host: t.host, removed: true, cache_purged: cachePurged },
        };
      },
    },

    get: {
      description:
        "READ-ONLY. Report service state, listen sockets, a config digest, cache size and filesystem free space, and persist the observation.",
      arguments: GetArgs,
      execute: async (args: z.infer<typeof GetArgs>, context: Ctx) => {
        const key = await resolveKey(context, args.ssh.ssh_key_ref);
        const t = targetOf(args.ssh, key);
        const now = deps.now();
        const base = await serverState(deps, t, args.cache_dir, now);
        const observation = ObservationSchema.parse({
          ...base,
          kind: "get",
          config_sha256: await remoteSha(deps, t, FRAGMENT_PATH) ??
            undefined,
          observed_at: iso(now),
        });
        const handle = await context.writeResource(
          "observation",
          observationName("get", t.host),
          observation,
        );
        return { dataHandles: [handle], result: observation };
      },
    },

    sync: {
      description:
        "READ-ONLY. Re-render the managed fragment, compare it with the live file, flag a PassThroughPattern the model did not render, and persist the observation.",
      arguments: SyncArgs,
      execute: async (args: z.infer<typeof SyncArgs>, context: Ctx) => {
        assertServerArgs(args);
        const key = await resolveKey(context, args.ssh.ssh_key_ref);
        const t = targetOf(args.ssh, key);
        const now = deps.now();
        const expected = renderServerFragment(serverInput(args));
        const expectedSha = await sha256Hex(new TextEncoder().encode(expected));
        const liveSha = await remoteSha(deps, t, FRAGMENT_PATH);
        const liveText = await readRemoteFile(deps, t, FRAGMENT_PATH);
        const livePattern = liveText === null
          ? undefined
          : /^PassThroughPattern:\s*(.*)$/m.exec(liveText)?.[1].trim();
        const expectedPattern = /^PassThroughPattern:\s*(.*)$/m.exec(
          expected,
        )![1].trim();
        const drift: string[] = [];
        if (liveSha === null) drift.push("fragment:missing");
        else if (liveSha !== expectedSha) drift.push("fragment:edited");
        if (livePattern !== undefined && livePattern !== expectedPattern) {
          drift.push(`passthrough:${livePattern}`);
        }
        const base = await serverState(deps, t, args.cache_dir, now);
        const observation = ObservationSchema.parse({
          ...base,
          kind: "sync",
          config_sha256: liveSha ?? undefined,
          expected_config_sha256: expectedSha,
          config_matches: liveSha === expectedSha,
          passthrough_pattern: livePattern,
          drift,
          observed_at: iso(now),
        });
        const handle = await context.writeResource(
          "observation",
          observationName("sync", t.host),
          observation,
        );
        return {
          dataHandles: [handle],
          result: { in_sync: drift.length === 0, drift },
        };
      },
    },

    stats: {
      description:
        "READ-ONLY. Read the report page over the server's loopback for hit/miss counts and bytes over a window, plus cache size and free space, and persist the observation. Fails closed on an unrecognised report page.",
      arguments: StatsArgs,
      execute: async (args: z.infer<typeof StatsArgs>, context: Ctx) => {
        const key = await resolveKey(context, args.ssh.ssh_key_ref);
        const t = targetOf(args.ssh, key);
        const now = deps.now();
        const record = await context.readResource(serverName(t.host)) as
          | ServerState
          | null;
        const port = record?.port ?? DEFAULT_PORT;
        const report = requireOk(
          await exec(deps, t, [
            "curl",
            "-fsS",
            "--max-time",
            "15",
            `http://127.0.0.1:${port}/acng-report.html`,
          ]),
          "curl acng-report.html",
        );
        let totals;
        try {
          totals = parseReportPage(report.stdout, args.window);
        } catch (e) {
          throw new AptCacheError(
            "parse_failed",
            e instanceof AptConfigError
              ? e.message
              : "could not parse the report page",
          );
        }
        const cacheOut = await exec(deps, t, [
          "du",
          "-sb",
          "--",
          args.cache_dir,
        ]);
        const dfOut = await exec(deps, t, [
          "df",
          "-B1",
          "--output=avail",
          "--",
          args.cache_dir,
        ]);
        const cacheBytes = cacheOut.exit_code === 0
          ? parseCacheBytes(cacheOut.stdout)
          : 0;
        const fsFree = dfOut.exit_code === 0 ? parseFsFree(dfOut.stdout) : 0;
        const totalReq = totals.hits + totals.misses;
        const hitRatio = totalReq > 0 ? totals.hits / totalReq : 0;
        const observation = ObservationSchema.parse({
          target: targetKey(t),
          kind: "stats",
          host: t.host,
          window: args.window,
          requests: totalReq,
          hits: totals.hits,
          misses: totals.misses,
          bytes_from_cache: totals.bytes_from_cache,
          bytes_upstream: totals.bytes_upstream,
          hit_ratio: hitRatio,
          cache_bytes: cacheBytes,
          fs_free_bytes: fsFree,
          observed_at: iso(now),
        });
        const handle = await context.writeResource(
          "observation",
          observationName("stats", t.host),
          observation,
        );
        return { dataHandles: [handle], result: observation };
      },
    },

    configure_client: {
      kind: "action" as const,
      description:
        "Write the managed apt snippet on a client, verify it with apt-config dump and optionally apt-get update, and persist the client state. Refuses a conflicting proxy file without override_existing_ack and a policy that disagrees with a recorded server for the proxy host.",
      arguments: ConfigureClientArgs,
      execute: async (
        args: z.infer<typeof ConfigureClientArgs>,
        context: Ctx,
      ) => {
        const proxy = parseProxyUrl(args.proxy_url);
        for (const host of args.bypass_hosts) assertPassthroughHost(host);
        const key = await resolveKey(context, args.ssh.ssh_key_ref);
        const t = targetOf(args.ssh, key);
        const recordedPolicy = await serverPolicyForHost(
          context,
          proxy.address,
        );
        if (
          recordedPolicy !== undefined && recordedPolicy !== args.https_policy
        ) {
          throw new AptCacheError(
            "policy_mismatch",
            `https_policy ${args.https_policy} does not match the recorded server policy ${recordedPolicy} for ${proxy.address}`,
          );
        }
        const conflicts = await proxyConflicts(deps, t);
        if (conflicts.length > 0 && !args.override_existing_ack) {
          throw new AptCacheError(
            "conflict",
            `another apt configuration sets a proxy: ${
              conflicts.join(", ")
            }; pass override_existing_ack=true`,
          );
        }
        const snippet = renderClientSnippet({
          proxy_url: proxy.url,
          https_policy: args.https_policy,
          bypass_hosts: args.bypass_hosts,
          fallback_direct: args.fallback_direct,
        });
        let changed = false;
        if (
          await uploadIfChanged(
            deps,
            t,
            CLIENT_SNIPPET_PATH,
            snippet,
            "0644",
          )
        ) {
          changed = true;
        }
        if (args.fallback_direct) {
          if (
            await uploadIfChanged(
              deps,
              t,
              DETECT_PATH,
              renderDetectScript(proxy.url),
              "0755",
            )
          ) {
            changed = true;
          }
        }
        let verified = await verifyClientProxy(deps, t, proxy.url);
        if (verified && args.verify_update) {
          const update = await exec(deps, t, ["apt-get", "update"]);
          verified = update.exit_code === 0;
          if (!verified && !args.fallback_direct) {
            await rollbackClient(deps, t);
            throw new AptCacheError(
              "verify_failed",
              `apt-get update failed after writing the snippet (exit ${update.exit_code})`,
            );
          }
        }
        if (!verified && !args.fallback_direct) {
          await rollbackClient(deps, t);
          throw new AptCacheError(
            "verify_failed",
            "the managed snippet is not the proxy apt-config reports",
          );
        }
        const now = deps.now();
        const handle = await context.writeResource(
          "client",
          clientName(t.host),
          ClientStateSchema.parse({
            target: targetKey(t),
            host: t.host,
            present: true,
            proxy_url: proxy.url,
            https_policy: args.https_policy,
            snippet_sha256: await sha256Hex(
              new TextEncoder().encode(snippet),
            ),
            verified,
            observed_at: iso(now),
          }),
        );
        return {
          dataHandles: [handle],
          result: {
            client: t.host,
            changed,
            proxy_url: proxy.url,
            https_policy: args.https_policy,
            verified,
          },
        };
      },
    },

    client_get: {
      description:
        "READ-ONLY. Report the effective Acquire::*::Proxy values on a client, whether the managed snippet is the one in force, and any conflicting file, and persist the observation.",
      arguments: ClientGetArgs,
      execute: async (args: z.infer<typeof ClientGetArgs>, context: Ctx) => {
        const key = await resolveKey(context, args.ssh.ssh_key_ref);
        const t = targetOf(args.ssh, key);
        const now = deps.now();
        const dump = requireOk(
          await exec(deps, t, ["apt-config", "dump"]),
          "apt-config dump",
        ).stdout;
        const proxyValues = parseAptConfigDump(dump);
        const record = await context.readResource(clientName(t.host)) as
          | ClientState
          | null;
        const liveSha = await remoteSha(deps, t, CLIENT_SNIPPET_PATH);
        const managedInForce = record?.snippet_sha256 !== undefined &&
          liveSha === record.snippet_sha256;
        const conflicts = await proxyConflicts(deps, t);
        const observation = ObservationSchema.parse({
          target: targetKey(t),
          kind: "client_get",
          host: t.host,
          proxy_values: proxyValues,
          managed_snippet_in_force: managedInForce,
          conflicts,
          observed_at: iso(now),
        });
        const handle = await context.writeResource(
          "observation",
          observationName("client_get", t.host),
          observation,
        );
        return { dataHandles: [handle], result: observation };
      },
    },

    unconfigure_client: {
      kind: "action" as const,
      description:
        "Remove the managed apt snippet and auto-detect script and verify apt no longer uses the managed proxy. Re-running when nothing is present is a clean no-op.",
      arguments: UnconfigureClientArgs,
      execute: async (
        args: z.infer<typeof UnconfigureClientArgs>,
        context: Ctx,
      ) => {
        const key = await resolveKey(context, args.ssh.ssh_key_ref);
        const t = targetOf(args.ssh, key);
        const present = await readRemoteFile(deps, t, CLIENT_SNIPPET_PATH) !==
          null;
        if (!present) {
          const handle = await context.writeResource(
            "client",
            clientName(t.host),
            ClientStateSchema.parse({
              target: targetKey(t),
              host: t.host,
              present: false,
              observed_at: iso(deps.now()),
            }),
          );
          return {
            dataHandles: [handle],
            result: { client: t.host, removed: false },
          };
        }
        await exec(deps, t, ["rm", "-f", "--", CLIENT_SNIPPET_PATH]);
        await exec(deps, t, ["rm", "-f", "--", DETECT_PATH]);
        const dump = requireOk(
          await exec(deps, t, ["apt-config", "dump"]),
          "apt-config dump",
        ).stdout;
        const stillManaged = /Acquire::http::Proxy-Auto-Detect/.test(dump) ||
          parseAptConfigDump(dump)["Acquire::http::Proxy"] !== undefined;
        if (stillManaged && (await proxyConflicts(deps, t)).length > 0) {
          throw new AptCacheError(
            "verify_failed",
            "another file still sets an apt proxy after removing the managed snippet",
          );
        }
        const handle = await context.writeResource(
          "client",
          clientName(t.host),
          ClientStateSchema.parse({
            target: targetKey(t),
            host: t.host,
            present: false,
            observed_at: iso(deps.now()),
          }),
        );
        return {
          dataHandles: [handle],
          result: { client: t.host, removed: true },
        };
      },
    },
  },
};

/** Test factory: install dependencies and return the model. */
export function createModel(overrides: Partial<AptCacheDeps> = {}) {
  setDeps(overrides);
  return model;
}

function listManagedConfNames(): string[] {
  return [
    FRAGMENT_PATH.split("/").pop() as string,
    ...DISTRO_KEYS.map((k) => managedBackendName(k)),
  ];
}

/** Finds a recorded server record whose host or listen covers `host`. */
async function serverPolicyForHost(
  context: Ctx,
  host: string,
): Promise<HttpsPolicy | undefined> {
  if (!context.queryData) return undefined;
  let records: unknown[];
  try {
    records = await context.queryData('specName == "server"');
  } catch {
    return undefined;
  }
  for (const raw of records) {
    const record = raw as {
      attributes?: { host?: string; listen?: string[]; https_policy?: string };
    };
    const attributes = record.attributes ?? {};
    const covers = attributes.host === host ||
      (attributes.listen ?? []).includes(host);
    if (covers && attributes.https_policy !== undefined) {
      return attributes.https_policy as HttpsPolicy;
    }
  }
  return undefined;
}

/** Files in apt.conf.d, other than ours, that set a proxy. */
async function proxyConflicts(
  run: SshDeps,
  t: SshTarget,
): Promise<string[]> {
  const res = await exec(run, t, [
    "sh",
    "-c",
    "grep -lE 'Acquire::(http|https)::Proxy' /etc/apt/apt.conf.d/* 2>/dev/null | grep -v 90apt-cache-proxy || true",
  ]);
  return parseNameListOf(res.stdout);
}

/** True when apt-config dump reports our proxy as effective. */
async function verifyClientProxy(
  run: SshDeps,
  t: SshTarget,
  proxyUrl: string,
): Promise<boolean> {
  const res = await exec(run, t, ["apt-config", "dump"]);
  if (res.exit_code !== 0) return false;
  const values = parseAptConfigDump(res.stdout);
  return values["Acquire::http::Proxy"] === proxyUrl;
}

async function rollbackClient(run: SshDeps, t: SshTarget): Promise<void> {
  await exec(run, t, ["rm", "-f", "--", CLIENT_SNIPPET_PATH]);
  await exec(run, t, ["rm", "-f", "--", DETECT_PATH]);
}

/** Parses `apt-config dump` lines into a flat `Key "value";` record. */
export function parseAptConfigDump(text: string): Record<string, string> {
  const out: Record<string, string> = {};
  for (const raw of text.split(/\r?\n/)) {
    const match = /^([A-Za-z0-9_:.-]+)\s+"(.*)";\s*$/.exec(raw.trim());
    if (match) out[match[1]] = match[2];
  }
  return out;
}
