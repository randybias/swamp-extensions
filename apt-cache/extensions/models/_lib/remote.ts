/**
 * The host-operations layer: the dependency seam, target naming, the small
 * remote read/write helpers, and the parsers and host probes the methods share.
 * Every function here takes the transport explicitly (`run`) so it can be
 * tested with a fake; only the module-level `deps` is the production seam the
 * model methods read.
 *
 * @module
 */

import {
  denoDeps,
  exec,
  type ExecResult,
  sha256Hex,
  type SshDeps,
  type SshTarget,
  upload,
} from "./ssh.ts";
import {
  assertCacheDir,
  CLIENT_SNIPPET_PATH,
  DETECT_PATH,
  DISTRO_KEYS,
  FRAGMENT_PATH,
  type HttpsPolicy,
  managedBackendName,
  parseCacheBytes,
  parseFsFree,
} from "./apt.ts";

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
interface VaultReader {
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

const denoAptCacheDeps: AptCacheDeps = { ...denoDeps };

/** The active dependencies. Replaced by {@link setDeps} in tests. */
export let deps: AptCacheDeps = denoAptCacheDeps;

/**
 * Replaces the model dependencies (tests only). Returns the previous set so a
 * test can restore it.
 */
export function setDeps(next: Partial<AptCacheDeps>): AptCacheDeps {
  const previous = deps;
  deps = { ...deps, ...next };
  return previous;
}

/** The method context surface the model uses. */
export interface Ctx {
  /** Structured logger. */
  logger: {
    /** Logs at info. */
    info(msg: string, ...args: unknown[]): void;
    /** Logs a warning. */
    warning(msg: string, ...args: unknown[]): void;
  };
  /** Persists a resource. */
  writeResource(
    spec: string,
    name: string,
    data: Record<string, unknown>,
  ): Promise<{ name: string }>;
  /** Reads the latest version of a resource. */
  readResource(
    name: string,
    version?: number,
  ): Promise<Record<string, unknown> | null>;
  /** CEL query across models. */
  queryData?: (predicate: string, select?: string) => Promise<unknown[]>;
  /** Vault service, used when no `resolveSecret` is injected. */
  vaultService?: VaultReader;
}

/** The argument shape `targetOf` needs. */
interface TargetArgs {
  host: string;
  port: number;
  user: string;
  host_key_policy: "strict";
  host_keys: string[];
  ssh_key_ref: { vault: string; key: string };
  connect_timeout_s: number;
}

/** The three fields that key a record: `{user, host, port}`. */
interface NamedTarget {
  host: string;
  port: number;
  user: string;
}

/** The canonical `user@host:port` key for a target. */
export function targetKey(a: NamedTarget): string {
  return `${a.user}@${a.host}:${a.port}`;
}

/** A filesystem-safe form of `host`. */
function hostInstance(host: string): string {
  return host.replace(/[^A-Za-z0-9._-]/g, "_").replace(/\.\./g, "_");
}

/** A filesystem-safe form of the whole target key. */
function targetInstance(t: NamedTarget): string {
  return `${hostInstance(t.user)}-${hostInstance(t.host)}-${t.port}`;
}

/** Resource name for a host's server record. */
export function serverName(t: NamedTarget): string {
  return `server-${targetInstance(t)}`;
}

/** Resource name for a host's client record. */
export function clientName(t: NamedTarget): string {
  return `client-${targetInstance(t)}`;
}

/** Resource name for a host's observation of `kind`. */
export function observationName(kind: string, t: NamedTarget): string {
  return `observation-${kind}-${targetInstance(t)}`;
}

/**
 * Resolves a vault reference to plaintext, preferring an injected
 * `resolveSecret` and falling back to the context's vault service.
 */
export async function resolveKey(
  context: { vaultService?: VaultReader },
  ref: { vault: string; key: string },
): Promise<string> {
  const injected = deps.resolveSecret;
  if (injected) {
    const value = await injected(ref.vault, ref.key);
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

/** Builds an `SshTarget` from the method's SSH arguments and a private key. */
export function targetOf(a: TargetArgs, privateKey: string): SshTarget {
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

/** Formats a millisecond epoch as an ISO-8601 string. */
export function iso(ms: number): string {
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

/** Throws a typed error unless the remote command exited 0. */
export function requireOk(res: ExecResult, what: string): ExecResult {
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
export async function readRemoteFile(
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

/**
 * Returns the remote SHA-256 of `path`, or null when it is absent. A
 * `sha256sum` that fails on a file that exists is a typed error, not absence:
 * conflating the two would let a failed probe overwrite a backup or report a
 * file removed that is still there.
 */
export async function remoteSha(
  run: SshDeps,
  t: SshTarget,
  path: string,
): Promise<string | null> {
  const res = await exec(run, t, ["sha256sum", "--", path]);
  if (res.exit_code === 0) {
    const match = /[0-9a-f]{64}/i.exec(res.stdout);
    if (match) return match[0].toLowerCase();
  }
  const exists = await exec(run, t, ["test", "-e", path]);
  if (exists.exit_code === 1) return null;
  throw new AptCacheError(
    "remote_failed",
    `could not hash ${path} (exit ${res.exit_code})`,
  );
}

/** Uploads a file only when its bytes changed. Returns `true` when written. */
export async function uploadIfChanged(
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

/** A listening address and port pair parsed from `ss -ltn`. */
interface ListenPair {
  /** Bare address, without IPv6 brackets. */
  address: string;
  /** TCP port. */
  port: number;
}

/** Extracts the listening address and port pairs from `ss -ltn` output. */
export function parseSsListen(stdout: string): {
  listen: string[];
  ports: number[];
  pairs: ListenPair[];
} {
  const listen: string[] = [];
  const ports: number[] = [];
  const pairs: ListenPair[] = [];
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
    if (!pairs.some((p) => p.address === address && p.port === port)) {
      pairs.push({ address, port });
    }
  }
  return { listen, ports, pairs };
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

/** Extracts the `PassThroughPattern` value from a fragment body. */
export function passThroughPatternOf(config: string): string | undefined {
  return /^PassThroughPattern:\s*(.*)$/m.exec(config)?.[1].trim();
}

/** The server file whose presence means apt-cacher-ng is installed. */
const INSTALLED_PATH = "/usr/sbin/apt-cacher-ng";

/** The host-observed server fields shared by `get` and `sync`. */
interface HostState {
  /** Whether the package binary is present. */
  installed: boolean;
  /** Whether the service reports active. */
  service_active: boolean;
  /** Whether the service reports enabled. */
  service_enabled: boolean;
  /** Listening addresses, when installed. */
  listen?: string[];
  /** First listening port, when installed. */
  port?: number;
  /** Rendered `PassThroughPattern`, when the fragment exists. */
  passthrough_pattern?: string;
  /** Cache directory bytes, when readable. */
  cache_bytes?: number;
  /** Filesystem free bytes, when readable. */
  fs_free_bytes?: number;
}

/** Probes the server host for the fields `get` and `sync` record. */
export async function serverState(
  run: SshDeps,
  t: SshTarget,
  cacheDir: string,
): Promise<HostState> {
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
  const installed = (await readRemoteFile(run, t, INSTALLED_PATH)) !== null;
  const listenOut = installed ? await exec(run, t, ["ss", "-ltn"]) : undefined;
  const listening = listenOut && listenOut.exit_code === 0
    ? parseSsListen(listenOut.stdout)
    : { listen: [], ports: [] };
  const configOut = await readRemoteFile(run, t, FRAGMENT_PATH);
  const cacheOut = installed
    ? await exec(run, t, ["du", "-sb", "--", cacheDir])
    : undefined;
  const dfOut = await exec(run, t, [
    "df",
    "-B1",
    "--output=avail",
    "--",
    cacheDir,
  ]);
  return {
    installed,
    service_active: active.stdout.trim() === "active",
    service_enabled: enabled.stdout.trim() === "enabled",
    listen: installed ? listening.listen : undefined,
    port: listening.ports[0],
    passthrough_pattern: configOut === null
      ? undefined
      : passThroughPatternOf(configOut),
    cache_bytes: cacheOut && cacheOut.exit_code === 0
      ? parseCacheBytes(cacheOut.stdout)
      : undefined,
    fs_free_bytes: dfOut.exit_code === 0
      ? parseFsFree(dfOut.stdout)
      : undefined,
  };
}

/** A filename list from newline-separated command output. */
function parseNameListOf(stdout: string): string[] {
  return stdout.split(/\r?\n/).map((l) => l.trim()).filter((l) => l !== "");
}

/** Files in apt.conf.d, other than ours, that set a proxy. */
export async function proxyConflicts(
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

/** True when apt-config dump reports every managed key at its expected value. */
export async function verifyClientProxy(
  run: SshDeps,
  t: SshTarget,
  expected: Record<string, string>,
): Promise<boolean> {
  const res = await exec(run, t, ["apt-config", "dump"]);
  if (res.exit_code !== 0) return false;
  const values = parseAptConfigDump(res.stdout);
  return Object.entries(expected).every(([key, value]) =>
    values[key] === value
  );
}

/** The prior managed client files, or null when absent. */
interface ClientSnapshot {
  /** Prior snippet body, or null. */
  snippet: string | null;
  /** Prior auto-detect script body, or null. */
  detect: string | null;
}

/** Reads the prior managed client files. */
export async function snapshotClient(
  run: SshDeps,
  t: SshTarget,
): Promise<ClientSnapshot> {
  return {
    snippet: await readRemoteFile(run, t, CLIENT_SNIPPET_PATH),
    detect: await readRemoteFile(run, t, DETECT_PATH),
  };
}

/** Restores the prior managed files, or removes them when they were absent. */
export async function restoreClient(
  run: SshDeps,
  t: SshTarget,
  snapshot: ClientSnapshot,
): Promise<void> {
  const files: [string, string | null, string][] = [
    [CLIENT_SNIPPET_PATH, snapshot.snippet, "0644"],
    [DETECT_PATH, snapshot.detect, "0755"],
  ];
  for (const [path, content, mode] of files) {
    if (content === null) {
      requireOk(await exec(run, t, ["rm", "-f", "--", path]), `rm ${path}`);
    } else {
      await uploadIfChanged(run, t, path, content, mode);
    }
  }
}

/** The sidecar file holding a pre-existing managed file's original bytes. */
export function backupPath(path: string): string {
  return `${path}.apt-cache.bak`;
}

/** The result of writing one managed file. */
interface ManagedWrite {
  /** SHA-256 of the bytes written; recorded for the removal guard. */
  sha256: string;
  /** Whether the write changed the file on disk. */
  changed: boolean;
}

/**
 * Writes a managed file, saving pre-existing content to a sidecar once, and
 * returns the SHA-256 of the bytes written. A file that is absent, or whose
 * digest equals what this model last recorded for it (`priorSha`) or is about
 * to write, is not backed up: those bytes are the model's own, so a second
 * apply must not turn them into a "backup" that a later remove restores.
 */
export async function writeManagedFile(
  run: SshDeps,
  t: SshTarget,
  path: string,
  content: string,
  mode: string,
  priorSha?: string,
): Promise<ManagedWrite> {
  const sha256 = await sha256Hex(new TextEncoder().encode(content));
  const current = await remoteSha(run, t, path);
  const ours = current === null || current === sha256 || current === priorSha;
  const backup = backupPath(path);
  if (!ours && (await remoteSha(run, t, backup)) === null) {
    requireOk(
      await exec(run, t, ["cp", "-p", "--", path, backup]),
      `back up ${path}`,
    );
  }
  const changed = await uploadIfChanged(run, t, path, content, mode);
  return { sha256, changed };
}

/**
 * Removes a file the model wrote, or restores the original it backed up.
 * Leaves the file untouched when its current digest differs from
 * `recordedSha`: that means an admin edit, or a file this model never wrote.
 */
export async function removeOrRestoreManaged(
  run: SshDeps,
  t: SshTarget,
  path: string,
  recordedSha: string | undefined,
): Promise<"removed" | "restored" | "kept"> {
  const current = await remoteSha(run, t, path);
  if (current === null) return "removed";
  if (recordedSha === undefined || current !== recordedSha) return "kept";
  const backup = backupPath(path);
  if ((await remoteSha(run, t, backup)) !== null) {
    requireOk(
      await exec(run, t, ["mv", "-f", "--", backup, path]),
      `restore ${path}`,
    );
    return "restored";
  }
  requireOk(await exec(run, t, ["rm", "-f", "--", path]), `rm ${path}`);
  return "removed";
}

/**
 * Deletes a validated cache directory when it still exists. Refuses a symlink
 * (never follow it). `apt-get purge` already removes the package default, so
 * this covers a custom `cache_dir`.
 */
export async function removeCacheDir(
  run: SshDeps,
  t: SshTarget,
  dir: string,
): Promise<void> {
  assertCacheDir(dir);
  const link = await exec(run, t, ["test", "-L", dir]);
  if (link.exit_code === 0) {
    throw new AptCacheError(
      "unsafe_cache_dir",
      `refusing to delete ${dir}: it is a symlink`,
    );
  }
  const present = await exec(run, t, ["test", "-d", dir]);
  if (present.exit_code !== 0) return;
  requireOk(await exec(run, t, ["rm", "-rf", "--", dir]), "rm -rf cache");
}

/** The managed config filenames, including the built-in backend files. */
export function listManagedConfNames(): string[] {
  return [
    FRAGMENT_PATH.split("/").pop() as string,
    "backends_debian",
    "backends_ubuntu",
    ...DISTRO_KEYS.map((k) => managedBackendName(k)),
  ];
}

/**
 * Finds a recorded server record whose host or listen covers `host`, scoped to
 * this model type. Refuses (unless `ack`) when there is no query API or the
 * query fails, rather than silently skipping the check.
 */
export async function serverPolicyForHost(
  context: Ctx,
  host: string,
  ack: boolean,
): Promise<HttpsPolicy | undefined> {
  if (!context.queryData) {
    if (ack) return undefined;
    throw new AptCacheError(
      "policy_unverifiable",
      "cannot verify the client HTTPS policy against a recorded server (no query API); pass policy_check_ack=true to proceed",
    );
  }
  let records: unknown[];
  try {
    records = await context.queryData(
      'modelType == "@randybias/apt-cache" && specName == "server"',
    );
  } catch (error) {
    if (ack) return undefined;
    throw new AptCacheError(
      "policy_unverifiable",
      `could not query recorded servers to verify the HTTPS policy: ${
        error instanceof Error ? error.message : "unknown error"
      }; pass policy_check_ack=true to proceed`,
    );
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
