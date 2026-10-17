/**
 * Generic SSH transport for swamp extensions.
 *
 * Three operations, all under an explicit host-key policy and with no
 * credential on the command line: run one argv vector on a remote host, push
 * bytes to a remote path atomically, and wait until a host answers SSH with
 * acceptable host keys. A private key is loaded into a short-lived ssh-agent
 * over stdin; a password is delivered through a temporary askpass helper and
 * an environment variable. Neither ever appears in a spawned argv.
 *
 * The module is self-contained: it imports nothing from the rest of the
 * extension, so it can be copied unchanged into a consuming extension's
 * `_lib/` directory.
 *
 * @module
 */

/** How observed host keys are treated. */
export type HostKeyPolicy = "strict" | "insecure_tofu";

/** Result of running an external command. */
export interface CommandResult {
  /** Process exit code. */
  code: number;
  /** Captured standard output. */
  stdout: string;
  /** Captured standard error. */
  stderr: string;
  /** Set when the output cap was reached in truncate mode. */
  truncated?: boolean;
  /** Set when the command was killed for exceeding its timeout. */
  timedOut?: boolean;
}

/** Options for one external command. */
export interface RunOptions {
  /** Bytes or text written to the command's standard input. */
  stdin?: Uint8Array | string;
  /** Extra environment variables; merged with the inherited environment. */
  env?: Record<string, string>;
  /** Cap in bytes on each captured stream; the runner throws when exceeded. */
  maxOutputBytes?: number;
  /** Stop at `maxOutputBytes` and mark the result truncated instead of throwing. */
  truncate?: boolean;
  /** Kill the command after this many milliseconds and mark it timed out. */
  timeoutMs?: number;
}

/** Per-call limits the transport entry points pass to {@link runRemote}. */
type RunLimits = Omit<RunOptions, "env">;

/** Runs an external command; injectable so tests spawn no process. */
export type CommandRunner = (
  cmd: string,
  args: string[],
  options?: RunOptions,
) => Promise<CommandResult>;

/** A host key as reported by `ssh-keyscan` or listed in `known_hosts`. */
export interface HostKey {
  /** Host pattern field, when the line carried one (e.g. `[host]:2222`). */
  host?: string;
  /** Key algorithm, e.g. `ssh-ed25519`. */
  type: string;
  /** Base64 public key blob. */
  key: string;
}

/** An SSH target plus the policy and credential used to reach it. */
export interface SshTarget {
  /** Hostname or IP literal. */
  host: string;
  /** SSH port, 1 to 65535. */
  port: number;
  /** Remote user name. */
  user: string;
  /** Required; there is no default. */
  host_key_policy: HostKeyPolicy;
  /** Pinned `ssh-keyscan`-format lines; required and authoritative for `strict`. */
  host_keys?: string[];
  /** Private key text; loaded into a short-lived ssh-agent over stdin. */
  private_key?: string;
  /** Password text; delivered through an askpass helper, never on argv. */
  password?: string;
  /** Connection timeout in seconds, 1 to 120. */
  connect_timeout_s?: number;
  /** Cap in bytes on captured stdout/stderr, 1 to 104857600. */
  max_output_bytes?: number;
}

/** Result of running a remote command. */
export interface ExecResult {
  /** Captured standard output. */
  stdout: string;
  /** Captured standard error. */
  stderr: string;
  /** Remote exit code; a non-zero value is data, not an error. */
  exit_code: number;
  /**
   * True when stdout or stderr reached the capture cap. When set, the child
   * was killed to stop the flood, so `exit_code` is not meaningful.
   */
  truncated: boolean;
  /** Wall-clock milliseconds spent in the transport. */
  duration_ms: number;
}

/** Optional per-call controls for {@link exec}. */
export interface ExecOptions {
  /** Bytes or text streamed to ssh's stdin; never placed on argv. */
  stdin?: Uint8Array | string;
  /**
   * Kill the local ssh after this many milliseconds and raise a typed timeout.
   * Only the local ssh is killed; the remote command keeps running unless it
   * is itself bounded (wrap it with the remote `timeout` in a surviving shell).
   */
  timeoutMs?: number;
  /**
   * Capture cap; exceeding it sets `truncated` instead of throwing. At most the
   * target's `max_output_bytes`.
   */
  maxOutputBytes?: number;
}

/** Result of pushing bytes to a remote path. */
export interface UploadResult {
  /** Destination path on the remote host. */
  path: string;
  /** Number of bytes written. */
  bytes: number;
  /** SHA-256 of the bytes, lowercase hex. */
  sha256: string;
  /** False when the destination already held these exact bytes; no write happened. */
  changed: boolean;
}

/** A host key with its SHA-256 fingerprint. */
export interface HostKeyInfo {
  /** Key algorithm, e.g. `ssh-ed25519`. */
  type: string;
  /** Base64 public key blob. */
  key: string;
  /** `ssh-keygen`-style fingerprint, e.g. `SHA256:....`. */
  sha256: string;
}

/** Result of waiting for a host to answer SSH. */
export interface WaitResult {
  /** Whether the host answered with acceptable host keys. */
  reachable: boolean;
  /** The accepted host keys. */
  host_keys: HostKeyInfo[];
}

/** Injectable dependencies of the transport. */
export interface SshDeps {
  /** Runs local commands (`ssh`, `ssh-agent`, `ssh-add`, `ssh-keyscan`). */
  run: CommandRunner;
  /** Current time in milliseconds. */
  now: () => number;
  /** Sleeps for the given number of milliseconds. */
  sleep: (ms: number) => Promise<void>;
}

/** Options for {@link upload}. */
export interface UploadOptions {
  /** Absolute destination path. */
  path: string;
  /** File bytes or UTF-8 text. */
  content: Uint8Array | string;
  /** Octal file mode, e.g. `0600`; defaults to `0600`. */
  mode?: string;
}

/** Options for {@link waitConnection}. */
export interface WaitOptions {
  /** Give up after this many seconds; defaults to 60. */
  timeout_s?: number;
  /** Seconds between polls; defaults to 5. */
  poll_interval_s?: number;
}

/** Invalid input or missing configuration; retrying will not fix it. */
export class SshConfigError extends Error {
  /** Creates a non-retryable configuration error. */
  constructor(message: string) {
    super(message);
    this.name = "SshConfigError";
  }
}

/** A distinguishable reason a call failed. */
export type SshErrorKind = "timeout";

/** A transport failure: unreachable host, rejected credential or key mismatch. */
export class SshError extends Error {
  /** The failure kind, when a caller should branch on it. */
  readonly kind?: SshErrorKind;
  /** Creates a transport error, optionally typed by kind. */
  constructor(message: string, kind?: SshErrorKind) {
    super(message);
    this.name = "SshError";
    this.kind = kind;
  }
}

/** Grammar for a plain hostname or IP literal. */
export const HOST_RE =
  /^(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$|^[0-9a-fA-F:.]{2,45}$/;
/** Grammar for POSIX user names, including uppercase and dotted names. */
export const USER_RE = /^[A-Za-z_][A-Za-z0-9._-]{0,31}$/;
/** Grammar for absolute remote paths: safe characters only. */
export const REMOTE_PATH_RE = /^\/[A-Za-z0-9._\/-]{1,4095}$/;
/** Grammar for octal file modes. */
export const MODE_RE = /^[0-7]{3,4}$/;

/** Throws unless `host` is a plain hostname or IP literal. */
export function assertHost(host: string): void {
  if (typeof host !== "string" || !HOST_RE.test(host)) {
    throw new SshConfigError(`Invalid host: ${String(host)}`);
  }
}

/** Throws unless `user` is a conventional POSIX user name. */
export function assertUser(user: string): void {
  if (typeof user !== "string" || !USER_RE.test(user)) {
    throw new SshConfigError(`Invalid SSH user: ${String(user)}`);
  }
}

/** Throws unless `port` is an integer from 1 to 65535. */
export function assertPort(port: number): void {
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new SshConfigError(`Invalid SSH port: ${String(port)}`);
  }
}

/**
 * Throws unless `path` is an absolute path naming one concrete file: no
 * trailing `/`, no `.` or `..` component, and a non-empty final segment.
 */
export function assertRemotePath(path: string): void {
  if (typeof path !== "string" || !REMOTE_PATH_RE.test(path)) {
    throw new SshConfigError(`Invalid remote path: ${String(path)}`);
  }
  if (path.endsWith("/")) {
    throw new SshConfigError(
      `Remote path must name a file, not a directory: ${path}`,
    );
  }
  const parts = path.split("/");
  if (parts.includes(".") || parts.includes("..")) {
    throw new SshConfigError(`Remote path must not contain . or ..: ${path}`);
  }
}

/** Throws unless `mode` is a 3- or 4-digit octal file mode. */
export function assertMode(mode: string): void {
  if (typeof mode !== "string" || !MODE_RE.test(mode)) {
    throw new SshConfigError(`Invalid file mode: ${String(mode)}`);
  }
}

/**
 * Quotes `value` for a POSIX shell as one literal word. Single quotes are the
 * only characters that can break out of a single-quoted string; each is closed,
 * escaped and reopened. The result never contains an unquoted metacharacter.
 */
export function posixQuote(value: string): string {
  if (value === "") return "''";
  return `'${value.replace(/'/g, "'\\''")}'`;
}

/** A shell operator allowed between remote command stages. */
export type RemoteOperator = "|" | "&&" | "||" | ";";

/**
 * Joins one argv vector into a single remote command, quoting every element as
 * a literal word. This is the only public way to build a command string: the
 * result is always a sequence of quoted words with no unquoted caller text.
 */
export function quoteArgv(argv: string[]): string {
  if (!Array.isArray(argv) || argv.length === 0) {
    throw new SshConfigError("argv must have at least one element");
  }
  for (const word of argv) {
    if (typeof word !== "string") {
      throw new SshConfigError("every argv element must be a string");
    }
    // A NUL cannot be carried in a process argument at all, so refuse it here
    // with a typed error rather than letting the spawn fail opaquely.
    if (word.includes("\u0000")) {
      throw new SshConfigError("argv elements must not contain a NUL byte");
    }
  }
  return argv.map(posixQuote).join(" ");
}

/**
 * Builds a remote command from one or more argv vectors joined by operators
 * chosen from a fixed allowlist. No caller value is ever an unquoted word, so
 * a pipeline can be expressed without handing the helper a raw shell string.
 */
export function buildRemoteCommand(
  stages: string[][],
  operators: RemoteOperator[] = [],
): string {
  if (!Array.isArray(stages) || stages.length === 0) {
    throw new SshConfigError("at least one command stage is required");
  }
  if (operators.length !== stages.length - 1) {
    throw new SshConfigError(
      "one operator is required between each pair of stages",
    );
  }
  const allowed = new Set<RemoteOperator>(["|", "&&", "||", ";"]);
  const parts = [quoteArgv(stages[0])];
  for (let i = 0; i < operators.length; i++) {
    if (!allowed.has(operators[i])) {
      throw new SshConfigError(`unsupported operator: ${String(operators[i])}`);
    }
    parts.push(operators[i], quoteArgv(stages[i + 1]));
  }
  return parts.join(" ");
}

/** Parses `ssh-keyscan` or `known_hosts` lines into host keys. */
export function parseHostKeys(text: string): HostKey[] {
  const keys: HostKey[] = [];
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (line === "" || line.startsWith("#")) continue;
    const parts = line.split(/\s+/);
    // A bare `type key` line has exactly two fields; anything else is
    // `host type key`. Discriminating on field count also accepts key
    // algorithms whose name does not start with `ssh-` or `ecdsa-`, such
    // as the FIDO `sk-` variants.
    const [host, type, key] = parts.length === 2
      ? [undefined, parts[0], parts[1]]
      : [parts[0], parts[1], parts[2]];
    if (type && key) keys.push(host ? { host, type, key } : { type, key });
  }
  return keys;
}

/**
 * Keeps the keys that apply to `host` on `port`: lines without a host field,
 * or whose comma-separated host list names `host`, `[host]:22` (both accepted
 * on port 22) or `[host]:port`. Hashed `known_hosts` entries are unsupported.
 */
export function keysForHost(
  keys: HostKey[],
  host: string,
  port: number,
): HostKey[] {
  const wants = port === 22 ? [host, `[${host}]:22`] : [`[${host}]:${port}`];
  return keys.filter((k) =>
    k.host === undefined || k.host.split(",").some((h) => wants.includes(h))
  );
}

/**
 * Verifies observed keys against `expected` when any are pinned, whatever the
 * policy: every observed key of a pinned type must match, types with no pin
 * are ignored, and at least one observed key must match. With `insecure_tofu`
 * and no pinned keys (genuine first use) it returns what was observed; with
 * `strict` and no pin it refuses.
 */
export function checkHostKeys(
  observed: HostKey[],
  policy: HostKeyPolicy,
  expected: HostKey[] = [],
): HostKey[] {
  if (expected.length === 0) {
    if (policy === "strict") {
      throw new SshConfigError("host_key_policy strict requires host keys");
    }
    return observed;
  }
  if (observed.length === 0) {
    throw new SshError("no host keys observed to verify");
  }
  const pinnedTypes = new Set(expected.map((e) => e.type));
  const trusted: HostKey[] = [];
  for (const k of observed) {
    if (!pinnedTypes.has(k.type)) continue;
    if (!expected.some((e) => e.type === k.type && e.key === k.key)) {
      throw new SshError(`host key mismatch for ${k.type}`);
    }
    trusted.push(k);
  }
  if (trusted.length === 0) {
    throw new SshError(
      `none of the host's key types (${
        observed.map((k) => k.type).join(", ")
      }) is pinned`,
    );
  }
  return trusted;
}

/** Renders pinned keys as a `known_hosts` body for `host` on `port`. */
export function buildKnownHosts(
  host: string,
  port: number,
  keys: HostKey[],
): string {
  const field = port === 22 ? host : `[${host}]:${port}`;
  return keys.map((k) => `${field} ${k.type} ${k.key}`).join("\n") +
    (keys.length > 0 ? "\n" : "");
}

/** The pinned keys that apply to `target`; empty when none are pinned. */
function applicableKeys(target: NormalizedTarget): HostKey[] {
  const parsed = parseHostKeys((target.host_keys ?? []).join("\n"));
  return keysForHost(parsed, target.host, target.port);
}

/**
 * The pinned keys that apply to `target`, refusing a supplied set that matches
 * nothing. A caller that hands over `host_keys` means it, so a set that does
 * not apply to this host/port is a configuration error, never a silent
 * fallback to trust-on-first-use.
 */
function pinnedKeys(target: NormalizedTarget): HostKey[] {
  const applicable = applicableKeys(target);
  if ((target.host_keys?.length ?? 0) > 0 && applicable.length === 0) {
    throw new SshConfigError(
      `host_keys were supplied but none apply to ${target.host}:${target.port}`,
    );
  }
  return applicable;
}

/** Resolves the pinned keys for `target`, refusing an empty or inapplicable set. */
function expectedKeys(target: NormalizedTarget): HostKey[] {
  const applicable = pinnedKeys(target);
  if (applicable.length === 0) {
    throw new SshConfigError(
      `host_key_policy strict requires pinned host keys for ${target.host}:${target.port}`,
    );
  }
  return applicable;
}

/** Decodes standard or URL-safe base64 into bytes. */
export function base64Decode(value: string): Uint8Array {
  const clean = value.replace(/\s+/g, "").replace(/-/g, "+").replace(/_/g, "/");
  let bin: string;
  try {
    bin = atob(clean);
  } catch {
    throw new SshConfigError("invalid base64 content");
  }
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

/** Encodes bytes as standard base64 without padding. */
function base64Encode(bytes: Uint8Array): string {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/=+$/, "");
}

/** Returns the lowercase hex SHA-256 of `data` (text is encoded as UTF-8). */
export async function sha256Hex(data: Uint8Array | string): Promise<string> {
  const view = typeof data === "string"
    ? new TextEncoder().encode(data)
    : new Uint8Array(data);
  const digest = await crypto.subtle.digest("SHA-256", view);
  return Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

/** Returns the `ssh-keygen -l -E sha256` fingerprint of a base64 key blob. */
export async function fingerprint(keyBlob: string): Promise<string> {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new Uint8Array(base64Decode(keyBlob)),
  );
  return `SHA256:${base64Encode(new Uint8Array(digest))}`;
}

/** Scans a host's public keys with `ssh-keyscan`; returns `[]` on no answer. */
export async function scanHostKeys(
  run: CommandRunner,
  host: string,
  port: number,
  timeoutS = 5,
): Promise<HostKey[]> {
  assertHost(host);
  assertPort(port);
  const res = await run("ssh-keyscan", [
    "-T",
    String(timeoutS),
    "-p",
    String(port),
    host,
  ]);
  if (res.code !== 0 && res.stdout.trim() === "") return [];
  return parseHostKeys(res.stdout);
}

/** Reads a stream into one Uint8Array, throwing when it exceeds `cap` bytes. */
async function readCappedStream(
  stream: ReadableStream<Uint8Array>,
  cap: number,
  label: string,
  truncate: boolean,
  onTruncate: () => void,
  signal?: AbortSignal,
): Promise<{ bytes: Uint8Array; truncated: boolean }> {
  const reader = stream.getReader();
  const chunks: Uint8Array[] = [];
  let stored = 0;
  let truncated = false;
  const onAbort = () => {
    reader.cancel().catch(() => undefined);
  };
  signal?.addEventListener("abort", onAbort, { once: true });
  try {
    while (true) {
      let read: ReadableStreamReadResult<Uint8Array>;
      try {
        read = await reader.read();
      } catch {
        break;
      }
      if (read.done) break;
      const value = read.value;
      if (stored + value.byteLength > cap) {
        if (!truncate) {
          throw new SshError(`${label} exceeded the ${cap}-byte capture limit`);
        }
        const keep = cap - stored;
        if (keep > 0) {
          chunks.push(value.subarray(0, keep));
          stored += keep;
        }
        truncated = true;
        // Stop reading and let the caller kill the child: draining a remote
        // that never stops writing (e.g. `yes`) would never return.
        onTruncate();
        break;
      }
      chunks.push(value);
      stored += value.byteLength;
    }
  } finally {
    signal?.removeEventListener("abort", onAbort);
    await reader.cancel().catch(() => undefined);
  }
  const out = new Uint8Array(stored);
  let offset = 0;
  for (const chunk of chunks) {
    out.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return { bytes: out, truncated };
}

/** Default command runner backed by `Deno.Command`. */
export const denoRunner: CommandRunner = async (cmd, args, options = {}) => {
  // Only ssh, ssh-agent, ssh-add and ssh-keyscan are run, with arguments
  // validated by the grammars above; credentials go via stdin or the
  // environment, never argv.
  const signal = options.timeoutMs === undefined
    ? undefined
    : AbortSignal.timeout(options.timeoutMs);
  const timedOut = (): CommandResult => ({
    code: -1,
    stdout: "",
    stderr: "",
    timedOut: true,
  });
  const decode = (bytes: Uint8Array): string => new TextDecoder().decode(bytes);
  let child: Deno.ChildProcess;
  try {
    // swamp-quality-ignore deno-command
    child = new Deno.Command(cmd, {
      args,
      stdin: options.stdin === undefined ? "null" : "piped",
      stdout: "piped",
      stderr: "piped",
      env: options.env,
      signal,
    }).spawn();
  } catch (e) {
    if (e instanceof Deno.errors.NotFound) {
      throw new SshConfigError(`${cmd} is not installed or not on PATH`);
    }
    throw e;
  }
  const stdin = (async (): Promise<void> => {
    if (options.stdin === undefined) return;
    const writer = child.stdin.getWriter();
    const onAbort = () => {
      writer.abort().catch(() => undefined);
    };
    signal?.addEventListener("abort", onAbort, { once: true });
    try {
      await writer.write(
        typeof options.stdin === "string"
          ? new TextEncoder().encode(options.stdin)
          : options.stdin,
      );
      await writer.close();
    } catch (e) {
      // A broken pipe after the child exited, or the abort, is expected; every
      // other failure must reach the caller.
      if (!(e instanceof Deno.errors.BrokenPipe) && !signal?.aborted) {
        throw e;
      }
    } finally {
      signal?.removeEventListener("abort", onAbort);
      try {
        writer.releaseLock();
      } catch {
        // the stream is already closed
      }
    }
  })();
  const cap = options.maxOutputBytes;
  const kill = () => {
    try {
      child.kill();
    } catch {
      // already gone
    }
  };
  const run = async (): Promise<CommandResult> => {
    if (cap === undefined) {
      await stdin;
      const out = await child.output();
      return {
        code: out.code,
        stdout: decode(out.stdout),
        stderr: decode(out.stderr),
      };
    }
    const truncate = options.truncate ?? false;
    const [stdout, stderr] = await Promise.all([
      readCappedStream(
        child.stdout,
        cap,
        `${cmd} stdout`,
        truncate,
        kill,
        signal,
      ),
      readCappedStream(
        child.stderr,
        cap,
        `${cmd} stderr`,
        truncate,
        kill,
        signal,
      ),
    ]);
    await stdin;
    const status = await child.status;
    return {
      code: status.code,
      stdout: decode(stdout.bytes),
      stderr: decode(stderr.bytes),
      truncated: stdout.truncated || stderr.truncated,
    };
  };
  try {
    const work = run();
    // The result is discarded on abort, so a late rejection is not unhandled.
    work.catch(() => undefined);
    if (signal === undefined) return await work;
    const outcome = await Promise.race([
      work,
      new Promise<"aborted">((resolve) => {
        signal.addEventListener("abort", () => resolve("aborted"), {
          once: true,
        });
      }),
    ]);
    if (outcome === "aborted") {
      kill();
      return timedOut();
    }
    return outcome;
  } catch (e) {
    kill();
    await child.status.catch(() => undefined);
    if (signal?.aborted) return timedOut();
    throw e;
  }
};

/** Production dependencies: the real command runner, clock and sleep. */
export const denoDeps: SshDeps = {
  run: denoRunner,
  now: () => Date.now(),
  sleep: (ms: number) => new Promise((resolve) => setTimeout(resolve, ms)),
};

/** A validated target with defaults filled in. */
interface NormalizedTarget {
  host: string;
  port: number;
  user: string;
  host_key_policy: HostKeyPolicy;
  host_keys?: string[];
  private_key?: string;
  password?: string;
  connect_timeout_s: number;
  max_output_bytes: number;
}

/** Validates a target and fills its defaults. */
function normalizeTarget(target: SshTarget): NormalizedTarget {
  assertHost(target.host);
  assertUser(target.user);
  assertPort(target.port);
  const policy = target.host_key_policy;
  if (policy !== "strict" && policy !== "insecure_tofu") {
    throw new SshConfigError(
      `Invalid host_key_policy: ${String(policy)}; use strict or insecure_tofu`,
    );
  }
  if (target.private_key && target.password) {
    throw new SshConfigError("pass private_key or password, not both");
  }
  if (
    policy === "strict" && (!target.host_keys || target.host_keys.length === 0)
  ) {
    throw new SshConfigError("host_key_policy strict requires host_keys");
  }
  const timeout = target.connect_timeout_s ?? 15;
  if (!Number.isInteger(timeout) || timeout < 1 || timeout > 120) {
    throw new SshConfigError(
      `connect_timeout_s must be an integer from 1 to 120, got ${timeout}`,
    );
  }
  const maxOutput = target.max_output_bytes ?? 10_485_760;
  if (
    !Number.isInteger(maxOutput) || maxOutput < 1 || maxOutput > 104_857_600
  ) {
    throw new SshConfigError(
      `max_output_bytes must be an integer from 1 to 104857600, got ${maxOutput}`,
    );
  }
  return {
    host: target.host,
    port: target.port,
    user: target.user,
    host_key_policy: policy,
    host_keys: target.host_keys,
    private_key: target.private_key,
    password: target.password,
    connect_timeout_s: timeout,
    max_output_bytes: maxOutput,
  };
}

/** Starts an ssh-agent and loads `privateKey` into it over stdin. */
async function startAgent(
  deps: SshDeps,
  privateKey: string,
): Promise<{ env: Record<string, string>; stop: () => Promise<void> }> {
  const agent = await deps.run("ssh-agent", ["-s"]);
  const sock = /SSH_AUTH_SOCK=([^;]+);/.exec(agent.stdout)?.[1];
  const pid = /SSH_AGENT_PID=(\d+);/.exec(agent.stdout)?.[1];
  if (agent.code !== 0 || !sock || !pid) {
    throw new SshConfigError("could not start ssh-agent");
  }
  const env = { SSH_AUTH_SOCK: sock, SSH_AGENT_PID: pid };
  const stop = (): Promise<void> =>
    deps.run("ssh-agent", ["-k"], { env }).then(() => undefined).catch(
      () => undefined,
    );
  try {
    const added = await deps.run("ssh-add", ["-q", "-"], {
      stdin: privateKey.endsWith("\n") ? privateKey : `${privateKey}\n`,
      env,
    });
    if (added.code !== 0) {
      throw new SshConfigError("ssh-add rejected the private key");
    }
  } catch (e) {
    await stop();
    throw e;
  }
  return { env, stop };
}

/** Writes a temporary askpass helper; the password stays in the environment. */
async function startAskpass(
  password: string,
): Promise<{ env: Record<string, string>; cleanup: () => Promise<void> }> {
  const script = await Deno.makeTempFile({
    prefix: "ssh-host-askpass-",
    suffix: ".sh",
  });
  await Deno.writeTextFile(
    script,
    "#!/bin/sh\nprintf '%s\\n' \"$SSH_ASKPASS_SECRET\"\n",
  );
  await Deno.chmod(script, 0o700);
  return {
    env: {
      SSH_ASKPASS: script,
      SSH_ASKPASS_REQUIRE: "force",
      SSH_ASKPASS_SECRET: password,
      DISPLAY: ":0",
    },
    cleanup: async () => {
      await Deno.remove(script).catch(() => undefined);
    },
  };
}

/** Maps a local OpenSSH error (exit 255) to a typed transport error, else null. */
function transportFailure(
  target: NormalizedTarget,
  res: CommandResult,
): SshError | null {
  if (res.code !== 255) return null;
  const e = res.stderr;
  if (/Host key verification failed/i.test(e)) {
    return new SshError(
      `host key verification failed for ${target.host}:${target.port}; refusing to connect`,
    );
  }
  if (
    /Permission denied|Authentication failed|no supported authentication/i.test(
      e,
    )
  ) {
    return new SshError(
      `authentication failed for ${target.user}@${target.host}:${target.port}`,
    );
  }
  if (
    /Connection (refused|timed out|closed|reset)|Connection attempt failed|No route to host|Network is unreachable|Could not resolve hostname|Operation timed out/i
      .test(e)
  ) {
    return new SshError(`could not connect to ${target.host}:${target.port}`);
  }
  // OpenSSH reserves exit 255 for its own failures, so any unrecognized 255
  // is a transport failure, not a remote exit code. A remote command that
  // itself exits 255 is therefore reported as a transport error.
  return new SshError(
    `ssh transport failed for ${target.host}:${target.port} (exit 255)`,
  );
}

/**
 * Runs `remoteCommand` on the target over SSH. Internal: a remote command is
 * built only by {@link exec}, {@link buildRemoteCommand} or this module's own
 * fixed scripts, so no public API accepts an unquoted command string. Returns
 * the remote exit code as data; a transport failure throws {@link SshError}.
 *
 * When keys are pinned — always for `strict`, and for `insecure_tofu` once the
 * caller supplies the keys it recorded on first use — the host is verified
 * against exactly those keys and a change is refused.
 */
async function runRemote(
  deps: SshDeps,
  target: SshTarget,
  remoteCommand: string,
  limits?: RunLimits,
): Promise<ExecResult> {
  const started = deps.now();
  const t = normalizeTarget(target);
  const knownHosts = await Deno.makeTempFile({ prefix: "ssh-host-kh-" });
  const cleanups: Array<() => Promise<void>> = [
    async () => {
      await Deno.remove(knownHosts).catch(() => undefined);
    },
  ];
  const env: Record<string, string> = {};
  const args: string[] = ["-F", "/dev/null", "-o", "IdentityFile=none"];
  try {
    const pinned = pinnedKeys(t);
    if (t.host_key_policy === "strict") {
      if (pinned.length === 0) {
        throw new SshConfigError(
          `host_key_policy strict requires pinned host keys for ${t.host}:${t.port}`,
        );
      }
      await Deno.writeTextFile(
        knownHosts,
        buildKnownHosts(t.host, t.port, pinned),
      );
      args.push("-o", "StrictHostKeyChecking=yes");
    } else if (pinned.length > 0) {
      // Recorded keys exist: this is trust-on-first-use enforced, not a
      // fresh accept-new. Pin exactly what was recorded.
      await Deno.writeTextFile(
        knownHosts,
        buildKnownHosts(t.host, t.port, pinned),
      );
      args.push("-o", "StrictHostKeyChecking=yes");
    } else {
      // Genuine first use under insecure_tofu: accept and learn the key.
      await Deno.writeTextFile(knownHosts, "");
      args.push("-o", "StrictHostKeyChecking=accept-new");
    }
    args.push("-o", `UserKnownHostsFile=${knownHosts}`);
    args.push("-o", "GlobalKnownHostsFile=/dev/null");
    args.push("-o", `ConnectTimeout=${t.connect_timeout_s}`);
    args.push("-o", "ServerAliveInterval=5", "-o", "ServerAliveCountMax=2");

    if (t.private_key) {
      const agent = await startAgent(deps, t.private_key);
      cleanups.push(agent.stop);
      env.SSH_AUTH_SOCK = agent.env.SSH_AUTH_SOCK;
      env.SSH_AGENT_PID = agent.env.SSH_AGENT_PID;
      args.push("-o", `IdentityAgent=${agent.env.SSH_AUTH_SOCK}`);
      args.push("-o", "BatchMode=yes");
      args.push("-o", "PreferredAuthentications=publickey");
    } else if (t.password) {
      const ask = await startAskpass(t.password);
      cleanups.push(ask.cleanup);
      Object.assign(env, ask.env);
      args.push("-o", "BatchMode=no");
      args.push("-o", "PreferredAuthentications=password");
      args.push("-o", "PubkeyAuthentication=no");
      args.push("-o", "NumberOfPasswordPrompts=1");
    } else {
      args.push("-o", "BatchMode=yes");
    }

    args.push("-p", String(t.port), "-l", t.user, t.host, remoteCommand);
    const cap = limits?.maxOutputBytes ?? t.max_output_bytes;
    const runOptions: RunOptions = { env, maxOutputBytes: cap };
    if (limits?.stdin !== undefined) runOptions.stdin = limits.stdin;
    if (limits?.truncate) runOptions.truncate = true;
    if (limits?.timeoutMs !== undefined) {
      runOptions.timeoutMs = limits.timeoutMs;
    }
    const res = await deps.run("ssh", args, runOptions);
    if (res.timedOut) {
      throw new SshError(`ssh to ${t.host}:${t.port} timed out`, "timeout");
    }
    const truncated = res.truncated ?? false;
    // A truncated result killed ssh to stop the flood, so its exit code is not
    // meaningful and must not be classified as a transport failure.
    if (!truncated) {
      const failure = transportFailure(t, res);
      if (failure) throw failure;
      // Defense in depth for an injected runner: a production runner enforces
      // the cap while streaming, so this only fires for one that does not.
      if (utf8Length(res.stdout) > cap || utf8Length(res.stderr) > cap) {
        throw new SshError(
          `output from ${t.host}:${t.port} exceeded the ${cap}-byte capture limit`,
        );
      }
    }
    return {
      stdout: res.stdout,
      stderr: res.stderr,
      exit_code: res.code,
      truncated,
      duration_ms: deps.now() - started,
    };
  } finally {
    for (const cleanup of cleanups.reverse()) await cleanup();
  }
}

/**
 * Runs one argv vector on the target. Each element is quoted as one literal
 * word before the vector is joined, so `;`, `$()`, backticks, newlines and
 * quotes inside an element can never split into a second command.
 */
/** Ceiling for a per-call timeout: 24 hours. */
export const MAX_EXEC_TIMEOUT_MS = 24 * 60 * 60 * 1000;

/** Validates the optional exec controls against the target's own capture cap. */
function assertExecOptions(
  options: ExecOptions,
  target: NormalizedTarget,
): void {
  const cap = options.maxOutputBytes;
  if (
    cap !== undefined &&
    (!Number.isInteger(cap) || cap < 1 || cap > target.max_output_bytes)
  ) {
    throw new SshConfigError(
      `maxOutputBytes must be an integer from 1 to ${target.max_output_bytes}`,
    );
  }
  const timeout = options.timeoutMs;
  if (
    timeout !== undefined &&
    (!Number.isInteger(timeout) || timeout < 1 ||
      timeout > MAX_EXEC_TIMEOUT_MS)
  ) {
    throw new SshConfigError(
      `timeoutMs must be an integer from 1 to ${MAX_EXEC_TIMEOUT_MS}`,
    );
  }
}

export async function exec(
  deps: SshDeps,
  target: SshTarget,
  argv: string[],
  options: ExecOptions = {},
): Promise<ExecResult> {
  assertExecOptions(options, normalizeTarget(target));
  return await runRemote(deps, target, quoteArgv(argv), {
    stdin: options.stdin,
    maxOutputBytes: options.maxOutputBytes,
    truncate: options.maxOutputBytes !== undefined,
    timeoutMs: options.timeoutMs,
  });
}

/** Returns the UTF-8 byte length of `text` without allocating a buffer. */
function utf8Length(text: string): number {
  let total = 0;
  for (let i = 0; i < text.length; i++) {
    const code = text.charCodeAt(i);
    if (code < 0x80) total += 1;
    else if (code < 0x800) total += 2;
    else if (code >= 0xd800 && code <= 0xdbff) {
      total += 4;
      i++;
    } else total += 3;
  }
  return total;
}

/** Normalizes an octal mode for comparison: `0600` and `600` are the same. */
function normalizeMode(mode: string): string {
  const trimmed = mode.replace(/^0+/, "");
  return trimmed === "" ? "0" : trimmed;
}

/**
 * Pushes `content` to `path` on the target: a temporary file in the
 * destination directory is written from stdin, chmod'ed, and renamed over the
 * destination, so the destination is never partially written. Converges on
 * bytes and mode: identical bytes and mode mean no write, no rename and no new
 * resource version, while a mode-only difference is replaced through the same
 * temp-file path (never chmod-in-place, which would follow a symlink). A
 * destination that is a directory or a symlink is refused. The expected hash
 * is never sent to the host: the remote prints the destination's own SHA-256
 * and mode after the rename and this side compares them, so no content-derived
 * digest appears on a command line. Returns the destination, byte count,
 * SHA-256 and whether anything changed.
 */
export async function upload(
  deps: SshDeps,
  target: SshTarget,
  options: UploadOptions,
): Promise<UploadResult> {
  assertRemotePath(options.path);
  const mode = options.mode ?? "0600";
  assertMode(mode);
  const bytes = typeof options.content === "string"
    ? new TextEncoder().encode(options.content)
    : options.content;
  const sha256 = await sha256Hex(bytes);
  const file = posixQuote(options.path);
  const UNSUPPORTED_PLATFORM =
    "ssh-host: upload requires a Linux target with mv -T";
  // Convergence probe: read the destination's SHA-256 and mode first, and
  // refuse a symlink or directory (both tested without following). Portability:
  // sha256sum on GNU, shasum -a 256 on macOS; stat -c on GNU, stat -f on BSD.
  // If none exists the probe yields `none` and the write proceeds.
  const check = await runRemote(
    deps,
    target,
    `f=${file}\n` +
      `if [ -L "$f" ]; then echo SYMLINK; elif [ -d "$f" ]; then echo DIRECTORY; elif [ -f "$f" ]; then\n` +
      `  h=$( { sha256sum "$f" 2>/dev/null || shasum -a 256 "$f" 2>/dev/null; } | awk '{print $1}' )\n` +
      `  m=$( { stat -c %a "$f" 2>/dev/null || stat -f %Lp "$f" 2>/dev/null; } )\n` +
      `  printf '%s %s\n' "\${h:-none}" "\${m:-none}"\n` +
      `else echo MISSING; fi`,
  );
  if (check.exit_code === 0) {
    const tokens = check.stdout.trim().split(/\s+/);
    if (tokens[0] === "SYMLINK") {
      throw new SshError(
        `upload destination ${target.user}@${target.host}:${options.path} is a symlink; refusing to follow it`,
      );
    }
    if (tokens[0] === "DIRECTORY") {
      throw new SshError(
        `upload destination ${target.user}@${target.host}:${options.path} is a directory`,
      );
    }
    const bytesMatch = tokens[0] === sha256;
    const modeMatch = normalizeMode(tokens[1] ?? "") === normalizeMode(mode);
    // A mode-only difference falls through to the temp-file replacement, so
    // permissions are set on the new file, never chmod'ed through a symlink.
    if (bytesMatch && modeMatch) {
      return {
        path: options.path,
        bytes: bytes.length,
        sha256,
        changed: false,
      };
    }
  }
  const dir = options.path.slice(0, options.path.lastIndexOf("/")) || "/";
  const script = [
    `f=${file}`,
    `d=${posixQuote(dir)}`,
    `t=$(mktemp "$d/.ssh-host-upload.XXXXXX") || exit 1`,
    `trap 'rm -f "$t"' EXIT HUP INT TERM`,
    `cat > "$t" || exit 1`,
    `chmod ${posixQuote(mode)} "$t" || exit 1`,
    `if [ -L "$f" ] || [ -d "$f" ]; then exit 1; fi`,
    // GNU mv -T has rename(2) no-target-directory semantics: it replaces a
    // symlink or file but never descends into a directory. No other platform
    // gives that guarantee, so fail closed rather than race a dir check.
    `case "$(uname -s)" in Linux) mv -T "$t" "$f" || exit 1;; *) echo ${
      posixQuote(UNSUPPORTED_PLATFORM)
    }; exit 1;; esac`,
    `[ -f "$f" ] && [ ! -d "$f" ] && [ ! -L "$f" ] || exit 1`,
    // Print the destination's hash and mode. The caller compares them locally,
    // so the expected hash never reaches the remote command line and cannot be
    // read back out of a process listing.
    `h=$( { sha256sum "$f" 2>/dev/null || shasum -a 256 "$f" 2>/dev/null; } | awk '{print $1}' )`,
    `m=$( { stat -c %a "$f" 2>/dev/null || stat -f %Lp "$f" 2>/dev/null; } )`,
    `printf '%s %s\n' "\${h:-none}" "\${m:-none}"`,
  ].join("\n");
  const res = await runRemote(deps, target, script, { stdin: bytes });
  if (res.exit_code !== 0) {
    if (res.stdout.includes(UNSUPPORTED_PLATFORM)) {
      throw new SshConfigError(
        "upload requires a Linux target with mv -T (a no-target-directory rename)",
      );
    }
    throw new SshError(
      `upload to ${target.user}@${target.host}:${options.path} failed (exit ${res.exit_code})`,
    );
  }
  // Verify the destination really holds these bytes and mode before reporting
  // success; both values came back from the remote, not the other way around.
  const tokens = res.stdout.trim().split(/\s+/);
  if (
    tokens[0] !== sha256 ||
    normalizeMode(tokens[1] ?? "") !== normalizeMode(mode)
  ) {
    throw new SshError(
      `upload to ${target.user}@${target.host}:${options.path} did not converge`,
    );
  }
  return { path: options.path, bytes: bytes.length, sha256, changed: true };
}

/**
 * Runs a pipeline of argv vectors joined by operators from the allowlist, for
 * example `execPipeline(deps, target, [["wg", "show"], ["grep", "peer"]],
 * ["|"])`. Every word of every stage is quoted, so no stage can inject a
 * second command.
 */
export async function execPipeline(
  deps: SshDeps,
  target: SshTarget,
  stages: string[][],
  operators: RemoteOperator[] = [],
): Promise<ExecResult> {
  return await runRemote(deps, target, buildRemoteCommand(stages, operators));
}

/** Waits until the host answers SSH with acceptable host keys, or times out. */
export async function waitConnection(
  deps: SshDeps,
  target: SshTarget,
  options: WaitOptions = {},
): Promise<WaitResult> {
  const t = normalizeTarget(target);
  const timeoutS = options.timeout_s ?? 60;
  const pollS = options.poll_interval_s ?? 5;
  // strict must have a pin; insecure_tofu may carry one recorded on first use,
  // in which case this poll verifies against it instead of trusting anew.
  const expected = t.host_key_policy === "strict"
    ? expectedKeys(t)
    : pinnedKeys(t);
  const deadline = deps.now() + timeoutS * 1000;
  const scanTimeout = Math.min(Math.max(t.connect_timeout_s, 1), 10);
  while (true) {
    const observed = await scanHostKeys(
      deps.run,
      t.host,
      t.port,
      scanTimeout,
    );
    if (observed.length > 0) {
      const accepted = checkHostKeys(
        observed,
        t.host_key_policy,
        expected,
      );
      if (accepted.length > 0) {
        const host_keys: HostKeyInfo[] = [];
        for (const key of accepted) {
          host_keys.push({
            type: key.type,
            key: key.key,
            sha256: await fingerprint(key.key),
          });
        }
        return { reachable: true, host_keys };
      }
    }
    const remaining = deadline - deps.now();
    if (remaining <= 0) {
      throw new SshError(
        `host ${t.host}:${t.port} did not answer SSH with acceptable host keys within ${timeoutS}s`,
      );
    }
    const sleepMs = Math.min(pollS * 1000, Math.max(remaining, 1));
    await deps.sleep(sleepMs);
  }
}
