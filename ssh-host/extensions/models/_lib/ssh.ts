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
}

/** Options for one external command. */
export interface RunOptions {
  /** Bytes or text written to the command's standard input. */
  stdin?: Uint8Array | string;
  /** Extra environment variables; merged with the inherited environment. */
  env?: Record<string, string>;
}

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
}

/** Result of running a remote command. */
export interface ExecResult {
  /** Captured standard output. */
  stdout: string;
  /** Captured standard error. */
  stderr: string;
  /** Remote exit code; a non-zero value is data, not an error. */
  exit_code: number;
}

/** Result of pushing bytes to a remote path. */
export interface UploadResult {
  /** Destination path on the remote host. */
  path: string;
  /** Number of bytes written. */
  bytes: number;
  /** SHA-256 of the bytes, lowercase hex. */
  sha256: string;
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

/** A transport failure: unreachable host, rejected credential or key mismatch. */
export class SshError extends Error {
  /** Creates a transport error. */
  constructor(message: string) {
    super(message);
    this.name = "SshError";
  }
}

/** Grammar for a plain hostname or IP literal. */
export const HOST_RE =
  /^(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$|^[0-9a-fA-F:.]{2,45}$/;
/** Grammar for conventional POSIX user names. */
export const USER_RE = /^[a-z_][a-z0-9_-]{0,31}$/;
/** Grammar for absolute remote paths: safe characters, no `..` segment. */
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

/** Throws unless `path` is an absolute path without a `..` segment. */
export function assertRemotePath(path: string): void {
  if (
    typeof path !== "string" || !REMOTE_PATH_RE.test(path) ||
    path.split("/").includes("..")
  ) {
    throw new SshConfigError(`Invalid remote path: ${String(path)}`);
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

/** Parses `ssh-keyscan` or `known_hosts` lines into host keys. */
export function parseHostKeys(text: string): HostKey[] {
  const keys: HostKey[] = [];
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (line === "" || line.startsWith("#")) continue;
    const parts = line.split(/\s+/);
    const bare = parts[0].startsWith("ssh-") || parts[0].startsWith("ecdsa-");
    const [host, type, key] = bare
      ? [undefined, parts[0], parts[1]]
      : [parts[0], parts[1], parts[2]];
    if (type && key) keys.push(host ? { host, type, key } : { type, key });
  }
  return keys;
}

/**
 * Keeps the keys that apply to `host` on `port`: lines without a host field,
 * or whose comma-separated host list names `host` (port 22) or `[host]:port`.
 * Hashed `known_hosts` entries are not supported.
 */
export function keysForHost(
  keys: HostKey[],
  host: string,
  port: number,
): HostKey[] {
  const want = port === 22 ? host : `[${host}]:${port}`;
  return keys.filter((k) =>
    k.host === undefined || k.host.split(",").includes(want)
  );
}

/**
 * Applies the host-key policy and returns the keys to trust. `strict` follows
 * OpenSSH: every observed key of a type that `expected` pins must match a
 * pinned key, types it does not pin are ignored, and at least one observed key
 * must match; only matching keys are returned. `insecure_tofu` returns what
 * was observed, without enforcement.
 */
export function checkHostKeys(
  observed: HostKey[],
  policy: HostKeyPolicy,
  expected: HostKey[] = [],
): HostKey[] {
  if (policy !== "strict") return observed;
  if (expected.length === 0) {
    throw new SshConfigError("host_key_policy strict requires host keys");
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

/** Resolves the pinned keys for `target`, refusing an empty or inapplicable set. */
function expectedKeys(target: NormalizedTarget): HostKey[] {
  const parsed = parseHostKeys((target.host_keys ?? []).join("\n"));
  const applicable = keysForHost(parsed, target.host, target.port);
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

/** Default command runner backed by `Deno.Command`. */
export const denoRunner: CommandRunner = async (cmd, args, options = {}) => {
  // Only ssh, ssh-agent, ssh-add and ssh-keyscan are run, with arguments
  // validated by the grammars above; credentials go via stdin or the
  // environment, never argv.
  let child: Deno.ChildProcess;
  try {
    // swamp-quality-ignore deno-command
    child = new Deno.Command(cmd, {
      args,
      stdin: options.stdin === undefined ? "null" : "piped",
      stdout: "piped",
      stderr: "piped",
      env: options.env,
    }).spawn();
  } catch (e) {
    if (e instanceof Deno.errors.NotFound) {
      throw new SshConfigError(`${cmd} is not installed or not on PATH`);
    }
    throw e;
  }
  if (options.stdin !== undefined) {
    const writer = child.stdin.getWriter();
    await writer.write(
      typeof options.stdin === "string"
        ? new TextEncoder().encode(options.stdin)
        : options.stdin,
    );
    await writer.close();
  }
  const out = await child.output();
  return {
    code: out.code,
    stdout: new TextDecoder().decode(out.stdout),
    stderr: new TextDecoder().decode(out.stderr),
  };
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
  return {
    host: target.host,
    port: target.port,
    user: target.user,
    host_key_policy: policy,
    host_keys: target.host_keys,
    private_key: target.private_key,
    password: target.password,
    connect_timeout_s: timeout,
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
  if (/^(?:ssh|ssh-agent): /m.test(e)) {
    return new SshError(
      `ssh transport failed for ${target.host}:${target.port} (exit 255)`,
    );
  }
  return null;
}

/**
 * Runs `remoteCommand` on the target over SSH. The command string is built by
 * the caller from {@link posixQuote}-quoted words, so no caller value is ever
 * interpreted by the remote shell. Returns the remote exit code as data; a
 * transport failure throws {@link SshError}.
 */
export async function runRemote(
  deps: SshDeps,
  target: SshTarget,
  remoteCommand: string,
  stdin?: Uint8Array | string,
): Promise<ExecResult> {
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
    if (t.host_key_policy === "strict") {
      const keys = expectedKeys(t);
      await Deno.writeTextFile(
        knownHosts,
        buildKnownHosts(t.host, t.port, keys),
      );
      args.push("-o", "StrictHostKeyChecking=yes");
    } else {
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
    const res = await deps.run("ssh", args, { stdin, env });
    const failure = transportFailure(t, res);
    if (failure) throw failure;
    return { stdout: res.stdout, stderr: res.stderr, exit_code: res.code };
  } finally {
    for (const cleanup of cleanups.reverse()) await cleanup();
  }
}

/**
 * Runs one argv vector on the target. Each element is quoted as one literal
 * word before the vector is joined, so `;`, `$()`, backticks, newlines and
 * quotes inside an element can never split into a second command.
 */
export async function exec(
  deps: SshDeps,
  target: SshTarget,
  argv: string[],
): Promise<ExecResult> {
  if (!Array.isArray(argv) || argv.length === 0) {
    throw new SshConfigError("argv must have at least one element");
  }
  for (const word of argv) {
    if (typeof word !== "string") {
      throw new SshConfigError("every argv element must be a string");
    }
  }
  const remoteCommand = argv.map(posixQuote).join(" ");
  return await runRemote(deps, target, remoteCommand);
}

/**
 * Pushes `content` to `path` on the target: a temporary file in the
 * destination directory is written from stdin, chmod'ed, and renamed over the
 * destination, so the destination is never partially written. Returns the
 * destination, byte count and SHA-256.
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
  const dir = options.path.slice(0, options.path.lastIndexOf("/")) || "/";
  const script = [
    `d=${posixQuote(dir)}`,
    `t=$(mktemp "$d/.ssh-host-upload.XXXXXX") || exit 1`,
    `trap 'rm -f "$t"' EXIT HUP INT TERM`,
    `cat > "$t" || exit 1`,
    `chmod ${mode} "$t" || exit 1`,
    `mv -f "$t" ${posixQuote(options.path)} || exit 1`,
  ].join("\n");
  const res = await runRemote(deps, target, script, bytes);
  if (res.exit_code !== 0) {
    throw new SshError(
      `upload to ${target.user}@${target.host}:${options.path} failed (exit ${res.exit_code})`,
    );
  }
  return { path: options.path, bytes: bytes.length, sha256 };
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
  const expected = t.host_key_policy === "strict" ? expectedKeys(t) : [];
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
