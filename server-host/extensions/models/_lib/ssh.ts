/**
 * SSH transport: run an argv on a remote host, push bytes to a remote path
 * atomically, and wait for a host to answer with the expected host keys.
 *
 * Security properties:
 * - The host-key policy is explicit. `strict` trusts only the pinned keys
 *   (written to a private temporary known_hosts file); `insecure_tofu` trusts
 *   whatever the host presents on first contact within one call and records
 *   nothing.
 * - The private key is loaded into a short-lived ssh-agent over stdin. It never
 *   appears on a command line and is never written to disk.
 * - Every caller value that reaches the remote shell is validated against an
 *   allowlist grammar and quoted as a single POSIX word.
 *
 * All process and file access goes through {@link SshDeps}, so tests spawn
 * nothing and open no socket.
 *
 * @module
 */

/** How the host's identity is established. */
export type HostKeyPolicy = "strict" | "insecure_tofu";

/** Output of one local command. */
export interface CommandResult {
  /** Process exit code; -1 when the command timed out. */
  code: number;
  /** Captured standard output (bytes decoded as UTF-8). */
  stdout: string;
  /** Captured standard error. */
  stderr: string;
  /** True when the command was killed for exceeding its timeout. */
  timedOut?: boolean;
}

/** Options for one local command. */
export interface RunOptions {
  /** Bytes written to the command's stdin; absent means no stdin. */
  stdin?: Uint8Array;
  /** Extra environment variables. */
  env?: Record<string, string>;
  /** Kill the command after this many milliseconds. */
  timeoutMs?: number;
}

/** Runs a local command. Injectable so tests spawn no process. */
export type CommandRunner = (
  cmd: string,
  args: string[],
  options?: RunOptions,
) => Promise<CommandResult>;

/** Everything the transport needs from the outside world. */
export interface SshDeps {
  /** Spawns a local command. */
  run: CommandRunner;
  /** Creates a private (mode 0700) temporary directory and returns its path. */
  makeTempDir: () => Promise<string>;
  /** Writes a text file. */
  writeFile: (path: string, text: string) => Promise<void>;
  /** Removes a directory tree, ignoring a missing one. */
  removeDir: (path: string) => Promise<void>;
  /** Milliseconds since the epoch. */
  now: () => number;
  /** Resolves after `ms` milliseconds. */
  sleep: (ms: number) => Promise<void>;
}

/** The kinds of transport failure a caller can branch on. */
export type SshErrorKind =
  | "config"
  | "unreachable"
  | "auth"
  | "host_key"
  | "transport"
  | "timeout"
  | "remote";

/**
 * A failure of the transport itself (as opposed to a remote command that ran
 * and exited non-zero). Messages name the host and the failure kind and never
 * contain key material or the remote command line.
 */
export class SshError extends Error {
  /** What went wrong. */
  readonly kind: SshErrorKind;
  /** Creates a typed transport error. */
  constructor(kind: SshErrorKind, message: string) {
    super(message);
    this.name = "SshError";
    this.kind = kind;
  }
}

/** One SSH target and how to authenticate to it. */
export interface Target {
  /** Hostname or IP literal. */
  host: string;
  /** TCP port. */
  port: number;
  /** Remote login name. */
  user: string;
  /** How the host's identity is established. */
  hostKeyPolicy: HostKeyPolicy;
  /** Pinned host keys in ssh-keyscan format; required for `strict`. */
  hostKeys?: string[];
  /** PEM/OpenSSH private key; loaded into a temporary ssh-agent. */
  privateKey: string;
  /** Seconds to wait for the TCP and SSH handshake. */
  connectTimeoutS: number;
}

/** A host key as `type` plus base64 blob. */
export interface HostKey {
  /** Key algorithm, e.g. `ssh-ed25519`. */
  type: string;
  /** Base64 public key blob. */
  key: string;
}

const HOST_RE =
  /^(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$|^[0-9a-fA-F:.]{2,45}$/;
/** Grammar for SSH user names (conventional POSIX names). */
export const USER_RE = /^[a-z_][a-z0-9_-]{0,31}$/;
/** Grammar for remote paths: absolute, safe characters only. */
export const PATH_RE = /^\/[A-Za-z0-9._\/@+:=,-]{1,4095}$/;
const MODE_RE = /^[0-7]{3,4}$/;
const KEY_TYPE_RE =
  /^(?:ssh-ed25519|ssh-rsa|ssh-dss|ecdsa-sha2-nistp(?:256|384|521)|sk-ssh-ed25519@openssh\.com|sk-ecdsa-sha2-nistp256@openssh\.com)$/;
const KEY_B64_RE = /^[A-Za-z0-9+\/]+={0,2}$/;
const MAX_KEY_BYTES = 16384;
/** Captured output beyond this many bytes is cut. */
export const MAX_OUTPUT_BYTES = 1048576;

/** Throws unless `host` is a plain hostname or IP literal. */
export function assertHost(host: string): void {
  if (!HOST_RE.test(host)) throw new SshError("config", "Invalid host");
}

/** Throws unless `user` is a conventional POSIX user name. */
export function assertUser(user: string): void {
  if (!USER_RE.test(user)) throw new SshError("config", "Invalid SSH user");
}

/** Throws unless `port` is an integer in 1-65535. */
export function assertPort(port: number): void {
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new SshError("config", "Invalid port");
  }
}

/** Throws unless `path` is an absolute path of safe characters with no `..`. */
export function assertRemotePath(path: string): void {
  if (
    !PATH_RE.test(path) || path.endsWith("/") ||
    path.split("/").some((s) => s === "..")
  ) {
    throw new SshError("config", "Invalid remote path");
  }
}

/** Throws unless `mode` is a 3-4 digit octal string. */
export function assertMode(mode: string): void {
  if (!MODE_RE.test(mode)) throw new SshError("config", "Invalid file mode");
}

/**
 * Quotes one string as a single POSIX shell word. Every byte is literal
 * inside single quotes; an embedded single quote is closed, escaped, and
 * reopened. NUL cannot be represented in a command line and is refused.
 */
export function posixQuote(s: string): string {
  if (s.includes("\0")) {
    throw new SshError("config", "Argument contains a NUL byte");
  }
  return `'${s.replace(/'/g, `'\\''`)}'`;
}

/**
 * Joins an argv into the single command string the SSH protocol carries.
 * The remote login shell must be POSIX-compatible; each element arrives as
 * exactly one word, however many spaces, quotes or metacharacters it holds.
 */
export function quoteArgv(argv: string[]): string {
  if (argv.length === 0) {
    throw new SshError("config", "argv must have at least one element");
  }
  if (argv[0] === "") {
    throw new SshError("config", "argv[0] must not be empty");
  }
  return argv.map(posixQuote).join(" ");
}

/**
 * Parses pinned host-key lines in ssh-keyscan format (`[host] type key`,
 * optional trailing comment). The host field is ignored: the pin set applies
 * to the target the caller names. Anything that is not a known key type with
 * a base64 blob is rejected, so no line can smuggle known_hosts syntax.
 */
export function parseHostKeys(lines: string[]): HostKey[] {
  const keys: HostKey[] = [];
  for (const raw of lines) {
    const line = raw.trim();
    if (line === "" || line.startsWith("#")) continue;
    if (/[\r\n\0]/.test(line)) {
      throw new SshError("config", "A host key entry must be a single line");
    }
    const parts = line.split(/\s+/);
    const i = parts.findIndex((p) => KEY_TYPE_RE.test(p));
    if (i < 0 || i > 1 || i + 1 >= parts.length) {
      throw new SshError("config", "Malformed host key line");
    }
    if (i === 1 && /^[@|]/.test(parts[0])) {
      throw new SshError("config", "Host key markers are not supported");
    }
    const key = parts[i + 1];
    if (!KEY_B64_RE.test(key)) {
      throw new SshError("config", "Malformed host key blob");
    }
    keys.push({ type: parts[i], key });
  }
  return keys;
}

/** The known_hosts host field for `host` on `port`. */
export function knownHostsField(host: string, port: number): string {
  return port === 22 ? host : `[${host}]:${port}`;
}

/** Renders pinned keys as known_hosts lines for `host` on `port`. */
export function renderKnownHosts(
  keys: HostKey[],
  host: string,
  port: number,
): string {
  const field = knownHostsField(host, port);
  return keys.map((k) => `${field} ${k.type} ${k.key}\n`).join("");
}

/** Formats observed keys as ssh-keyscan lines, ready to pin. */
export function formatHostKeys(
  keys: HostKey[],
  host: string,
  port: number,
): string[] {
  const field = knownHostsField(host, port);
  return keys.map((k) => `${field} ${k.type} ${k.key}`);
}

/** Parses ssh-keyscan output into host keys, skipping comments. */
export function parseKeyscan(text: string): HostKey[] {
  const out: HostKey[] = [];
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (line === "" || line.startsWith("#")) continue;
    const p = line.split(/\s+/);
    if (p.length >= 3 && KEY_TYPE_RE.test(p[1]) && KEY_B64_RE.test(p[2])) {
      out.push({ type: p[1], key: p[2] });
    }
  }
  return out;
}

/**
 * Checks observed keys against the pinned set, following OpenSSH: an observed
 * key of a pinned type must match a pinned key, types that are not pinned are
 * ignored, and at least one observed key must match. Returns the matching
 * observed keys and throws a `host_key` error otherwise.
 */
export function verifyHostKeys(
  observed: HostKey[],
  pinned: HostKey[],
  host: string,
): HostKey[] {
  if (pinned.length === 0) {
    throw new SshError("config", "host_key_policy strict requires host_keys");
  }
  const types = new Set(pinned.map((p) => p.type));
  const trusted: HostKey[] = [];
  for (const k of observed) {
    if (!types.has(k.type)) continue;
    if (!pinned.some((p) => p.type === k.type && p.key === k.key)) {
      throw new SshError("host_key", `Host key mismatch for ${host}`);
    }
    trusted.push(k);
  }
  if (trusted.length === 0) {
    throw new SshError(
      "host_key",
      `No host key from ${host} matches a pinned key`,
    );
  }
  return trusted;
}

/** Validates a target; throws a `config` error on the first problem. */
export function assertTarget(t: Target): void {
  assertHost(t.host);
  assertPort(t.port);
  assertUser(t.user);
  if (t.hostKeyPolicy !== "strict" && t.hostKeyPolicy !== "insecure_tofu") {
    throw new SshError(
      "config",
      "host_key_policy must be strict or insecure_tofu",
    );
  }
  if (t.hostKeyPolicy === "strict") {
    if (parseHostKeys(t.hostKeys ?? []).length === 0) {
      throw new SshError("config", "host_key_policy strict requires host_keys");
    }
  }
  if (
    !Number.isInteger(t.connectTimeoutS) || t.connectTimeoutS < 1 ||
    t.connectTimeoutS > 120
  ) {
    throw new SshError("config", "connect_timeout_s must be 1-120");
  }
  normalizeKey(t.privateKey);
}

/** Normalises a private key for `ssh-add -`: LF endings, trailing newline. */
export function normalizeKey(key: string): string {
  const k = key.replace(/\r\n?/g, "\n").trim();
  if (
    !/^-----BEGIN [A-Z ]*PRIVATE KEY-----\n/.test(k) ||
    !/\n-----END [A-Z ]*PRIVATE KEY-----$/.test(k) ||
    new TextEncoder().encode(k).length > MAX_KEY_BYTES
  ) {
    throw new SshError(
      "config",
      "private_key is not a PEM/OpenSSH private key",
    );
  }
  return `${k}\n`;
}

const enc = new TextEncoder();

/** The `-o` options shared by every ssh invocation of a session. */
export function baseSshArgs(
  t: Target,
  sock: string,
  knownHostsFile: string,
): string[] {
  return [
    "-F",
    "/dev/null",
    "-o",
    "IdentityFile=none",
    "-o",
    `IdentityAgent=${sock}`,
    "-o",
    "IdentitiesOnly=no",
    "-o",
    "BatchMode=yes",
    "-o",
    `StrictHostKeyChecking=${
      t.hostKeyPolicy === "strict" ? "yes" : "accept-new"
    }`,
    "-o",
    `UserKnownHostsFile=${knownHostsFile}`,
    "-o",
    "GlobalKnownHostsFile=/dev/null",
    "-o",
    "VerifyHostKeyDNS=no",
    "-o",
    `ConnectTimeout=${t.connectTimeoutS}`,
    "-o",
    "ServerAliveInterval=5",
    "-o",
    "ServerAliveCountMax=3",
    "-o",
    "ControlMaster=no",
    "-o",
    "ControlPath=none",
    "-o",
    "ForwardAgent=no",
    "-o",
    "ForwardX11=no",
    "-o",
    "ClearAllForwardings=yes",
    "-o",
    "PermitLocalCommand=no",
    "-o",
    "RequestTTY=no",
    "-p",
    String(t.port),
    "-l",
    t.user,
  ];
}

/** Maps ssh's stderr and exit code to a typed error; never echoes stderr. */
export function classifyFailure(
  t: Target,
  stderr: string,
  timedOut = false,
): SshError {
  if (timedOut) return new SshError("timeout", `SSH to ${t.host} timed out`);
  if (
    /Host key verification failed|REMOTE HOST IDENTIFICATION HAS CHANGED/i.test(
      stderr,
    )
  ) {
    return new SshError(
      "host_key",
      `Host key verification failed for ${t.host}`,
    );
  }
  if (
    /Permission denied|no mutual signature|Too many authentication failures/i
      .test(stderr)
  ) {
    return new SshError("auth", `Authentication failed for ${t.host}`);
  }
  if (
    /Connection (?:refused|timed out|closed|reset)|timed out|No route to host|Network is unreachable|Could not resolve|Name or service not known/i
      .test(stderr)
  ) {
    return new SshError("unreachable", `Cannot connect to ${t.host}`);
  }
  return new SshError("transport", `SSH to ${t.host} failed`);
}

/**
 * Fixes the host identity for one logical operation. Under `strict` the
 * target is returned unchanged. Under `insecure_tofu` the host's keys are
 * scanned ONCE and the returned target pins them with strict checking, so
 * every later `exec` of the operation must see the same keys: a host that
 * offers a different key on a later step fails with a `host_key` error
 * instead of being trusted afresh each time. Nothing is persisted.
 */
export async function pinHostKeys(
  deps: SshDeps,
  t: Target,
): Promise<Target> {
  assertTarget(t);
  if (t.hostKeyPolicy === "strict") return t;
  const scanned = await deps.run("ssh-keyscan", [
    "-T",
    String(t.connectTimeoutS),
    "-p",
    String(t.port),
    t.host,
  ]);
  const keys = parseKeyscan(scanned.stdout);
  if (keys.length === 0) {
    throw new SshError("host_key", `No host keys offered by ${t.host}`);
  }
  return {
    ...t,
    hostKeyPolicy: "strict",
    hostKeys: formatHostKeys(keys, t.host, t.port),
  };
}

/** The result of `exec`. */
export interface ExecResult {
  /** The remote command's exit status. */
  exit_code: number;
  /** Captured stdout, cut at {@link MAX_OUTPUT_BYTES}. */
  stdout: string;
  /** Captured stderr, cut at {@link MAX_OUTPUT_BYTES}. */
  stderr: string;
  /** True when stdout or stderr was cut. */
  truncated: boolean;
  /** Wall-clock duration in milliseconds. */
  duration_ms: number;
}

function cap(s: string): [string, boolean] {
  const b = enc.encode(s);
  if (b.length <= MAX_OUTPUT_BYTES) return [s, false];
  return [new TextDecoder().decode(b.subarray(0, MAX_OUTPUT_BYTES)), true];
}

/** A prepared connection: a temporary agent holding the key, and known_hosts. */
export interface Session {
  /** Runs one remote command string; returns raw local command result. */
  ssh: (
    command: string,
    stdin?: Uint8Array,
    timeoutMs?: number,
  ) => Promise<CommandResult>;
}

/**
 * Prepares a session for `t`, runs `fn`, and always tears the agent and the
 * temporary files down. In `strict` mode the pinned keys are written to a
 * private known_hosts; in `insecure_tofu` mode an empty one is used so nothing
 * persists.
 */
export async function withSession<T>(
  deps: SshDeps,
  t: Target,
  fn: (s: Session) => Promise<T>,
): Promise<T> {
  assertTarget(t);
  const key = normalizeKey(t.privateKey);
  const dir = await deps.makeTempDir();
  let agentEnv: Record<string, string> | undefined;
  try {
    const started = await deps.run("ssh-agent", ["-s"]);
    const sock = /SSH_AUTH_SOCK=([^;]+);/.exec(started.stdout)?.[1];
    const pid = /SSH_AGENT_PID=(\d+);/.exec(started.stdout)?.[1];
    if (started.code !== 0 || !sock || !pid) {
      throw new SshError("config", "Could not start ssh-agent");
    }
    agentEnv = { SSH_AUTH_SOCK: sock, SSH_AGENT_PID: pid };
    const added = await deps.run("ssh-add", ["-q", "-"], {
      stdin: enc.encode(key),
      env: agentEnv,
    });
    if (added.code !== 0) {
      throw new SshError("config", "ssh-add rejected the private key");
    }
    const known = `${dir}/known_hosts`;
    await deps.writeFile(
      known,
      t.hostKeyPolicy === "strict"
        ? renderKnownHosts(parseHostKeys(t.hostKeys ?? []), t.host, t.port)
        : "",
    );
    const base = baseSshArgs(t, sock, known);
    return await fn({
      ssh: (command, stdin, timeoutMs) =>
        deps.run("ssh", [...base, "--", t.host, command], {
          stdin,
          env: agentEnv,
          timeoutMs,
        }),
    });
  } finally {
    if (agentEnv) {
      await deps.run("ssh-agent", ["-k"], { env: agentEnv }).catch(() =>
        undefined
      );
    }
    await deps.removeDir(dir).catch(() => undefined);
  }
}

/**
 * Runs `argv` on the target. A non-zero remote exit is returned as data;
 * ssh's own failures (exit 255) and timeouts throw {@link SshError}. A remote
 * command that itself exits 255 is indistinguishable from a transport failure
 * and is reported as one.
 */
export async function exec(
  deps: SshDeps,
  t: Target,
  argv: string[],
  options: { stdin?: Uint8Array; timeoutS?: number } = {},
): Promise<ExecResult> {
  const command = quoteArgv(argv);
  const timeoutS = options.timeoutS ?? 300;
  const started = deps.now();
  const res = await withSession(
    deps,
    t,
    (s) => s.ssh(command, options.stdin, timeoutS * 1000),
  );
  if (res.timedOut) throw classifyFailure(t, res.stderr, true);
  if (res.code === 255) throw classifyFailure(t, res.stderr);
  const [stdout, t1] = cap(res.stdout);
  const [stderr, t2] = cap(res.stderr);
  return {
    exit_code: res.code,
    stdout,
    stderr,
    truncated: t1 || t2,
    duration_ms: deps.now() - started,
  };
}

/** The result of `upload`. */
export interface UploadResult {
  /** Destination path. */
  path: string;
  /** Bytes written. */
  bytes: number;
  /** SHA-256 of the content, hex. */
  sha256: string;
  /** False when the destination already held identical content. */
  changed: boolean;
}

/**
 * Remote side of `upload`, run as `sh -c SCRIPT sh DEST MODE` with the content
 * on stdin. It writes a temp file in the destination directory, sets the mode,
 * and renames it into place, so a failure never leaves a partial destination;
 * identical content leaves the destination untouched.
 */
export const UPLOAD_SCRIPT = `set -e
dest=$1
mode=$2
tmp=$(mktemp "$dest.swamp.XXXXXX")
trap 'rm -f "$tmp"' EXIT
cat > "$tmp"
if command -v sha256sum >/dev/null 2>&1; then sum=$(sha256sum "$tmp"); else sum=$(shasum -a 256 "$tmp"); fi
sum=\${sum%% *}
bytes=$(wc -c < "$tmp" | tr -d ' ')
if [ -f "$dest" ] && cmp -s "$tmp" "$dest"; then
  chmod "$mode" "$dest"
  changed=0
else
  chmod "$mode" "$tmp"
  mv -f "$tmp" "$dest"
  changed=1
fi
trap - EXIT
rm -f "$tmp"
printf '%s %s %s\\n' "$sum" "$bytes" "$changed"
`;

async function sha256Hex(bytes: Uint8Array): Promise<string> {
  const d = await crypto.subtle.digest("SHA-256", bytes as BufferSource);
  return [...new Uint8Array(d)].map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

/**
 * Writes `content` to `path` on the target atomically (temp file in the same
 * directory, chmod, rename) and verifies the remote SHA-256 and size against
 * the local ones. Re-uploading identical bytes reports `changed: false`.
 */
export async function upload(
  deps: SshDeps,
  t: Target,
  path: string,
  content: Uint8Array,
  mode = "0644",
  timeoutS = 300,
): Promise<UploadResult> {
  assertRemotePath(path);
  assertMode(mode);
  const local = await sha256Hex(content);
  const command = quoteArgv(["sh", "-c", UPLOAD_SCRIPT, "sh", path, mode]);
  const res = await withSession(
    deps,
    t,
    (s) => s.ssh(command, content, timeoutS * 1000),
  );
  if (res.timedOut) throw classifyFailure(t, res.stderr, true);
  if (res.code === 255) throw classifyFailure(t, res.stderr);
  if (res.code !== 0) {
    throw new SshError(
      "remote",
      `Upload to ${t.host} failed (remote exit ${res.code}); nothing was written to the destination`,
    );
  }
  const m = /^([0-9a-f]{64}) (\d+) ([01])\s*$/.exec(res.stdout.trim());
  if (!m || m[1] !== local || Number(m[2]) !== content.length) {
    throw new SshError(
      "remote",
      `Upload to ${t.host} could not be verified against the local checksum`,
    );
  }
  return { path, bytes: content.length, sha256: local, changed: m[3] === "1" };
}

/** The result of `waitConnection`. */
export interface WaitResult {
  /** True when the host answered with acceptable host keys in time. */
  reachable: boolean;
  /** Observed host keys in ssh-keyscan format (empty when none answered). */
  host_keys: string[];
  /** Why the last attempt failed, when `reachable` is false. */
  reason?: string;
  /** Scan attempts made. */
  attempts: number;
}

/**
 * Polls ssh-keyscan until the host presents acceptable host keys or the
 * deadline passes. In `strict` mode the keys must match the pinned set;
 * `insecure_tofu` accepts any key. READ-ONLY: authenticates nothing and
 * changes nothing on either side.
 */
export async function waitConnection(
  deps: SshDeps,
  t: Pick<
    Target,
    "host" | "port" | "hostKeyPolicy" | "hostKeys" | "connectTimeoutS"
  >,
  timeoutS: number,
  intervalS: number,
): Promise<WaitResult> {
  assertHost(t.host);
  assertPort(t.port);
  if (t.hostKeyPolicy !== "strict" && t.hostKeyPolicy !== "insecure_tofu") {
    throw new SshError(
      "config",
      "host_key_policy must be strict or insecure_tofu",
    );
  }
  const pinned = t.hostKeyPolicy === "strict"
    ? parseHostKeys(t.hostKeys ?? [])
    : [];
  if (t.hostKeyPolicy === "strict" && pinned.length === 0) {
    throw new SshError("config", "host_key_policy strict requires host_keys");
  }
  const deadline = deps.now() + timeoutS * 1000;
  let attempts = 0;
  let reason = "no attempt completed";
  for (;;) {
    attempts++;
    const res = await deps.run("ssh-keyscan", [
      "-T",
      String(Math.min(t.connectTimeoutS, 10)),
      "-p",
      String(t.port),
      "--",
      t.host,
    ], { timeoutMs: (t.connectTimeoutS + 5) * 1000 });
    const observed = parseKeyscan(res.stdout);
    if (observed.length === 0) {
      reason = "host did not present SSH host keys";
    } else {
      try {
        const keys = t.hostKeyPolicy === "strict"
          ? verifyHostKeys(observed, pinned, t.host)
          : observed;
        return {
          reachable: true,
          host_keys: formatHostKeys(keys, t.host, t.port),
          attempts,
        };
      } catch (e) {
        reason = e instanceof SshError ? e.message : "host key check failed";
      }
    }
    if (deps.now() + intervalS * 1000 >= deadline) break;
    await deps.sleep(intervalS * 1000);
  }
  return { reachable: false, host_keys: [], reason, attempts };
}

/** Production dependencies backed by `Deno.Command` and the real clock. */
export const denoDeps: SshDeps = {
  run: async (cmd, args, options = {}) => {
    // Only ssh, ssh-keyscan, ssh-agent and ssh-add are run; values reaching
    // them are validated above, and secrets travel over stdin only.
    let child: Deno.ChildProcess;
    const signal = options.timeoutMs === undefined
      ? undefined
      : AbortSignal.timeout(options.timeoutMs);
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
        throw new SshError("config", `${cmd} is not installed or not on PATH`);
      }
      throw e;
    }
    try {
      if (options.stdin !== undefined) {
        const w = child.stdin.getWriter();
        try {
          await w.write(options.stdin);
          await w.close();
        } catch { /* the child exited before reading all input */ }
      }
      const out = await child.output();
      return {
        code: out.code,
        stdout: new TextDecoder().decode(out.stdout),
        stderr: new TextDecoder().decode(out.stderr),
      };
    } catch (e) {
      if (signal?.aborted) {
        return { code: -1, stdout: "", stderr: "", timedOut: true };
      }
      throw e;
    }
  },
  makeTempDir: () => Deno.makeTempDir({ prefix: "ssh-host-" }),
  writeFile: (path, text) => Deno.writeTextFile(path, text, { mode: 0o600 }),
  removeDir: (path) => Deno.remove(path, { recursive: true }),
  now: () => Date.now(),
  sleep: (ms) => new Promise((r) => setTimeout(r, ms)),
};
