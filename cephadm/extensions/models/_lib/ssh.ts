/**
 * SSH transport for the cephadm model.
 *
 * Every remote action goes through the system OpenSSH client, spawned as a
 * subprocess with key-only authentication and no prompts. This module builds
 * the argv, supplies an identity (a path, or key content placed in a
 * short-lived private file), applies the host-key policy, classifies a lost
 * session so a caller knows whether a write may be re-sent, and optionally
 * runs all calls over one multiplexed master.
 *
 * @module
 */

import {
  fail,
  LocalRefusalError,
  RemoteExitError,
  SudoPolicyError,
  TransportError,
} from "./errors.ts";
import type { PreSessionCause, TransportKind } from "./errors.ts";
import { cappedBackoff } from "./backoff.ts";
import { assertSerial, isKeyPath, SSH_USER_RE, truncate } from "./validate.ts";

/** A remote command's outcome. */
export interface CommandResult {
  /** Remote exit code. */
  code: number;
  /** Remote standard output. */
  stdout: string;
  /** Remote standard error. */
  stderr: string;
}

/** The connection fields after null/undefined/empty collapsing. */
export interface Target {
  /** Hostname or IPv4 address. */
  host: string;
  /** Login user. */
  user: string;
  /** SSH port; omitted means 22. */
  port?: number;
  /** Local private-key path; mutually exclusive with {@link privateKey}. */
  keyPath?: string;
  /** Private-key content; mutually exclusive with {@link keyPath}. */
  privateKey?: string;
  /** `yes` (strict) or an explicit `no`. Required. */
  strictHostKeyChecking: "yes" | "no";
}

/** An already-spawned child with a writable stdin; injectable for tests. */
export interface SpawnedChild {
  /** Writable child stdin. */
  stdin: WritableStream<Uint8Array>;
  /** Waits for exit and collects output. */
  output(): Promise<{ code: number; stdout: Uint8Array; stderr: Uint8Array }>;
  /** Kills the child (best effort). */
  kill(): void;
}

/** Spawns one command; the production form returns an already-spawned child. */
export type Spawner = (cmd: string, args: string[]) => SpawnedChild;

/** Dependencies the transport needs; all injected. */
export interface SshDeps {
  /** Spawns the ssh binary. */
  spawn: Spawner;
  /** Current time in milliseconds. */
  now: () => number;
  /** Sleeps for the given milliseconds. */
  sleep: (ms: number) => Promise<void>;
  /** Overrides the kill grace period; tests only. */
  killGraceMs?: number;
}

/** Production spawner backed by `Deno.Command`. */
export const denoSpawner: Spawner = (cmd, args) => {
  // Only the ssh binary is spawned, with arguments this module assembles.
  // swamp-quality-ignore deno-command
  const child = new Deno.Command(cmd, {
    args,
    stdin: "piped",
    stdout: "piped",
    stderr: "piped",
  }).spawn();
  return {
    stdin: child.stdin,
    output: async () => {
      const out = await child.output();
      return { code: out.code, stdout: out.stdout, stderr: out.stderr };
    },
    kill: () => {
      try {
        child.kill();
      } catch { /* already exited */ }
    },
  };
};

const encoder = new TextEncoder();
const decoder = new TextDecoder();

/** Default per-call budget in milliseconds. */
export const DEFAULT_BUDGET_MS = 30_000;
/** Extra milliseconds allowed before the whole ssh process is killed. */
export const KILL_GRACE_MS = 5_000;
/** Ceiling for ConnectTimeout, in seconds. */
export const MAX_CONNECT_TIMEOUT_S = 30;

/** ConnectTimeout in whole seconds: rounded up, minimum 1, capped at 30. */
export function connectTimeoutSeconds(budgetMs: number): number {
  const raw = Math.ceil(budgetMs / 1000);
  return Math.max(1, Math.min(MAX_CONNECT_TIMEOUT_S, raw));
}

/** Collapses null, undefined and empty string to absent, refusing two identities. */
export function toTarget(fields: {
  host: string;
  sshUser?: string | null;
  port?: number | null;
  keyPath?: string | null;
  privateKey?: string | null;
  strictHostKeyChecking?: "yes" | "no" | null;
}): Target {
  if (
    fields.strictHostKeyChecking !== "yes" &&
    fields.strictHostKeyChecking !== "no"
  ) {
    fail("validate", "strictHostKeyChecking is required (yes or no)", {
      field: "strictHostKeyChecking",
      value: fields.strictHostKeyChecking ?? "absent",
    });
  }
  const clean = (v: string | null | undefined): string | undefined =>
    v === null || v === undefined || v === "" ? undefined : v;
  const user = clean(fields.sshUser) ?? "";
  if (!SSH_USER_RE.test(user)) {
    fail("validate", "invalid sshUser", {
      field: "sshUser",
      value: truncate(fields.sshUser ?? ""),
    });
  }
  const keyPath = clean(fields.keyPath);
  const privateKey = clean(fields.privateKey);
  if (keyPath !== undefined && privateKey !== undefined) {
    throw new LocalRefusalError(
      "both keyPath and privateKey were set; pass exactly one",
    );
  }
  if (keyPath !== undefined && !isKeyPath(keyPath)) {
    fail("validate", "invalid keyPath", {
      field: "keyPath",
      value: truncate(keyPath),
    });
  }
  const target: Target = {
    host: fields.host,
    user,
    strictHostKeyChecking: fields.strictHostKeyChecking as "yes" | "no",
  };
  if (fields.port !== undefined && fields.port !== null) {
    target.port = fields.port;
  }
  if (keyPath !== undefined) target.keyPath = keyPath;
  if (privateKey !== undefined) target.privateKey = privateKey;
  return target;
}

/** The port a target dials, defaulted to 22 for reporting. */
export function targetPort(target: Target): number {
  return target.port ?? 22;
}

function assertNoNul(value: string, what: string): void {
  if (value.includes("\0")) {
    throw new LocalRefusalError(`${what} contains a NUL byte`);
  }
}

/** Characters the by-id resolver accepts in a link name (kept here for reuse). */
export function assertDeviceSerialRuntime(serial: string): string {
  return assertSerial("serial", serial);
}

/** Builds the `-o`/`-p`/`-i` prefix for one ssh call. */
function connectionArgs(
  target: Target,
  opts: {
    budgetMs: number;
    multiplex: boolean;
    controlPath?: string;
    persistSeconds?: number;
  },
): string[] {
  const args: string[] = ["-p", String(targetPort(target))];
  args.push("-o", "BatchMode=yes");
  args.push("-o", "PreferredAuthentications=publickey");
  const strict = target.strictHostKeyChecking;
  args.push("-o", `StrictHostKeyChecking=${strict}`);
  if (strict === "no") {
    args.push("-o", "UserKnownHostsFile=/dev/null");
    args.push("-o", "GlobalKnownHostsFile=/dev/null");
  }
  args.push("-o", `ConnectTimeout=${connectTimeoutSeconds(opts.budgetMs)}`);
  if (opts.multiplex && opts.controlPath !== undefined) {
    args.push("-o", "ControlMaster=auto");
    args.push("-o", `ControlPath=${opts.controlPath}`);
    args.push("-o", `ControlPersist=${opts.persistSeconds ?? 600}`);
    args.push("-o", "ServerAliveInterval=15");
    args.push("-o", "ServerAliveCountMax=3");
  }
  if (target.keyPath !== undefined) {
    args.push("-o", "IdentitiesOnly=yes");
    args.push("-i", target.keyPath);
  }
  return args;
}

/** A short hex digest of a string, used to name a control socket. */
async function shortHash(input: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-1", encoder.encode(input));
  return Array.from(new Uint8Array(digest)).map((b) =>
    b.toString(16).padStart(2, "0")
  ).join("");
}

/** Where a control socket for `target` lives, and its directory. */
export interface ControlSocket {
  /** Directory holding the socket; created mode 0700. */
  dir: string;
  /** Full socket path. */
  path: string;
}

/** Portable UNIX socket path length limit. */
export const SOCKET_PATH_LIMIT = 103;
/** Namespace subdirectory, so sockets never collide with other ssh tooling. */
export const SOCKET_NAMESPACE = "swamp-cephadm-ssh";

/** Resolves the control-socket path for a target, falling back under /tmp if too long. */
export async function controlSocketPath(
  target: Target,
  env: (key: string) => string | undefined = (k) => Deno.env.get(k),
): Promise<ControlSocket> {
  // A master is reusable only within one trust and one credential identity,
  // so a strict connection can never ride a master opened with checking off.
  const identity = target.keyPath !== undefined
    ? `path:${target.keyPath}`
    : target.privateKey !== undefined
    ? `inline:${target.privateKey}`
    : "agent";
  const name = `${
    (await shortHash(
      `${target.user}@${target.host}:${
        targetPort(target)
      }|strict=${target.strictHostKeyChecking}|id=${identity}`,
    ))
      .slice(0, 12)
  }.sock`;
  const base = env("XDG_RUNTIME_DIR") ?? env("TMPDIR") ?? "/tmp";
  let dir = `${base.replace(/\/$/, "")}/${SOCKET_NAMESPACE}`;
  let path = `${dir}/${name}`;
  if (path.length > SOCKET_PATH_LIMIT) {
    dir = `/tmp/${SOCKET_NAMESPACE}`;
    path = `${dir}/${name}`;
  }
  return { dir, path };
}

/** Ensures the socket directory exists with mode 0700, refusing a shared one. */
export async function ensureControlSocketDir(
  dir: string,
  stat: (path: string) => Promise<Deno.FileInfo> = (p) => Deno.stat(p),
  mkdir: (path: string, mode: number) => Promise<void> = async (p, mode) => {
    await Deno.mkdir(p, { recursive: true, mode });
  },
): Promise<void> {
  await mkdir(dir, 0o700);
  const info = await stat(dir);
  if (typeof info.mode !== "number") return;
  if ((info.mode & 0o077) !== 0) {
    throw new LocalRefusalError(
      `control-socket directory ${dir} has group or world permissions; fix them or relocate the base directory`,
    );
  }
}

/** Options for one remote command. */
export interface RunOptions {
  /** Remote command string. */
  command: string;
  /** Content written to the child's stdin, then closed. */
  stdin?: string;
  /** Return a non-zero remote exit instead of throwing, except transport errors. */
  allowNonZero?: boolean;
  /** Prefix the command with `sudo -n --`. */
  sudo?: boolean;
  /** Per-call budget; defaults to {@link DEFAULT_BUDGET_MS}. */
  budgetMs?: number;
}

/** A live SSH session to one target, possibly multiplexed. */
export interface SshSession {
  /** Target being dialled. */
  target: Target;
  /** Control socket path when multiplexing, else null. */
  controlPath: string | null;
  /** Runs one command. */
  run(opts: RunOptions): Promise<CommandResult>;
  /** Best-effort close of a multiplexed master; never throws. */
  close(): Promise<{ closed: boolean; detail: string }>;
}

/** Options for opening a session. */
export interface SessionOptions {
  /** Reuse one master across calls. */
  multiplex: boolean;
  /** Persist seconds for the master; default 600. */
  persistSeconds?: number;
  /** Environment reader for the socket base; injectable. */
  env?: (key: string) => string | undefined;
}

/** Opens a session, resolving and preparing the socket directory when multiplexing. */
export async function openSession(
  deps: SshDeps,
  target: Target,
  opts: SessionOptions,
): Promise<SshSession> {
  if (target.keyPath !== undefined && target.privateKey !== undefined) {
    throw new LocalRefusalError(
      "both keyPath and privateKey were set; pass exactly one",
    );
  }
  let controlPath: string | null = null;
  if (opts.multiplex) {
    const socket = await controlSocketPath(target, opts.env);
    await ensureControlSocketDir(socket.dir);
    controlPath = socket.path;
  }

  const run = async (runOpts: RunOptions): Promise<CommandResult> => {
    const budgetMs = runOpts.budgetMs ?? DEFAULT_BUDGET_MS;
    const command = runOpts.sudo
      ? `sudo -n -- ${runOpts.command}`
      : runOpts.command;
    assertNoNul(command, "command");
    if (runOpts.stdin !== undefined) assertNoNul(runOpts.stdin, "stdin");

    // Inline key content is materialised per call and removed in all cases.
    let keyDir: string | null = null;
    let keyFile: string | null = null;
    const removeKeyDir = async (): Promise<void> => {
      if (keyDir === null) return;
      await Deno.remove(keyDir, { recursive: true });
    };
    let result: CommandResult;
    try {
      if (target.privateKey !== undefined) {
        keyDir = await Deno.makeTempDir({ prefix: "cephadm-key-" });
        await Deno.chmod(keyDir, 0o700);
        const content = target.privateKey.endsWith("\n")
          ? target.privateKey
          : `${target.privateKey}\n`;
        keyFile = `${keyDir}/id`;
        const handle = await Deno.open(keyFile, {
          createNew: true,
          write: true,
          mode: 0o600,
        });
        await handle.write(encoder.encode(content));
        await handle.close();
        await Deno.chmod(keyFile, 0o600);
      }

      const args: string[] = [];
      args.push(...connectionArgs(target, {
        budgetMs,
        multiplex: opts.multiplex,
        ...(controlPath ? { controlPath } : {}),
        ...(opts.persistSeconds !== undefined
          ? { persistSeconds: opts.persistSeconds }
          : {}),
      }));
      if (keyFile !== null) {
        args.push("-o", "IdentitiesOnly=yes");
        args.push("-i", keyFile);
      }
      args.push("--", `${target.user}@${target.host}`, command);

      result = await runChild(
        deps,
        target,
        args,
        runOpts.stdin,
        budgetMs,
      );
      if (runOpts.sudo && result.code !== 0 && isSudoRefusal(result.stderr)) {
        throw new SudoPolicyError(
          "passwordless sudo is required; fix the target's sudoers and do not retry",
        );
      }
      if (result.code !== 0 && !runOpts.allowNonZero) {
        throw new RemoteExitError(
          result.code,
          result.stdout,
          result.stderr,
          `${target.user}@${target.host}:${targetPort(target)}: ${command}`,
        );
      }
    } catch (e) {
      // A key left on disk must never pass silently, but it must not mask the
      // call's own error either.
      try {
        await removeKeyDir();
      } catch { /* the call's error wins */ }
      throw e;
    }
    // A successful call whose cleanup fails must not pass silently.
    await removeKeyDir();
    return result;
  };

  const close = async (): Promise<{ closed: boolean; detail: string }> => {
    if (controlPath === null) {
      return { closed: false, detail: "not closed, multiplex off" };
    }
    const args = [
      "-O",
      "exit",
      "-o",
      `ControlPath=${controlPath}`,
      "-p",
      String(targetPort(target)),
      `${target.user}@${target.host}`,
    ];
    let child: SpawnedChild;
    try {
      child = deps.spawn("ssh", args);
    } catch (e) {
      return { closed: false, detail: `not closed: ${(e as Error).message}` };
    }
    try {
      const writer = child.stdin.getWriter();
      await writer.close();
      const out = await child.output();
      const stderr = decoder.decode(out.stderr).trim();
      if (out.code === 0) return { closed: true, detail: "closed" };
      return {
        closed: false,
        detail: `not closed, exit ${out.code}${stderr ? `: ${stderr}` : ""}`,
      };
    } catch (e) {
      return { closed: false, detail: `not closed: ${(e as Error).message}` };
    }
  };

  return { target, controlPath, run, close };
}

/** Spawns and awaits one ssh child, applying stdin, the budget kill and classification. */
async function runChild(
  deps: SshDeps,
  target: Target,
  args: string[],
  stdin: string | undefined,
  budgetMs: number,
): Promise<CommandResult> {
  let child: SpawnedChild;
  try {
    child = deps.spawn("ssh", args);
  } catch (e) {
    throw new TransportError({
      host: target.host,
      port: targetPort(target),
      user: target.user,
      kind: "other",
      cause: null,
      message: `could not start ssh: ${(e as Error).message}`,
    });
  }
  const graceMs = deps.killGraceMs ?? KILL_GRACE_MS;
  let timedOut = false;
  const timer = setTimeout(() => {
    timedOut = true;
    child.kill();
  }, budgetMs + graceMs);
  let out: { code: number; stdout: Uint8Array; stderr: Uint8Array };
  try {
    const writer = child.stdin.getWriter();
    if (stdin !== undefined) await writer.write(encoder.encode(stdin));
    await writer.close();
    out = await child.output();
  } finally {
    clearTimeout(timer);
  }
  if (timedOut) {
    throw new TransportError({
      host: target.host,
      port: targetPort(target),
      user: target.user,
      kind: "aborted",
      cause: null,
      message: `killed after ${budgetMs + graceMs}ms`,
    });
  }
  const stdout = decoder.decode(out.stdout);
  const stderr = decoder.decode(out.stderr);
  if (out.code === 255) {
    throw classifyTransport(target, stderr);
  }
  return { code: out.code, stdout, stderr };
}

/** Classifies a lost session from ssh's stderr. */
export function classifyTransport(
  target: Target,
  stderr: string,
): TransportError {
  const { kind, cause, message } = describeTransport(
    stderr,
    target.host,
    targetPort(target),
    target.user,
  );
  return new TransportError({
    host: target.host,
    port: targetPort(target),
    user: target.user,
    kind,
    cause,
    message,
    stderr,
  });
}

const KEX_PREFIX = "kex_exchange_identification";
const BANNER_TIMEOUT = "connection timed out during banner exchange";

/** Result of reading ssh stderr: the session kind, cause and human text. */
export interface TransportDescription {
  /** Session-loss kind. */
  kind: TransportKind;
  /** Pre-session cause when the command provably never ran. */
  cause: PreSessionCause;
  /** Human-readable cause text. */
  message: string;
}

/** Best-effort extraction of the pre-session cause from ssh stderr. */
export function preSessionCause(stderr: string): PreSessionCause {
  const lines = stderr.split("\n").map((l) => l.trimEnd());
  for (const raw of lines) {
    const l = raw.toLowerCase();
    if (/^ssh: connect to host .+ port \d+: connection refused/.test(l)) {
      return "connect-refused";
    }
    if (/^ssh: could not resolve hostname/.test(l)) return "name-resolution";
    if (
      /^ssh: connect to host .+ port \d+:/.test(l) &&
      /(connection timed out|operation timed out|no route to host|network is unreachable)/
        .test(l)
    ) return "connect-timeout";
    if (l.trimStart().startsWith(BANNER_TIMEOUT)) return "connect-timeout";
    if (/^unable to negotiate with .+ port \d+: no matching/.test(l)) {
      return "negotiation";
    }
    if (l.trimStart().startsWith(KEX_PREFIX)) return "negotiation";
    if (/@.+: permission denied \(publickey/.test(l)) return "auth";
  }
  return null;
}

/** Describes a lost session for the transport error. */
export function describeTransport(
  stderr: string,
  host: string,
  port: number,
  user: string,
): TransportDescription {
  const lines = stderr.split("\n").map((l) => l.trimEnd());
  const lower = stderr.toLowerCase();
  const cause = preSessionCause(stderr);

  // Order matters: a changed key and an absent key both end in the same
  // verification-failed line, so they are checked before it.
  if (lower.includes("permission denied")) {
    return { kind: "other", cause, message: "authentication failed" };
  }
  if (lower.includes("remote host identification has changed")) {
    return {
      kind: "other",
      cause,
      message:
        "the host key changed; this is almost always a re-imaged node and not a bad credential " +
        "(ssh aborted before authentication). Remove the stale known_hosts entries for both the address " +
        `and the hostname with ssh-keygen -R, then verify the new fingerprint out of band`,
    };
  }
  if (lower.includes("host key verification failed")) {
    if (
      lower.includes("no such file") ||
      lower.includes("no matching host key") || !lower.includes("changed")
    ) {
      return {
        kind: "other",
        cause,
        message:
          `the target ${host} is not in known_hosts; pass strictHostKeyChecking=no only for a target ` +
          `that genuinely has no distributed key yet`,
      };
    }
  }

  const dropped = isDroppedBeforeAuth(lines);
  if (dropped) {
    return {
      kind: "dropped-before-auth",
      cause,
      message:
        "closed by the remote host before the command ran; nothing executed; not evidence about the command's own outcome",
    };
  }
  if (isMidSessionLoss(lines, stderr)) {
    return {
      kind: "other",
      cause: null,
      message:
        "session lost after it may have been established; the command MAY HAVE RUN; do not re-send blindly; " +
        "re-read the target's state",
    };
  }
  if (cause === "connect-refused") {
    return { kind: "other", cause, message: "connection refused" };
  }
  if (cause === "connect-timeout") {
    return {
      kind: "other",
      cause,
      message: "connection or operation timed out",
    };
  }
  if (cause === "name-resolution") {
    return { kind: "other", cause, message: "could not resolve hostname" };
  }
  if (cause === "negotiation") {
    return {
      kind: "other",
      cause,
      message: `algorithm negotiation failed: ${firstLine(stderr)}`,
    };
  }
  if (/identity file .* not found|no such identity/.test(lower)) {
    return {
      kind: "other",
      cause: null,
      message: "the identity file was not found on the control host",
    };
  }
  const raw = firstLine(stderr);
  return {
    kind: "other",
    cause: null,
    message: raw !== ""
      ? raw
      : `ssh failed (exit 255) for ${user}@${host}:${port}`,
  };
}

function firstLine(text: string): string {
  const line = text.split("\n").map((l) => l.trim()).find((l) => l !== "");
  return line ?? "";
}

/** True when a line proves the session closed before authentication completed. */
function isDroppedBeforeAuth(lines: string[]): boolean {
  return lines.some((l) => {
    const t = l.trimStart().toLowerCase();
    return t.startsWith(KEX_PREFIX) || t.startsWith(BANNER_TIMEOUT);
  });
}

/** True for a mid-session loss, per the anchored triggers. */
function isMidSessionLoss(lines: string[], stderr: string): boolean {
  const lower = stderr.toLowerCase();
  if (lower.includes("connection reset by peer")) return true;
  for (let i = 0; i < lines.length; i++) {
    const l = lines[i].trim();
    const low = l.toLowerCase();
    if (/^connection to .+ closed by remote host\.?$/.test(low)) return true;
    if (/^read from remote host .+: connection reset by peer$/.test(low)) {
      return true;
    }
    if (low === "client_loop: send disconnect: broken pipe") return true;
    if (
      /^connection closed by .+ port \d+$/.test(low) ||
      /^connection reset by .+ port \d+$/.test(low)
    ) {
      // Ambiguous alone: only a preceding kex line makes it pre-session.
      const prev = i > 0 ? lines[i - 1].trimStart().toLowerCase() : "";
      const prev2 = i > 1 ? lines[i - 2].trimStart().toLowerCase() : "";
      if (prev.startsWith(KEX_PREFIX) || prev2.startsWith(KEX_PREFIX)) continue;
      return true;
    }
  }
  return false;
}

/** True when stderr is sudo's password or tty refusal. */
export function isSudoRefusal(stderr: string): boolean {
  const l = stderr.toLowerCase();
  return l.includes("a password is required") ||
    l.includes("must have a tty") ||
    l.includes("a terminal is required") || l.includes("no tty present") ||
    l.includes("sudo: a password");
}

/** How a step may be re-sent after a lost session. */
export type ResendPolicy = "never" | "dropped" | "any";

/** Runs one step, applying the re-send policy and logging retried blips. */
export async function runStep(
  deps: { sleep: (ms: number) => Promise<void> },
  session: SshSession,
  opts: RunOptions & {
    phase: string;
    resend: ResendPolicy;
    maxAttempts?: number;
  },
  log?: { warn: (msg: string, props?: Record<string, unknown>) => void },
): Promise<CommandResult> {
  const maxAttempts = opts.maxAttempts ?? 3;
  let attempt = 0;
  for (;;) {
    attempt++;
    try {
      return await session.run(opts);
    } catch (e) {
      if (!(e instanceof TransportError)) throw e;
      const mayResend = opts.resend === "any" ||
        (opts.resend === "dropped" && e.kind === "dropped-before-auth");
      if (mayResend && attempt < maxAttempts) {
        log?.warn("Retrying {phase} after a transport blip", {
          phase: opts.phase,
          kind: e.kind,
          attempt,
        });
        await deps.sleep(cappedBackoff(attempt - 1, 5000, 0.5));
        continue;
      }
      if (opts.resend !== "any" && e.kind !== "dropped-before-auth") {
        fail(`${opts.phase}-outcome-unknown`, e.message, {
          host: session.target.host,
          kind: e.kind,
          cause: e.sessionCause ?? undefined,
        });
      }
      throw e;
    }
  }
}

/** A step whose command is expected to fail; a sudo refusal still throws. */
export function assertNotSudoRefusal(result: CommandResult): CommandResult {
  if (result.code !== 0 && isSudoRefusal(result.stderr)) {
    throw new SudoPolicyError(
      "passwordless sudo is required; fix the target's sudoers and do not retry",
    );
  }
  return result;
}
