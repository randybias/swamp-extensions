/**
 * The cephadm session layer over the canonical vendored `_lib/ssh.ts`.
 *
 * The canonical transport owns host-key verification, credential delivery and
 * the ssh argv; this module only preserves the shape the cephadm modules use
 * (`session.run({command, stdin, sudo, allowNonZero, budgetMs})` plus the
 * `runStep` re-send policy). `command` is a shell string, so it is run through
 * `sh -c`; `stdin` streams to the child and never reaches argv. Multiplexing and
 * the inline-key control-socket map are gone: each call opens a fresh
 * connection and the canonical transport loads the key into a short-lived
 * ssh-agent over stdin.
 *
 * @module
 */

import {
  buildKnownHosts,
  type CommandRunner,
  exec as canonExec,
  type ExecResult,
  type HostKey,
  SshConfigError,
  type SshDeps as CanonicalSshDeps,
  SshError,
  type SshTarget,
  waitConnection,
} from "./ssh.ts";
import {
  type HostKeys,
  hostKeysName,
  HostKeysSchema,
  resolvePins,
} from "./hostkeys.ts";
import { cappedBackoff } from "./backoff.ts";
import {
  fail,
  LocalRefusalError,
  RemoteExitError,
  SudoPolicyError,
  TransportError,
} from "./errors.ts";
import type { PreSessionCause, TransportKind } from "./errors.ts";

const encoder = new TextEncoder();
const decoder = new TextDecoder();

/** A remote command's outcome. */
export interface CommandResult {
  /** Remote exit code. */
  code: number;
  /** Remote standard output. */
  stdout: string;
  /** Remote standard error. */
  stderr: string;
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

/** Spawns one command; the environment carries the agent socket, never a secret. */
export type Spawner = (
  cmd: string,
  args: string[],
  env?: Record<string, string>,
) => SpawnedChild;

/** Spawner seam plus the clock; the canonical transport is built from these. */
export interface SshDeps {
  /** Spawns the process. */
  spawn: Spawner;
  /** Current time in milliseconds. */
  now: () => number;
  /** Sleeps for the given milliseconds. */
  sleep: (ms: number) => Promise<void>;
  /** Overrides the kill grace period; unused now, kept for callers. */
  killGraceMs?: number;
}

/** Production spawner backed by `Deno.Command`. */
export const denoSpawner: Spawner = (cmd, args, env) => {
  // swamp-quality-ignore deno-command
  const child = new Deno.Command(cmd, {
    args,
    stdin: "piped",
    stdout: "piped",
    stderr: "piped",
    env,
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

/** Options for one remote command. */
export interface RunOptions {
  /** Remote shell command, run through `sh -c`. */
  command: string;
  /** Content written to the child's stdin, then closed. */
  stdin?: string;
  /** Return a non-zero remote exit instead of throwing, except transport errors. */
  allowNonZero?: boolean;
  /** Prefix the command with `sudo -n --`. */
  sudo?: boolean;
  /** Per-call timeout in milliseconds. */
  budgetMs?: number;
}

/** The target fields `runStep` reports on. */
export interface SessionTarget {
  /** Host name or IP literal. */
  host: string;
  /** SSH port. */
  port?: number;
}

/** A live SSH session to one target. */
export interface SshSession {
  /** Target being dialled. */
  target: SessionTarget;
  /** Runs one command. */
  run(opts: RunOptions): Promise<CommandResult>;
  /** Always a no-op now: there is no multiplexed master to close. */
  close(): Promise<{ closed: boolean; detail: string }>;
}

/** Bridges the spawner seam onto the canonical `CommandRunner`. */
function canonicalDeps(deps: SshDeps): CanonicalSshDeps {
  const run: CommandRunner = async (cmd, args, options = {}) => {
    const child = deps.spawn(cmd, args, options.env);
    let timedOut = false;
    const timer = options.timeoutMs === undefined ? undefined : setTimeout(
      () => {
        timedOut = true;
        child.kill();
      },
      options.timeoutMs,
    );
    try {
      const writer = child.stdin.getWriter();
      if (options.stdin !== undefined) {
        await writer.write(
          typeof options.stdin === "string"
            ? encoder.encode(options.stdin)
            : options.stdin,
        );
      }
      await writer.close();
      const out = await child.output();
      return {
        code: out.code,
        stdout: decoder.decode(out.stdout),
        stderr: decoder.decode(out.stderr),
        timedOut,
      };
    } finally {
      if (timer !== undefined) clearTimeout(timer);
    }
  };
  return { run, now: deps.now, sleep: deps.sleep };
}

function assertNoNul(value: string, what: string): void {
  if (value.includes("\0")) {
    throw new LocalRefusalError(`${what} contains a NUL byte`);
  }
}

/** Maps a canonical transport or config error onto the cephadm vocabulary. */
function toTransportError(e: unknown, target: SshTarget): TransportError {
  if (e instanceof TransportError) return e;
  if (e instanceof SshConfigError) {
    return new TransportError({
      host: target.host,
      port: target.port,
      user: target.user,
      kind: "other",
      cause: null,
      message: e.message,
    });
  }
  if (e instanceof SshError) {
    const kind: TransportKind = e.kind === "timeout"
      ? "aborted"
      : /connect|refused|resolve|route|timed out|host key|authentication|permission/i
          .test(e.message)
      ? "dropped-before-auth"
      : "other";
    const cause: PreSessionCause = kind === "dropped-before-auth"
      ? /host key/i.test(e.message)
        ? "negotiation"
        : /permission|authentication/i.test(e.message)
        ? "auth"
        : "connect-refused"
      : null;
    return new TransportError({
      host: target.host,
      port: target.port,
      user: target.user,
      kind,
      cause,
      message: e.message,
    });
  }
  return new TransportError({
    host: target.host,
    port: target.port,
    user: target.user,
    kind: "other",
    cause: null,
    message: (e as Error).message,
  });
}

/** The cephadm connection fields a session is built from. */
export interface SessionRequest {
  /** Host name or IP literal. */
  host: string;
  /** Login user. */
  sshUser?: string | null;
  /** SSH port; absent means 22. */
  port?: number | null;
  /** Local private-key path; mutually exclusive with privateKey. */
  keyPath?: string | null;
  /** Private-key content; mutually exclusive with keyPath. */
  privateKey?: string | null;
  /** Host-key policy; required. */
  host_key_policy: "strict" | "insecure_tofu";
  /** Pinned ssh-keyscan lines. */
  host_keys?: string[] | null;
}

/** The resource surface the TOFU learning needs; the model context satisfies it. */
export interface SessionContext {
  /** Reads a resource by instance name, or null when the context has none. */
  readResource?: (name: string) => Promise<Record<string, unknown> | null>;
  /** Writes a resource. */
  writeResource: (
    specName: string,
    name: string,
    data: Record<string, unknown>,
  ) => Promise<unknown>;
}

/** Validates the connection fields; `host_key_policy` is required. */
export function toTarget(fields: SessionRequest): SessionRequest {
  if (
    fields.host_key_policy !== "strict" &&
    fields.host_key_policy !== "insecure_tofu"
  ) {
    throw new LocalRefusalError(
      "host_key_policy is required (strict or insecure_tofu)",
    );
  }
  return fields;
}

/** ssh-keyscan lines for learned keys, with a port-aware host field. */
function knownHostsLines(
  host: string,
  port: number,
  keys: HostKey[],
): string[] {
  return buildKnownHosts(host, port, keys).split("\n").filter((l) => l !== "");
}

/**
 * Resolves the canonical target: pins from the request or the `hostkeys`
 * record, or — for a first `insecure_tofu` contact — learned with
 * `waitConnection` and persisted per host:port.
 */
async function resolveTarget(
  deps: SshDeps,
  request: SessionRequest,
  context: SessionContext,
): Promise<SshTarget> {
  const host = request.host;
  const port = request.port ?? 22;
  const user = request.sshUser ?? "";
  const key = hostKeysName(host, port);
  const stored = (await context.readResource?.(key) ?? null) as HostKeys | null;
  const decision = resolvePins({
    host,
    port,
    host_key_policy: request.host_key_policy,
    supplied: request.host_keys,
    stored,
  });
  let pins = decision.hostKeys;
  if (decision.learn) {
    const probe: SshTarget = {
      host,
      port,
      user,
      host_key_policy: "insecure_tofu",
      connect_timeout_s: 15,
    };
    const wait = await waitConnection(canonicalDeps(deps), probe, {
      timeout_s: 60,
    });
    if (!wait.reachable || wait.host_keys.length === 0) {
      throw new TransportError({
        host,
        port,
        user,
        kind: "dropped-before-auth",
        cause: "connect-timeout",
        message: "the host did not answer SSH with a usable host key",
      });
    }
    pins = knownHostsLines(host, port, wait.host_keys);
    await context.writeResource(
      "hostkeys",
      key,
      HostKeysSchema.parse({
        host,
        port,
        host_keys: pins,
        learned_at: new Date(deps.now()).toISOString(),
      }),
    );
  }
  const privateKey = request.privateKey ??
    (request.keyPath !== undefined && request.keyPath !== null
      ? await Deno.readTextFile(request.keyPath)
      : undefined);
  return {
    host,
    port,
    user,
    host_key_policy: request.host_key_policy,
    ...(pins.length > 0 ? { host_keys: pins } : {}),
    ...(privateKey !== undefined && privateKey !== ""
      ? { private_key: privateKey }
      : {}),
    connect_timeout_s: 15,
  };
}

/** Builds the session over an already-resolved canonical target. */
function sessionOn(deps: SshDeps, target: SshTarget): SshSession {
  const canonical = canonicalDeps(deps);
  const run = async (opts: RunOptions): Promise<CommandResult> => {
    const command = opts.sudo ? `sudo -n -- ${opts.command}` : opts.command;
    assertNoNul(command, "command");
    if (opts.stdin !== undefined) assertNoNul(opts.stdin, "stdin");
    let res: ExecResult;
    try {
      res = await canonExec(canonical, target, ["sh", "-c", command], {
        ...(opts.stdin !== undefined ? { stdin: opts.stdin } : {}),
        ...(opts.budgetMs !== undefined ? { timeoutMs: opts.budgetMs } : {}),
      });
    } catch (e) {
      throw toTransportError(e, target);
    }
    if (res.truncated) {
      throw new TransportError({
        host: target.host,
        port: target.port,
        user: target.user,
        kind: "other",
        cause: null,
        message: "stdout was truncated at the capture limit",
      });
    }
    if (res.exit_code !== 0 && opts.sudo && isSudoRefusal(res.stderr)) {
      throw new SudoPolicyError(
        "passwordless sudo is required; fix the target's sudoers and do not retry",
      );
    }
    if (res.exit_code !== 0 && !opts.allowNonZero) {
      throw new RemoteExitError(
        res.exit_code,
        res.stdout,
        res.stderr,
        `${target.user}@${target.host}:${target.port}: ${command}`,
      );
    }
    return { code: res.exit_code, stdout: res.stdout, stderr: res.stderr };
  };
  return {
    target,
    run,
    close: () => Promise.resolve({ closed: true, detail: "not multiplexed" }),
  };
}

/**
 * Opens a session on the canonical transport, resolving (and, on a first
 * insecure_tofu contact, learning and persisting) the host-key pins.
 */
export async function openSession(
  deps: SshDeps,
  request: SessionRequest,
  context: SessionContext,
): Promise<SshSession> {
  const target = await resolveTarget(deps, request, context);
  return sessionOn(deps, target);
}

/** True when stderr is sudo's password or tty refusal. */
export function isSudoRefusal(stderr: string): boolean {
  const l = stderr.toLowerCase();
  return l.includes("a password is required") ||
    l.includes("must have a tty") ||
    l.includes("a terminal is required") || l.includes("no tty present") ||
    l.includes("sudo: a password");
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

/** How a step may be re-sent after a lost session. */
export type ResendPolicy = "never" | "dropped" | "any";

/** The minimal session `runStep` needs; a fake session satisfies it. */
export interface StepSession {
  /** Target being dialled. */
  target: { host: string };
  /** Runs one command. */
  run(opts: RunOptions): Promise<CommandResult>;
}

/** Runs one step, applying the re-send policy and logging retried blips. */
export async function runStep(
  deps: { sleep: (ms: number) => Promise<void> },
  session: StepSession,
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
