/**
 * The cephadm session layer over the canonical vendored `_lib/ssh.ts`.
 *
 * The canonical transport owns host-key verification, credential delivery and
 * the ssh argv; this module only preserves the shape the cephadm modules use
 * (`session.run({command, stdin, sudo, allowNonZero, budgetMs})` plus the
 * `runStep` re-send policy). `command` is a shell string, so it is run through
 * `sh -c`; `stdin` streams to the child and never reaches argv. There is no
 * multiplexing and no in-memory key map: the canonical transport loads the key
 * into a short-lived ssh-agent over stdin.
 *
 * @module
 */

import {
  buildKnownHosts,
  exec as canonExec,
  type ExecResult,
  type HostKey,
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

/** The canonical transport dependencies. */
export type SshDeps = CanonicalSshDeps;

/** Default per-call budget in milliseconds when a caller gives none. */
export const DEFAULT_BUDGET_MS = 30_000;
/** Extra milliseconds allowed before the whole ssh process is killed. */
export const KILL_GRACE_MS = 5_000;

/** A remote command's outcome. */
export interface CommandResult {
  /** Remote exit code. */
  code: number;
  /** Remote standard output. */
  stdout: string;
  /** Remote standard error. */
  stderr: string;
}

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
  /** Per-call budget in milliseconds; the ssh kill is delayed by the grace. */
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
  /** A no-op now: there is no multiplexed master to close. */
  close(): Promise<{ closed: boolean; detail: string }>;
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
  /** Reads a resource by instance name, or null. */
  readResource: (name: string) => Promise<Record<string, unknown> | null>;
  /** Writes a resource. */
  writeResource: (
    specName: string,
    name: string,
    data: Record<string, unknown>,
  ) => Promise<unknown>;
}

/**
 * Validates the connection fields. `host_key_policy` is required and the two
 * key sources are mutually exclusive.
 */
export function toTarget(fields: SessionRequest): SessionRequest {
  if (
    fields.host_key_policy !== "strict" &&
    fields.host_key_policy !== "insecure_tofu"
  ) {
    throw new LocalRefusalError(
      "host_key_policy is required (strict or insecure_tofu)",
    );
  }
  const keyPath = fields.keyPath;
  const privateKey = fields.privateKey;
  if (
    keyPath !== undefined && keyPath !== null && keyPath !== "" &&
    privateKey !== undefined && privateKey !== null && privateKey !== ""
  ) {
    throw new LocalRefusalError(
      "both keyPath and privateKey were set; pass exactly one",
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

function assertNoNul(value: string, what: string): void {
  if (value.includes("\0")) {
    throw new LocalRefusalError(`${what} contains a NUL byte`);
  }
}

/**
 * Maps a canonical transport error onto the cephadm vocabulary. Only the
 * canonical's own typed timeout is retryable; every other failure, including a
 * mid-session reset or an authentication failure, is outcome-unknown and is
 * never classified from message text, so `runStep` cannot re-send a command
 * that may have run.
 */
function toTransportError(e: unknown, target: SshTarget): TransportError {
  if (e instanceof TransportError) return e;
  const kind = e instanceof SshError && e.kind === "timeout"
    ? "aborted"
    : "other";
  return new TransportError({
    host: target.host,
    port: target.port,
    user: target.user,
    kind,
    cause: null,
    message: (e as Error).message,
  });
}

/** Pins learned on a first contact, persisted after the first command runs. */
interface PendingPins {
  key: string;
  host: string;
  port: number;
  pins: string[];
}

/** Builds the session over an already-resolved canonical target. */
function sessionOn(
  deps: SshDeps,
  target: SshTarget,
  pending?: PendingPins,
  context?: SessionContext,
): SshSession {
  let persisted = pending === undefined;
  const persist = async (): Promise<void> => {
    if (persisted || pending === undefined || context === undefined) return;
    persisted = true;
    await context.writeResource(
      "hostkeys",
      pending.key,
      HostKeysSchema.parse({
        host: pending.host,
        port: pending.port,
        host_keys: pending.pins,
        learned_at: new Date(deps.now()).toISOString(),
      }),
    );
  };
  const run = async (opts: RunOptions): Promise<CommandResult> => {
    const command = opts.sudo ? `sudo -n -- ${opts.command}` : opts.command;
    assertNoNul(command, "command");
    if (opts.stdin !== undefined) assertNoNul(opts.stdin, "stdin");
    const budgetMs = opts.budgetMs ?? DEFAULT_BUDGET_MS;
    let res: ExecResult;
    try {
      res = await canonExec(deps, target, ["sh", "-c", command], {
        ...(opts.stdin !== undefined ? { stdin: opts.stdin } : {}),
        timeoutMs: budgetMs + KILL_GRACE_MS,
      });
    } catch (e) {
      throw toTransportError(e, target);
    }
    // A first contact authenticated and the command ran; record the pins.
    await persist();
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
 * Opens a session on the canonical transport, resolving the host-key pins. On a
 * first `insecure_tofu` contact the keys are learned with `waitConnection` and
 * pinned for this session; the `hostkeys` record is written only after the
 * first command has run, so a failed first contact is never persisted.
 */
export async function openSession(
  deps: SshDeps,
  request: SessionRequest,
  context: SessionContext,
): Promise<SshSession> {
  const host = request.host;
  const port = request.port ?? 22;
  const user = request.sshUser ?? "";
  const key = hostKeysName(host, port);
  const stored = await context.readResource(key) as HostKeys | null;
  const decision = resolvePins({
    host,
    port,
    host_key_policy: request.host_key_policy,
    supplied: request.host_keys,
    stored,
  });
  let pins = decision.hostKeys;
  let pending: PendingPins | undefined;
  if (decision.learn) {
    const probe: SshTarget = {
      host,
      port,
      user,
      host_key_policy: "insecure_tofu",
      connect_timeout_s: 15,
    };
    const wait = await waitConnection(deps, probe, { timeout_s: 60 });
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
    pending = { key, host, port, pins };
  }
  const privateKey = request.privateKey ??
    (request.keyPath !== undefined && request.keyPath !== null &&
        request.keyPath !== ""
      ? await Deno.readTextFile(request.keyPath)
      : undefined);
  const target: SshTarget = {
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
  return sessionOn(deps, target, pending, context);
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
