/**
 * Builders for the canonical remote shell shape used by swamp extensions.
 * Every rendered script runs under `dash` with `set -eu`; signals are turned
 * into normal exits so the `EXIT` trap always cleans up; a change is
 * serialised under `flock`; waits on post-state are bounded settle retries;
 * anything that must survive the SSH session runs as a detached transient
 * unit; and anything that may hang is bounded by the remote `timeout` inside a
 * shell that survives it (so ssh never exits 255 for a killed command).
 *
 * {@link posixQuote} is the ONE quoting helper: every caller value crosses
 * into shell text through it and nothing else.
 *
 * The module imports nothing, so it can be vendored byte-identical into an
 * extension's `extensions/models/_lib/bogworks/` directory.
 *
 * @module
 */

/** Exit code when the lock is busy or settle retries are exhausted (EX_TEMPFAIL). */
export const EXIT_TEMPFAIL = 75;

/** Exit codes the signal traps map to (128 + signal number). */
export const SIGNAL_EXITS = { HUP: 129, INT: 130, PIPE: 141, TERM: 143 } as const;

/**
 * Quotes `value` for a POSIX shell as one literal word. Single quotes are the
 * only characters that can break out of a single-quoted string; each is closed,
 * escaped and reopened. The result never contains an unquoted metacharacter.
 * Identical to the canonical transport's helper.
 */
export function posixQuote(value: string): string {
  if (typeof value !== "string") {
    throw new TypeError("posixQuote: value must be a string");
  }
  if (value.includes("\u0000")) {
    throw new Error("posixQuote: a NUL byte cannot be carried in shell text");
  }
  if (value === "") return "''";
  return `'${value.replace(/'/g, "'\\''")}'`;
}

/** Grammar for absolute lock paths: safe characters only. */
export const LOCK_PATH_RE = /^\/[A-Za-z0-9._\/-]{1,4095}$/;

/** Grammar for a transient systemd unit name (no instance `@`, no suffix). */
export const UNIT_NAME_RE = /^[A-Za-z0-9][A-Za-z0-9:_.-]{0,230}$/;

/** Throws unless `n` is an integer in `[min, max]`. */
function assertInt(label: string, n: number, min: number, max: number): void {
  if (!Number.isInteger(n) || n < min || n > max) {
    throw new Error(`${label} must be an integer from ${min} to ${max}, got ${n}`);
  }
}

/** Throws unless `body` is shell text the builders can embed. */
function assertBody(label: string, body: string): void {
  if (typeof body !== "string" || body.trim() === "") {
    throw new Error(`${label} must be a non-empty string`);
  }
  if (body.includes("\u0000")) throw new Error(`${label} must not contain NUL`);
}

/** Options for {@link script}. */
export interface ScriptOptions {
  /** The script body; runs after the prologue. */
  body: string;
  /**
   * Serialise under `flock` on `path`, waiting up to `waitSec`. A busy lock
   * exits {@link EXIT_TEMPFAIL} (75) with a one-line stderr message, and a host
   * without `flock` is refused the same way before anything is touched.
   */
  lock?: { path: string; waitSec: number };
  /**
   * Install the traps (default true): an `EXIT` trap running `cleanup`, and
   * HUP/INT/TERM/PIPE traps that `exit 129/130/143/141` so the EXIT trap runs.
   */
  traps?: boolean;
  /** Shell text run by the EXIT trap; defaults to a no-op. */
  cleanup?: string;
  /** Octal umask to set first, e.g. `077`; none by default. */
  umask?: string;
}

/**
 * Renders the canonical script: `set -eu`, optional umask, a `bw_cleanup`
 * function and EXIT trap, the signal traps, the optional lock, then the body.
 * The signal traps turn a signal into a normal `exit`, which is what makes the
 * EXIT trap (and so the cleanup) run on TERM/HUP/INT/PIPE.
 */
export function script(opts: ScriptOptions): string {
  assertBody("body", opts.body);
  const lines: string[] = ["set -eu"];
  if (opts.umask !== undefined) {
    if (!/^[0-7]{3,4}$/.test(opts.umask)) {
      throw new Error(`umask must be 3 or 4 octal digits, got ${opts.umask}`);
    }
    lines.push(`umask ${opts.umask}`);
  }
  if (opts.traps ?? true) {
    if (opts.cleanup !== undefined) assertBody("cleanup", opts.cleanup);
    const cleanup = opts.cleanup ?? ":";
    lines.push(
      "bw_cleanup() {",
      ...cleanup.split("\n").map((l) => `  ${l}`),
      "}",
      "trap bw_cleanup EXIT",
      `trap 'exit ${SIGNAL_EXITS.HUP}' HUP`,
      `trap 'exit ${SIGNAL_EXITS.INT}' INT`,
      `trap 'exit ${SIGNAL_EXITS.TERM}' TERM`,
      `trap 'exit ${SIGNAL_EXITS.PIPE}' PIPE`,
    );
  } else if (opts.cleanup !== undefined) {
    throw new Error("cleanup requires traps");
  }
  if (opts.lock) {
    if (!LOCK_PATH_RE.test(opts.lock.path)) {
      throw new Error(`lock.path must be an absolute safe path, got ${opts.lock.path}`);
    }
    assertInt("lock.waitSec", opts.lock.waitSec, 1, 86400);
    const p = posixQuote(opts.lock.path);
    lines.push(
      "if ! command -v flock >/dev/null 2>&1; then " +
        `echo 'flock is required' >&2; exit ${EXIT_TEMPFAIL}; fi`,
      `exec 9>${p}`,
      `if ! flock -w ${opts.lock.waitSec} 9; then ` +
        `echo ${posixQuote(`lock busy: ${opts.lock.path}`)} >&2; ` +
        `exit ${EXIT_TEMPFAIL}; fi`,
    );
  }
  lines.push(opts.body);
  return lines.join("\n") + "\n";
}

/** Options for {@link settleRetry}. */
export interface SettleRetryOptions {
  /** Shell text whose success (exit 0) ends the wait. */
  cmd: string;
  /** Seconds between attempts, 1 or more (POSIX `sleep` takes integers). */
  everySec: number;
  /** Total bound in seconds; the number of attempts is `ceil(maxSec / everySec)`. */
  maxSec: number;
  /** Shell text run when the bound is reached; defaults to `exit 75`. */
  onFail?: string;
  /** Label for the stderr message; defaults to the command text. */
  label?: string;
}

/**
 * Renders a bounded retry loop: `cmd` is run up to `ceil(maxSec/everySec)`
 * times with `everySec` of sleep between attempts, and `onFail` (default
 * `exit 75`) runs after the last failure. The condition sits in `until`, so it
 * is exempt from `set -e`. Judge post-state with it; never a tool's exit code.
 */
export function settleRetry(opts: SettleRetryOptions): string {
  assertBody("cmd", opts.cmd);
  assertInt("everySec", opts.everySec, 1, 3600);
  assertInt("maxSec", opts.maxSec, 1, 86400);
  const tries = Math.ceil(opts.maxSec / opts.everySec);
  const onFail = opts.onFail ?? `exit ${EXIT_TEMPFAIL}`;
  assertBody("onFail", onFail);
  const label = opts.label ?? opts.cmd;
  const msg = posixQuote(`settle: ${label} did not succeed within ${opts.maxSec}s`);
  return [
    "bw_attempt=0",
    `until ${opts.cmd}; do`,
    "  bw_attempt=$((bw_attempt + 1))",
    `  if [ "$bw_attempt" -ge ${tries} ]; then`,
    `    echo ${msg} >&2`,
    ...onFail.split("\n").map((l) => `    ${l}`),
    "  fi",
    `  sleep ${opts.everySec}`,
    "done",
  ].join("\n") + "\n";
}

/** Options for {@link detachedUnit}. */
export interface DetachedUnitOptions {
  /** Transient unit name; validated against {@link UNIT_NAME_RE}. */
  name: string;
  /** Shell text the unit runs under `/bin/sh -c`. */
  script: string;
  /** Extra `--property=` settings, e.g. `["KillMode=process"]`. */
  properties?: string[];
}

/**
 * Renders a `systemd-run --unit=<name> --no-block --collect` command that runs
 * `script` under `/bin/sh -c` as a transient service, detached from the SSH
 * session that started it. `--collect` removes the unit after it finishes so a
 * re-arm with the same name is not refused by a lingering failed unit.
 */
export function detachedUnit(opts: DetachedUnitOptions): string {
  if (!UNIT_NAME_RE.test(opts.name)) {
    throw new Error(`invalid unit name ${JSON.stringify(opts.name)}`);
  }
  assertBody("script", opts.script);
  // Grammar AND quoting: a property is a word from a closed alphabet (no shell
  // operators, no `$`), and the whole argument still crosses into shell text
  // through posixQuote like every other caller value.
  const props = (opts.properties ?? []).map((p) => {
    if (!/^[A-Za-z]+=[A-Za-z0-9._:@/=,+-]+$/.test(p)) {
      throw new Error(`invalid unit property ${JSON.stringify(p)}`);
    }
    return posixQuote(`--property=${p}`);
  });
  return [
    "systemd-run",
    `--unit=${opts.name}`,
    "--no-block",
    "--collect",
    ...props,
    "/bin/sh",
    "-c",
    posixQuote(opts.script),
  ].join(" ");
}

/** Options for {@link remoteTimeout}. */
export interface RemoteTimeoutOptions {
  /** Seconds before the body's process group gets TERM. */
  sec: number;
  /** Seconds after TERM before KILL; defaults to 5. */
  killAfterSec?: number;
  /** The shell text to bound. */
  body: string;
}

/**
 * Renders `timeout -k <killAfterSec> <sec> sh -c <body>; exit $?`: the body
 * runs in its own process group under `timeout`, and the surviving outer
 * shell reports 124 (TERM) or 137 (KILL) as a normal exit. Pass the result as
 * `["sh", "-c", ...]` to `exec`; never put `timeout` itself on the top-level
 * remote argv, because a killed top-level command makes ssh exit 255, which
 * the canonical transport classifies as a transport failure.
 */
export function remoteTimeout(opts: RemoteTimeoutOptions): string {
  assertInt("sec", opts.sec, 1, 86400);
  const kill = opts.killAfterSec ?? 5;
  assertInt("killAfterSec", kill, 1, 3600);
  assertBody("body", opts.body);
  return `timeout -k ${kill} ${opts.sec} sh -c ${posixQuote(opts.body)}; exit $?`;
}
