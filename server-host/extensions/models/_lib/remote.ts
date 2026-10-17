/**
 * One way to run a shell script on the host: the script text goes over the
 * SSH session's stdin to `sh -s`, never on the remote command line and never
 * through a remote temp file. Caller values reach it only as positional
 * parameters (each one `posixQuote`d into a `set --`), and the bytes a script
 * installs travel base64-encoded inside the same stdin, read back through the
 * `bw_data` function.
 *
 * Every call carries a remote deadline: the body runs under `timeout` inside a
 * shell that survives it, so a hung command ends as exit 124 or 137 and not as
 * a killed ssh (exit 255, a transport error). The local ssh deadline is set
 * past the remote one, so the host-side bound always fires first.
 *
 * @module
 */

import {
  posixQuote,
  remoteTimeout,
  script,
  type ScriptOptions,
} from "./bogworks/remote-script.ts";
import { exec, type ExecResult, type SshDeps, type SshTarget } from "./ssh.ts";

/** Seconds `timeout` waits after TERM before it sends KILL. */
const KILL_AFTER_S = 5;
/** Seconds the local ssh deadline exceeds the remote deadline by. */
const LOCAL_SLACK_S = 20;

/** Exit codes `timeout` produces when the deadline fires (TERM, then KILL). */
export const DEADLINE_EXITS: readonly number[] = [124, 137];

/** One script to run on the host. */
export interface RemoteCall {
  /** Run through non-interactive `sudo`. */
  sudo: boolean;
  /** POSIX sh text. It reads its arguments as `"$1"`, `"$2"`, ... */
  script: string;
  /** Positional parameters of the script. */
  args?: string[];
  /** Bytes the script reads by calling `bw_data`. */
  data?: Uint8Array;
  /** Remote deadline in seconds. */
  deadlineS: number;
  /** Serialise under `flock` on this path, waiting at most `waitSec`. */
  lock?: ScriptOptions["lock"];
  /** Shell text the EXIT trap runs, for example to remove a temp file. */
  cleanup?: string;
  /** Octal umask set before anything else. */
  umask?: string;
}

/** Prefixes `argv` with a non-interactive `sudo` when `sudo` is true. */
export function withSudo(sudo: boolean, argv: string[]): string[] {
  return sudo ? ["sudo", "-n", ...argv] : argv;
}

/** Standard base64 of `bytes`. */
function base64(bytes: Uint8Array): string {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin);
}

/**
 * The full script text a call sends: the data function and the positional
 * parameters first, then the body inside the canonical prologue (`set -eu`,
 * traps, optional lock).
 */
export function renderScript(call: RemoteCall): string {
  const head: string[] = [];
  if (call.data !== undefined) {
    head.push(
      `bw_data() { printf '%s' ${posixQuote(base64(call.data))} | base64 -d; }`,
    );
  }
  if (call.args !== undefined && call.args.length > 0) {
    head.push(`set -- ${call.args.map(posixQuote).join(" ")}`);
  }
  const opts: ScriptOptions = {
    body: [...head, call.script].join("\n"),
    ...(call.lock ? { lock: call.lock } : {}),
    ...(call.cleanup ? { cleanup: call.cleanup } : {}),
    ...(call.umask ? { umask: call.umask } : {}),
  };
  return script(opts);
}

/** The ssh argv and stdin that run `call`, plus the local deadline. */
export function renderRemote(
  call: RemoteCall,
): { argv: string[]; stdin: string; timeoutMs: number } {
  return {
    argv: withSudo(call.sudo, ["sh", "-s"]),
    stdin: remoteTimeout({
      sec: call.deadlineS,
      killAfterSec: KILL_AFTER_S,
      body: renderScript(call),
    }),
    timeoutMs: (call.deadlineS + KILL_AFTER_S + LOCAL_SLACK_S) * 1000,
  };
}

/** Runs `call` on `target` through the SSH transport. */
export async function runRemote(
  deps: SshDeps,
  target: SshTarget,
  call: RemoteCall,
): Promise<ExecResult> {
  const { argv, stdin, timeoutMs } = renderRemote(call);
  return await exec(deps, target, argv, { stdin, timeoutMs });
}
