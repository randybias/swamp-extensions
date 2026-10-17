/**
 * Execution of Ceph CLI commands through `cephadm shell`.
 *
 * A `ceph ...` command is never assembled as
 * `cephadm shell -- bash -c "..."`, because caps such as `mon 'allow r'`
 * break under three nested quoting layers. Instead the commands are written to
 * a fresh private script file inside a `mktemp -d` directory, bind-mounted into
 * the container and run, then the directory is removed whether the command
 * succeeded or not. The JSON variant parses stdout, treating the single human
 * line some list commands print when empty as an empty list.
 *
 * @module
 */

import { fail } from "./errors.ts";
import type { CommandResult, ResendPolicy, SshSession } from "./ssh.ts";
import { runStep } from "./ssh.ts";
import { quote, truncate } from "./validate.ts";
import { CEPHADM_SHELL_FLOOR_MS, type PrepDeps } from "./hostprep.ts";

/** Options for one cephadm-shell command. */
export interface CephRunOptions {
  /** Append `-f json` and parse stdout. */
  json?: boolean;
  /** Requested budget; raised to the shell floor. */
  budgetMs?: number;
  /** Phase label for re-send errors. */
  phase: string;
  /** How a lost session may be re-sent. */
  resend?: ResendPolicy;
  /** Return a non-zero exit instead of throwing (transport errors still throw). */
  allowNonZero?: boolean;
}

/** Result of one cephadm-shell command. */
export interface CephRunResult {
  /** The raw command result. */
  result: CommandResult;
  /** Parsed JSON when `json` was requested, else undefined. */
  json?: unknown;
}

/** A file to write into the private script directory before the run. */
export interface ScriptFile {
  /** File name inside the directory. */
  name: string;
  /** File content. */
  content: string;
  /** File mode; default 0600. */
  mode?: string;
}

/** Options for an arbitrary cephadm-shell script. */
export interface CephScriptOptions {
  /** Commands after the `set -euo pipefail` line. */
  body: string;
  /** Extra files written into the private directory. */
  files?: ScriptFile[];
  /** Append `-f json` and parse stdout (for a plain ceph command). */
  json?: boolean;
  /** Requested budget; raised to the shell floor. */
  budgetMs?: number;
  /** Phase label for re-send errors. */
  phase: string;
  /** How a lost session may be re-sent. */
  resend?: ResendPolicy;
  /** Return a non-zero exit instead of throwing (transport errors still throw). */
  allowNonZero?: boolean;
}

/** A short random hex string from the injected randomness source. */
export function randomHex(random: () => number, chars: number): string {
  let out = "";
  while (out.length < chars) {
    const byte = Math.floor(random() * 256) & 0xff;
    out += byte.toString(16).padStart(2, "0");
  }
  return out.slice(0, chars);
}

/** The script body for a set of Ceph arguments. */
export function cephScriptBody(cephArgs: string, json: boolean): string {
  const suffix = json ? " -f json" : "";
  return `#!/bin/bash\nset -euo pipefail\nceph ${cephArgs}${suffix}\n`;
}

/** The full script body for arbitrary commands. */
export function scriptBody(body: string): string {
  return `#!/bin/bash\nset -euo pipefail\n${body}\n`;
}

/** The remote command that writes a script file from stdin and chmods it. */
export function writeScriptCommand(path: string, mode = "0700"): string {
  return `umask 022; cat > ${quote(path)} && chmod ${quote(mode)} ${
    quote(path)
  }`;
}

/** The remote command that runs a mounted script inside cephadm shell. */
export function shellRunCommand(dir: string, scriptPath: string): string {
  return `cephadm shell --mount ${quote(`${dir}:${dir}`)} -- bash ${
    quote(scriptPath)
  }`;
}

/** Parses JSON stdout, reading the lone "No <things> reported" line as an empty list. */
export function parseCephJson(stdout: string, phase: string): unknown {
  const trimmed = stdout.trim();
  if (trimmed === "") return null;
  if (/^No .+ reported$/.test(trimmed)) return [];
  try {
    return JSON.parse(trimmed);
  } catch {
    fail(`${phase}.json`, "ceph returned output that is not JSON", {
      stdout: truncate(trimmed, 300),
    });
  }
}

/**
 * Runs an arbitrary script through cephadm shell, writing a private directory
 * and script, running it under sudo, and removing the directory in all cases.
 */
export async function runCephScript(
  deps: PrepDeps,
  session: SshSession,
  opts: CephScriptOptions,
  log?: { warn: (message: string, props?: Record<string, unknown>) => void },
): Promise<CephRunResult> {
  const requested = opts.budgetMs ?? CEPHADM_SHELL_FLOOR_MS;
  const budgetMs = Math.max(CEPHADM_SHELL_FLOOR_MS, requested);
  if (budgetMs > requested) {
    log?.warn("Raised the command budget to the cephadm-shell floor", {
      requestedMs: requested,
      budgetMs,
    });
  }
  const dirResult = await runStep(deps, session, {
    command: "mktemp -d",
    phase: `${opts.phase}.mktemp`,
    resend: "any",
  });
  const dir = dirResult.stdout.trim();
  if (dir === "") fail(`${opts.phase}.mktemp`, "mktemp -d returned no path");
  const scriptPath = `${dir}/run-${randomHex(deps.random, 12)}.sh`;
  let result: CephRunResult;
  try {
    for (const file of opts.files ?? []) {
      await runStep(deps, session, {
        command: writeScriptCommand(`${dir}/${file.name}`, file.mode ?? "0600"),
        stdin: file.content,
        phase: `${opts.phase}.write`,
        resend: "dropped",
      });
    }
    await runStep(deps, session, {
      command: writeScriptCommand(scriptPath),
      stdin: scriptBody(opts.body),
      phase: `${opts.phase}.write`,
      resend: "dropped",
    });
    const run = await runStep(deps, session, {
      command: shellRunCommand(dir, scriptPath),
      sudo: true,
      budgetMs,
      allowNonZero: opts.allowNonZero ?? true,
      phase: opts.phase,
      resend: opts.resend ?? "dropped",
    });
    result = {
      result: run,
      ...(opts.json ? { json: parseCephJson(run.stdout, opts.phase) } : {}),
    };
  } finally {
    // Best effort: a removal failure must not mask the command's own result.
    try {
      await session.run({
        command: `rm -rf ${quote(dir)}`,
        allowNonZero: true,
      });
    } catch {
      log?.warn("Could not remove the cephadm-shell script directory", { dir });
    }
  }
  return result;
}

/**
 * Runs one `ceph <args>` command through cephadm shell, writing a private
 * script, running it under sudo, and removing the directory in all cases.
 */
export async function runCeph(
  deps: PrepDeps,
  session: SshSession,
  cephArgs: string,
  opts: CephRunOptions,
  log?: { warn: (message: string, props?: Record<string, unknown>) => void },
): Promise<CephRunResult> {
  return await runCephScript(
    deps,
    session,
    {
      body: `ceph ${cephArgs}${opts.json ? " -f json" : ""}`,
      json: opts.json,
      budgetMs: opts.budgetMs,
      phase: opts.phase,
      resend: opts.resend,
      allowNonZero: opts.allowNonZero,
    },
    log,
  );
}
