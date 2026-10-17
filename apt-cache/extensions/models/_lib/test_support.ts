/**
 * Shared test doubles for the apt-cache tests: a fake SSH transport that
 * records remote commands and simulates uploads, plus small assertion helpers
 * and the fixed test clock.
 *
 * @module
 */

import type { CommandRunner } from "./ssh.ts";
import { setDeps } from "./remote.ts";

/** The fixed clock every test uses. */
export const TEST_NOW = 1_700_000_000_000;

/** A fake command result. */
export interface Resp {
  /** Exit code; defaults to 0. */
  code?: number;
  /** Standard output. */
  stdout?: string;
  /** Standard error. */
  stderr?: string;
}

/** A responder keyed on the raw (quoted) remote command string. */
export type Respond = (command: string) => Resp;

/** A recorded fake transport. */
export interface Fake {
  /** The runner to inject. */
  run: CommandRunner;
  /** Every remote command string, in order. */
  commands: string[];
  /** Every file written through `upload`, with its decoded body. */
  uploads: { path: string; content: string }[];
  /** Destinations of every real `rm` invocation. */
  removed: string[];
}

/** The destination path of an upload from its write script. */
function parseUploadPath(command: string): string {
  return /^f='([^']+)'/m.exec(command)?.[1] ?? "";
}

async function sha256HexLocal(bytes: Uint8Array): Promise<string> {
  const input = new Uint8Array(bytes);
  const digest = await crypto.subtle.digest("SHA-256", input.buffer);
  return Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, "0")).join("");
}

/**
 * A transport fake that records remote commands and simulates uploads. The
 * `respond` callback answers every non-upload `ssh` invocation.
 */
export function fakeApt(respond: Respond): Fake {
  const commands: string[] = [];
  const uploads: { path: string; content: string }[] = [];
  const removed: string[] = [];
  const run: CommandRunner = async (cmd, args, options = {}) => {
    if (cmd === "ssh-agent") {
      return args[0] === "-s"
        ? {
          code: 0,
          stdout:
            "SSH_AUTH_SOCK=/tmp/a.sock; export SSH_AUTH_SOCK;\nSSH_AGENT_PID=1; export SSH_AGENT_PID;\n",
          stderr: "",
        }
        : { code: 0, stdout: "", stderr: "" };
    }
    if (cmd === "ssh-add") return { code: 0, stdout: "", stderr: "" };
    if (cmd !== "ssh") return { code: 0, stdout: "", stderr: "" };
    const command = args[args.length - 1];
    commands.push(command);
    // Record real `rm` invocations, not the upload script's own trap.
    if (/^'rm' /.test(command)) {
      const match = /'([^']+)'\s*$/.exec(command);
      if (match) removed.push(match[1]);
    }
    if (command.includes(".ssh-host-upload")) {
      const bytes = options.stdin === undefined
        ? new Uint8Array()
        : typeof options.stdin === "string"
        ? new TextEncoder().encode(options.stdin)
        : options.stdin;
      uploads.push({
        path: parseUploadPath(command),
        content: new TextDecoder().decode(bytes),
      });
      const digest = await sha256HexLocal(bytes);
      const mode = /chmod '([0-7]{3,4})'/.exec(command)?.[1] ?? "0644";
      return { code: 0, stdout: `${digest} ${mode}\n`, stderr: "" };
    }
    const r = respond(command);
    return {
      code: r.code ?? 0,
      stdout: r.stdout ?? "",
      stderr: r.stderr ?? "",
    };
  };
  return { run, commands, uploads, removed };
}

/** Installs a fake transport plus a resolved vault secret. */
export function useFake(fake: Fake, now = TEST_NOW): void {
  setDeps({
    run: fake.run,
    now: () => now,
    sleep: () => Promise.resolve(),
    resolveSecret: () => Promise.resolve("PLACEHOLDER-KEY"),
  });
}

/** True when any recorded command contains `sub`. */
export function has(fake: Fake, sub: string): boolean {
  return fake.commands.some((c) => c.includes(sub));
}

/** True when one recorded command contains every token (remote argv is quoted). */
export function hasTok(fake: Fake, ...tokens: string[]): boolean {
  return fake.commands.some((c) => tokens.every((t) => c.includes(t)));
}
