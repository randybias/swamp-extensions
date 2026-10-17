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
  /**
   * For a `test -e` probe: the answer is meant even when it is a plain success
   * with no output. Without it a bare `{ code: 0 }` is a responder's catch-all
   * and the probe agrees with the preceding digest probe instead.
   */
  deliberate?: boolean;
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

/** Every single-quoted word of a quoted argv (paths never contain quotes). */
function argvOf(command: string): string[] {
  return (command.match(/'[^']*'/g) ?? []).map((t) => t.slice(1, -1));
}

/** What a runner returns: all three fields present. */
type CommandResultShape = { code: number; stdout: string; stderr: string };

/** A fully populated result from a possibly partial responder answer. */
function reply(r: Resp): CommandResultShape {
  return { code: r.code ?? 0, stdout: r.stdout ?? "", stderr: r.stderr ?? "" };
}

const OK = reply({});

/** The `ssh-agent` side of the transport: start (`-s`) or kill (`-k`). */
function agentReply(args: string[]): CommandResultShape {
  return args[0] === "-s"
    ? reply({
      stdout:
        "SSH_AUTH_SOCK=/tmp/a.sock; export SSH_AUTH_SOCK;\nSSH_AGENT_PID=1; export SSH_AGENT_PID;\n",
    })
    : OK;
}

/** The bytes a fake upload received on stdin. */
function stdinBytes(stdin: string | Uint8Array | undefined): Uint8Array {
  if (stdin === undefined) return new Uint8Array();
  return typeof stdin === "string" ? new TextEncoder().encode(stdin) : stdin;
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
  // `remoteSha` reads a file's digest and, when that probe fails, checks that
  // the file is really absent. A responder that does not model a file returns
  // success with no hash, which is not a real sha256sum outcome; remember the
  // per-path result so the follow-up `test -e` answers consistently.
  const shaExists = new Map<string, boolean>();
  const run: CommandRunner = async (cmd, args, options = {}) => {
    if (cmd === "ssh-agent") return agentReply(args);
    if (cmd !== "ssh") return OK;
    const command = args[args.length - 1];
    commands.push(command);
    // Record real `rm` invocations, not the upload script's own trap.
    if (/^'rm' /.test(command)) {
      const match = /'([^']+)'\s*$/.exec(command);
      if (match) removed.push(match[1]);
    }
    if (command.includes(".ssh-host-upload")) {
      const bytes = stdinBytes(options.stdin);
      uploads.push({
        path: parseUploadPath(command),
        content: new TextDecoder().decode(bytes),
      });
      const mode = /chmod '([0-7]{3,4})'/.exec(command)?.[1] ?? "0644";
      return reply({ stdout: `${await sha256HexLocal(bytes)} ${mode}\n` });
    }
    const r = respond(command);
    const path = argvOf(command).at(-1) ?? "";
    if (/^'sha256sum' /.test(command)) {
      shaExists.set(
        path,
        (r.code ?? 0) === 0 && /[0-9a-f]{64}/i.test(r.stdout ?? ""),
      );
    }
    if (/^'test' '-e' /.test(command)) {
      // An explicit answer wins; otherwise agree with the digest probe.
      const explicit = r.deliberate === true || (r.code ?? 0) !== 0 ||
        (r.stdout ?? "") !== "" || (r.stderr ?? "") !== "";
      const known = shaExists.get(path);
      if (!explicit && known !== undefined) {
        return reply({ code: known ? 0 : 1 });
      }
    }
    return reply(r);
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

/** A fake target with an in-memory filesystem. */
export interface Box {
  /** The current remote files, by absolute path. */
  files: Map<string, { content: string; mode: string }>;
  /** The transport fake, for transcript assertions. */
  fake: Fake;
}

/**
 * A transport fake backed by an in-memory filesystem, so uploads, `sha256sum`,
 * `test`, `cp`, `rm` and `mv` are consistent across calls. Use it for any test
 * whose behaviour depends on what is on disk (backups, ownership, removal).
 * Commands it does not model are answered by `respond`.
 */
export function boxFake(
  initial: Record<string, string> = {},
  respond: Respond = () => ({}),
): Box {
  const files = new Map<string, { content: string; mode: string }>();
  for (const [path, content] of Object.entries(initial)) {
    files.set(path, { content, mode: "0644" });
  }
  const commands: string[] = [];
  const uploads: { path: string; content: string }[] = [];
  const removed: string[] = [];
  const run: CommandRunner = async (cmd, args, options = {}) => {
    if (cmd === "ssh-agent") return agentReply(args);
    if (cmd !== "ssh") return OK;
    const command = args[args.length - 1];
    commands.push(command);
    if (command.includes(".ssh-host-upload")) {
      const path = parseUploadPath(command);
      const bytes = stdinBytes(options.stdin);
      const content = new TextDecoder().decode(bytes);
      const mode = /chmod '([0-7]{3,4})'/.exec(command)?.[1] ?? "0644";
      files.set(path, { content, mode });
      uploads.push({ path, content });
      return reply({ stdout: `${await sha256HexLocal(bytes)} ${mode}\n` });
    }
    const argv = argvOf(command);
    const verb = argv[0];
    const target = (path: string) => {
      const file = files.get(path);
      return file ?? null;
    };
    switch (verb) {
      case "cat": {
        const file = target(argv[2]);
        return file
          ? { code: 0, stdout: file.content, stderr: "" }
          : { code: 1, stdout: "", stderr: "No such file" };
      }
      case "sha256sum": {
        const file = target(argv[2]);
        if (!file) return { code: 1, stdout: "", stderr: "No such file" };
        const digest = await sha256HexLocal(
          new TextEncoder().encode(file.content),
        );
        return { code: 0, stdout: `${digest}  ${argv[2]}\n`, stderr: "" };
      }
      case "test": {
        const file = target(argv[2]);
        if (argv[1] === "-e") {
          return file ? OK : { code: 1, stdout: "", stderr: "" };
        }
        if (argv[1] === "-L" || argv[1] === "-d") {
          return { code: 1, stdout: "", stderr: "" };
        }
        return OK;
      }
      case "cp": {
        const file = target(argv[3]);
        if (!file) return { code: 1, stdout: "", stderr: "No such file" };
        files.set(argv[4], { ...file });
        return OK;
      }
      case "rm": {
        for (const path of argv.slice(3)) {
          if (files.delete(path)) removed.push(path);
        }
        return OK;
      }
      case "mv": {
        const file = target(argv[3]);
        if (!file) return { code: 1, stdout: "", stderr: "No such file" };
        files.delete(argv[3]);
        files.set(argv[4], file);
        return OK;
      }
      case "chmod": {
        const file = target(argv[3]);
        if (file) file.mode = argv[1];
        return OK;
      }
      default:
        return reply(respond(command));
    }
  };
  return { files, fake: { run, commands, uploads, removed } };
}

/** True when any recorded command contains `sub`. */
export function has(fake: Fake, sub: string): boolean {
  return fake.commands.some((c) => c.includes(sub));
}

/** True when one recorded command contains every token (remote argv is quoted). */
export function hasTok(fake: Fake, ...tokens: string[]): boolean {
  return fake.commands.some((c) => tokens.every((t) => c.includes(t)));
}
