/**
 * A fake SSH transport for the model-level tests: it records every remote
 * command, answers uploads with the digest of what was sent, and lets a test
 * decide how the host script ends.
 *
 * @module
 */

import { setDeps } from "./runtime.ts";
import { type CommandRunner, sha256Hex } from "./ssh.ts";

/** How a test answers one remote command. */
export interface Answer {
  /** Exit code; defaults to 0. */
  code?: number;
  /** Standard output. */
  stdout?: string;
  /** Standard error. */
  stderr?: string;
}

/** What the fake saw. */
export interface Recorder {
  /** Every remote command (the quoted argv), in order. */
  commands: string[];
  /** Restores the real transport. */
  restore: () => void;
}

const AGENT_START =
  "SSH_AUTH_SOCK=/tmp/a.sock; export SSH_AUTH_SOCK;\nSSH_AGENT_PID=1; export SSH_AGENT_PID;\n";

/**
 * Installs a fake transport. `answer` sees each non-upload remote command and
 * returns its result (default: success with no output).
 */
export function fakeHost(answer: (command: string) => Answer): Recorder {
  const commands: string[] = [];
  const reply = (r: Answer) => ({
    code: r.code ?? 0,
    stdout: r.stdout ?? "",
    stderr: r.stderr ?? "",
  });
  const run: CommandRunner = async (cmd, args, options = {}) => {
    if (cmd === "ssh-agent") {
      return reply({ stdout: args[0] === "-s" ? AGENT_START : "" });
    }
    if (cmd !== "ssh") return reply({});
    const command = args[args.length - 1];
    commands.push(command);
    if (command.includes(".ssh-host-upload")) {
      const body = typeof options.stdin === "string"
        ? options.stdin
        : new TextDecoder().decode(options.stdin ?? new Uint8Array());
      const mode = /chmod '([0-7]{3,4})'/.exec(command)?.[1] ?? "0644";
      return reply({ stdout: `${await sha256Hex(body)} ${mode}\n` });
    }
    return reply(answer(command));
  };
  const prev = setDeps({ run, sleep: () => Promise.resolve() });
  return { commands, restore: () => void setDeps(prev) };
}
