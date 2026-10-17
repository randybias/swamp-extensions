/**
 * Shared test helpers: a recording SSH transport whose remote scripts are read
 * back as the shell text the host would run.
 *
 * @module
 */

import {
  createRecordingRunner,
  type RecordedCall,
  type RecordingRunner,
  splitQuotedWords,
} from "./bogworks/recording-runner.ts";

/** What a fake host answers to one remote script. */
export interface HostReply {
  /** Remote exit code. */
  code: number;
  /** Remote stdout; empty when absent. */
  stdout?: string;
}

/** The remote command the transport sends: the last ssh argument. */
const remoteOf = (call: RecordedCall) => call.argv[call.argv.length - 1] ?? "";

/**
 * The script the host would run for an `ssh` call: the body inside the
 * `timeout` wrapper that `renderRemote` puts on stdin. Empty for a call that
 * did not carry one.
 */
export function bodyOf(call: RecordedCall): string {
  return unquoteBody(call.stdin ?? "");
}

/** The script inside a `timeout ... sh -c '<script>'; exit $?` stdin text. */
export function unquoteBody(stdin: string): string {
  const m = /^timeout -k \d+ \d+ sh -c ('[\s\S]*'); exit \$\?$/.exec(stdin);
  return m === null ? "" : splitQuotedWords(m[1])?.[0] ?? "";
}

/** Bytes a script reads through `bw_data`, decoded from its base64 literal. */
export function dataOf(body: string): string {
  const m = /^bw_data\(\) \{ printf '%s' '([A-Za-z0-9+/=]*)' \| base64 -d; \}$/m
    .exec(body);
  return m === null ? "" : new TextDecoder().decode(
    Uint8Array.from(atob(m[1]), (c) => c.charCodeAt(0)),
  );
}

/** A recording transport that answers each remote script through `respond`. */
export interface FakeHost extends RecordingRunner {
  /** The script of every `ssh` call so far, in order. */
  scripts(): string[];
  /** Every `ssh` call so far, in order. */
  sshCalls(): RecordedCall[];
}

/**
 * Creates the fake. `respond` sees each remote script (the body, with the
 * deadline wrapper and the data literal included) and answers it; unanswered
 * scripts exit 0 with no output. Local `ssh-agent`, `ssh-add` and
 * `ssh-keyscan` calls get the harness's default replies.
 */
export function fakeHost(
  respond: (body: string, call: RecordedCall) => HostReply | undefined = () =>
    undefined,
): FakeHost {
  // The harness recognises a stdin script only behind a bare `sh -s`, not behind
  // `sudo -n`; this mirror feeds it the call without sudo so the scripts reach
  // the capture directory the gates read.
  const mirror = createRecordingRunner();
  const runner = createRecordingRunner({
    respond: async (call) => {
      if (call.cmd !== "ssh") return undefined;
      await mirror.run("ssh", [
        ...call.argv.slice(0, -1),
        remoteOf(call).replace(/^'sudo' '-n' /, ""),
      ], { stdin: call.stdinBytes });
      const r = respond(bodyOf(call), call);
      return r === undefined
        ? undefined
        : { code: r.code, stdout: r.stdout ?? "", stderr: "" };
    },
  });
  const sshCalls = () => runner.recording.calls.filter((c) => c.cmd === "ssh");
  return { ...runner, sshCalls, scripts: () => sshCalls().map(bodyOf) };
}
