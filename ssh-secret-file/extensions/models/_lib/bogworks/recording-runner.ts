/**
 * A recording fake for the canonical swamp SSH transport (`_lib/ssh.ts`,
 * blob 8f132c43). It satisfies the transport's `CommandRunner` and `SshDeps`
 * shapes, spawns nothing, records every call (`argv`, `stdin`, `env`, `cwd`)
 * and every upload (`path`, `bytes`), and answers with the minimal replies the
 * canonical transport needs to run end to end (ssh-agent, ssh-add,
 * ssh-keyscan, the upload probe and the upload write). Tests then assert over
 * the recording: no secret on any argv (raw, sha256 or base64), no secret
 * written through an upload or a plaintext `cat >`/`tee`/`printf >` in a
 * remote command, and behaviour preservation between two transports.
 *
 * Capture conventions (consumed by the bogworks gates):
 * - `BOGWORKS_CAPTURE_SCRIPTS=<dir>`: every `sh -c <body>` and every
 *   stdin-delivered script is written to `<dir>/<n>-<sha12>.sh` with an
 *   `index.json` beside them. The runner does this automatically when the
 *   variable is set; {@link captureScripts} does it on demand.
 * - `BOGWORKS_CAPTURE_RENDERS=<dir>`: {@link captureRenders} writes a rendered
 *   config (nft ruleset, knot.conf, netplan yaml, ...) to `<dir>/<name>` for
 *   the real-tool validators.
 *
 * The module imports nothing, so it can be vendored byte-identical into an
 * extension's `extensions/models/_lib/bogworks/` directory.
 *
 * @module
 */

/** Result of running an external command (mirrors the canonical transport). */
export interface CommandResult {
  code: number;
  stdout: string;
  stderr: string;
  truncated?: boolean;
  killedForCap?: boolean;
  timedOut?: boolean;
}

/** Options for one external command (mirrors the canonical transport). */
export interface RunOptions {
  stdin?: Uint8Array | string;
  env?: Record<string, string>;
  /** Not part of the canonical transport; recorded when a caller passes it. */
  cwd?: string;
  maxOutputBytes?: number;
  stderrMaxOutputBytes?: number;
  truncate?: boolean;
  timeoutMs?: number;
}

/** Runs an external command; the shape the canonical transport injects. */
export type CommandRunner = (
  cmd: string,
  args: string[],
  options?: RunOptions,
) => Promise<CommandResult>;

/** Injectable dependencies of the canonical transport. */
export interface SshDeps {
  run: CommandRunner;
  now: () => number;
  sleep: (ms: number) => Promise<void>;
}

/** One recorded command invocation. */
export interface RecordedCall {
  /** Zero-based call index. */
  n: number;
  /** The executable. */
  cmd: string;
  /** The argument vector (without the executable). */
  argv: string[];
  /** Standard input as UTF-8 text, when any was supplied. */
  stdin?: string;
  /** Standard input as the exact bytes, when any was supplied. */
  stdinBytes?: Uint8Array;
  /** Extra environment variables, when any were supplied. */
  env?: Record<string, string>;
  /** Working directory, when one was supplied. */
  cwd?: string;
  /** Per-call controls the caller passed. */
  timeoutMs?: number;
  maxOutputBytes?: number;
}

/** One recorded upload: a canonical `upload()` write, or a manual record. */
export interface RecordedUpload {
  /** Index of the call that carried the bytes, or -1 for a manual record. */
  call: number;
  /** Destination path on the remote. */
  path: string;
  /** The bytes written. */
  bytes: Uint8Array;
  /** Octal mode, when the write script named one. */
  mode?: string;
}

/** Everything the runner recorded. */
export interface Recording {
  calls: RecordedCall[];
  uploads: RecordedUpload[];
  /** Milliseconds slept through `deps.sleep`, in order. */
  sleeps: number[];
}

/** A caller-supplied answer; return `undefined` to fall through to the default. */
export type Responder = (
  call: RecordedCall,
) => CommandResult | undefined | Promise<CommandResult | undefined>;

/** Options for {@link createRecordingRunner}. */
export interface RecordingOptions {
  /** Answers calls before the built-in canonical replies. */
  respond?: Responder;
  /** Capture dir for scripts; defaults to `$BOGWORKS_CAPTURE_SCRIPTS`. */
  captureDir?: string;
  /** Fixed start of the fake clock in ms; defaults to 1_700_000_000_000. */
  startMs?: number;
}

/** What {@link createRecordingRunner} returns. */
export interface RecordingRunner {
  /** The recording fake as a `CommandRunner`. */
  run: CommandRunner;
  /** `SshDeps` with this runner, a fake clock and a non-sleeping sleep. */
  deps: SshDeps;
  /** The live recording; grows with every call. */
  recording: Recording;
  /** Records an upload made outside the canonical `upload()` script. */
  recordUpload: (path: string, bytes: Uint8Array | string, mode?: string) => void;
}

const FAKE_HOST_KEY = "ssh-ed25519 " +
  "AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

const encoder = new TextEncoder();
const decoder = new TextDecoder();

/** Encodes text or bytes as bytes. */
function toBytes(value: Uint8Array | string): Uint8Array {
  return typeof value === "string" ? encoder.encode(value) : value;
}

/** Lowercase hex SHA-256 of text or bytes. */
export async function sha256Hex(data: Uint8Array | string): Promise<string> {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new Uint8Array(toBytes(data)),
  );
  return Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

/** Standard base64 of text or bytes, with padding. */
function base64(data: Uint8Array | string): string {
  let bin = "";
  for (const b of toBytes(data)) bin += String.fromCharCode(b);
  return btoa(bin);
}

/** Reads the canonical upload script's destination (`f='<path>'` first line). */
function uploadPathOf(script: string): string | undefined {
  const m = /^f=(?:'((?:[^']|'\\'')*)'|(\S+))/.exec(script);
  if (!m) return undefined;
  return m[1] !== undefined ? m[1].replace(/'\\''/g, "'") : m[2];
}

/** Reads the canonical upload script's mode (`chmod '0600' "$t"`). */
function uploadModeOf(script: string): string | undefined {
  return /\bchmod '?([0-7]{3,4})'? "\$t"/.exec(script)?.[1];
}

/** True for the canonical `upload()` write script. */
function isCanonicalUploadWrite(script: string): boolean {
  return script.startsWith("f=") && script.includes('cat > "$t"') &&
    script.includes("mktemp");
}

/** True for the canonical `upload()` convergence probe. */
function isCanonicalUploadProbe(script: string): boolean {
  return script.startsWith("f=") && script.includes("echo MISSING");
}

/**
 * Creates the recording fake. The default replies make the canonical transport
 * succeed: `ssh-agent -s` yields a socket and pid, `ssh-add` accepts, the
 * keyscan returns one fake ed25519 key, the upload probe reports `MISSING`, the
 * upload write echoes the sha256 and mode of what it received, and every other
 * `ssh` exits 0 with empty output. A `respond` hook overrides any of them.
 */
export function createRecordingRunner(
  options: RecordingOptions = {},
): RecordingRunner {
  const recording: Recording = { calls: [], uploads: [], sleeps: [] };
  const captureDir = options.captureDir ??
    readEnv("BOGWORKS_CAPTURE_SCRIPTS");
  let clock = options.startMs ?? 1_700_000_000_000;

  const recordUpload = (
    path: string,
    bytes: Uint8Array | string,
    mode?: string,
    call = -1,
  ): void => {
    const rec: RecordedUpload = { call, path, bytes: toBytes(bytes) };
    if (mode !== undefined) rec.mode = mode;
    recording.uploads.push(rec);
  };

  const defaultReply = async (call: RecordedCall): Promise<CommandResult> => {
    const ok = (stdout = ""): CommandResult => ({ code: 0, stdout, stderr: "" });
    if (call.cmd === "ssh-agent") {
      if (call.argv[0] === "-s") {
        return ok(
          "SSH_AUTH_SOCK=/tmp/bogworks-agent.sock; export SSH_AUTH_SOCK;\n" +
            "SSH_AGENT_PID=4242; export SSH_AGENT_PID;\n",
        );
      }
      return ok();
    }
    if (call.cmd === "ssh-add") return ok();
    if (call.cmd === "ssh-keyscan") {
      const host = call.argv[call.argv.length - 1] ?? "host";
      return ok(`${host} ${FAKE_HOST_KEY}\n`);
    }
    if (call.cmd === "ssh") {
      const remote = call.argv[call.argv.length - 1] ?? "";
      if (isCanonicalUploadProbe(remote)) return ok("MISSING\n");
      if (isCanonicalUploadWrite(remote)) {
        const bytes = call.stdinBytes ?? new Uint8Array();
        const path = uploadPathOf(remote) ?? "?";
        const mode = uploadModeOf(remote) ?? "0600";
        recordUpload(path, bytes, mode, call.n);
        return ok(`${await sha256Hex(bytes)} ${mode.replace(/^0+/, "")}\n`);
      }
    }
    return ok();
  };

  const run: CommandRunner = async (cmd, args, opts = {}) => {
    const call: RecordedCall = { n: recording.calls.length, cmd, argv: [...args] };
    if (opts.stdin !== undefined) {
      call.stdinBytes = toBytes(opts.stdin);
      call.stdin = decoder.decode(call.stdinBytes);
    }
    if (opts.env !== undefined) call.env = { ...opts.env };
    if (opts.cwd !== undefined) call.cwd = opts.cwd;
    if (opts.timeoutMs !== undefined) call.timeoutMs = opts.timeoutMs;
    if (opts.maxOutputBytes !== undefined) {
      call.maxOutputBytes = opts.maxOutputBytes;
    }
    recording.calls.push(call);
    if (captureDir) await captureCall(call, captureDir);
    const custom = options.respond ? await options.respond(call) : undefined;
    return custom ?? await defaultReply(call);
  };

  const deps: SshDeps = {
    run,
    now: () => clock++,
    sleep: (ms: number) => {
      recording.sleeps.push(ms);
      clock += ms;
      return Promise.resolve();
    },
  };

  return {
    run,
    deps,
    recording,
    recordUpload: (path, bytes, mode) => recordUpload(path, bytes, mode),
  };
}

/** Reads an environment variable, treating a denied permission as unset. */
function readEnv(name: string): string | undefined {
  try {
    const v = Deno.env.get(name);
    return v === undefined || v === "" ? undefined : v;
  } catch {
    return undefined;
  }
}

// ---------------------------------------------------------------------------
// Secret assertions
// ---------------------------------------------------------------------------

/** One way a secret could appear in text. */
interface SecretForm {
  label: string;
  text: string;
}

/** Every textual form of `secret` the assertions look for. */
async function secretForms(secret: string): Promise<SecretForm[]> {
  if (typeof secret !== "string" || secret.length === 0) {
    throw new Error("assert*: every secret must be a non-empty string");
  }
  const forms: SecretForm[] = [];
  const seen = new Set<string>();
  const add = (label: string, text: string) => {
    if (text.length < 4 || seen.has(text)) return;
    seen.add(text);
    forms.push({ label, text });
  };
  const variants = new Set([secret, secret.trim()]);
  for (const v of variants) {
    if (v.length === 0) continue;
    add("raw", v);
    add("sha256", await sha256Hex(v));
    const b64 = base64(v);
    add("base64", b64);
    add("base64-nopad", b64.replace(/=+$/, ""));
    add("base64url", b64.replace(/\+/g, "-").replace(/\//g, "_"));
    add(
      "base64url-nopad",
      b64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, ""),
    );
  }
  return forms;
}

/** Replaces every form of every secret in `text` with `***`. */
function redact(text: string, forms: SecretForm[]): string {
  let out = text;
  for (const f of forms) out = out.split(f.text).join("***");
  return out;
}

/** Finds the first secret form contained in `text`. */
function findForm(text: string, forms: SecretForm[]): SecretForm | undefined {
  return forms.find((f) => text.includes(f.text));
}

/**
 * Throws when any recorded command name or argument contains a secret, its
 * SHA-256 hex, or its base64 (standard or URL-safe, padded or not). Argv is
 * public (`/proc/<pid>/cmdline`), and so is the remote command text that the
 * transport places on ssh's argv. Stdin and the environment are not checked:
 * they are the sanctioned channels. The error message is redacted.
 */
export async function assertNoSecretOnArgv(
  recording: Recording,
  secrets: string[],
): Promise<void> {
  const forms = (await Promise.all(secrets.map(secretForms))).flat();
  for (const call of recording.calls) {
    const words = [call.cmd, ...call.argv];
    for (let i = 0; i < words.length; i++) {
      const hit = findForm(words[i], forms);
      if (hit) {
        throw new Error(
          `secret (${hit.label}) on argv: call ${call.n} word ${i} of ${call.cmd}: ` +
            redact(words[i], forms).slice(0, 200),
        );
      }
    }
  }
}

/** Shell text that writes a file: `cat >`, `tee`, `printf ... >`, `echo ... >`. */
const WRITE_FORM_RE =
  /\bcat\s*>|\btee\b|\bprintf\b[^\n;|&]*>|\becho\b[^\n;|&]*>|\bdd\b[^\n;|&]*\bof=/;

/**
 * Throws when a secret is written to the remote in the clear: by an upload
 * whose bytes contain it, or by remote command text (an argv word, or a script
 * delivered on stdin to `sh -s`) that contains both a write form (`cat >`,
 * `tee`, `printf >`, `echo >`) and the secret itself. A secret that arrives on
 * stdin as data and is written by a script that does not spell it out is the
 * sanctioned pattern and passes.
 */
export async function assertNoRemoteSecretWrite(
  recording: Recording,
  secrets: string[],
): Promise<void> {
  const forms = (await Promise.all(secrets.map(secretForms))).flat();
  for (const up of recording.uploads) {
    const text = decoder.decode(up.bytes);
    const hit = findForm(text, forms);
    if (hit) {
      throw new Error(
        `secret (${hit.label}) uploaded to ${up.path} (call ${up.call})`,
      );
    }
  }
  for (const call of recording.calls) {
    const texts = [...call.argv];
    if (call.stdin !== undefined && stdinIsScript(call)) texts.push(call.stdin);
    for (const text of texts) {
      if (!WRITE_FORM_RE.test(text)) continue;
      const hit = findForm(text, forms);
      if (hit) {
        throw new Error(
          `secret (${hit.label}) written by remote command text in call ${call.n} ` +
            `of ${call.cmd}: ${redact(text, forms).slice(0, 200)}`,
        );
      }
    }
  }
}

// ---------------------------------------------------------------------------
// Behaviour preservation
// ---------------------------------------------------------------------------

/** Options for {@link assertCommandsEqual}. */
export interface CommandsEqualOptions {
  /**
   * Compare only what the remote sees: drop `ssh-agent`, `ssh-add` and
   * `ssh-keyscan` calls, and reduce each `ssh` call to its remote command and
   * stdin (ignoring `-o`, `-F`, `-p`, `-l` and the host word).
   */
  ignoreTransportArgs?: boolean;
}

/** A call reduced to the parts under comparison. */
interface NormalizedCall {
  cmd: string;
  argv: string[];
  stdin?: string;
}

const TRANSPORT_HELPERS = new Set(["ssh-agent", "ssh-add", "ssh-keyscan"]);
const SSH_FLAGS_WITH_VALUE = new Set(["-o", "-F", "-p", "-l", "-i", "-J"]);

/** Reduces the recorded calls per the comparison options. */
function normalizeCalls(
  rec: Recording,
  opts: CommandsEqualOptions,
): NormalizedCall[] {
  const out: NormalizedCall[] = [];
  for (const call of rec.calls) {
    if (opts.ignoreTransportArgs && TRANSPORT_HELPERS.has(call.cmd)) continue;
    let argv = call.argv;
    if (opts.ignoreTransportArgs && call.cmd === "ssh") {
      // Strip option flags and their values, then the host word, leaving the
      // remote command (and anything odd after it) for the comparison.
      const rest: string[] = [];
      for (let i = 0; i < call.argv.length; i++) {
        const w = call.argv[i];
        if (SSH_FLAGS_WITH_VALUE.has(w)) {
          i++;
          continue;
        }
        if (/^-[a-zA-Z0-9]+$/.test(w) && i < call.argv.length - 1) continue;
        rest.push(w);
      }
      // The first remaining positional is the host (or user@host).
      argv = rest.length > 1 ? rest.slice(1) : rest;
    }
    const n: NormalizedCall = { cmd: call.cmd, argv };
    if (call.stdin !== undefined) n.stdin = call.stdin;
    out.push(n);
  }
  return out;
}

/**
 * Throws unless two recordings performed the same commands in the same order.
 * With `ignoreTransportArgs`, transport mechanics (agent, keyscan, ssh flags)
 * are ignored and only the remote command text plus stdin are compared, which
 * is the proof that re-vendoring a transport preserved behaviour. The message
 * names the first differing call and shows argv; stdin is shown only as a
 * length and SHA-256 so a secret delivered on stdin is never printed.
 */
export async function assertCommandsEqual(
  oldRec: Recording,
  newRec: Recording,
  options: CommandsEqualOptions = {},
): Promise<void> {
  const a = normalizeCalls(oldRec, options);
  const b = normalizeCalls(newRec, options);
  const describe = async (c: NormalizedCall | undefined): Promise<string> => {
    if (!c) return "(no call)";
    const stdin = c.stdin === undefined
      ? "none"
      : `${encoder.encode(c.stdin).length}B sha256:${
        (await sha256Hex(c.stdin)).slice(0, 12)
      }`;
    return `${c.cmd} ${JSON.stringify(c.argv)} stdin=${stdin}`;
  };
  const max = Math.max(a.length, b.length);
  for (let i = 0; i < max; i++) {
    const x = a[i];
    const y = b[i];
    const same = x !== undefined && y !== undefined && x.cmd === y.cmd &&
      x.argv.length === y.argv.length &&
      x.argv.every((w, j) => w === y.argv[j]) && x.stdin === y.stdin;
    if (!same) {
      throw new Error(
        `commands differ at call ${i} (old has ${a.length}, new has ${b.length}):\n` +
          `  old: ${await describe(x)}\n  new: ${await describe(y)}`,
      );
    }
  }
}

// ---------------------------------------------------------------------------
// Script extraction and capture
// ---------------------------------------------------------------------------

/** Where a captured script came from. */
export type ScriptKind = "argv-sh-c" | "remote-sh-c" | "stdin-script";

/** One script found in a recorded call. */
export interface ExtractedScript {
  kind: ScriptKind;
  /** Index of the call that carried it. */
  call: number;
  /** 0 for a top-level body, 1 for a `sh -c` nested inside it, and so on. */
  depth: number;
  text: string;
}

const SHELLS = new Set(["sh", "dash", "bash", "/bin/sh", "/bin/dash", "/bin/bash"]);

/** True when the call's stdin is a script (`sh -s`, `sh`, `sh -` reads it). */
function stdinIsScript(call: RecordedCall): boolean {
  if (call.stdin === undefined) return false;
  if (SHELLS.has(call.cmd)) {
    return call.argv.length === 0 || call.argv.every((a) => a === "-s" || a === "-");
  }
  if (call.cmd === "ssh") {
    const remote = call.argv[call.argv.length - 1] ?? "";
    const words = splitQuotedWords(remote);
    if (!words || words.length === 0 || !SHELLS.has(words[0])) return false;
    return words.length === 1 ||
      words.slice(1).every((w) => w === "-s" || w === "-");
  }
  return false;
}

/**
 * Splits text that consists only of `posixQuote`d words separated by spaces
 * (the output of the canonical `quoteArgv`). Returns `null` for anything else.
 */
export function splitQuotedWords(text: string): string[] | null {
  const words: string[] = [];
  let i = 0;
  while (i < text.length) {
    if (text[i] === " ") {
      i++;
      continue;
    }
    if (text[i] !== "'") return null;
    const parsed = readQuotedWord(text, i);
    if (!parsed) return null;
    words.push(parsed.value);
    i = parsed.end;
  }
  return words;
}

/**
 * Reads one single-quoted shell word starting at `start` (which must be a
 * quote), honouring the `'\''` escape. Returns the value and the index after
 * the word, or `null` when the quote is unterminated.
 */
function readQuotedWord(
  text: string,
  start: number,
): { value: string; end: number } | null {
  let i = start;
  let value = "";
  while (i < text.length) {
    if (text[i] !== "'") return { value, end: i };
    const close = text.indexOf("'", i + 1);
    if (close === -1) return null;
    value += text.slice(i + 1, close);
    i = close + 1;
    if (text.startsWith("\\'", i)) {
      value += "'";
      i += 2;
      if (text[i] !== "'") return { value, end: i };
      continue;
    }
    return { value, end: i };
  }
  return null;
}

const SH_C_RE = /(?:^|[\s;&|(])(?:'?(?:\/bin\/)?(?:sh|dash|bash)'?)\s+(?:'-c'|-c)\s+'/g;

/** Finds every `sh -c '<body>'` in `text`, recursing into each body. */
function findShBodies(text: string, depth: number): { text: string; depth: number }[] {
  const out: { text: string; depth: number }[] = [];
  SH_C_RE.lastIndex = 0;
  let m: RegExpExecArray | null;
  while ((m = SH_C_RE.exec(text)) !== null) {
    const quoteAt = m.index + m[0].length - 1;
    const word = readQuotedWord(text, quoteAt);
    if (!word) continue;
    out.push({ text: word.value, depth });
    out.push(...findShBodies(word.value, depth + 1));
    SH_C_RE.lastIndex = word.end;
  }
  return out;
}

/** Extracts every shell script a recorded call would execute. */
export function extractScripts(call: RecordedCall): ExtractedScript[] {
  const out: ExtractedScript[] = [];
  if (SHELLS.has(call.cmd) && call.argv[0] === "-c" && call.argv[1] !== undefined) {
    out.push({ kind: "argv-sh-c", call: call.n, depth: 0, text: call.argv[1] });
    for (const b of findShBodies(call.argv[1], 1)) {
      out.push({ kind: "argv-sh-c", call: call.n, ...b });
    }
  } else if (call.cmd === "ssh") {
    const remote = call.argv[call.argv.length - 1] ?? "";
    for (const b of findShBodies(remote, 0)) {
      out.push({ kind: "remote-sh-c", call: call.n, ...b });
    }
  }
  if (stdinIsScript(call) && call.stdin !== undefined) {
    out.push({ kind: "stdin-script", call: call.n, depth: 0, text: call.stdin });
    for (const b of findShBodies(call.stdin, 1)) {
      out.push({ kind: "stdin-script", call: call.n, ...b });
    }
  }
  return out;
}

/** One line of the capture dir's `index.json`. */
export interface CaptureIndexEntry {
  /** Sequence number; the file is `<n>-<sha12>.sh`. */
  n: number;
  file: string;
  sha256: string;
  kind: ScriptKind;
  call: number;
  depth: number;
  cmd: string;
  bytes: number;
}

/** Process-wide sequence for auto-capture so files from several runners never collide. */
let autoSeq = 0;

/** Writes one script into `dir` and appends its entry to `index.json`. */
async function writeCapture(
  dir: string,
  n: number,
  s: ExtractedScript,
  cmd: string,
): Promise<CaptureIndexEntry> {
  await Deno.mkdir(dir, { recursive: true });
  const sha = await sha256Hex(s.text);
  const file = `${String(n).padStart(3, "0")}-${sha.slice(0, 12)}.sh`;
  await Deno.writeTextFile(`${dir}/${file}`, s.text);
  const entry: CaptureIndexEntry = {
    n,
    file,
    sha256: sha,
    kind: s.kind,
    call: s.call,
    depth: s.depth,
    cmd,
    bytes: encoder.encode(s.text).length,
  };
  const indexPath = `${dir}/index.json`;
  let index: CaptureIndexEntry[] = [];
  try {
    index = JSON.parse(await Deno.readTextFile(indexPath)) as CaptureIndexEntry[];
  } catch {
    index = [];
  }
  index.push(entry);
  const tmp = `${indexPath}.${crypto.randomUUID().slice(0, 8)}.tmp`;
  await Deno.writeTextFile(tmp, JSON.stringify(index, null, 2) + "\n");
  await Deno.rename(tmp, indexPath);
  return entry;
}

/** Auto-capture of one call (when `BOGWORKS_CAPTURE_SCRIPTS` is set). */
async function captureCall(call: RecordedCall, dir: string): Promise<void> {
  for (const s of extractScripts(call)) {
    autoSeq++;
    await writeCapture(dir, autoSeq, s, call.cmd);
  }
}

/**
 * Writes every script in `recording` to `dir`, one file each, named
 * `<n>-<sha12>.sh` (n = 1-based sequence, sha12 = first 12 hex of the body's
 * SHA-256), plus `index.json` describing them. The body is written byte-exact
 * with no header, so the file hashes to its name and runs under `dash` as-is.
 * This is the `BOGWORKS_CAPTURE_SCRIPTS` layout the gates consume.
 */
export async function captureScripts(
  recording: Recording,
  dir: string,
): Promise<CaptureIndexEntry[]> {
  const entries: CaptureIndexEntry[] = [];
  let n = 0;
  for (const call of recording.calls) {
    for (const s of extractScripts(call)) {
      n++;
      entries.push(await writeCapture(dir, n, s, call.cmd));
    }
  }
  return entries;
}

const RENDER_NAME_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;

/**
 * Writes a rendered configuration to `<dir>/<name>` for the real-tool gate.
 * `dir` defaults to `$BOGWORKS_CAPTURE_RENDERS`; when neither is set nothing is
 * written and `null` is returned, so production code paths can call this
 * unconditionally. The name is one plain file name (no path separators).
 */
export async function captureRenders(
  name: string,
  text: string,
  dir?: string,
): Promise<string | null> {
  if (!RENDER_NAME_RE.test(name)) {
    throw new Error(`captureRenders: invalid name ${JSON.stringify(name)}`);
  }
  const target = dir ?? readEnv("BOGWORKS_CAPTURE_RENDERS");
  if (!target) return null;
  await Deno.mkdir(target, { recursive: true });
  const path = `${target}/${name}`;
  await Deno.writeTextFile(path, text);
  return path;
}
