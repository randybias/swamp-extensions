/**
 * Remote file and command helpers on top of the canonical SSH transport.
 *
 * Every action is `exec(argv)` or `upload()`. A root-owned destination is
 * staged as the login user, installed with `install -o -g -m`, and verified by
 * reading the destination back; a digest is never placed on a command line.
 *
 * @module
 */

import {
  exec,
  type ExecResult,
  posixQuote,
  sha256Hex,
  SshConfigError,
  type SshDeps,
  SshError,
  type SshTarget,
  upload,
} from "./ssh.ts";

/** Runs one argv vector under `sudo -n`, refusing a sudo prompt. */
export async function execSudo(
  deps: SshDeps,
  target: SshTarget,
  argv: string[],
): Promise<ExecResult> {
  const result = await exec(deps, target, ["sudo", "-n", "--", ...argv]);
  if (
    result.exit_code !== 0 &&
    /a password is required|no tty present|a terminal is required/i.test(
      result.stderr,
    )
  ) {
    throw new SshConfigError("passwordless sudo is required on the target");
  }
  return result;
}

/** Runs a script through `bash -c`; `sudo` prefixes the one bash argv. */
export async function runScript(
  deps: SshDeps,
  target: SshTarget,
  script: string,
  sudo = false,
): Promise<ExecResult> {
  const argv = sudo
    ? ["sudo", "-n", "--", "bash", "-c", script]
    : ["bash", "-c", script];
  return await exec(deps, target, argv);
}

/**
 * A shell expression that prints a file's SHA-256, using GNU `sha256sum` or
 * BSD `shasum - a 256`. `pathExpr` must already be a safe shell word (a quoted
 * literal or a quoted variable). The pipeline returns awk's status, so callers
 * that depend on the value must check it is 64 hex characters.
 */
export function hashCmd(pathExpr: string): string {
  return `{ sha256sum ${pathExpr} 2>/dev/null || shasum -a 256 ${pathExpr} 2>/dev/null; } | awk '{print $1}'`;
}

/** One file's observed state. */
export interface FileProbe {
  /** `missing`, `file`, `symlink` or `dir`. */
  state: "missing" | "file" | "symlink" | "dir";
  /** Content SHA-256, for a readable file. */
  sha256?: string;
  /** Octal mode, for a file. */
  mode?: string;
  /** Owner user name, for a file. */
  owner?: string;
  /** Group name, for a file. */
  group?: string;
  /** Size in bytes, for a file. */
  size?: number;
}

/** Reads one path's type, and for a file its hash, mode, owner and group. */
export async function probeFile(
  deps: SshDeps,
  target: SshTarget,
  path: string,
  sudo = false,
): Promise<FileProbe> {
  const script = [
    `f=${posixQuote(path)}`,
    `if [ -L "$f" ]; then echo symlink`,
    `elif [ -d "$f" ]; then echo dir`,
    `elif [ -f "$f" ]; then`,
    `  h=$(${hashCmd('"$f"')})`,
    `  printf '%s' "$h" | grep -Eq '^[0-9a-f]{64}$' || h=`,
    `  m=$( { stat -c %a "$f" 2>/dev/null || stat -f %Lp "$f" 2>/dev/null; } )`,
    `  u=$( { stat -c %U "$f" 2>/dev/null; } )`,
    `  g=$( { stat -c %G "$f" 2>/dev/null; } )`,
    `  s=$(stat -c %s "$f" 2>/dev/null || echo 0)`,
    `  printf '%s %s %s %s %s\\n' "\${h:-none}" "\${m:-none}" "\${u:-none}" "\${g:-none}" "\${s:-0}"`,
    `else echo missing; fi`,
  ].join("\n");
  const result = await runScript(deps, target, script, sudo);
  if (result.exit_code !== 0) {
    throw new SshError(`could not read ${path} (exit ${result.exit_code})`);
  }
  const first = result.stdout.trim().split(/\s+/)[0] ?? "";
  if (first === "symlink") return { state: "symlink" };
  if (first === "dir") return { state: "dir" };
  if (first === "missing" || first === "") return { state: "missing" };
  const [sha256, mode, owner, group, size] = result.stdout.trim().split(/\s+/);
  return {
    state: "file",
    sha256,
    mode: normalizeMode(mode),
    owner,
    group,
    size: Number(size) || 0,
  };
}

/** Normalizes an octal mode: `0600` and `600` are the same. */
export function normalizeMode(mode: string | undefined): string | undefined {
  if (mode === undefined) return undefined;
  const trimmed = mode.replace(/^0+/, "");
  return trimmed === "" ? "0" : trimmed;
}

/** Options for {@link putRootFile}. */
export interface PutFileOptions {
  /** Absolute destination path. */
  path: string;
  /** Bytes or UTF-8 text. */
  content: Uint8Array | string;
  /** Octal mode applied to the destination. */
  mode: string;
  /** Destination owner user. */
  owner: string;
  /** Destination owner group. */
  group: string;
}

/** Result of a file write. */
export interface PutFileResult {
  /** Content SHA-256, computed locally. */
  sha256: string;
  /** Whether the destination was written this run. */
  changed: boolean;
}

/**
 * Installs a root-owned file idempotently: stage it as the login user, then
 * `install -o -g -m` it into place, and verify by reading the destination back.
 */
export async function putRootFile(
  deps: SshDeps,
  target: SshTarget,
  opts: PutFileOptions,
): Promise<PutFileResult> {
  const desiredSha = await sha256Hex(opts.content);
  const mode = normalizeMode(opts.mode);
  const before = await probeFile(deps, target, opts.path, true);
  if (
    before.state === "file" && before.sha256 === desiredSha &&
    before.mode === mode && before.owner === opts.owner &&
    before.group === opts.group
  ) {
    return { sha256: desiredSha, changed: false };
  }
  if (before.state === "symlink") {
    throw new SshError(`${opts.path} is a symlink; refusing to follow it`);
  }
  const stage = `/tmp/artifact-server.stage.${await randomSuffix(deps)}`;
  await upload(deps, target, {
    path: stage,
    content: opts.content,
    mode: "0600",
  });
  const installed = await execSudo(deps, target, [
    "install",
    "-o",
    opts.owner,
    "-g",
    opts.group,
    "-m",
    opts.mode,
    stage,
    opts.path,
  ]);
  await execSudo(deps, target, ["rm", "-f", stage]).catch(() => undefined);
  if (installed.exit_code !== 0) {
    throw new SshError(
      `could not install ${opts.path} (exit ${installed.exit_code})`,
    );
  }
  const after = await probeFile(deps, target, opts.path, true);
  if (
    after.state !== "file" || after.sha256 !== desiredSha ||
    after.mode !== mode || after.owner !== opts.owner ||
    after.group !== opts.group
  ) {
    throw new SshError(`${opts.path} did not converge after install`);
  }
  return { sha256: desiredSha, changed: true };
}

/** A short random suffix from the injected clock and randomness. */
async function randomSuffix(deps: SshDeps): Promise<string> {
  const digest = await sha256Hex(
    `${deps.now()}-${Math.random()}-${
      crypto.getRandomValues(new Uint32Array(4)).join("")
    }`,
  );
  return digest.slice(0, 16);
}

/** Creates the parent directory of a destination path as the login user. */
export async function makeParentDir(
  deps: SshDeps,
  target: SshTarget,
  path: string,
): Promise<void> {
  const dir = path.slice(0, path.lastIndexOf("/")) || "/";
  const result = await runScript(deps, target, `mkdir -p ${posixQuote(dir)}`);
  if (result.exit_code !== 0) {
    throw new SshError(`could not create ${dir} (exit ${result.exit_code})`);
  }
}

/** Writes a file owned by the login user, converging on bytes and mode. */
export async function putUserFile(
  deps: SshDeps,
  target: SshTarget,
  path: string,
  content: Uint8Array | string,
  mode: string,
): Promise<PutFileResult> {
  const desiredSha = await sha256Hex(content);
  const before = await probeFile(deps, target, path);
  if (
    before.state === "file" && before.sha256 === desiredSha &&
    before.mode === normalizeMode(mode)
  ) {
    return { sha256: desiredSha, changed: false };
  }
  const result = await upload(deps, target, { path, content, mode });
  return { sha256: desiredSha, changed: result.changed };
}
