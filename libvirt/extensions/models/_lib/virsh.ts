/**
 * Thin `virsh` command builders and execution helpers over the vendored SSH
 * transport. Every command is an argv vector; the transport quotes each word,
 * so names, pool names and the connection URI cannot inject a second command.
 *
 * @module
 */

import {
  exec,
  type ExecResult,
  quoteArgv,
  type SshDeps,
  type SshTarget,
  upload,
} from "./ssh.ts";

/** A `virsh` command failed, or a returned state was unusable. */
export class LibvirtError extends Error {
  /** Creates a libvirt error with a message safe to show a caller. */
  constructor(message: string) {
    super(message);
    this.name = "LibvirtError";
  }
}

/** The argv that runs one `virsh` subcommand against `uri`. */
export function virshArgv(uri: string, args: string[]): string[] {
  return ["virsh", "-c", uri, ...args];
}

/**
 * Runs `virsh -c uri args` and throws {@link LibvirtError} on a non-zero exit.
 * A transport failure still throws the transport's own typed error.
 */
export async function virsh(
  deps: SshDeps,
  target: SshTarget,
  uri: string,
  args: string[],
): Promise<ExecResult> {
  const res = await exec(deps, target, virshArgv(uri, args));
  if (res.exit_code !== 0) {
    const detail = `${res.stderr || res.stdout}`.trim().split("\n").slice(-3)
      .join(" ").slice(0, 400);
    throw new LibvirtError(
      `virsh ${args[0]} failed (exit ${res.exit_code})${
        detail ? `: ${detail}` : ""
      }`,
    );
  }
  return res;
}

/** Runs `virsh -c uri args` and returns the result without throwing on exit. */
export async function virshTry(
  deps: SshDeps,
  target: SshTarget,
  uri: string,
  args: string[],
): Promise<ExecResult> {
  return await exec(deps, target, virshArgv(uri, args));
}

/** True when `result` failed only because the object was already in the target state. */
export function isBenign(result: ExecResult, patterns: RegExp[]): boolean {
  if (result.exit_code === 0) return true;
  const text = `${result.stderr}\n${result.stdout}`;
  return patterns.some((p) => p.test(text));
}

const TOKEN_RE = /^[0-9a-f]{8,64}$/;

/** The remote path of the temporary XML file for `token`. */
export function xmlTempPath(token: string): string {
  if (!TOKEN_RE.test(token)) {
    throw new LibvirtError("invalid temporary-file token");
  }
  return `/tmp/randybias-libvirt-${token}.xml`;
}

/** Uploads `xml` to a temporary remote file and returns its path. */
export async function uploadXml(
  deps: SshDeps,
  target: SshTarget,
  token: string,
  xml: string,
): Promise<string> {
  const path = xmlTempPath(token);
  await upload(deps, target, { path, content: xml, mode: "0600" });
  return path;
}

/** Removes a remote file, ignoring a missing one. */
export async function removeFile(
  deps: SshDeps,
  target: SshTarget,
  path: string,
): Promise<void> {
  await exec(deps, target, ["rm", "-f", "--", path]).catch(() => undefined);
}

/** The argv that attaches to a domain's serial console under a hard bound. */
export function consoleArgv(
  uri: string,
  name: string,
  timeoutS: number,
  devname?: string,
): string[] {
  const args = ["console", name, "--force"];
  if (devname !== undefined) args.push("--devname", devname);
  // `virsh console` has no --timeout option and needs a controlling TTY, so
  // wrap it: `script` allocates a pty and `timeout -s KILL` is the real bound.
  // The wrapper runs in an outer shell that survives the killed child: without
  // it, GNU timeout kills the session process, ssh exits 255, and the canonical
  // transport (correctly) reports a transport failure, discarding the bytes
  // captured so far. Here 137 (SIGKILL) and 124 (timeout) become exit 0.
  const inner = quoteArgv(virshArgv(uri, args));
  const script =
    `timeout -s KILL ${timeoutS} script -qec ${inner} /dev/null; rc=$?; ` +
    `[ $rc -eq 137 ] || [ $rc -eq 124 ]; exit $?`;
  return ["sh", "-c", script];
}

const NOT_FOUND: Record<string, RegExp> = {
  network:
    /failed to get network|network not found|no network with matching name/i,
  domain: /failed to get domain|domain not found|no domain with matching name/i,
  volume:
    /failed to get vol|storage volume not found|no storage vol with matching name/i,
};

/**
 * True when a non-zero `virsh` exit is an explicit not-found (the object is
 * absent), as opposed to a hard error such as a refused connection or denied
 * permission, which the caller must surface rather than read as absence.
 */
export function isNotFound(
  result: ExecResult,
  kind: "network" | "domain" | "volume",
): boolean {
  if (result.exit_code === 0) return false;
  return NOT_FOUND[kind].test(`${result.stderr}\n${result.stdout}`);
}
