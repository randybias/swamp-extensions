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

/** The argv that attaches to a domain's serial console with a hard timeout. */
export function consoleArgv(
  uri: string,
  name: string,
  timeoutS: number,
  devname?: string,
): string[] {
  const args = ["console", name, "--force", "--timeout", String(timeoutS)];
  if (devname !== undefined) args.push("--devname", devname);
  return virshArgv(uri, args);
}
