/**
 * Boot-disk probes for the zfs model.
 *
 * The decision logic lives in the vendored `protected_devices.ts`; this module
 * only runs the probes that module judges, privileged with `sudo -n --` exactly
 * as the shared guard expects, and turns a refusal into a typed error. A probe
 * an unprivileged read would return empty values for is run as root, so an
 * unreadable device column is never read as "unrelated".
 *
 * @module
 */

import {
  assess,
  BLKID_COMMAND,
  type CommandProbe,
  examineTargets,
  type FileProbe,
  FINDMNT_COMMAND,
  LINKS_COMMAND,
  LSBLK_COMMAND,
  mdExamineCommand,
  type ProbeInputs,
  type ProtectedSet,
  PVS_COMMAND,
  type Refusal,
  ZPOOL_COMMAND,
} from "./protected_devices.ts";
import { exec, type SshDeps, type SshTarget } from "./ssh.ts";

/** True when stderr is sudo's password or tty refusal. */
export function isSudoRefusal(stderr: string): boolean {
  const l = stderr.toLowerCase();
  return l.includes("a password is required") ||
    l.includes("must have a tty") ||
    l.includes("a terminal is required") ||
    l.includes("no tty present") ||
    l.includes("sudo: a password");
}

/** A boot-disk guard refusal, carrying the shared module's code and detail. */
export class DeviceGuardError extends Error {
  /** `boot-protected` when a device backs the system; `boot-unverifiable` otherwise. */
  readonly code: "boot-protected" | "boot-unverifiable";
  /** Structured detail: host, device, reasons. */
  readonly detail: Record<string, unknown>;
  /** Creates a typed guard error. */
  constructor(
    code: "boot-protected" | "boot-unverifiable",
    message: string,
    detail: Record<string, unknown> = {},
  ) {
    super(message);
    this.name = "DeviceGuardError";
    this.code = code;
    this.detail = detail;
  }
}

/** Runs one probe command privileged or not, returning its status as data. */
async function runCommand(
  deps: SshDeps,
  target: SshTarget,
  command: string,
  sudo: boolean,
): Promise<CommandProbe> {
  const argv = sudo
    ? ["sudo", "-n", "--", "sh", "-c", command]
    : ["sh", "-c", command];
  const result = await exec(deps, target, argv);
  if (sudo && result.exit_code !== 0 && isSudoRefusal(result.stderr)) {
    throw new DeviceGuardError(
      "boot-unverifiable",
      "passwordless sudo is required",
      { host: target.host, exit: result.exit_code },
    );
  }
  return {
    code: result.exit_code,
    stdout: result.stdout,
    stderr: result.stderr,
  };
}

/**
 * Reads a host file. Only an explicit not-exists is `absent`; any other failure
 * is an `error` the shared module refuses on.
 */
async function readFileProbe(
  deps: SshDeps,
  target: SshTarget,
  path: string,
): Promise<FileProbe> {
  const result = await exec(deps, target, ["cat", "--", path]);
  if (result.exit_code === 0) return { state: "ok", text: result.stdout };
  if (
    result.exit_code === 1 &&
    /No such file or directory/i.test(result.stderr)
  ) {
    return { state: "absent" };
  }
  return { state: "error", detail: `exit ${result.exit_code}` };
}

/**
 * Reads every probe the shared module judges. `lsblk`, `blkid`, `mdadm`,
 * `zpool` and `pvs` run as root because their device columns are empty for an
 * unprivileged reader on a host without udev.
 */
export async function collectProbes(
  deps: SshDeps,
  target: SshTarget,
  candidates: string[],
): Promise<ProbeInputs> {
  const lsblk = await runCommand(deps, target, LSBLK_COMMAND, true);
  const links = await runCommand(deps, target, LINKS_COMMAND, false);
  const blkid = await runCommand(deps, target, BLKID_COMMAND, true);
  const mdstat = await readFileProbe(deps, target, "/proc/mdstat");
  const mdExamine: Record<string, CommandProbe> = {};
  for (
    const path of examineTargets(
      { lsblk, links, blkid, mdstat },
      candidates,
    )
  ) {
    mdExamine[path] = await runCommand(
      deps,
      target,
      mdExamineCommand(path),
      true,
    );
  }
  return {
    lsblk,
    findmnt: await runCommand(deps, target, FINDMNT_COMMAND, false),
    fstab: await readFileProbe(deps, target, "/etc/fstab"),
    swaps: await readFileProbe(deps, target, "/proc/swaps"),
    mdstat,
    links,
    blkid,
    zpool: await runCommand(deps, target, ZPOOL_COMMAND, true),
    pvs: await runCommand(deps, target, PVS_COMMAND, true),
    mdExamine,
  };
}

/** Maps a shared-module refusal to a typed error naming the device. */
function refusalError(target: SshTarget, refusal: Refusal): DeviceGuardError {
  const device = typeof refusal.detail.device === "string"
    ? refusal.detail.device
    : undefined;
  const message = device
    ? `refusing ${device}: ${refusal.message}`
    : refusal.message;
  return new DeviceGuardError(
    refusal.code === "protected" ? "boot-protected" : "boot-unverifiable",
    message,
    { host: target.host, ...refusal.detail },
  );
}

/**
 * Runs the probes, judges the candidates with the vendored shared guard, and
 * returns the protected set. Pass `previous` on a re-read so the set can only
 * grow. Any refusal is a typed {@link DeviceGuardError}.
 */
export async function assessProtected(
  deps: SshDeps,
  target: SshTarget,
  candidates: string[],
  previous?: ProtectedSet,
): Promise<ProtectedSet> {
  const result = assess(
    await collectProbes(deps, target, candidates),
    candidates,
    previous,
  );
  if (result.ok) return result.set;
  throw refusalError(target, result.refusal);
}
