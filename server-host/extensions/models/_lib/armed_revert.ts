/**
 * The armed-revert protocol: a host-side dead-man's switch built before any
 * dangerous firewall change, and cancelled only by an explicit commit.
 *
 * The switch is a `systemd-run --on-active` transient timer, owned by PID 1,
 * that runs a small restore script after `revert_after_s`. Because the timer
 * lives on the host, it fires even when the SSH session that armed it has
 * died, so an operator who locks themselves out recovers without console
 * access. This module renders the scripts and argv; it never runs anything.
 *
 * @module
 */

import { HostConfigError } from "./validate.ts";

/** Remote directory holding snapshots and revert scripts. */
export const STATE_DIR = "/var/lib/server-host";
/** Grammar of a revert token; the token is embedded in remote paths and units. */
export const TOKEN_RE = /^[0-9a-f]{16,64}$/;

/** The remote path of the nftables snapshot for `token`. */
export function snapshotPath(token: string): string {
  assertToken(token);
  return `${STATE_DIR}/revert-${token}.nft`;
}

/** The remote path of the revert script for `token`. */
export function scriptPath(token: string): string {
  assertToken(token);
  return `${STATE_DIR}/revert-${token}.sh`;
}

/** The base name of the transient timer unit for `token`. */
export function unitName(token: string): string {
  assertToken(token);
  return `server-host-revert-${token}`;
}

function assertToken(token: string): void {
  if (!TOKEN_RE.test(token)) {
    throw new HostConfigError("Not a revert token");
  }
}

/** Prefixes `argv` with a non-interactive `sudo` when `sudo` is true. */
export function withSudo(sudo: boolean, argv: string[]): string[] {
  return sudo ? ["sudo", "-n", ...argv] : argv;
}

/**
 * The argv that snapshots the whole current ruleset to a file on the host.
 * Run before the arm step, so the restore point predates the change.
 */
export function renderSnapshotArgv(token: string, sudo: boolean): string[] {
  const script = `set -e\nmkdir -p "${STATE_DIR}"\nnft list ruleset > "${
    snapshotPath(token)
  }"\n`;
  return withSudo(sudo, ["sh", "-c", script]);
}

/**
 * The host-side lock that serializes a restore and a commit so they cannot
 * race. Both the restore script and the commit script take it with `flock`.
 */
export const LOCK_PATH = `${STATE_DIR}/revert.lock`;

/**
 * The restore script the timer runs. It holds the host-side lock, aborts when
 * the snapshot has already been cleaned up by a commit, and otherwise submits
 * `flush ruleset` plus the snapshot as a SINGLE `nft -f -` transaction, so the
 * restore is atomic: nft either commits the whole restore or leaves the
 * applied rules in place.
 */
export function renderRevertScript(token: string): string {
  const snap = snapshotPath(token);
  return `#!/bin/sh
# Armed revert for @randybias/server-host. Generated; do not edit.
set -e
exec 9>"${LOCK_PATH}"
flock 9
snap="${snap}"
if [ ! -f "$snap" ]; then
  rm -f "${scriptPath(token)}"
  exit 0
fi
{
  echo 'flush ruleset'
  if [ -s "$snap" ]; then cat "$snap"; fi
} | nft -f -
rm -f "$snap"
rm -f "${scriptPath(token)}"
`;
}

/**
 * The argv that arms the dead-man's switch: a transient `--on-active` timer
 * that runs the uploaded revert script after `revertAfterS` seconds. The
 * timer belongs to PID 1 and survives a dropped SSH session.
 */
export function renderArmArgv(
  token: string,
  revertAfterS: number,
  sudo: boolean,
): string[] {
  if (
    !Number.isInteger(revertAfterS) || revertAfterS < 60 || revertAfterS > 1800
  ) {
    throw new HostConfigError("revert_after_s must be 60-1800");
  }
  const unit = unitName(token);
  return withSudo(sudo, [
    "systemd-run",
    `--on-active=${revertAfterS}s`,
    `--unit=${unit}`,
    "--collect",
    "--description=server-host armed revert",
    "--quiet",
    scriptPath(token),
  ]);
}

/**
 * The argv that cancels the timer and removes the snapshot and script. It
 * holds the same host-side lock as the restore script, FAILS unless the timer
 * is still active at cancel time, stops the timer and any already-started
 * service, and only then removes the files. A non-zero exit means no commit
 * may be recorded.
 */
export function renderCommitArgv(token: string, sudo: boolean): string[] {
  const unit = unitName(token);
  const script = `set -e
exec 9>"${LOCK_PATH}"
flock 9
unit='${unit}'
state=$(systemctl is-active "$unit.timer" || true)
if [ "$state" != "active" ]; then
  echo "revert timer $unit is not active" >&2
  exit 1
fi
systemctl stop "$unit.timer"
systemctl stop "$unit.service" 2>/dev/null || true
rm -f '${snapshotPath(token)}' '${scriptPath(token)}'
`;
  return withSudo(sudo, ["sh", "-c", script]);
}

/** The READ-ONLY argv that reports whether the revert timer is still armed. */
export function renderProbeArgv(token: string, sudo: boolean): string[] {
  return withSudo(sudo, ["systemctl", "is-active", unitName(token) + ".timer"]);
}

/** True when `systemctl is-active` reported `active` for a timer. */
export function isTimerActive(stdout: string): boolean {
  return stdout.trim() === "active";
}
