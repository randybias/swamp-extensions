/**
 * Serial-to-stable-device resolution.
 *
 * A disk is selected by serial, never by kernel name: kernel names reorder
 * across reboots. The resolver lists the target's `/dev/disk/by-id` entries,
 * keeps the names that end with the serial, proves every match resolves to a
 * single block device, and returns the by-id link path to use in Ceph specs
 * plus the canonical device for local lookups. An invalid serial is refused
 * before any ssh call, and the serial never reaches a remote glob.
 *
 * @module
 */

import { fail } from "./errors.ts";
import type { CommandResult } from "./ssh_session.ts";
import type { SshSession } from "./ssh_session.ts";
import { assertSerial, quote, truncate } from "./validate.ts";

/** By-id link-component characters: letters, digits, dot, underscore, colon, hyphen. */
export const BY_ID_NAME_RE = /^[A-Za-z0-9._:-]+$/;

/** Resolved device path: absolute `/dev/`, letters, digits, dot, underscore, hyphen, slash. */
export const DEVICE_PATH_RE = /^\/dev\/[A-Za-z0-9._/-]+$/;

/** A resolved disk: the stable by-id path and the proven canonical device. */
export interface ResolvedDevice {
  /** By-id link path; always the value callers put in OSD specs. */
  path: string;
  /** Canonical kernel device, for local lookups and comparisons only. */
  device: string;
}

/** True when a by-id name matches `serial` at its end, including the NVMe namespace form. */
export function matchesSerial(name: string, serial: string): boolean {
  if (name.endsWith(`_${serial}`) || name.endsWith(`-${serial}`)) return true;
  // A namespace link ends `<serial>_<n>`; the serial must still be a whole segment.
  const marker = `_${serial}_`;
  const at = name.lastIndexOf(marker);
  if (at < 0) return false;
  const ns = name.slice(at + marker.length);
  return /^\d+$/.test(ns) && name.slice(0, at).length > 0;
}

/** True when a by-id name is a partition link that must be ignored. */
export function isPartitionLink(name: string): boolean {
  return /-part\d+$/.test(name);
}

/** Keeps candidate by-id names that match the serial and are not partitions. */
export function candidateNames(names: string[], serial: string): string[] {
  return names.filter((n) =>
    BY_ID_NAME_RE.test(n) && !isPartitionLink(n) && matchesSerial(n, serial)
  );
}

/** Parses `readlink -f` output into the distinct device paths it named. */
export function distinctDevices(stdout: string): string[] {
  const seen = new Set<string>();
  for (const line of stdout.split("\n")) {
    const value = line.trim();
    if (value !== "") seen.add(value);
  }
  return [...seen].sort();
}

/** The ssh call a resolver makes to list by-id entries; no sudo, no serial, no glob. */
export function listByIdCommand(): string {
  return 'for p in /dev/disk/by-id/*; do [ -e "$p" ] && basename -- "$p"; done; true';
}

/** The ssh call a resolver makes to resolve candidate links to canonical devices. */
export function readlinkCommand(fullPaths: string[]): string {
  return `readlink -f ${fullPaths.map(quote).join(" ")} | sort -u`;
}

/** Dependencies a resolver needs from the transport. */
export interface ResolverSession {
  target: { host: string };
  run: SshSession["run"];
}

/**
 * Resolves one serial to a stable device. `phase` labels the caller's failure,
 * e.g. `wipe.resolve`; a malformed serial fails as `validate` before any call.
 */
export async function resolveSerial(
  session: ResolverSession,
  serial: string,
  phase: string,
): Promise<ResolvedDevice> {
  assertSerial("serial", serial);
  const host = session.target.host;
  const baseDetail = { host, serial };

  const listed: CommandResult = await session.run({
    command: listByIdCommand(),
    allowNonZero: true,
  });
  const names = listed.stdout.split("\n").map((l) => l.trim()).filter((l) =>
    l !== ""
  );
  const matches = candidateNames(names, serial);
  if (matches.length === 0) {
    fail(phase, "serial resolved to zero devices", baseDetail);
  }

  const fullPaths = matches.map((n) => `/dev/disk/by-id/${n}`);
  const resolved = await session.run({ command: readlinkCommand(fullPaths) });
  const devices = distinctDevices(resolved.stdout);
  if (devices.length === 0) {
    fail(phase, "serial resolved to zero devices", baseDetail);
  }
  if (devices.length > 1) {
    fail(phase, "serial resolved to several devices", {
      ...baseDetail,
      devices,
    });
  }
  const device = devices[0];
  if (!DEVICE_PATH_RE.test(device)) {
    fail(phase, "resolved device is not a plausible device path", {
      ...baseDetail,
      device: truncate(device),
    });
  }
  // With several links proven onto one device, the answer is deterministic.
  const chosen = [...matches].sort()[0];
  return { path: `/dev/disk/by-id/${chosen}`, device };
}
