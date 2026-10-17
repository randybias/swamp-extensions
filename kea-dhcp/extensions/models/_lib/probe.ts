/**
 * Reading the live server and judging a commit's verify checks.
 *
 * @module
 */

import type { SshTarget } from "./ssh.ts";
import { deps } from "./deps.ts";
import {
  type Observation,
  ObservationSchema,
  type RevertState,
  type VerifyResult,
} from "./schemas.ts";
import {
  configHash,
  keaVersion,
  readMarker,
  remoteFileSha,
  runScript,
  serviceActive,
} from "./transport.ts";
import { CONFIG_PATH } from "./host_scripts.ts";

/** Probes the live server and builds an observation. */
export async function probe(
  target: SshTarget,
  args: { host: string },
  socket: string,
): Promise<Observation> {
  const active = await serviceActive(target);
  const versionText = await runScript(target, "kea-dhcp4 -V 2>&1 || true");
  const sockets = await runScript(
    target,
    `ss -lunp 2>/dev/null | awk '/:67 /{print $5}' || true`,
  );
  const fileSha = await remoteFileSha(target, CONFIG_PATH);
  const marker = await readMarker(target);
  let keaHash: string | undefined;
  if (active) {
    keaHash = await configHash(target, socket).catch(() => undefined);
  }
  return ObservationSchema.parse({
    host: args.host,
    service_active: active,
    kea_version: keaVersion(versionText.stdout),
    file_sha256: fileSha ?? undefined,
    kea_hash: keaHash,
    sockets: sockets.stdout.split(/\s+/).filter((line) => line !== ""),
    revert_armed: marker !== null,
    revert_token: marker?.token,
    revert_expires_at: marker?.expiresAt,
    drift: [],
    observed_at: new Date(deps.now()).toISOString(),
  });
}

/** Maps an observation onto the verify checks for a commit. */
export function verifyOf(
  observation: Observation,
  revert: RevertState,
  runningHash: string | undefined,
  expectActive: boolean,
  freshConnection: boolean,
): VerifyResult {
  const serviceOk = expectActive
    ? observation.service_active
    : !observation.service_active;
  const socketsOk = expectActive
    ? observation.sockets.length > 0
    : observation.sockets.length === 0;
  const hashOk = expectActive
    ? observation.kea_hash !== undefined &&
      (runningHash === undefined || observation.kea_hash === runningHash)
    : true;
  return {
    service: serviceOk ? "pass" : "fail",
    hash_match: hashOk ? "pass" : "fail",
    file_match: observation.file_sha256 === revert.armed_sha256
      ? "pass"
      : "fail",
    sockets: socketsOk ? "pass" : "fail",
    fresh_connection: freshConnection ? "pass" : "fail",
    canaries: (revert.canaries?.length ?? 0) > 0 ? "pass" : "skipped",
  };
}
