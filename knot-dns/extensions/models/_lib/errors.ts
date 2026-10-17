/**
 * Maps the marker a failed host script prints on stderr to a typed error.
 *
 * @module
 */

import { KnotError } from "./vault.ts";

/** Turns a host script's stderr markers and exit code into a `KnotError`. */
export function mapScriptError(stderr: string, exit: number): KnotError {
  if (stderr.includes("INCLUDE_MISSING")) {
    return new KnotError(
      "invalid_input",
      "knot.conf does not include /etc/knot/knot.conf.d/*.conf; run install first",
    );
  }
  if (stderr.includes("STAGE_MISSING")) {
    return new KnotError("invalid_input", "staged files are missing");
  }
  const missing = /TOOL_MISSING (\S+)/.exec(stderr)?.[1];
  if (missing !== undefined) {
    return new KnotError(
      "tool_missing",
      `${missing} is not installed; run install first`,
    );
  }
  if (stderr.includes("KZONECHECK_MISSING")) {
    return new KnotError(
      "tool_missing",
      "kzonecheck is not installed (package knot-dnssecutils); run install first",
    );
  }
  if (stderr.includes("KRESCTL_MISSING")) {
    return new KnotError(
      "tool_missing",
      "kresctl is not installed (Knot Resolver 6); run install with resolver true",
    );
  }
  if (stderr.includes("KEY_MISMATCH")) {
    return new KnotError(
      "invalid_input",
      "the package repository's signing key does not have the pinned fingerprint; nothing was trusted",
    );
  }
  if (stderr.includes("KEY_FETCH_FAILED")) {
    return new KnotError(
      "tool_failed",
      "could not fetch the repository signing key",
    );
  }
  if (stderr.includes("UNSUPPORTED_OS")) {
    return new KnotError(
      "invalid_input",
      "this host's OS release has no codename",
    );
  }
  if (stderr.includes("UNEXPECTED_VERSION")) {
    return new KnotError(
      "verify_failed",
      "an installed tool is not the major version this model is written for",
    );
  }
  if (stderr.includes("KZONECHECK_FAILED")) {
    return new KnotError("tool_failed", "kzonecheck rejected the zone");
  }
  if (stderr.includes("CONFCHECK_FAILED")) {
    return new KnotError("tool_failed", "knotc conf-check rejected the config");
  }
  if (stderr.includes("RESTORE_RELOAD_FAILED")) {
    return new KnotError(
      "reload_failed",
      "the rollback reload failed; the backup was not removed",
    );
  }
  if (stderr.includes("VERIFY_QUERY_FAILED")) {
    return new KnotError(
      "verify_failed",
      "knotd did not answer for the zone on every listen address; the previous configuration was restored",
    );
  }
  if (stderr.includes("KDIG_MISSING")) {
    return new KnotError(
      "invalid_input",
      "kdig is not installed; run install first",
    );
  }
  if (stderr.includes("RELOAD_FAILED")) {
    return new KnotError(
      "reload_failed",
      "reload failed; the previous configuration was restored",
    );
  }
  if (stderr.includes("KRESCTL_FAILED")) {
    return new KnotError("tool_failed", "kresctl validate rejected the config");
  }
  if (stderr.includes("TEST_QUERY_FAILED")) {
    return new KnotError("verify_failed", "the resolver test query failed");
  }
  if (stderr.includes("DNSSEC_UNSIGN_ACK_REQUIRED")) {
    return new KnotError(
      "invalid_input",
      "the zone is signed; pass dnssec_unsign_ack to remove it",
    );
  }
  if (stderr.includes("STOP_FAILED")) {
    return new KnotError("reload_failed", "could not stop the resolver");
  }
  if (stderr.includes("CHOWN_FAILED")) {
    return new KnotError(
      "tool_failed",
      "could not set root:knot ownership on a managed file",
    );
  }
  if (stderr.includes("PROBE_FAILED")) {
    return new KnotError("tool_failed", "a live probe failed");
  }
  if (stderr.includes("NO_BACKUP")) {
    return new KnotError("reload_failed", "the backup directory is missing");
  }
  // 127 is the shell's "command not found": say so, instead of blaming the
  // tool's verdict.
  if (exit === 127) {
    return new KnotError("tool_missing", "a required tool is not installed");
  }
  return new KnotError("tool_failed", `remote command failed (exit ${exit})`);
}
