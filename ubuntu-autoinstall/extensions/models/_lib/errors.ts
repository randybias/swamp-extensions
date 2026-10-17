/**
 * The typed failures of the autoinstall model.
 *
 * Messages are fixed and never echo an input value: the seed carries a password
 * hash and the storage input can carry a passphrase.
 *
 * @module
 */

import type { Finding } from "./schemas.ts";

/** Failure classes a caller can branch on. */
export type AutoinstallErrorCode =
  | "invalid_input"
  | "validation"
  | "transport"
  | "layout"
  | "not_found"
  | "conflict";

/** A typed refusal or validation failure. */
export class AutoinstallError extends Error {
  /** The failure class. */
  readonly code: AutoinstallErrorCode;
  /** Schema findings, when the failure is validation. */
  readonly findings?: Finding[];
  /** Creates the error. */
  constructor(
    code: AutoinstallErrorCode,
    message: string,
    findings?: Finding[],
  ) {
    super(message);
    this.name = "AutoinstallError";
    this.code = code;
    this.findings = findings;
  }
}
