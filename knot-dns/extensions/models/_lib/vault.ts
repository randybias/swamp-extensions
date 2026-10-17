/**
 * Vault references and the typed error for the Knot DNS model.
 *
 * A workflow cannot resolve a dynamic vault reference in an expression, so the
 * model resolves its secret references itself through the runtime's
 * `context.vaultService` (a `{get, put}` object, not a factory). A failure
 * names the vault and key, never the value. Tests drive a plain-object
 * `{get, put}` context.
 *
 * @module
 */

/** Grammar shared by vault names and vault key names. */
export const VAULT_NAME_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;

/** True for a vault name this model will ask the runtime to read. */
export const isVaultName = (s: string): boolean => VAULT_NAME_RE.test(s);
/** True for a vault key name this model will ask the runtime to read. */
export const isVaultKey = (s: string): boolean => VAULT_NAME_RE.test(s);

/** One vault reference: a vault name and a key inside it. */
export interface VaultRef {
  /** Vault instance name, as configured in the repository. */
  vault: string;
  /** Key inside that vault. */
  key: string;
}

/** Reads one secret from a swamp vault. Implemented by the runtime. */
export interface VaultReader {
  /** Returns the secret's plaintext, or throws when it is missing. */
  get(vaultName: string, secretKey: string): Promise<string>;
}

/** Failure classes a Knot DNS call can report. */
export type KnotErrorCode =
  | "invalid_input"
  | "transport"
  | "tool_failed"
  | "reload_failed"
  | "rollback_failed"
  | "verify_failed"
  | "port_busy"
  | "timeout";

/** A typed failure whose message carries no secret value. */
export class KnotError extends Error {
  /** The failure class. */
  readonly code: KnotErrorCode;
  /** Creates a typed error. */
  constructor(code: KnotErrorCode, message: string) {
    super(message);
    this.name = "KnotError";
    this.code = code;
  }
}

function readError(ref: VaultRef): KnotError {
  return new KnotError(
    "invalid_input",
    `Could not read vault ${ref.vault} key ${ref.key}`,
  );
}

/**
 * Resolves one vault reference to its plaintext. Throws a fixed error naming
 * the vault and key (never a value) when the runtime has no vault service or
 * the lookup fails.
 */
export async function resolveSecret(
  service: unknown,
  ref: VaultRef,
): Promise<string> {
  if (
    !service || typeof service !== "object" ||
    typeof (service as VaultReader).get !== "function"
  ) {
    throw new KnotError(
      "invalid_input",
      "No vault service is available to resolve a secret reference",
    );
  }
  let value: unknown;
  try {
    value = await (service as VaultReader).get(ref.vault, ref.key);
  } catch {
    throw readError(ref);
  }
  if (typeof value !== "string" || value.length === 0) {
    throw readError(ref);
  }
  return value;
}
