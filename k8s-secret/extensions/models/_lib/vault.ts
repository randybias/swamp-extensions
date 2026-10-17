/**
 * Vault reference resolution for the Secret model.
 *
 * A workflow cannot resolve a dynamic map of vault references in an
 * expression, so the model resolves `data_from_vault` itself through the
 * runtime's `context.vaultService` (a `{get, put}` object, not a factory).
 * Resolved values live only in memory; a failure names the vault and key,
 * never the value. Tests drive a plain-object `{get, put}` context.
 *
 * @module
 */

import { K8sSecretError } from "./kubectl.ts";

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

function readError(vault: string, key: string): K8sSecretError {
  return new K8sSecretError(
    "invalid_input",
    `Could not read vault ${vault} key ${key}`,
  );
}

/**
 * Resolves every `secretKey -> {vault, key}` entry to its plaintext. Throws a
 * fixed error naming the vault and key (never a value) when the runtime has no
 * vault service, when the service is the old factory shape, or when a lookup
 * fails or does not return a string.
 */
export async function resolveDataFromVault(
  service: unknown,
  refs: Record<string, VaultRef>,
): Promise<Record<string, string>> {
  if (
    !service || typeof service !== "object" ||
    typeof (service as VaultReader).get !== "function"
  ) {
    throw new K8sSecretError(
      "invalid_input",
      "No vault service is available to resolve data_from_vault",
    );
  }
  const reader = service as VaultReader;
  const data: Record<string, string> = {};
  for (const [secretKey, ref] of Object.entries(refs)) {
    let value: unknown;
    try {
      value = await reader.get(ref.vault, ref.key);
    } catch {
      throw readError(ref.vault, ref.key);
    }
    if (typeof value !== "string") throw readError(ref.vault, ref.key);
    data[secretKey] = value;
  }
  return data;
}
