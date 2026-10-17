/**
 * Injectable dependencies and the method context for the Kea model.
 *
 * `deps` is a module-level live binding so tests and the transport share one
 * seam. It is exported as `let`; `setDeps` reassigns it and importers observe
 * the new value.
 *
 * @module
 */

import { denoDeps, type SshDeps } from "./ssh.ts";

/** A handle returned by `writeResource`. */
export interface DataHandle {
  name: string;
  specName: string;
  kind: string;
  dataId: string;
  version: number;
  size: number;
}

/** The subset of the swamp method context this model uses. */
export interface MethodContext {
  logger: {
    info: (message: string, fields?: Record<string, unknown>) => void;
    warn: (message: string, fields?: Record<string, unknown>) => void;
  };
  writeResource: (
    specName: string,
    instanceName: string,
    data: Record<string, unknown>,
  ) => Promise<DataHandle>;
  readResource: (
    instanceName: string,
    version?: number,
  ) => Promise<Record<string, unknown> | null>;
  vaultService?: {
    get: (vaultName: string, key: string) => Promise<string>;
  };
  extensionFile?: (path: string) => string;
}

/** The outcome shape every model method returns. */
export interface MethodOutcome {
  dataHandles: DataHandle[];
  result: unknown;
}

/** Injectable dependencies, including the overridable transport seams. */
export interface KeaDeps extends SshDeps {
  /** Resolves a vault reference to its secret. Tests replace this. */
  resolveSecret?: (reference: string) => Promise<string>;
  /** Generates an unguessable revert token. Tests replace this. */
  token: () => string;
}

/** The active dependencies: the real transport plus a random token until `setDeps`. */
export let deps: KeaDeps = {
  ...denoDeps,
  token: () => crypto.randomUUID(),
};

/** Replaces the model dependencies (tests only). Returns the previous ones. */
export function setDeps(next: Partial<KeaDeps>): KeaDeps {
  const previous = deps;
  deps = { ...deps, ...next };
  return previous;
}
