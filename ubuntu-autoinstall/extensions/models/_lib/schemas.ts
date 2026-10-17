/**
 * cloud-config JSON-Schema validation against a vendored, pinned schema.
 *
 * cloud-init's `schema-cloud-config-v1.json` ships with the extension (dual
 * Apache-2.0 / GPL-3.0; see LICENSE.txt) and is compiled once. Subiquity's
 * autoinstall schema is **not** shipped: it is AGPL-3.0. The autoinstall
 * document is instead validated by `./autoinstall.ts`, written from the public
 * docs, and optionally cross-checked against the upstream schema by a gated
 * dev-only test.
 *
 * @module
 */

import AjvModule from "npm:ajv@8.17.1";
import AjvDraft04Module from "npm:ajv-draft-04@1.0.0";
import addFormatsModule from "npm:ajv-formats@3.0.1";
import cloudConfigSchema from "./schemas/cloud-config-26.1.json" with {
  type: "json",
};

/** Provenance of the vendored cloud-config schema, and its license. */
export const CLOUD_CONFIG_SCHEMA_SOURCE =
  "cloud-init 26.1 schema-cloud-config-v1.json (Apache-2.0 / GPL-3.0)";

/** One validation problem, addressed by a JSON pointer. */
export interface Finding {
  /** JSON pointer to the offending member. */
  pointer: string;
  /** Fixed human message; never echoes a value. */
  message: string;
}

interface AjvError {
  instancePath?: string;
  message?: string;
}

interface Compiled {
  (data: unknown): boolean;
  errors?: AjvError[] | null;
}

interface AjvInstance {
  compile(schema: object): Compiled;
}

/**
 * AJV is CommonJS; the default export is the class at runtime.
 *
 * `ajv-draft-04` peer-depends on `ajv` (it extends `ajv/dist/core`). Importing
 * `ajv` here, pinned, keeps it in the module graph so a bundler resolves the
 * peer even when the extension's deno.json/deno.lock are not beside it (a
 * registry consumer in a plain swamp repo), which otherwise fails with
 * "Could not resolve ajv/dist/core".
 */
const AjvBase = AjvModule as unknown as (new (
  opts?: Record<string, unknown>,
) => AjvInstance);
const AjvDraft04 = AjvDraft04Module as unknown as typeof AjvBase;
const addFormats = addFormatsModule as unknown as (ajv: AjvInstance) => void;

let cloudConfigValidator: Compiled | undefined;

/** Validates a cloud-config document against the vendored cloud-init schema. */
export function validateCloudConfigSchema(doc: unknown): Finding[] {
  cloudConfigValidator ??= (() => {
    const ajv = new AjvDraft04({ strict: false, allErrors: true });
    addFormats(ajv);
    return ajv.compile(cloudConfigSchema as object);
  })();
  const ok = cloudConfigValidator(doc);
  if (ok) return [];
  return (cloudConfigValidator.errors ?? []).map((e) => ({
    pointer: e.instancePath === "" || e.instancePath === undefined
      ? "/"
      : e.instancePath,
    message: e.message ?? "does not match the schema",
  }));
}
