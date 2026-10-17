/**
 * Swamp extension model for a static artifact server: serve a directory of
 * pinned artifacts over HTTP(S) from one host and manage it over SSH.
 *
 * The model is generic: it holds no host, path or credential in its
 * definition. Every method takes its SSH target and `root` as arguments, and
 * stored data is keyed by the canonical target plus root, never the definition
 * name. Consumers fetch bytes by content hash; the server is a cache, not a
 * source of trust.
 *
 * @module
 */

import { z } from "npm:zod@4.3.6";
import { denoDeps, type SshDeps } from "./_lib/ssh.ts";
import { setDeps } from "./_lib/runtime.ts";
import {
  ArtifactSchema,
  ConfigSchema,
  ListingSchema,
  PrunePlanSchema,
  ServerSchema,
  VerificationSchema,
} from "./_lib/schema.ts";
import { adminMethods } from "./_lib/methods_admin.ts";
import { lifecycleMethods } from "./_lib/methods_lifecycle.ts";
import { objectMethods } from "./_lib/methods_objects.ts";
import type { ArtifactServerModel } from "./_lib/types.ts";

/** The artifact-server model: a plain object literal. */
export const model = {
  type: "@randybias/artifact-server",
  version: "2026.10.17.1",
  description:
    "Serve a directory of pinned artifacts over HTTP(S) from one host and manage it over SSH: nginx site config, upload, host-side fetch, bundles, refs, listing, verification and prune. One generic definition with no host, path or credential in it.",
  globalArguments: z.strictObject({}),
  resources: {
    config: {
      description: "Rendered nginx site config and its hash",
      schema: ConfigSchema,
      lifetime: "infinite",
      garbageCollection: 10,
    },
    server: {
      description: "Observed nginx state and layout summary",
      schema: ServerSchema,
      lifetime: "infinite",
      garbageCollection: 10,
    },
    artifact: {
      description: "One stored blob or bundle: hash, path, url, size",
      schema: ArtifactSchema,
      lifetime: "infinite",
      garbageCollection: 5,
    },
    listing: {
      description: "Refs, blobs and bundles with sizes and mtimes",
      schema: ListingSchema,
      lifetime: "infinite",
      garbageCollection: 10,
    },
    verification: {
      description: "Objects rehashed and compared against SHA256SUMS",
      schema: VerificationSchema,
      lifetime: "infinite",
      garbageCollection: 10,
    },
    prune_plan: {
      description: "Objects not reachable from a ref or keep list",
      schema: PrunePlanSchema,
      lifetime: "1d",
      garbageCollection: 10,
    },
  },
  methods: {
    ...lifecycleMethods,
    ...objectMethods,
    ...adminMethods,
  },
};

/** Compatibility factory: sets the transport and returns the model. */
export function createModel(next: SshDeps = denoDeps): ArtifactServerModel {
  setDeps(next);
  return model;
}
