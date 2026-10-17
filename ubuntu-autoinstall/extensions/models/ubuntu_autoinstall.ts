/**
 * Swamp extension model for Ubuntu Server autoinstall.
 *
 * Renders a NoCloud seed (`user-data`, `meta-data`, `vendor-data`) from typed
 * inputs, validates it against cloud-init's vendored schema plus a
 * parser-differential guard and our own structural checks, and makes it
 * reachable by the installer as an HTTP bundle on an artifact-server root or as
 * the input to a `CIDATA` image. The password is a crypt hash from vault; no
 * method result carries the hash or the file bytes, which live only in a
 * sensitive `seed_files` resource.
 *
 * @module
 */

import { z } from "npm:zod@4.3.6";
import { AutoinstallError } from "./_lib/errors.ts";
import { CLOUD_CONFIG_SCHEMA_SOURCE } from "./_lib/schemas.ts";
import {
  buildUserDataDocument,
  cmdlineFor,
  cmdlineForCidata,
  type RenderedSeed,
  renderSeed,
} from "./_lib/render.ts";
import {
  type Finding,
  roundTripGuard,
  validateUserDataObject,
  validateUserDataText,
} from "./_lib/validate.ts";
import { sanitizeScalars } from "./_lib/yaml.ts";
import { bundleDir, bundleUrl } from "./_lib/seed.ts";
import {
  assertLayout,
  bundleContents,
  bundleHostname,
  bundleStatus,
  readRef,
  removeTree,
  transportError,
  writeRef,
  writeTree,
} from "./_lib/publish.ts";
import {
  CmdlineArgs,
  PublishArgs,
  type PublishArgsT,
  RenderArgs,
  type RenderArgsT,
  RenderStateSchema,
  SeedFilesSchema,
  SeedStateSchema,
  toInput,
  toTarget,
  UnpublishArgs,
  ValidateArgs,
} from "./_lib/model_args.ts";
import { denoDeps, type SshDeps } from "./_lib/ssh.ts";

// deno-lint-ignore no-explicit-any
type Ctx = any;

let deps: SshDeps = denoDeps;

/** Replaces the injected transport dependencies and returns the previous ones. */
export function setDeps(d: Partial<SshDeps>): SshDeps {
  const prev = deps;
  deps = { ...deps, ...d };
  return prev;
}

/** Runs a block of remote calls, mapping any failure to a typed error. */
async function withTransport<T>(fn: () => Promise<T>): Promise<T> {
  try {
    return await fn();
  } catch (e) {
    throw transportError(e);
  }
}

/** Throws a typed validation error when findings are present. */
function assertValid(findings: Finding[]): void {
  if (findings.length > 0) {
    throw new AutoinstallError(
      "validation",
      `the autoinstall document has ${findings.length} problem(s)`,
      findings,
    );
  }
}

/**
 * Renders the seed once and runs every validation layer, throwing on the first
 * problem. The round-trip guard compares the re-parsed bytes to the same
 * sanitized tree the emitter saw.
 */
async function renderValidated(
  a: RenderArgsT | PublishArgsT,
): Promise<RenderedSeed> {
  const input = toInput(a);
  const tree = buildUserDataDocument(input);
  const seed = await renderSeed(input);
  const findings = roundTripGuard(seed.user_data, sanitizeScalars(tree));
  findings.push(...roundTripGuard(seed.meta_data, seed.meta_tree));
  findings.push(...validateUserDataObject(tree));
  assertValid(findings);
  return seed;
}

/**
 * Renders, validates and checks a published bundle, then persists the
 * observation as the `seed` resource. Shared by `get` and `sync`.
 */
async function observePublished(context: Ctx, a: PublishArgsT) {
  const seed = await renderValidated(a);
  const t = toTarget(a.server.ssh);
  const status = await withTransport(async () => {
    await assertLayout(deps, t, a.server.root);
    return await bundleStatus(
      deps,
      t,
      bundleDir(a.server.root, seed.tree_sha256),
      bundleContents(seed),
    );
  });
  const state = {
    hostname: a.identity.hostname,
    tree_sha256: seed.tree_sha256,
    seed_url: bundleUrl(a.server.url_base, seed.tree_sha256),
    files: seed.files,
    status,
    observed_at: new Date().toISOString(),
  };
  const handle = await context.writeResource(
    "seed",
    a.identity.hostname,
    state,
  );
  return { handle, state };
}

/** Model definition for `@randybias/ubuntu-autoinstall`. */
export const model = {
  type: "@randybias/ubuntu-autoinstall",
  version: "2026.10.17.1",
  description:
    "Render, validate and publish an Ubuntu Server autoinstall NoCloud seed from typed inputs, over SSH to an artifact-server root or for a CIDATA image. The password is a crypt hash from vault and no output carries a plaintext.",
  globalArguments: z.strictObject({}),
  resources: {
    render: {
      description: "A rendered seed's tree hash, per-file hashes and cmdline",
      schema: RenderStateSchema,
      lifetime: "30d" as const,
      garbageCollection: 10,
    },
    seed_files: {
      description: "The rendered seed file bytes; sensitive",
      schema: SeedFilesSchema,
      lifetime: "30d" as const,
      garbageCollection: 5,
    },
    seed: {
      description: "Observation of a published seed bundle on the server",
      schema: SeedStateSchema,
      lifetime: "infinite" as const,
      garbageCollection: 10,
    },
  },
  methods: {
    render: {
      description:
        "READ-ONLY. Build and validate user-data, meta-data and vendor-data from the inputs; identical inputs give identical bytes. Returns the tree hash, per-file digests and the command lines; the file bytes are written to the sensitive seed_files resource, not returned.",
      arguments: RenderArgs,
      execute: async (args: z.input<typeof RenderArgs>, context: Ctx) => {
        const a = RenderArgs.parse(args);
        const seed = await renderValidated(a);
        // One instance name per resource kind: swamp rejects a duplicate name
        // within a method run, even across resource specs.
        const key = `${a.identity.hostname}-${seed.tree_sha256.slice(0, 12)}`;
        const renderHandle = await context.writeResource(
          "render",
          `${key}-render`,
          {
            hostname: a.identity.hostname,
            tree_sha256: seed.tree_sha256,
            files: seed.files,
            cmdline: seed.cmdline,
            seed_url: a.seed_url,
            observed_at: new Date().toISOString(),
          },
        );
        const filesHandle = await context.writeResource(
          "seed_files",
          `${key}-files`,
          {
            "user-data": seed.user_data,
            "meta-data": seed.meta_data,
            "vendor-data": seed.vendor_data,
          },
        );
        return {
          dataHandles: [renderHandle, filesHandle],
          result: {
            tree_sha256: seed.tree_sha256,
            files: seed.files,
            cmdline: seed.cmdline,
          },
        };
      },
    },

    validate: {
      description:
        "READ-ONLY. Validate a supplied autoinstall user-data document with the same pipeline and return findings; the document is never rewritten and no value is echoed.",
      arguments: ValidateArgs,
      execute: (args: z.input<typeof ValidateArgs>, _context: Ctx) => {
        const a = ValidateArgs.parse(args);
        const findings = validateUserDataText(a.user_data);
        return {
          dataHandles: [],
          result: {
            valid: findings.length === 0,
            findings,
            schema_sources: {
              cloud_config: CLOUD_CONFIG_SCHEMA_SOURCE,
              autoinstall:
                "structural checks written from the public reference",
            },
          },
        };
      },
    },

    cmdline: {
      description:
        "READ-ONLY. Emit the kernel and GRUB command lines for an HTTP seed URL, and the plain autoinstall argument for a CIDATA seed.",
      arguments: CmdlineArgs,
      execute: (args: z.input<typeof CmdlineArgs>, _context: Ctx) => {
        const a = CmdlineArgs.parse(args);
        return {
          dataHandles: [],
          result: {
            ...cmdlineFor(a.seed_url),
            cidata_args: cmdlineForCidata(),
          },
        };
      },
    },

    publish_http: {
      kind: "action" as const,
      description:
        "Idempotent. Render, validate and write the seed into an artifact-server bundle over SSH, then set the hostname's ref. The same bundle and ref is a no-op. Returns the seed URL, tree hash and command lines.",
      arguments: PublishArgs,
      execute: async (args: z.input<typeof PublishArgs>, context: Ctx) => {
        const a = PublishArgs.parse(args);
        const seed = await renderValidated(a);
        const contents = bundleContents(seed);
        const dir = bundleDir(a.server.root, seed.tree_sha256);
        const url = bundleUrl(a.server.url_base, seed.tree_sha256);
        const t = toTarget(a.server.ssh);
        const { changed } = await withTransport(async () => {
          await assertLayout(deps, t, a.server.root);
          const status = await bundleStatus(deps, t, dir, contents);
          const ref = await readRef(
            deps,
            t,
            a.server.root,
            a.identity.hostname,
          );
          const refOk = ref === seed.tree_sha256;
          if (status !== "present") {
            await writeTree(deps, t, a.server.root, dir, contents);
          }
          if (!refOk) {
            await writeRef(
              deps,
              t,
              a.server.root,
              a.identity.hostname,
              seed.tree_sha256,
            );
          }
          return { changed: status !== "present" || !refOk };
        });
        const state = await context.writeResource("seed", a.identity.hostname, {
          hostname: a.identity.hostname,
          tree_sha256: seed.tree_sha256,
          seed_url: url,
          files: seed.files,
          status: "present" as const,
          observed_at: new Date().toISOString(),
        });
        context.logger.info("Seed {host} published at {url}", {
          host: a.identity.hostname,
          url,
        });
        return {
          dataHandles: [state],
          result: {
            seed_url: url,
            tree_sha256: seed.tree_sha256,
            cmdline: cmdlineFor(url),
            changed,
          },
        };
      },
    },

    unpublish: {
      kind: "action" as const,
      description:
        "DESTRUCTIVE. Remove the seed bundle named by the hostname's ref and the ref (the seed carries a password hash); remove it once the host is installed. An absent seed is a clean no-op, and a supplied tree_sha256 must match the ref or the bundle's own hostname.",
      arguments: UnpublishArgs,
      execute: async (args: z.input<typeof UnpublishArgs>, context: Ctx) => {
        const a = UnpublishArgs.parse(args);
        const t = toTarget(a.ssh);
        const outcome = await withTransport(async () => {
          const ref = await readRef(deps, t, a.root, a.hostname);
          if (
            ref !== undefined && a.tree_sha256 !== undefined &&
            a.tree_sha256 !== ref
          ) {
            throw new AutoinstallError(
              "conflict",
              "tree_sha256 does not match the hostname's ref",
            );
          }
          const tree = ref ?? a.tree_sha256;
          if (tree === undefined) return { status: "not_found" as const };
          if (ref === undefined) {
            // No ref: only a bundle that exists and records this hostname may
            // be deleted, so a guessed tree hash cannot remove another host's
            // live seed. An absent bundle is already gone, so it is a no-op.
            const owner = await bundleHostname(
              deps,
              t,
              bundleDir(a.root, tree),
            );
            if (owner === null) return { status: "not_found" as const };
            if (owner !== a.hostname) {
              throw new AutoinstallError(
                "conflict",
                "the bundle does not record this hostname",
              );
            }
          }
          await removeTree(deps, t, a.root, tree, a.hostname);
          return { status: "deleted" as const, tree_sha256: tree };
        });
        const handle = await context.writeResource("seed", a.hostname, {
          hostname: a.hostname,
          ...(outcome.status === "deleted"
            ? { tree_sha256: outcome.tree_sha256 }
            : {}),
          files: [],
          status: "not_found" as const,
          observed_at: new Date().toISOString(),
        });
        context.logger.info("Seed {host} {status}", {
          host: a.hostname,
          status: outcome.status,
        });
        return { dataHandles: [handle], result: outcome };
      },
    },

    get: {
      description:
        "READ-ONLY. Render the inputs, then check the published bundle (presence and per-file SHA-256) and persist the observation as the seed resource.",
      arguments: PublishArgs,
      execute: async (args: z.input<typeof PublishArgs>, context: Ctx) => {
        const { handle, state } = await observePublished(
          context,
          PublishArgs.parse(args),
        );
        return { dataHandles: [handle], result: state };
      },
    },

    sync: {
      description:
        "READ-ONLY. Reconcile the recorded seed with the server; an absent bundle is recorded as not_found and a partial one as mismatch, never as an error.",
      arguments: PublishArgs,
      execute: async (args: z.input<typeof PublishArgs>, context: Ctx) => {
        const a = PublishArgs.parse(args);
        const { handle, state } = await observePublished(context, a);
        context.logger.info("Seed {host} status {status}", {
          host: a.identity.hostname,
          status: state.status,
        });
        return { dataHandles: [handle], result: state };
      },
    },
  },
};
