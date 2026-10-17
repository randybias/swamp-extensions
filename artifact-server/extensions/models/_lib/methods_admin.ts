/**
 * Inspection and cleanup methods: list, verify, plan and prune.
 *
 * @module
 */

import type { ArtifactServerMethod, MethodContext } from "./types.ts";
import {
  parseSha256Sums,
  planPrune,
  type PruneObject,
  type PrunePlan,
} from "./layout.ts";
import { type Layout, type ObjectEntry, readLayout } from "./observe.ts";
import {
  assertNoSymlinkedHashDirs,
  regenerateSha256Sums,
  removeObjects,
} from "./ops.ts";
import { parseVerifyOutput, verifyScript } from "./verify.ts";
import { runScript } from "./remote.ts";
import { activeDeps } from "./runtime.ts";
import {
  ListArgs,
  ListingSchema,
  PlanPruneArgs,
  PruneArgs,
  PrunePlanSchema,
  VerificationSchema,
  VerifyArgs,
} from "./schema.ts";
import { sha256Hex, SshError } from "./ssh.ts";
import { instanceKey, toTarget } from "./target.ts";

/** Maps a layout read onto the prune plan for a keep list. */
async function computePlan(layout: Layout, keep: string[]): Promise<PrunePlan> {
  const toObject = (o: ObjectEntry): PruneObject => ({
    kind: o.kind,
    hash: o.hash,
    bytes: o.bytes,
    path: o.path,
  });
  return await planPrune(
    {
      refs: layout.refs.map((r) => ({
        name: r.name,
        target: { kind: r.kind, hash: r.hash },
      })),
      blobs: layout.blobs.map(toObject),
      bundles: layout.bundles.map(toObject),
      keep,
    },
    (t) => sha256Hex(t),
  );
}

/** The methods in this group. */
export const adminMethods: Record<string, ArtifactServerMethod> = {
  list: {
    description:
      "READ-ONLY. Read refs, blobs and bundles with their sizes and mtimes from the host and persist the listing. Never returns a digest of secret content.",
    arguments: ListArgs,
    execute: async (rawArgs: unknown, context: MethodContext) => {
      const args = ListArgs.parse(rawArgs);
      const target = toTarget(args.ssh);
      const layout = await readLayout(activeDeps, target, args.root);
      const handle = await context.writeResource(
        "listing",
        `listing-${instanceKey(args)}`,
        ListingSchema.parse({
          host: args.ssh.host,
          root: args.root,
          refs: layout.refs,
          blobs: layout.blobs.map((b) => ({
            sha256: b.hash,
            filename: b.name,
            bytes: b.bytes,
            mtime_ms: b.mtimeMs,
          })),
          bundles: layout.bundles.map((b) => ({
            tree_sha256: b.hash,
            bytes: b.bytes,
            mtime_ms: b.mtimeMs,
            files: 0,
          })),
          observed_at: new Date(activeDeps.now()).toISOString(),
        }),
      );
      return {
        dataHandles: [handle],
        result: {
          refs: layout.refs.length,
          blobs: layout.blobs.length,
          bundles: layout.bundles.length,
        },
      };
    },
  },
  verify: {
    description:
      "READ-ONLY. Rehash every object on the host and compare each blob against its path hash and against SHA256SUMS; reports ok, corrupt, missing and extra and never repairs.",
    arguments: VerifyArgs,
    execute: async (rawArgs: unknown, context: MethodContext) => {
      const args = VerifyArgs.parse(rawArgs);
      const target = toTarget(args.ssh);
      const layout = await readLayout(activeDeps, target, args.root);
      const raw = await runScript(activeDeps, target, verifyScript(args.root));
      if (raw.exit_code !== 0) {
        throw new SshError("verify could not read the objects");
      }
      const recorded = new Map(
        parseSha256Sums(layout.sha256sums ?? "").map((e) => [e.path, e.sha256]),
      );
      const { ok, corrupt, seen } = parseVerifyOutput(raw.stdout, recorded);
      const missing = [...recorded.keys()].filter((p) => !seen.has(p));
      const extra = [...seen].filter((p) => !recorded.has(p));
      const handle = await context.writeResource(
        "verification",
        `verification-${instanceKey(args)}`,
        VerificationSchema.parse({
          host: args.ssh.host,
          root: args.root,
          ok,
          corrupt,
          missing,
          extra,
          checked_at: new Date(activeDeps.now()).toISOString(),
        }),
      );
      return {
        dataHandles: [handle],
        result: {
          ok: ok.length,
          corrupt: corrupt.length,
          missing: missing.length,
          extra: extra.length,
        },
      };
    },
  },
  plan_prune: {
    description:
      "READ-ONLY. List objects not reachable from any ref and not in keep[], with the total bytes and a plan hash over the sorted list, and persist the plan.",
    arguments: PlanPruneArgs,
    execute: async (rawArgs: unknown, context: MethodContext) => {
      const args = PlanPruneArgs.parse(rawArgs);
      const target = toTarget(args.ssh);
      const layout = await readLayout(activeDeps, target, args.root);
      await assertNoSymlinkedHashDirs(activeDeps, target, args.root);
      const plan = await computePlan(layout, args.keep);
      const handle = await context.writeResource(
        "prune_plan",
        `prune_plan-${instanceKey(args)}`,
        PrunePlanSchema.parse({
          host: args.ssh.host,
          root: args.root,
          objects: plan.objects,
          total_bytes: plan.totalBytes,
          plan_sha256: plan.planSha256,
          created_at: new Date(activeDeps.now()).toISOString(),
        }),
      );
      return { dataHandles: [handle], result: plan };
    },
  },
  prune: {
    kind: "action",
    description:
      "DESTRUCTIVE. Delete exactly the objects of a plan whose hash matches plan_sha256; refuses when the recomputed plan differs, so a change since planning deletes nothing. Then regenerates SHA256SUMS.",
    arguments: PruneArgs,
    execute: async (rawArgs: unknown, context: MethodContext) => {
      const args = PruneArgs.parse(rawArgs);
      const target = toTarget(args.ssh);
      const layout = await readLayout(activeDeps, target, args.root);
      await assertNoSymlinkedHashDirs(activeDeps, target, args.root);
      const plan = await computePlan(layout, args.keep);
      if (plan.planSha256 !== args.plan_sha256) {
        throw new SshError(
          "the prune plan changed since planning; nothing deleted",
        );
      }
      await removeObjects(
        activeDeps,
        target,
        args.root,
        plan.objects.map((o) => o.path),
      );
      await regenerateSha256Sums(activeDeps, target, args.root);
      context.logger.warn("Pruned {count} objects ({bytes} bytes)", {
        count: plan.objects.length,
        bytes: plan.totalBytes,
      });
      return {
        result: {
          removed: plan.objects.length,
          bytes: plan.totalBytes,
          plan_sha256: plan.planSha256,
        },
      };
    },
  },
};
