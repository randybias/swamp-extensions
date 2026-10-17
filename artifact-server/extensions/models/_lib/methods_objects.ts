/**
 * Object methods: store, fetch, bundle and reference artifacts.
 *
 * @module
 */

import type { ArtifactServerMethod, MethodContext } from "./types.ts";
import { recordBlob, recordBundle } from "./artifacts.ts";
import { downloadPinned, newTempToken } from "./fetch.ts";
import { blobRelPath, BUNDLE_DIR, treeHash } from "./layout.ts";
import { regenerateSha256Sums, setRef, unsetRef } from "./ops.ts";
import { makeParentDir, probeFile, putUserFile, runScript } from "./remote.ts";
import { activeDeps } from "./runtime.ts";
import {
  FetchArgsSchema,
  PublishBundleArgs,
  RefArgs,
  UnrefArgs,
  UploadArgsSchema,
} from "./schema.ts";
import { posixQuote, sha256Hex, SshConfigError, SshError } from "./ssh.ts";
import { contentBytes, toTarget } from "./target.ts";

/** The methods in this group. */
export const objectMethods: Record<string, ArtifactServerMethod> = {
  upload: {
    kind: "action",
    description:
      "Idempotent. Push bytes to sha256/<hex>/<filename> over stdin and regenerate SHA256SUMS; refuses when the computed hash differs from a supplied sha256. Optionally sets a ref. Returns the hash, path, url and whether anything changed.",
    arguments: UploadArgsSchema,
    execute: async (rawArgs: unknown, context: MethodContext) => {
      const args = UploadArgsSchema.parse(rawArgs);
      const bytes = contentBytes(args);
      if (bytes.length > args.max_upload_bytes) {
        throw new SshConfigError(
          `content is ${bytes.length} bytes, over max_upload_bytes ${args.max_upload_bytes}`,
        );
      }
      const hash = await sha256Hex(bytes);
      if (args.sha256 != null && args.sha256 !== hash) {
        throw new SshConfigError(
          `computed sha256 ${hash} does not match the supplied ${args.sha256}`,
        );
      }
      const target = toTarget(args.ssh);
      const rel = blobRelPath({ sha256: hash, filename: args.filename });
      await makeParentDir(activeDeps, target, `${args.root}/${rel}`);
      const put = await putUserFile(
        activeDeps,
        target,
        `${args.root}/${rel}`,
        bytes,
        "0644",
      );
      await regenerateSha256Sums(activeDeps, target, args.root);
      if (args.ref != null) {
        await setRef(activeDeps, target, args.root, args.ref, "blob", hash);
      }
      return await recordBlob(context, args, {
        sha256: hash,
        filename: args.filename,
        bytes: bytes.length,
        ref: args.ref,
        changed: put.changed,
      });
    },
  },
  fetch: {
    kind: "action",
    description:
      "Idempotent. Download one https upstream on the host to a hidden temp file, compare the host's SHA-256 to the required pin, and only then rename it into sha256/<hex>/<filename>; a mismatch removes the temp and changes nothing. Optionally sets a ref.",
    arguments: FetchArgsSchema,
    execute: async (rawArgs: unknown, context: MethodContext) => {
      const args = FetchArgsSchema.parse(rawArgs);
      const target = toTarget(args.ssh);
      const destRel = blobRelPath({
        sha256: args.sha256,
        filename: args.filename,
      });
      const dest = `${args.root}/${destRel}`;
      const before = await probeFile(activeDeps, target, dest);
      if (before.state === "symlink") {
        throw new SshError(
          `${dest} is a symlink; refusing to write through it`,
        );
      }
      const present = before.state === "file" &&
        before.sha256 === args.sha256;
      if (!present) {
        const temp = `${args.root}/.fetch.${await newTempToken(activeDeps)}`;
        await downloadPinned(activeDeps, target, args, temp, dest);
      }
      // Always reindex: a stale or missing SHA256SUMS is repaired even when the
      // object was already present.
      await regenerateSha256Sums(activeDeps, target, args.root);
      if (args.ref != null) {
        await setRef(
          activeDeps,
          target,
          args.root,
          args.ref,
          "blob",
          args.sha256,
        );
      }
      const after = present
        ? before
        : await probeFile(activeDeps, target, dest);
      return await recordBlob(context, args, {
        sha256: args.sha256,
        filename: args.filename,
        bytes: after.size ?? 0,
        ref: args.ref,
        changed: !present,
      });
    },
  },
  publish_bundle: {
    kind: "action",
    description:
      "Idempotent. Write a set of small named files under bundles/<tree-hash>/ where the tree hash is the SHA-256 of the bundle's sorted SHA256SUMS lines, for seed directories with fixed names. Optionally sets a ref; returns the tree hash and a URL ending in /.",
    arguments: PublishBundleArgs,
    execute: async (rawArgs: unknown, context: MethodContext) => {
      const args = PublishBundleArgs.parse(rawArgs);
      const target = toTarget(args.ssh);
      const decoded = args.files.map((f) => ({
        name: f.name,
        bytes: contentBytes(f),
      }));
      const names = decoded.map((f) => f.name);
      if (new Set(names).size !== names.length) {
        throw new SshConfigError("bundle file names must be unique");
      }
      const files = [];
      for (const f of decoded) {
        files.push({ name: f.name, sha256: await sha256Hex(f.bytes) });
      }
      const tree = await treeHash(files, (t) => sha256Hex(t));
      const stage = `${args.root}/${BUNDLE_DIR}/.stage-${await newTempToken(
        activeDeps,
      )}`;
      const final = `${args.root}/${BUNDLE_DIR}/${tree}`;
      // Stage into a hidden dot-directory, which the site config denies and
      // the layout reader ignores, then publish the directory in one rename.
      for (const f of decoded) {
        await makeParentDir(activeDeps, target, `${stage}/${f.name}`);
        await putUserFile(
          activeDeps,
          target,
          `${stage}/${f.name}`,
          f.bytes,
          "0644",
        );
      }
      const finalProbe = await probeFile(activeDeps, target, final);
      if (finalProbe.state === "symlink") {
        throw new SshError(
          `${final} is a symlink; refusing to write through it`,
        );
      }
      const commit = await runScript(
        activeDeps,
        target,
        `if [ -e ${posixQuote(final)} ]; then rm -rf ${
          posixQuote(stage)
        }; else mv -T ${posixQuote(stage)} ${posixQuote(final)}; fi`,
      );
      if (commit.exit_code !== 0) {
        throw new SshError("could not publish the bundle");
      }
      if (args.ref != null) {
        await setRef(activeDeps, target, args.root, args.ref, "bundle", tree);
      }
      const total = decoded.reduce((sum, f) => sum + f.bytes.length, 0);
      return await recordBundle(context, args, {
        tree,
        files: files.length,
        bytes: total,
        ref: args.ref,
        changed: finalProbe.state === "missing",
      });
    },
  },
  ref: {
    kind: "action",
    description:
      "Idempotent. Point a named ref at a blob or bundle hash; refs make an object referenced and thus protected from prune.",
    arguments: RefArgs,
    execute: async (rawArgs: unknown, context: MethodContext) => {
      const args = RefArgs.parse(rawArgs);
      const target = toTarget(args.ssh);
      await setRef(
        activeDeps,
        target,
        args.root,
        args.ref,
        args.kind,
        args.hash,
      );
      context.logger.info("Set ref {ref} -> {hash}", {
        ref: args.ref,
        hash: args.hash,
      });
      return {
        result: { ref: args.ref, kind: args.kind, hash: args.hash },
      };
    },
  },
  unref: {
    kind: "action",
    description:
      "DESTRUCTIVE. Remove a named ref; an absent ref is a clean no-op. Removing a ref can make its object unreachable and eligible for prune.",
    arguments: UnrefArgs,
    execute: async (rawArgs: unknown, _context: MethodContext) => {
      const args = UnrefArgs.parse(rawArgs);
      const target = toTarget(args.ssh);
      const existed = await unsetRef(activeDeps, target, args.root, args.ref);
      return { result: { ref: args.ref, removed: existed } };
    },
  },
};
