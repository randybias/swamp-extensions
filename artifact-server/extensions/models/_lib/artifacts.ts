/**
 * Persisted resources for an object or a server observation: the artifact
 * writer and the reader that resolves the public URL base and the server state.
 *
 * @module
 */

import { activeDeps } from "./runtime.ts";
import { instanceKey } from "./target.ts";
import {
  ArtifactSchema,
  type RootArgs,
  ServerSchema,
  type SshBlock,
} from "./schema.ts";
import type { DataHandle, MethodContext, MethodResult } from "./types.ts";
import type { SshDeps, SshTarget } from "./ssh.ts";
import { SshError } from "./ssh.ts";
import { readLayout, readNginxState } from "./observe.ts";
import { NGINX_SITE_PATH } from "./nginx.ts";
import { blobRelPath, blobUrl, bundleRelPath, bundleUrl } from "./layout.ts";

const writeArtifact = async (
  context: MethodContext,
  args: RootArgs,
  data: {
    sha256: string;
    kind: "blob" | "bundle";
    path: string;
    url: string;
    bytes: number;
    files: number;
    ref?: string | null;
    changed: boolean;
  },
): Promise<DataHandle> =>
  await context.writeResource(
    "artifact",
    `artifact-${instanceKey(args)}-${data.sha256}`,
    ArtifactSchema.parse({
      ...data,
      ref: data.ref ?? null,
      written_at: new Date(activeDeps.now()).toISOString(),
    }),
  );

/**
 * The public URL base for a target: the `url_base` recorded by render_config or
 * install, or a plain `http://<host>` when neither has run yet.
 */
async function resolveBase(
  context: MethodContext,
  args: RootArgs,
): Promise<string> {
  const stored = await context.readResource?.(
    `config-${instanceKey(args)}`,
  ) as { url_base?: unknown } | null;
  const base = stored?.url_base;
  return typeof base === "string" && base !== ""
    ? base
    : `http://${args.ssh.host}`;
}

/** Records a stored blob and returns the method result with its public URL. */
export async function recordBlob(
  context: MethodContext,
  args: RootArgs,
  data: {
    sha256: string;
    filename: string;
    bytes: number;
    ref?: string | null;
    changed: boolean;
  },
): Promise<MethodResult> {
  const base = await resolveBase(context, args);
  const path = blobRelPath({ sha256: data.sha256, filename: data.filename });
  const url = blobUrl(base, { sha256: data.sha256, filename: data.filename });
  const handle = await writeArtifact(context, args, {
    sha256: data.sha256,
    kind: "blob",
    path,
    url,
    bytes: data.bytes,
    files: 1,
    ref: data.ref,
    changed: data.changed,
  });
  return {
    dataHandles: [handle],
    result: { sha256: data.sha256, path, url, changed: data.changed },
  };
}

/** Records a stored bundle and returns the method result with its public URL. */
export async function recordBundle(
  context: MethodContext,
  args: RootArgs,
  data: {
    tree: string;
    files: number;
    bytes: number;
    ref?: string | null;
    changed: boolean;
  },
): Promise<MethodResult> {
  const base = await resolveBase(context, args);
  const url = bundleUrl(base, data.tree);
  const handle = await writeArtifact(context, args, {
    sha256: data.tree,
    kind: "bundle",
    path: bundleRelPath(data.tree),
    url,
    bytes: data.bytes,
    files: data.files,
    ref: data.ref,
    changed: data.changed,
  });
  return { dataHandles: [handle], result: { tree_sha256: data.tree, url } };
}

/** Reads nginx and the layout and persists the `server` resource. */
export async function observeServer(
  deps: SshDeps,
  target: SshTarget,
  args: { ssh: SshBlock; root: string },
  context: MethodContext,
  options: { requireSite?: boolean } = {},
): Promise<MethodResult> {
  const nginx = await readNginxState(deps, target, NGINX_SITE_PATH);
  if (options.requireSite && nginx.configSha256 === null) {
    throw new SshError(`no artifact-server site at ${NGINX_SITE_PATH}`);
  }
  const layout = await readLayout(deps, target, args.root);
  const handle = await context.writeResource(
    "server",
    `server-${instanceKey(args)}`,
    ServerSchema.parse({
      host: args.ssh.host,
      port: args.ssh.port,
      user: args.ssh.user,
      root: args.root,
      nginx_active: nginx.active,
      config_sha256: nginx.configSha256,
      tls: nginx.tls,
      basic_auth: nginx.basicAuth,
      blobs: layout.blobs.length,
      bundles: layout.bundles.length,
      refs: layout.refs.length,
      layout_version: layout.layoutVersion,
      observed_at: new Date(deps.now()).toISOString(),
    }),
  );
  return {
    dataHandles: [handle],
    result: {
      nginx_active: nginx.active,
      config_sha256: nginx.configSha256,
      blobs: layout.blobs.length,
      bundles: layout.bundles.length,
      refs: layout.refs.length,
    },
  };
}
