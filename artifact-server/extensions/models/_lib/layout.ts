/**
 * Pure helpers for the artifact-server on-disk layout: `SHA256SUMS` rendering,
 * bundle tree hashing, URL building and the prune plan.
 *
 * Nothing here touches a host. Every function is deterministic, so the same
 * inputs render the same bytes and the same plan hash.
 *
 * @module
 */

/** Layout version written to `<root>/.layout-version`. */
export const LAYOUT_VERSION = 1;
/** Served checksum index. */
export const SHA256SUMS_FILE = "SHA256SUMS";
/** Served immutable blob directory. */
export const BLOB_DIR = "sha256";
/** Served immutable bundle directory. */
export const BUNDLE_DIR = "bundles";
/** Control-only ref directory; never served. */
export const REFS_DIR = "refs";
/** `flock(1)` target for `SHA256SUMS` regeneration. */
export const LOCK_FILE = ".lock";
/** Layout version file. */
export const LAYOUT_VERSION_FILE = ".layout-version";

/** The one object-file-name grammar; the blob path builds on it. */
const FILENAME_SRC = "[A-Za-z0-9][A-Za-z0-9._-]{0,127}";
/** A served object file name. */
export const FILENAME_RE = new RegExp(`^${FILENAME_SRC}$`);
/** A blob path relative to `<root>`: `<64-hex>/<name>` (captures both). */
export const BLOB_REL_RE = new RegExp(`^([0-9a-f]{64})/(${FILENAME_SRC})$`);
/** A bundle directory name: a 64-hex tree hash. */
export const BUNDLE_NAME_RE = /^[0-9a-f]{64}$/;
/** A ref name. */
export const REF_NAME_RE = /^[a-z0-9][a-z0-9._-]{0,63}$/;

/** One blob: its content hash and file name. */
export interface Blob {
  /** Lowercase hex SHA-256 of the content. */
  sha256: string;
  /** File name within the hash directory. */
  filename: string;
}

/** Relative path of a blob within `<root>`. */
export function blobRelPath(blob: Blob): string {
  return `${BLOB_DIR}/${blob.sha256}/${blob.filename}`;
}

/** Relative path of a bundle directory within `<root>`. */
export function bundleRelPath(tree: string): string {
  return `${BUNDLE_DIR}/${tree}`;
}

/**
 * Renders `SHA256SUMS` in `sha256sum -c` format: one `<hex>  <path>` line per
 * blob, two spaces between hash and path, sorted by path, trailing newline.
 */
export function renderSha256Sums(blobs: Blob[]): string {
  const lines = blobs
    .map((b) => ({ sha256: b.sha256, path: blobRelPath(b) }))
    .sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
  return lines.map((l) => `${l.sha256}  ${l.path}\n`).join("");
}

/** Parses `SHA256SUMS` into hash/path pairs, ignoring blank and malformed lines. */
export function parseSha256Sums(
  text: string,
): { sha256: string; path: string }[] {
  const out: { sha256: string; path: string }[] = [];
  for (const raw of text.split("\n")) {
    const line = raw.trimEnd();
    if (line === "") continue;
    const match = line.match(/^([0-9a-fA-F]{64})\s+\*?(.+)$/);
    if (!match) continue;
    out.push({ sha256: match[1].toLowerCase(), path: match[2] });
  }
  return out;
}

/** One bundle file: its name and content hash. */
export interface BundleFile {
  /** File name within the bundle directory. */
  name: string;
  /** Lowercase hex SHA-256 of the file content. */
  sha256: string;
}

/**
 * The bundle tree hash: SHA-256 of the bundle's sorted `SHA256SUMS` lines
 * (`<sha256>  <name>`), the same rendering used for the top-level index.
 */
export async function treeHash(
  files: BundleFile[],
  hash: (data: string) => Promise<string>,
): Promise<string> {
  const text = files
    .map((f) => ({ sha256: f.sha256, name: f.name }))
    .sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0))
    .map((f) => `${f.sha256}  ${f.name}\n`)
    .join("");
  return await hash(text);
}

/** An object eligible for pruning. */
export interface PruneObject {
  /** `blob` or `bundle`. */
  kind: "blob" | "bundle";
  /** The blob hash or bundle tree hash. */
  hash: string;
  /** Size in bytes. */
  bytes: number;
  /** Relative path within `<root>`. */
  path: string;
}

/** The prune plan. */
export interface PrunePlan {
  /** Objects not reachable from a ref or `keep`, sorted by path. */
  objects: PruneObject[];
  /** Total bytes of those objects. */
  totalBytes: number;
  /** SHA-256 over the sorted object paths, one per line. */
  planSha256: string;
}

/**
 * Builds the prune plan: unreachable blobs and bundles are those whose hash is
 * neither referenced by a ref nor listed in `keep`.
 */
export async function planPrune(
  input: {
    refs: { name: string; target: { kind: "blob" | "bundle"; hash: string } }[];
    blobs: PruneObject[];
    bundles: PruneObject[];
    keep: string[];
  },
  hash: (data: string) => Promise<string>,
): Promise<PrunePlan> {
  const reachable = new Set<string>(input.keep);
  for (const ref of input.refs) reachable.add(ref.target.hash);
  const objects = [...input.blobs, ...input.bundles]
    .filter((o) => !reachable.has(o.hash))
    .sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
  const planText = objects.map((o) => o.path).join("\n");
  return {
    objects,
    totalBytes: objects.reduce((sum, o) => sum + o.bytes, 0),
    planSha256: await hash(planText),
  };
}

/** The rendered site's URL base, without a trailing slash. */
export function urlBase(
  serverName: string,
  port: number,
  scheme: "http" | "https",
): string {
  const host = serverName.includes(":") && !serverName.startsWith("[")
    ? `[${serverName}]`
    : serverName;
  const defaultPort = scheme === "https" ? 443 : 80;
  const suffix = port === defaultPort ? "" : `:${port}`;
  return `${scheme}://${host}${suffix}`;
}

/** The public URL of a blob. */
export function blobUrl(base: string, blob: Blob): string {
  return `${base}/${blobRelPath(blob)}`;
}

/** The public URL of a bundle directory; always ends in `/`. */
export function bundleUrl(base: string, tree: string): string {
  return `${base}/${bundleRelPath(tree)}/`;
}
