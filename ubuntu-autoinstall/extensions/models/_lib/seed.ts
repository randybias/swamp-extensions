/**
 * Artifact-server seed-bundle layout.
 *
 * The published seed lives under `<root>/bundles/<tree-hash>/` with fixed file
 * names, exactly as `@randybias/artifact-server` documents, and a ref at
 * `<root>/refs/autoinstall-<hostname>` marks it live. A caller of the server can
 * verify every file against the bundle's `SHA256SUMS`.
 *
 * @module
 */

import type { RenderedFile } from "./render.ts";
import { sha256sumsLines } from "./render.ts";

/** Layout version this extension writes; a mismatch is refused. */
export const LAYOUT_VERSION = "1";

/** Absolute artifact-server root, e.g. `/srv/artifacts`. */
export const ROOT_RE = /^\/[A-Za-z0-9._/-]{0,255}$/;

/** True for a root path that is absolute and free of `..` segments and `//`. */
export function isRootPath(p: string): boolean {
  if (!ROOT_RE.test(p)) return false;
  if (p === "/") return false;
  if (p.includes("//")) return false;
  return !p.split("/").some((seg) => seg === ".." || seg === ".");
}

/** Directory that holds one bundle. */
export function bundleDir(root: string, tree: string): string {
  return `${root}/bundles/${tree}`;
}

/** The served, immutable bundle directory URL (always ends in `/`). */
export function bundleUrl(urlBase: string, tree: string): string {
  return `${urlBase.replace(/\/+$/, "")}/bundles/${tree}/`;
}

/** The ref file that marks a hostname's seed live. */
export function refPath(root: string, hostname: string): string {
  return `${root}/refs/autoinstall-${hostname}`;
}

/** The one-line content of a ref file. */
export function refLine(tree: string): string {
  return `bundle ${tree}\n`;
}

/** The `SHA256SUMS` text for a bundle: sorted, `"<hash>  <name>"` lines. */
export function bundleSums(files: RenderedFile[]): string {
  return sha256sumsLines(files).join("\n") + "\n";
}

/** The four file names written into a bundle, in order. */
export const BUNDLE_FILES = [
  "user-data",
  "meta-data",
  "vendor-data",
  "SHA256SUMS",
] as const;

/**
 * A seed server URL: `http(s)://` then only RFC 3986 unreserved characters plus
 * `/ : . - _ ~ %`. `$`, quotes, backslash, backtick, braces, `;`, `?`, `#` and
 * whitespace are refused, so nothing can expand or split the GRUB/Kernel line.
 */
const SEED_URL_RE = /^https?:\/\/[A-Za-z0-9._~:/%-]+$/i;

/** True for a seed URL base (no userinfo, query, fragment or shell character). */
export function isSeedUrlBase(u: string): boolean {
  if (!SEED_URL_RE.test(u)) return false;
  try {
    const x = new URL(u);
    return (x.protocol === "http:" || x.protocol === "https:") &&
      x.username === "" && x.password === "" && x.search === "" &&
      x.hash === "";
  } catch {
    return false;
  }
}

/** True for a NoCloud seed URL, which must end in `/`. */
export function isSeedUrl(u: string): boolean {
  return isSeedUrlBase(u) && u.endsWith("/");
}
