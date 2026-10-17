/**
 * Mutating layout operations: atomic `SHA256SUMS` regeneration, refs and
 * object removal.
 *
 * The shell for each operation is built by an exported pure function so tests
 * can run it through a real `sh`. `SHA256SUMS` is rebuilt under `flock(1)` from
 * the blob paths present and renamed into place, so a reader never sees a
 * partial index. The recorded hash is the content address in the path, not a
 * re-read of the bytes: verification happens when bytes are written and again
 * in `verify`. No content digest is placed on a command line.
 *
 * @module
 */

import { posixQuote, type SshDeps, SshError, type SshTarget } from "./ssh.ts";
import {
  BLOB_DIR,
  BLOB_REL_ERE,
  BLOB_REL_RE,
  LOCK_FILE,
  REFS_DIR,
  SHA256SUMS_FILE,
} from "./layout.ts";
import { execSudo, probeFile, runScript } from "./remote.ts";

/** The `SHA256SUMS` rebuild script: records each blob's path hash. */
export function regenerateSumsScript(root: string): string {
  const r = posixQuote(root);
  return [
    `set -eu`,
    `r=${r}`,
    `[ -d "$r/${BLOB_DIR}" ] || mkdir -p "$r/${BLOB_DIR}"`,
    `exec 9>"$r/${LOCK_FILE}"`,
    `flock 9`,
    `tmp="$r/.${SHA256SUMS_FILE}.tmp.$$"`,
    `trap 'rm -f "$tmp"' EXIT`,
    `ere=${posixQuote(BLOB_REL_ERE)}`,
    `for d in "$r/${BLOB_DIR}"/*/; do`,
    `  [ -d "$d" ] || continue`,
    `  hex="\${d%/}"; hex="\${hex##*/}"`,
    `  for f in "$d"*; do`,
    `    [ -f "$f" ] || continue`,
    `    rel="\${f#"$r/"}"`,
    `    printf '%s' "$rel" | grep -Eq "$ere" || continue`,
    `    printf '%s  %s\\n' "$hex" "$rel"`,
    `  done`,
    `done > "$tmp"`,
    `LC_ALL=C sort -o "$tmp" "$tmp"`,
    `mv -T "$tmp" "$r/${SHA256SUMS_FILE}"`,
    `trap - EXIT`,
  ].join("\n");
}

/** The `setRef` script: writes a ref file atomically next to its siblings. */
export function setRefScript(
  root: string,
  name: string,
  kind: "blob" | "bundle",
  hash: string,
): string {
  const r = posixQuote(root);
  const refPath = posixQuote(`${root}/${REFS_DIR}/${name}`);
  return [
    `set -eu`,
    `r=${r}`,
    `mkdir -p "$r/${REFS_DIR}"`,
    `tmp="$r/${REFS_DIR}/.${name}.tmp.$$"`,
    `trap 'rm -f "$tmp"' EXIT`,
    `printf '%s  %s\\n' ${posixQuote(kind)} ${posixQuote(hash)} > "$tmp"`,
    `mv -T "$tmp" ${refPath}`,
    `trap - EXIT`,
  ].join("\n");
}

/** The `unsetRef` script. */
export function unsetRefScript(root: string, name: string): string {
  return `rm -f ${posixQuote(`${root}/${REFS_DIR}/${name}`)}`;
}

/**
 * The object removal script. It refuses a symlinked `sha256/`, `bundles/` or
 * `<hex>` directory before removing anything, so a planted link cannot redirect
 * `rm` outside the root. Each path must be a blob or bundle relative path.
 */
export function removeObjectsScript(root: string, paths: string[]): string {
  const r = posixQuote(root);
  const list = paths.map(posixQuote).join(" ");
  return [
    `set -eu`,
    `r=${r}`,
    `cd "$r"`,
    `for d in "$r/${BLOB_DIR}" "$r/bundles"; do`,
    `  [ -L "$d" ] && { echo "refusing symlinked $d" >&2; exit 3; }`,
    `done`,
    `for p in ${list}; do`,
    `  case "$p" in`,
    `    ${BLOB_DIR}/*/*) h="\${p#${BLOB_DIR}/}"; h="\${h%%/*}"; d="$r/${BLOB_DIR}/$h";;`,
    `    bundles/*) d="$r/bundles/\${p#bundles/}";;`,
    `    *) echo "unexpected path $p" >&2; exit 3;;`,
    `  esac`,
    `  [ -L "$d" ] && { echo "refusing symlinked $d" >&2; exit 3; }`,
    `done`,
    `rm -rf -- ${list}`,
  ].join("\n");
}

/** Returns whether a relative path is an accepted blob or bundle path. */
function isSafeObjectPath(path: string): boolean {
  if (/^bundles\/[0-9a-f]{64}$/.test(path)) return true;
  return BLOB_REL_RE.test(path.replace(/^sha256\//, ""));
}

/** Rebuilds `SHA256SUMS` from the blobs present, under an exclusive lock. */
export async function regenerateSha256Sums(
  deps: SshDeps,
  target: SshTarget,
  root: string,
): Promise<void> {
  const result = await runScript(deps, target, regenerateSumsScript(root));
  if (result.exit_code !== 0) {
    throw new SshError(
      `could not regenerate SHA256SUMS (exit ${result.exit_code})`,
    );
  }
}

/** Writes a ref file atomically, refusing to write through a symlink. */
export async function setRef(
  deps: SshDeps,
  target: SshTarget,
  root: string,
  name: string,
  kind: "blob" | "bundle",
  hash: string,
): Promise<void> {
  const refPath = `${root}/${REFS_DIR}/${name}`;
  const probe = await probeFile(deps, target, refPath);
  if (probe.state === "symlink") {
    throw new SshError(`${refPath} is a symlink; refusing to write through it`);
  }
  const result = await runScript(
    deps,
    target,
    setRefScript(root, name, kind, hash),
  );
  if (result.exit_code !== 0) {
    throw new SshError(`could not write ref ${name}`);
  }
}

/** Removes a ref file; an absent ref is a no-op. Returns whether it existed. */
export async function unsetRef(
  deps: SshDeps,
  target: SshTarget,
  root: string,
  name: string,
): Promise<boolean> {
  const refPath = `${root}/${REFS_DIR}/${name}`;
  const probe = await probeFile(deps, target, refPath);
  if (probe.state === "missing") return false;
  if (probe.state === "symlink") {
    throw new SshError(
      `${refPath} is a symlink; refusing to remove through it`,
    );
  }
  const result = await runScript(deps, target, unsetRefScript(root, name));
  if (result.exit_code !== 0) {
    throw new SshError(`could not remove ref ${name}`);
  }
  return true;
}

/** Removes object paths (relative to `<root>`) validated by a plan. */
export async function removeObjects(
  deps: SshDeps,
  target: SshTarget,
  root: string,
  paths: string[],
): Promise<void> {
  if (paths.length === 0) return;
  for (const path of paths) {
    if (!isSafeObjectPath(path)) {
      throw new SshError(`refusing to remove unexpected path ${path}`);
    }
  }
  const result = await runScript(
    deps,
    target,
    removeObjectsScript(root, paths),
  );
  if (result.exit_code !== 0) {
    throw new SshError("could not remove the planned objects");
  }
}

/** Removes the whole root directory, as root. */
export async function removeRoot(
  deps: SshDeps,
  target: SshTarget,
  root: string,
): Promise<void> {
  const result = await execSudo(deps, target, ["rm", "-rf", "--", root]);
  if (result.exit_code !== 0) {
    throw new SshError(`could not remove ${root}`);
  }
}
