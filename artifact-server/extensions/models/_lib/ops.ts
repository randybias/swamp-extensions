/**
 * Mutating layout operations: atomic `SHA256SUMS` regeneration, refs and
 * object removal.
 *
 * `SHA256SUMS` is rebuilt under `flock(1)` from the blob files actually
 * present, written to a same-directory temp file and renamed into place, so a
 * reader never sees a partial index. No content digest is ever placed on a
 * command line.
 *
 * @module
 */

import { posixQuote, type SshDeps, SshError, type SshTarget } from "./ssh.ts";
import { BLOB_DIR, LOCK_FILE, REFS_DIR, SHA256SUMS_FILE } from "./layout.ts";
import { execSudo, probeFile, runScript } from "./remote.ts";

/** Rebuilds `SHA256SUMS` from the blobs present, under an exclusive lock. */
export async function regenerateSha256Sums(
  deps: SshDeps,
  target: SshTarget,
  root: string,
): Promise<void> {
  const r = posixQuote(root);
  const script = [
    `set -e`,
    `r=${r}`,
    `[ -d "$r/${BLOB_DIR}" ] || mkdir -p "$r/${BLOB_DIR}"`,
    `exec 9>"$r/${LOCK_FILE}"`,
    `flock 9`,
    `tmp="$r/.${SHA256SUMS_FILE}.tmp.$$"`,
    `trap 'rm -f "$tmp"' EXIT`,
    `find "$r/${BLOB_DIR}" -type f 2>/dev/null | LC_ALL=C sort | while IFS= read -r f; do`,
    `  rel="\${f#"$r/"}"`,
    `  h=$( { sha256sum "$f" 2>/dev/null || shasum -a 256 "$f" 2>/dev/null; } | awk '{print $1}' )`,
    `  printf '%s  %s\\n' "$h" "$rel"`,
    `done > "$tmp"`,
    `mv -T "$tmp" "$r/${SHA256SUMS_FILE}"`,
    `trap - EXIT`,
  ].join("\n");
  const result = await runScript(deps, target, script);
  if (result.exit_code !== 0) {
    throw new SshError(
      `could not regenerate SHA256SUMS (exit ${result.exit_code})`,
    );
  }
}

/** Writes a ref file atomically. */
export async function setRef(
  deps: SshDeps,
  target: SshTarget,
  root: string,
  name: string,
  kind: "blob" | "bundle",
  hash: string,
): Promise<void> {
  const r = posixQuote(root);
  const refPath = `${root}/${REFS_DIR}/${name}`;
  const probe = await probeFile(deps, target, refPath);
  if (probe.state === "symlink") {
    throw new SshError(`${refPath} is a symlink; refusing to write through it`);
  }
  const script = [
    `set -e`,
    `r=${r}`,
    `mkdir -p "$r/${REFS_DIR}"`,
    `tmp="$r/${REFS_DIR}/.${name}.tmp.$$"`,
    `trap 'rm -f "$tmp"' EXIT`,
    `printf '%s  %s\\n' ${posixQuote(kind)} ${posixQuote(hash)} > "$tmp"`,
    `mv -T "$tmp" "$r/${REFS_DIR}/${posixQuote(name)}"`,
    `trap - EXIT`,
  ].join("\n");
  const result = await runScript(deps, target, script);
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
  const result = await runScript(
    deps,
    target,
    `rm -f ${posixQuote(refPath)}`,
  );
  if (result.exit_code !== 0) {
    throw new SshError(`could not remove ref ${name}`);
  }
  return true;
}

/** Removes object paths (relative to `<root>`) that were validated by a plan. */
export async function removeObjects(
  deps: SshDeps,
  target: SshTarget,
  root: string,
  paths: string[],
): Promise<void> {
  if (paths.length === 0) return;
  const quoted = paths.map(posixQuote).join(" ");
  const result = await runScript(
    deps,
    target,
    `cd ${posixQuote(root)} && rm -rf -- ${quoted}`,
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
