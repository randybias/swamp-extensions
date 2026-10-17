/**
 * The read-only verification pass: re-hash every object on the host and compare
 * each blob against both its path hash and the recorded `SHA256SUMS` value.
 *
 * @module
 */

import { posixQuote } from "./ssh.ts";
import { BLOB_DIR, BUNDLE_DIR } from "./layout.ts";

/** One object whose bytes do not match what was recorded. */
export interface VerifyFinding {
  /** Relative path within the served root. */
  path: string;
  /** The hash that was recorded (path or index), or the tree name. */
  expected: string;
  /** The hash actually observed. */
  actual: string;
}

/** The parsed result of the verify script. */
export interface VerifyResult {
  /** Blob paths that match. */
  ok: string[];
  /** Objects that do not match. */
  corrupt: VerifyFinding[];
  /** Every blob path the script reported. */
  seen: Set<string>;
}

/** Prints one `BLOB` or `BUNDLE` line per object with its observed hash. */
export function verifyScript(root: string): string {
  const r = posixQuote(root);
  return [
    `set -u`,
    `r=${r}`,
    `if [ -d "$r/${BLOB_DIR}" ]; then`,
    `  find "$r/${BLOB_DIR}" -type f ! -name '.*' 2>/dev/null | LC_ALL=C sort | while IFS= read -r f; do`,
    `    rel="\${f#"$r/"}"`,
    `    h=$( { sha256sum "$f" 2>/dev/null || shasum -a 256 "$f" 2>/dev/null; } | awk '{print $1}' )`,
    `    printf 'BLOB\\t%s\\t%s\\n' "$rel" "$h"`,
    `  done`,
    `fi`,
    `if [ -d "$r/${BUNDLE_DIR}" ]; then`,
    `  for d in "$r/${BUNDLE_DIR}"/*/; do`,
    `    [ -d "$d" ] || continue`,
    `    tree="\${d%/}"; tree="\${tree##*/}"`,
    `    lines=$(mktemp)`,
    `    find "$d" -type f 2>/dev/null | LC_ALL=C sort | while IFS= read -r f; do`,
    `      sha256sum "$f" 2>/dev/null | awk -v n="\${f##*/}" '{print $1"  "n}'`,
    `    done > "$lines"`,
    `    h=$(sha256sum "$lines" 2>/dev/null | awk '{print $1}')`,
    `    rm -f "$lines"`,
    `    printf 'BUNDLE\\t%s\\t%s\\n' "$tree" "$h"`,
    `  done`,
    `fi`,
  ].join("\n");
}

/**
 * Parses the script output. A blob is corrupt when the bytes hash to something
 * other than the hash in its path, or when the recorded `SHA256SUMS` value for
 * that path differs from the path hash. A bundle is corrupt when its recomputed
 * tree hash differs from its directory name.
 */
export function parseVerifyOutput(
  stdout: string,
  recorded: Map<string, string>,
): VerifyResult {
  const ok: string[] = [];
  const corrupt: VerifyFinding[] = [];
  const seen = new Set<string>();
  for (const line of stdout.split("\n")) {
    const [kind, rel, actual] = line.split("\t");
    if (!kind || !rel || !actual) continue;
    if (kind === "BLOB") {
      seen.add(rel);
      const pathHash = rel.split("/")[1] ?? "";
      const sumsHash = recorded.get(rel);
      if (
        actual !== pathHash || (sumsHash !== undefined && sumsHash !== pathHash)
      ) {
        corrupt.push({ path: rel, expected: sumsHash ?? pathHash, actual });
      } else {
        ok.push(rel);
      }
    } else if (kind === "BUNDLE") {
      const path = `${BUNDLE_DIR}/${rel}`;
      if (actual === rel) ok.push(path);
      else corrupt.push({ path, expected: rel, actual });
    }
  }
  return { ok, corrupt, seen };
}
