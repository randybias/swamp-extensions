/**
 * The read-only verification pass: re-hash every object on the host and compare
 * each blob against both its path hash and the recorded `SHA256SUMS` value.
 *
 * @module
 */

import { posixQuote } from "./ssh.ts";
import { hashCmd } from "./remote.ts";
import {
  BLOB_DIR,
  BLOB_REL_ERE,
  BUNDLE_DIR,
  BUNDLE_NAME_ERE,
  FILENAME_ERE,
} from "./layout.ts";

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
    `blobEre=${posixQuote(BLOB_REL_ERE)}`,
    `treeEre=${posixQuote(BUNDLE_NAME_ERE)}`,
    `nameEre=${posixQuote("^" + FILENAME_ERE + "$")}`,
    `if [ -d "$r/${BLOB_DIR}" ]; then`,
    `  for d in "$r/${BLOB_DIR}"/*/; do`,
    `    [ -d "$d" ] || continue`,
    `    for f in "$d"*; do`,
    `      [ -f "$f" ] || continue`,
    `      rel="\${f#"$r/"}"`,
    `      printf '%s' "$rel" | grep -Eq "$blobEre" || continue`,
    `      h=$(${hashCmd('"$f"')})`,
    `      printf 'BLOB\\t%s\\t%s\\n' "$rel" "$h"`,
    `    done`,
    `  done`,
    `fi`,
    `if [ -d "$r/${BUNDLE_DIR}" ]; then`,
    `  for d in "$r/${BUNDLE_DIR}"/*/; do`,
    `    [ -d "$d" ] || continue`,
    `    tree="\${d%/}"; tree="\${tree##*/}"`,
    `    printf '%s' "$tree" | grep -Eq "$treeEre" || continue`,
    `    lines=$(mktemp)`,
    `    for f in "$d"*; do`,
    `      [ -f "$f" ] || continue`,
    `      n="\${f##*/}"`,
    `      printf '%s' "$n" | grep -Eq "$nameEre" || continue`,
    `      h=$(${hashCmd('"$f"')})`,
    `      printf '%s  %s\\n' "$h" "$n"`,
    `    done > "$lines"`,
    `    h=$(${hashCmd('"$lines"')})`,
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
