/**
 * The host-side fetch: download one pinned https object to a hidden temp file,
 * verify the host-reported hash against the pin, and only then move it in.
 *
 * @module
 */

import {
  posixQuote,
  sha256Hex,
  type SshDeps,
  SshError,
  type SshTarget,
} from "./ssh.ts";
import { runScript } from "./remote.ts";
import type { FetchArgsType } from "./schema.ts";

/** A fresh, unguessable temp-file suffix. */
export async function newTempToken(deps: SshDeps): Promise<string> {
  const digest = await sha256Hex(
    `${deps.now()}-${crypto.getRandomValues(new Uint32Array(4)).join("")}`,
  );
  return digest.slice(0, 16);
}

/** The download script: https only, bounded redirects and size, prints the hash. */
export function fetchScript(
  args: { url: string; max_bytes: number },
  temp: string,
): string {
  return [
    `set -e`,
    `curl -fsS -L --max-redirs 5 --max-filesize ${args.max_bytes} --proto '=https' --proto-redir '=https' -o ${
      posixQuote(temp)
    } ${posixQuote(args.url)}`,
    `s=$(stat -c %s ${posixQuote(temp)} 2>/dev/null || echo 0)`,
    `[ "$s" -le ${args.max_bytes} ] || { echo "too large" >&2; exit 4; }`,
    `{ sha256sum ${posixQuote(temp)} 2>/dev/null || shasum -a 256 ${
      posixQuote(temp)
    } 2>/dev/null; } | awk '{print $1}'`,
  ].join("\n");
}

/** Removes a partial download; a failed cleanup must not mask the real error. */
async function discard(
  deps: SshDeps,
  target: SshTarget,
  temp: string,
): Promise<void> {
  await runScript(deps, target, `rm -f ${posixQuote(temp)}`).catch(
    () => undefined,
  );
}

/**
 * Downloads `args.url` to `temp`, refuses a hash or size mismatch, and renames
 * it into `dest` only after the host's own SHA-256 matches the pin.
 */
export async function downloadPinned(
  deps: SshDeps,
  target: SshTarget,
  args: FetchArgsType,
  temp: string,
  dest: string,
): Promise<void> {
  const download = await runScript(deps, target, fetchScript(args, temp));
  if (download.exit_code !== 0) {
    await discard(deps, target, temp);
    throw new SshError("the upstream download failed; no object stored");
  }
  const actual = download.stdout.trim().split(/\s+/)[0] ?? "";
  if (actual !== args.sha256) {
    await discard(deps, target, temp);
    throw new SshError(
      `downloaded content hash ${actual} does not match the pinned ${args.sha256}; temp removed`,
    );
  }
  const destDir = dest.slice(0, dest.lastIndexOf("/"));
  const move = await runScript(
    deps,
    target,
    `mkdir -p ${posixQuote(destDir)} && mv -T ${posixQuote(temp)} ${
      posixQuote(dest)
    }`,
  );
  if (move.exit_code !== 0) {
    throw new SshError("could not move the downloaded object into place");
  }
}
