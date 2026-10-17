/**
 * Seed-bundle operations on an artifact-server root, over the canonical SSH
 * transport.
 *
 * Every remote path is built from a validated root, a hex tree hash and a
 * fixed file name, and every write goes through `upload`, so the seed bytes
 * travel on stdin and never on a command line. Existence is probed separately
 * from reading, so a permission error is a transport failure, not an absent
 * file, and a present-but-wrong file is a mismatch, not absence.
 *
 * @module
 */

import { AutoinstallError } from "./errors.ts";
import type { RenderedSeed } from "./render.ts";
import {
  BUNDLE_FILES,
  bundleDir,
  bundleSums,
  LAYOUT_VERSION,
  refLine,
  refPath,
} from "./seed.ts";
import {
  exec,
  sha256Hex,
  type SshDeps,
  SshError,
  type SshTarget,
  upload,
} from "./ssh.ts";

/** Presence of a bundle on the server. */
export type BundleStatus = "present" | "not_found" | "mismatch";

/** How one remote file compares to its expected content. */
export type FilePresence = "absent" | "match" | "wrong";

/** The four files written into a bundle, keyed by name. */
export function bundleContents(seed: RenderedSeed): Record<string, string> {
  return {
    "user-data": seed.user_data,
    "meta-data": seed.meta_data,
    "vendor-data": seed.vendor_data,
    SHA256SUMS: bundleSums(seed.files),
  };
}

/** Re-throws a transport failure as a typed error without echoing it. */
export function transportError(e: unknown): AutoinstallError {
  if (e instanceof AutoinstallError) return e;
  if (e instanceof SshError) {
    return new AutoinstallError("transport", "the SSH transport failed");
  }
  return new AutoinstallError("transport", "a remote operation failed");
}

/**
 * True when a remote path exists. `stat` is used rather than `test -e` because
 * `test -e` exits 1 both for a missing file and for an unreadable parent; the
 * stderr distinguishes them, so a permission error is a transport failure.
 */
async function remoteExists(
  deps: SshDeps,
  target: SshTarget,
  path: string,
): Promise<boolean> {
  const r = await exec(deps, target, ["stat", "-c", "%F", "--", path]);
  if (r.exit_code === 0) return true;
  if (/No such file or directory|Not a directory/i.test(r.stderr)) return false;
  throw new AutoinstallError("transport", "could not check a remote path");
}

/** Reads a remote file, or null when it does not exist. */
async function readFile(
  deps: SshDeps,
  target: SshTarget,
  path: string,
): Promise<string | null> {
  if (!(await remoteExists(deps, target, path))) return null;
  const r = await exec(deps, target, ["cat", "--", path]);
  if (r.exit_code !== 0) {
    throw new AutoinstallError("transport", "could not read a remote file");
  }
  return r.stdout;
}

/** Compares a remote file to expected content: absent, matching or wrong. */
export async function compareRemoteFile(
  deps: SshDeps,
  target: SshTarget,
  path: string,
  content: string,
): Promise<FilePresence> {
  if (!(await remoteExists(deps, target, path))) return "absent";
  const r = await exec(deps, target, ["sha256sum", "--", path]);
  if (r.exit_code !== 0) {
    throw new AutoinstallError("transport", "could not hash a remote file");
  }
  const hex = r.stdout.trim().split(/\s+/)[0];
  return hex === await sha256Hex(content) ? "match" : "wrong";
}

/** Reads `<root>/.layout-version`; a mismatched layout is refused. */
export async function assertLayout(
  deps: SshDeps,
  target: SshTarget,
  root: string,
): Promise<void> {
  const text = await readFile(deps, target, `${root}/.layout-version`);
  if (text !== null && text.trim() !== LAYOUT_VERSION) {
    throw new AutoinstallError(
      "layout",
      `the artifact-server layout version is not ${LAYOUT_VERSION}`,
    );
  }
}

/** The tree hash a hostname's ref points at, or undefined when there is none. */
export async function readRef(
  deps: SshDeps,
  target: SshTarget,
  root: string,
  hostname: string,
): Promise<string | undefined> {
  const text = await readFile(deps, target, refPath(root, hostname));
  return text === null
    ? undefined
    : /^bundle ([0-9a-f]{64})\n?$/.exec(text)?.[1];
}

/**
 * Whether a bundle is present, absent or partial. A single wrong file among
 * present ones is a mismatch; every file absent is not_found.
 */
export async function bundleStatus(
  deps: SshDeps,
  target: SshTarget,
  dir: string,
  contents: Record<string, string>,
): Promise<BundleStatus> {
  const results: FilePresence[] = [];
  for (const name of BUNDLE_FILES) {
    results.push(
      await compareRemoteFile(deps, target, `${dir}/${name}`, contents[name]),
    );
  }
  if (results.every((r) => r === "match")) return "present";
  if (results.every((r) => r === "absent")) return "not_found";
  return "mismatch";
}

/**
 * The `local-hostname` a bundle's `meta-data` records: null when the file is
 * absent, empty when it exists but does not parse.
 */
export async function bundleHostname(
  deps: SshDeps,
  target: SshTarget,
  dir: string,
): Promise<string | null> {
  const text = await readFile(deps, target, `${dir}/meta-data`);
  if (text === null) return null;
  return /^"local-hostname": "([^"]+)"$/m.exec(text)?.[1] ?? "";
}

/** Writes every bundle file, creating the bundle and refs directories. */
export async function writeTree(
  deps: SshDeps,
  target: SshTarget,
  root: string,
  dir: string,
  contents: Record<string, string>,
): Promise<void> {
  const mk = await exec(deps, target, [
    "mkdir",
    "-p",
    "--",
    dir,
    `${root}/refs`,
  ]);
  if (mk.exit_code !== 0) {
    throw new AutoinstallError(
      "transport",
      "could not create the bundle directory",
    );
  }
  for (const name of BUNDLE_FILES) {
    try {
      await upload(deps, target, {
        path: `${dir}/${name}`,
        content: contents[name],
        mode: "0644",
      });
    } catch (e) {
      throw transportError(e);
    }
  }
}

/** Points a hostname's ref at a tree. */
export async function writeRef(
  deps: SshDeps,
  target: SshTarget,
  root: string,
  hostname: string,
  tree: string,
): Promise<void> {
  try {
    await upload(deps, target, {
      path: refPath(root, hostname),
      content: refLine(tree),
      mode: "0644",
    });
  } catch (e) {
    throw transportError(e);
  }
}

/**
 * Removes a ref and then its bundle. The ref goes first: a failure between the
 * two leaves a bundle with no ref (a re-publish converges), never a live ref to
 * a missing seed.
 */
export async function removeTree(
  deps: SshDeps,
  target: SshTarget,
  root: string,
  tree: string,
  hostname: string,
): Promise<void> {
  for (const path of [refPath(root, hostname), bundleDir(root, tree)]) {
    const r = await exec(deps, target, ["rm", "-rf", "--", path]);
    if (r.exit_code !== 0) {
      throw new AutoinstallError("transport", "could not remove the seed");
    }
  }
}
