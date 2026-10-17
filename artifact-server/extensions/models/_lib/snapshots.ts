/**
 * Snapshot and restore of the host files an install may touch, so a failed
 * `nginx -t` can put the host back exactly as it was.
 *
 * @module
 */

import { execSudo, probeFile, putRootFile } from "./remote.ts";
import { readFileText, readLink } from "./observe.ts";
import { LAYOUT_VERSION_FILE } from "./layout.ts";
import { type SshDeps, SshError, type SshTarget } from "./ssh.ts";

/**
 * Classifies a served root: `missing`, `ours` when it is a real directory that
 * holds a regular `.layout-version` sentinel, or `foreign` otherwise.
 */
export async function rootState(
  deps: SshDeps,
  target: SshTarget,
  root: string,
): Promise<"missing" | "ours" | "foreign"> {
  const probe = await probeFile(deps, target, root, true);
  if (probe.state === "missing") return "missing";
  if (probe.state !== "dir") return "foreign";
  const sentinel = await probeFile(
    deps,
    target,
    `${root}/${LAYOUT_VERSION_FILE}`,
    true,
  );
  return sentinel.state === "file" ? "ours" : "foreign";
}

/** One root-owned file's state before a run. */
export interface FileSnap {
  path: string;
  existed: boolean;
  content: string;
  mode: string;
  owner: string;
  group: string;
}

/** Captures a file's bytes, mode and owner so a rollback can restore it. */
export async function snapFile(
  deps: SshDeps,
  target: SshTarget,
  path: string,
): Promise<FileSnap> {
  const probe = await probeFile(deps, target, path, true);
  if (probe.state !== "file") {
    return {
      path,
      existed: false,
      content: "",
      mode: "0644",
      owner: "root",
      group: "root",
    };
  }
  const content = await readFileText(deps, target, path, true);
  if (content === null) {
    // A probe that saw a file but a read that failed must fail the run before
    // any mutation, or a rollback could replace a real file with an empty one.
    throw new SshError(
      `could not read ${path} for rollback; refusing to change the host`,
    );
  }
  return {
    path,
    existed: true,
    content,
    mode: probe.mode ?? "0644",
    owner: probe.owner ?? "root",
    group: probe.group ?? "root",
  };
}

/** Restores a file captured by {@link snapFile}, or removes it if it was absent. */
export async function restoreFile(
  deps: SshDeps,
  target: SshTarget,
  snap: FileSnap,
): Promise<void> {
  if (!snap.existed) {
    const rm = await execSudo(deps, target, ["rm", "-f", snap.path]);
    if (rm.exit_code !== 0) {
      throw new SshError(`could not remove ${snap.path} during rollback`);
    }
    return;
  }
  await putRootFile(deps, target, {
    path: snap.path,
    content: snap.content,
    mode: snap.mode,
    owner: snap.owner,
    group: snap.group,
  });
}

/** A link or file at a fixed path, before a run. */
export interface LinkSnap {
  path: string;
  state: "missing" | "symlink" | "file" | "dir";
  target: string | null;
  content: string | null;
}

/** Captures a link or file so a rollback can restore it. */
export async function snapLink(
  deps: SshDeps,
  target: SshTarget,
  path: string,
): Promise<LinkSnap> {
  const probe = await probeFile(deps, target, path, true);
  if (probe.state === "symlink") {
    return {
      path,
      state: "symlink",
      target: await readLink(deps, target, path, true),
      content: null,
    };
  }
  if (probe.state === "file") {
    const content = await readFileText(deps, target, path, true);
    if (content === null) {
      // Same rule as snapFile: a probe that saw a file but a read that failed
      // must fail before any mutation, or the rollback would delete it.
      throw new SshError(
        `could not read ${path} for rollback; refusing to change the host`,
      );
    }
    return { path, state: "file", target: null, content };
  }
  return { path, state: probe.state, target: null, content: null };
}

/** Restores a link or file captured by {@link snapLink}, or removes it. */
export async function restoreLink(
  deps: SshDeps,
  target: SshTarget,
  snap: LinkSnap,
): Promise<void> {
  if (snap.state === "symlink" && snap.target !== null) {
    const ln = await execSudo(deps, target, [
      "ln",
      "-sfn",
      snap.target,
      snap.path,
    ]);
    if (ln.exit_code !== 0) {
      throw new SshError(`could not restore link ${snap.path} during rollback`);
    }
  } else if (snap.state === "file" && snap.content !== null) {
    await putRootFile(deps, target, {
      path: snap.path,
      content: snap.content,
      mode: "0644",
      owner: "root",
      group: "root",
    });
  } else {
    const rm = await execSudo(deps, target, ["rm", "-f", snap.path]);
    if (rm.exit_code !== 0) {
      throw new SshError(`could not remove ${snap.path} during rollback`);
    }
  }
}
