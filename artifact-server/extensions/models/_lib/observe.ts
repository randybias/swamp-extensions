/**
 * Read the artifact-server host state: the layout, the checksum index and the
 * nginx service.
 *
 * Every read is one `bash -c` script on the target, parsed on the control host.
 * Nothing here mutates.
 *
 * @module
 */

import { posixQuote, type SshDeps, SshError, type SshTarget } from "./ssh.ts";
import {
  BLOB_DIR,
  bundleRelPath,
  LAYOUT_VERSION_FILE,
  LOCK_FILE,
  REFS_DIR,
  SHA256SUMS_FILE,
} from "./layout.ts";
import { probeFile, runScript } from "./remote.ts";

/** Accepted blob relative path: `sha256/<64-hex>/<safe filename>`. */
const BLOB_REL_RE = /^([0-9a-f]{64})\/([A-Za-z0-9][A-Za-z0-9._-]{0,127})$/;
/** Accepted bundle directory name: a 64-hex tree hash. */
const BUNDLE_NAME_RE = /^[0-9a-f]{64}$/;
/** Accepted ref name. */
const REF_NAME_RE = /^[a-z0-9][a-z0-9._-]{0,63}$/;

/** One ref as stored on disk. */
export interface RefEntry {
  /** Ref name. */
  name: string;
  /** `blob` or `bundle`. */
  kind: "blob" | "bundle";
  /** Target hash. */
  hash: string;
}

/** One object found in the layout. */
export interface ObjectEntry {
  /** `blob` or `bundle`. */
  kind: "blob" | "bundle";
  /** Blob hash or bundle tree hash. */
  hash: string;
  /** File name (blob) or directory name (bundle). */
  name: string;
  /** Size in bytes. */
  bytes: number;
  /** Last-modified epoch milliseconds. */
  mtimeMs: number;
  /** Relative path within `<root>`. */
  path: string;
}

/** The full layout read. */
export interface Layout {
  /** Blobs, sorted by path. */
  blobs: ObjectEntry[];
  /** Bundle directories, sorted by path. */
  bundles: ObjectEntry[];
  /** Refs, sorted by name. */
  refs: RefEntry[];
  /** `.layout-version` content, or null when absent. */
  layoutVersion: number | null;
  /** `SHA256SUMS` text exactly as stored, or null when absent. */
  sha256sums: string | null;
}

/** Reads the layout in one round trip. */
export async function readLayout(
  deps: SshDeps,
  target: SshTarget,
  root: string,
): Promise<Layout> {
  const r = posixQuote(root);
  const script = [
    `set -u`,
    `r=${r}`,
    `echo "##VERSION"`,
    `if [ -f "$r/${LAYOUT_VERSION_FILE}" ]; then cat "$r/${LAYOUT_VERSION_FILE}"; fi`,
    `echo "##SUMS"`,
    `if [ -f "$r/${SHA256SUMS_FILE}" ]; then cat "$r/${SHA256SUMS_FILE}"; fi`,
    `echo "##REFS"`,
    `if [ -d "$r/${REFS_DIR}" ]; then`,
    `  for f in "$r/${REFS_DIR}"/*; do`,
    `    [ -f "$f" ] || continue`,
    `    printf '%s\\t%s\\n' "\${f##*/}" "$(cat "$f")"`,
    `  done`,
    `fi`,
    `echo "##BLOBS"`,
    `if [ -d "$r/${BLOB_DIR}" ]; then`,
    `  find "$r/${BLOB_DIR}" -type f -printf '%P\\t%s\\t%T@\\n' 2>/dev/null | sort`,
    `fi`,
    `echo "##BUNDLES"`,
    `if [ -d "$r/bundles" ]; then`,
    `  find "$r/bundles" -mindepth 1 -maxdepth 1 -type d -printf '%f\\t%s\\t%T@\\n' 2>/dev/null | sort`,
    `fi`,
    `echo "##END"`,
  ].join("\n");
  const result = await runScript(deps, target, script);
  if (result.exit_code !== 0) {
    throw new SshError(`could not read the layout at ${root}`);
  }
  const sections = splitSections(result.stdout);
  const refs: RefEntry[] = [];
  for (const line of sections.refs) {
    const [name, value] = line.split("\t");
    const match = (value ?? "").trim().match(
      /^(blob|bundle)\s+([0-9a-f]{64})$/,
    );
    if (name && match && REF_NAME_RE.test(name)) {
      refs.push({ name, kind: match[1] as "blob" | "bundle", hash: match[2] });
    }
  }
  const blobs: ObjectEntry[] = [];
  for (const line of sections.blobs) {
    const parts = line.split("\t");
    if (parts.length !== 3) continue;
    const [rel, size, mtime] = parts;
    const match = rel.match(BLOB_REL_RE);
    if (!match || !/^\d+$/.test(size) || !/^[0-9.]+$/.test(mtime)) continue;
    blobs.push({
      kind: "blob",
      hash: match[1],
      name: match[2],
      bytes: Number(size) || 0,
      mtimeMs: Math.round((Number(mtime) || 0) * 1000),
      path: `${BLOB_DIR}/${rel}`,
    });
  }
  const bundles: ObjectEntry[] = [];
  for (const line of sections.bundles) {
    const parts = line.split("\t");
    if (parts.length !== 3) continue;
    const [name, size, mtime] = parts;
    if (!BUNDLE_NAME_RE.test(name)) continue;
    if (!/^\d+$/.test(size) || !/^[0-9.]+$/.test(mtime)) continue;
    bundles.push({
      kind: "bundle",
      hash: name,
      name,
      bytes: Number(size) || 0,
      mtimeMs: Math.round((Number(mtime) || 0) * 1000),
      path: bundleRelPath(name),
    });
  }
  return {
    blobs,
    bundles,
    refs: refs.sort((a, b) => (a.name < b.name ? -1 : 1)),
    layoutVersion: sections.version.trim() === ""
      ? null
      : Number(sections.version.trim()),
    sha256sums: sections.sums.join("\n") === ""
      ? null
      : sections.sums.join("\n"),
  };
}

/** Splits the marker-delimited sections of the layout script. */
export function splitSections(
  stdout: string,
): {
  version: string;
  sums: string[];
  refs: string[];
  blobs: string[];
  bundles: string[];
} {
  const out = {
    version: "",
    sums: [] as string[],
    refs: [] as string[],
    blobs: [] as string[],
    bundles: [] as string[],
  };
  let current: keyof typeof out | null = null;
  for (const raw of stdout.split("\n")) {
    const line = raw.replace(/\r$/, "");
    if (line === "##VERSION") {
      current = "version";
      continue;
    }
    if (line === "##SUMS") {
      current = "sums";
      continue;
    }
    if (line === "##REFS") {
      current = "refs";
      continue;
    }
    if (line === "##BLOBS") {
      current = "blobs";
      continue;
    }
    if (line === "##BUNDLES") {
      current = "bundles";
      continue;
    }
    if (line === "##END") {
      current = null;
      continue;
    }
    if (current === null) continue;
    if (current === "version") out.version += line;
    else out[current].push(line);
  }
  return out;
}

/** Observed nginx state. */
export interface NginxState {
  /** `systemctl is-active nginx` output, trimmed. */
  active: string;
  /** SHA-256 of the loaded site file, or null when absent. */
  configSha256: string | null;
  /** Whether the site listens with TLS. */
  tls: boolean;
  /** Whether the site has basic auth. */
  basicAuth: boolean;
}

/** Reads nginx service state and the site file's hash and mode flags. */
export async function readNginxState(
  deps: SshDeps,
  target: SshTarget,
  sitePath: string,
): Promise<NginxState> {
  const r = posixQuote(sitePath);
  const script = [
    `set -u`,
    `echo "##ACTIVE"`,
    `systemctl is-active nginx 2>/dev/null || true`,
    `echo "##CFG"`,
    `if [ -f ${r} ]; then sha256sum ${r} | awk '{print $1}'; fi`,
    `echo "##TLS"`,
    `if [ -f ${r} ] && grep -q 'ssl;' ${r}; then echo yes; else echo no; fi`,
    `echo "##AUTH"`,
    `if [ -f ${r} ] && grep -q 'auth_basic ' ${r}; then echo yes; else echo no; fi`,
    `echo "##END"`,
  ].join("\n");
  const result = await runScript(deps, target, script);
  if (result.exit_code !== 0) {
    throw new SshError("could not read nginx state");
  }
  const parts: Record<string, string[]> = {
    ACTIVE: [],
    CFG: [],
    TLS: [],
    AUTH: [],
  };
  let current: string | null = null;
  for (const raw of result.stdout.split("\n")) {
    const line = raw.trim();
    const marker = line.match(/^##(\w+)$/)?.[1];
    if (marker !== undefined && marker in parts) {
      current = marker;
      continue;
    }
    if (marker === "END") {
      current = null;
      continue;
    }
    if (current !== null) parts[current].push(line);
  }
  const cfg = parts.CFG[0] ?? "";
  return {
    active: parts.ACTIVE[0] ?? "",
    configSha256: /^[0-9a-f]{64}$/.test(cfg) ? cfg : null,
    tls: parts.TLS[0] === "yes",
    basicAuth: parts.AUTH[0] === "yes",
  };
}

/** Reads a file's text over SSH. */
export async function readFileText(
  deps: SshDeps,
  target: SshTarget,
  path: string,
  sudo = false,
): Promise<string | null> {
  const probe = await probeFile(deps, target, path, sudo);
  if (probe.state !== "file") return null;
  const result = await runScript(
    deps,
    target,
    `cat ${posixQuote(path)}`,
    sudo,
  );
  return result.exit_code === 0 ? result.stdout : null;
}

/** Reads a symlink's raw target, or null when the path is not a symlink. */
export async function readLink(
  deps: SshDeps,
  target: SshTarget,
  path: string,
  sudo = false,
): Promise<string | null> {
  const result = await runScript(
    deps,
    target,
    `if [ -L ${posixQuote(path)} ]; then readlink ${posixQuote(path)}; fi`,
    sudo,
  );
  const text = result.stdout.trim();
  return result.exit_code === 0 && text !== "" ? text : null;
}

/** True when the lock file exists. */
export async function lockExists(
  deps: SshDeps,
  target: SshTarget,
  root: string,
): Promise<boolean> {
  const probe = await probeFile(deps, target, `${root}/${LOCK_FILE}`);
  return probe.state === "file";
}
