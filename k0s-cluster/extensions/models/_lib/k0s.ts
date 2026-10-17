/**
 * Pure k0s helpers: version and path grammars, release URL and argv assembly,
 * `k0s.yaml` rendering, and parsing of the JSON the cluster's `kubectl` emits.
 *
 * Nothing here opens a socket, spawns a process, or reads a clock, so the whole
 * module is exercised offline. The model in `k0s_cluster.ts` is a thin layer of
 * orchestration over these functions.
 *
 * @module
 */

import { type ExecResult, sha256Hex } from "./ssh.ts";

/** Absolute path the k0s binary is installed at on the remote host. */
export const K0S_BINARY_PATH = "/usr/local/bin/k0s";
/** Absolute path of the rendered cluster configuration. */
export const K0S_CONFIG_PATH = "/etc/k0s/k0s.yaml";
/** Absolute path of the join token a worker reads. */
export const K0S_WORKER_TOKEN_PATH = "/etc/k0s/worker-token";
/** Directory whose subdirectories are k0s manifest stacks. */
export const K0S_MANIFEST_DIR = "/var/lib/k0s/manifests";
/** Default release host for the k0s binary. */
export const K0S_RELEASE_BASE =
  "https://github.com/k0sproject/k0s/releases/download";

/** k0s release version, e.g. `v1.31.2+k0s.0`. */
export const K0S_VERSION_RE = /^v?\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$/;
/** A 64-character hex digest. */
export const SHA256_RE = /^[0-9a-f]{64}$/i;
/** A cluster role the host may be installed as. */
export type K0sRole = "single" | "controller" | "worker";

/** A host's CPU architecture as k0s names it in a release artifact. */
export type K0sArch = "amd64" | "arm64";

/** One Helm chart declared in `k0s.yaml`. */
export interface HelmChartInput {
  /** Chart name as k0s writes it into `chartname`, e.g. `repo/chart`. */
  chart: string;
  /** Chart repository URL. */
  repo: string;
  /** Chart version. */
  version: string;
  /** Namespace the chart is installed into. */
  namespace: string;
  /** Values passed to the chart. */
  values?: Record<string, unknown>;
}

/** One file inside a manifest stack. */
export interface ManifestFileInput {
  /** Path relative to the stack directory. */
  path: string;
  /** File text. */
  content: string;
}

/** One named manifest stack, placed under the k0s manifest directory. */
export interface ManifestStackInput {
  /** DNS-1123 label naming the stack. */
  name: string;
  /** Non-empty list of files. */
  files: ManifestFileInput[];
}

/** Everything `renderK0sConfig` needs, independent of transport. */
export interface K0sConfigInput {
  /** Cluster name written to `metadata.name`. */
  cluster_name: string;
  /** API server port. */
  api_port: number;
  /** Subject alternative names for the API server certificate. */
  api_sans: string[];
  /** Pod network CIDR. */
  pod_cidr: string;
  /** Service network CIDR. */
  service_cidr: string;
  /** Datastore backend. */
  storage_type: "etcd" | "kine";
  /** Whether anonymous telemetry is enabled. */
  telemetry_enabled: boolean;
  /** Helm extensions to declare. */
  helm: HelmChartInput[];
}

/** A fetched release artifact. */
export type BinaryFetcher = (
  url: string,
  options?: { headers?: Record<string, string> },
) => Promise<Uint8Array>;

/** Removes user info, query and fragment from a URL for safe messages. */
export function redactUrl(url: string): string {
  try {
    const parsed = new URL(url);
    const port = parsed.port === "" ? "" : `:${parsed.port}`;
    return `${parsed.protocol}//${parsed.hostname}${port}${parsed.pathname}`;
  } catch {
    return "<invalid url>";
  }
}

/** A download that never produced bytes. */
export class DownloadError extends Error {
  /** Creates a download error naming the redacted URL and nothing secret. */
  constructor(url: string, detail: string) {
    super(`could not download ${redactUrl(url)}: ${detail}`);
    this.name = "DownloadError";
  }
}

/** The downloaded binary did not match the pinned digest. */
export class ChecksumMismatchError extends Error {
  /** Creates a checksum error; both digests are public values. */
  constructor(url: string, expected: string, actual: string) {
    super(
      `k0s binary from ${
        redactUrl(url)
      } has SHA-256 ${actual}, not the pinned ${expected}; refusing to install`,
    );
    this.name = "ChecksumMismatchError";
  }
}

/** Default {@link BinaryFetcher} backed by `fetch`. */
export const defaultFetcher: BinaryFetcher = async (
  url,
  options = {},
): Promise<Uint8Array> => {
  let response: Response;
  try {
    response = await fetch(url, {
      headers: options.headers,
      redirect: "follow",
    });
  } catch (error) {
    // A fetch failure names only the error class, never a URL token.
    throw new DownloadError(url, `request failed: ${(error as Error).name}`);
  }
  if (!response.ok) {
    await response.body?.cancel();
    throw new DownloadError(url, `HTTP ${response.status}`);
  }
  return new Uint8Array(await response.arrayBuffer());
};

const MAX_JSON_DEPTH = 8;
const MAX_JSON_ENTRIES = 128;
const MAX_JSON_LENGTH = 65536;

/** True for a JSON value within the depth and entry-count caps. */
export function isBoundedJson(value: unknown, depth = 0): boolean {
  if (depth > MAX_JSON_DEPTH) return false;
  if (
    value === null || typeof value === "string" || typeof value === "number" ||
    typeof value === "boolean"
  ) {
    return true;
  }
  if (Array.isArray(value)) {
    return value.length <= MAX_JSON_ENTRIES &&
      value.every((item) => isBoundedJson(item, depth + 1));
  }
  if (isPlain(value)) {
    const entries = Object.entries(value);
    return entries.length <= MAX_JSON_ENTRIES &&
      entries.every(([key, item]) =>
        key.length <= MAX_JSON_ENTRIES && isBoundedJson(item, depth + 1)
      );
  }
  return false;
}

/** True for a JSON value within every bound, including the total size cap. */
export function isBoundedJsonValue(value: unknown): boolean {
  if (!isBoundedJson(value)) return false;
  try {
    return JSON.stringify(value).length <= MAX_JSON_LENGTH;
  } catch {
    return false;
  }
}

/** Maps `uname -m` output to the k0s release architecture. */
export function archFromUname(uname: string): K0sArch {
  const value = uname.trim().split(/\s+/)[0];
  switch (value) {
    case "x86_64":
    case "amd64":
      return "amd64";
    case "aarch64":
    case "arm64":
      return "arm64";
    default:
      throw new Error(`unsupported remote architecture: ${value}`);
  }
}

/** Returns the pinned release URL, or the caller's override. */
export function downloadUrl(
  version: string,
  arch: K0sArch,
  override?: string | null,
): string {
  if (override) return override;
  return `${K0S_RELEASE_BASE}/${version}/k0s-${version}-${arch}`;
}

/** Every k0s build must have this digest before it is uploaded. */
export async function verifyBinary(
  bytes: Uint8Array,
  expected: string,
  url: string,
): Promise<string> {
  const actual = await sha256Hex(bytes);
  if (actual.toLowerCase() !== expected.toLowerCase()) {
    throw new ChecksumMismatchError(url, expected.toLowerCase(), actual);
  }
  return actual;
}

/** `k0s install` arguments for a role. */
export function installArgs(role: K0sRole, force = false): string[] {
  const base = role === "single"
    ? ["install", "controller", "--enable-worker"]
    : role === "controller"
    ? ["install", "controller"]
    : ["install", "worker", "--token-file", K0S_WORKER_TOKEN_PATH];
  return force ? [...base, "--force"] : base;
}

/** systemd unit name for a role. */
export function serviceName(role: K0sRole): string {
  return role === "worker" ? "k0sworker" : "k0scontroller";
}

const YAML_RESERVED = new Set([
  "true",
  "false",
  "null",
  "yes",
  "no",
  "on",
  "off",
  "y",
  "n",
  "~",
]);

function isPlain(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isScalar(value: unknown): boolean {
  return value === null || ["string", "number", "boolean"].includes(
    typeof value,
  );
}

/** Quotes or leaves bare one YAML scalar. */
export function yamlScalar(value: unknown): string {
  if (value === null) return "null";
  if (typeof value === "boolean" || typeof value === "number") {
    return String(value);
  }
  const text = String(value);
  if (text === "") return '""';
  // Bare only when the text starts with a letter and is not a YAML 1.1
  // boolean or null in any case, so "123", "True" and "1e3" stay strings.
  if (
    /^[A-Za-z][A-Za-z0-9._/@-]*$/.test(text) &&
    !YAML_RESERVED.has(text.toLowerCase())
  ) {
    return text;
  }
  return JSON.stringify(text);
}

function yamlLines(value: unknown, indent: number): string[] {
  const pad = "  ".repeat(indent);
  if (isScalar(value)) return [pad + yamlScalar(value)];
  if (Array.isArray(value)) {
    if (value.length === 0) return [pad + "[]"];
    const out: string[] = [];
    for (const item of value) {
      if (isScalar(item)) {
        out.push(`${pad}- ${yamlScalar(item)}`);
      } else if (isPlain(item) && Object.keys(item).length === 0) {
        out.push(`${pad}- {}`);
      } else {
        const child = yamlLines(item, indent + 1);
        out.push(`${pad}- ${child[0].slice(pad.length + 2)}`);
        out.push(...child.slice(1));
      }
    }
    return out;
  }
  const object = value as Record<string, unknown>;
  const keys = Object.keys(object).sort();
  if (keys.length === 0) return [pad + "{}"];
  const out: string[] = [];
  for (const key of keys) {
    const child = object[key];
    if (isScalar(child)) {
      out.push(`${pad}${yamlScalar(key)}: ${yamlScalar(child)}`);
    } else if (Array.isArray(child) && child.length === 0) {
      out.push(`${pad}${yamlScalar(key)}: []`);
    } else if (isPlain(child) && Object.keys(child).length === 0) {
      out.push(`${pad}${yamlScalar(key)}: {}`);
    } else {
      out.push(`${pad}${yamlScalar(key)}:`);
      out.push(...yamlLines(child, indent + 1));
    }
  }
  return out;
}

function sortKeys(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sortKeys);
  if (isPlain(value)) {
    return Object.fromEntries(
      Object.keys(value).sort().map((k) => [k, sortKeys(value[k])]),
    );
  }
  return value;
}

/** Renders a JSON value with sorted keys and two-space indentation. */
export function stableJson(value: unknown): string {
  return JSON.stringify(sortKeys(value), null, 2);
}

/** Renders any JSON value as deterministic YAML. */
export function toYaml(value: unknown): string {
  return yamlLines(value, 0).join("\n");
}

/** Derives a DNS-1123-safe Helm repository name from its URL. */
export function repoSlug(url: string): string {
  let candidate: string;
  try {
    const parsed = new URL(url);
    candidate = `${parsed.hostname}${parsed.pathname}`;
  } catch {
    candidate = url;
  }
  const slug = candidate.toLowerCase().replace(/[^a-z0-9-]+/g, "-")
    .replace(/^-+|-+$/g, "");
  return (slug || "repo").slice(0, 53).replace(/-+$/, "");
}

/** The chart name part of a `repo/chart` reference. */
export function chartBaseName(chart: string): string {
  const parts = chart.split("/");
  return parts[parts.length - 1];
}

/**
 * Renders `k0s.yaml` deterministically from validated inputs. Manifest stacks
 * are not part of this file: k0s reads them from `/var/lib/k0s/manifests`, so
 * they ship as separate uploads.
 */
export function renderK0sConfig(input: K0sConfigInput): string {
  const lines: string[] = [];
  lines.push("apiVersion: k0s.k0sproject.io/v1beta1");
  lines.push("kind: ClusterConfig");
  lines.push("metadata:");
  lines.push(`  name: ${yamlScalar(input.cluster_name)}`);
  lines.push("spec:");
  lines.push("  api:");
  lines.push(`    port: ${input.api_port}`);
  if (input.api_sans.length > 0) {
    lines.push("    sans:");
    for (const san of input.api_sans) {
      lines.push(`      - ${yamlScalar(san)}`);
    }
  }
  lines.push("  network:");
  lines.push(`    podCIDR: ${yamlScalar(input.pod_cidr)}`);
  lines.push(`    serviceCIDR: ${yamlScalar(input.service_cidr)}`);
  lines.push("  storage:");
  lines.push(`    type: ${yamlScalar(input.storage_type)}`);
  lines.push("  telemetry:");
  lines.push(`    enabled: ${input.telemetry_enabled}`);
  if (input.helm.length > 0) {
    lines.push("  extensions:");
    lines.push("    helm:");
    const repos = new Map<string, string>();
    for (const chart of input.helm) {
      const slug = repoSlug(chart.repo);
      const existing = repos.get(slug);
      if (existing !== undefined && existing !== chart.repo) {
        throw new Error(
          `two Helm repositories map to the repository name ${slug}; use distinct repository hosts`,
        );
      }
      repos.set(slug, chart.repo);
    }
    lines.push("      repositories:");
    for (const [name, url] of [...repos.entries()].sort()) {
      lines.push(`        - name: ${yamlScalar(name)}`);
      lines.push(`          url: ${yamlScalar(url)}`);
    }
    lines.push("      charts:");
    const charts = [...input.helm].sort((a, b) =>
      a.chart.localeCompare(b.chart) || a.namespace.localeCompare(b.namespace)
    );
    for (const chart of charts) {
      lines.push(`        - name: ${yamlScalar(chartBaseName(chart.chart))}`);
      lines.push(`          chartname: ${yamlScalar(chart.chart)}`);
      lines.push(`          version: ${yamlScalar(chart.version)}`);
      lines.push(`          namespace: ${yamlScalar(chart.namespace)}`);
      if (chart.values !== undefined && Object.keys(chart.values).length > 0) {
        // JSON is YAML, and unlike a hand-built YAML it keeps every string a
        // string, so values such as "123" or "True" are not retyped.
        lines.push("          values: |");
        const values = stableJson(chart.values).split("\n");
        for (const line of values) lines.push(`            ${line}`);
      }
    }
  }
  return lines.join("\n") + "\n";
}

/** A deterministic, human-readable render of one manifest stack's layout. */
export function renderManifestStack(stack: ManifestStackInput): string {
  const files = [...stack.files].sort((a, b) => a.path.localeCompare(b.path));
  const lines = [`stack ${stack.name}`];
  for (const file of files) lines.push(`  ${file.path}`);
  return lines.join("\n") + "\n";
}

/** A node reported by `kubectl get nodes -o json`. */
export interface NodeStatus {
  /** Node name. */
  name: string;
  /** Whether the `Ready` condition is `True`. */
  ready: boolean;
}

/** A pod reported by `kubectl get pods -o json`. */
export interface PodStatus {
  /** Pod namespace. */
  namespace: string;
  /** Pod name. */
  name: string;
  /** Kubernetes phase, e.g. `Running`. */
  phase: string;
  /** Whether every container is ready. */
  ready: boolean;
}

/** A Helm release observed as a Kubernetes secret. */
export interface HelmRelease {
  /** Release name. */
  name: string;
  /** Release namespace. */
  namespace: string;
  /** Helm status label, e.g. `deployed`. */
  status: string;
}

function parseJson(text: string): Record<string, unknown> | null {
  try {
    const value = JSON.parse(text);
    return isPlain(value) ? value : null;
  } catch {
    return null;
  }
}

function jsonItems(text: string): Record<string, unknown>[] {
  const parsed = parseJson(text);
  return parsed && Array.isArray(parsed.items)
    ? parsed.items.filter(isPlain)
    : [];
}

function labelOf(
  meta: Record<string, unknown> | undefined,
  key: string,
): string {
  const labels = meta?.labels;
  if (!isPlain(labels)) return "";
  const value = labels[key];
  return typeof value === "string" ? value : "";
}

/** Parses `kubectl get nodes -o json`; returns `[]` for unusable input. */
export function parseNodes(text: string): NodeStatus[] {
  return jsonItems(text).map((item) => {
    const meta = isPlain(item.metadata) ? item.metadata : undefined;
    const status = isPlain(item.status) ? item.status : undefined;
    const conditions = Array.isArray(status?.conditions)
      ? status.conditions.filter(isPlain)
      : [];
    const ready = conditions.some((condition) =>
      condition.type === "Ready" && condition.status === "True"
    );
    return {
      name: typeof meta?.name === "string" ? meta.name : "",
      ready,
    };
  }).filter((node) => node.name !== "");
}

/** Parses `kubectl get pods -o json`; returns `[]` for unusable input. */
export function parsePods(text: string): PodStatus[] {
  return jsonItems(text).map((item) => {
    const meta = isPlain(item.metadata) ? item.metadata : undefined;
    const status = isPlain(item.status) ? item.status : undefined;
    const conditions = Array.isArray(status?.conditions)
      ? status.conditions.filter(isPlain)
      : [];
    const ready = conditions.some((condition) =>
      condition.type === "Ready" && condition.status === "True"
    );
    return {
      namespace: typeof meta?.namespace === "string" ? meta.namespace : "",
      name: typeof meta?.name === "string" ? meta.name : "",
      phase: typeof status?.phase === "string" ? status.phase : "Unknown",
      ready,
    };
  }).filter((pod) => pod.name !== "");
}

/** True when every system pod is finished and at least one is running. */
export function systemPodsHealthy(pods: PodStatus[]): boolean {
  if (pods.length === 0) return false;
  return pods.every((pod) =>
    pod.phase === "Running" ? pod.ready : pod.phase === "Succeeded"
  );
}

/** Parses Helm release secrets from `kubectl get secrets -A -o json`. */
export function parseHelmReleases(text: string): HelmRelease[] {
  const releases: HelmRelease[] = [];
  for (const item of jsonItems(text)) {
    if (item.type !== "helm.sh/release.v1") continue;
    const meta = isPlain(item.metadata) ? item.metadata : undefined;
    const secretName = typeof meta?.name === "string" ? meta.name : "";
    const match = /^sh\.helm\.release\.v1\.(.+)\.v\d+$/.exec(secretName);
    if (!match) continue;
    releases.push({
      name: match[1],
      namespace: typeof meta?.namespace === "string" ? meta.namespace : "",
      status: labelOf(meta, "status") || "unknown",
    });
  }
  return releases.sort((a, b) =>
    a.namespace.localeCompare(b.namespace) || a.name.localeCompare(b.name)
  );
}

/** Extracts the first 64-hex token of a `sha256sum` line, if present. */
export function parseSha256(stdout: string): string | null {
  const match = /[0-9a-f]{64}/i.exec(stdout);
  return match ? match[0].toLowerCase() : null;
}

/** Splits `ls -1` output into non-empty names. */
export function parseNameList(stdout: string): string[] {
  return stdout.split(/\r?\n/).map((line) => line.trim()).filter((line) =>
    line !== ""
  );
}

/**
 * Extracts the API server URL from a kubeconfig without keeping the rest. User
 * info, query and fragment are dropped, so a server written as
 * `https://user:secret@host/?token=x` is never reflected.
 */
export function parseKubeconfigServer(text: string): string | null {
  const match = /^\s*server:\s*(\S+)\s*$/m.exec(text);
  if (!match) return null;
  try {
    const parsed = new URL(match[1].replace(/^["']|["']$/g, ""));
    const port = parsed.port === "" ? "" : `:${parsed.port}`;
    const path = parsed.pathname === "/" ? "" : parsed.pathname;
    return `${parsed.protocol}//${parsed.hostname}${port}${path}`;
  } catch {
    return null;
  }
}

/** Converts an arbitrary name into a safe swamp data instance name. */
export function instanceName(name: string): string {
  return name.replace(/[/\\]/g, "_").replace(/\.\./g, "_").replace(/\0/g, "");
}

/** Convenience: true when the command exited zero. */
export function ok(result: ExecResult): boolean {
  return result.exit_code === 0;
}
