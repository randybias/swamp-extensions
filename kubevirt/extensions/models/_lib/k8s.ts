/**
 * Kubernetes plumbing shared by the KubeVirt models.
 *
 * The kubeconfig never touches a command line: it is written to a private
 * temporary file for the duration of one `kubectl` call and removed in a
 * `finally`. Manifests reach `kubectl apply -f -` on stdin. Every failure is
 * mapped to a fixed, typed message, so remote `kubectl` output can never echo
 * a kubeconfig or a Secret value back out. The cluster is addressed only by
 * method arguments, so one definition serves any cluster.
 *
 * @module
 */

import { z } from "npm:zod@4.3.6";
import {
  K8sSecretError,
  type KubeconfigFiles,
  type KubectlResult,
  type KubectlRunner,
  sha256Hex,
  withKubectl,
} from "./kubectl.ts";
import { checkKubeconfig, resolveServer } from "./kubeconfig.ts";
export {
  checkCanonical,
  checkKubeconfig,
  resolveServer,
} from "./kubeconfig.ts";
export { sha256Hex } from "./kubectl.ts";
export type {
  KubeconfigFiles,
  KubectlResult,
  KubectlRunner,
} from "./kubectl.ts";

/** Why a KubeVirt call failed. */
export type KubevirtErrorCode =
  | "invalid_input"
  | "invalid_response"
  | "unreachable"
  | "unauthorized"
  | "not_found"
  | "kubectl_failed"
  | "manifest_fetch"
  | "manifest_mismatch"
  | "version_conflict"
  | "version_skew"
  | "not_ready"
  | "crd_missing"
  | "workloads_exist"
  | "unschedulable"
  | "running_field"
  | "restart_halted"
  | "uninstall_blocked";

/** A typed failure whose message carries no kubeconfig or secret value. */
export class KubevirtError extends Error {
  /** The failure class. */
  readonly code: KubevirtErrorCode;
  /** Creates a typed error. */
  constructor(code: KubevirtErrorCode, message: string) {
    super(message);
    this.name = "KubevirtError";
    this.code = code;
  }
}

/** One HTTP response, its body already read and bounded by the fetcher. */
export interface FetchResult {
  /** HTTP status code. */
  status: number;
  /** Response body (may be empty). */
  body: string;
}

/** Reads one URL; injectable so tests start no network. */
export type Fetcher = (url: string) => Promise<FetchResult>;

/** Injectable dependencies for both models. */
export interface Deps {
  /** Runs kubectl. */
  run: KubectlRunner;
  /** Handles the temporary kubeconfig file. */
  files: KubeconfigFiles;
  /** Current time. */
  now: () => Date;
  /** Reads a manifest URL. */
  fetch: Fetcher;
  /** Waits between polls. */
  sleep: (ms: number) => Promise<void>;
}

/** Largest manifest body accepted, in bytes. */
export const MAX_MANIFEST_BYTES = 8 * 1024 * 1024;

const denoFetch: Fetcher = async (url) => {
  const r = await fetch(url, { redirect: "follow" });
  const buf = new Uint8Array(await r.arrayBuffer());
  if (buf.byteLength > MAX_MANIFEST_BYTES) {
    throw new KubevirtError("manifest_fetch", "manifest is too large");
  }
  return { status: r.status, body: new TextDecoder().decode(buf) };
};

const denoFiles: KubeconfigFiles = {
  write: async (content) => {
    const path = await Deno.makeTempFile({ prefix: "kubeconfig-" });
    try {
      await Deno.chmod(path, 0o600);
      await Deno.writeTextFile(path, content);
      return path;
    } catch (e) {
      try {
        await Deno.remove(path);
      } catch {
        // The file is already gone; nothing to clean up.
      }
      throw e;
    }
  },
  async remove(path) {
    try {
      await Deno.remove(path);
    } catch (e) {
      if (!(e instanceof Deno.errors.NotFound)) throw e;
    }
  },
};

const denoRun: KubectlRunner = async (args, options) => {
  // swamp-quality-ignore deno-command
  const cmd = new Deno.Command("kubectl", {
    args,
    env: options.env,
    clearEnv: true,
    stdin: options.stdin === undefined ? "null" : "piped",
    stdout: "piped",
    stderr: "piped",
  });
  const child = cmd.spawn();
  if (options.stdin !== undefined) {
    const w = child.stdin.getWriter();
    await w.write(new TextEncoder().encode(options.stdin));
    await w.close();
  }
  const out = await child.output();
  const dec = new TextDecoder();
  return {
    code: out.code,
    stdout: dec.decode(out.stdout),
    stderr: dec.decode(out.stderr),
  };
};

/** Production dependencies. */
export function defaultDeps(): Deps {
  return {
    run: denoRun,
    files: denoFiles,
    now: () => new Date(),
    fetch: denoFetch,
    sleep: (ms) => new Promise((resolve) => setTimeout(resolve, ms)),
  };
}

let deps: Deps = defaultDeps();

/** Replaces the injected dependencies and returns the previous ones. */
export function setDeps(d: Partial<Deps>): Deps {
  const prev = deps;
  deps = { ...deps, ...d };
  return prev;
}

/** The dependencies one model call uses. */
export function currentDeps(): Deps {
  return deps;
}

/**
 * Rewraps a vendored `K8sSecretError` as a {@link KubevirtError}, so a caller
 * sees one error type. The message is already fixed and carries no remote text.
 */
export function mapSecretError(e: unknown): never {
  if (e instanceof KubevirtError) throw e;
  if (e instanceof K8sSecretError) {
    throw new KubevirtError(
      e.code === "namespace_not_found" ? "not_found" : e.code,
      e.message,
    );
  }
  throw new KubevirtError("kubectl_failed", "kubectl failed");
}

/**
 * Runs `fn` with a kubectl bound to a validated temporary kubeconfig.
 *
 * `namespace` is set on the vendored `withKubectl` target, which appends
 * `--namespace <namespace>` to every argv itself; a per-call `-n` would only
 * be overridden by that trailing flag. Open one `withCluster` per target
 * namespace (the KubeVirt namespace, the CDI namespace, or a VM's namespace).
 */
export async function withCluster<T>(
  d: Deps,
  kubeconfig: string,
  context: string | undefined,
  namespace: string,
  fn: (
    kubectl: (args: string[], stdin?: string) => Promise<KubectlResult>,
  ) => Promise<T>,
): Promise<T> {
  // An error thrown by `fn` itself (a parse or validation failure on what the
  // cluster returned) is not a kubectl process failure: it must not be
  // flattened into a fixed "kubectl failed". Only the vendored wrapper's own
  // errors are rewrapped.
  let inner: { error: unknown } | undefined;
  try {
    return await withKubectl(
      { run: d.run, files: d.files, now: d.now },
      { kubeconfig, context, namespace, name: "unused" },
      async (kubectl) => {
        try {
          return await fn(kubectl);
        } catch (e) {
          inner = { error: e };
          throw e;
        }
      },
    );
  } catch (e) {
    if (inner !== undefined && inner.error === e) throw describeInnerError(e);
    mapSecretError(e);
  }
}

/**
 * A typed, non-secret error for something thrown by a method body: a
 * {@link KubevirtError} as is; a zod validation failure as `invalid_response`
 * naming only the issue paths and codes (never the offending values); anything
 * else as its error name.
 */
function describeInnerError(e: unknown): Error {
  if (e instanceof KubevirtError) return e;
  if (e instanceof z.ZodError) {
    const issues = e.issues.slice(0, 5).map((i) =>
      `${i.path.join(".") || "(root)"}: ${i.code}`
    ).join("; ");
    return new KubevirtError(
      "invalid_response",
      `the cluster returned an object this model could not read (${issues})`,
    );
  }
  const name = e instanceof Error ? e.name : "error";
  return new KubevirtError("kubectl_failed", `unexpected ${name}`);
}

/**
 * Projects the observed conditions of a Kubernetes object to the fields this
 * model keeps. External objects carry more (`lastProbeTime`,
 * `lastTransitionTime`, ...) and are never parsed with a strict schema.
 */
export function projectConditions(
  list: unknown,
): { type?: string; status?: string; reason?: string; message?: string }[] {
  if (!Array.isArray(list)) return [];
  const str = (v: unknown) => typeof v === "string" ? v : undefined;
  return list.flatMap((c) => {
    if (c === null || typeof c !== "object") return [];
    const o = c as Record<string, unknown>;
    const out: {
      type?: string;
      status?: string;
      reason?: string;
      message?: string;
    } = {};
    for (const key of ["type", "status", "reason", "message"] as const) {
      const v = str(o[key]);
      if (v !== undefined) out[key] = v.slice(0, 2048);
    }
    return [out];
  });
}

/**
 * Maps kubectl stderr to a typed error with a fixed message. The stderr is
 * matched but never included: it can echo a manifest.
 */
export function classifyKubectl(
  stderr: string,
  resource = "resource",
): KubevirtError {
  if (/namespaces? "[^"]*" not found/i.test(stderr)) {
    return new KubevirtError("not_found", "Namespace does not exist");
  }
  if (
    /the server doesn't have a resource type|could not find the requested resource|no matches for kind/i
      .test(stderr)
  ) {
    return new KubevirtError(
      "crd_missing",
      "The cluster does not have the required KubeVirt resource type",
    );
  }
  if (/unauthorized|forbidden|must be logged in|credentials/i.test(stderr)) {
    return new KubevirtError(
      "unauthorized",
      "Not authorized to access the API server",
    );
  }
  if (
    /unable to connect|connection refused|no such host|i\/o timeout|timed out|dial tcp|tls: |context deadline|no route to host/i
      .test(stderr)
  ) {
    return new KubevirtError("unreachable", "API server unreachable");
  }
  return new KubevirtError(
    "kubectl_failed",
    `kubectl could not read ${resource}`,
  );
}

/** Runs `kubectl` and returns stdout text, throwing a typed error on failure. */
export async function kubectlText(
  kubectl: (args: string[], stdin?: string) => Promise<KubectlResult>,
  args: string[],
  stdin?: string,
): Promise<string> {
  const r = await kubectl(args, stdin);
  if (r.code !== 0) throw classifyKubectl(r.stderr);
  return r.stdout;
}

/**
 * Runs `kubectl ... -o json --ignore-not-found` and parses the body, or returns
 * null when the object is absent. The JSON body is parsed locally and never
 * surfaced in an error.
 */
export async function kubectlJson<T>(
  kubectl: (args: string[], stdin?: string) => Promise<KubectlResult>,
  args: string[],
): Promise<T | null> {
  const r = await kubectl([...args, "-o", "json", "--ignore-not-found"]);
  if (r.code !== 0) throw classifyKubectl(r.stderr);
  if (!r.stdout.trim()) return null;
  try {
    return JSON.parse(r.stdout) as T;
  } catch {
    throw new KubevirtError(
      "kubectl_failed",
      "kubectl returned invalid JSON",
    );
  }
}

/** Field-manager prefix for server-side apply. */
export const FIELD_MANAGER_PREFIX = "swamp-kubevirt";

/**
 * Stable server-side apply field manager for one model definition. Deriving it
 * from the definition name keeps two definitions that target the same cluster
 * from pruning each other's fields.
 */
export async function fieldManager(definitionName: string): Promise<string> {
  return `${FIELD_MANAGER_PREFIX}-${
    (await sha256Hex(definitionName)).slice(0, 12)
  }`;
}

/**
 * Normalizes an API server URL for fingerprinting: scheme and host are
 * lowercased and the port is kept only when it was explicit. The raw URL is
 * never put in an id or output.
 */
export function normalizeServer(server: string): string {
  try {
    const u = new URL(server);
    const scheme = u.protocol.toLowerCase();
    const host = u.hostname.toLowerCase();
    const port = u.port === "" ? "" : `:${u.port}`;
    return `${scheme}//${host}${port}`;
  } catch {
    return server.toLowerCase();
  }
}

/**
 * Nonsecret fingerprint of the API server the selected context talks to: the
 * first 16 hex of sha256 over the normalized server URL. It is stable across
 * credential rotation and distinct per cluster. Falls back to hashing the whole
 * kubeconfig when the current context cannot be resolved; the raw URL is never
 * exposed.
 */
export async function clusterFingerprint16(
  content: string,
  context?: string,
): Promise<string> {
  const check = checkKubeconfig(content);
  const server = check.ok ? resolveServer(check.facts, context) : undefined;
  const material = server === undefined ? content : normalizeServer(server);
  return (await sha256Hex(material)).slice(0, 16);
}

/**
 * State instance name for the operator record: the cluster fingerprint and the
 * fixed `kubevirt` suffix, joined by `_`. Two contexts on one server share the
 * fingerprint. swamp rejects `/` in a data name, so the spec's `fp/kubevirt`
 * form is not usable; `_` cannot appear in a hex fingerprint or in a DNS-1123
 * namespace or name, so the keys stay injective.
 */
export async function operatorStateKey(
  kubeconfig: string,
  context?: string,
): Promise<string> {
  return `${await clusterFingerprint16(kubeconfig, context)}_kubevirt`;
}

/**
 * State instance name for one VM: the cluster fingerprint, namespace and name
 * joined by `_` (swamp rejects `/`). Namespace and name are DNS-1123 labels and
 * cannot contain `_`, so the key cannot collide with another VM or with the
 * operator record (which has one part fewer).
 */
export async function vmStateKey(
  kubeconfig: string,
  context: string | undefined,
  namespace: string,
  name: string,
): Promise<string> {
  const fp = await clusterFingerprint16(kubeconfig, context);
  return `${fp}_${namespace}_${name}`;
}

/** The `kubeconfig` and `context` fields every method takes. */
export const TargetShape = {
  kubeconfig: z.string().min(1).max(262144).superRefine((value, ctx) => {
    const check = checkKubeconfig(value);
    if (!check.ok) ctx.addIssue({ code: "custom", message: check.reason });
  }).describe(
    "Kubeconfig content; only static credentials are allowed (no exec or auth-provider plugin). Wire with a vault.get(...) expression.",
  ).meta({ sensitive: true }),
  context: z.string().regex(/^[A-Za-z0-9._@:-]{1,253}$/, "invalid context name")
    .optional().describe(
      "Kubeconfig context; defaults to the current context.",
    ),
};

/** A timeout argument, bounded. */
export const timeoutField = (def: number) =>
  z.number().int().min(10).max(3600).default(def).describe(
    "Deadline in seconds for any wait.",
  );

/** A `vMAJOR.MINOR.PATCH` KubeVirt or CDI release tag. */
export const RELEASE_TAG_RE = /^v\d{1,3}\.\d{1,3}\.\d{1,3}$/;
/** A lowercase 64-hex SHA-256. */
export const SHA256_RE = /^[0-9a-f]{64}$/;
const DNS_LABEL_RE = /^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$/;
const DNS_SUBDOMAIN_RE =
  /^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?(\.[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?)*$/;
/** A KubeVirt feature-gate name. */
export const FEATURE_GATE_RE = /^[A-Z][A-Za-z0-9]{1,63}$/;
const MEMORY_RE = /^(\d{1,6})(Mi|Gi)$/;
const SIZE_RE = /^(\d{1,4})(Mi|Gi)$/;
const DIGEST_IMAGE_RE =
  /^[a-z0-9.-]+(:\d+)?(\/[a-z0-9._-]+)+@sha256:[0-9a-f]{64}$/;

/** True for a DNS-1123 label (namespace or VM name). */
export const isDnsLabel = (s: string): boolean =>
  s.length <= 63 && DNS_LABEL_RE.test(s);
/** True for a DNS-1123 subdomain (Secret or StorageClass name). */
export const isDnsSubdomain = (s: string): boolean =>
  s.length <= 253 && DNS_SUBDOMAIN_RE.test(s);
/** True for a memory quantity bounded to 64Mi..256Gi. */
export function isMemory(s: string): boolean {
  const m = MEMORY_RE.exec(s);
  if (!m) return false;
  const n = Number(m[1]);
  const mib = m[2] === "Gi" ? n * 1024 : n;
  return mib >= 64 && mib <= 256 * 1024;
}
/** True for a DataVolume size of 1Gi..9999Gi. */
export function isDataVolumeSize(s: string): boolean {
  const m = SIZE_RE.exec(s);
  if (!m) return false;
  return m[2] === "Gi" && Number(m[1]) >= 1;
}
/** True for a digest-pinned container image (a tag alone is refused). */
export const isDigestPinnedImage = (s: string): boolean =>
  DIGEST_IMAGE_RE.test(s);

/** Parses a release tag into major, minor and patch numbers. */
export function parseVersion(
  tag: string,
): { major: number; minor: number; patch: number } {
  const m = /^v(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(tag);
  if (!m) throw new KubevirtError("invalid_input", "invalid release tag");
  return { major: Number(m[1]), minor: Number(m[2]), patch: Number(m[3]) };
}

/** True when `to` is a downgrade from `from`, across major, minor or patch. */
export function isDowngrade(from: string, to: string): boolean {
  const a = parseVersion(from);
  const b = parseVersion(to);
  if (a.major !== b.major) return b.major < a.major;
  if (a.minor !== b.minor) return b.minor < a.minor;
  return b.patch < a.patch;
}

/** True when `to` skips more than one minor ahead of `from` in one major. */
export function isMinorSkip(from: string, to: string): boolean {
  const a = parseVersion(from);
  const b = parseVersion(to);
  return b.major === a.major && b.minor - a.minor > 1;
}

const DEFAULT_RELEASE_BASE = "https://github.com";

/**
 * Builds the release-asset URL for one operator manifest. `manifest_base_url`
 * overrides the GitHub host and must mirror the release-download path layout.
 */
export function manifestUrl(
  base: string | undefined,
  org: string,
  repo: string,
  tag: string,
  asset: string,
): string {
  const root = (base ?? DEFAULT_RELEASE_BASE).replace(/\/+$/, "");
  return `${root}/${org}/${repo}/releases/download/${tag}/${asset}`;
}

/**
 * Fetches a manifest and verifies its SHA-256 against `expected` before the
 * bytes can be applied. A mismatch, a non-200 status or an empty body is a
 * typed error naming only the URL.
 */
export async function fetchVerifiedManifest(
  d: Deps,
  url: string,
  expected: string,
): Promise<string> {
  let res: FetchResult;
  try {
    res = await d.fetch(url);
  } catch (e) {
    if (e instanceof KubevirtError) throw e;
    throw new KubevirtError(
      "manifest_fetch",
      `could not fetch the operator manifest from ${url}`,
    );
  }
  if (res.status !== 200) {
    throw new KubevirtError(
      "manifest_fetch",
      `could not fetch the operator manifest from ${url} (status ${res.status})`,
    );
  }
  if (res.body.trim() === "") {
    throw new KubevirtError(
      "manifest_fetch",
      `the operator manifest at ${url} is empty`,
    );
  }
  const actual = await sha256Hex(res.body);
  if (actual !== expected) {
    throw new KubevirtError(
      "manifest_mismatch",
      `the operator manifest at ${url} does not match operator_manifest_sha256`,
    );
  }
  return res.body;
}

/** One `status.conditions` entry, narrowed to the fields we read. */
export interface Condition {
  /** Condition type, e.g. Available. */
  type?: string;
  /** "True", "False" or "Unknown". */
  status?: string;
  /** Short machine reason. */
  reason?: string;
  /** Human message. */
  message?: string;
}

/** True when a condition list has `type` set to "True". */
export function conditionTrue(
  conditions: Condition[] | undefined,
  type: string,
): boolean {
  return (conditions ?? []).some((c) =>
    c.type === type && (c.status === "True" || c.status === "true")
  );
}

/** True when a condition list has `type` set to "False". */
export function conditionFalse(
  conditions: Condition[] | undefined,
  type: string,
): boolean {
  return (conditions ?? []).some((c) =>
    c.type === type && (c.status === "False" || c.status === "false")
  );
}

/** A bounded poll: probe until `done` or `timeoutMs`, then return the last value. */
export async function pollUntil<T>(
  d: Deps,
  timeoutMs: number,
  intervalMs: number,
  probe: () => Promise<T>,
  done: (v: T) => boolean,
): Promise<T> {
  const start = d.now().getTime();
  let last = await probe();
  while (!done(last)) {
    if (d.now().getTime() - start >= timeoutMs) return last;
    await d.sleep(intervalMs);
    last = await probe();
  }
  return last;
}

/** Default poll interval, in milliseconds. */
export const POLL_INTERVAL_MS = 5000;
