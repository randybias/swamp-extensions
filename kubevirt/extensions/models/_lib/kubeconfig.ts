/**
 * Kubeconfig inspection for the Secret model.
 *
 * kubectl honors a kubeconfig's `users[].user.exec` and dynamic
 * `auth-provider` credential plugins by running them as local commands. A
 * kubeconfig supplied by a caller, vault or CEL expression is therefore
 * inspected before it reaches kubectl: this module parses it and rejects any
 * credential plugin that would execute a local command. Parsing uses the
 * `yaml` package with a strict `maxAliasCount`, so alias-expansion ("billion
 * laughs") input is refused instead of expanded.
 *
 * Inspection happens twice. First the caller's text is parsed here, and any
 * YAML merge key (`<<`) or merge tag is refused, because the `yaml` package
 * (YAML 1.2) reads `<<` as a plain key while kubectl's own loader applies the
 * merge, so a merge could hide a credential plugin from this parser. Then,
 * before kubectl runs anything, `kubectl config view --raw -o json` produces
 * the canonical document exactly as kubectl will see it, and that document is
 * validated with default-deny at every level and is the only thing written to
 * the kubeconfig file kubectl uses afterwards.
 *
 * @module
 */

import { parse } from "npm:yaml@2.9.1";

/** Maximum YAML aliases accepted before the parser refuses the document. */
export const MAX_ALIASES = 100;

/** A resolved kubeconfig: its contexts, their clusters, and cluster servers. */
export interface KubeconfigFacts {
  /** `current-context`, when present. */
  currentContext?: string;
  /** Context name to the cluster name it selects. */
  contexts: { name: string; cluster: string }[];
  /** Cluster name to its API server URL. */
  clusters: { name: string; server: string }[];
}

/** Outcome of inspecting a kubeconfig before it is used. */
export type KubeconfigCheck =
  | { ok: true; facts: KubeconfigFacts }
  | { ok: false; reason: string };

function asRecord(v: unknown): Record<string, unknown> | undefined {
  return v && typeof v === "object" && !Array.isArray(v)
    ? v as Record<string, unknown>
    : undefined;
}

function str(v: unknown): string | undefined {
  return typeof v === "string" ? v : undefined;
}

const EXEC_REASON =
  "kubeconfig uses exec credentials, which run a local command; not allowed";
const AUTH_PROVIDER_REASON =
  "kubeconfig uses an auth-provider credential plugin, which can run a local command; not allowed";
const UNSUPPORTED_USER_REASON =
  "kubeconfig uses a user field that names a local file or is not a supported static credential; not allowed";
const UNSUPPORTED_CLUSTER_REASON =
  "kubeconfig uses a cluster field that names a local file or is not supported; not allowed";

/** User fields with a named reason, checked before the allowlist. */
const USER_PATH_REASONS: Record<string, string> = {
  tokenFile:
    "kubeconfig uses a tokenFile credential, which reads a local file; not allowed",
  "client-certificate":
    "kubeconfig uses a client-certificate file, which reads a local file; not allowed",
  "client-key":
    "kubeconfig uses a client-key file, which reads a local file; not allowed",
};

/** Cluster fields with a named reason, checked before the allowlist. */
const CLUSTER_PATH_REASONS: Record<string, string> = {
  "certificate-authority":
    "kubeconfig uses a certificate-authority file, which reads a local file; not allowed",
};

/** The only user fields accepted: embedded credentials, never a file path. */
const USER_KEYS = new Set([
  "client-certificate-data",
  "client-key-data",
  "token",
  "username",
  "password",
]);

/** The only cluster fields accepted; a CA file path is not one of them. */
const CLUSTER_KEYS = new Set([
  "server",
  "certificate-authority-data",
  "insecure-skip-tls-verify",
  "tls-server-name",
  "proxy-url",
  "disable-compression",
]);

const TOP_KEYS = new Set([
  "apiVersion",
  "kind",
  "clusters",
  "users",
  "contexts",
  "current-context",
  "preferences",
  "extensions",
]);
const CONTEXT_KEYS = new Set(["cluster", "user", "namespace"]);
const PREFERENCE_KEYS = new Set(["colors"]);
const MALFORMED_REASON = "kubeconfig has a key or shape that is not supported";
const MERGE_REASON =
  "kubeconfig uses a YAML merge key or tag, which is not allowed";

/** True for a scalar a static kubeconfig field may hold. */
function isScalar(v: unknown): boolean {
  return typeof v === "string" || typeof v === "boolean" ||
    typeof v === "number";
}

/** True when any object key at any depth is the YAML merge key. */
function hasMergeKey(v: unknown, depth = 0): boolean {
  if (depth > 64) return true;
  if (Array.isArray(v)) return v.some((x) => hasMergeKey(x, depth + 1));
  if (v && typeof v === "object") {
    for (const [k, x] of Object.entries(v)) {
      if (k === "<<" || hasMergeKey(x, depth + 1)) return true;
    }
  }
  return false;
}

/** True for an `extensions` value that carries nothing. */
function emptyExtensions(v: unknown): boolean {
  return v === undefined || v === null ||
    (Array.isArray(v) && v.length === 0);
}

function entries(
  root: Record<string, unknown>,
  list: string,
  inner: string,
): Record<string, unknown>[] | string {
  const raw = root[list];
  if (raw === undefined || raw === null) return [];
  if (!Array.isArray(raw)) return MALFORMED_REASON;
  const out: Record<string, unknown>[] = [];
  for (const item of raw) {
    const e = asRecord(item);
    if (!e) return MALFORMED_REASON;
    for (const key of Object.keys(e)) {
      if (key !== "name" && key !== inner) return MALFORMED_REASON;
    }
    if (typeof e.name !== "string" || e.name === "") return MALFORMED_REASON;
    out.push(e);
  }
  return out;
}

/**
 * Validates a parsed kubeconfig with default-deny at every level: top-level
 * keys, the keys of each entry, and the fields of every user, cluster and
 * context. Returns its facts when it is safe, or a fixed reason; no kubeconfig
 * content is ever echoed.
 */
export function validateKubeconfig(doc: unknown): KubeconfigCheck {
  const root = asRecord(doc);
  if (!root) return { ok: false, reason: "kubeconfig is not a YAML mapping" };
  if (hasMergeKey(root)) return { ok: false, reason: MERGE_REASON };
  for (const key of Object.keys(root)) {
    if (!TOP_KEYS.has(key)) return { ok: false, reason: MALFORMED_REASON };
  }
  if (root.apiVersion !== undefined && root.apiVersion !== "v1") {
    return { ok: false, reason: MALFORMED_REASON };
  }
  if (root.kind !== undefined && root.kind !== "Config") {
    return { ok: false, reason: MALFORMED_REASON };
  }
  if (
    root["current-context"] !== undefined && !isScalar(root["current-context"])
  ) {
    return { ok: false, reason: MALFORMED_REASON };
  }
  if (!emptyExtensions(root.extensions)) {
    return { ok: false, reason: MALFORMED_REASON };
  }
  if (root.preferences !== undefined && root.preferences !== null) {
    const prefs = asRecord(root.preferences);
    if (!prefs) return { ok: false, reason: MALFORMED_REASON };
    for (const key of Object.keys(prefs)) {
      if (key === "extensions" && emptyExtensions(prefs[key])) continue;
      if (!PREFERENCE_KEYS.has(key)) {
        return { ok: false, reason: MALFORMED_REASON };
      }
    }
  }

  const users = entries(root, "users", "user");
  const clusters = entries(root, "clusters", "cluster");
  const contexts = entries(root, "contexts", "context");
  for (const list of [users, clusters, contexts]) {
    if (typeof list === "string") return { ok: false, reason: list };
  }

  for (const entry of users as Record<string, unknown>[]) {
    if (entry.user === undefined || entry.user === null) continue;
    const user = asRecord(entry.user);
    if (!user) return { ok: false, reason: MALFORMED_REASON };
    if (user.exec !== undefined) return { ok: false, reason: EXEC_REASON };
    if (user["auth-provider"] !== undefined) {
      return { ok: false, reason: AUTH_PROVIDER_REASON };
    }
    for (const [key, value] of Object.entries(user)) {
      const named = USER_PATH_REASONS[key];
      if (named) return { ok: false, reason: named };
      if (!USER_KEYS.has(key) || !isScalar(value)) {
        return { ok: false, reason: UNSUPPORTED_USER_REASON };
      }
    }
  }

  for (const entry of clusters as Record<string, unknown>[]) {
    if (entry.cluster === undefined || entry.cluster === null) continue;
    const cluster = asRecord(entry.cluster);
    if (!cluster) return { ok: false, reason: MALFORMED_REASON };
    for (const [key, value] of Object.entries(cluster)) {
      const named = CLUSTER_PATH_REASONS[key];
      if (named) return { ok: false, reason: named };
      if (!CLUSTER_KEYS.has(key) || !isScalar(value)) {
        return { ok: false, reason: UNSUPPORTED_CLUSTER_REASON };
      }
    }
  }

  for (const entry of contexts as Record<string, unknown>[]) {
    if (entry.context === undefined || entry.context === null) continue;
    const context = asRecord(entry.context);
    if (!context) return { ok: false, reason: MALFORMED_REASON };
    for (const [key, value] of Object.entries(context)) {
      if (key === "extensions" && emptyExtensions(value)) continue;
      if (!CONTEXT_KEYS.has(key) || !isScalar(value)) {
        return { ok: false, reason: MALFORMED_REASON };
      }
    }
  }

  const facts: KubeconfigFacts = {
    currentContext: str(root["current-context"]),
    contexts: [],
    clusters: [],
  };
  for (const e of contexts as Record<string, unknown>[]) {
    const cluster = str(asRecord(e.context)?.cluster);
    if (cluster) facts.contexts.push({ name: e.name as string, cluster });
  }
  for (const e of clusters as Record<string, unknown>[]) {
    const server = str(asRecord(e.cluster)?.server);
    if (server) facts.clusters.push({ name: e.name as string, server });
  }
  return { ok: true, facts };
}

/** Matches a YAML merge tag in any spelling, however the key is written. */
const MERGE_TAG =
  /!!merge\b|!<tag:yaml\.org,2002:merge>|tag:yaml\.org,2002:merge/;

/**
 * Parses and inspects the caller's kubeconfig text. Anything that looks like a
 * YAML merge is refused outright; everything else is validated with
 * {@link validateKubeconfig}. This is the early check; the authoritative one
 * runs on kubectl's own canonical view, see {@link checkCanonical}.
 */
export function checkKubeconfig(content: string): KubeconfigCheck {
  if (MERGE_TAG.test(content)) return { ok: false, reason: MERGE_REASON };
  let doc: unknown;
  try {
    doc = parse(content, { maxAliasCount: MAX_ALIASES });
  } catch {
    return { ok: false, reason: "kubeconfig is not valid YAML" };
  }
  return validateKubeconfig(doc);
}

/**
 * Validates the JSON that `kubectl config view --raw -o json` printed. That
 * is the document as kubectl itself resolves it, merges and all, so it is
 * the one that decides whether the kubeconfig is safe to use.
 */
export function checkCanonical(json: string): KubeconfigCheck {
  let doc: unknown;
  try {
    doc = JSON.parse(json);
  } catch {
    return { ok: false, reason: "kubectl did not return a kubeconfig" };
  }
  return validateKubeconfig(doc);
}

async function digestHex(s: string): Promise<string> {
  const d = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s));
  return [...new Uint8Array(d)].map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

/** Resolves the API server for a context, or the current context if omitted. */
export function resolveServer(
  facts: KubeconfigFacts,
  context?: string,
): string | undefined {
  const wanted = context ?? facts.currentContext;
  const clusterName = facts.contexts.find((c) => c.name === wanted)?.cluster;
  return clusterName
    ? facts.clusters.find((c) => c.name === clusterName)?.server
    : undefined;
}

/**
 * Nonsecret fingerprint of the API server the selected context talks to. It is
 * stable across credential rotation and distinct per cluster, so a Secret's
 * state id does not change when its token does and does not collide with a
 * different context that shares a server. Falls back to hashing the whole
 * kubeconfig when the context cannot be resolved; the raw URL is never put in
 * an id or output.
 */
export async function clusterFingerprint(
  content: string,
  context?: string,
): Promise<string> {
  const check = checkKubeconfig(content);
  const server = check.ok ? resolveServer(check.facts, context) : undefined;
  return (await digestHex(server ?? content)).slice(0, 12);
}
