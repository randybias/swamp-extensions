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
 * @module
 */

import { parse } from "npm:yaml@2.9.1";
import { sha256Hex } from "./kubectl.ts";

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

/**
 * Parses and inspects a kubeconfig. Returns its context/cluster facts when it
 * is safe, or a fixed reason when it is malformed or uses a dynamic credential
 * plugin. No kubeconfig content is echoed in the reason.
 */
export function checkKubeconfig(content: string): KubeconfigCheck {
  let doc: unknown;
  try {
    doc = parse(content, { maxAliasCount: MAX_ALIASES });
  } catch {
    return { ok: false, reason: "kubeconfig is not valid YAML" };
  }
  const root = asRecord(doc);
  if (!root) return { ok: false, reason: "kubeconfig is not a YAML mapping" };

  for (const entry of Array.isArray(root.users) ? root.users : []) {
    const user = asRecord(asRecord(entry)?.user);
    if (!user) continue;
    if (user.exec !== undefined) return { ok: false, reason: EXEC_REASON };
    if (user["auth-provider"] !== undefined) {
      return { ok: false, reason: AUTH_PROVIDER_REASON };
    }
    for (const key of Object.keys(user)) {
      const named = USER_PATH_REASONS[key];
      if (named) return { ok: false, reason: named };
      if (!USER_KEYS.has(key)) {
        return { ok: false, reason: UNSUPPORTED_USER_REASON };
      }
    }
  }

  for (const entry of Array.isArray(root.clusters) ? root.clusters : []) {
    const cluster = asRecord(asRecord(entry)?.cluster);
    if (!cluster) continue;
    for (const key of Object.keys(cluster)) {
      const named = CLUSTER_PATH_REASONS[key];
      if (named) return { ok: false, reason: named };
      if (!CLUSTER_KEYS.has(key)) {
        return { ok: false, reason: UNSUPPORTED_CLUSTER_REASON };
      }
    }
  }

  const facts: KubeconfigFacts = {
    currentContext: str(root["current-context"]),
    contexts: [],
    clusters: [],
  };
  for (const entry of Array.isArray(root.contexts) ? root.contexts : []) {
    const e = asRecord(entry);
    const name = str(e?.name);
    const cluster = str(asRecord(e?.context)?.cluster);
    if (name && cluster) facts.contexts.push({ name, cluster });
  }
  for (const entry of Array.isArray(root.clusters) ? root.clusters : []) {
    const e = asRecord(entry);
    const name = str(e?.name);
    const server = str(asRecord(e?.cluster)?.server);
    if (name && server) facts.clusters.push({ name, server });
  }
  return { ok: true, facts };
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
  return (await sha256Hex(server ?? content)).slice(0, 12);
}
