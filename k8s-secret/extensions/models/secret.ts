/**
 * Swamp extension model for a Kubernetes Secret written from vault values.
 *
 * Values reach kubectl only on stdin, as a manifest streamed to
 * `kubectl apply -f -`; they never appear on a command line, in a file other
 * than the private temporary kubeconfig, in stored state, or in method output.
 * No value hash is returned or stored either, because a raw sha256 of a
 * low-entropy secret can be reversed by brute force. A kubeconfig that would
 * make kubectl run a local credential command (exec or auth-provider) is
 * rejected before it is used. One definition serves any cluster: the target is
 * a method argument.
 *
 * @module
 */

import { z } from "npm:zod@4.3.6";
import {
  buildManifest,
  classify,
  defaultDeps,
  type Deps,
  FIELD_MANAGER,
  hashData,
  hashObserved,
  isContext,
  isDataKey,
  isNamespace,
  isSecretName,
  isSecretType,
  K8sSecretError,
  type ManagedFieldEntry,
  ownedDataKeys,
  sha256Hex,
  type Target,
  withKubectl,
} from "./_lib/kubectl.ts";
import { checkKubeconfig, clusterFingerprint } from "./_lib/kubeconfig.ts";

/** Maximum number of keys in one Secret. */
export const MAX_KEYS = 256;
/** Maximum combined UTF-8 size of all keys and values, in bytes. */
export const MAX_TOTAL_BYTES = 1024 * 1024;

const textEncoder = new TextEncoder();

function dataBytes(data: Record<string, string>): number {
  let n = 0;
  for (const [k, v] of Object.entries(data)) {
    n += textEncoder.encode(k).length + textEncoder.encode(v).length;
  }
  return n;
}

const TargetShape = {
  kubeconfig: z.string().min(1).max(262144).superRefine((value, ctx) => {
    const check = checkKubeconfig(value);
    if (!check.ok) ctx.addIssue({ code: "custom", message: check.reason });
  }).describe(
    "Kubeconfig content; only static credentials are allowed (no exec or auth-provider plugin). Wire with a vault.get(...) expression.",
  ).meta({ sensitive: true }),
  context: z.string().refine(isContext, "invalid context name").optional()
    .describe("Kubeconfig context; defaults to the current context."),
  namespace: z.string().refine(isNamespace, "not a DNS-1123 label").describe(
    "Namespace of the Secret.",
  ),
  name: z.string().refine(isSecretName, "not a DNS-1123 subdomain").describe(
    "Secret name.",
  ),
};

const TargetArgs = z.strictObject(TargetShape);

const ApplyArgs = z.strictObject({
  ...TargetShape,
  type: z.string().refine(isSecretType, "invalid Secret type").default(
    "Opaque",
  ).describe("Secret type, e.g. Opaque or kubernetes.io/tls."),
  data: z.record(
    z.string().refine(isDataKey, "invalid Secret key"),
    z.string().max(MAX_TOTAL_BYTES).meta({ sensitive: true }),
  ).refine((d) => Object.keys(d).length > 0, "data must not be empty").refine(
    (d) => Object.keys(d).length <= MAX_KEYS,
    `data must have at most ${MAX_KEYS} keys`,
  ).refine(
    (d) => dataBytes(d) <= MAX_TOTAL_BYTES,
    `data must be at most ${MAX_TOTAL_BYTES} UTF-8 bytes in total`,
  ).meta({ sensitive: true }).describe(
    "Secret key to value. Wire each value with a vault.get(...) expression.",
  ),
});

const GlobalArgsSchema = z.strictObject({});

const StateSchema = z.strictObject({
  context: z.string(),
  namespace: z.string(),
  name: z.string(),
  type: z.string().optional(),
  keys: z.array(z.string()),
  resource_version: z.string().optional(),
  status: z.enum(["present", "not_found", "deleted"]),
  observed_at: z.string(),
});

/** Stored state of one Secret; holds names and metadata, never values. */
export type SecretState = z.infer<typeof StateSchema>;

// deno-lint-ignore no-explicit-any
type Ctx = any;

let deps: Deps = defaultDeps();

/** Replaces the injected dependencies and returns the previous ones. */
export function setDeps(d: Partial<Deps>): Deps {
  const prev = deps;
  deps = { ...deps, ...d };
  return prev;
}

function target(a: z.infer<typeof TargetArgs>): Target {
  return {
    kubeconfig: a.kubeconfig,
    context: a.context,
    namespace: a.namespace,
    name: a.name,
  };
}

/**
 * State instance name for a Secret. Includes the context, namespace and name
 * plus a digest of the selected cluster's server and the components, so a
 * context whose name contains `/` cannot collide with one that contains `_`,
 * and the same context name in two clusters keeps separate state.
 */
export async function stateName(t: Target): Promise<string> {
  const cluster = await clusterFingerprint(t.kubeconfig, t.context);
  const readable = [t.context ?? "current-context", t.namespace, t.name]
    .join("_")
    .replace(/[^A-Za-z0-9._-]+/g, "-")
    .replace(/^[.-]+|[.-]+$/g, "")
    .slice(0, 120);
  const digest = (await sha256Hex(
    `${cluster}\0${t.context ?? ""}\0${t.namespace}\0${t.name}`,
  )).slice(0, 16);
  return `${readable === "" ? "secret" : readable}_${digest}`;
}

interface Observed {
  type: string;
  resource_version: string;
  dataB64: Record<string, string>;
  ownedKeys: string[];
}

interface SecretJson {
  type?: string;
  metadata?: {
    resourceVersion?: string;
    managedFields?: ManagedFieldEntry[];
  };
  data?: Record<string, string>;
}

async function observe(
  kubectl: (a: string[], stdin?: string) => Promise<
    { code: number; stdout: string; stderr: string }
  >,
  t: Target,
): Promise<Observed | null> {
  const r = await kubectl([
    "get",
    "secret",
    t.name,
    "--show-managed-fields",
    "-o",
    "json",
    "--ignore-not-found",
  ]);
  if (r.code !== 0) throw classify(r.stderr, t);
  if (!r.stdout.trim()) return null;
  let raw: SecretJson;
  try {
    raw = JSON.parse(r.stdout) as SecretJson;
  } catch {
    // The body holds the Secret values; never surface it in the error.
    throw new K8sSecretError("kubectl_failed", "kubectl returned invalid JSON");
  }
  return {
    type: raw.type ?? "Opaque",
    resource_version: raw.metadata?.resourceVersion ?? "",
    dataB64: raw.data ?? {},
    ownedKeys: ownedDataKeys(raw.metadata?.managedFields, FIELD_MANAGER),
  };
}

function toState(
  t: Target,
  o: Observed | null,
  status: SecretState["status"],
  now: Date,
): SecretState {
  return StateSchema.parse({
    context: t.context ?? "current-context",
    namespace: t.namespace,
    name: t.name,
    ...(o ? { type: o.type, resource_version: o.resource_version } : {}),
    keys: o ? Object.keys(o.dataB64).sort() : [],
    status,
    observed_at: now.toISOString(),
  });
}

function summary(s: SecretState) {
  return {
    name: s.name,
    namespace: s.namespace,
    type: s.type,
    keys: s.keys,
    resource_version: s.resource_version,
  };
}

/** Writes the Secret's state under its instance name; returns the handle. */
async function persistState(context: Ctx, t: Target, state: SecretState) {
  return await context.writeResource("state", await stateName(t), state);
}

/**
 * True when applying `data` would change nothing: the type matches, every
 * desired key is owned by this field manager and has the same value, and the
 * manager owns no key that is no longer desired. Keys owned by other tools
 * are ignored, so an externally-added key does not force a rewrite.
 */
async function unchanged(
  before: Observed,
  type: string,
  want: Record<string, string>,
  desiredKeys: string[],
): Promise<boolean> {
  if (before.type !== type) return false;
  const owned = new Set(before.ownedKeys);
  if (owned.size !== desiredKeys.length) return false;
  const have = await hashObserved(before.dataB64);
  for (const k of desiredKeys) {
    if (!owned.has(k) || have[k] !== want[k]) return false;
  }
  return true;
}

/** Model definition for `@randybias/k8s-secret`. */
export const model = {
  type: "@randybias/k8s-secret",
  version: "2026.10.17.1",
  description:
    "Write a Kubernetes Secret from vault values delivered to kubectl on stdin, and read or delete it without ever exposing the values.",
  globalArguments: GlobalArgsSchema,
  resources: {
    state: {
      description: "Secret metadata and key names; no values",
      schema: StateSchema,
      lifetime: "infinite" as const,
      garbageCollection: 10,
    },
  },
  methods: {
    apply: {
      kind: "action" as const,
      description:
        "DESTRUCTIVE. Create or update a Secret from vault values streamed to kubectl on stdin. Server-side apply prunes keys this model previously owned that are no longer given, and force-conflicts overwrites conflicting values. Idempotent when the desired keys, values and type already match. Returns key names and metadata, never values.",
      arguments: ApplyArgs,
      execute: async (args: z.input<typeof ApplyArgs>, context: Ctx) => {
        const a = ApplyArgs.parse(args);
        const t = target(a);
        const want = await hashData(a.data);
        const desiredKeys = Object.keys(want);
        const state = await withKubectl(deps, t, async (kubectl) => {
          const before = await observe(kubectl, t);
          if (before && await unchanged(before, a.type, want, desiredKeys)) {
            context.logger.info("Secret {name} unchanged", { name: t.name });
            return toState(t, before, "present", deps.now());
          }
          const r = await kubectl(
            [
              "apply",
              "--server-side",
              "--force-conflicts",
              `--field-manager=${FIELD_MANAGER}`,
              "-f",
              "-",
              "-o",
              "name",
            ],
            buildManifest(t, a.type, a.data),
          );
          if (r.code !== 0) throw classify(r.stderr, t);
          const after = await observe(kubectl, t);
          context.logger.info("Secret {name} applied", { name: t.name });
          return toState(t, after, "present", deps.now());
        });
        const handle = await persistState(context, t, state);
        return { dataHandles: [handle], result: summary(state) };
      },
    },

    get: {
      description:
        "READ-ONLY. Read the Secret's metadata and key names. Never returns the values or a value hash.",
      arguments: TargetArgs,
      execute: async (args: z.infer<typeof TargetArgs>, context: Ctx) => {
        const a = TargetArgs.parse(args);
        const t = target(a);
        const state = await withKubectl(deps, t, async (k) => {
          const o = await observe(k, t);
          if (!o) {
            throw new K8sSecretError(
              "not_found",
              `Secret ${t.namespace}/${t.name} not found`,
            );
          }
          return toState(t, o, "present", deps.now());
        });
        const handle = await persistState(context, t, state);
        return { dataHandles: [handle], result: summary(state) };
      },
    },

    sync: {
      description:
        "READ-ONLY. Refresh stored state from the cluster; a Secret that is gone is recorded as not_found instead of failing.",
      arguments: TargetArgs,
      execute: async (args: z.infer<typeof TargetArgs>, context: Ctx) => {
        const a = TargetArgs.parse(args);
        const t = target(a);
        const state = await withKubectl(deps, t, async (k) => {
          const o = await observe(k, t);
          return toState(t, o, o ? "present" : "not_found", deps.now());
        });
        context.logger.info("Secret {name} status {status}", {
          name: t.name,
          status: state.status,
        });
        const handle = await persistState(context, t, state);
        return { dataHandles: [handle], result: summary(state) };
      },
    },

    delete: {
      // A "delete" kind would tombstone every record of a shared definition;
      // an action marks only the Secret it deleted.
      kind: "action" as const,
      description:
        "DESTRUCTIVE. Delete the Secret. An already-absent Secret is a clean no-op recorded as not_found.",
      arguments: TargetArgs,
      execute: async (args: z.infer<typeof TargetArgs>, context: Ctx) => {
        const a = TargetArgs.parse(args);
        const t = target(a);
        const status = await withKubectl(deps, t, async (kubectl) => {
          const r = await kubectl([
            "delete",
            "secret",
            t.name,
            "--ignore-not-found",
            "-o",
            "name",
          ]);
          if (r.code !== 0) throw classify(r.stderr, t);
          return r.stdout.trim() ? "deleted" as const : "not_found" as const;
        });
        context.logger.info("Secret {name} {status}", {
          name: t.name,
          status,
        });
        const state = toState(t, null, status, deps.now());
        const handle = await persistState(context, t, state);
        return { dataHandles: [handle], result: { status } };
      },
    },
  },
};
