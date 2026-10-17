/**
 * Swamp extension model for a Kubernetes Secret written from vault values.
 *
 * Values reach kubectl only on stdin, as a manifest streamed to
 * `kubectl apply -f -`; they never appear on a command line, in a file other
 * than the private temporary kubeconfig, in stored state, or in method output.
 * One definition serves any cluster: the target is a method argument.
 *
 * @module
 */

import { z } from "npm:zod@4.3.6";
import {
  buildManifest,
  classify,
  defaultDeps,
  type Deps,
  hashData,
  hashObserved,
  isContext,
  isDataKey,
  isNamespace,
  isSecretName,
  isSecretType,
  K8sSecretError,
  type Target,
  withKubectl,
} from "./_lib/kubectl.ts";

const MAX_TOTAL_BYTES = 1024 * 1024;

const TargetShape = {
  kubeconfig: z.string().min(1).max(262144).meta({ sensitive: true }).describe(
    "Kubeconfig content. Wire with a vault.get(...) expression.",
  ),
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
  ).refine((d) => Object.keys(d).length > 0, "data must not be empty").describe(
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
  key_sha256: z.record(z.string(), z.string()),
  data_sha256: z.string().optional(),
  resource_version: z.string().optional(),
  status: z.enum(["present", "not_found", "deleted"]),
  observed_at: z.string(),
});

/** Stored state of one Secret; holds hashes, never values. */
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

/** State instance name for a Secret: `{context}/{namespace}/{name}`. */
export function stateName(t: Target): string {
  return `${t.context ?? "current-context"}/${t.namespace}/${t.name}`
    .replace(/[\/\\]/g, "_").replace(/\.\./g, "_").replace(/\0/g, "");
}

interface Observed {
  type: string;
  resource_version: string;
  dataB64: Record<string, string>;
}

interface SecretJson {
  type?: string;
  metadata?: { resourceVersion?: string };
  data?: Record<string, string>;
}

async function observe(
  kubectl: (a: string[], stdin?: string) => Promise<
    { code: number; stdout: string; stderr: string }
  >,
  t: Target,
  secrets: string[],
): Promise<Observed | null> {
  const r = await kubectl([
    "get",
    "secret",
    t.name,
    "-o",
    "json",
    "--ignore-not-found",
  ]);
  if (r.code !== 0) throw classify(r.stderr, t, secrets);
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
  };
}

async function toState(
  t: Target,
  o: Observed | null,
  status: SecretState["status"],
  now: Date,
): Promise<SecretState> {
  const h = o ? await hashObserved(o.dataB64) : { keys: {}, total: undefined };
  return StateSchema.parse({
    context: t.context ?? "current-context",
    namespace: t.namespace,
    name: t.name,
    ...(o ? { type: o.type, resource_version: o.resource_version } : {}),
    keys: Object.keys(h.keys),
    key_sha256: h.keys,
    ...(h.total ? { data_sha256: h.total } : {}),
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
    data_sha256: s.data_sha256,
  };
}

/** Model definition for `@randybias/k8s-secret`. */
export const model = {
  type: "@randybias/k8s-secret",
  version: "2026.10.17.1",
  globalArguments: GlobalArgsSchema,
  resources: {
    state: {
      description: "Secret metadata, key names and per-key sha256; no values",
      schema: StateSchema,
      lifetime: "infinite" as const,
      garbageCollection: 10,
    },
  },
  methods: {
    apply: {
      kind: "action" as const,
      description:
        "Create or update a Secret from vault values streamed to kubectl on stdin. Idempotent: identical data and type is a no-op by sha256. Returns metadata and hashes, never values.",
      arguments: ApplyArgs,
      execute: async (args: z.input<typeof ApplyArgs>, context: Ctx) => {
        const a = ApplyArgs.parse(args);
        const t = target(a);
        const secrets = [t.kubeconfig, ...Object.values(a.data)];
        const want = await hashData(a.data);
        const state = await withKubectl(deps, t, secrets, async (kubectl) => {
          const before = await observe(kubectl, t, secrets);
          if (before) {
            const have = await hashObserved(before.dataB64);
            const same = before.type === a.type &&
              JSON.stringify(Object.keys(want.keys)) ===
                JSON.stringify(Object.keys(have.keys)) &&
              have.total === want.total;
            if (same) {
              context.logger.info("Secret {name} unchanged", { name: t.name });
              return toState(t, before, "present", deps.now());
            }
          }
          const r = await kubectl(
            [
              "apply",
              "--server-side",
              "--force-conflicts",
              "--field-manager=swamp-k8s-secret",
              "-f",
              "-",
              "-o",
              "name",
            ],
            buildManifest(t, a.type, a.data),
          );
          if (r.code !== 0) throw classify(r.stderr, t, secrets);
          const after = await observe(kubectl, t, secrets);
          context.logger.info("Secret {name} applied", { name: t.name });
          return toState(t, after, "present", deps.now());
        });
        const handle = await context.writeResource(
          "state",
          stateName(t),
          state,
        );
        return { dataHandles: [handle], result: summary(state) };
      },
    },

    get: {
      description:
        "READ-ONLY. Read the Secret's metadata, key names and a sha256 per value. Never returns the values.",
      arguments: TargetArgs,
      execute: async (args: z.infer<typeof TargetArgs>, context: Ctx) => {
        const a = TargetArgs.parse(args);
        const t = target(a);
        const state = await withKubectl(deps, t, [t.kubeconfig], async (k) => {
          const o = await observe(k, t, [t.kubeconfig]);
          if (!o) {
            throw new K8sSecretError(
              "not_found",
              `Secret ${t.namespace}/${t.name} not found`,
            );
          }
          return toState(t, o, "present", deps.now());
        });
        const handle = await context.writeResource(
          "state",
          stateName(t),
          state,
        );
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
        const state = await withKubectl(deps, t, [t.kubeconfig], async (k) => {
          const o = await observe(k, t, [t.kubeconfig]);
          return toState(t, o, o ? "present" : "not_found", deps.now());
        });
        context.logger.info("Secret {name} status {status}", {
          name: t.name,
          status: state.status,
        });
        const handle = await context.writeResource(
          "state",
          stateName(t),
          state,
        );
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
        const secrets = [t.kubeconfig];
        const status = await withKubectl(deps, t, secrets, async (kubectl) => {
          const r = await kubectl([
            "delete",
            "secret",
            t.name,
            "--ignore-not-found",
            "-o",
            "name",
          ]);
          if (r.code !== 0) throw classify(r.stderr, t, secrets);
          return r.stdout.trim() ? "deleted" as const : "not_found" as const;
        });
        context.logger.info("Secret {name} {status}", {
          name: t.name,
          status,
        });
        const state = await toState(t, null, status, deps.now());
        const handle = await context.writeResource(
          "state",
          stateName(t),
          state,
        );
        return { dataHandles: [handle], result: { status } };
      },
    },
  },
};
