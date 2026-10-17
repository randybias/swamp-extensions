/**
 * Swamp extension model for a KubeVirt installation on an existing Kubernetes
 * cluster.
 *
 * The operator manifest is pinned by a required SHA-256 and verified before any
 * `kubectl apply`. The cluster is reached only through a kubeconfig handed to
 * `kubectl` in a private temporary file and validated before use (no exec or
 * auth-provider plugin); the kubeconfig never appears on a command line, in
 * stored state or in method output. One definition serves any cluster: the
 * target is a method argument.
 *
 * @module
 */

import { z } from "npm:zod@4.3.6";
import {
  classifyKubectl,
  clusterFingerprint16,
  type Condition,
  conditionFalse,
  conditionTrue,
  currentDeps,
  type Deps,
  fetchVerifiedManifest,
  fieldManager,
  isDowngrade,
  isMinorSkip,
  kubectlJson,
  kubectlText,
  KubevirtError,
  manifestUrl,
  operatorStateKey,
  POLL_INTERVAL_MS,
  pollUntil,
  sha256Hex,
  TargetShape,
  timeoutField,
  withCluster,
} from "./_lib/k8s.ts";
import {
  CDI_CR_NAME,
  CDI_NAMESPACE,
  CDI_OPERATOR_ASSET,
  CDI_REPO,
  KUBEVIRT_CR_NAME,
  KUBEVIRT_NAMESPACE,
  KUBEVIRT_OPERATOR_ASSET,
  KUBEVIRT_REPO,
  renderCdiCr,
  renderKubeVirtCr,
  UNINSTALL_STRATEGIES,
  WORKLOAD_UPDATE_METHODS,
} from "./_lib/manifests.ts";

// deno-lint-ignore no-explicit-any
type Ctx = any;

const HTTPS_URL_RE = /^https:\/\/[^\s?#@]+$/;
const FEATURE_GATE_RE = /^[A-Z][A-Za-z0-9]{1,63}$/;
const RELEASE_TAG_RE = /^v\d{1,3}\.\d{1,3}\.\d{1,3}$/;
const SHA256_RE = /^[0-9a-f]{64}$/;

/** True for an https URL with no userinfo or query (a mirror override). */
export function isHttpsBase(u: string): boolean {
  if (!HTTPS_URL_RE.test(u)) return false;
  try {
    const x = new URL(u);
    return x.protocol === "https:" && x.username === "" && x.password === "" &&
      x.search === "";
  } catch {
    return false;
  }
}

const FeatureGates = z.array(
  z.string().regex(FEATURE_GATE_RE, "invalid feature gate name"),
).max(32).default([]).describe("Feature gates to enable; sorted on render.");

const WorkloadUpdateMethods = z.array(
  z.enum(WORKLOAD_UPDATE_METHODS),
).default([]).describe(
  "Workload update methods; empty omits the strategy and lets upstream default apply.",
);

const OperatorArgs = {
  ...TargetShape,
  kubevirt_version: z.string().regex(
    RELEASE_TAG_RE,
    "not a vMAJOR.MINOR.PATCH release tag",
  ).describe("KubeVirt release to install or move to."),
  cdi_version: z.string().regex(
    RELEASE_TAG_RE,
    "not a vMAJOR.MINOR.PATCH release tag",
  ).optional().describe("CDI release, required when install_cdi is true."),
  operator_manifest_sha256: z.string().regex(
    SHA256_RE,
    "not a lowercase 64-hex SHA-256",
  ).describe(
    "Required SHA-256 of the KubeVirt operator manifest; the fetch is refused unless it matches.",
  ),
  cdi_operator_manifest_sha256: z.string().regex(
    SHA256_RE,
    "not a lowercase 64-hex SHA-256",
  ).optional().describe(
    "Required SHA-256 of the CDI operator manifest when install_cdi is true.",
  ),
  manifest_base_url: z.string().max(2048).refine(
    isHttpsBase,
    "must be an https URL with no userinfo or query",
  ).optional().describe(
    "Mirror that shadows the GitHub release-download host; still SHA-checked.",
  ),
  install_cdi: z.boolean().default(false).describe(
    "Also install CDI; required before defining a VM with a DataVolume source.",
  ),
  use_emulation: z.boolean().default(false).describe(
    "Set developerConfiguration.useEmulation; slow, for hosts without /dev/kvm.",
  ),
  feature_gates: FeatureGates,
  workload_update_methods: WorkloadUpdateMethods,
  uninstall_strategy: z.enum(UNINSTALL_STRATEGIES).default(
    "BlockUninstallIfWorkloadsExist",
  ).describe("Uninstall strategy written into the KubeVirt CR."),
  timeout_s: timeoutField(600),
};

function requireCdi(a: {
  install_cdi: boolean;
  cdi_version?: string;
  cdi_operator_manifest_sha256?: string;
}, ctx: z.RefinementCtx): void {
  if (!a.install_cdi) return;
  if (!a.cdi_version) {
    ctx.addIssue({
      code: "custom",
      path: ["cdi_version"],
      message: "cdi_version is required when install_cdi is true",
    });
  }
  if (!a.cdi_operator_manifest_sha256) {
    ctx.addIssue({
      code: "custom",
      path: ["cdi_operator_manifest_sha256"],
      message:
        "cdi_operator_manifest_sha256 is required when install_cdi is true",
    });
  }
}

const InstallArgs = z.strictObject(OperatorArgs).superRefine(requireCdi);

const UpgradeArgs = z.strictObject({
  ...OperatorArgs,
  allow_minor_skip: z.boolean().default(false).describe(
    "Allow a jump of more than one minor version.",
  ),
}).superRefine(requireCdi);

const WaitReadyArgs = z.strictObject({
  ...TargetShape,
  kubevirt_version: z.string().regex(
    RELEASE_TAG_RE,
    "not a vMAJOR.MINOR.PATCH release tag",
  ).describe("Version the CR must report as observed."),
  install_cdi: z.boolean().default(false).describe(
    "Also require the CDI custom resource to be Available.",
  ),
  timeout_s: timeoutField(300),
});

const ReadArgs = z.strictObject({ ...TargetShape });

const UninstallArgs = z.strictObject({
  ...OperatorArgs,
  confirm: z.string().min(1).max(64).describe(
    "Must equal the cluster fingerprint; guards against the wrong cluster.",
  ),
});

const RenderCrArgs = z.strictObject({
  use_emulation: z.boolean().default(false).describe(
    "Set developerConfiguration.useEmulation.",
  ),
  feature_gates: FeatureGates,
  workload_update_methods: WorkloadUpdateMethods,
  uninstall_strategy: z.enum(UNINSTALL_STRATEGIES).default(
    "BlockUninstallIfWorkloadsExist",
  ).describe("Uninstall strategy written into the KubeVirt CR."),
});

const ConditionSchema = z.strictObject({
  type: z.string().optional(),
  status: z.string().optional(),
  reason: z.string().optional(),
  message: z.string().optional(),
});

const RenderedSchema = z.strictObject({
  yaml: z.string(),
  sha256: z.string(),
});

const OperatorStateSchema = z.strictObject({
  cluster_fp: z.string(),
  context: z.string(),
  kubevirt_version: z.string().optional(),
  cdi_version: z.string().optional(),
  observed_cdi_version: z.string().optional(),
  operator_sha256: z.string().optional(),
  cr_sha256: z.string().optional(),
  phase: z.string().optional(),
  conditions: z.array(ConditionSchema).default([]),
  use_emulation: z.boolean().optional(),
  feature_gates: z.array(z.string()).default([]),
  schedulable_nodes: z.array(z.string()).default([]),
  kvm_nodes: z.array(z.string()).default([]),
  outdated_vmis: z.number().int().default(0),
  cdi_installed_by_model: z.boolean().optional(),
  cdi_operator_sha256: z.string().optional(),
  status: z.enum(["present", "not_found"]),
  observed_at: z.string(),
});

/** Stored state of one KubeVirt installation; holds no kubeconfig. */
export type OperatorState = z.infer<typeof OperatorStateSchema>;

interface KubeVirtCr {
  metadata?: { uid?: string; generation?: number };
  spec?: {
    configuration?: {
      developerConfiguration?: {
        useEmulation?: boolean;
        featureGates?: string[];
      };
    };
    uninstallStrategy?: string;
    workloadUpdateStrategy?: { workloadUpdateMethods?: string[] };
  };
  status?: {
    phase?: string;
    observedKubeVirtVersion?: string;
    outdatedVirtualMachineInstanceWorkloads?: number;
    conditions?: Condition[];
  };
}

interface CdiCr {
  status?: {
    phase?: string;
    observedVersion?: string;
    conditions?: Condition[];
  };
}

interface Node {
  metadata?: { name?: string; labels?: Record<string, string> };
  status?: { allocatable?: Record<string, string> };
}

interface NodeFacts {
  schedulable: string[];
  kvm: string[];
}

type Kubectl = (
  args: string[],
  stdin?: string,
) => Promise<{ code: number; stdout: string; stderr: string }>;

async function readCr(kubectl: Kubectl): Promise<KubeVirtCr | null> {
  return await kubectlJson<KubeVirtCr>(kubectl, [
    "get",
    "kubevirt",
    KUBEVIRT_CR_NAME,
  ]);
}

async function readCdi(kubectl: Kubectl): Promise<CdiCr | null> {
  return await kubectlJson<CdiCr>(kubectl, ["get", "cdi", CDI_CR_NAME]);
}

/** True for a node whose allocatable KVM device count is greater than zero. */
function nodeHasKvm(n: Node): boolean {
  const raw = n.status?.allocatable?.["devices.kubevirt.io/kvm"] ?? "0";
  const count = Number.parseInt(raw, 10);
  return Number.isFinite(count) && count > 0;
}

async function readNodes(kubectl: Kubectl): Promise<NodeFacts> {
  const list = await kubectlJson<{ items?: Node[] }>(kubectl, [
    "get",
    "nodes",
  ]);
  const nodes = list?.items ?? [];
  const names = (pred: (n: Node) => boolean) =>
    nodes.filter(pred).map((n) => n.metadata?.name ?? "").filter((n) =>
      n !== ""
    ).sort();
  return {
    schedulable: names((n) =>
      n.metadata?.labels?.["kubevirt.io/schedulable"] === "true"
    ),
    // KubeVirt advertises KVM as the node resource devices.kubevirt.io/kvm,
    // not as a label.
    kvm: names(nodeHasKvm),
  };
}

/**
 * True when any object from the operator manifest still exists: the `kubevirt`
 * namespace or the `kubevirts.kubevirt.io` CRD. Used so an uninstall whose
 * custom resource is already gone still deletes the rest.
 */
async function operatorObjectsRemain(kubectl: Kubectl): Promise<boolean> {
  const ns = await kubectlJson<unknown>(kubectl, [
    "get",
    "namespace",
    KUBEVIRT_NAMESPACE,
  ]);
  if (ns) return true;
  const crd = await kubectlJson<unknown>(kubectl, [
    "get",
    "crd",
    "kubevirts.kubevirt.io",
  ]);
  return crd !== null;
}

/**
 * True when any CDI object this model would have installed still exists: the
 * `cdi` custom resource, the `cdi` namespace or the `cdis.cdi.kubevirt.io`
 * CRD. Used so CDI cleanup runs even when KubeVirt is already gone.
 */
async function cdiObjectsRemain(kubectl: Kubectl): Promise<boolean> {
  const cr = await kubectlJson<unknown>(kubectl, ["get", "cdi", CDI_CR_NAME]);
  if (cr) return true;
  const ns = await kubectlJson<unknown>(kubectl, [
    "get",
    "namespace",
    CDI_NAMESPACE,
  ]);
  if (ns) return true;
  const crd = await kubectlJson<unknown>(kubectl, [
    "get",
    "crd",
    "cdis.cdi.kubevirt.io",
  ]);
  return crd !== null;
}

function cdiReady(cdi: CdiCr | null): boolean {
  return cdi?.status?.phase === "Deployed" &&
    conditionTrue(cdi.status?.conditions, "Available");
}

interface ReadyProbe {
  ready: boolean;
  phase?: string;
  conditions: Condition[];
  nodes: NodeFacts;
  cdi: CdiCr | null;
  observed?: string;
}

/**
 * Polls the CR until it is `Deployed` with `Available=True`,
 * `Progressing=False` and `Degraded=False`, reports the expected observed
 * version and (when asked) has an Available CDI. Returns the last probe on
 * timeout; it never throws for not-ready.
 */
async function waitOperatorReady(
  d: Deps,
  kubectl: Kubectl,
  version: string,
  installCdi: boolean,
  timeoutMs: number,
): Promise<ReadyProbe> {
  return await pollUntil<ReadyProbe>(
    d,
    timeoutMs,
    POLL_INTERVAL_MS,
    async () => {
      const cr = await readCr(kubectl);
      const nodes = await readNodes(kubectl);
      const cdi = installCdi ? await readCdi(kubectl) : null;
      const conditions = cr?.status?.conditions ?? [];
      const observed = cr?.status?.observedKubeVirtVersion;
      const ready = cr?.status?.phase === "Deployed" &&
        conditionTrue(conditions, "Available") &&
        conditionFalse(conditions, "Progressing") &&
        conditionFalse(conditions, "Degraded") &&
        observed === version &&
        (!installCdi || cdiReady(cdi));
      return {
        ready,
        phase: cr?.status?.phase,
        conditions,
        nodes,
        cdi,
        observed,
      };
    },
    (v) => v.ready,
  );
}

interface StateInput {
  context?: string;
  kubevirt_version?: string;
  cdi_version?: string;
  operator_manifest_sha256?: string;
}

interface StateExtra {
  operator_sha256?: string;
  cr_sha256?: string;
  cdi_version?: string;
  observed_cdi_version?: string;
  cdi_operator_sha256?: string;
  cdi_installed_by_model?: boolean;
  use_emulation?: boolean;
  feature_gates?: string[];
}

function stateOf(
  a: StateInput,
  fp: string,
  cr: KubeVirtCr | null,
  nodes: NodeFacts,
  status: OperatorState["status"],
  now: Date,
  extra: StateExtra = {},
): OperatorState {
  const version = cr?.status?.observedKubeVirtVersion ?? a.kubevirt_version;
  const cdiVersion = extra.cdi_version;
  const operatorSha = extra.operator_sha256 ?? a.operator_manifest_sha256;
  return OperatorStateSchema.parse({
    cluster_fp: fp,
    context: a.context ?? "current-context",
    ...(version ? { kubevirt_version: version } : {}),
    ...(cdiVersion ? { cdi_version: cdiVersion } : {}),
    ...(extra.observed_cdi_version
      ? { observed_cdi_version: extra.observed_cdi_version }
      : {}),
    ...(operatorSha ? { operator_sha256: operatorSha } : {}),
    ...(extra.cr_sha256 ? { cr_sha256: extra.cr_sha256 } : {}),
    ...(extra.cdi_operator_sha256
      ? { cdi_operator_sha256: extra.cdi_operator_sha256 }
      : {}),
    ...(cr?.status?.phase ? { phase: cr.status.phase } : {}),
    conditions: cr?.status?.conditions ?? [],
    ...(extra.use_emulation !== undefined
      ? { use_emulation: extra.use_emulation }
      : {}),
    feature_gates: extra.feature_gates ?? [],
    schedulable_nodes: nodes.schedulable,
    kvm_nodes: nodes.kvm,
    outdated_vmis: cr?.status?.outdatedVirtualMachineInstanceWorkloads ?? 0,
    ...(extra.cdi_installed_by_model !== undefined
      ? { cdi_installed_by_model: extra.cdi_installed_by_model }
      : {}),
    status,
    observed_at: now.toISOString(),
  });
}

function summary(s: OperatorState) {
  return {
    kubevirt_version: s.kubevirt_version,
    cdi_version: s.cdi_version,
    phase: s.phase,
    conditions: s.conditions,
    use_emulation: s.use_emulation,
    feature_gates: s.feature_gates,
    status: s.status,
    schedulable_nodes: s.schedulable_nodes,
    kvm_nodes: s.kvm_nodes,
    outdated_vmis: s.outdated_vmis,
    cdi_installed_by_model: s.cdi_installed_by_model,
  };
}

/** Writes the installation's state under its cluster fingerprint. */
async function persist(
  context: Ctx,
  a: { kubeconfig: string; context?: string },
  state: OperatorState,
) {
  return await context.writeResource(
    "state",
    await operatorStateKey(a.kubeconfig, a.context),
    state,
  );
}

/** Reads the stored installation record, or null when there is none. */
async function readPrior(
  context: Ctx,
  a: { kubeconfig: string; context?: string },
): Promise<OperatorState | null> {
  return await context.readResource(
    await operatorStateKey(a.kubeconfig, a.context),
  ) as OperatorState | null;
}

/** Model definition for the KubeVirt operator install. */
export const model = {
  type: "@randybias/kubevirt",
  version: "2026.10.17.1",
  description:
    "Install and upgrade KubeVirt on an existing Kubernetes cluster at a SHA-256-pinned operator manifest, wait for it to be usable and manage the installation. One definition serves any cluster: the kubeconfig is a method argument.",
  globalArguments: z.strictObject({}),
  resources: {
    state: {
      description: "Installed versions, CR phase and conditions, node facts",
      schema: OperatorStateSchema,
      lifetime: "infinite" as const,
      garbageCollection: 10,
    },
    rendered: {
      description: "A rendered KubeVirt custom resource and its digest",
      schema: RenderedSchema,
      lifetime: "infinite" as const,
      garbageCollection: 10,
    },
  },
  methods: {
    render_cr: {
      description:
        "READ-ONLY. Render the KubeVirt custom resource for the given inputs; the same inputs give identical bytes.",
      arguments: RenderCrArgs,
      execute: async (args: z.input<typeof RenderCrArgs>, context: Ctx) => {
        const a = RenderCrArgs.parse(args);
        const yaml = renderKubeVirtCr(a);
        const sha256 = await sha256Hex(yaml);
        const handle = await context.writeResource("rendered", "kubevirt", {
          yaml,
          sha256,
        });
        return { dataHandles: [handle], result: { yaml, sha256 } };
      },
    },

    install: {
      kind: "action" as const,
      description:
        "Idempotent. Verify the pinned operator manifest, server-side apply it and the KubeVirt custom resource, and optionally CDI (operator manifest and custom resource). Adopts an install at the same version and refuses a different one with a pointer to upgrade. Returns the versions and manifest digests.",
      arguments: InstallArgs,
      execute: async (args: z.input<typeof InstallArgs>, context: Ctx) => {
        const a = InstallArgs.parse(args);
        const d = currentDeps();
        const fm = await fieldManager(context.definition.name);
        const fp = await clusterFingerprint16(a.kubeconfig, a.context);
        const prior = await readPrior(context, a);
        // 1. Refuse a different installed version before fetching anything.
        await withCluster(
          d,
          a.kubeconfig,
          a.context,
          KUBEVIRT_NAMESPACE,
          async (kubectl) => {
            const before = await readCr(kubectl);
            const installed = before?.status?.observedKubeVirtVersion;
            if (installed && installed !== a.kubevirt_version) {
              throw new KubevirtError(
                "version_conflict",
                `KubeVirt ${installed} is installed; use upgrade to move to ${a.kubevirt_version}`,
              );
            }
          },
        );
        // 2. Fetch and verify every requested manifest before the first apply.
        const opUrl = manifestUrl(
          a.manifest_base_url,
          KUBEVIRT_REPO.org,
          KUBEVIRT_REPO.repo,
          a.kubevirt_version,
          KUBEVIRT_OPERATOR_ASSET,
        );
        const opManifest = await fetchVerifiedManifest(
          d,
          opUrl,
          a.operator_manifest_sha256,
        );
        // 3. Plan CDI. Never claim a CDI this model did not install: an
        // existing CDI with no ownership record is adopted, not erased later.
        let cdiOwned = prior?.cdi_installed_by_model ?? false;
        let cdiVersion = prior?.cdi_version;
        let cdiSha = prior?.cdi_operator_sha256;
        let cdiManifest: string | undefined;
        if (a.install_cdi && a.cdi_version && a.cdi_operator_manifest_sha256) {
          const wantVersion = a.cdi_version;
          const wantSha = a.cdi_operator_manifest_sha256;
          const planned = await withCluster(
            d,
            a.kubeconfig,
            a.context,
            CDI_NAMESPACE,
            async (kubectl) => {
              const exists = await cdiObjectsRemain(kubectl);
              if (exists && prior?.cdi_installed_by_model !== true) {
                context.logger.info(
                  "CDI exists and is not owned by this model; adopting it",
                  {},
                );
                return { owned: false as const };
              }
              const cdiUrl = manifestUrl(
                a.manifest_base_url,
                CDI_REPO.org,
                CDI_REPO.repo,
                wantVersion,
                CDI_OPERATOR_ASSET,
              );
              const manifest = await fetchVerifiedManifest(d, cdiUrl, wantSha);
              return {
                owned: true as const,
                manifest,
                version: wantVersion,
                sha: wantSha,
              };
            },
          );
          if (planned.owned) {
            cdiOwned = true;
            cdiVersion = planned.version;
            cdiSha = planned.sha;
            cdiManifest = planned.manifest;
          } else {
            cdiOwned = false;
            cdiVersion = prior?.cdi_version;
            cdiSha = prior?.cdi_operator_sha256;
          }
        }
        // 4. Apply KubeVirt.
        const facts = await withCluster(
          d,
          a.kubeconfig,
          a.context,
          KUBEVIRT_NAMESPACE,
          async (kubectl) => {
            const apply = (body: string) =>
              kubectlText(
                kubectl,
                [
                  "apply",
                  "--server-side",
                  "--force-conflicts",
                  `--field-manager=${fm}`,
                  "-f",
                  "-",
                ],
                body,
              );
            await apply(opManifest);
            const crYaml = renderKubeVirtCr({
              use_emulation: a.use_emulation,
              feature_gates: a.feature_gates,
              workload_update_methods: a.workload_update_methods,
              uninstall_strategy: a.uninstall_strategy,
            });
            await apply(crYaml);
            const cr = await readCr(kubectl);
            const nodes = await readNodes(kubectl);
            context.logger.info("KubeVirt {version} installed", {
              version: a.kubevirt_version,
            });
            return { cr, nodes, crSha: await sha256Hex(crYaml) };
          },
        );
        // 5. Apply CDI if planned.
        if (cdiManifest) {
          const body = cdiManifest;
          await withCluster(
            d,
            a.kubeconfig,
            a.context,
            CDI_NAMESPACE,
            async (kubectl) => {
              const apply = (text: string) =>
                kubectlText(
                  kubectl,
                  [
                    "apply",
                    "--server-side",
                    "--force-conflicts",
                    `--field-manager=${fm}`,
                    "-f",
                    "-",
                  ],
                  text,
                );
              await apply(body);
              await apply(renderCdiCr());
            },
          );
        }
        const state = stateOf(
          a,
          fp,
          facts.cr,
          facts.nodes,
          "present",
          d.now(),
          {
            operator_sha256: a.operator_manifest_sha256,
            cr_sha256: facts.crSha,
            cdi_version: cdiVersion,
            cdi_operator_sha256: cdiSha,
            cdi_installed_by_model: cdiOwned,
            use_emulation: a.use_emulation,
            feature_gates: a.feature_gates,
          },
        );
        const handle = await persist(context, a, state);
        return {
          dataHandles: [handle],
          result: {
            kubevirt_version: a.kubevirt_version,
            cdi_version: cdiOwned ? cdiVersion : undefined,
            operator_sha256: a.operator_manifest_sha256,
            cr_sha256: state.cr_sha256,
          },
        };
      },
    },

    wait_ready: {
      kind: "action" as const,
      description:
        "READ-ONLY semantics. Poll until the CR is Deployed with Available=True, Progressing=False and Degraded=False and reports the given version, and CDI is Available when asked. Never throws for not-ready; returns ready:false with the last conditions after the timeout.",
      arguments: WaitReadyArgs,
      execute: async (args: z.input<typeof WaitReadyArgs>, context: Ctx) => {
        const a = WaitReadyArgs.parse(args);
        const d = currentDeps();
        const fp = await clusterFingerprint16(a.kubeconfig, a.context);
        const prior = await readPrior(context, a);
        const probe = await withCluster(
          d,
          a.kubeconfig,
          a.context,
          KUBEVIRT_NAMESPACE,
          (kubectl) =>
            waitOperatorReady(
              d,
              kubectl,
              a.kubevirt_version,
              a.install_cdi,
              a.timeout_s * 1000,
            ),
        );
        context.logger.info("KubeVirt ready={ready} phase={phase}", {
          ready: probe.ready,
          phase: probe.phase ?? "",
        });
        const state = stateOf(
          { context: a.context, kubevirt_version: probe.observed },
          fp,
          null,
          probe.nodes,
          "present",
          d.now(),
          {
            cdi_version: prior?.cdi_version,
            observed_cdi_version: probe.cdi?.status?.observedVersion,
            cdi_installed_by_model: prior?.cdi_installed_by_model,
            feature_gates: prior?.feature_gates ?? [],
            ...(prior?.cdi_operator_sha256
              ? { cdi_operator_sha256: prior.cdi_operator_sha256 }
              : {}),
          },
        );
        const readyState: OperatorState = {
          ...state,
          ...(probe.phase ? { phase: probe.phase } : {}),
          conditions: probe.conditions,
        };
        const handle = await persist(context, a, readyState);
        return {
          dataHandles: [handle],
          result: {
            ready: probe.ready,
            phase: probe.phase,
            conditions: probe.conditions,
            schedulable_nodes: probe.nodes.schedulable,
            kvm_nodes: probe.nodes.kvm,
          },
        };
      },
    },

    upgrade: {
      kind: "action" as const,
      description:
        "Verify the new pinned operator manifest and apply it, so the CR follows the operator, then wait as wait_ready. Refuses a downgrade and a jump of more than one minor unless allow_minor_skip is set. Returns the from and to versions and the outdated workload count.",
      arguments: UpgradeArgs,
      execute: async (args: z.input<typeof UpgradeArgs>, context: Ctx) => {
        const a = UpgradeArgs.parse(args);
        const d = currentDeps();
        const fm = await fieldManager(context.definition.name);
        const fp = await clusterFingerprint16(a.kubeconfig, a.context);
        const prior = await readPrior(context, a);
        const outcome = await withCluster(
          d,
          a.kubeconfig,
          a.context,
          KUBEVIRT_NAMESPACE,
          async (kubectl) => {
            const cr = await readCr(kubectl);
            const from = cr?.status?.observedKubeVirtVersion;
            if (!cr || !from) {
              throw new KubevirtError(
                "not_found",
                "KubeVirt is not installed; use install first",
              );
            }
            if (isDowngrade(from, a.kubevirt_version)) {
              throw new KubevirtError(
                "version_skew",
                `downgrades are not supported: ${from} to ${a.kubevirt_version}`,
              );
            }
            if (isMinorSkip(from, a.kubevirt_version) && !a.allow_minor_skip) {
              throw new KubevirtError(
                "version_skew",
                `upgrades move one minor at a time: ${from} to ${a.kubevirt_version}; set allow_minor_skip to override`,
              );
            }
            const opUrl = manifestUrl(
              a.manifest_base_url,
              KUBEVIRT_REPO.org,
              KUBEVIRT_REPO.repo,
              a.kubevirt_version,
              KUBEVIRT_OPERATOR_ASSET,
            );
            const opManifest = await fetchVerifiedManifest(
              d,
              opUrl,
              a.operator_manifest_sha256,
            );
            await kubectlText(
              kubectl,
              [
                "apply",
                "--server-side",
                "--force-conflicts",
                `--field-manager=${fm}`,
                "-f",
                "-",
              ],
              opManifest,
            );
            const probe = await waitOperatorReady(
              d,
              kubectl,
              a.kubevirt_version,
              a.install_cdi,
              a.timeout_s * 1000,
            );
            const after = await readCr(kubectl);
            context.logger.info("KubeVirt upgraded {from} to {to}", {
              from,
              to: a.kubevirt_version,
            });
            return {
              state: stateOf(a, fp, after, probe.nodes, "present", d.now(), {
                operator_sha256: a.operator_manifest_sha256,
                cdi_installed_by_model: prior?.cdi_installed_by_model,
                ...(prior?.cdi_operator_sha256
                  ? { cdi_operator_sha256: prior.cdi_operator_sha256 }
                  : {}),
                ...(prior?.cdi_version
                  ? { cdi_version: prior.cdi_version }
                  : {}),
              }),
              from,
            };
          },
        );
        const handle = await persist(context, a, outcome.state);
        return {
          dataHandles: [handle],
          result: {
            from: outcome.from,
            to: a.kubevirt_version,
            outdated_vmis: outcome.state.outdated_vmis,
          },
        };
      },
    },

    get: {
      description:
        "READ-ONLY. Installed versions, CR phase and conditions, emulation flag, feature gates, node facts and outdated workload count.",
      arguments: ReadArgs,
      execute: async (args: z.infer<typeof ReadArgs>, context: Ctx) => {
        const a = ReadArgs.parse(args);
        const d = currentDeps();
        const fp = await clusterFingerprint16(a.kubeconfig, a.context);
        const prior = await readPrior(context, a);
        const state = await withCluster(
          d,
          a.kubeconfig,
          a.context,
          KUBEVIRT_NAMESPACE,
          async (kubectl) => {
            const cr = await readCr(kubectl);
            if (!cr) {
              throw new KubevirtError("not_found", "KubeVirt is not installed");
            }
            const nodes = await readNodes(kubectl);
            const cdi = await readCdi(kubectl);
            const dev = cr.spec?.configuration?.developerConfiguration;
            return stateOf(a, fp, cr, nodes, "present", d.now(), {
              cdi_version: prior?.cdi_version,
              observed_cdi_version: cdi?.status?.observedVersion,
              cdi_installed_by_model: prior?.cdi_installed_by_model,
              ...(prior?.cdi_operator_sha256
                ? { cdi_operator_sha256: prior.cdi_operator_sha256 }
                : {}),
              use_emulation: dev?.useEmulation,
              feature_gates: dev?.featureGates ?? [],
            });
          },
        );
        const handle = await persist(context, a, state);
        return { dataHandles: [handle], result: summary(state) };
      },
    },

    sync: {
      description:
        "READ-ONLY. Reconcile recorded state with the cluster; an absent CR is recorded as not_found instead of failing.",
      arguments: ReadArgs,
      execute: async (args: z.infer<typeof ReadArgs>, context: Ctx) => {
        const a = ReadArgs.parse(args);
        const d = currentDeps();
        const fp = await clusterFingerprint16(a.kubeconfig, a.context);
        const prior = await readPrior(context, a);
        const state = await withCluster(
          d,
          a.kubeconfig,
          a.context,
          KUBEVIRT_NAMESPACE,
          async (kubectl) => {
            const cr = await readCr(kubectl);
            if (!cr) {
              return stateOf(
                a,
                fp,
                null,
                {
                  schedulable: [],
                  kvm: [],
                },
                "not_found",
                d.now(),
                {
                  cdi_version: prior?.cdi_version,
                  cdi_installed_by_model: prior?.cdi_installed_by_model,
                  ...(prior?.cdi_operator_sha256
                    ? { cdi_operator_sha256: prior.cdi_operator_sha256 }
                    : {}),
                },
              );
            }
            const nodes = await readNodes(kubectl);
            const cdi = await readCdi(kubectl);
            const dev = cr.spec?.configuration?.developerConfiguration;
            return stateOf(a, fp, cr, nodes, "present", d.now(), {
              cdi_version: prior?.cdi_version,
              observed_cdi_version: cdi?.status?.observedVersion,
              cdi_installed_by_model: prior?.cdi_installed_by_model,
              ...(prior?.cdi_operator_sha256
                ? { cdi_operator_sha256: prior.cdi_operator_sha256 }
                : {}),
              use_emulation: dev?.useEmulation,
              feature_gates: dev?.featureGates ?? [],
            });
          },
        );
        const handle = await persist(context, a, state);
        context.logger.info("KubeVirt status {status}", {
          status: state.status,
        });
        return { dataHandles: [handle], result: summary(state) };
      },
    },

    uninstall: {
      kind: "action" as const,
      description:
        "DESTRUCTIVE. Delete the KubeVirt custom resource with --wait, then the operator manifest's objects, then CDI when this definition installed it. The CDI version and digest must match the record. With the default BlockUninstallIfWorkloadsExist strategy a running workload blocks the delete (typed error); with RemoveWorkloads upstream deletes the running VMs. Requires confirm equal to the cluster fingerprint; an absent install is a clean no-op.",
      arguments: UninstallArgs,
      execute: async (args: z.input<typeof UninstallArgs>, context: Ctx) => {
        const a = UninstallArgs.parse(args);
        const d = currentDeps();
        const fp = await clusterFingerprint16(a.kubeconfig, a.context);
        if (a.confirm !== fp) {
          throw new KubevirtError(
            "invalid_input",
            "confirm must equal the cluster fingerprint",
          );
        }
        const prior = await readPrior(context, a);
        const cdiInstalled = prior?.cdi_installed_by_model === true;
        // CDI is deleted only when this definition installed it, and only with
        // the exact version and digest it recorded. Fail before any kubectl.
        if (cdiInstalled) {
          if (!a.cdi_version || !a.cdi_operator_manifest_sha256) {
            throw new KubevirtError(
              "invalid_input",
              "CDI was installed by this model; cdi_version and cdi_operator_manifest_sha256 are required to uninstall it",
            );
          }
          if (
            a.cdi_version !== prior?.cdi_version ||
            a.cdi_operator_manifest_sha256 !== prior?.cdi_operator_sha256
          ) {
            throw new KubevirtError(
              "invalid_input",
              "cdi_version and cdi_operator_manifest_sha256 must match the CDI this model installed",
            );
          }
        }
        const cdiVersion = a.cdi_version;
        const cdiSha = a.cdi_operator_manifest_sha256;
        // KubeVirt cleanup. A missing CR with the namespace or CRD gone is a
        // clean no-op; anything else is verified then deleted.
        const opUrl = manifestUrl(
          a.manifest_base_url,
          KUBEVIRT_REPO.org,
          KUBEVIRT_REPO.repo,
          a.kubevirt_version,
          KUBEVIRT_OPERATOR_ASSET,
        );
        const kvDeleted = await withCluster(
          d,
          a.kubeconfig,
          a.context,
          KUBEVIRT_NAMESPACE,
          async (kubectl) => {
            const cr = await readCr(kubectl);
            if (!cr && !(await operatorObjectsRemain(kubectl))) return false;
            const opManifest = await fetchVerifiedManifest(
              d,
              opUrl,
              a.operator_manifest_sha256,
            );
            if (cr) {
              const del = await kubectl([
                "delete",
                "kubevirt",
                KUBEVIRT_CR_NAME,
                "--wait=true",
                `--timeout=${a.timeout_s}s`,
              ]);
              if (del.code !== 0) {
                if (
                  /workloads|BlockUninstall|denied the request|admission webhook/i
                    .test(del.stderr)
                ) {
                  throw new KubevirtError(
                    "uninstall_blocked",
                    "the cluster still runs KubeVirt workloads; stop them before uninstalling",
                  );
                }
                throw classifyKubectl(del.stderr);
              }
            }
            await kubectlText(
              kubectl,
              ["delete", "-f", "-", "--ignore-not-found"],
              opManifest,
            );
            return true;
          },
        );
        // CDI cleanup is independent of KubeVirt, so a KubeVirt removed by hand
        // or a failed retry never orphans the CDI this model installed.
        let cdiDeleted = false;
        if (cdiInstalled && cdiVersion && cdiSha) {
          const version = cdiVersion;
          const sha = cdiSha;
          cdiDeleted = await withCluster(
            d,
            a.kubeconfig,
            a.context,
            CDI_NAMESPACE,
            async (kubectl) => {
              if (!(await cdiObjectsRemain(kubectl))) return true;
              const cdiUrl = manifestUrl(
                a.manifest_base_url,
                CDI_REPO.org,
                CDI_REPO.repo,
                version,
                CDI_OPERATOR_ASSET,
              );
              const cdiManifest = await fetchVerifiedManifest(d, cdiUrl, sha);
              await kubectlText(kubectl, [
                "delete",
                "cdi",
                CDI_CR_NAME,
                "--ignore-not-found",
                "--wait=true",
                `--timeout=${a.timeout_s}s`,
              ]);
              await kubectlText(
                kubectl,
                ["delete", "-f", "-", "--ignore-not-found"],
                cdiManifest,
              );
              return true;
            },
          );
        }
        const status = kvDeleted || cdiDeleted ? "deleted" : "not_found";
        context.logger.info("KubeVirt {status}", { status });
        // The record is cleared: the flag only while a CDI delete has not
        // succeeded, cdi_version/operator_sha256 kept as history.
        const state = stateOf(
          a,
          fp,
          null,
          { schedulable: [], kvm: [] },
          "not_found",
          d.now(),
          {
            cdi_version: prior?.cdi_version,
            cdi_operator_sha256: prior?.cdi_operator_sha256,
            cdi_installed_by_model: cdiInstalled ? !cdiDeleted : false,
          },
        );
        const handle = await persist(context, a, state);
        return { dataHandles: [handle], result: { status } };
      },
    },
  },
};
