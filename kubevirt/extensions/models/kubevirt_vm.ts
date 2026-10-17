/**
 * Swamp extension model for one KubeVirt `VirtualMachine`.
 *
 * A VM is addressed by method arguments (kubeconfig, context, namespace, name),
 * so one definition serves any VM. The source is exactly one of a digest-pinned
 * containerDisk image or a CDI DataVolume template. The deprecated
 * `spec.running` is never written and an existing VM that uses it is refused.
 * The kubeconfig is validated and written to a private temporary file for one
 * `kubectl` call only; it never appears on a command line, in state or in
 * output.
 *
 * @module
 */

import { z } from "npm:zod@4.3.6";
import {
  clusterFingerprint16,
  type Condition,
  currentDeps,
  fieldManager,
  isDataVolumeSize,
  isDigestPinnedImage,
  isDnsLabel,
  isDnsSubdomain,
  isMemory,
  kubectlJson,
  kubectlText,
  KubevirtError,
  POLL_INTERVAL_MS,
  pollUntil,
  projectConditions,
  sha256Hex,
  TargetShape,
  timeoutField,
  vmStateKey,
  withCluster,
} from "./_lib/k8s.ts";
import {
  renderVm,
  RUN_STRATEGIES,
  type VmInput,
  vmSpecSha256,
} from "./_lib/manifests.ts";

// deno-lint-ignore no-explicit-any
type Ctx = any;

/**
 * Strict grammar for a DataVolume http(s) URL: no query, fragment, userinfo,
 * backslash, whitespace or control character anywhere. Combined with a `URL`
 * parse that must show no username or password, so no credential (literal or
 * percent-encoded) and no query token can reach the VM spec, rendered YAML or
 * state.
 */
const HTTP_URL_RE = /^https?:\/\/[A-Za-z0-9._~:\/%+,;=!$&'()*-]+$/;

export function isHttpUrl(u: string): boolean {
  if (!HTTP_URL_RE.test(u)) return false;
  try {
    const x = new URL(u);
    return (x.protocol === "http:" || x.protocol === "https:") &&
      x.username === "" && x.password === "";
  } catch {
    return false;
  }
}

const ContainerDisk = z.strictObject({
  image: z.string().max(1024).refine(
    isDigestPinnedImage,
    "must be a digest-pinned image (name@sha256:<64 hex>); tags are refused",
  ).describe("Digest-pinned containerDisk image."),
});

const DataVolumeSource = z.union([
  z.strictObject({
    http: z.strictObject({
      url: z.string().max(2048).refine(
        isHttpUrl,
        "must be an http(s) URL with no userinfo",
      ),
    }),
  }),
  z.strictObject({
    registry: z.strictObject({
      image: z.string().max(1024).refine(
        isDigestPinnedImage,
        "must be a digest-pinned image (name@sha256:<64 hex>); tags are refused",
      ),
    }),
  }),
]);

const DataVolume = z.strictObject({
  source: DataVolumeSource,
  size: z.string().max(16).refine(
    isDataVolumeSize,
    "must be a whole number of Gi, 1Gi or more",
  ).describe("DataVolume size, e.g. 20Gi."),
  storage_class: z.string().max(253).refine(
    isDnsSubdomain,
    "not a DNS-1123 subdomain",
  ).optional().describe("StorageClass name; omit to use the cluster default."),
});

const VmFields = {
  ...TargetShape,
  namespace: z.string().refine(isDnsLabel, "not a DNS-1123 label").describe(
    "Namespace of the VirtualMachine.",
  ),
  name: z.string().refine(isDnsLabel, "not a DNS-1123 label").describe(
    "VirtualMachine name.",
  ),
  container_disk: ContainerDisk.optional().describe(
    "Ephemeral source: a containerDisk image. Exactly one of container_disk or data_volume is required; guest disk changes are lost on stop or restart.",
  ),
  data_volume: DataVolume.optional().describe(
    "Persistent source: a CDI DataVolume template. Requires CDI to be installed.",
  ),
  cpu_cores: z.number().int().min(1).max(64).default(1).describe(
    "Guest vCPU count.",
  ),
  memory: z.string().max(16).refine(isMemory, "must be 64Mi..256Gi").default(
    "2Gi",
  ).describe("Guest memory request, e.g. 2Gi."),
  // The name of an existing Kubernetes Secret, not secret material.
  // swamp-quality-ignore credentials-sensitive-field
  cloud_init_secret: z.string().max(253).refine(
    isDnsSubdomain,
    "not a DNS-1123 subdomain",
  ).optional().describe(
    "Existing Secret used as cloudInitNoCloud.userDataSecretRef; inline user-data is not accepted.",
  ),
  // swamp-quality-ignore credentials-sensitive-field
  ssh_public_key_secret: z.string().max(253).refine(
    isDnsSubdomain,
    "not a DNS-1123 subdomain",
  ).optional().describe("Existing Secret used for accessCredentials."),
  run_strategy: z.enum(RUN_STRATEGIES).default("Halted").describe(
    "spec.runStrategy; the deprecated spec.running is never written.",
  ),
  timeout_s: timeoutField(600),
};

function requireOneSource(
  a: { container_disk?: unknown; data_volume?: unknown },
  ctx: z.RefinementCtx,
): void {
  const present =
    [a.container_disk, a.data_volume].filter((v) => v !== undefined).length;
  if (present !== 1) {
    ctx.addIssue({
      code: "custom",
      message: "exactly one of container_disk or data_volume is required",
    });
  }
}

const DefineArgs = z.strictObject(VmFields).superRefine(requireOneSource);

const RenderVmArgs = z.strictObject({
  namespace: VmFields.namespace,
  name: VmFields.name,
  container_disk: ContainerDisk.optional(),
  data_volume: DataVolume.optional(),
  cpu_cores: VmFields.cpu_cores,
  memory: VmFields.memory,
  cloud_init_secret: VmFields.cloud_init_secret,
  ssh_public_key_secret: VmFields.ssh_public_key_secret,
  run_strategy: VmFields.run_strategy,
}).superRefine(requireOneSource);

const TargetedArgs = z.strictObject({
  ...TargetShape,
  namespace: VmFields.namespace,
  name: VmFields.name,
});

const StartArgs = z.strictObject({
  ...TargetShape,
  namespace: VmFields.namespace,
  name: VmFields.name,
  wait: z.boolean().default(true).describe(
    "Wait until the VM reports Running before returning.",
  ),
  timeout_s: timeoutField(600),
});

const StopArgs = z.strictObject({
  ...TargetShape,
  namespace: VmFields.namespace,
  name: VmFields.name,
  grace_s: timeoutField(120),
});

const RestartArgs = z.strictObject({
  ...TargetShape,
  namespace: VmFields.namespace,
  name: VmFields.name,
  timeout_s: timeoutField(120),
});

const WaitReadyArgs = z.strictObject({
  ...TargetShape,
  namespace: VmFields.namespace,
  name: VmFields.name,
  require_agent: z.boolean().default(false).describe(
    "Also require the guest agent to be connected.",
  ),
  timeout_s: timeoutField(600),
});

const DeleteArgs = z.strictObject({
  ...TargetShape,
  namespace: VmFields.namespace,
  name: VmFields.name,
  confirm: z.string().max(253).optional().describe(
    "Must equal the VM name when the VM owns a DataVolume.",
  ),
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

const VmStateSchema = z.strictObject({
  cluster_fp: z.string(),
  context: z.string(),
  namespace: z.string(),
  name: z.string(),
  uid: z.string().optional(),
  generation: z.number().int().optional(),
  run_strategy: z.string().optional(),
  printable_status: z.string().optional(),
  phase: z.string().optional(),
  node: z.string().optional(),
  ips: z.array(z.string()).default([]),
  dv_name: z.string().optional(),
  dv_phase: z.string().optional(),
  dv_progress: z.string().optional(),
  conditions: z.array(ConditionSchema).default([]),
  spec_sha256: z.string().optional(),
  status: z.enum(["present", "not_found"]),
  observed_at: z.string(),
});

/** Stored state of one VirtualMachine; holds no kubeconfig. */
export type VmState = z.infer<typeof VmStateSchema>;

type Kubectl = (
  args: string[],
  stdin?: string,
) => Promise<{ code: number; stdout: string; stderr: string }>;

interface VmJson {
  metadata?: { uid?: string; generation?: number };
  spec?: {
    runStrategy?: string;
    running?: boolean;
    template?: {
      spec?: {
        domain?: {
          cpu?: { cores?: number };
          resources?: { requests?: { memory?: string } };
        };
      };
    };
    dataVolumeTemplates?: { metadata?: { name?: string } }[];
  };
  status?: { printableStatus?: string; conditions?: Condition[] };
}

interface VmiJson {
  metadata?: { uid?: string };
  status?: {
    phase?: string;
    nodeName?: string;
    interfaces?: { ipAddress?: string; ipAddresses?: string[] }[];
    conditions?: Condition[];
  };
}

interface DvJson {
  metadata?: { name?: string };
  status?: { phase?: string; progress?: string; conditions?: Condition[] };
}

// The namespace is set on the withCluster target, which appends
// `--namespace <ns>` to every argv; per-call `-n` would be overridden.
async function readVm(kubectl: Kubectl, name: string): Promise<VmJson | null> {
  return await kubectlJson<VmJson>(kubectl, ["get", "vm", name]);
}

async function readVmi(
  kubectl: Kubectl,
  name: string,
): Promise<VmiJson | null> {
  return await kubectlJson<VmiJson>(kubectl, ["get", "vmi", name]);
}

async function readDv(kubectl: Kubectl, name: string): Promise<DvJson | null> {
  return await kubectlJson<DvJson>(kubectl, ["get", "datavolume", name]);
}

/** The DataVolume name owned by a VM, or undefined when the VM has none. */
function dvName(vm: VmJson | null): string | undefined {
  return vm?.spec?.dataVolumeTemplates?.[0]?.metadata?.name;
}

function patchRunStrategy(
  kubectl: Kubectl,
  name: string,
  value: string,
) {
  return kubectlText(
    kubectl,
    [
      "patch",
      "vm",
      name,
      "--type=merge",
      "-p",
      JSON.stringify({ spec: { runStrategy: value } }),
    ],
  );
}

function vmInput(a: {
  namespace: string;
  name: string;
  container_disk?: { image: string };
  data_volume?: {
    source: { http?: { url: string }; registry?: { image: string } };
    size: string;
    storage_class?: string;
  };
  cpu_cores: number;
  memory: string;
  cloud_init_secret?: string;
  ssh_public_key_secret?: string;
  run_strategy: typeof RUN_STRATEGIES[number];
}): VmInput {
  const source: VmInput["source"] = a.container_disk
    ? { kind: "container_disk", image: a.container_disk.image }
    : {
      kind: "data_volume",
      source: a.data_volume!.source.http
        ? { kind: "http", url: a.data_volume!.source.http.url }
        : { kind: "registry", image: a.data_volume!.source.registry!.image },
      size: a.data_volume!.size,
      storage_class: a.data_volume!.storage_class,
    };
  return {
    namespace: a.namespace,
    name: a.name,
    source,
    cpu_cores: a.cpu_cores,
    memory: a.memory,
    cloud_init_secret: a.cloud_init_secret,
    ssh_public_key_secret: a.ssh_public_key_secret,
    run_strategy: a.run_strategy,
  };
}

function addresses(vmi: VmiJson | null): string[] {
  const out: string[] = [];
  for (const i of vmi?.status?.interfaces ?? []) {
    if (i.ipAddress) out.push(i.ipAddress);
    for (const ip of i.ipAddresses ?? []) if (!out.includes(ip)) out.push(ip);
  }
  return out;
}

function vmStateOf(
  a: { context?: string; namespace: string; name: string },
  fp: string,
  vm: VmJson | null,
  vmi: VmiJson | null,
  dv: DvJson | null,
  status: VmState["status"],
  now: Date,
  extra: { spec_sha256?: string } = {},
): VmState {
  return VmStateSchema.parse({
    cluster_fp: fp,
    context: a.context ?? "current-context",
    namespace: a.namespace,
    name: a.name,
    ...(vm?.metadata?.uid ? { uid: vm.metadata.uid } : {}),
    ...(vm?.metadata?.generation !== undefined
      ? { generation: vm.metadata.generation }
      : {}),
    ...(vm?.spec?.runStrategy ? { run_strategy: vm.spec.runStrategy } : {}),
    ...(vm?.status?.printableStatus
      ? { printable_status: vm.status.printableStatus }
      : {}),
    ...(vmi?.status?.phase ? { phase: vmi.status.phase } : {}),
    ...(vmi?.status?.nodeName ? { node: vmi.status.nodeName } : {}),
    ips: addresses(vmi),
    ...(dv?.metadata?.name ? { dv_name: dv.metadata.name } : {}),
    ...(dv?.status?.phase ? { dv_phase: dv.status.phase } : {}),
    ...(dv?.status?.progress ? { dv_progress: dv.status.progress } : {}),
    conditions: projectConditions(vm?.status?.conditions),
    ...(extra.spec_sha256 ? { spec_sha256: extra.spec_sha256 } : {}),
    status,
    observed_at: now.toISOString(),
  });
}

function summary(s: VmState) {
  return {
    namespace: s.namespace,
    name: s.name,
    uid: s.uid,
    generation: s.generation,
    run_strategy: s.run_strategy,
    printable_status: s.printable_status,
    phase: s.phase,
    node: s.node,
    ips: s.ips,
    dv_name: s.dv_name,
    dv_phase: s.dv_phase,
    dv_progress: s.dv_progress,
    conditions: s.conditions,
    spec_sha256: s.spec_sha256,
    status: s.status,
  };
}

async function persist(
  context: Ctx,
  a: { kubeconfig: string; context?: string; namespace: string; name: string },
  state: VmState,
) {
  return await context.writeResource(
    "state",
    await vmStateKey(a.kubeconfig, a.context, a.namespace, a.name),
    state,
  );
}

/** Model definition for a KubeVirt VirtualMachine. */
export const model = {
  type: "@randybias/kubevirt-vm",
  version: "2026.10.17.1",
  description:
    "Define, start, stop, restart, inspect and delete one KubeVirt VirtualMachine, from a digest-pinned containerDisk image or a CDI DataVolume template. One definition serves any VM: the kubeconfig, namespace and name are method arguments.",
  globalArguments: z.strictObject({}),
  resources: {
    state: {
      description: "VM spec summary, run strategy and live status",
      schema: VmStateSchema,
      lifetime: "infinite" as const,
      garbageCollection: 10,
    },
    rendered: {
      description: "A rendered VirtualMachine and its digest",
      schema: RenderedSchema,
      lifetime: "infinite" as const,
      garbageCollection: 10,
    },
  },
  methods: {
    render_vm: {
      description:
        "READ-ONLY. Render the VirtualMachine YAML for the given inputs; the same inputs give identical bytes.",
      arguments: RenderVmArgs,
      execute: async (args: z.input<typeof RenderVmArgs>, context: Ctx) => {
        const a = RenderVmArgs.parse(args);
        const yaml = renderVm(vmInput(a));
        const sha256 = await sha256Hex(yaml);
        const handle = await context.writeResource(
          "rendered",
          `${a.namespace}/${a.name}`,
          { yaml, sha256 },
        );
        return { dataHandles: [handle], result: { yaml, sha256 } };
      },
    },

    define: {
      kind: "action" as const,
      description:
        "Idempotent. Create or update the VirtualMachine by server-side apply, always writing spec.runStrategy and never spec.running. Refuses an existing VM that uses the deprecated spec.running, and a DataVolume source when CDI is not installed. Returns the uid, generation and spec digest.",
      arguments: DefineArgs,
      execute: async (args: z.input<typeof DefineArgs>, context: Ctx) => {
        const a = DefineArgs.parse(args);
        const d = currentDeps();
        const fm = await fieldManager(context.definition.name);
        const fp = await clusterFingerprint16(a.kubeconfig, a.context);
        const input = vmInput(a);
        const yaml = renderVm(input);
        const specSha = await vmSpecSha256(input);
        const state = await withCluster(
          d,
          a.kubeconfig,
          a.context,
          a.namespace,
          async (kubectl) => {
            const before = await readVm(kubectl, a.name);
            if (before?.spec?.running !== undefined) {
              throw new KubevirtError(
                "running_field",
                "the existing VirtualMachine uses the deprecated spec.running; migrate it to spec.runStrategy first",
              );
            }
            if (a.data_volume) {
              const crd = await kubectlJson<unknown>(kubectl, [
                "get",
                "crd",
                "datavolumes.cdi.kubevirt.io",
              ]);
              if (!crd) {
                throw new KubevirtError(
                  "crd_missing",
                  "CDI is not installed: the datavolumes.cdi.kubevirt.io resource type is absent",
                );
              }
            }
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
              yaml,
            );
            const vm = await readVm(kubectl, a.name);
            const vmi = await readVmi(kubectl, a.name);
            const dv = dvName(vm) ? await readDv(kubectl, dvName(vm)!) : null;
            context.logger.info("VirtualMachine {name} defined", {
              name: a.name,
            });
            return vmStateOf(a, fp, vm, vmi, dv, "present", d.now(), {
              spec_sha256: specSha,
            });
          },
        );
        const handle = await persist(context, a, state);
        return {
          dataHandles: [handle],
          result: {
            namespace: state.namespace,
            name: state.name,
            uid: state.uid,
            generation: state.generation,
            run_strategy: state.run_strategy,
            spec_sha256: state.spec_sha256,
          },
        };
      },
    },

    start: {
      kind: "action" as const,
      description:
        "Set runStrategy to Always, a no-op when it already is, and optionally wait until the VM reports Running. Returns the printable status.",
      arguments: StartArgs,
      execute: async (args: z.input<typeof StartArgs>, context: Ctx) => {
        const a = StartArgs.parse(args);
        const d = currentDeps();
        const fp = await clusterFingerprint16(a.kubeconfig, a.context);
        const state = await withCluster(
          d,
          a.kubeconfig,
          a.context,
          a.namespace,
          async (kubectl) => {
            const vm = await readVm(kubectl, a.name);
            if (!vm) {
              throw new KubevirtError(
                "not_found",
                `VirtualMachine ${a.namespace}/${a.name} not found`,
              );
            }
            if (vm.spec?.runStrategy !== "Always") {
              await patchRunStrategy(kubectl, a.name, "Always");
            }
            if (a.wait) {
              await pollUntil(
                d,
                a.timeout_s * 1000,
                POLL_INTERVAL_MS,
                async () => await readVm(kubectl, a.name),
                (v) => v?.status?.printableStatus === "Running",
              );
            }
            const after = await readVm(kubectl, a.name);
            const vmi = await readVmi(kubectl, a.name);
            const dv = dvName(after)
              ? await readDv(kubectl, dvName(after)!)
              : null;
            return vmStateOf(a, fp, after, vmi, dv, "present", d.now());
          },
        );
        const handle = await persist(context, a, state);
        return {
          dataHandles: [handle],
          result: { printable_status: state.printable_status },
        };
      },
    },

    stop: {
      kind: "action" as const,
      description:
        "Set runStrategy to Halted, then wait until no VMI exists or grace_s elapses. Returns the printable status.",
      arguments: StopArgs,
      execute: async (args: z.input<typeof StopArgs>, context: Ctx) => {
        const a = StopArgs.parse(args);
        const d = currentDeps();
        const fp = await clusterFingerprint16(a.kubeconfig, a.context);
        const state = await withCluster(
          d,
          a.kubeconfig,
          a.context,
          a.namespace,
          async (kubectl) => {
            const vm = await readVm(kubectl, a.name);
            if (!vm) {
              throw new KubevirtError(
                "not_found",
                `VirtualMachine ${a.namespace}/${a.name} not found`,
              );
            }
            await patchRunStrategy(kubectl, a.name, "Halted");
            await pollUntil(
              d,
              a.grace_s * 1000,
              POLL_INTERVAL_MS,
              async () => await readVmi(kubectl, a.name),
              (v) => v === null,
            );
            const after = await readVm(kubectl, a.name);
            const vmi = await readVmi(kubectl, a.name);
            const dv = dvName(after)
              ? await readDv(kubectl, dvName(after)!)
              : null;
            return vmStateOf(a, fp, after, vmi, dv, "present", d.now());
          },
        );
        const handle = await persist(context, a, state);
        return {
          dataHandles: [handle],
          result: { printable_status: state.printable_status },
        };
      },
    },

    restart: {
      kind: "action" as const,
      description:
        "Call the public restart subresource with an empty body, then wait until the VMI has a new uid and is Running. Refuses a Halted VM. Returns the VMI uid before and after.",
      arguments: RestartArgs,
      execute: async (args: z.input<typeof RestartArgs>, context: Ctx) => {
        const a = RestartArgs.parse(args);
        const d = currentDeps();
        const outcome = await withCluster(
          d,
          a.kubeconfig,
          a.context,
          a.namespace,
          async (kubectl) => {
            const vm = await readVm(kubectl, a.name);
            if (!vm) {
              throw new KubevirtError(
                "not_found",
                `VirtualMachine ${a.namespace}/${a.name} not found`,
              );
            }
            if (vm.spec?.runStrategy === "Halted") {
              throw new KubevirtError(
                "restart_halted",
                "cannot restart a Halted VirtualMachine; start it first",
              );
            }
            const before = await readVmi(kubectl, a.name);
            await kubectlText(
              kubectl,
              [
                "replace",
                "--raw",
                `/apis/subresources.kubevirt.io/v1/namespaces/${a.namespace}/virtualmachines/${a.name}/restart`,
                "-f",
                "-",
              ],
              "",
            );
            const after = await pollUntil<VmiJson | null>(
              d,
              a.timeout_s * 1000,
              POLL_INTERVAL_MS,
              async () => await readVmi(kubectl, a.name),
              (v) =>
                v !== null && v.metadata?.uid !== before?.metadata?.uid &&
                v.status?.phase === "Running",
            );
            return {
              vmi_uid_before: before?.metadata?.uid,
              vmi_uid_after: after?.metadata?.uid,
            };
          },
        );
        context.logger.info("VirtualMachine {name} restarted", {
          name: a.name,
        });
        return { dataHandles: [], result: outcome };
      },
    },

    wait_ready: {
      kind: "action" as const,
      description:
        "READ-ONLY semantics. Poll until the DataVolume (when present) has Succeeded and the VM is Running with the VMI Ready condition true, and AgentConnected when asked. Never throws for not-ready; returns ready:false after the timeout.",
      arguments: WaitReadyArgs,
      execute: async (args: z.input<typeof WaitReadyArgs>, context: Ctx) => {
        const a = WaitReadyArgs.parse(args);
        const d = currentDeps();
        const fp = await clusterFingerprint16(a.kubeconfig, a.context);
        const probe = await withCluster(
          d,
          a.kubeconfig,
          a.context,
          a.namespace,
          async (kubectl) => {
            return await pollUntil(
              d,
              a.timeout_s * 1000,
              POLL_INTERVAL_MS,
              async () => {
                const vm = await readVm(kubectl, a.name);
                const vmi = await readVmi(kubectl, a.name);
                const name = dvName(vm);
                const dv = name ? await readDv(kubectl, name) : null;
                const ready = vm?.status?.printableStatus === "Running" &&
                  vmiBoolean(vmi, "Ready") &&
                  (!a.require_agent || vmiBoolean(vmi, "AgentConnected")) &&
                  (dv === null || dv.status?.phase === "Succeeded");
                return { ready, vm, vmi, dv };
              },
              (v) => v.ready,
            );
          },
        );
        context.logger.info("VirtualMachine {name} ready={ready}", {
          name: a.name,
          ready: probe.ready,
        });
        const state = vmStateOf(
          a,
          fp,
          probe.vm,
          probe.vmi,
          probe.dv,
          "present",
          d.now(),
        );
        const handle = await persist(context, a, state);
        return {
          dataHandles: [handle],
          result: {
            ready: probe.ready,
            printable_status: state.printable_status,
            node: state.node,
            interfaces: state.ips,
            dv_phase: state.dv_phase,
            dv_progress: state.dv_progress,
          },
        };
      },
    },

    get: {
      description:
        "READ-ONLY. The VM spec summary, printable status, VMI phase/node/IPs, DataVolume phase/progress and conditions.",
      arguments: TargetedArgs,
      execute: async (args: z.infer<typeof TargetedArgs>, context: Ctx) => {
        const a = TargetedArgs.parse(args);
        const d = currentDeps();
        const fp = await clusterFingerprint16(a.kubeconfig, a.context);
        const state = await withCluster(
          d,
          a.kubeconfig,
          a.context,
          a.namespace,
          async (kubectl) => {
            const vm = await readVm(kubectl, a.name);
            if (!vm) {
              throw new KubevirtError(
                "not_found",
                `VirtualMachine ${a.namespace}/${a.name} not found`,
              );
            }
            const vmi = await readVmi(kubectl, a.name);
            const name = dvName(vm);
            const dv = name ? await readDv(kubectl, name) : null;
            return vmStateOf(a, fp, vm, vmi, dv, "present", d.now());
          },
        );
        const handle = await persist(context, a, state);
        return { dataHandles: [handle], result: summary(state) };
      },
    },

    sync: {
      description:
        "READ-ONLY. Reconcile recorded state with the cluster; an absent VM is recorded as not_found instead of failing.",
      arguments: TargetedArgs,
      execute: async (args: z.infer<typeof TargetedArgs>, context: Ctx) => {
        const a = TargetedArgs.parse(args);
        const d = currentDeps();
        const fp = await clusterFingerprint16(a.kubeconfig, a.context);
        const state = await withCluster(
          d,
          a.kubeconfig,
          a.context,
          a.namespace,
          async (kubectl) => {
            const vm = await readVm(kubectl, a.name);
            if (!vm) {
              return vmStateOf(a, fp, null, null, null, "not_found", d.now());
            }
            const vmi = await readVmi(kubectl, a.name);
            const name = dvName(vm);
            const dv = name ? await readDv(kubectl, name) : null;
            return vmStateOf(a, fp, vm, vmi, dv, "present", d.now());
          },
        );
        const handle = await persist(context, a, state);
        context.logger.info("VirtualMachine {name} status {status}", {
          name: a.name,
          status: state.status,
        });
        return { dataHandles: [handle], result: summary(state) };
      },
    },

    delete: {
      kind: "action" as const,
      description:
        "DESTRUCTIVE. Delete the VirtualMachine, cascading its VMI and any DataVolume it owns; disk data is lost. Requires confirm equal to the VM name when it owns a DataVolume; an absent VM is a clean no-op.",
      arguments: DeleteArgs,
      execute: async (args: z.input<typeof DeleteArgs>, context: Ctx) => {
        const a = DeleteArgs.parse(args);
        const d = currentDeps();
        const fp = await clusterFingerprint16(a.kubeconfig, a.context);
        const status = await withCluster(
          d,
          a.kubeconfig,
          a.context,
          a.namespace,
          async (kubectl) => {
            const vm = await readVm(kubectl, a.name);
            if (!vm) return "not_found" as const;
            if (dvName(vm) && a.confirm !== a.name) {
              throw new KubevirtError(
                "invalid_input",
                "confirm must equal the VM name when it owns a DataVolume",
              );
            }
            await kubectlText(kubectl, [
              "delete",
              "vm",
              a.name,
              "--ignore-not-found",
              "--wait=true",
            ]);
            return "deleted" as const;
          },
        );
        context.logger.info("VirtualMachine {name} {status}", {
          name: a.name,
          status,
        });
        const state = vmStateOf(
          a,
          fp,
          null,
          null,
          null,
          status === "not_found" ? "not_found" : "present",
          d.now(),
        );
        const handle = await persist(context, a, state);
        return { dataHandles: [handle], result: { status } };
      },
    },
  },
};

/** True when a VMI has the named condition set to "True". */
function vmiBoolean(vmi: VmiJson | null, type: string): boolean {
  return (vmi?.status?.conditions ?? []).some((c) =>
    c.type === type && (c.status === "True" || c.status === "true")
  );
}
