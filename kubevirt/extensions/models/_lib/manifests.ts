/**
 * Deterministic KubeVirt manifests.
 *
 * Both models render their object from a plain input and hand the same document
 * to `kubectl apply -f -` and to the read-only `render_*` method, so what a
 * caller sees is exactly what is applied. The renderers are pure: no cluster,
 * no clock, no network.
 *
 * @module
 */

import { stringify } from "npm:yaml@2.9.1";

/** Namespace the KubeVirt operator and its CR live in (upstream fixed). */
export const KUBEVIRT_NAMESPACE = "kubevirt";
/** Name of the single `KubeVirt` custom resource (upstream fixed). */
export const KUBEVIRT_CR_NAME = "kubevirt";
/** Namespace the CDI operator and its CR live in (upstream fixed). */
export const CDI_NAMESPACE = "cdi";
/** Name of the single `CDI` custom resource (upstream fixed). */
export const CDI_CR_NAME = "cdi";
/** Release asset that carries the KubeVirt operator manifest. */
export const KUBEVIRT_OPERATOR_ASSET = "kubevirt-operator.yaml";
/** Release asset that carries the CDI operator manifest. */
export const CDI_OPERATOR_ASSET = "cdi-operator.yaml";
/** GitHub org and repo for the KubeVirt release assets. */
export const KUBEVIRT_REPO = { org: "kubevirt", repo: "kubevirt" } as const;
/** GitHub org and repo for the CDI release assets. */
export const CDI_REPO = {
  org: "kubevirt",
  repo: "containerized-data-importer",
} as const;
/** API version of the CDI custom resource at the pinned CDI releases. */
export const CDI_API_VERSION = "cdi.kubevirt.io/v1beta1";
/** The uninstall strategies the `KubeVirt` CR accepts. */
export const UNINSTALL_STRATEGIES = [
  "BlockUninstallIfWorkloadsExist",
  "RemoveWorkloads",
] as const;
/** The workload update methods the `KubeVirt` CR accepts. */
export const WORKLOAD_UPDATE_METHODS = ["LiveMigrate", "Evict"] as const;
/** The run strategies a `VirtualMachine` accepts. */
export const RUN_STRATEGIES = [
  "Always",
  "Halted",
  "Manual",
  "RerunOnFailure",
] as const;

/** Inputs of the `KubeVirt` custom resource. */
export interface CrInput {
  /** Sets `developerConfiguration.useEmulation`. */
  use_emulation: boolean;
  /** Feature gates, sorted on render. */
  feature_gates: string[];
  /** Workload update methods, sorted on render; empty omits the field. */
  workload_update_methods: string[];
  /** Uninstall strategy for the CR. */
  uninstall_strategy: typeof UNINSTALL_STRATEGIES[number];
}

/**
 * Renders the minimal `CDI` custom resource. The CDI operator manifest ships
 * the operator and CRDs but not the CR, so install applies this after it.
 */
export function renderCdiCr(): string {
  return stringify({
    apiVersion: CDI_API_VERSION,
    kind: "CDI",
    metadata: { name: CDI_CR_NAME },
    spec: {},
  }, { lineWidth: 0 });
}

/** Inputs of a `VirtualMachine` and its optional DataVolume template. */
export interface VmInput {
  /** Namespace of the VM. */
  namespace: string;
  /** VM name. */
  name: string;
  /** Exactly one of a containerDisk image or a DataVolume source. */
  source:
    | { kind: "container_disk"; image: string }
    | {
      kind: "data_volume";
      source:
        | { kind: "http"; url: string }
        | { kind: "registry"; image: string };
      size: string;
      storage_class?: string;
    };
  /** Guest vCPU count. */
  cpu_cores: number;
  /** Guest memory request, e.g. `2Gi`. */
  memory: string;
  /** Name of an existing Secret used as `cloudInitNoCloud.userDataSecretRef`. */
  cloud_init_secret?: string;
  /** Name of an existing Secret used for `accessCredentials`. */
  ssh_public_key_secret?: string;
  /** `spec.runStrategy`; the deprecated `spec.running` is never written. */
  run_strategy: typeof RUN_STRATEGIES[number];
}

/**
 * Renders the `KubeVirt` custom resource. Deterministic: feature gates and
 * workload update methods are sorted, and empty lists are omitted.
 */
export function renderKubeVirtCr(i: CrInput): string {
  const developer: Record<string, unknown> = {
    useEmulation: i.use_emulation,
  };
  const gates = [...i.feature_gates].sort();
  if (gates.length > 0) developer.featureGates = gates;
  const spec: Record<string, unknown> = {
    configuration: { developerConfiguration: developer },
    uninstallStrategy: i.uninstall_strategy,
  };
  if (i.workload_update_methods.length > 0) {
    spec.workloadUpdateStrategy = {
      workloadUpdateMethods: [...i.workload_update_methods].sort(),
    };
  }
  return stringify({
    apiVersion: "kubevirt.io/v1",
    kind: "KubeVirt",
    metadata: { name: KUBEVIRT_CR_NAME, namespace: KUBEVIRT_NAMESPACE },
    spec,
  }, { lineWidth: 0 });
}

/**
 * Builds the `VirtualMachine` document. The source disks, volumes, the
 * cloud-init volume and the DataVolume template are assembled here so the
 * render method and the apply path cannot drift.
 */
export function vmDocument(i: VmInput): Record<string, unknown> {
  const disks: Record<string, unknown>[] = [];
  const volumes: Record<string, unknown>[] = [];
  const dvName = `${i.name}-dv`;

  if (i.source.kind === "container_disk") {
    disks.push({ name: "containerdisk", disk: { bus: "virtio" } });
    volumes.push({
      name: "containerdisk",
      containerDisk: { image: i.source.image },
    });
  } else {
    disks.push({ name: "dv-disk", disk: { bus: "virtio" } });
    volumes.push({ name: "dv-disk", dataVolume: { name: dvName } });
  }

  if (i.cloud_init_secret) {
    disks.push({ name: "cloudinitdisk", disk: { bus: "virtio" } });
    volumes.push({
      name: "cloudinitdisk",
      cloudInitNoCloud: { userDataSecretRef: { name: i.cloud_init_secret } },
    });
  }

  const templateSpec: Record<string, unknown> = {
    domain: {
      cpu: { cores: i.cpu_cores },
      resources: { requests: { memory: i.memory } },
      devices: { disks },
    },
    volumes,
  };
  if (i.ssh_public_key_secret) {
    templateSpec.accessCredentials = [{
      sshPublicKey: {
        source: { secret: { secretName: i.ssh_public_key_secret } },
        propagationMethod: { configDrive: {} },
      },
    }];
  }

  const spec: Record<string, unknown> = {
    runStrategy: i.run_strategy,
    template: {
      metadata: { labels: { "kubevirt.io/domain": i.name } },
      spec: templateSpec,
    },
  };

  if (i.source.kind === "data_volume") {
    const source = i.source.source.kind === "http"
      ? { http: { url: i.source.source.url } }
      : { registry: { url: `docker://${i.source.source.image}` } };
    const pvc: Record<string, unknown> = {
      accessModes: ["ReadWriteOnce"],
      resources: { requests: { storage: i.source.size } },
    };
    if (i.source.storage_class) pvc.storageClassName = i.source.storage_class;
    spec.dataVolumeTemplates = [{
      metadata: { name: dvName },
      spec: { source, pvc },
    }];
  }

  return {
    apiVersion: "kubevirt.io/v1",
    kind: "VirtualMachine",
    metadata: { name: i.name, namespace: i.namespace },
    spec,
  };
}

/** Renders the `VirtualMachine` document as deterministic YAML. */
export function renderVm(i: VmInput): string {
  return stringify(vmDocument(i), { lineWidth: 0 });
}

/**
 * Stable JSON of a value: object keys are sorted at every depth, so the digest
 * does not depend on insertion order.
 */
export function stableJson(v: unknown): string {
  if (Array.isArray(v)) return `[${v.map(stableJson).join(",")}]`;
  if (v !== null && typeof v === "object") {
    const entries = Object.entries(v as Record<string, unknown>)
      .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
      .map(([k, x]) => `${JSON.stringify(k)}:${stableJson(x)}`);
    return `{${entries.join(",")}}`;
  }
  return JSON.stringify(v);
}

/** Hex sha256 of the VM spec's stable JSON; used only in-process. */
export async function vmSpecSha256(i: VmInput): Promise<string> {
  const spec = (vmDocument(i) as { spec: unknown }).spec;
  const d = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(stableJson(spec)),
  );
  return [...new Uint8Array(d)].map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}
