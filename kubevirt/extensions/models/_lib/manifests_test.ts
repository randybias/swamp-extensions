import { assert, assertEquals } from "jsr:@std/assert@1.0.19";
import { parse } from "npm:yaml@2.9.1";
import {
  CDI_CR_NAME,
  KUBEVIRT_CR_NAME,
  renderCdiCr,
  renderKubeVirtCr,
  renderVm,
  stableJson,
  vmDocument,
  type VmInput,
  vmSpecSha256,
} from "./manifests.ts";

const DIGEST = "sha256:" + "a".repeat(64);

Deno.test("the KubeVirt CR is deterministic and omits an empty update strategy", () => {
  const cr = renderKubeVirtCr({
    use_emulation: false,
    feature_gates: [],
    workload_update_methods: [],
    uninstall_strategy: "BlockUninstallIfWorkloadsExist",
  });
  assertEquals(
    cr,
    renderKubeVirtCr({
      use_emulation: false,
      feature_gates: [],
      workload_update_methods: [],
      uninstall_strategy: "BlockUninstallIfWorkloadsExist",
    }),
  );
  const doc = parse(cr) as Record<string, unknown>;
  assertEquals(doc.apiVersion, "kubevirt.io/v1");
  assertEquals(doc.kind, "KubeVirt");
  assertEquals((doc.metadata as { name: string }).name, KUBEVIRT_CR_NAME);
  const spec = doc.spec as Record<string, unknown>;
  assertEquals(spec.uninstallStrategy, "BlockUninstallIfWorkloadsExist");
  assertEquals(spec.workloadUpdateStrategy, undefined);
  assertEquals(
    (spec.configuration as { developerConfiguration: unknown })
      .developerConfiguration,
    { useEmulation: false },
  );
});

Deno.test("the KubeVirt CR sorts gates and update methods", () => {
  const cr = renderKubeVirtCr({
    use_emulation: true,
    feature_gates: ["Zeta", "Alpha"],
    workload_update_methods: ["LiveMigrate", "Evict"],
    uninstall_strategy: "RemoveWorkloads",
  });
  const spec = (parse(cr) as { spec: Record<string, unknown> }).spec;
  const dev = (spec.configuration as {
    developerConfiguration: { useEmulation: boolean; featureGates: string[] };
  }).developerConfiguration;
  assertEquals(dev.useEmulation, true);
  assertEquals(dev.featureGates, ["Alpha", "Zeta"]);
  assertEquals(
    (spec.workloadUpdateStrategy as { workloadUpdateMethods: string[] })
      .workloadUpdateMethods,
    ["Evict", "LiveMigrate"],
  );
});

const CONTAINER_VM: VmInput = {
  namespace: "app",
  name: "vm-1",
  source: { kind: "container_disk", image: `quay.io/example/disk@${DIGEST}` },
  cpu_cores: 2,
  memory: "2Gi",
  run_strategy: "Halted",
};

Deno.test("a containerDisk VM never writes spec.running", () => {
  const doc = vmDocument(CONTAINER_VM);
  const spec = doc.spec as Record<string, unknown>;
  assertEquals(spec.runStrategy, "Halted");
  assertEquals("running" in spec, false);
  const template = spec.template as {
    metadata: { labels: Record<string, string> };
    spec: {
      domain: {
        cpu: { cores: number };
        resources: { requests: { memory: string } };
      };
      volumes: Record<string, unknown>[];
    };
  };
  assertEquals(template.metadata.labels["kubevirt.io/domain"], "vm-1");
  assertEquals(template.spec.domain.cpu.cores, 2);
  assertEquals(template.spec.domain.resources.requests.memory, "2Gi");
  assertEquals(template.spec.volumes[0].containerDisk, {
    image: `quay.io/example/disk@${DIGEST}`,
  });
  assert(!renderVm(CONTAINER_VM).includes("running:"));
});

Deno.test("a cloud-init Secret becomes a userDataSecretRef volume and disk", () => {
  const doc = vmDocument({
    ...CONTAINER_VM,
    cloud_init_secret: "vm-cloud-init",
  });
  const spec = (doc.spec as { template: { spec: Record<string, unknown>[] } })
    .template.spec as unknown as {
      domain: { devices: { disks: Record<string, unknown>[] } };
      volumes: Record<string, unknown>[];
    };
  assertEquals(spec.domain.devices.disks.length, 2);
  assertEquals(spec.volumes[1], {
    name: "cloudinitdisk",
    cloudInitNoCloud: { userDataSecretRef: { name: "vm-cloud-init" } },
  });
  // The Secret content is never in the document; only its name is.
  assert(
    !renderVm({ ...CONTAINER_VM, cloud_init_secret: "vm-cloud-init" })
      .includes("userData:"),
  );
});

Deno.test("a DataVolume VM renders a dataVolumeTemplates entry", () => {
  const doc = vmDocument({
    ...CONTAINER_VM,
    source: {
      kind: "data_volume",
      source: { kind: "http", url: "https://images.example.com/disk.img" },
      size: "20Gi",
      storage_class: "local-path",
    },
  });
  const spec = doc.spec as { dataVolumeTemplates: Record<string, unknown>[] };
  const tpl = spec.dataVolumeTemplates[0];
  assertEquals((tpl.metadata as { name: string }).name, "vm-1-dv");
  const tspec = tpl.spec as Record<string, unknown>;
  assertEquals(tspec.source, {
    http: { url: "https://images.example.com/disk.img" },
  });
  const pvc = tspec.pvc as Record<string, unknown>;
  assertEquals(pvc.storageClassName, "local-path");
  assertEquals(
    (pvc.resources as { requests: { storage: string } }).requests.storage,
    "20Gi",
  );
});

Deno.test("a registry DataVolume source is rendered as docker://", () => {
  const doc = vmDocument({
    ...CONTAINER_VM,
    source: {
      kind: "data_volume",
      source: { kind: "registry", image: `quay.io/example/disk@${DIGEST}` },
      size: "10Gi",
    },
  });
  const tpl = (doc.spec as { dataVolumeTemplates: Record<string, unknown>[] })
    .dataVolumeTemplates[0];
  assertEquals((tpl.spec as { source: unknown }).source, {
    registry: { url: `docker://quay.io/example/disk@${DIGEST}` },
  });
});

Deno.test("stableJson sorts keys at every depth and vmSpecSha256 is order independent", async () => {
  assertEquals(
    stableJson({ b: 1, a: [2, { d: 4, c: 3 }] }),
    '{"a":[2,{"c":3,"d":4}],"b":1}',
  );
  const a = await vmSpecSha256(CONTAINER_VM);
  const b = await vmSpecSha256({
    ...CONTAINER_VM,
    source: {
      kind: "container_disk",
      image: CONTAINER_VM.source.kind === "container_disk"
        ? CONTAINER_VM.source.image
        : "",
    },
  });
  assertEquals(a, b);
  assertEquals(a.length, 64);
  const changed = await vmSpecSha256({ ...CONTAINER_VM, cpu_cores: 3 });
  assert(a !== changed);
});

Deno.test("the CDI custom resource is a minimal deterministic document", () => {
  const cr = renderCdiCr();
  assertEquals(cr, renderCdiCr());
  const doc = parse(cr) as Record<string, unknown>;
  assertEquals(doc.apiVersion, "cdi.kubevirt.io/v1beta1");
  assertEquals(doc.kind, "CDI");
  assertEquals((doc.metadata as { name: string }).name, CDI_CR_NAME);
  assertEquals((doc.metadata as { namespace: string }).namespace, "cdi");
  assertEquals(doc.spec, {});
});
