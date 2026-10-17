import { assert, assertEquals, assertRejects } from "jsr:@std/assert@1.0.19";
import { createModelTestContext } from "jsr:@swamp-club/swamp-testing@0.20261014.55";
import { isHttpUrl, model } from "./kubevirt_vm.ts";
import { type KubectlResult, KubevirtError, setDeps } from "./_lib/k8s.ts";

const KC = `apiVersion: v1
kind: Config
current-context: c
clusters:
- name: k
  cluster: {server: "https://192.0.2.10:6443"}
contexts:
- name: c
  context: {cluster: k, user: u}
users:
- name: u
  user: {token: placeholder}
`;

const CANONICAL = JSON.stringify({
  apiVersion: "v1",
  kind: "Config",
  clusters: [{ name: "k", cluster: { server: "https://192.0.2.10:6443" } }],
  contexts: [{ name: "c", context: { cluster: "k", user: "u" } }],
  users: [{ name: "u", user: { token: "placeholder" } }],
  "current-context": "c",
});

const DIGEST = "sha256:" + "a".repeat(64);

const vmJson = (
  opts: {
    runStrategy?: string;
    running?: boolean;
    generation?: number;
    uid?: string;
    printable?: string;
    dv?: boolean;
  } = {},
) =>
  JSON.stringify({
    apiVersion: "kubevirt.io/v1",
    kind: "VirtualMachine",
    metadata: {
      name: "vm-1",
      namespace: "app",
      uid: opts.uid ?? "u-1",
      generation: opts.generation ?? 1,
    },
    spec: {
      ...(opts.running !== undefined
        ? { running: opts.running }
        : { runStrategy: opts.runStrategy ?? "Halted" }),
      ...(opts.dv
        ? { dataVolumeTemplates: [{ metadata: { name: "vm-1-dv" } }] }
        : {}),
      template: {
        spec: {
          domain: {
            cpu: { cores: 1 },
            resources: { requests: { memory: "2Gi" } },
          },
        },
      },
    },
    status: {
      printableStatus: opts.printable ?? "Stopped",
      // Real conditions carry timestamps, reason and message too.
      conditions: [{
        type: "Ready",
        status: "False",
        lastProbeTime: null,
        lastTransitionTime: "2026-10-17T12:00:00Z",
        reason: "VMINotExists",
        message: "VMI does not exist",
      }],
    },
  });

const vmiJson = (
  opts: {
    uid?: string;
    phase?: string;
    ready?: boolean;
    agent?: boolean;
    node?: string;
  } = {},
) =>
  JSON.stringify({
    metadata: { uid: opts.uid ?? "vmi-1" },
    status: {
      phase: opts.phase ?? "Running",
      nodeName: opts.node ?? "node-1",
      interfaces: [{ ipAddress: "192.0.2.50" }],
      conditions: [
        { type: "Ready", status: opts.ready === false ? "False" : "True" },
        { type: "AgentConnected", status: opts.agent ? "True" : "False" },
      ],
    },
  });

const dvJson = (phase = "Succeeded", progress = "100.0%") =>
  JSON.stringify({
    metadata: { name: "vm-1-dv" },
    status: { phase, progress },
  });

type Call = { args: string[]; stdin?: string };

function testCtx() {
  return createModelTestContext({
    globalArgs: {},
    definition: { name: "test-kubevirt-vm" },
  });
}

function harness(route: (c: Call) => Partial<KubectlResult>) {
  const calls: Call[] = [];
  const written: string[] = [];
  const removed: string[] = [];
  let t = 0;
  const prev = setDeps({
    now: () => new Date(t),
    sleep: (ms) => {
      t += ms;
      return Promise.resolve();
    },
    files: {
      write: () => {
        const p = `/tmp/kc-${written.length + 1}`;
        written.push(p);
        return Promise.resolve(p);
      },
      remove: (p) => {
        removed.push(p);
        return Promise.resolve();
      },
    },
    run: (args, opts) => {
      if (args[0] === "config") {
        return Promise.resolve({ code: 0, stdout: CANONICAL, stderr: "" });
      }
      const c = { args, stdin: opts.stdin };
      calls.push(c);
      return Promise.resolve({ code: 0, stdout: "", stderr: "", ...route(c) });
    },
  });
  return {
    calls,
    written,
    removed,
    restore: () => setDeps(prev),
  };
}

const verb = (c: Call) => c.args[0];
const sub = (c: Call) => c.args[1] ?? "";
const nsOf = (c: Call): string | undefined => {
  const i = c.args.indexOf("--namespace");
  return i >= 0 ? c.args[i + 1] : undefined;
};

/** A present CDI DataVolume CRD, so a DataVolume define can proceed. */
const CRD = JSON.stringify({
  kind: "CustomResourceDefinition",
  metadata: { name: "datavolumes.cdi.kubevirt.io" },
});
const argv = (h: { calls: Call[] }) =>
  h.calls.map((c) => c.args.join(" ")).join("\n");

const CONTAINER = {
  kubeconfig: KC,
  namespace: "app",
  name: "vm-1",
  container_disk: { image: `quay.io/example/disk@${DIGEST}` },
  run_strategy: "Halted",
  timeout_s: 10,
} as const;

const readRoute =
  (vm: string | null, vmi: string | null, dv: string | null) =>
  (c: Call): Partial<KubectlResult> => {
    if (verb(c) === "get" && sub(c) === "vm") return { stdout: vm ?? "" };
    if (verb(c) === "get" && sub(c) === "vmi") return { stdout: vmi ?? "" };
    if (verb(c) === "get" && sub(c) === "datavolume") {
      return { stdout: dv ?? "" };
    }
    if (verb(c) === "get" && sub(c) === "crd") return { stdout: CRD };
    return {};
  };

Deno.test("schema: exactly one source, digest-pinned image, bounded memory", () => {
  const both = model.methods.define.arguments.safeParse({
    ...CONTAINER,
    data_volume: {
      source: { http: { url: "https://x.test/d.img" } },
      size: "1Gi",
    },
  });
  assertEquals(both.success, false);
  const neither = model.methods.define.arguments.safeParse({
    kubeconfig: KC,
    namespace: "app",
    name: "vm-1",
  });
  assertEquals(neither.success, false);
  const tag = model.methods.define.arguments.safeParse({
    ...CONTAINER,
    container_disk: { image: "quay.io/example/disk:v1" },
  });
  assertEquals(tag.success, false);
  const mem = model.methods.define.arguments.safeParse({
    ...CONTAINER,
    memory: "2G",
  });
  assertEquals(mem.success, false);
  // A URL credential would land in the VM spec and in state.
  const userinfo = model.methods.define.arguments.safeParse({
    ...CONTAINER,
    container_disk: undefined,
    data_volume: {
      source: { http: { url: "https://user:pass@images.test/d.img" } },
      size: "1Gi",
    },
  });
  assertEquals(userinfo.success, false);
  assertEquals(isHttpUrl("https://images.test/d.img"), true);
  const good = [
    "http://images.test/disk.img",
    "https://images.test:8443/a/b.img",
    "https://user-host.example.com/d.img",
  ];
  const bad = [
    "ftp://images.test/d.img",
    "http://user:pass@images.test/d.img",
    "https://user%40example.com@images.test/d.img",
    "http://images.test/d.img?tok=1",
    "http://images.test/d.img#frag",
    "http://a\\:secret@host.test/x",
    "http://h.test/a@b",
    "https://images.test/d img",
    "https://images.test/d\timg",
  ];
  for (const u of good) assertEquals(isHttpUrl(u), true, u);
  for (const u of bad) assertEquals(isHttpUrl(u), false, u);
  const ok = model.methods.define.arguments.parse(CONTAINER) as {
    run_strategy: string;
    cpu_cores: number;
  };
  assertEquals(ok.run_strategy, "Halted");
  assertEquals(ok.cpu_cores, 1);
});

Deno.test("render_vm is pure and deterministic", async () => {
  const ctx = testCtx();
  const out = await model.methods.render_vm.execute({
    namespace: "app",
    name: "vm-1",
    container_disk: { image: `quay.io/example/disk@${DIGEST}` },
    run_strategy: "Halted",
  }, ctx.context) as { result: { yaml: string; sha256: string } };
  assert(out.result.yaml.includes("kind: VirtualMachine"));
  assert(out.result.yaml.includes("runStrategy: Halted"));
  assert(!out.result.yaml.includes("running:"));
  assertEquals(out.result.sha256.length, 64);
});

Deno.test("define applies the VM on stdin and never writes spec.running", async () => {
  let applied = false;
  const h = harness((c) => {
    if (verb(c) === "apply") {
      applied = true;
      return { stdout: "configured\n" };
    }
    return readRoute(applied ? vmJson() : null, null, null)(c);
  });
  try {
    const ctx = testCtx();
    const out = await model.methods.define.execute(CONTAINER, ctx.context) as {
      result: Record<string, unknown>;
    };
    const apply = h.calls.find((c) => verb(c) === "apply")!;
    assert(apply.args.includes("--server-side"));
    assert(apply.stdin!.includes("runStrategy: Halted"));
    assert(!apply.stdin!.includes("running:"));
    assertEquals(out.result.name, "vm-1");
    assertEquals(out.result.run_strategy, "Halted");
    assertEquals(out.result.generation, 1);
    assertEquals((out.result.spec_sha256 as string).length, 64);
    assert(!argv(h).includes("kind: Config"));
    assertEquals(h.removed, h.written);
  } finally {
    h.restore();
  }
});

Deno.test("define refuses an existing VM that uses the deprecated spec.running", async () => {
  const h = harness(readRoute(vmJson({ running: true }), null, null));
  try {
    const ctx = testCtx();
    const e = await assertRejects(
      () => model.methods.define.execute(CONTAINER, ctx.context),
      KubevirtError,
    );
    assertEquals((e as KubevirtError).code, "running_field");
    assertEquals(h.calls.some((c) => verb(c) === "apply"), false);
  } finally {
    h.restore();
  }
});

Deno.test("define with a DataVolume records the DataVolume name", async () => {
  let applied = false;
  const h = harness((c) => {
    if (verb(c) === "apply") {
      applied = true;
      return { stdout: "" };
    }
    return readRoute(
      applied ? vmJson({ dv: true }) : null,
      null,
      dvJson("Pending", "0.0%"),
    )(c);
  });
  try {
    const ctx = testCtx();
    const out = await model.methods.define.execute({
      ...CONTAINER,
      container_disk: undefined,
      data_volume: {
        source: { http: { url: "https://images.example.com/d.img" } },
        size: "20Gi",
      },
    }, ctx.context) as { result: { uid: string } };
    assertEquals(out.result.uid, "u-1");
    assert(h.calls.some((c) => verb(c) === "get" && sub(c) === "datavolume"));
    // Every call is scoped to the VM's namespace.
    assertEquals(nsOf(h.calls[0]), "app");
  } finally {
    h.restore();
  }
});

Deno.test("define refuses a DataVolume source when CDI is not installed", async () => {
  const h = harness((c) => {
    if (verb(c) === "get" && sub(c) === "crd") return { stdout: "" };
    if (verb(c) === "get" && sub(c) === "vm") return { stdout: "" };
    return {};
  });
  try {
    const ctx = testCtx();
    const e = await assertRejects(
      () =>
        model.methods.define.execute({
          ...CONTAINER,
          container_disk: undefined,
          data_volume: {
            source: { http: { url: "https://images.example.com/d.img" } },
            size: "20Gi",
          },
        }, ctx.context),
      KubevirtError,
    );
    assertEquals((e as KubevirtError).code, "crd_missing");
    assertEquals(h.calls.some((c) => verb(c) === "apply"), false);
  } finally {
    h.restore();
  }
});

Deno.test("start patches runStrategy to Always and waits", async () => {
  let strategy = "Halted";
  const h = harness((c) => {
    if (verb(c) === "patch") {
      const i = c.args.indexOf("-p");
      strategy = JSON.parse(c.args[i + 1]).spec.runStrategy;
      return { stdout: "patched\n" };
    }
    return readRoute(
      vmJson({ runStrategy: strategy, printable: "Running" }),
      vmiJson(),
      null,
    )(c);
  });
  try {
    const ctx = testCtx();
    const out = await model.methods.start.execute({
      kubeconfig: KC,
      namespace: "app",
      name: "vm-1",
      timeout_s: 10,
    }, ctx.context) as { result: { printable_status: string } };
    assertEquals(strategy, "Always");
    assertEquals(out.result.printable_status, "Running");
  } finally {
    h.restore();
  }
});

Deno.test("start is a no-op patch when already Always", async () => {
  const h = harness(
    readRoute(
      vmJson({ runStrategy: "Always", printable: "Running" }),
      vmiJson(),
      null,
    ),
  );
  try {
    const ctx = testCtx();
    await model.methods.start.execute({
      kubeconfig: KC,
      namespace: "app",
      name: "vm-1",
      timeout_s: 10,
    }, ctx.context);
    assertEquals(h.calls.some((c) => verb(c) === "patch"), false);
  } finally {
    h.restore();
  }
});

Deno.test("stop patches Halted and returns once no VMI exists", async () => {
  let vmi: string | null = vmiJson();
  const h = harness((c) => {
    if (verb(c) === "patch") {
      vmi = null;
      return { stdout: "patched\n" };
    }
    return readRoute(
      vmJson({ runStrategy: "Halted", printable: "Stopped" }),
      vmi,
      null,
    )(c);
  });
  try {
    const ctx = testCtx();
    const out = await model.methods.stop.execute({
      kubeconfig: KC,
      namespace: "app",
      name: "vm-1",
      grace_s: 10,
    }, ctx.context) as { result: { printable_status: string } };
    assertEquals(vmi, null);
    assertEquals(out.result.printable_status, "Stopped");
  } finally {
    h.restore();
  }
});

Deno.test("restart refuses a Halted VM", async () => {
  const h = harness(
    readRoute(vmJson({ runStrategy: "Halted" }), vmiJson(), null),
  );
  try {
    const ctx = testCtx();
    const e = await assertRejects(
      () =>
        model.methods.restart.execute({
          kubeconfig: KC,
          namespace: "app",
          name: "vm-1",
        }, ctx.context),
      KubevirtError,
    );
    assertEquals((e as KubevirtError).code, "restart_halted");
    assertEquals(h.calls.some((c) => verb(c) === "replace"), false);
  } finally {
    h.restore();
  }
});

Deno.test("restart calls the restart subresource with an empty body", async () => {
  let uid = "vmi-before";
  const h = harness((c) => {
    if (verb(c) === "replace") {
      uid = "vmi-after";
      return { stdout: "" };
    }
    return readRoute(
      vmJson({ runStrategy: "Always", printable: "Running" }),
      vmiJson({ uid }),
      null,
    )(c);
  });
  try {
    const ctx = testCtx();
    const out = await model.methods.restart.execute({
      kubeconfig: KC,
      namespace: "app",
      name: "vm-1",
    }, ctx.context) as {
      result: { vmi_uid_before: string; vmi_uid_after: string };
    };
    const replace = h.calls.find((c) => verb(c) === "replace")!;
    assert(replace.args.includes("--raw"));
    assert(replace.args.some((a) => a.includes("subresources.kubevirt.io/v1")));
    assertEquals(replace.stdin, "");
    assertEquals(out.result.vmi_uid_before, "vmi-before");
    assertEquals(out.result.vmi_uid_after, "vmi-after");
  } finally {
    h.restore();
  }
});

Deno.test("wait_ready needs Running, Ready and a Succeeded DataVolume", async () => {
  const h = harness(
    readRoute(vmJson({ printable: "Running", dv: true }), vmiJson(), dvJson()),
  );
  try {
    const ctx = testCtx();
    const out = await model.methods.wait_ready.execute({
      kubeconfig: KC,
      namespace: "app",
      name: "vm-1",
      timeout_s: 10,
    }, ctx.context) as {
      result: { ready: boolean; dv_phase: string; interfaces: string[] };
    };
    assertEquals(out.result.ready, true);
    assertEquals(out.result.dv_phase, "Succeeded");
    assertEquals(out.result.interfaces, ["192.0.2.50"]);
  } finally {
    h.restore();
  }
});

Deno.test("wait_ready returns ready:false for an unschedulable VM, never throws", async () => {
  const h = harness(
    readRoute(vmJson({ printable: "ErrorUnschedulable" }), null, null),
  );
  try {
    const ctx = testCtx();
    const out = await model.methods.wait_ready.execute({
      kubeconfig: KC,
      namespace: "app",
      name: "vm-1",
      timeout_s: 10,
    }, ctx.context) as { result: { ready: boolean; printable_status: string } };
    assertEquals(out.result.ready, false);
    assertEquals(out.result.printable_status, "ErrorUnschedulable");
  } finally {
    h.restore();
  }
});

Deno.test("get reports the VM and VMI; get refuses when absent", async () => {
  const h = harness(
    readRoute(vmJson({ printable: "Running" }), vmiJson(), null),
  );
  try {
    const ctx = testCtx();
    const out = await model.methods.get.execute({
      kubeconfig: KC,
      namespace: "app",
      name: "vm-1",
    }, ctx.context) as { result: Record<string, unknown> };
    assertEquals(out.result.printable_status, "Running");
    assertEquals(out.result.node, "node-1");
  } finally {
    h.restore();
  }
});

Deno.test("sync records not_found when the VM is absent", async () => {
  const h = harness(readRoute(null, null, null));
  try {
    const ctx = testCtx();
    const out = await model.methods.sync.execute({
      kubeconfig: KC,
      namespace: "app",
      name: "vm-1",
    }, ctx.context) as { result: { status: string } };
    assertEquals(out.result.status, "not_found");
  } finally {
    h.restore();
  }
});

Deno.test("delete requires confirm when the VM owns a DataVolume", async () => {
  const h = harness(readRoute(vmJson({ dv: true }), null, null));
  try {
    const ctx = testCtx();
    const e = await assertRejects(
      () =>
        model.methods.delete.execute({
          kubeconfig: KC,
          namespace: "app",
          name: "vm-1",
        }, ctx.context),
      KubevirtError,
    );
    assertEquals((e as KubevirtError).code, "invalid_input");
    assertEquals(h.calls.some((c) => verb(c) === "delete"), false);
  } finally {
    h.restore();
  }
});

Deno.test("delete removes the VM with confirm and is a no-op when absent", async () => {
  const present = harness((c) => {
    if (verb(c) === "delete") return { stdout: "deleted\n" };
    return readRoute(vmJson({ dv: true }), null, null)(c);
  });
  try {
    const ctx = testCtx();
    const out = await model.methods.delete.execute({
      kubeconfig: KC,
      namespace: "app",
      name: "vm-1",
      confirm: "vm-1",
    }, ctx.context) as { result: { status: string } };
    assertEquals(out.result.status, "deleted");
  } finally {
    present.restore();
  }
  const absent = harness(readRoute(null, null, null));
  try {
    const ctx = testCtx();
    const out = await model.methods.delete.execute({
      kubeconfig: KC,
      namespace: "app",
      name: "vm-1",
    }, ctx.context) as { result: { status: string } };
    assertEquals(out.result.status, "not_found");
    assertEquals(absent.calls.some((c) => verb(c) === "delete"), false);
  } finally {
    absent.restore();
  }
});

Deno.test("the cloud-init Secret name reaches only the manifest, never argv", async () => {
  let applied = false;
  const h = harness((c) => {
    if (verb(c) === "apply") {
      applied = true;
      return { stdout: "" };
    }
    return readRoute(applied ? vmJson() : null, null, null)(c);
  });
  try {
    const ctx = testCtx();
    await model.methods.define.execute({
      ...CONTAINER,
      cloud_init_secret: "vm-cloud-init",
    }, ctx.context);
    const apply = h.calls.find((c) => verb(c) === "apply")!;
    assert(apply.stdin!.includes("userDataSecretRef"));
    assert(apply.args.join(" ").includes("vm-cloud-init") === false);
    assert(!argv(h).includes("kind: CloudInit"));
  } finally {
    h.restore();
  }
});
