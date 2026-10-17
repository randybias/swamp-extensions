import { assert, assertEquals, assertRejects } from "jsr:@std/assert@1.0.19";
import { createModelTestContext } from "jsr:@swamp-club/swamp-testing@0.20261014.55";
import { model } from "./kubevirt.ts";
import {
  clusterFingerprint16,
  type KubectlResult,
  KubevirtError,
  operatorStateKey,
  setDeps,
} from "./_lib/k8s.ts";

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

const MANIFEST =
  "apiVersion: v1\nkind: Namespace\nmetadata: {name: kubevirt}\n";

const crJson = (
  opts: {
    version?: string;
    phase?: string;
    available?: string;
    progressing?: string;
    degraded?: string;
    outdated?: number;
    useEmulation?: boolean;
  } = {},
) =>
  JSON.stringify({
    apiVersion: "kubevirt.io/v1",
    kind: "KubeVirt",
    metadata: { name: "kubevirt", namespace: "kubevirt" },
    spec: {
      configuration: {
        developerConfiguration: {
          useEmulation: opts.useEmulation ?? false,
          featureGates: ["LiveMigration"],
        },
      },
      uninstallStrategy: "BlockUninstallIfWorkloadsExist",
    },
    status: {
      phase: opts.phase ?? "Deployed",
      observedKubeVirtVersion: opts.version ?? "v1.2.3",
      outdatedVirtualMachineInstanceWorkloads: opts.outdated ?? 0,
      conditions: [
        { type: "Available", status: opts.available ?? "True" },
        { type: "Progressing", status: opts.progressing ?? "False" },
        { type: "Degraded", status: opts.degraded ?? "False" },
      ],
    },
  });

const nodeList = JSON.stringify({
  items: [
    {
      metadata: {
        name: "node-1",
        labels: { "kubevirt.io/schedulable": "true" },
      },
      status: { allocatable: { "devices.kubevirt.io/kvm": "1" } },
    },
    {
      metadata: {
        name: "node-2",
        labels: { "kubevirt.io/schedulable": "true" },
      },
      status: { allocatable: {} },
    },
  ],
});

type Call = { args: string[]; stdin?: string };

function testCtx(
  options: { storedResources?: Record<string, Record<string, unknown>> } = {},
) {
  return createModelTestContext({
    globalArgs: {},
    definition: { name: "test-kubevirt" },
    ...options,
  });
}

interface HarnessOptions {
  fetch?: (url: string) => { status: number; body: string };
  storedResources?: Record<string, unknown>;
}

function harness(
  route: (c: Call) => Partial<KubectlResult>,
  o: HarnessOptions = {},
) {
  const calls: Call[] = [];
  const written: string[] = [];
  const contents: string[] = [];
  const removed: string[] = [];
  const fetched: string[] = [];
  let t = 0;
  const prev = setDeps({
    now: () => new Date(t),
    sleep: (ms) => {
      t += ms;
      return Promise.resolve();
    },
    files: {
      write: (content) => {
        contents.push(content);
        const p = `/tmp/kc-${written.length + 1}`;
        written.push(p);
        return Promise.resolve(p);
      },
      remove: (p) => {
        removed.push(p);
        return Promise.resolve();
      },
    },
    fetch: (url) => {
      fetched.push(url);
      return Promise.resolve(
        o.fetch ? o.fetch(url) : { status: 404, body: "" },
      );
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
    contents,
    removed,
    fetched,
    restore: () => setDeps(prev),
  };
}

const verb = (c: Call) => c.args[0];
const sub = (c: Call) => c.args[1] ?? "";
const nsOf = (c: Call): string | undefined => {
  const i = c.args.indexOf("--namespace");
  return i >= 0 ? c.args[i + 1] : undefined;
};
const argv = (h: { calls: Call[] }) =>
  h.calls.map((c) => c.args.join(" ")).join("\n");

async function sha256(s: string): Promise<string> {
  const d = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s));
  return [...new Uint8Array(d)].map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

const MANIFEST_SHA = await sha256(MANIFEST);
const INSTALL = {
  kubeconfig: KC,
  kubevirt_version: "v1.2.3",
  operator_manifest_sha256: MANIFEST_SHA,
  timeout_s: 10,
};

const getRoute = (cr: string | null, nodes = nodeList) =>
(
  c: Call,
): Partial<KubectlResult> => {
  if (verb(c) === "get" && sub(c) === "kubevirt") {
    return { stdout: cr ?? "" };
  }
  if (verb(c) === "get" && sub(c) === "nodes") return { stdout: nodes };
  if (verb(c) === "get" && sub(c) === "cdi") return { stdout: "" };
  return {};
};

Deno.test("schema: kubeconfig is sensitive, install defaults are bounded", () => {
  type Field = { meta(): { sensitive?: boolean } | undefined };
  const shape = (model.methods.install.arguments as unknown as {
    shape: Record<string, Field>;
  }).shape;
  assertEquals(shape.kubeconfig.meta()?.sensitive, true);
  const parsed = model.methods.install.arguments.parse(INSTALL) as {
    use_emulation: boolean;
    feature_gates: string[];
    install_cdi: boolean;
    timeout_s: number;
  };
  assertEquals(parsed.use_emulation, false);
  assertEquals(parsed.feature_gates, []);
  assertEquals(parsed.install_cdi, false);
  assertEquals(parsed.timeout_s, 10);
  const defaults = model.methods.install.arguments.parse({
    kubeconfig: KC,
    kubevirt_version: "v1.2.3",
    operator_manifest_sha256: MANIFEST_SHA,
  }) as { timeout_s: number };
  assertEquals(defaults.timeout_s, 600);
});

Deno.test("install requires the CDI version and digest when install_cdi", () => {
  const r = model.methods.install.arguments.safeParse({
    ...INSTALL,
    install_cdi: true,
  });
  assertEquals(r.success, false);
});

Deno.test("install verifies the manifest and applies it and the CR on stdin", async () => {
  let applied = false;
  const stateful = harness((c) => {
    if (verb(c) === "apply") applied = true;
    return getRoute(applied ? crJson() : null)(c);
  }, {
    fetch: (url) =>
      url.includes("kubevirt-operator")
        ? { status: 200, body: MANIFEST }
        : { status: 404, body: "" },
  });
  try {
    const ctx = testCtx();
    const out = await model.methods.install.execute(INSTALL, ctx.context) as {
      result: Record<string, unknown>;
    };
    const applyCalls = stateful.calls.filter((c) => verb(c) === "apply");
    assertEquals(applyCalls.length, 2);
    assertEquals(applyCalls[0].stdin, MANIFEST);
    assert(applyCalls[1].stdin!.includes("kind: KubeVirt"));
    assert(applyCalls[0].args.includes("--server-side"));
    assert(
      applyCalls[0].args.some((a) =>
        a.startsWith("--field-manager=swamp-kubevirt-")
      ),
    );
    const all = argv(stateful);
    assert(!all.includes("kind: Config"));
    assert(!all.includes("kind: Namespace"));
    assertEquals(out.result.kubevirt_version, "v1.2.3");
    assertEquals(out.result.operator_sha256, MANIFEST_SHA);
    // Every call is scoped to the KubeVirt namespace; withKubectl appends
    // --namespace itself, so a per-call -n would have been overridden.
    assertEquals(stateful.calls.every((c) => nsOf(c) === "kubevirt"), true);
    assertEquals(stateful.removed, stateful.written);
  } finally {
    stateful.restore();
  }
});

Deno.test("a manifest SHA mismatch refuses before any apply", async () => {
  const h = harness(getRoute(null), {
    fetch: () => ({ status: 200, body: MANIFEST }),
  });
  try {
    const ctx = testCtx();
    const e = await assertRejects(
      () =>
        model.methods.install.execute(
          { ...INSTALL, operator_manifest_sha256: "0".repeat(64) },
          ctx.context,
        ),
      KubevirtError,
    );
    assertEquals((e as KubevirtError).code, "manifest_mismatch");
    assertEquals(h.calls.some((c) => verb(c) === "apply"), false);
    assert(!(e as Error).message.includes("kind: Namespace"));
  } finally {
    h.restore();
  }
});

Deno.test("a manifest fetch failure is typed and names the URL only", async () => {
  const h = harness(getRoute(null), {
    fetch: () => ({ status: 404, body: "" }),
  });
  try {
    const ctx = testCtx();
    const e = await assertRejects(
      () => model.methods.install.execute(INSTALL, ctx.context),
      KubevirtError,
    );
    assertEquals((e as KubevirtError).code, "manifest_fetch");
    assert((e as Error).message.includes("kubevirt-operator.yaml"));
    assertEquals(h.calls.some((c) => verb(c) === "apply"), false);
  } finally {
    h.restore();
  }
});

Deno.test("install refuses a different installed version and points to upgrade", async () => {
  const h = harness(getRoute(crJson({ version: "v1.0.0" })));
  try {
    const ctx = testCtx();
    const e = await assertRejects(
      () => model.methods.install.execute(INSTALL, ctx.context),
      KubevirtError,
    );
    assertEquals((e as KubevirtError).code, "version_conflict");
    assert((e as Error).message.includes("upgrade"));
    assertEquals(h.fetched.length, 0);
    assertEquals(h.calls.some((c) => verb(c) === "apply"), false);
  } finally {
    h.restore();
  }
});

Deno.test("install adopts the same version and re-applies idempotently", async () => {
  const h = harness(getRoute(crJson({ version: "v1.2.3" })), {
    fetch: () => ({ status: 200, body: MANIFEST }),
  });
  try {
    const ctx = testCtx();
    await model.methods.install.execute(INSTALL, ctx.context);
    // Two applies (operator + CR) even when adopting: server-side apply is a no-op.
    assertEquals(h.calls.filter((c) => verb(c) === "apply").length, 2);
  } finally {
    h.restore();
  }
});

Deno.test("install_cdi fetches and applies the CDI manifest too", async () => {
  const cdi = "apiVersion: v1\nkind: Namespace\nmetadata: {name: cdi}\n";
  const cdiSha = await sha256(cdi);
  const h = harness(getRoute(null), {
    fetch: (url) =>
      url.includes("kubevirt-operator")
        ? { status: 200, body: MANIFEST }
        : { status: 200, body: cdi },
  });
  try {
    const { context, getWrittenResources } = testCtx();
    await model.methods.install.execute({
      ...INSTALL,
      install_cdi: true,
      cdi_version: "v1.2.3",
      cdi_operator_manifest_sha256: cdiSha,
    }, context);
    assertEquals(h.fetched.length, 2);
    assert(h.fetched.some((u) => u.includes("containerized-data-importer")));
    // operator + CR in the KubeVirt namespace, then CDI operator + CDI CR in
    // the CDI namespace.
    const applies = h.calls.filter((c) => verb(c) === "apply");
    assertEquals(applies.length, 4);
    assertEquals(nsOf(applies[0]), "kubevirt");
    assertEquals(nsOf(applies[1]), "kubevirt");
    assertEquals(nsOf(applies[2]), "cdi");
    assertEquals(nsOf(applies[3]), "cdi");
    assert(applies[3].stdin!.includes("kind: CDI"));
    // The install records that this model owns CDI.
    const state = getWrittenResources()[0].data as {
      cdi_installed_by_model?: boolean;
      cdi_operator_sha256?: string;
    };
    assertEquals(state.cdi_installed_by_model, true);
    assertEquals(state.cdi_operator_sha256, cdiSha);
  } finally {
    h.restore();
  }
});

Deno.test("install adopts an existing CDI without claiming it", async () => {
  const { context, getWrittenResources } = testCtx();
  const h = harness((c) => {
    if (verb(c) === "get" && sub(c) === "cdi") {
      return {
        stdout: JSON.stringify({ kind: "CDI", metadata: { name: "cdi" } }),
      };
    }
    return getRoute(null)(c);
  }, {
    fetch: (url) =>
      url.includes("kubevirt-operator")
        ? { status: 200, body: MANIFEST }
        : { status: 404, body: "" },
  });
  try {
    await model.methods.install.execute({
      ...INSTALL,
      install_cdi: true,
      cdi_version: "v1.2.3",
      cdi_operator_manifest_sha256: "a".repeat(64),
    }, context);
    // Only the KubeVirt operator + CR were applied; CDI was not fetched.
    assertEquals(h.fetched.length, 1);
    assertEquals(h.calls.filter((c) => verb(c) === "apply").length, 2);
    const state = getWrittenResources()[0].data as {
      cdi_installed_by_model?: boolean;
    };
    assertEquals(state.cdi_installed_by_model, false);
  } finally {
    h.restore();
  }
});

Deno.test("install without install_cdi preserves a prior CDI ownership record", async () => {
  const key = await operatorStateKey(KC);
  const { context, getWrittenResources } = testCtx({
    storedResources: {
      [key]: {
        cluster_fp: await fingerprint(),
        context: "current-context",
        cdi_version: "v1.2.3",
        cdi_installed_by_model: true,
        cdi_operator_sha256: "a".repeat(64),
        status: "present",
        observed_at: "2026-10-17T00:00:00.000Z",
      },
    },
  });
  const h = harness(getRoute(null), {
    fetch: () => ({ status: 200, body: MANIFEST }),
  });
  try {
    await model.methods.install.execute(INSTALL, context);
    const state = getWrittenResources()[0].data as {
      cdi_installed_by_model?: boolean;
      cdi_version?: string;
    };
    assertEquals(state.cdi_installed_by_model, true);
    assertEquals(state.cdi_version, "v1.2.3");
  } finally {
    h.restore();
  }
});

Deno.test("wait_ready reports ready with node facts", async () => {
  const h = harness(getRoute(crJson()));
  try {
    const ctx = testCtx();
    const out = await model.methods.wait_ready.execute({
      kubeconfig: KC,
      kubevirt_version: "v1.2.3",
      timeout_s: 10,
    }, ctx.context) as {
      result: {
        ready: boolean;
        schedulable_nodes: string[];
        kvm_nodes: string[];
      };
    };
    assertEquals(out.result.ready, true);
    assertEquals(out.result.schedulable_nodes, ["node-1", "node-2"]);
    assertEquals(out.result.kvm_nodes, ["node-1"]);
  } finally {
    h.restore();
  }
});

Deno.test("wait_ready returns ready:false after the timeout, never throws", async () => {
  const h = harness(
    getRoute(crJson({ phase: "Deploying", version: "v1.2.2" })),
  );
  try {
    const ctx = testCtx();
    const out = await model.methods.wait_ready.execute({
      kubeconfig: KC,
      kubevirt_version: "v1.2.3",
      timeout_s: 10,
    }, ctx.context) as { result: { ready: boolean; phase: string } };
    assertEquals(out.result.ready, false);
    assertEquals(out.result.phase, "Deploying");
  } finally {
    h.restore();
  }
});

Deno.test("upgrade refuses a downgrade and a multi-minor jump", async () => {
  for (
    const [from, to, code] of [
      ["v1.3.0", "v1.2.0", "version_skew"],
      ["v1.2.0", "v1.4.0", "version_skew"],
    ] as const
  ) {
    const h = harness(getRoute(crJson({ version: from })));
    try {
      const ctx = testCtx();
      const e = await assertRejects(
        () =>
          model.methods.upgrade.execute({
            ...INSTALL,
            kubevirt_version: to,
          }, ctx.context),
        KubevirtError,
      );
      assertEquals((e as KubevirtError).code, code);
      assertEquals(h.calls.some((c) => verb(c) === "apply"), false);
    } finally {
      h.restore();
    }
  }
});

Deno.test("upgrade applies the new manifest and reports the outdated count", async () => {
  let version = "v1.2.0";
  const h = harness((c) => {
    if (verb(c) === "apply") {
      version = "v1.3.0";
      return { stdout: "applied\n" };
    }
    return getRoute(crJson({ version, outdated: 1 }))(c);
  }, {
    fetch: () => ({ status: 200, body: MANIFEST }),
  });
  try {
    const ctx = testCtx();
    const out = await model.methods.upgrade.execute({
      ...INSTALL,
      kubevirt_version: "v1.3.0",
      timeout_s: 10,
    }, ctx.context) as {
      result: { from: string; to: string; outdated_vmis: number };
    };
    assertEquals(out.result.from, "v1.2.0");
    assertEquals(out.result.to, "v1.3.0");
    assertEquals(out.result.outdated_vmis, 1);
  } finally {
    h.restore();
  }
});

Deno.test("get reports the install and its node facts", async () => {
  const h = harness(getRoute(crJson({ useEmulation: true })));
  try {
    const ctx = testCtx();
    const out = await model.methods.get.execute(
      { kubeconfig: KC },
      ctx.context,
    ) as {
      result: Record<string, unknown>;
    };
    assertEquals(out.result.kubevirt_version, "v1.2.3");
    assertEquals(out.result.use_emulation, true);
    assertEquals(out.result.feature_gates, ["LiveMigration"]);
    assertEquals(out.result.kvm_nodes, ["node-1"]);
  } finally {
    h.restore();
  }
});

Deno.test("get refuses when KubeVirt is absent; sync records not_found", async () => {
  const h = harness(getRoute(null));
  try {
    const ctx = testCtx();
    const e = await assertRejects(
      () => model.methods.get.execute({ kubeconfig: KC }, ctx.context),
      KubevirtError,
    );
    assertEquals((e as KubevirtError).code, "not_found");
    const out = await model.methods.sync.execute(
      { kubeconfig: KC },
      ctx.context,
    ) as {
      result: { status: string };
    };
    assertEquals(out.result.status, "not_found");
  } finally {
    h.restore();
  }
});

Deno.test("uninstall requires the cluster fingerprint as confirm", async () => {
  const h = harness(getRoute(crJson()));
  try {
    const fp = await fingerprint();
    const ctx = testCtx();
    const e = await assertRejects(
      () =>
        model.methods.uninstall.execute({
          ...INSTALL,
          confirm: "wrong",
        }, ctx.context),
      KubevirtError,
    );
    assertEquals((e as KubevirtError).code, "invalid_input");
    assert(fp.length === 16);
    assertEquals(h.calls.length, 0);
  } finally {
    h.restore();
  }
});

Deno.test("uninstall deletes the CR then the manifest objects", async () => {
  const h = harness(getRoute(crJson()), {
    fetch: () => ({ status: 200, body: MANIFEST }),
  });
  try {
    const fp = await fingerprint();
    const ctx = testCtx();
    const out = await model.methods.uninstall.execute({
      ...INSTALL,
      confirm: fp,
    }, ctx.context) as { result: { status: string } };
    assertEquals(out.result.status, "deleted");
    const delCr = h.calls.find((c) =>
      verb(c) === "delete" && sub(c) === "kubevirt"
    )!;
    assert(delCr.args.includes("--wait=true"));
    const delManifest = h.calls.find((c) =>
      verb(c) === "delete" && sub(c) === "-f"
    )!;
    assertEquals(delManifest.stdin, MANIFEST);
  } finally {
    h.restore();
  }
});

Deno.test("uninstall is a clean no-op when KubeVirt is absent", async () => {
  const h = harness(getRoute(null));
  try {
    const fp = await fingerprint();
    const ctx = testCtx();
    const out = await model.methods.uninstall.execute({
      ...INSTALL,
      confirm: fp,
    }, ctx.context) as { result: { status: string } };
    assertEquals(out.result.status, "not_found");
    assertEquals(h.calls.some((c) => verb(c) === "delete"), false);
  } finally {
    h.restore();
  }
});

Deno.test("uninstall surfaces a blocked delete as a typed error", async () => {
  const h = harness((c) => {
    if (verb(c) === "delete" && sub(c) === "kubevirt") {
      return {
        code: 1,
        stderr:
          "admission webhook denied the request: BlockUninstallIfWorkloadsExist",
      };
    }
    return getRoute(crJson())(c);
  }, {
    fetch: () => ({ status: 200, body: MANIFEST }),
  });
  try {
    const fp = await fingerprint();
    const ctx = testCtx();
    const e = await assertRejects(
      () =>
        model.methods.uninstall.execute(
          { ...INSTALL, confirm: fp },
          ctx.context,
        ),
      KubevirtError,
    );
    assertEquals((e as KubevirtError).code, "uninstall_blocked");
    assert((e as Error).message.includes("workloads"));
  } finally {
    h.restore();
  }
});

Deno.test("get preserves the CDI install-owned flag set by install", async () => {
  const key = await operatorStateKey(KC);
  const ctx = testCtx({
    storedResources: {
      [key]: {
        cluster_fp: await fingerprint(),
        context: "current-context",
        cdi_version: "v1.2.3",
        cdi_installed_by_model: true,
        cdi_operator_sha256: "a".repeat(64),
        status: "present",
        observed_at: "2026-10-17T00:00:00.000Z",
      },
    },
  });
  const h = harness(getRoute(crJson()));
  try {
    const out = await model.methods.get.execute(
      { kubeconfig: KC },
      ctx.context,
    ) as {
      result: { cdi_installed_by_model?: boolean };
    };
    assertEquals(out.result.cdi_installed_by_model, true);
  } finally {
    h.restore();
  }
});

Deno.test("uninstall with the CDI flag requires matching CDI inputs", async () => {
  const key = await operatorStateKey(KC);
  const ctx = testCtx({
    storedResources: {
      [key]: {
        cluster_fp: await fingerprint(),
        context: "current-context",
        cdi_installed_by_model: true,
        status: "present",
        observed_at: "2026-10-17T00:00:00.000Z",
      },
    },
  });
  const h = harness(getRoute(crJson()));
  try {
    const fp = await fingerprint();
    const e = await assertRejects(
      () =>
        model.methods.uninstall.execute(
          { ...INSTALL, confirm: fp },
          ctx.context,
        ),
      KubevirtError,
    );
    assertEquals((e as KubevirtError).code, "invalid_input");
    assertEquals(h.calls.length, 0);
  } finally {
    h.restore();
  }
});

Deno.test("uninstall deletes CDI only when this model installed it", async () => {
  const cdi = "apiVersion: v1\nkind: Namespace\nmetadata: {name: cdi}\n";
  const cdiSha = await sha256(cdi);
  const key = await operatorStateKey(KC);
  const ctx = testCtx({
    storedResources: {
      [key]: {
        cluster_fp: await fingerprint(),
        context: "current-context",
        cdi_version: "v1.2.3",
        cdi_installed_by_model: true,
        cdi_operator_sha256: cdiSha,
        status: "present",
        observed_at: "2026-10-17T00:00:00.000Z",
      },
    },
  });
  const h = harness((c) => {
    if (verb(c) === "get" && sub(c) === "cdi") {
      return {
        stdout: JSON.stringify({ kind: "CDI", metadata: { name: "cdi" } }),
      };
    }
    return getRoute(crJson())(c);
  }, {
    fetch: (url) =>
      url.includes("containerized-data-importer")
        ? { status: 200, body: cdi }
        : { status: 200, body: MANIFEST },
  });
  try {
    const fp = await fingerprint();
    const out = await model.methods.uninstall.execute({
      ...INSTALL,
      confirm: fp,
      cdi_version: "v1.2.3",
      cdi_operator_manifest_sha256: cdiSha,
    }, ctx.context) as { result: { status: string } };
    assertEquals(out.result.status, "deleted");
    const delCdi = h.calls.find((c) =>
      verb(c) === "delete" && sub(c) === "cdi"
    )!;
    assertEquals(nsOf(delCdi), "cdi");
    assert(delCdi.args.includes("--timeout=10s"));
    const manifestDeletes = h.calls.filter((c) =>
      verb(c) === "delete" && sub(c) === "-f"
    );
    assertEquals(manifestDeletes.length, 2);
    assertEquals(nsOf(manifestDeletes[1]), "cdi");
    assertEquals(manifestDeletes[1].stdin, cdi);
  } finally {
    h.restore();
  }
});

Deno.test("uninstall refuses a CDI version or digest that does not match the record", async () => {
  const key = await operatorStateKey(KC);
  const ctx = testCtx({
    storedResources: {
      [key]: {
        cluster_fp: await fingerprint(),
        context: "current-context",
        cdi_version: "v1.60.0",
        cdi_installed_by_model: true,
        cdi_operator_sha256: "a".repeat(64),
        status: "present",
        observed_at: "2026-10-17T00:00:00.000Z",
      },
    },
  });
  const h = harness(getRoute(crJson()), {
    fetch: () => ({ status: 200, body: MANIFEST }),
  });
  try {
    const fp = await fingerprint();
    const e = await assertRejects(
      () =>
        model.methods.uninstall.execute({
          ...INSTALL,
          confirm: fp,
          cdi_version: "v1.59.0",
          cdi_operator_manifest_sha256: "b".repeat(64),
        }, ctx.context),
      KubevirtError,
    );
    assertEquals((e as KubevirtError).code, "invalid_input");
    assert((e as Error).message.includes("must match"));
    assertEquals(h.calls.some((c) => verb(c) === "delete"), false);
  } finally {
    h.restore();
  }
});

Deno.test("uninstall deletes an owned CDI even when KubeVirt is already gone", async () => {
  const cdi = "apiVersion: v1\nkind: Namespace\nmetadata: {name: cdi}\n";
  const cdiSha = await sha256(cdi);
  const key = await operatorStateKey(KC);
  const ctx = testCtx({
    storedResources: {
      [key]: {
        cluster_fp: await fingerprint(),
        context: "current-context",
        cdi_version: "v1.2.3",
        cdi_installed_by_model: true,
        cdi_operator_sha256: cdiSha,
        status: "present",
        observed_at: "2026-10-17T00:00:00.000Z",
      },
    },
  });
  // KubeVirt is fully absent; only a CDI object remains.
  const h = harness((c) => {
    if (verb(c) === "get" && sub(c) === "cdi") {
      return {
        stdout: JSON.stringify({ kind: "CDI", metadata: { name: "cdi" } }),
      };
    }
    return getRoute(null)(c);
  }, {
    fetch: () => ({ status: 200, body: cdi }),
  });
  try {
    const fp = await fingerprint();
    const out = await model.methods.uninstall.execute({
      ...INSTALL,
      confirm: fp,
      cdi_version: "v1.2.3",
      cdi_operator_manifest_sha256: cdiSha,
    }, ctx.context) as { result: { status: string } };
    assertEquals(out.result.status, "deleted");
    // No KubeVirt manifest was fetched, but CDI was cleaned up.
    assertEquals(h.fetched.length, 1);
    assert(h.fetched[0].includes("containerized-data-importer"));
    assert(h.calls.some((c) => verb(c) === "delete" && sub(c) === "cdi"));
  } finally {
    h.restore();
  }
});

Deno.test("uninstall finishing when the CR is gone but the operator remains", async () => {
  // The custom resource is absent but the kubevirt namespace lingers.
  const h = harness((c) => {
    if (verb(c) === "get" && sub(c) === "namespace") {
      return {
        stdout: JSON.stringify({
          kind: "Namespace",
          metadata: { name: "kubevirt" },
        }),
      };
    }
    return getRoute(null)(c);
  }, {
    fetch: () => ({ status: 200, body: MANIFEST }),
  });
  try {
    const fp = await fingerprint();
    const ctx = testCtx();
    const out = await model.methods.uninstall.execute({
      ...INSTALL,
      confirm: fp,
    }, ctx.context) as { result: { status: string } };
    assertEquals(out.result.status, "deleted");
    assertEquals(
      h.calls.some((c) => verb(c) === "delete" && sub(c) === "kubevirt"),
      false,
    );
    const delManifest = h.calls.find((c) =>
      verb(c) === "delete" && sub(c) === "-f"
    )!;
    assertEquals(delManifest.stdin, MANIFEST);
  } finally {
    h.restore();
  }
});

Deno.test("render_cr is pure and writes only the rendered resource", async () => {
  const ctx = testCtx();
  const out = await model.methods.render_cr.execute({
    use_emulation: true,
    feature_gates: ["Alpha"],
    workload_update_methods: [],
    uninstall_strategy: "RemoveWorkloads",
  }, ctx.context) as { result: { yaml: string; sha256: string } };
  assert(out.result.yaml.includes("kind: KubeVirt"));
  assert(out.result.yaml.includes("useEmulation: true"));
  assertEquals(out.result.sha256.length, 64);
});

async function fingerprint(): Promise<string> {
  return await clusterFingerprint16(KC, undefined);
}

// The operator state key is derived from the fingerprint; assert the shape.
Deno.test("the uninstall state key is the fingerprint plus kubevirt", async () => {
  assertEquals(await operatorStateKey(KC), `${await fingerprint()}/kubevirt`);
});
