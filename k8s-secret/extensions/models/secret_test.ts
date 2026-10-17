import { assert, assertEquals, assertRejects } from "jsr:@std/assert@1.0.19";
import { createModelTestContext } from "jsr:@swamp-club/swamp-testing@0.20261014.55";
import { model, setDeps, stateName } from "./secret.ts";
import { b64, K8sSecretError, type KubectlResult } from "./_lib/kubectl.ts";

const KC = "apiVersion: v1\nkind: Config\nclusters: []\n";
const VAL = "placeholder-value-one";
const BASE = { kubeconfig: KC, namespace: "app", name: "db-creds" };
const APPLY = { ...BASE, data: { password: VAL, user: "svc" } };

interface Call {
  args: string[];
  stdin?: string;
  kubeconfigPath?: string;
}

function harness(route: (c: Call) => Partial<KubectlResult>) {
  const calls: Call[] = [];
  const written: string[] = [];
  const removed: string[] = [];
  const prev = setDeps({
    now: () => new Date("2026-10-17T00:00:00Z"),
    files: {
      write: (content) => {
        assertEquals(content, KC);
        const p = `/tmp/kc-${written.length}`;
        written.push(p);
        return Promise.resolve(p);
      },
      remove: (p) => {
        removed.push(p);
        return Promise.resolve();
      },
    },
    run: (args, o) => {
      const c = { args, stdin: o.stdin, kubeconfigPath: o.env.KUBECONFIG };
      calls.push(c);
      const r = route(c);
      return Promise.resolve({ code: 0, stdout: "", stderr: "", ...r });
    },
  });
  return { calls, written, removed, restore: () => setDeps(prev) };
}

const secretJson = (data: Record<string, string>, rv = "7", type = "Opaque") =>
  JSON.stringify({
    type,
    metadata: { resourceVersion: rv },
    data: Object.fromEntries(Object.entries(data).map(([k, v]) => [k, b64(v)])),
  });

const verb = (c: Call) => c.args[0];

Deno.test("schema: kubeconfig and every data value are sensitive", () => {
  const shape = (model.methods.apply.arguments as unknown as {
    shape: Record<string, { meta(): unknown }>;
  }).shape;
  assertEquals(
    (shape.kubeconfig.meta() as { sensitive: boolean }).sensitive,
    true,
  );
  const valueType = (shape.data as unknown as {
    valueType: { meta(): { sensitive?: boolean } };
  }).valueType;
  assertEquals(valueType.meta().sensitive, true);
});

Deno.test("apply creates: values on stdin only, never argv", async () => {
  let created = false;
  const h = harness((c) => {
    if (verb(c) === "get") {
      return created ? { stdout: secretJson(APPLY.data) } : { stdout: "" };
    }
    created = true;
    return { stdout: "secret/db-creds\n" };
  });
  try {
    const { context, getWrittenResources } = createModelTestContext({
      globalArgs: {},
    });
    const out = await model.methods.apply.execute(APPLY, context) as {
      result: Record<string, unknown>;
    };
    const ap = h.calls.find((c) => verb(c) === "apply")!;
    assert(ap.args.includes("-f") && ap.args.includes("-"));
    assert(!ap.args.some((a) => a.includes("from-literal")));
    const all = h.calls.map((c) => c.args.join(" ")).join("\n");
    assert(!all.includes(VAL) && !all.includes(b64(VAL)));
    const m = JSON.parse(ap.stdin!);
    assertEquals(m.data.password, b64(VAL));
    assertEquals(m.type, "Opaque");
    // output and stored state carry no value and no kubeconfig
    const dump = JSON.stringify([out.result, getWrittenResources()]);
    assert(!dump.includes(VAL) && !dump.includes(b64(VAL)));
    assert(!dump.includes("kind: Config"));
    assertEquals(out.result.keys, ["password", "user"]);
    assertEquals(typeof out.result.data_sha256, "string");
    assertEquals(h.removed, h.written);
  } finally {
    h.restore();
  }
});

Deno.test("apply is a no-op when data and type are identical", async () => {
  const h = harness((c) =>
    verb(c) === "get" ? { stdout: secretJson(APPLY.data) } : {}
  );
  try {
    const { context } = createModelTestContext({ globalArgs: {} });
    const out = await model.methods.apply.execute(APPLY, context) as {
      result: { resource_version: string };
    };
    assertEquals(h.calls.some((c) => verb(c) === "apply"), false);
    assertEquals(out.result.resource_version, "7");
  } finally {
    h.restore();
  }
});

Deno.test("apply updates when one key changes", async () => {
  let applied = false;
  const h = harness((c) => {
    if (verb(c) === "get") {
      return applied
        ? { stdout: secretJson(APPLY.data, "8") }
        : { stdout: secretJson({ ...APPLY.data, user: "old" }) };
    }
    applied = true;
    return { stdout: "secret/db-creds" };
  });
  try {
    const { context } = createModelTestContext({ globalArgs: {} });
    const out = await model.methods.apply.execute(APPLY, context) as {
      result: { resource_version: string };
    };
    assertEquals(out.result.resource_version, "8");
    assertEquals(h.calls.filter((c) => verb(c) === "apply").length, 1);
  } finally {
    h.restore();
  }
});

Deno.test("get returns hashes, never values", async () => {
  const h = harness(() => ({ stdout: secretJson(APPLY.data) }));
  try {
    const { context, getWrittenResources } = createModelTestContext({
      globalArgs: {},
    });
    const out = await model.methods.get.execute(BASE, context);
    const dump = JSON.stringify([out, getWrittenResources()]);
    assert(!dump.includes(VAL) && !dump.includes(b64(VAL)));
    assert(!dump.includes("kind: Config"));
    const st = getWrittenResources()[0].data as {
      key_sha256: Record<string, string>;
    };
    assertEquals(Object.keys(st.key_sha256), ["password", "user"]);
  } finally {
    h.restore();
  }
});

Deno.test("get of a missing Secret is a typed not_found", async () => {
  const h = harness(() => ({ stdout: "" }));
  try {
    const { context } = createModelTestContext({ globalArgs: {} });
    const e = await assertRejects(() =>
      model.methods.get.execute(BASE, context)
    );
    assertEquals((e as K8sSecretError).code, "not_found");
  } finally {
    h.restore();
  }
});

Deno.test("sync records not_found instead of failing", async () => {
  const h = harness(() => ({ stdout: "" }));
  try {
    const { context, getWrittenResources } = createModelTestContext({
      globalArgs: {},
    });
    await model.methods.sync.execute(BASE, context);
    assertEquals(
      (getWrittenResources()[0].data as { status: string }).status,
      "not_found",
    );
  } finally {
    h.restore();
  }
});

Deno.test("delete: deleted, then clean no-op when absent", async () => {
  let n = 0;
  const h = harness(() => ({ stdout: n++ === 0 ? "secret/db-creds\n" : "" }));
  try {
    const { context, getWrittenResources } = createModelTestContext({
      globalArgs: {},
    });
    await model.methods.delete.execute(BASE, context);
    await model.methods.delete.execute(BASE, context);
    const st = getWrittenResources().map((r) =>
      (r.data as { status: string }).status
    );
    assertEquals(st, ["deleted", "not_found"]);
    assertEquals(model.methods.delete.kind, "action");
  } finally {
    h.restore();
  }
});

Deno.test("failure modes are typed and scrubbed; kubeconfig removed", async () => {
  const cases: [string, string][] = [
    [
      "Unable to connect to the server: dial tcp 192.0.2.1:6443: i/o timeout",
      "unreachable",
    ],
    ["Error from server (Forbidden): secrets is forbidden", "unauthorized"],
    ["Error from server (Unauthorized)", "unauthorized"],
    [
      'Error from server (NotFound): namespaces "app" not found',
      "namespace_not_found",
    ],
    [`boom ${VAL}`, "kubectl_failed"],
  ];
  for (const [stderr, code] of cases) {
    const h = harness((c) =>
      verb(c) === "get" ? { stdout: "" } : { code: 1, stderr }
    );
    try {
      const { context } = createModelTestContext({ globalArgs: {} });
      const e = await assertRejects(() =>
        model.methods.apply.execute(APPLY, context)
      ) as K8sSecretError;
      assertEquals(e.code, code);
      assert(!e.message.includes(VAL));
      assertEquals(h.removed, h.written);
      assert(h.written.length > 0);
    } finally {
      h.restore();
    }
  }
});

Deno.test("malformed kubectl JSON is typed and leaks no value", async () => {
  const h = harness((c) =>
    verb(c) === "get" ? { stdout: `{"data":{"password":"${b64(VAL)}"` } : {}
  );
  try {
    const { context } = createModelTestContext({ globalArgs: {} });
    const e = await assertRejects(() =>
      model.methods.get.execute(BASE, context)
    ) as K8sSecretError;
    assertEquals(e.code, "kubectl_failed");
    assert(!e.message.includes(VAL) && !e.message.includes(b64(VAL)));
    assertEquals(h.removed, h.written);
  } finally {
    h.restore();
  }
});

Deno.test("get failure also removes the kubeconfig", async () => {
  const h = harness(() => ({ code: 1, stderr: "Unauthorized" }));
  try {
    const { context } = createModelTestContext({ globalArgs: {} });
    await assertRejects(() => model.methods.get.execute(BASE, context));
    assertEquals(h.removed, h.written);
  } finally {
    h.restore();
  }
});

Deno.test("adversarial input is rejected before any kubectl call", async () => {
  const h = harness(() => ({}));
  try {
    const { context } = createModelTestContext({ globalArgs: {} });
    const bad: Record<string, unknown>[] = [
      { ...APPLY, name: "a; rm -rf /" },
      { ...APPLY, name: "$(id)" },
      { ...APPLY, name: "A_B" },
      { ...APPLY, namespace: "app --all" },
      { ...APPLY, namespace: "-n" },
      { ...APPLY, namespace: "a.b" },
      { ...APPLY, context: "--token=x" },
      { ...APPLY, context: "c;id" },
      { ...APPLY, type: "x y" },
      { ...APPLY, data: { "bad key": "v" } },
      { ...APPLY, data: { "a/b": "v" } },
      { ...APPLY, data: { "..": "v" } },
      { ...APPLY, data: { "k`id`": "v" } },
      { ...APPLY, data: {} },
      { ...APPLY, extra: 1 },
    ];
    for (const b of bad) {
      await assertRejects(() =>
        model.methods.apply.execute(b as never, context)
      );
    }
    await assertRejects(() =>
      model.methods.get.execute({ ...BASE, name: "x|y" } as never, context)
    );
    await assertRejects(() =>
      model.methods.delete.execute(
        { ...BASE, namespace: "x y" } as never,
        context,
      )
    );
    assertEquals(h.calls.length, 0);
    assertEquals(h.written.length, 0);
  } finally {
    h.restore();
  }
});

Deno.test("state is keyed by context/namespace/name", () => {
  assertEquals(
    stateName({ ...BASE, context: "prod.test" }),
    "prod.test_app_db-creds",
  );
  assertEquals(stateName(BASE), "current-context_app_db-creds");
});

Deno.test("no fixture, source or doc carries real-looking secret material", async () => {
  const patterns: [string, RegExp][] = [
    ["PEM private key", /-----BEGIN [A-Z ]*PRIVATE KEY-----/],
    [
      "JWT",
      /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/,
    ],
    ["AWS access key", /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/],
    ["GitHub token", /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}\b/],
    ["Slack token", /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/],
  ];
  const files: URL[] = [];
  async function walk(dir: URL): Promise<void> {
    for await (const e of Deno.readDir(dir)) {
      if (e.name === ".swamp" || e.name === ".gates") continue;
      const child = new URL(e.name + (e.isDirectory ? "/" : ""), dir);
      if (e.isDirectory) await walk(child);
      else if (/\.(ts|md|ya?ml|json|txt)$/.test(e.name)) files.push(child);
    }
  }
  await walk(new URL("../../", import.meta.url));
  assert(files.length > 0);
  for (const file of files) {
    const text = await Deno.readTextFile(file);
    for (const [name, re] of patterns) {
      assertEquals(re.test(text), false, `${name} found in ${file.pathname}`);
    }
  }
});
