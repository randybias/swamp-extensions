import { assert, assertEquals } from "jsr:@std/assert@1.0.19";
import {
  checkCanonical,
  checkKubeconfig,
  clusterFingerprint,
  resolveServer,
} from "./kubeconfig.ts";

/** A two-cluster kubeconfig whose first listed server is shared. */
const KC = `
apiVersion: v1
kind: Config
current-context: staged
clusters:
- name: shared
  cluster:
    server: https://shared.test:6443
- name: other
  cluster:
    server: https://other.test:6443
contexts:
- name: staged
  context:
    cluster: other
    user: u
- name: live
  context:
    cluster: shared
    user: u
users:
- name: u
  user:
    token: placeholder
`;

Deno.test("checkKubeconfig resolves contexts, clusters and servers", () => {
  const check = checkKubeconfig(KC);
  assert(check.ok);
  if (!check.ok) return;
  assertEquals(check.facts.currentContext, "staged");
  assertEquals(resolveServer(check.facts), "https://other.test:6443");
  assertEquals(resolveServer(check.facts, "live"), "https://shared.test:6443");
  assertEquals(resolveServer(check.facts, "missing"), undefined);
});

Deno.test("checkKubeconfig rejects exec and auth-provider credentials", () => {
  const exec = `
apiVersion: v1
kind: Config
users:
- name: u
  user:
    exec:
      apiVersion: client.authentication.k8s.io/v1
      command: /bin/sh
      args: ["-c", "id"]
`;
  const e = checkKubeconfig(exec);
  assertEquals(e.ok, false);
  assert(!e.ok && e.reason.includes("exec"));

  const provider = `
apiVersion: v1
kind: Config
users:
- name: u
  user:
    auth-provider:
      name: gcp
      config:
        cmd-path: /bin/sh
`;
  const p = checkKubeconfig(provider);
  assertEquals(p.ok, false);
  assert(!p.ok && p.reason.includes("auth-provider"));
});

Deno.test("checkKubeconfig rejects local-file credential paths", () => {
  const userFields: [string, string][] = [
    ["tokenFile", "/var/run/secrets/token"],
    ["client-certificate", "/etc/kubernetes/pki/cert"],
    ["client-key", "/etc/kubernetes/pki/key"],
  ];
  for (const [field, path] of userFields) {
    const kc =
      `apiVersion: v1\nkind: Config\nusers:\n- name: u\n  user:\n    ${field}: ${path}\n`;
    const check = checkKubeconfig(kc);
    assertEquals(check.ok, false, field);
    assert(!check.ok && check.reason.includes(field), field);
  }
  const clusterKc =
    "apiVersion: v1\nkind: Config\nclusters:\n- name: c\n  cluster:\n    server: https://a.test\n    certificate-authority: /etc/kubernetes/pki/ca\n";
  const ca = checkKubeconfig(clusterKc);
  assertEquals(ca.ok, false);
  assert(!ca.ok && ca.reason.includes("certificate-authority"));
});

Deno.test("checkKubeconfig rejects unknown user and cluster fields", () => {
  const extraUser =
    "apiVersion: v1\nkind: Config\nusers:\n- name: u\n  user:\n    impersonate: admin\n";
  assertEquals(checkKubeconfig(extraUser).ok, false);
  const extraCluster =
    "apiVersion: v1\nkind: Config\nclusters:\n- name: c\n  cluster:\n    server: https://a.test\n    extensions: []\n";
  assertEquals(checkKubeconfig(extraCluster).ok, false);
});

Deno.test("checkKubeconfig accepts embedded data credentials", () => {
  const kc = [
    "apiVersion: v1",
    "kind: Config",
    "clusters:",
    "- name: c",
    "  cluster:",
    "    server: https://a.test:6443",
    "    certificate-authority-data: placeholder-ca",
    "users:",
    "- name: u",
    "  user:",
    "    client-certificate-data: placeholder-cert",
    "    client-key-data: placeholder-key",
    "    token: placeholder",
    "",
  ].join("\n");
  assert(checkKubeconfig(kc).ok);
});

Deno.test("checkKubeconfig refuses YAML alias expansion", () => {
  let bomb = "a: &a [x,x,x,x,x,x,x,x,x]\n";
  for (let i = 0; i < 9; i++) {
    const prev = String.fromCharCode(97 + i);
    const cur = String.fromCharCode(98 + i);
    bomb += `${cur}: &${cur} [${
      Array.from({ length: 9 }, () => `*${prev}`).join(",")
    }]\n`;
  }
  const check = checkKubeconfig(bomb);
  assertEquals(check.ok, false);
});

Deno.test("checkKubeconfig rejects malformed YAML without echoing it", () => {
  const check = checkKubeconfig("users: [\n  - a: b\n  c:\n");
  assertEquals(check.ok, false);
  assert(!check.ok && !check.reason.includes("users"));
});

Deno.test("clusterFingerprint follows the selected cluster, not the first server", async () => {
  // Both contexts exist in one kubeconfig; staged -> other, live -> shared.
  const staged = await clusterFingerprint(KC, "staged");
  const live = await clusterFingerprint(KC, "live");
  assert(staged !== live);
  // A rotated token, same selected cluster, keeps the fingerprint.
  const rotated = KC.replace("token: placeholder", "token: rotated");
  assertEquals(await clusterFingerprint(rotated, "staged"), staged);
  // The omitted context uses current-context.
  assertEquals(await clusterFingerprint(KC), staged);
});

const HEAD = `apiVersion: v1
kind: Config
current-context: c
clusters:
- name: k
  cluster: {server: "https://192.0.2.1:6443"}
contexts:
- name: c
  context: {cluster: k, user: u}
`;
const EXEC_USER =
  `{user: {exec: {apiVersion: client.authentication.k8s.io/v1, command: /bin/true, args: []}}}`;

Deno.test("a merge key cannot smuggle an exec plugin into a user entry", () => {
  const smuggled = `${HEAD}users:\n- name: u\n  <<: ${EXEC_USER}\n`;
  const r = checkKubeconfig(smuggled);
  assert(!r.ok);
  assert(!r.ok && r.reason.includes("merge"));
  // The same keys written quoted, in flow style, or with an explicit tag.
  for (
    const text of [
      `${HEAD}users:\n- name: u\n  "<<": ${EXEC_USER}\n`,
      `${HEAD}users: [{name: u, <<: ${EXEC_USER}}]\n`,
      `${HEAD}users:\n- name: u\n  !!merge <<: ${EXEC_USER}\n`,
      `${HEAD}users:\n- name: u\n  ? !<tag:yaml.org,2002:merge> <<\n  : ${EXEC_USER}\n`,
    ]
  ) {
    assert(!checkKubeconfig(text).ok, text);
  }
});

Deno.test("a top-level merge cannot smuggle a tokenFile", () => {
  const text =
    `${HEAD}<<: {users: [{name: u, user: {tokenFile: /etc/hostname}}]}\n`;
  assert(!checkKubeconfig(text).ok);
});

Deno.test("anchors and aliases are resolved, then judged like any other value", () => {
  const ok =
    `${HEAD}users:\n- name: u\n  user: &u {token: placeholder}\n- name: v\n  user: *u\n`;
  assert(checkKubeconfig(ok).ok);
  const bad =
    `${HEAD}users:\n- name: a\n  user: &x {token: t}\n- name: u\n  user:\n    token: t\n    exec: &e {command: /bin/true}\n- name: w\n  user: {exec: *e}\n`;
  assert(!checkKubeconfig(bad).ok);
  const laughs = ["a: &a [x,x,x,x,x,x,x,x,x]"];
  let prev = "a";
  for (const n of "bcdefghijk") {
    laughs.push(`${n}: &${n} [${Array(9).fill(`*${prev}`).join(",")}]`);
    prev = n;
  }
  assert(!checkKubeconfig(laughs.join("\n")).ok);
});

Deno.test("the canonical document is default-deny at every level", () => {
  const base = {
    apiVersion: "v1",
    kind: "Config",
    "current-context": "c",
    clusters: [{ name: "k", cluster: { server: "https://192.0.2.1:6443" } }],
    contexts: [{ name: "c", context: { cluster: "k", user: "u" } }],
    users: [{ name: "u", user: { token: "placeholder" } }],
    preferences: {},
  };
  assert(checkCanonical(JSON.stringify(base)).ok);
  const mutations: [string, (c: Record<string, unknown>) => void][] = [
    ["exec", (c) => {
      c.users = [{ name: "u", user: { exec: { command: "/bin/true" } } }];
    }],
    ["auth-provider", (c) => {
      c.users = [{ name: "u", user: { "auth-provider": { name: "gcp" } } }];
    }],
    ["tokenFile", (c) => {
      c.users = [{ name: "u", user: { tokenFile: "/etc/hostname" } }];
    }],
    ["top-level key", (c) => {
      c.somethingElse = true;
    }],
    ["top-level extensions", (c) => {
      c.extensions = [{ name: "x", extension: { a: 1 } }];
    }],
    ["wrong kind", (c) => {
      c.kind = "Other";
    }],
    ["entry key", (c) => {
      c.users = [{ name: "u", user: { token: "t" }, extra: {} }];
    }],
    ["entry without name", (c) => {
      c.users = [{ user: { token: "t" } }];
    }],
    ["context key", (c) => {
      c.contexts = [{
        name: "c",
        context: { cluster: "k", user: "u", extensions: [{ name: "x" }] },
      }];
    }],
    ["context extra field", (c) => {
      c.contexts = [{
        name: "c",
        context: { cluster: "k", user: "u", x: "y" },
      }];
    }],
    ["cluster ca file", (c) => {
      c.clusters = [{
        name: "k",
        cluster: {
          server: "https://192.0.2.1:6443",
          "certificate-authority": "/etc/ca",
        },
      }];
    }],
    ["cluster nested value", (c) => {
      c.clusters = [{ name: "k", cluster: { server: { a: "b" } } }];
    }],
    ["preferences key", (c) => {
      c.preferences = { extensions: [{ name: "x" }] };
    }],
    ["merge key in output", (c) => {
      (c.users as Record<string, unknown>[])[0]["<<"] = {};
    }],
  ];
  for (const [name, mutate] of mutations) {
    const doc = structuredClone(base) as Record<string, unknown>;
    mutate(doc);
    const r = checkCanonical(JSON.stringify(doc));
    assert(!r.ok, name);
  }
  assert(!checkCanonical("not json").ok);
  assert(!checkCanonical("[]").ok);
});

Deno.test("a null-prototype or __proto__ key in the document is not trusted", () => {
  const json = `{"apiVersion":"v1","kind":"Config","__proto__":{"x":1}}`;
  assert(!checkCanonical(json).ok);
});

Deno.test("real kubectl: merge-smuggled configs are rejected at both stages", async () => {
  const perm = await Deno.permissions.query({
    name: "run",
    command: "kubectl",
  });
  if (perm.state !== "granted") return;
  try {
    await new Deno.Command("kubectl", {
      args: ["version", "--client"],
      stdout: "null",
      stderr: "null",
    }).output();
  } catch {
    return; // kubectl is not installed here
  }
  const dir = await Deno.makeTempDir({ prefix: "kc-merge-" });
  try {
    const cases: [string, string][] = [
      ["user", `${HEAD}users:\n- name: u\n  <<: ${EXEC_USER}\n`],
      [
        "top",
        `${HEAD}<<: {users: [{name: u, user: {tokenFile: /etc/hostname}}]}\n`,
      ],
    ];
    for (const [name, text] of cases) {
      assert(!checkKubeconfig(text).ok, `${name} early`);
      const path = `${dir}/${name}.yaml`;
      await Deno.writeTextFile(path, text, { mode: 0o600 });
      const out = await new Deno.Command("kubectl", {
        args: ["config", "view", "--raw", "-o", "json"],
        env: { KUBECONFIG: path, PATH: Deno.env.get("PATH") ?? "", HOME: dir },
        clearEnv: true,
      }).output();
      assertEquals(out.code, 0, name);
      // kubectl applied the merge, so the canonical document carries it, and
      // the canonical check refuses it.
      assert(!checkCanonical(new TextDecoder().decode(out.stdout)).ok, name);
    }
    const good = `${HEAD}users:\n- name: u\n  user: {token: placeholder}\n`;
    const path = `${dir}/good.yaml`;
    await Deno.writeTextFile(path, good, { mode: 0o600 });
    const out = await new Deno.Command("kubectl", {
      args: ["config", "view", "--raw", "-o", "json"],
      env: { KUBECONFIG: path, PATH: Deno.env.get("PATH") ?? "", HOME: dir },
      clearEnv: true,
    }).output();
    assert(checkCanonical(new TextDecoder().decode(out.stdout)).ok);
  } finally {
    await Deno.remove(dir, { recursive: true });
  }
});
