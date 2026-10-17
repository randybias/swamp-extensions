import { assert, assertEquals } from "jsr:@std/assert@1.0.19";
import {
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
