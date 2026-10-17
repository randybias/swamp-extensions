import { assert, assertEquals, assertRejects } from "jsr:@std/assert@1.0.19";
import {
  classifyKubectl,
  clusterFingerprint16,
  type Deps,
  fetchVerifiedManifest,
  fieldManager,
  isDataVolumeSize,
  isDigestPinnedImage,
  isDnsLabel,
  isDnsSubdomain,
  isDowngrade,
  isFeatureGate,
  isMemory,
  isMinorSkip,
  isReleaseTag,
  isSha256,
  kubectlJson,
  KubevirtError,
  manifestUrl,
  normalizeServer,
  operatorStateKey,
  parseVersion,
  pollUntil,
  TargetShape,
  vmStateKey,
} from "./k8s.ts";

const deps = (over: Partial<Deps> = {}): Deps => ({
  run: () => Promise.resolve({ code: 0, stdout: "", stderr: "" }),
  files: {
    write: () => Promise.resolve("/tmp/kc"),
    remove: () => Promise.resolve(),
  },
  now: () => new Date(0),
  fetch: () => Promise.resolve({ status: 200, body: "body" }),
  sleep: () => Promise.resolve(),
  ...over,
});

Deno.test("grammars accept the documented shapes and refuse the rest", () => {
  assertEquals(isReleaseTag("v1.2.3"), true);
  assertEquals(isReleaseTag("1.2.3"), false);
  assertEquals(isReleaseTag("v1.2"), false);
  assertEquals(isSha256("0".repeat(64)), true);
  assertEquals(isSha256("0".repeat(63)), false);
  assertEquals(isSha256("A".repeat(64)), false);
  assertEquals(isDnsLabel("vm-1"), true);
  assertEquals(isDnsLabel("-vm"), false);
  assertEquals(isDnsLabel("a".repeat(64)), false);
  assertEquals(isDnsSubdomain("a.b-c"), true);
  assertEquals(isDnsSubdomain("a..b"), false);
  assertEquals(isFeatureGate("LiveMigration"), true);
  assertEquals(isFeatureGate("liveMigration"), false);
  assertEquals(isFeatureGate("A"), false);
  assertEquals(isMemory("64Mi"), true);
  assertEquals(isMemory("256Gi"), true);
  assertEquals(isMemory("63Mi"), false);
  assertEquals(isMemory("257Gi"), false);
  assertEquals(isMemory("2G"), false);
  assertEquals(isDataVolumeSize("1Gi"), true);
  assertEquals(isDataVolumeSize("0Gi"), false);
  assertEquals(isDataVolumeSize("5Mi"), false);
});

Deno.test("only digest-pinned container images are accepted", () => {
  const digest = "sha256:" + "a".repeat(64);
  assertEquals(
    isDigestPinnedImage(`quay.io/example/disk@${digest}`),
    true,
  );
  assertEquals(
    isDigestPinnedImage(`registry.example.com:5000/x/y@${digest}`),
    true,
  );
  assertEquals(isDigestPinnedImage("quay.io/example/disk:v1.2.3"), false);
  assertEquals(isDigestPinnedImage("quay.io/example/disk"), false);
  assertEquals(isDigestPinnedImage(`disk@${digest}`), false);
});

Deno.test("kubeconfig is sensitive and refused when it uses a plugin", () => {
  const schema = TargetShape.kubeconfig;
  assertEquals(schema.meta()?.sensitive, true);
  const bad = schema.safeParse(
    "apiVersion: v1\nkind: Config\nusers:\n- name: u\n  user:\n    exec:\n      command: /bin/sh\n",
  );
  assertEquals(bad.success, false);
});

Deno.test("server URLs are normalized for fingerprinting", () => {
  assertEquals(
    normalizeServer("https://API.Example.com:6443"),
    "https://api.example.com:6443",
  );
  assertEquals(
    normalizeServer("HTTPS://api.example.com"),
    "https://api.example.com",
  );
  assertEquals(normalizeServer("not a url"), "not a url");
});

const KC = `apiVersion: v1
kind: Config
current-context: c
clusters:
- name: a
  cluster: {server: "https://192.0.2.10:6443"}
- name: b
  cluster: {server: "https://192.0.2.11:6443"}
contexts:
- name: c
  context: {cluster: a, user: u}
- name: d
  context: {cluster: b, user: u}
users:
- name: u
  user: {token: placeholder}
`;

Deno.test("clusterFingerprint16 follows the selected server, not the text", async () => {
  const a = await clusterFingerprint16(KC, "c");
  const b = await clusterFingerprint16(KC, "d");
  assert(a !== b);
  assertEquals(a.length, 16);
  // A rotated token keeps the fingerprint.
  const rotated = KC.replace("token: placeholder", "token: rotated");
  assertEquals(await clusterFingerprint16(rotated, "c"), a);
  // Two contexts on one server share the fingerprint.
  const same = KC.replace("cluster: b", "cluster: a");
  assertEquals(await clusterFingerprint16(same, "d"), a);
});

Deno.test("state keys are the cluster fingerprint plus the operands", async () => {
  const fp = await clusterFingerprint16(KC, "c");
  assertEquals(await operatorStateKey(KC, "c"), `${fp}/kubevirt`);
  assertEquals(await vmStateKey(KC, "c", "app", "vm-1"), `${fp}/app/vm-1`);
});

Deno.test("version guards refuse a downgrade and a multi-minor jump", () => {
  assertEquals(isDowngrade("v1.2.0", "v1.1.0"), true);
  assertEquals(isDowngrade("v1.2.0", "v1.3.0"), false);
  assertEquals(isDowngrade("v2.0.0", "v1.9.0"), true);
  // A patch-level move backwards is still a downgrade.
  assertEquals(isDowngrade("v1.3.2", "v1.3.1"), true);
  assertEquals(isDowngrade("v1.3.1", "v1.3.2"), false);
  assertEquals(isDowngrade("v1.3.1", "v1.3.1"), false);
  assertEquals(isMinorSkip("v1.2.0", "v1.3.0"), false);
  assertEquals(isMinorSkip("v1.2.0", "v1.4.0"), true);
  assertEquals(isMinorSkip("v1.2.0", "v2.0.0"), false);
  assertEquals(parseVersion("v1.2.3"), { major: 1, minor: 2, patch: 3 });
});

Deno.test("manifestUrl builds a release-asset URL for the default and a mirror", () => {
  assertEquals(
    manifestUrl(
      undefined,
      "kubevirt",
      "kubevirt",
      "v1.2.3",
      "kubevirt-operator.yaml",
    ),
    "https://github.com/kubevirt/kubevirt/releases/download/v1.2.3/kubevirt-operator.yaml",
  );
  assertEquals(
    manifestUrl(
      "https://mirror.example.com/",
      "kubevirt",
      "containerized-data-importer",
      "v1.2.3",
      "cdi-operator.yaml",
    ),
    "https://mirror.example.com/kubevirt/containerized-data-importer/releases/download/v1.2.3/cdi-operator.yaml",
  );
});

Deno.test("fetchVerifiedManifest applies only a byte-exact manifest", async () => {
  const bodySha = await sha256("body");
  const good = await fetchVerifiedManifest(
    deps({ fetch: () => Promise.resolve({ status: 200, body: "body" }) }),
    "https://example.com/manifest.yaml",
    bodySha,
  );
  assertEquals(good, "body");
  const mismatch = await assertRejects(
    () =>
      fetchVerifiedManifest(
        deps({
          fetch: () => Promise.resolve({ status: 200, body: "tampered" }),
        }),
        "https://example.com/manifest.yaml",
        bodySha,
      ),
    KubevirtError,
  );
  assertEquals((mismatch as KubevirtError).code, "manifest_mismatch");
  assert(!(mismatch as Error).message.includes("tampered"));
});

Deno.test("fetchVerifiedManifest maps status and empty bodies to typed errors", async () => {
  const missing = await assertRejects(
    () =>
      fetchVerifiedManifest(
        deps({ fetch: () => Promise.resolve({ status: 404, body: "" }) }),
        "https://example.com/manifest.yaml",
        "0".repeat(64),
      ),
    KubevirtError,
  );
  assertEquals((missing as KubevirtError).code, "manifest_fetch");
  assert((missing as Error).message.includes("example.com"));
  const whitespaceSha = await sha256("  \n");
  const empty = await assertRejects(
    () =>
      fetchVerifiedManifest(
        deps({ fetch: () => Promise.resolve({ status: 200, body: "  \n" }) }),
        "https://example.com/manifest.yaml",
        whitespaceSha,
      ),
    KubevirtError,
  );
  assertEquals((empty as KubevirtError).code, "manifest_fetch");
});

Deno.test("classifyKubectl returns fixed messages that never echo stderr", () => {
  const leaky = "Error: something with secret-value-x";
  const e = classifyKubectl(leaky);
  assertEquals(e.code, "kubectl_failed");
  assert(!e.message.includes("secret-value-x"));
  assertEquals(
    classifyKubectl('the server doesn\'t have a resource type "kubevirts"')
      .code,
    "crd_missing",
  );
  assertEquals(
    classifyKubectl("Unable to connect to the server: dial tcp").code,
    "unreachable",
  );
  assertEquals(
    classifyKubectl("Error from server (Forbidden): forbidden").code,
    "unauthorized",
  );
});

Deno.test("kubectlJson returns null for an absent object and refuses bad JSON", async () => {
  const kubectl = (stdout: string) => () =>
    Promise.resolve({ code: 0, stdout, stderr: "" });
  assertEquals(await kubectlJson(kubectl(""), ["get", "vm"]), null);
  assertEquals(
    await kubectlJson(kubectl('{"kind":"VirtualMachine"}'), ["get", "vm"]),
    { kind: "VirtualMachine" },
  );
  await assertRejects(
    () => kubectlJson(kubectl("{not json"), ["get", "vm"]),
    KubevirtError,
    "invalid JSON",
  );
});

Deno.test("fieldManager is stable per definition and distinct across them", async () => {
  const a = await fieldManager("kv");
  assertEquals(a, await fieldManager("kv"));
  assert(a.startsWith("swamp-kubevirt-"));
  assert(a !== await fieldManager("other"));
});

Deno.test("pollUntil stops at the deadline using the injected clock", async () => {
  let t = 0;
  let calls = 0;
  const d = deps({
    now: () => new Date(t),
    sleep: () => {
      t += 5000;
      return Promise.resolve();
    },
  });
  const out = await pollUntil(
    d,
    10000,
    5000,
    () => {
      calls += 1;
      return Promise.resolve("never");
    },
    (v) => v === "done",
  );
  assertEquals(out, "never");
  assert(calls >= 3);
});

async function sha256(s: string): Promise<string> {
  const d = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(s),
  );
  return [...new Uint8Array(d)].map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}
