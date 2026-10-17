import {
  assertEquals,
  assertRejects,
  assertThrows,
} from "jsr:@std/assert@1.0.19";
import {
  apiServerUrl,
  archFromUname,
  chartBaseName,
  ChecksumMismatchError,
  classifyControllerExecStart,
  DownloadError,
  downloadUrl,
  installArgs,
  instanceName,
  isBoundedJsonValue,
  type K0sConfigInput,
  parseCharts,
  parseHelmReleases,
  parseKubeconfigServer,
  parseNameList,
  parseNodes,
  parsePods,
  parseSha256,
  redactUrl,
  renderK0sConfig,
  renderManifestStack,
  repoSlug,
  serviceName,
  systemPodsHealthy,
  toYaml,
  verifyBinary,
  withServer,
  yamlScalar,
} from "./k0s.ts";
import { isCidr, isIp } from "./grammar.ts";
import { sha256Hex } from "./ssh.ts";

const BASE: K0sConfigInput = {
  cluster_name: "k0s-lab",
  api_port: 6443,
  api_sans: ["192.0.2.10", "k0s.example.com"],
  pod_cidr: "192.0.2.0/24",
  service_cidr: "198.51.100.0/24",
  storage_type: "etcd",
  telemetry_enabled: false,
  helm: [],
};

async function golden(name: string): Promise<string> {
  return await Deno.readTextFile(
    new URL(`./testdata/${name}`, import.meta.url),
  );
}

Deno.test("renderK0sConfig matches the single-node golden", async () => {
  assertEquals(renderK0sConfig(BASE), await golden("single-node.golden.txt"));
});

Deno.test("renderK0sConfig matches the Helm golden deterministically", async () => {
  const withHelm: K0sConfigInput = {
    ...BASE,
    helm: [{
      chart: "example/nginx",
      repo: "https://charts.example.com",
      version: "1.2.3",
      namespace: "default",
      values: { replicaCount: 1 },
    }],
  };
  const first = renderK0sConfig(withHelm);
  assertEquals(first, await golden("with-helm.golden.txt"));
  // A second render is byte-identical, regardless of key order.
  assertEquals(
    renderK0sConfig({
      ...withHelm,
      helm: [{ ...withHelm.helm[0], values: { replicaCount: 1 } }],
    }),
    first,
  );
});

Deno.test("renderManifestStack matches the manifest-stack golden", async () => {
  assertEquals(
    renderManifestStack({
      name: "example-stack",
      files: [
        {
          path: "configmap.yaml",
          content:
            "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: example\n",
        },
        {
          path: "namespace.yaml",
          content:
            "apiVersion: v1\nkind: Namespace\nmetadata:\n  name: example\n",
        },
      ],
    }),
    await golden("with-manifest-stack.golden.txt"),
  );
});

Deno.test("verifyBinary proceeds on a match and refuses on a mismatch", async () => {
  const bytes = new TextEncoder().encode("k0s release payload");
  const good = await sha256Hex(bytes);
  assertEquals(
    await verifyBinary(bytes, good.toUpperCase(), "https://example.com/k0s"),
    good,
  );
  const wrong = "0".repeat(64);
  await assertRejects(
    () => verifyBinary(bytes, wrong, "https://example.com/k0s"),
    ChecksumMismatchError,
    "refusing to install",
  );
});

Deno.test("archFromUname maps supported machines and rejects others", () => {
  assertEquals(archFromUname("x86_64\n"), "amd64");
  assertEquals(archFromUname("amd64"), "amd64");
  assertEquals(archFromUname("aarch64\n"), "arm64");
  assertEquals(archFromUname("arm64"), "arm64");
  assertThrows(() => archFromUname("sparc"), Error, "unsupported");
});

Deno.test("downloadUrl uses the pinned release path and honors an override", () => {
  assertEquals(
    downloadUrl("v1.31.2+k0s.0", "amd64"),
    "https://github.com/k0sproject/k0s/releases/download/v1.31.2+k0s.0/k0s-v1.31.2+k0s.0-amd64",
  );
  assertEquals(
    downloadUrl("v1.31.2+k0s.0", "arm64", "https://mirror.example.com/k0s"),
    "https://mirror.example.com/k0s",
  );
});

Deno.test("installArgs and serviceName cover every role", () => {
  assertEquals(installArgs("single"), [
    "install",
    "controller",
    "--enable-worker",
    "--no-taints",
  ]);
  assertEquals(installArgs("controller"), ["install", "controller"]);
  assertEquals(installArgs("worker"), [
    "install",
    "worker",
    "--token-file",
    "/etc/k0s/worker-token",
  ]);
  assertEquals(serviceName("single"), "k0scontroller");
  assertEquals(serviceName("controller"), "k0scontroller");
  assertEquals(serviceName("worker"), "k0sworker");
});

Deno.test("toYaml is deterministic and quotes unsafe scalars", () => {
  const text = toYaml({
    zebra: 1,
    alpha: true,
    nothing: null,
    url: "https://example.com/x",
    nested: { b: ["one", "two"], a: {} },
    list: [{ name: "first" }, { name: "second" }],
  });
  assertEquals(
    text,
    [
      "alpha: true",
      "list:",
      "  - name: first",
      "  - name: second",
      "nested:",
      "  a: {}",
      "  b:",
      "    - one",
      "    - two",
      "nothing: null",
      'url: "https://example.com/x"',
      "zebra: 1",
    ].join("\n"),
  );
  assertEquals(yamlScalar("yes"), '"yes"');
  assertEquals(yamlScalar("plain"), "plain");
});

Deno.test("repoSlug and chartBaseName derive safe names", () => {
  assertEquals(
    repoSlug("https://charts.example.com/stable"),
    "charts-example-com-stable",
  );
  assertEquals(repoSlug("https://charts.example.com"), "charts-example-com");
  assertEquals(chartBaseName("example/nginx"), "nginx");
  assertEquals(chartBaseName("nginx"), "nginx");
});

Deno.test("isCidr accepts real CIDRs and rejects malformed ones", () => {
  assertEquals(isCidr("192.0.2.0/24"), true);
  assertEquals(isCidr("192.0.2.0/24"), true);
  assertEquals(isCidr("2001:db8::/32"), true);
  assertEquals(isCidr("192.0.2.0"), false);
  assertEquals(isCidr("192.0.2.0/33"), false);
  assertEquals(isCidr("300.0.0.0/24"), false);
  assertEquals(isCidr("not-a-cidr"), false);
});

Deno.test("parseNodes reads the Ready condition", () => {
  const nodes = parseNodes(JSON.stringify({
    items: [{
      metadata: { name: "k0s-lab" },
      status: { conditions: [{ type: "Ready", status: "True" }] },
    }],
  }));
  assertEquals(nodes, [{ name: "k0s-lab", ready: true }]);
  assertEquals(parseNodes("not json"), []);
});

Deno.test("parsePods and systemPodsHealthy judge kube-system health", () => {
  const running = JSON.stringify({
    items: [{
      metadata: { namespace: "kube-system", name: "coredns" },
      status: {
        phase: "Running",
        conditions: [{ type: "Ready", status: "True" }],
      },
    }],
  });
  const pods = parsePods(running);
  assertEquals(pods.length, 1);
  assertEquals(systemPodsHealthy(pods), true);
  assertEquals(systemPodsHealthy(parsePods('{"items":[]}')), false);
  const pending = parsePods(JSON.stringify({
    items: [{
      metadata: { namespace: "kube-system", name: "coredns" },
      status: { phase: "Pending", conditions: [] },
    }],
  }));
  assertEquals(systemPodsHealthy(pending), false);
});

Deno.test("parseHelmReleases extracts release names and status", () => {
  const releases = parseHelmReleases(JSON.stringify({
    items: [{
      type: "helm.sh/release.v1",
      metadata: {
        name: "sh.helm.release.v1.nginx.v3",
        namespace: "default",
        labels: { status: "deployed" },
      },
    }, {
      type: "Opaque",
      metadata: { name: "ignored", namespace: "default" },
    }],
  }));
  assertEquals(releases, [{
    name: "nginx",
    namespace: "default",
    status: "deployed",
    revision: 3,
  }]);
});

Deno.test("parseHelmReleases keeps only the latest revision of a release", () => {
  const secret = (rev: number, status: string) => ({
    type: "helm.sh/release.v1",
    metadata: {
      name: `sh.helm.release.v1.nginx.v${rev}`,
      namespace: "default",
      labels: { status },
    },
  });
  const releases = parseHelmReleases(
    JSON.stringify({
      items: [
        secret(2, "failed"),
        secret(1, "deployed"),
        secret(3, "deployed"),
      ],
    }),
  );
  assertEquals(releases.length, 1);
  assertEquals([releases[0].revision, releases[0].status], [3, "deployed"]);
});

Deno.test("parseCharts reads the reconciled version and error", () => {
  const charts = parseCharts(JSON.stringify({
    items: [{
      metadata: { name: "k0s-addon-chart-nginx" },
      spec: { namespace: "default" },
      status: { releaseName: "nginx", version: "1.2.3", namespace: "default" },
    }, {
      metadata: { name: "k0s-addon-chart-bad" },
      spec: { namespace: "web" },
      status: { error: "chart not found" },
    }],
  }));
  assertEquals(charts, [
    { name: "nginx", namespace: "default", version: "1.2.3", error: null },
    { name: "bad", namespace: "web", version: null, error: "chart not found" },
  ]);
});

Deno.test("isCidr rejects malformed IPv6", () => {
  for (
    const bad of [
      "::::/64",
      "2001:db8:3:4:5:6:7:8:9/64",
      "2001:db8::2::3/64",
      ":1/64",
    ]
  ) {
    assertEquals(isCidr(bad), false, bad);
  }
  for (
    const good of [
      "2001:db8:1::/64",
      "2001:db8::/32",
      "::/0",
      "2001:db8:0:0:0:0:0:1/128",
    ]
  ) {
    assertEquals(isCidr(good), true, good);
  }
});

Deno.test("parseSha256 and parseNameList read command output", () => {
  const hash = "a".repeat(64);
  assertEquals(parseSha256(`${hash}  /etc/k0s/k0s.yaml\n`), hash);
  assertEquals(parseSha256("no digest here"), null);
  assertEquals(parseNameList("one\n\ntwo\n"), ["one", "two"]);
});

Deno.test("parseKubeconfigServer reads only the server URL", () => {
  const server = parseKubeconfigServer(
    "apiVersion: v1\nclusters:\n- cluster:\n    server: https://192.0.2.10:6443\n",
  );
  assertEquals(server, "https://192.0.2.10:6443");
  assertEquals(parseKubeconfigServer("kind: Config"), null);
});

Deno.test("instanceName cannot escape the data directory", () => {
  assertEquals(instanceName("192.0.2.10"), "192.0.2.10");
  const escaped = instanceName("../../etc");
  assertEquals(escaped.includes(".."), false);
  assertEquals(escaped.includes("/"), false);
});

Deno.test("redactUrl removes user info, query and fragment", () => {
  assertEquals(
    redactUrl("https://user:pass@example.com/k0s?token=secret#frag"),
    "https://example.com/k0s",
  );
  assertEquals(
    redactUrl("https://example.com:8443/a/b"),
    "https://example.com:8443/a/b",
  );
  assertEquals(redactUrl("not a url"), "<invalid url>");
});

Deno.test("download errors never echo credentials or query tokens", () => {
  const url = "https://user:pass@example.com/k0s?token=secret";
  const download = new DownloadError(url, "HTTP 404");
  assertEquals(download.message.includes("secret"), false);
  assertEquals(download.message.includes("user"), false);
  assertEquals(download.message.includes("https://example.com/k0s"), true);
  const mismatch = new ChecksumMismatchError(
    url,
    "a".repeat(64),
    "b".repeat(64),
  );
  assertEquals(mismatch.message.includes("secret"), false);
  assertEquals(mismatch.message.includes("https://example.com/k0s"), true);
});

Deno.test("isBoundedJsonValue caps depth, entries and size", () => {
  assertEquals(isBoundedJsonValue({ a: [1, 2, { b: "c" }] }), true);
  let deep: unknown = "leaf";
  for (let i = 0; i < 12; i++) deep = { nested: deep };
  assertEquals(isBoundedJsonValue(deep), false);
  assertEquals(isBoundedJsonValue({ big: "x".repeat(70000) }), false);
  const wide: Record<string, number> = {};
  for (let i = 0; i < 200; i++) wide[`k${i}`] = i;
  assertEquals(isBoundedJsonValue(wide), false);
  assertEquals(isBoundedJsonValue(() => 1), false);
});

Deno.test("renderK0sConfig writes spec.api.address and always adds it to the SANs", () => {
  const text = renderK0sConfig({ ...BASE, api_address: "198.51.100.7" });
  assertEquals(
    text.split("\n").slice(4, 12).join("\n"),
    [
      "spec:",
      "  api:",
      '    address: "198.51.100.7"',
      "    port: 6443",
      "    sans:",
      '      - "198.51.100.7"',
      '      - "192.0.2.10"',
      "      - k0s.example.com",
    ].join("\n"),
  );
  // Already listed: not repeated.
  const again = renderK0sConfig({
    ...BASE,
    api_address: "192.0.2.10",
  });
  assertEquals(again.match(/192\.0\.2\.10/g)?.length, 2);
  // Not given: nothing is written, matching the golden.
  assertEquals(renderK0sConfig(BASE).includes("address:"), false);
});

Deno.test("isIp accepts only IP literals", () => {
  for (const good of ["192.0.2.1", "2001:db8::1", "::1"]) {
    assertEquals(isIp(good), true, good);
  }
  for (
    const bad of [
      "",
      "example.com",
      "192.0.2",
      "192.0.2.256",
      "2001:db8::2::3",
      "::::",
      "192.0.2.1/24",
      "192.0.2.1 ",
    ]
  ) {
    assertEquals(isIp(bad), false, bad);
  }
});

Deno.test("apiServerUrl brackets IPv6 and withServer rewrites every server line", () => {
  assertEquals(apiServerUrl("198.51.100.7", 6443), "https://198.51.100.7:6443");
  assertEquals(apiServerUrl("2001:db8::7", 6443), "https://[2001:db8::7]:6443");
  const text =
    "clusters:\n- cluster:\n    server: https://192.0.2.10:6443\n  name: k\n";
  assertEquals(
    withServer(text, "https://198.51.100.7:6443"),
    "clusters:\n- cluster:\n    server: https://198.51.100.7:6443\n  name: k\n",
  );
});

Deno.test("classifyControllerExecStart reads the argv[] field of the real systemd struct", () => {
  // Verbatim from a live host: the node kept the control-plane taint.
  const real =
    "{ path=/usr/local/bin/k0s ; argv[]=/usr/local/bin/k0s controller --enable-worker=true ; ignore_errors=no ; start_time=[...] ; stop_time=[n/a] ; pid=12838 ; code=(null) ; status=0/0 }";
  assertEquals(classifyControllerExecStart(real), "controller+worker");
  const wrap = (cmd: string) =>
    `{ path=/usr/local/bin/k0s ; argv[]=/usr/local/bin/k0s ${cmd} ; ignore_errors=no ; status=0/0 }`;
  assertEquals(
    classifyControllerExecStart(wrap("controller --enable-worker --no-taints")),
    "single",
  );
  assertEquals(
    classifyControllerExecStart(
      wrap("controller --enable-worker=true --no-taints=true"),
    ),
    "single",
  );
  assertEquals(
    classifyControllerExecStart(wrap("controller --single")),
    "single",
  );
  assertEquals(
    classifyControllerExecStart(wrap("controller --config=/etc/k0s/k0s.yaml")),
    "controller",
  );
  // A flag-looking word outside argv[] (here in another field) is not read.
  assertEquals(
    classifyControllerExecStart(
      "{ path=/usr/local/bin/k0s ; argv[]=/usr/local/bin/k0s controller ; ignore_errors=no ; note=--enable-worker }",
    ),
    "controller",
  );
  for (
    const bad of [
      "",
      "controller --enable-worker",
      "{ path=/usr/bin/true ; argv[]=/usr/bin/true ; ignore_errors=no }",
    ]
  ) {
    let threw = false;
    try {
      classifyControllerExecStart(bad);
    } catch {
      threw = true;
    }
    assertEquals(threw, true, bad);
  }
});

Deno.test("HA config inputs render only when set, leaving the base byte-identical", () => {
  const base = renderK0sConfig(BASE);
  assertEquals(base.includes("externalAddress"), false);
  assertEquals(base.includes("nodeLocalLoadBalancing"), false);
  assertEquals(base.includes("controlPlaneLoadBalancing"), false);
  const nllb = renderK0sConfig({ ...BASE, node_local_load_balancing: true });
  assertEquals(
    nllb.includes("nodeLocalLoadBalancing:\n      enabled: true"),
    true,
  );
  const cplb = renderK0sConfig({
    ...BASE,
    control_plane_load_balancing: {
      virtual_ip: "192.0.2.10",
      auth_pass: "abc12345",
    },
  });
  assertEquals(cplb.includes("controlPlaneLoadBalancing:"), true);
  assertEquals(cplb.includes("authPass: abc12345"), true);
  const ext = renderK0sConfig({ ...BASE, external_address: "192.0.2.10" });
  assertEquals(ext.includes('externalAddress: "192.0.2.10"'), true);
});
