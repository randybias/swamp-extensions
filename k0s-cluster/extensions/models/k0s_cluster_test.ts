import {
  assertEquals,
  assertRejects,
  assertThrows,
} from "jsr:@std/assert@1.0.19";
import { createModelTestContext } from "jsr:@swamp-club/swamp-testing@0.20261014.55";
import {
  ChecksumMismatchError,
  DownloadError,
  K0S_BINARY_PATH,
  K0S_CONFIG_PATH,
  K0S_MANIFEST_DIR,
  renderK0sConfig,
} from "./_lib/k0s.ts";
import { sha256Hex, SshError } from "./_lib/ssh.ts";
import type { SshTransport } from "./_lib/transport.ts";
import {
  createModel,
  type K0sDeps,
  ResetCleanupError,
  targetId,
} from "./k0s_cluster.ts";

const HOST = "192.0.2.10";
const KEY = "PLACEHOLDER-PRIVATE-KEY-NOT-REAL";
const VERSION = "v1.31.2+k0s.0";
const PAYLOAD = new TextEncoder().encode("fake k0s release payload");
const PAYLOAD_SHA = await sha256Hex(PAYLOAD);
const encoder = new TextEncoder();

const SSH = {
  host: HOST,
  user: "root",
  host_key_policy: "insecure_tofu" as const,
  private_key: KEY,
};

const CLUSTER = {
  cluster_name: "k0s-lab",
  api_sans: ["192.0.2.10", "k0s.example.com"],
  api_port: 6443,
  pod_cidr: "192.0.2.0/24",
  service_cidr: "198.51.100.0/24",
  storage_type: "etcd" as const,
  telemetry_enabled: false,
};

interface Upload {
  path: string;
  content: Uint8Array;
  mode?: string;
}

interface Fake {
  deps: K0sDeps;
  execs: string[][];
  uploads: Upload[];
  fetches: string[];
  learned: string[];
  clock: { value: number };
}

function makeDeps(
  options: {
    exec?: (
      argv: string[],
    ) => { code?: number; stdout?: string; stderr?: string } | undefined;
    fetch?: (url: string) => Promise<Uint8Array>;
    /** Whether an upload changed the remote file; defaults to true. */
    uploadChanged?: (path: string) => boolean;
  } = {},
): Fake {
  const execs: string[][] = [];
  const uploads: Upload[] = [];
  const fetches: string[] = [];
  const learned: string[] = [];
  const clock = { value: Date.UTC(2026, 9, 17, 12, 0, 0) };
  const ssh: SshTransport = {
    exec: (_target, argv) => {
      execs.push([...argv]);
      return Promise.resolve().then(() => {
        const out = options.exec?.(argv) ?? {
          code: 0,
          stdout: "",
          stderr: "",
        };
        return {
          exit_code: out.code ?? 0,
          stdout: out.stdout ?? "",
          stderr: out.stderr ?? "",
        };
      });
    },
    upload: (_target, file) => {
      uploads.push({ ...file });
      return Promise.resolve({
        path: file.path,
        bytes: file.content.length,
        sha256: "0".repeat(64),
        changed: options.uploadChanged?.(file.path) ?? true,
      });
    },
    learnHostKeys: (target) => {
      learned.push(`${target.host}:${target.port}`);
      return Promise.resolve([
        `${target.host} ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFAKEKEYFORTESTS`,
      ]);
    },
  };
  const deps: K0sDeps = {
    ssh,
    fetch: (url) => {
      fetches.push(url);
      if (!options.fetch) return Promise.reject(new Error("unexpected fetch"));
      return options.fetch(url);
    },
    now: () => clock.value,
    sleep: (ms) => {
      clock.value += ms;
      return Promise.resolve();
    },
  };
  return { deps, execs, uploads, fetches, clock, learned };
}

function installArgs(overrides: Record<string, unknown> = {}) {
  return createModel(makeDeps().deps).methods.install.arguments.parse({
    ssh: SSH,
    k0s_version: VERSION,
    k0s_binary_sha256: PAYLOAD_SHA,
    ...CLUSTER,
    ...overrides,
  });
}

/** The records a method wrote, apart from the recorded SSH host keys. */
function primary<T extends { specName: string }>(rows: T[]): T;
function primary<T extends { specName: string }>(rows: T[], all: true): T[];
function primary<T extends { specName: string }>(rows: T[], all?: true) {
  const kept = rows.filter((r) => r.specName !== "hostkeys");
  return all ? kept : kept[0];
}

/**
 * The real `systemctl show -p ExecStart --value k0scontroller` output of an
 * install made with `k0s install controller --enable-worker` and no
 * `--no-taints` (the old, tainted "single" mode). It is a struct, and the
 * command line is its `argv[]=` field.
 */
const REAL_TAINTED_EXECSTART =
  "{ path=/usr/local/bin/k0s ; argv[]=/usr/local/bin/k0s controller --enable-worker=true ; ignore_errors=no ; start_time=[...] ; stop_time=[n/a] ; pid=12838 ; code=(null) ; status=0/0 }";

/** The same struct for each way the unit can have been installed. */
const execStart = (cmd: string) =>
  `{ path=/usr/local/bin/k0s ; argv[]=/usr/local/bin/k0s ${cmd} ; ignore_errors=no ; start_time=[...] ; stop_time=[n/a] ; pid=12838 ; code=(null) ; status=0/0 }\n`;

/** true = a real single node, false = controller only, "tainted" = the old mode. */
const showController = (mode: boolean | "tainted") => ({
  code: 0,
  stdout: mode === "tainted"
    ? REAL_TAINTED_EXECSTART + "\n"
    : mode
    ? execStart("controller --enable-worker=true --no-taints")
    : execStart("controller"),
});
const isShow = (argv: string[]) =>
  argv[0] === "systemctl" && argv[1] === "show";

const ABSENT = { code: 1, stderr: "Unit could not be found." };

const installed = { value: false };

function installRouter(argv: string[]) {
  if (argv[0] === "systemctl" && argv[1] === "cat") installed.value = false;
  if (argv[0] === "systemctl" && argv[1] === "enable") installed.value = true;
  if (argv[0] === "systemctl" && argv[1] === "is-active") {
    return { code: installed.value ? 0 : 3, stdout: "" };
  }
  if (argv[0] === "systemctl" && argv[1] === "cat") return ABSENT;
  if (argv[0] === "uname") return { code: 0, stdout: "x86_64\n" };
  return { code: 0, stdout: "", stderr: "" };
}

function adoptRouter(
  configSha: string,
  binarySha: string = PAYLOAD_SHA,
  presentUnit = "k0scontroller",
): (argv: string[]) => { code?: number; stdout?: string } {
  return (argv) => {
    if (isShow(argv)) return showController(true);
    if (argv[0] === "systemctl" && argv[1] === "cat") {
      return argv[2] === presentUnit ? { code: 0 } : ABSENT;
    }
    if (argv[0] === "systemctl" && argv[1] === "is-active") {
      return { code: 0, stdout: "active\n" };
    }
    if (argv[0] === "sha256sum" && argv[1] === K0S_BINARY_PATH) {
      return { code: 0, stdout: `${binarySha}  ${K0S_BINARY_PATH}\n` };
    }
    if (argv[0] === "sha256sum" && argv[1] === K0S_CONFIG_PATH) {
      return { code: 0, stdout: `${configSha}  ${K0S_CONFIG_PATH}\n` };
    }
    if (argv[0] === K0S_BINARY_PATH && argv[1] === "version") {
      return { code: 0, stdout: `${VERSION}\n` };
    }
    return { code: 0, stdout: "" };
  };
}

const READY_NODES = JSON.stringify({
  items: [{
    metadata: { name: "k0s-lab" },
    status: { conditions: [{ type: "Ready", status: "True" }] },
  }],
});
const READY_PODS = JSON.stringify({
  items: [{
    metadata: { namespace: "kube-system", name: "coredns" },
    status: {
      phase: "Running",
      conditions: [{ type: "Ready", status: "True" }],
    },
  }],
});
const HELM_CHARTS = JSON.stringify({
  items: [{
    metadata: { name: "k0s-addon-chart-nginx" },
    spec: { namespace: "default" },
    status: { releaseName: "nginx", version: "1.2.3", namespace: "default" },
  }],
});
const HELM_SECRETS = JSON.stringify({
  items: [{
    type: "helm.sh/release.v1",
    metadata: {
      name: "sh.helm.release.v1.nginx.v1",
      namespace: "default",
      labels: { status: "deployed" },
    },
  }],
});

const FAKE_KUBECONFIG = [
  "apiVersion: v1",
  "kind: Config",
  "clusters:",
  "- cluster:",
  "    server: https://192.0.2.10:6443",
  "  name: k0s",
  "contexts:",
  "- context:",
  "    cluster: k0s",
  "    user: admin",
  "  name: k0s",
  "current-context: k0s",
  "users:",
  "- name: admin",
  "  user:",
  "    client-certificate-data: FAKE-CERT-DATA",
  "    client-key-data: FAKE-KEY-DATA",
  "",
].join("\n");

Deno.test("render_config renders the golden and stores the file", async () => {
  const fake = makeDeps();
  const model = createModel(fake.deps);
  const args = model.methods.render_config.arguments.parse({
    k0s_version: VERSION,
    ...CLUSTER,
    manifests: [{
      name: "example-stack",
      files: [{ path: "namespace.yaml", content: "kind: Namespace\n" }],
    }],
    helm: [],
  });
  const { context, getWrittenFiles } = createModelTestContext();
  const out = await model.methods.render_config.execute(args, context);
  const expected = await Deno.readTextFile(
    new URL("./_lib/testdata/single-node.golden.txt", import.meta.url),
  );
  assertEquals(out.result.k0s_yaml, expected);
  assertEquals(
    out.result.config_sha256,
    await sha256Hex(encoder.encode(expected)),
  );
  assertEquals(out.result.manifests[0].stack, "example-stack");
  assertEquals(out.result.manifests[0].files[0].path.length > 0, true);
  assertEquals("sha256" in out.result.manifests[0].files[0], false);
  const files = getWrittenFiles();
  assertEquals(files.length, 1);
  assertEquals(new TextDecoder().decode(files[0].content), expected);
  assertEquals(fake.execs.length, 0);
});

Deno.test("install verifies, uploads and starts a single-node cluster", async () => {
  const fake = makeDeps({
    exec: installRouter,
    fetch: () => Promise.resolve(PAYLOAD),
  });
  const model = createModel(fake.deps);
  const { context, getWrittenResources } = createModelTestContext();
  const out = await model.methods.install.execute(installArgs(), context);
  assertEquals(out.result, {
    host: HOST,
    k0s_version: VERSION,
    role: "single",
    config_sha256: out.result.config_sha256,
  });
  assertEquals(fake.fetches, [
    `https://github.com/k0sproject/k0s/releases/download/${VERSION}/k0s-${VERSION}-amd64`,
  ]);
  const binary = fake.uploads.find((u) => u.path === K0S_BINARY_PATH);
  assertEquals(binary?.mode, "0755");
  assertEquals(binary?.content.length, PAYLOAD.length);
  assertEquals(fake.uploads.some((u) => u.path === K0S_CONFIG_PATH), true);
  assertEquals(
    fake.execs.find((argv) => argv[1] === "install"),
    [
      K0S_BINARY_PATH,
      "install",
      "controller",
      "--enable-worker",
      "--no-taints",
    ],
  );
  assertEquals(
    fake.execs.some((argv) => argv[0] === "systemctl" && argv[1] === "enable"),
    true,
  );
  const state = primary(getWrittenResources()).data as Record<string, unknown>;
  assertEquals(state.host, HOST);
  assertEquals(state.binary_sha256, PAYLOAD_SHA);
  assertEquals(state.installed, true);
  assertEquals(state.adopted, false);
});

Deno.test("install refuses a binary whose SHA-256 does not match", async () => {
  const fake = makeDeps({
    exec: installRouter,
    fetch: () => Promise.resolve(PAYLOAD),
  });
  const model = createModel(fake.deps);
  const { context } = createModelTestContext();
  await assertRejects(
    () =>
      model.methods.install.execute(
        installArgs({ k0s_binary_sha256: "0".repeat(64) }),
        context,
      ),
    ChecksumMismatchError,
    "refusing to install",
  );
  assertEquals(fake.uploads.length, 0);
  assertEquals(fake.execs.some((argv) => argv[1] === "install"), false);
});

Deno.test("install names the URL when the download fails", async () => {
  const fake = makeDeps({
    exec: installRouter,
    fetch: () => {
      throw new DownloadError("https://example.com/k0s", "HTTP 404");
    },
  });
  const model = createModel(fake.deps);
  const { context } = createModelTestContext();
  await assertRejects(
    () => model.methods.install.execute(installArgs(), context),
    DownloadError,
    "https://example.com/k0s",
  );
  assertEquals(fake.uploads.length, 0);
});

Deno.test("install adopts an active service without re-fetching", async () => {
  const yaml = renderK0sConfig({ ...CLUSTER, helm: [] });
  const configSha = await sha256Hex(encoder.encode(yaml));
  const fake = makeDeps({
    exec: adoptRouter(configSha),
    uploadChanged: () => false,
    fetch: () => {
      throw new Error("fetch must not run on adopt");
    },
  });
  const model = createModel(fake.deps);
  const { context } = createModelTestContext();
  const out = await model.methods.install.execute(installArgs(), context);
  assertEquals(out.result.config_sha256, configSha);
  // The config goes through upload even when unchanged, so its mode is
  // converged to 0600; unchanged bytes and mode mean no restart.
  assertEquals(fake.uploads.map((u) => [u.path, u.mode]), [
    [K0S_CONFIG_PATH, "0600"],
  ]);
  assertEquals(
    fake.execs.some((argv) => argv[0] === "systemctl" && argv[1] === "restart"),
    false,
  );
  assertEquals(fake.fetches.length, 0);
});

Deno.test("install refuses to adopt a binary that does not match the pin", async () => {
  const configSha = await sha256Hex(
    encoder.encode(renderK0sConfig({ ...CLUSTER, helm: [] })),
  );
  const fake = makeDeps({
    exec: adoptRouter(configSha, "0".repeat(64)),
  });
  const model = createModel(fake.deps);
  const { context } = createModelTestContext();
  await assertRejects(
    () => model.methods.install.execute(installArgs(), context),
    Error,
    "refusing to adopt",
  );
  assertEquals(fake.uploads.length, 0);
});

Deno.test("install restarts the service when the rendered config changed", async () => {
  const fake = makeDeps({
    exec: adoptRouter("a".repeat(64)),
  });
  const model = createModel(fake.deps);
  const { context } = createModelTestContext();
  await model.methods.install.execute(installArgs(), context);
  assertEquals(fake.uploads.some((u) => u.path === K0S_CONFIG_PATH), true);
  assertEquals(
    fake.execs.some((argv) => argv[1] === "restart"),
    true,
  );
});

Deno.test("install requires a join token for the worker role", async () => {
  const fake = makeDeps({ exec: installRouter });
  const model = createModel(fake.deps);
  const { context } = createModelTestContext();
  await assertRejects(
    () =>
      model.methods.install.execute(installArgs({ role: "worker" }), context),
    Error,
    "join_token",
  );
});

Deno.test("wait_ready returns ready once the node and system pods are up", async () => {
  const fake = makeDeps({
    exec: (argv) => {
      if (argv.includes("nodes")) return { code: 0, stdout: READY_NODES };
      if (argv.includes("pods")) return { code: 0, stdout: READY_PODS };
      return { code: 0, stdout: "" };
    },
  });
  const model = createModel(fake.deps);
  const args = model.methods.wait_ready.arguments.parse({ ssh: SSH });
  const { context } = createModelTestContext();
  const out = await model.methods.wait_ready.execute(args, context);
  assertEquals(out.result.ready, true);
  assertEquals(out.result.node, { name: "k0s-lab", ready: true });
  assertEquals(out.result.system_pods.length, 1);
});

Deno.test("wait_ready returns ready false after the timeout, not a hang", async () => {
  const fake = makeDeps({
    exec: (argv) => {
      if (argv.includes("nodes")) {
        return {
          code: 0,
          stdout: JSON.stringify({
            items: [{
              metadata: { name: "k0s-lab" },
              status: { conditions: [{ type: "Ready", status: "False" }] },
            }],
          }),
        };
      }
      return { code: 0, stdout: "" };
    },
  });
  const model = createModel(fake.deps);
  const args = model.methods.wait_ready.arguments.parse({
    ssh: SSH,
    ready_timeout_s: 10,
    poll_interval_s: 1,
  });
  const { context, getWrittenResources } = createModelTestContext();
  const out = await model.methods.wait_ready.execute(args, context);
  assertEquals(out.result.ready, false);
  assertEquals(
    (primary(getWrittenResources()).data as { ready: boolean }).ready,
    false,
  );
});

Deno.test("kubeconfig stores a sensitive value and leaks nothing", async () => {
  const fake = makeDeps({
    exec: (argv) => {
      if (argv.includes("kubeconfig")) {
        return { code: 0, stdout: FAKE_KUBECONFIG };
      }
      return { code: 0, stdout: "" };
    },
  });
  const model = createModel(fake.deps);
  const args = model.methods.kubeconfig.arguments.parse({ ssh: SSH });
  const { context, getWrittenResources, getLogs } = createModelTestContext();
  const out = await model.methods.kubeconfig.execute(args, context);
  const returned = JSON.stringify(out.result);
  assertEquals(returned.includes("client-key-data"), false);
  assertEquals(returned.includes("FAKE-KEY-DATA"), false);
  assertEquals(out.result.server, "https://192.0.2.10:6443");
  assertEquals(out.result.sha256.length, 64);
  const resource = primary(getWrittenResources());
  assertEquals(
    (resource.data.kubeconfig as string).includes("client-key-data"),
    true,
    "the raw kubeconfig is kept only for the vault",
  );
  for (const log of getLogs()) {
    assertEquals(JSON.stringify(log).includes("client-key-data"), false);
  }
  const schema = model.resources.kubeconfig.schema;
  assertEquals(schema.shape.kubeconfig.meta()?.sensitive, true);
});

Deno.test("no production source embeds kubeconfig or key material", async () => {
  for (const file of ["k0s_cluster.ts", "_lib/k0s.ts", "_lib/ssh.ts"]) {
    const text = await Deno.readTextFile(new URL(`./${file}`, import.meta.url));
    assertEquals(
      /client-key-data|BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY|BEGIN CERTIFICATE/
        .test(text),
      false,
      file,
    );
  }
});

Deno.test("apply_manifests is a no-op when the stack is unchanged", async () => {
  const content = "kind: ConfigMap\nmetadata:\n  name: example\n";
  const digest = await sha256Hex(encoder.encode(content));
  void digest;
  const fake = makeDeps({
    uploadChanged: () => false,
    exec: (argv) => {
      if (argv[0] === "find") {
        return {
          code: 0,
          stdout: `${K0S_MANIFEST_DIR}/example/configmap.yaml\n`,
        };
      }
      return { code: 0, stdout: "" };
    },
  });
  const model = createModel(fake.deps);
  const args = model.methods.apply_manifests.arguments.parse({
    ssh: SSH,
    stack: { name: "example", files: [{ path: "configmap.yaml", content }] },
  });
  const { context } = createModelTestContext();
  const out = await model.methods.apply_manifests.execute(args, context);
  assertEquals(out.result.applied, false);
  // Even an unchanged file is pushed through upload, which converges its mode.
  assertEquals(fake.uploads.map((u) => u.mode), ["0600"]);
});

Deno.test("apply_manifests uploads changed files and removes stale ones", async () => {
  const fake = makeDeps({
    exec: (argv) => {
      if (argv[0] === "find") {
        return {
          code: 0,
          stdout: [
            `${K0S_MANIFEST_DIR}/example/configmap.yaml`,
            `${K0S_MANIFEST_DIR}/example/stale.yaml`,
            "",
          ].join("\n"),
        };
      }
      if (argv[0] === "sha256sum") {
        return { code: 0, stdout: `${"a".repeat(64)}  ${argv[1]}\n` };
      }
      return { code: 0, stdout: "" };
    },
  });
  const model = createModel(fake.deps);
  const args = model.methods.apply_manifests.arguments.parse({
    ssh: SSH,
    stack: {
      name: "example",
      files: [{ path: "configmap.yaml", content: "kind: ConfigMap\n" }],
    },
  });
  const { context } = createModelTestContext();
  const out = await model.methods.apply_manifests.execute(args, context);
  assertEquals(out.result.applied, true);
  assertEquals(
    fake.uploads.some((u) =>
      u.path === `${K0S_MANIFEST_DIR}/example/configmap.yaml`
    ),
    true,
  );
  assertEquals(
    fake.execs.some((argv) =>
      argv[0] === "rm" && argv[2] === `${K0S_MANIFEST_DIR}/example/stale.yaml`
    ),
    true,
  );
});

Deno.test("apply_helm reconciles a declared chart", async () => {
  const helm = [{
    chart: "example/nginx",
    repo: "https://charts.example.com",
    version: "1.2.3",
    namespace: "default",
  }];
  const yaml = renderK0sConfig({ ...CLUSTER, helm });
  const configSha = await sha256Hex(encoder.encode(yaml));
  void configSha;
  const fake = makeDeps({
    uploadChanged: () => false,
    exec: (argv) => {
      if (argv.includes("charts.helm.k0sproject.io")) {
        return { code: 0, stdout: HELM_CHARTS };
      }
      if (argv.includes("secrets")) return { code: 0, stdout: HELM_SECRETS };
      return { code: 0, stdout: "" };
    },
  });
  const model = createModel(fake.deps);
  const args = model.methods.apply_helm.arguments.parse({
    ssh: SSH,
    ...CLUSTER,
    helm,
  });
  const { context } = createModelTestContext();
  const out = await model.methods.apply_helm.execute(args, context);
  assertEquals(out.result.reconciled, true);
  assertEquals(out.result.charts[0].status, "deployed");
  assertEquals(fake.uploads.map((u) => u.mode), ["0600"]);
  assertEquals(
    fake.execs.some((argv) => argv[0] === "systemctl" && argv[1] === "restart"),
    false,
  );
});

Deno.test("apply_helm fails when a chart never reconciles", async () => {
  const fake = makeDeps({
    exec: (argv) => {
      if (argv[0] === "sha256sum") {
        return { code: 0, stdout: `${"a".repeat(64)}  ${K0S_CONFIG_PATH}\n` };
      }
      if (argv.includes("secrets")) {
        return { code: 0, stdout: '{"items":[]}' };
      }
      return { code: 0, stdout: "" };
    },
  });
  const model = createModel(fake.deps);
  const args = model.methods.apply_helm.arguments.parse({
    ssh: SSH,
    ...CLUSTER,
    helm: [{
      chart: "example/missing",
      repo: "https://charts.example.com",
      version: "9.9.9",
      namespace: "default",
    }],
    reconcile_timeout_s: 10,
    poll_interval_s: 1,
  });
  const { context } = createModelTestContext();
  await assertRejects(
    () => model.methods.apply_helm.execute(args, context),
    Error,
    "default/missing",
  );
});

Deno.test("get reports live cluster state", async () => {
  const fake = makeDeps({
    exec: (argv) => {
      if (argv.includes("version")) return { code: 0, stdout: `${VERSION}\n` };
      if (argv.includes("nodes")) return { code: 0, stdout: READY_NODES };
      if (argv.includes("pods")) return { code: 0, stdout: READY_PODS };
      if (argv[0] === "sha256sum") {
        return { code: 0, stdout: `${"b".repeat(64)}  ${K0S_CONFIG_PATH}\n` };
      }
      if (argv[0] === "ls") return { code: 0, stdout: "example\n" };
      if (argv.includes("charts.helm.k0sproject.io")) {
        return { code: 0, stdout: HELM_CHARTS };
      }
      if (argv.includes("secrets")) return { code: 0, stdout: HELM_SECRETS };
      return { code: 0, stdout: "" };
    },
  });
  const model = createModel(fake.deps);
  const args = model.methods.get.arguments.parse({ ssh: SSH });
  const { context } = createModelTestContext();
  const out = await model.methods.get.execute(args, context);
  assertEquals(out.result.installed, true);
  assertEquals(out.result.k0s_version, VERSION);
  assertEquals(out.result.kubeconfig_present, false);
  assertEquals(out.result.stacks, ["example"]);
  assertEquals(out.result.helm_releases[0].name, "nginx");
});

Deno.test("sync reports drift and refreshes status", async () => {
  const fake = makeDeps({
    exec: (argv) => {
      if (argv.includes("version")) return { code: 0, stdout: `${VERSION}\n` };
      return { code: 0, stdout: "" };
    },
  });
  const model = createModel(fake.deps);
  const args = model.methods.sync.arguments.parse({ ssh: SSH });
  const { context } = createModelTestContext();
  const out = await model.methods.sync.execute(args, context);
  assertEquals(out.result.in_sync, false);
  assertEquals(
    out.result.diffs.some((d) => d.includes("no recorded install")),
    true,
  );
});

Deno.test("reset is a clean no-op when no k0s service exists", async () => {
  const fake = makeDeps({
    exec: (argv) => {
      if (argv[0] === "systemctl" && argv[1] === "cat") return ABSENT;
      return { code: 0, stdout: "" };
    },
  });
  const model = createModel(fake.deps);
  const args = model.methods.reset.arguments.parse({
    ssh: SSH,
    confirm_host: HOST,
  });
  const { context } = createModelTestContext();
  const out = await model.methods.reset.execute(args, context);
  assertEquals(out.result.reset, false);
  assertEquals(fake.execs.some((argv) => argv[1] === "reset"), false);
});

Deno.test("reset stops and resets an installed cluster", async () => {
  const fake = makeDeps({
    exec: (argv) => {
      if (
        argv[0] === "systemctl" && argv[1] === "cat" &&
        argv[2] === "k0scontroller"
      ) {
        return { code: 0, stdout: "unit\n" };
      }
      if (argv[0] === "systemctl" && argv[1] === "is-active") {
        return { code: 0, stdout: "active\n" };
      }
      if (argv[0] === "systemctl" && argv[1] === "cat") return ABSENT;
      return { code: 0, stdout: "" };
    },
  });
  const model = createModel(fake.deps);
  const args = model.methods.reset.arguments.parse({
    ssh: SSH,
    confirm_host: HOST,
  });
  const { context } = createModelTestContext();
  const out = await model.methods.reset.execute(args, context);
  assertEquals(out.result.reset, true);
  assertEquals(fake.execs.some((argv) => argv[1] === "stop"), true);
  assertEquals(fake.execs.some((argv) => argv[1] === "reset"), true);
  assertEquals(
    fake.execs.some((argv) => argv[0] === "rm" && argv[2] === K0S_CONFIG_PATH),
    true,
  );
});

Deno.test("reset removes the config dir and the installed binary", async () => {
  const fake = makeDeps({
    exec: (argv) => {
      if (
        argv[0] === "systemctl" && argv[1] === "cat" &&
        argv[2] === "k0scontroller"
      ) {
        return { code: 0, stdout: "unit\n" };
      }
      if (argv[0] === "systemctl" && argv[1] === "cat") return ABSENT;
      if (argv[0] === "sha256sum" && argv[1] === K0S_BINARY_PATH) {
        return { code: 0, stdout: `${PAYLOAD_SHA}  ${K0S_BINARY_PATH}\n` };
      }
      return { code: 0, stdout: "" };
    },
  });
  const model = createModel(fake.deps);
  const args = model.methods.reset.arguments.parse({
    ssh: SSH,
    confirm_host: HOST,
  });
  const { context } = createModelTestContext({
    storedResources: {
      [targetId({ host: HOST, port: 22, user: "root" })]: {
        binary_sha256: PAYLOAD_SHA,
      },
    },
  });
  const out = await model.methods.reset.execute(args, context);
  assertEquals(out.result.reset, true);
  assertEquals(
    fake.execs.some((argv) =>
      argv[0] === "rm" && argv[1] === "-rf" && argv[2] === "/etc/k0s"
    ),
    true,
  );
  assertEquals(
    fake.execs.some((argv) =>
      argv[0] === "rm" && argv[1] === "-f" && argv[2] === K0S_BINARY_PATH
    ),
    true,
  );
});

Deno.test("reset keeps a binary whose digest is not the installed one", async () => {
  const fake = makeDeps({
    exec: (argv) => {
      if (
        argv[0] === "systemctl" && argv[1] === "cat" &&
        argv[2] === "k0scontroller"
      ) {
        return { code: 0, stdout: "unit\n" };
      }
      if (argv[0] === "systemctl" && argv[1] === "cat") return ABSENT;
      if (argv[0] === "sha256sum" && argv[1] === K0S_BINARY_PATH) {
        return { code: 0, stdout: `${"f".repeat(64)}  ${K0S_BINARY_PATH}\n` };
      }
      return { code: 0, stdout: "" };
    },
  });
  const model = createModel(fake.deps);
  const args = model.methods.reset.arguments.parse({
    ssh: SSH,
    confirm_host: HOST,
  });
  const { context } = createModelTestContext({
    storedResources: {
      [targetId({ host: HOST, port: 22, user: "root" })]: {
        binary_sha256: PAYLOAD_SHA,
      },
    },
  });
  await model.methods.reset.execute(args, context);
  assertEquals(
    fake.execs.some((argv) =>
      argv[0] === "rm" && argv[1] === "-f" && argv[2] === K0S_BINARY_PATH
    ),
    false,
  );
});

Deno.test("reset removes the config dir but no binary when none is recorded", async () => {
  const fake = makeDeps({
    exec: (argv) => {
      if (
        argv[0] === "systemctl" && argv[1] === "cat" &&
        argv[2] === "k0scontroller"
      ) {
        return { code: 0, stdout: "unit\n" };
      }
      if (argv[0] === "systemctl" && argv[1] === "cat") return ABSENT;
      return { code: 0, stdout: "" };
    },
  });
  const model = createModel(fake.deps);
  const args = model.methods.reset.arguments.parse({
    ssh: SSH,
    confirm_host: HOST,
  });
  const { context } = createModelTestContext();
  await model.methods.reset.execute(args, context);
  assertEquals(
    fake.execs.some((argv) =>
      argv[0] === "rm" && argv[1] === "-rf" && argv[2] === "/etc/k0s"
    ),
    true,
  );
  assertEquals(
    fake.execs.some((argv) =>
      argv[0] === "rm" && argv[1] === "-f" && argv[2] === K0S_BINARY_PATH
    ),
    false,
  );
});

Deno.test("a failed k0s reset removes nothing", async () => {
  const fake = makeDeps({
    exec: (argv) => {
      if (
        argv[0] === "systemctl" && argv[1] === "cat" &&
        argv[2] === "k0scontroller"
      ) {
        return { code: 0, stdout: "unit\n" };
      }
      if (argv[0] === "systemctl" && argv[1] === "cat") return ABSENT;
      if (argv[0] === K0S_BINARY_PATH && argv[1] === "reset") {
        return { code: 1, stdout: "", stderr: "reset failed" };
      }
      return { code: 0, stdout: "" };
    },
  });
  const model = createModel(fake.deps);
  const args = model.methods.reset.arguments.parse({
    ssh: SSH,
    confirm_host: HOST,
  });
  const { context } = createModelTestContext();
  await assertRejects(
    () => model.methods.reset.execute(args, context),
    Error,
    "k0s reset failed",
  );
  assertEquals(fake.execs.some((argv) => argv[0] === "rm"), false);
});

Deno.test("reset retries a pending cleanup on a host with no unit", async () => {
  const fake = makeDeps({
    exec: (argv) => {
      if (argv[0] === "systemctl" && argv[1] === "cat") return ABSENT;
      if (argv[0] === "sha256sum" && argv[1] === K0S_BINARY_PATH) {
        return { code: 0, stdout: `${PAYLOAD_SHA}  ${K0S_BINARY_PATH}\n` };
      }
      return { code: 0, stdout: "" };
    },
  });
  const model = createModel(fake.deps);
  const args = model.methods.reset.arguments.parse({
    ssh: SSH,
    confirm_host: HOST,
  });
  const { context } = createModelTestContext({
    storedResources: {
      [targetId({ host: HOST, port: 22, user: "root" })]: {
        binary_sha256: PAYLOAD_SHA,
        cleanup_pending: true,
      },
    },
  });
  const out = await model.methods.reset.execute(args, context);
  assertEquals(out.result.reset, true);
  assertEquals(
    fake.execs.some((argv) =>
      argv[0] === "rm" && argv[1] === "-rf" && argv[2] === "/etc/k0s"
    ),
    true,
  );
  assertEquals(
    fake.execs.some((argv) =>
      argv[0] === "rm" && argv[1] === "-f" && argv[2] === K0S_BINARY_PATH
    ),
    true,
  );
});

Deno.test("reset raises a typed error when the binary digest cannot be read", async () => {
  const fake = makeDeps({
    exec: (argv) => {
      if (
        argv[0] === "systemctl" && argv[1] === "cat" &&
        argv[2] === "k0scontroller"
      ) {
        return { code: 0, stdout: "unit\n" };
      }
      if (argv[0] === "systemctl" && argv[1] === "cat") return ABSENT;
      if (argv[0] === "sha256sum" && argv[1] === K0S_BINARY_PATH) {
        return { code: 1, stdout: "", stderr: "no such file" };
      }
      return { code: 0, stdout: "" };
    },
  });
  const model = createModel(fake.deps);
  const args = model.methods.reset.arguments.parse({
    ssh: SSH,
    confirm_host: HOST,
  });
  const { context } = createModelTestContext({
    storedResources: {
      [targetId({ host: HOST, port: 22, user: "root" })]: {
        binary_sha256: PAYLOAD_SHA,
      },
    },
  });
  await assertRejects(
    () => model.methods.reset.execute(args, context),
    ResetCleanupError,
  );
  assertEquals(
    fake.execs.some((argv) =>
      argv[0] === "rm" && argv[1] === "-f" && argv[2] === K0S_BINARY_PATH
    ),
    false,
  );
});

Deno.test("reset skips k0s stop when the unit is already inactive", async () => {
  const fake = makeDeps({
    exec: (argv) => {
      if (
        argv[0] === "systemctl" && argv[1] === "cat" &&
        argv[2] === "k0scontroller"
      ) {
        return { code: 0, stdout: "unit\n" };
      }
      if (argv[0] === "systemctl" && argv[1] === "is-active") {
        return { code: 3, stdout: "inactive\n" };
      }
      if (argv[0] === "systemctl" && argv[1] === "cat") return ABSENT;
      return { code: 0, stdout: "" };
    },
  });
  const model = createModel(fake.deps);
  const args = model.methods.reset.arguments.parse({
    ssh: SSH,
    confirm_host: HOST,
  });
  const { context } = createModelTestContext();
  const out = await model.methods.reset.execute(args, context);
  assertEquals(out.result.reset, true);
  assertEquals(fake.execs.some((argv) => argv[1] === "stop"), false);
  assertEquals(fake.execs.some((argv) => argv[1] === "reset"), true);
});

Deno.test("reset survives a stop that exits non-zero on an inactive unit", async () => {
  let activeChecks = 0;
  const fake = makeDeps({
    exec: (argv) => {
      if (
        argv[0] === "systemctl" && argv[1] === "cat" &&
        argv[2] === "k0scontroller"
      ) {
        return { code: 0, stdout: "unit\n" };
      }
      if (argv[0] === "systemctl" && argv[1] === "is-active") {
        activeChecks++;
        return activeChecks === 1
          ? { code: 0, stdout: "active\n" }
          : { code: 3, stdout: "inactive\n" };
      }
      if (argv[0] === K0S_BINARY_PATH && argv[1] === "stop") {
        return { code: 1, stdout: "", stderr: "already stopped" };
      }
      if (argv[0] === "systemctl" && argv[1] === "cat") return ABSENT;
      return { code: 0, stdout: "" };
    },
  });
  const model = createModel(fake.deps);
  const args = model.methods.reset.arguments.parse({
    ssh: SSH,
    confirm_host: HOST,
  });
  const { context } = createModelTestContext();
  const out = await model.methods.reset.execute(args, context);
  assertEquals(out.result.reset, true);
  assertEquals(fake.execs.some((argv) => argv[1] === "stop"), true);
  assertEquals(fake.execs.some((argv) => argv[1] === "reset"), true);
});

Deno.test("reset reports a foreign binary it left in place", async () => {
  const fake = makeDeps({
    exec: (argv) => {
      if (
        argv[0] === "systemctl" && argv[1] === "cat" &&
        argv[2] === "k0scontroller"
      ) {
        return { code: 0, stdout: "unit\n" };
      }
      if (argv[0] === "systemctl" && argv[1] === "cat") return ABSENT;
      if (argv[0] === "sha256sum" && argv[1] === K0S_BINARY_PATH) {
        return { code: 0, stdout: `${"f".repeat(64)}  ${K0S_BINARY_PATH}\n` };
      }
      return { code: 0, stdout: "" };
    },
  });
  const model = createModel(fake.deps);
  const args = model.methods.reset.arguments.parse({
    ssh: SSH,
    confirm_host: HOST,
  });
  const { context } = createModelTestContext({
    storedResources: {
      [targetId({ host: HOST, port: 22, user: "root" })]: {
        binary_sha256: PAYLOAD_SHA,
      },
    },
  });
  const out = await model.methods.reset.execute(args, context);
  assertEquals(out.result.reset, true);
  assertEquals(out.result.binary_removed, false);
  assertEquals(
    String(out.result.reason).includes("does not match"),
    true,
  );
});

Deno.test("reset refuses a confirm_host that does not match", async () => {
  const fake = makeDeps();
  const model = createModel(fake.deps);
  const args = model.methods.reset.arguments.parse({
    ssh: SSH,
    confirm_host: "198.51.100.20",
  });
  const { context } = createModelTestContext();
  await assertRejects(
    () => model.methods.reset.execute(args, context),
    Error,
    "does not match",
  );
});

Deno.test("the grammar rejects injection on every remote-bound input", () => {
  const model = createModel(makeDeps().deps);
  const bad = [
    { ssh: { ...SSH, host: "192.0.2.10; rm -rf /" } },
    { ssh: { ...SSH, user: "root; rm -rf /" } },
    { k0s_version: `v1.0.0; rm -rf /` },
    { k0s_version: "v1.0.0`id`" },
    { cluster_name: "Bad_Name" },
    { api_sans: ["$(whoami)"] },
    { k0s_download_url: "https://example.com/k0s; rm -rf /" },
    { pod_cidr: "not-a-cidr" },
  ];
  for (const override of bad) {
    assertThrows(
      () =>
        model.methods.install.arguments.parse({
          ...installArgs(),
          ...override,
        }),
      Error,
      undefined,
      JSON.stringify(override),
    );
  }
});

Deno.test("strict host-key policy requires pinned keys at the schema body", () => {
  const model = createModel(makeDeps().deps);
  assertThrows(() =>
    model.methods.install.arguments.parse({
      ...installArgs(),
      ssh: { ...SSH, host_key_policy: "strict" },
    })
  );
  const pinned = model.methods.install.arguments.parse({
    ...installArgs(),
    ssh: {
      ...SSH,
      host_key_policy: "strict",
      host_keys: ["192.0.2.10 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFAKE"],
    },
  });
  assertEquals(pinned.ssh.host_key_policy, "strict");
});

Deno.test("render_config redacts helm values and writes no file", async () => {
  const fake = makeDeps();
  const model = createModel(fake.deps);
  const args = model.methods.render_config.arguments.parse({
    k0s_version: VERSION,
    ...CLUSTER,
    helm: [{
      chart: "example/nginx",
      repo: "https://charts.example.com",
      version: "1.2.3",
      namespace: "default",
      values: { adminPassword: "PLACEHOLDER-PASSWORD" },
    }],
  });
  const { context, getWrittenFiles } = createModelTestContext();
  const out = await model.methods.render_config.execute(args, context);
  assertEquals(out.result.values_redacted, true);
  assertEquals(out.result.k0s_yaml.includes("adminPassword"), false);
  assertEquals(out.result.k0s_yaml.includes("PLACEHOLDER-PASSWORD"), false);
  assertEquals(out.result.config_sha256.length, 64);
  assertEquals(getWrittenFiles().length, 0);
});

Deno.test("the schema rejects duplicate manifest paths", () => {
  const model = createModel(makeDeps().deps);
  assertThrows(
    () =>
      model.methods.apply_manifests.arguments.parse({
        ssh: SSH,
        stack: {
          name: "example",
          files: [
            { path: "./a.yaml", content: "one" },
            { path: "a.yaml", content: "two" },
          ],
        },
      }),
    Error,
    undefined,
    "duplicate manifest path",
  );
});

Deno.test("the schema rejects a URL that embeds credentials", () => {
  const model = createModel(makeDeps().deps);
  assertThrows(
    () =>
      model.methods.install.arguments.parse(
        installArgs({
          k0s_download_url: "https://user:pass@example.com/k0s",
        }),
      ),
    Error,
    undefined,
    "must not embed credentials",
  );
});

Deno.test("wait_ready raises a transport failure and stores no readiness", async () => {
  const fake = makeDeps({
    exec: (argv) => {
      if (argv.includes("nodes")) {
        throw new SshError("192.0.2.10:22: authentication failed");
      }
      return { code: 0, stdout: "" };
    },
  });
  const model = createModel(fake.deps);
  const args = model.methods.wait_ready.arguments.parse({ ssh: SSH });
  const { context, getWrittenResources } = createModelTestContext();
  await assertRejects(
    () => model.methods.wait_ready.execute(args, context),
    SshError,
    "authentication failed",
  );
  assertEquals(primary(getWrittenResources(), true).length, 0);
});

Deno.test("get raises a transport failure and stores no status", async () => {
  const fake = makeDeps({
    exec: (argv) => {
      if (argv.includes("version")) {
        throw new SshError("192.0.2.10:22: host key verification failed");
      }
      return { code: 0, stdout: "" };
    },
  });
  const model = createModel(fake.deps);
  const args = model.methods.get.arguments.parse({ ssh: SSH });
  const { context, getWrittenResources } = createModelTestContext();
  await assertRejects(
    () => model.methods.get.execute(args, context),
    SshError,
    "host key verification failed",
  );
  assertEquals(primary(getWrittenResources(), true).length, 0);
});

Deno.test("reset fails and stores no state when cleanup fails", async () => {
  const fake = makeDeps({
    exec: (argv) => {
      if (
        argv[0] === "systemctl" && argv[1] === "cat" &&
        argv[2] === "k0scontroller"
      ) {
        return { code: 0, stdout: "unit\n" };
      }
      if (argv[0] === "systemctl" && argv[1] === "cat") {
        return { code: 1, stdout: "", stderr: "Unit could not be found." };
      }
      if (argv[0] === "rm") return { code: 1, stdout: "" };
      return { code: 0, stdout: "" };
    },
  });
  const model = createModel(fake.deps);
  const args = model.methods.reset.arguments.parse({
    ssh: SSH,
    confirm_host: HOST,
  });
  const { context, getWrittenResources } = createModelTestContext();
  await assertRejects(
    () => model.methods.reset.execute(args, context),
    Error,
    "could not remove the k0s configuration",
  );
  assertEquals(primary(getWrittenResources(), true).length, 0);
});

Deno.test("apply_manifests refuses to remove an unsafe stale entry", async () => {
  const content = "kind: ConfigMap\n";
  const digest = await sha256Hex(encoder.encode(content));
  const fake = makeDeps({
    exec: (argv) => {
      if (argv[0] === "find") {
        return {
          code: 0,
          stdout: [
            `${K0S_MANIFEST_DIR}/example/configmap.yaml`,
            `${K0S_MANIFEST_DIR}/example/../escape`,
            "",
          ].join("\n"),
        };
      }
      if (argv[0] === "sha256sum") {
        return { code: 0, stdout: `${digest}  ${argv[1]}\n` };
      }
      return { code: 0, stdout: "" };
    },
  });
  const model = createModel(fake.deps);
  const args = model.methods.apply_manifests.arguments.parse({
    ssh: SSH,
    stack: { name: "example", files: [{ path: "configmap.yaml", content }] },
  });
  const { context } = createModelTestContext();
  await assertRejects(
    () => model.methods.apply_manifests.execute(args, context),
    Error,
    "refusing to remove",
  );
});

Deno.test("the manifest packages README and LICENSE but not LOGBOOK", async () => {
  const text = await Deno.readTextFile(
    new URL("../../manifest.yaml", import.meta.url),
  );
  assertEquals(text.includes("README.md"), true);
  assertEquals(text.includes("LICENSE.txt"), true);
  assertEquals(text.includes("LOGBOOK.md"), false);
});

// --- escalation fixes -------------------------------------------------------

const ACTIVE_CONTROLLER = (argv: string[]) => {
  if (argv[0] === "systemctl" && argv[1] === "cat") {
    return argv[2] === "k0scontroller" ? { code: 0 } : ABSENT;
  }
  if (argv[0] === "systemctl" && argv[1] === "is-active") {
    return { code: argv[2] === "k0scontroller" ? 0 : 3 };
  }
  return undefined;
};

Deno.test("install refuses to turn an installed controller into a worker", async () => {
  const fake = makeDeps({ exec: ACTIVE_CONTROLLER });
  const model = createModel(fake.deps);
  const { context } = createModelTestContext();
  await assertRejects(
    () =>
      model.methods.install.execute(
        installArgs({ role: "worker", join_token: "PLACEHOLDER-JOIN-TOKEN" }),
        context,
      ),
    Error,
    "confirm_role_change",
  );
  assertEquals(fake.uploads.length, 0, "no token or config was sent");
  assertEquals(
    fake.execs.some((argv) => argv[1] === "install" || argv[1] === "reset"),
    false,
  );
  assertEquals(fake.fetches.length, 0);
});

Deno.test("allow_role_change stops and resets the old role before installing", async () => {
  const fake = makeDeps({
    exec: (argv) => {
      const cat = ACTIVE_CONTROLLER(argv);
      if (argv[0] === "systemctl" && argv[1] === "enable") {
        installed.value = true;
      }
      if (argv[0] === "systemctl" && argv[1] === "is-active") {
        return argv[2] === "k0sworker" && installed.value ? { code: 0 } : cat;
      }
      if (argv[0] === "uname") return { code: 0, stdout: "x86_64\n" };
      return cat;
    },
    fetch: () => Promise.resolve(PAYLOAD),
  });
  const model = createModel(fake.deps);
  const { context } = createModelTestContext();
  await model.methods.install.execute(
    installArgs({
      role: "worker",
      join_token: "PLACEHOLDER-JOIN-TOKEN",
      confirm_role_change: HOST,
    }),
    context,
  );
  const verbs = fake.execs.map((argv) => argv.slice(0, 2).join(" "));
  assertEquals(
    verbs.indexOf(`${K0S_BINARY_PATH} stop`) <
      verbs.indexOf(`${K0S_BINARY_PATH} reset`),
    true,
  );
  assertEquals(
    verbs.indexOf(`${K0S_BINARY_PATH} reset`) <
      verbs.indexOf(`${K0S_BINARY_PATH} install`),
    true,
  );
});

Deno.test("a failed k0s stop during force_reinstall is not ignored", async () => {
  const fake = makeDeps({
    exec: (argv) => {
      if (isShow(argv)) return showController(true);
      if (argv[0] === "systemctl" && argv[1] === "cat") {
        return argv[2] === "k0scontroller" ? { code: 0 } : ABSENT;
      }
      if (argv[0] === "systemctl" && argv[1] === "is-active") {
        return { code: 0 };
      }
      if (argv[0] === "uname") return { code: 0, stdout: "x86_64\n" };
      if (argv[1] === "stop") return { code: 1 };
      return undefined;
    },
    fetch: () => Promise.resolve(PAYLOAD),
  });
  const model = createModel(fake.deps);
  const { context, getWrittenResources } = createModelTestContext();
  await assertRejects(
    () =>
      model.methods.install.execute(
        installArgs({ force_reinstall: true }),
        context,
      ),
    Error,
    "k0s stop failed",
  );
  assertEquals(primary(getWrittenResources(), true).length, 0);
  assertEquals(fake.execs.some((argv) => argv[1] === "install"), false);
});

Deno.test("the join token goes up only on a fresh worker install", async () => {
  const fake = makeDeps({
    exec: (argv) => {
      if (argv[0] === "systemctl" && argv[1] === "cat") {
        return argv[2] === "k0sworker" ? { code: 0 } : ABSENT;
      }
      if (argv[0] === "systemctl" && argv[1] === "is-active") {
        return { code: 0 };
      }
      return undefined;
    },
  });
  const model = createModel(fake.deps);
  const { context } = createModelTestContext();
  // The unit is active but the binary digest is wrong: the adopt check fails.
  await assertRejects(
    () =>
      model.methods.install.execute(
        installArgs({ role: "worker", join_token: "PLACEHOLDER-JOIN-TOKEN" }),
        context,
      ),
    Error,
    "refusing to adopt",
  );
  assertEquals(fake.uploads.length, 0);
});

Deno.test("a failed restart on adoption fails and writes no state", async () => {
  const router = adoptRouter("0".repeat(64));
  const fake = makeDeps({
    exec: (argv) =>
      argv[0] === "systemctl" && argv[1] === "restart"
        ? { code: 1 }
        : router(argv),
  });
  const model = createModel(fake.deps);
  const { context, getWrittenResources } = createModelTestContext();
  await assertRejects(
    () => model.methods.install.execute(installArgs(), context),
    Error,
    "restart",
  );
  assertEquals(primary(getWrittenResources(), true).length, 0);
});

Deno.test("a restart that never turns healthy fails apply_helm", async () => {
  const fake = makeDeps({
    exec: (argv) => {
      if (argv[0] === "systemctl" && argv[1] === "is-active") {
        return { code: 3 };
      }
      return undefined;
    },
  });
  const model = createModel(fake.deps);
  const args = model.methods.apply_helm.arguments.parse({
    ssh: SSH,
    ...CLUSTER,
    helm: [{
      chart: "example/nginx",
      repo: "https://charts.example.com",
      version: "1.2.3",
      namespace: "default",
    }],
  });
  const { context, getWrittenResources } = createModelTestContext();
  await assertRejects(
    () => model.methods.apply_helm.execute(args, context),
    Error,
    "did not become healthy",
  );
  assertEquals(primary(getWrittenResources(), true).length, 0);
});

Deno.test("a failed restart fails apply_helm before it waits for releases", async () => {
  const fake = makeDeps({
    exec: (argv) =>
      argv[0] === "systemctl" && argv[1] === "restart"
        ? { code: 1 }
        : undefined,
  });
  const model = createModel(fake.deps);
  const args = model.methods.apply_helm.arguments.parse({
    ssh: SSH,
    ...CLUSTER,
    helm: [{
      chart: "example/nginx",
      repo: "https://charts.example.com",
      version: "1.2.3",
      namespace: "default",
    }],
  });
  const { context } = createModelTestContext();
  await assertRejects(
    () => model.methods.apply_helm.execute(args, context),
    Error,
    "systemctl restart k0scontroller failed",
  );
});

Deno.test("secret-bearing uploads are root-only", async () => {
  const fake = makeDeps({
    exec: installRouter,
    fetch: () => Promise.resolve(PAYLOAD),
  });
  const model = createModel(fake.deps);
  const { context } = createModelTestContext();
  await model.methods.install.execute(
    installArgs({
      helm: [{
        chart: "example/nginx",
        repo: "https://charts.example.com",
        version: "1.2.3",
        namespace: "default",
        values: { adminPassword: "PLACEHOLDER-PASSWORD" },
      }],
    }),
    context,
  );
  const config = fake.uploads.find((u) => u.path === K0S_CONFIG_PATH);
  assertEquals(config?.mode, "0600");
  const stack = makeDeps();
  const m2 = createModel(stack.deps);
  await m2.methods.apply_manifests.execute(
    m2.methods.apply_manifests.arguments.parse({
      ssh: SSH,
      stack: {
        name: "secrets",
        files: [{ path: "s.yaml", content: "kind: Secret\n" }],
      },
    }),
    context,
  );
  assertEquals(stack.uploads.every((u) => u.mode === "0600"), true);
});

Deno.test("the kubeconfig server URL is returned without credentials", async () => {
  const fake = makeDeps({
    exec: (argv) =>
      argv.includes("kubeconfig")
        ? {
          code: 0,
          stdout: FAKE_KUBECONFIG.replace(
            "https://192.0.2.10:6443",
            "https://admin:PLACEHOLDER-PW@192.0.2.10:6443/?token=PLACEHOLDER-TOKEN#frag",
          ),
        }
        : undefined,
  });
  const model = createModel(fake.deps);
  const { context, getWrittenResources } = createModelTestContext();
  const out = await model.methods.kubeconfig.execute(
    model.methods.kubeconfig.arguments.parse({ ssh: SSH }),
    context,
  );
  assertEquals(out.result.server, "https://192.0.2.10:6443");
  const stored = primary(getWrittenResources()).data as { server: string };
  assertEquals(stored.server, "https://192.0.2.10:6443");
});

Deno.test("targets that differ by port or user never share records", async () => {
  const fake = makeDeps({
    exec: (argv) =>
      argv.includes("kubeconfig")
        ? { code: 0, stdout: FAKE_KUBECONFIG }
        : undefined,
  });
  const model = createModel(fake.deps);
  const { context, getWrittenResources } = createModelTestContext();
  for (const ssh of [SSH, { ...SSH, port: 2222 }, { ...SSH, user: "admin" }]) {
    await model.methods.kubeconfig.execute(
      model.methods.kubeconfig.arguments.parse({ ssh }),
      context,
    );
  }
  const names = primary(getWrittenResources(), true).map((r) => r.name);
  assertEquals(new Set(names).size, 3);
  for (const name of names) assertEquals(name.includes("/"), false);
});

Deno.test("insecure_tofu learns host keys once, records them and pins later calls", async () => {
  const fake = makeDeps({
    exec: (argv) =>
      argv.includes("kubeconfig")
        ? { code: 0, stdout: FAKE_KUBECONFIG }
        : undefined,
  });
  const targets: (string[] | undefined)[] = [];
  const base = fake.deps.ssh;
  fake.deps.ssh = {
    ...base,
    exec: (target, argv) => {
      targets.push(target.host_keys);
      return base.exec(target, argv);
    },
  };
  const model = createModel(fake.deps);
  const args = model.methods.kubeconfig.arguments.parse({ ssh: SSH });
  const first = createModelTestContext();
  await model.methods.kubeconfig.execute(args, first.context);
  assertEquals(fake.learned.length, 1);
  const recorded = first.getWrittenResources().find((r) =>
    r.specName === "hostkeys"
  );
  assertEquals(
    (recorded?.data as { host_keys: string[] }).host_keys.length,
    1,
  );
  assertEquals(targets.every((keys) => keys?.length === 1), true);

  // A later call with the record on hand does not scan again and is pinned.
  const second = createModelTestContext({
    storedResources: {
      [recorded!.name]: recorded!.data as Record<string, unknown>,
    },
  });
  await model.methods.kubeconfig.execute(args, second.context);
  assertEquals(fake.learned.length, 1);
  assertEquals(
    targets.at(-1),
    (recorded?.data as { host_keys: string[] }).host_keys,
  );
});

Deno.test("URLs carrying a query, fragment or user info are rejected", () => {
  const model = createModel(makeDeps().deps);
  for (
    const repo of [
      "https://charts.example.com/?token=PLACEHOLDER",
      "https://charts.example.com/#frag",
      "https://user:PLACEHOLDER" + "@charts.example.com",
      "https://charts.example.com/a@b",
    ]
  ) {
    assertThrows(() =>
      model.methods.install.arguments.parse({
        ...installArgs(),
        helm: [{
          chart: "example/nginx",
          repo,
          version: "1.2.3",
          namespace: "default",
        }],
      })
    );
  }
  assertThrows(() =>
    model.methods.install.arguments.parse({
      ...installArgs(),
      k0s_download_url: "https://mirror.example.com/k0s?sig=PLACEHOLDER",
    })
  );
});

Deno.test("manifest paths that normalize to nothing are rejected", () => {
  const model = createModel(makeDeps().deps);
  for (const path of [".", "./", "./.", "a/", "a/.."]) {
    assertThrows(() =>
      model.methods.apply_manifests.arguments.parse({
        ssh: SSH,
        stack: { name: "s", files: [{ path, content: "x" }] },
      })
    );
  }
});

Deno.test("sensitive digests are not returned by get, apply_manifests or render_config", async () => {
  const fake = makeDeps({
    exec: (argv) =>
      argv[1] === "version"
        ? { code: 0, stdout: `k0s ${VERSION}\n` }
        : undefined,
  });
  const model = createModel(fake.deps);
  const { context } = createModelTestContext();
  const got = await model.methods.get.execute(
    model.methods.get.arguments.parse({ ssh: SSH }),
    context,
  );
  assertEquals("config_file_sha256" in got.result, false);
  const applied = await model.methods.apply_manifests.execute(
    model.methods.apply_manifests.arguments.parse({
      ssh: SSH,
      stack: {
        name: "s",
        files: [{ path: "a.yaml", content: "kind: Secret\n" }],
      },
    }),
    context,
  );
  assertEquals(JSON.stringify(applied.result).includes("sha256"), false);
  const rs = model.resources.manifests.schema.shape.files.element.shape;
  assertEquals(rs.sha256.meta()?.sensitive, true);
  assertEquals(
    model.resources.state.schema.shape.config_file_sha256.meta()?.sensitive,
    true,
  );
});

Deno.test("a role change downloads and verifies before it tears anything down", async () => {
  for (
    const failure of [
      () => Promise.reject(new Error("download failed")),
      () => Promise.resolve(new TextEncoder().encode("not the pinned binary")),
    ]
  ) {
    const fake = makeDeps({ exec: ACTIVE_CONTROLLER, fetch: failure });
    const model = createModel(fake.deps);
    const { context, getWrittenResources } = createModelTestContext();
    await assertRejects(() =>
      model.methods.install.execute(
        installArgs({
          role: "worker",
          join_token: "PLACEHOLDER-JOIN-TOKEN",
          confirm_role_change: HOST,
        }),
        context,
      )
    );
    assertEquals(
      fake.execs.some((argv) => argv[1] === "stop" || argv[1] === "reset"),
      false,
      "the running controller was not touched",
    );
    assertEquals(fake.uploads.length, 0);
    assertEquals(primary(getWrittenResources(), true).length, 0);
  }
});

Deno.test("a role change needs the host named as confirmation", async () => {
  for (const confirm of [undefined, "wrong.example.com"]) {
    const fake = makeDeps({ exec: ACTIVE_CONTROLLER });
    const model = createModel(fake.deps);
    const { context } = createModelTestContext();
    await assertRejects(
      () =>
        model.methods.install.execute(
          installArgs({
            role: "worker",
            join_token: "PLACEHOLDER-JOIN-TOKEN",
            confirm_role_change: confirm,
          }),
          context,
        ),
      Error,
      "confirm_role_change",
    );
    assertEquals(fake.fetches.length, 0);
  }
});

Deno.test("a failure after the old role is reset is reported and recorded", async () => {
  const fake = makeDeps({
    exec: (argv) => {
      const base = ACTIVE_CONTROLLER(argv);
      if (argv[0] === "uname") return { code: 0, stdout: "x86_64\n" };
      if (argv[1] === "install") return { code: 1 };
      return base;
    },
    fetch: () => Promise.resolve(PAYLOAD),
  });
  const model = createModel(fake.deps);
  const { context, getWrittenResources } = createModelTestContext();
  await assertRejects(
    () =>
      model.methods.install.execute(
        installArgs({
          role: "worker",
          join_token: "PLACEHOLDER-JOIN-TOKEN",
          confirm_role_change: HOST,
        }),
        context,
      ),
    Error,
    "could not be restored",
  );
  const state = primary(getWrittenResources()).data as { installed: boolean };
  assertEquals(state.installed, false);
});

Deno.test("an existing looser mode is tightened even when the bytes match", async () => {
  const fake = makeDeps({ uploadChanged: () => true });
  const model = createModel(fake.deps);
  const { context } = createModelTestContext();
  const out = await model.methods.apply_manifests.execute(
    model.methods.apply_manifests.arguments.parse({
      ssh: SSH,
      stack: {
        name: "s",
        files: [{ path: "a.yaml", content: "kind: Secret\n" }],
      },
    }),
    context,
  );
  assertEquals(out.result.applied, true);
  assertEquals(fake.uploads.every((u) => u.mode === "0600"), true);
});

Deno.test("apply_helm keeps waiting while the chart is still the old version", async () => {
  const fake = makeDeps({
    exec: (argv) => {
      if (argv.includes("charts.helm.k0sproject.io")) {
        return {
          code: 0,
          stdout: HELM_CHARTS.replace('"1.2.3"', '"1.0.0"'),
        };
      }
      if (argv.includes("secrets")) return { code: 0, stdout: HELM_SECRETS };
      return undefined;
    },
    uploadChanged: () => false,
  });
  const model = createModel(fake.deps);
  const { context, getWrittenResources } = createModelTestContext();
  await assertRejects(
    () =>
      model.methods.apply_helm.execute(
        model.methods.apply_helm.arguments.parse({
          ssh: SSH,
          ...CLUSTER,
          reconcile_timeout_s: 10,
          poll_interval_s: 1,
          helm: [{
            chart: "example/nginx",
            repo: "https://charts.example.com",
            version: "1.2.3",
            namespace: "default",
          }],
        }),
        context,
      ),
    Error,
    "chart version 1.0.0, wanted 1.2.3",
  );
  assertEquals(primary(getWrittenResources(), true).length, 0);
});

Deno.test("apply_helm fails at once on a failed release", async () => {
  const fake = makeDeps({
    exec: (argv) => {
      if (argv.includes("secrets")) {
        return {
          code: 0,
          stdout: HELM_SECRETS.replace('"deployed"', '"failed"'),
        };
      }
      if (argv.includes("charts.helm.k0sproject.io")) {
        return { code: 0, stdout: HELM_CHARTS };
      }
      return undefined;
    },
    uploadChanged: () => false,
  });
  const model = createModel(fake.deps);
  const { context } = createModelTestContext();
  await assertRejects(
    () =>
      model.methods.apply_helm.execute(
        model.methods.apply_helm.arguments.parse({
          ssh: SSH,
          ...CLUSTER,
          helm: [{
            chart: "example/nginx",
            repo: "https://charts.example.com",
            version: "1.2.3",
            namespace: "default",
          }],
        }),
        context,
      ),
    Error,
    "failed",
  );
  assertEquals(fake.clock.value, Date.UTC(2026, 9, 17, 12, 0, 0));
});

Deno.test("a failed manifest listing stops before any upload or delete", async () => {
  const fake = makeDeps({
    exec: (argv) => argv[0] === "find" ? { code: 1 } : undefined,
  });
  const model = createModel(fake.deps);
  const { context } = createModelTestContext();
  await assertRejects(
    () =>
      model.methods.apply_manifests.execute(
        model.methods.apply_manifests.arguments.parse({
          ssh: SSH,
          stack: { name: "s", files: [{ path: "a.yaml", content: "x: 1\n" }] },
        }),
        context,
      ),
    Error,
    "could not list",
  );
  assertEquals(fake.uploads.length, 0);
});

Deno.test("a mid-stack upload failure names the files that landed", async () => {
  const fake = makeDeps({});
  const base = fake.deps.ssh.upload;
  let n = 0;
  fake.deps.ssh.upload = (target, file) =>
    ++n === 2 ? Promise.reject(new SshError("boom")) : base(target, file);
  const model = createModel(fake.deps);
  const { context } = createModelTestContext();
  await assertRejects(
    () =>
      model.methods.apply_manifests.execute(
        model.methods.apply_manifests.arguments.parse({
          ssh: SSH,
          stack: {
            name: "s",
            files: [
              { path: "a.yaml", content: "x: 1\n" },
              { path: "b.yaml", content: "x: 2\n" },
            ],
          },
        }),
        context,
      ),
    Error,
    "1 of 2 files uploaded (a.yaml), failed at b.yaml",
  );
});

Deno.test("reset fails closed when systemctl cat gives an unexplained error", async () => {
  const fake = makeDeps({
    exec: (argv) =>
      argv[0] === "systemctl" && argv[1] === "cat"
        ? { code: 255, stderr: "Failed to connect to bus" }
        : undefined,
  });
  const model = createModel(fake.deps);
  const { context, getWrittenResources } = createModelTestContext();
  await assertRejects(
    () =>
      model.methods.reset.execute(
        model.methods.reset.arguments.parse({ ssh: SSH, confirm_host: HOST }),
        context,
      ),
    Error,
    "could not tell whether",
  );
  assertEquals(primary(getWrittenResources(), true).length, 0);
});

Deno.test("an installed but stopped unit is started, not reinstalled over", async () => {
  let started = false;
  const fake = makeDeps({
    exec: (argv) => {
      if (isShow(argv)) return showController(true);
      if (argv[0] === "systemctl" && argv[1] === "cat") {
        return argv[2] === "k0scontroller" ? { code: 0 } : ABSENT;
      }
      if (argv[0] === "systemctl" && argv[1] === "enable") started = true;
      if (argv[0] === "systemctl" && argv[1] === "is-active") {
        return { code: started ? 0 : 3 };
      }
      return adoptRouter("0".repeat(64))(argv);
    },
  });
  const model = createModel(fake.deps);
  const { context } = createModelTestContext();
  const out = await model.methods.install.execute(installArgs(), context);
  assertEquals(out.result.role, "single");
  assertEquals(fake.execs.some((argv) => argv[1] === "install"), false);
  assertEquals(started, true);
});

Deno.test("a failed restart puts the previous k0s.yaml back", async () => {
  const fake = makeDeps({
    exec: (argv) => {
      if (argv[0] === "cat") return { code: 0, stdout: "previous: config\n" };
      if (argv[0] === "systemctl" && argv[1] === "restart") return { code: 1 };
      return undefined;
    },
  });
  const model = createModel(fake.deps);
  const { context } = createModelTestContext();
  await assertRejects(
    () =>
      model.methods.apply_helm.execute(
        model.methods.apply_helm.arguments.parse({
          ssh: SSH,
          ...CLUSTER,
          helm: [{
            chart: "example/nginx",
            repo: "https://charts.example.com",
            version: "1.2.3",
            namespace: "default",
          }],
        }),
        context,
      ),
    Error,
    "previous k0s.yaml was restored",
  );
  const last = fake.uploads.at(-1)!;
  assertEquals(new TextDecoder().decode(last.content), "previous: config\n");
  assertEquals(last.mode, "0600");
});

/** A host whose k0scontroller unit was installed with or without a worker. */
function controllerHost(withWorker: boolean) {
  return (argv: string[]) => {
    if (isShow(argv)) return showController(withWorker);
    if (argv[0] === "systemctl" && argv[1] === "cat") {
      return argv[2] === "k0scontroller" ? { code: 0 } : ABSENT;
    }
    if (argv[0] === "systemctl" && argv[1] === "is-active") {
      return { code: argv[2] === "k0scontroller" ? 0 : 3 };
    }
    if (argv[0] === "uname") return { code: 0, stdout: "x86_64\n" };
    return undefined;
  };
}

Deno.test("single and controller are different roles on the shared unit", async () => {
  for (
    const [role, installedWithWorker] of [
      ["single", false],
      ["controller", true],
    ] as const
  ) {
    const fake = makeDeps({
      exec: controllerHost(installedWithWorker),
      fetch: () => Promise.resolve(PAYLOAD),
    });
    const model = createModel(fake.deps);
    const { context, getWrittenResources } = createModelTestContext();
    await assertRejects(
      () => model.methods.install.execute(installArgs({ role }), context),
      Error,
      "confirm_role_change",
    );
    assertEquals(fake.fetches.length, 0);
    assertEquals(fake.uploads.length, 0);
    assertEquals(
      fake.execs.some((argv) => argv[1] === "stop" || argv[1] === "reset"),
      false,
    );
    assertEquals(primary(getWrittenResources(), true).length, 0);
  }
});

Deno.test("a confirmed single/controller change resets and reinstalls in the new mode", async () => {
  for (
    const [role, installedWithWorker, expected] of [
      [
        "single",
        false,
        ["install", "controller", "--enable-worker", "--no-taints"],
      ],
      ["controller", true, ["install", "controller"]],
    ] as const
  ) {
    let reinstalled = false;
    const fake = makeDeps({
      exec: (argv) => {
        if (argv[1] === "install") reinstalled = true;
        if (argv[0] === "systemctl" && argv[1] === "enable") {
          reinstalled = true;
        }
        if (reinstalled && argv[0] === "systemctl") {
          if (argv[1] === "is-active") return { code: 0 };
        }
        return controllerHost(installedWithWorker)(argv);
      },
      fetch: () => Promise.resolve(PAYLOAD),
    });
    const model = createModel(fake.deps);
    const { context, getWrittenResources } = createModelTestContext();
    await model.methods.install.execute(
      installArgs({ role, confirm_role_change: HOST }),
      context,
    );
    const verbs = fake.execs.map((argv) => argv.slice(0, 2).join(" "));
    const at = (verb: string) => verbs.indexOf(`${K0S_BINARY_PATH} ${verb}`);
    assertEquals(fake.fetches.length, 1);
    assertEquals(at("stop") >= 0 && at("stop") < at("reset"), true);
    assertEquals(at("reset") < at("install"), true);
    assertEquals(
      fake.execs.find((argv) => argv[1] === "install"),
      [K0S_BINARY_PATH, ...expected],
    );
    assertEquals(
      (primary(getWrittenResources()).data as { role: string }).role,
      role,
    );
  }
});

Deno.test("a matching single/controller mode is adopted without a change", async () => {
  for (
    const [role, installedWithWorker] of [
      ["single", true],
      ["controller", false],
    ] as const
  ) {
    const configSha = await sha256Hex(
      encoder.encode(renderK0sConfig({ ...CLUSTER, helm: [] })),
    );
    const base = adoptRouter(configSha);
    const fake = makeDeps({
      exec: (argv) =>
        isShow(argv) ? showController(installedWithWorker) : base(argv),
      uploadChanged: () => false,
    });
    const model = createModel(fake.deps);
    const { context } = createModelTestContext();
    const out = await model.methods.install.execute(
      installArgs({ role }),
      context,
    );
    assertEquals(out.result.role, role);
    assertEquals(
      fake.execs.some((argv) => argv[1] === "stop" || argv[1] === "reset"),
      false,
    );
  }
});

Deno.test("kubeconfig can be written to a caller-named vault key and kept out of the record", async () => {
  const fake = makeDeps({
    exec: (argv) =>
      argv.includes("kubeconfig")
        ? { code: 0, stdout: FAKE_KUBECONFIG }
        : undefined,
  });
  const model = createModel(fake.deps);
  const puts: [string, string, string][] = [];
  const { context, getWrittenResources, getLogs } = createModelTestContext();
  // deno-lint-ignore no-explicit-any
  (context as any).vaultService = {
    put: (vault: string, key: string, value: string) => {
      puts.push([vault, key, value]);
      return Promise.resolve();
    },
  };
  const out = await model.methods.kubeconfig.execute(
    model.methods.kubeconfig.arguments.parse({
      ssh: SSH,
      store_in_vault: { vault: "cluster", key: "kubeconfig-a" },
    }),
    context,
  );
  assertEquals(puts, [["cluster", "kubeconfig-a", FAKE_KUBECONFIG]]);
  assertEquals(out.result.vault, "cluster");
  assertEquals(out.result.vault_key, "kubeconfig-a");
  const kept = JSON.stringify([
    out.result,
    getWrittenResources(),
    getLogs(),
  ]);
  assertEquals(kept.includes("client-key-data"), false);
  assertEquals(kept.includes("FAKE-KEY-DATA"), false);
  const record = primary(getWrittenResources()).data as Record<string, unknown>;
  assertEquals("kubeconfig" in record, false);
  assertEquals(record.vault_key, "kubeconfig-a");
});

Deno.test("a vault write failure or missing vault service fails without the value", async () => {
  const fake = makeDeps({
    exec: (argv) =>
      argv.includes("kubeconfig")
        ? { code: 0, stdout: FAKE_KUBECONFIG }
        : undefined,
  });
  const model = createModel(fake.deps);
  const args = model.methods.kubeconfig.arguments.parse({
    ssh: SSH,
    store_in_vault: { vault: "cluster", key: "kc" },
  });
  const none = createModelTestContext();
  await assertRejects(
    () => model.methods.kubeconfig.execute(args, none.context),
    Error,
    "does not expose a vault service",
  );
  const failing = createModelTestContext();
  // deno-lint-ignore no-explicit-any
  (failing.context as any).vaultService = {
    put: (_v: string, _k: string, value: string) =>
      Promise.reject(
        new Error(
          `backend rejected ${
            value.split("\n")[0]
          } client-key-data: FAKE-KEY-DATA`,
        ),
      ),
  };
  const error = await assertRejects(
    () => model.methods.kubeconfig.execute(args, failing.context),
    Error,
    "could not write the kubeconfig to vault cluster",
  );
  assertEquals(error.message.includes("FAKE-KEY-DATA"), false);
  assertEquals(error.message.includes("client-key-data"), false);
  assertEquals(error.message.includes("apiVersion"), false);
  assertEquals(
    error.message,
    "could not write the kubeconfig to vault cluster key kc",
  );
  assertEquals(primary(failing.getWrittenResources(), true).length, 0);
});

Deno.test("store_in_vault rejects malformed vault names and keys", () => {
  const model = createModel(makeDeps().deps);
  for (
    const bad of [
      { vault: "a b", key: "k" },
      { vault: "v", key: "../k" },
      { vault: "", key: "k" },
      { vault: "v", key: "k;rm" },
    ]
  ) {
    assertThrows(() =>
      model.methods.kubeconfig.arguments.parse({
        ssh: SSH,
        store_in_vault: bad,
      })
    );
  }
});

Deno.test("a failed first-time restart removes the unverified k0s.yaml", async () => {
  const fake = makeDeps({
    exec: (argv) => {
      if (argv[0] === "cat") return { code: 1 };
      if (argv[0] === "systemctl" && argv[1] === "restart") return { code: 1 };
      return undefined;
    },
  });
  const model = createModel(fake.deps);
  const { context } = createModelTestContext();
  await assertRejects(
    () =>
      model.methods.apply_helm.execute(
        model.methods.apply_helm.arguments.parse({
          ssh: SSH,
          ...CLUSTER,
          helm: [{
            chart: "example/nginx",
            repo: "https://charts.example.com",
            version: "1.2.3",
            namespace: "default",
          }],
        }),
        context,
      ),
    Error,
    "the new k0s.yaml was removed",
  );
  assertEquals(
    fake.execs.some((argv) =>
      argv[0] === "rm" && argv.includes(K0S_CONFIG_PATH)
    ),
    true,
  );
});

Deno.test("api_address is validated and rendered into the uploaded config", async () => {
  const model = createModel(makeDeps().deps);
  for (const bad of ["example.com", "192.0.2.256", "192.0.2.1/24", "::::"]) {
    assertThrows(() =>
      model.methods.render_config.arguments.parse({
        k0s_version: VERSION,
        ...CLUSTER,
        api_address: bad,
      })
    );
  }
  const fake = makeDeps({
    exec: installRouter,
    fetch: () => Promise.resolve(PAYLOAD),
  });
  const m = createModel(fake.deps);
  const { context } = createModelTestContext();
  await m.methods.install.execute(
    installArgs({ api_address: "198.51.100.7" }),
    context,
  );
  const config = fake.uploads.find((u) => u.path === K0S_CONFIG_PATH)!;
  const text = new TextDecoder().decode(config.content);
  assertEquals(
    text.includes('    address: "198.51.100.7"\n    port: 6443'),
    true,
  );
  assertEquals(text.includes('      - "198.51.100.7"\n'), true);
  const rendered = await m.methods.render_config.execute(
    m.methods.render_config.arguments.parse({
      k0s_version: VERSION,
      ...CLUSTER,
      api_address: "198.51.100.7",
    }),
    createModelTestContext().context,
  );
  assertEquals(rendered.result.k0s_yaml.includes("address:"), true);
});

Deno.test("kubeconfig builds the server URL from api_address and stores that kubeconfig", async () => {
  const fake = makeDeps({
    exec: (argv) =>
      argv.includes("kubeconfig")
        ? { code: 0, stdout: FAKE_KUBECONFIG }
        : undefined,
  });
  const model = createModel(fake.deps);
  const puts: string[] = [];
  const { context, getWrittenResources } = createModelTestContext();
  // deno-lint-ignore no-explicit-any
  (context as any).vaultService = {
    put: (_v: string, _k: string, value: string) => {
      puts.push(value);
      return Promise.resolve();
    },
  };
  const out = await model.methods.kubeconfig.execute(
    model.methods.kubeconfig.arguments.parse({
      ssh: SSH,
      api_address: "198.51.100.7",
      store_in_vault: { vault: "cluster", key: "kc" },
    }),
    context,
  );
  assertEquals(out.result.server, "https://198.51.100.7:6443");
  assertEquals(puts[0].includes("server: https://198.51.100.7:6443"), true);
  assertEquals(puts[0].includes("192.0.2.10"), false);
  assertEquals(
    JSON.stringify(getWrittenResources()).includes("client-key-data"),
    false,
  );
  // Without api_address the kubeconfig is returned as k0s wrote it.
  const plain = await model.methods.kubeconfig.execute(
    model.methods.kubeconfig.arguments.parse({ ssh: SSH }),
    createModelTestContext().context,
  );
  assertEquals(plain.result.server, "https://192.0.2.10:6443");
  // An IPv6 address is bracketed.
  const v6 = await model.methods.kubeconfig.execute(
    model.methods.kubeconfig.arguments.parse({
      ssh: SSH,
      api_address: "2001:db8::7",
      api_port: 6444,
    }),
    createModelTestContext().context,
  );
  assertEquals(v6.result.server, "https://[2001:db8::7]:6444");
});

Deno.test("the exact install argv for single, controller and worker", async () => {
  const cases: [string, string[]][] = [
    ["single", ["install", "controller", "--enable-worker", "--no-taints"]],
    ["controller", ["install", "controller"]],
    [
      "worker",
      ["install", "worker", "--token-file", "/etc/k0s/worker-token"],
    ],
  ];
  for (const [role, expected] of cases) {
    const fake = makeDeps({
      exec: installRouter,
      fetch: () => Promise.resolve(PAYLOAD),
    });
    const model = createModel(fake.deps);
    const { context } = createModelTestContext();
    await model.methods.install.execute(
      installArgs({ role, join_token: "PLACEHOLDER-JOIN-TOKEN" }),
      context,
    );
    assertEquals(
      fake.execs.find((argv) => argv[1] === "install"),
      [K0S_BINARY_PATH, ...expected],
      role,
    );
  }
});

Deno.test("an install in the old tainted single mode is detected, never silently adopted", async () => {
  for (const role of ["single", "controller"] as const) {
    const fake = makeDeps({
      exec: (argv) =>
        isShow(argv) ? showController("tainted") : controllerHost(true)(argv),
      fetch: () => Promise.resolve(PAYLOAD),
    });
    const model = createModel(fake.deps);
    const { context, getWrittenResources } = createModelTestContext();
    const e = await assertRejects(
      () => model.methods.install.execute(installArgs({ role }), context),
      Error,
      "confirm_role_change",
    );
    assertEquals(e.message.includes("controller+worker"), true);
    assertEquals(e.message.includes("taint"), true);
    assertEquals(fake.fetches.length, 0);
    assertEquals(fake.uploads.length, 0);
    assertEquals(
      fake.execs.some((argv) => argv[1] === "stop" || argv[1] === "reset"),
      false,
    );
    assertEquals(primary(getWrittenResources(), true).length, 0);
  }
});

Deno.test("confirming reconciles the tainted mode into a real single node", async () => {
  let reinstalled = false;
  const fake = makeDeps({
    exec: (argv) => {
      if (argv[1] === "install") reinstalled = true;
      if (argv[0] === "systemctl" && argv[1] === "enable") reinstalled = true;
      if (isShow(argv)) {
        return showController(reinstalled ? true : "tainted");
      }
      if (reinstalled && argv[0] === "systemctl" && argv[1] === "is-active") {
        return { code: 0 };
      }
      return controllerHost(true)(argv);
    },
    fetch: () => Promise.resolve(PAYLOAD),
  });
  const model = createModel(fake.deps);
  const { context, getWrittenResources } = createModelTestContext();
  await model.methods.install.execute(
    installArgs({ confirm_role_change: HOST }),
    context,
  );
  const verbs = fake.execs.map((argv) => argv.slice(0, 2).join(" "));
  const at = (v: string) => verbs.indexOf(`${K0S_BINARY_PATH} ${v}`);
  assertEquals(at("stop") >= 0 && at("stop") < at("reset"), true);
  assertEquals(at("reset") < at("install"), true);
  assertEquals(fake.execs.find((argv) => argv[1] === "install"), [
    K0S_BINARY_PATH,
    "install",
    "controller",
    "--enable-worker",
    "--no-taints",
  ]);
  assertEquals(
    (primary(getWrittenResources()).data as { role: string }).role,
    "single",
  );
});

Deno.test("a host whose unit cannot be read as a k0s controller fails closed", async () => {
  for (
    const stdout of [
      "",
      "{ path=/usr/bin/true ; argv[]=/usr/bin/true ; ignore_errors=no }",
      "{ path=/usr/local/bin/k0s ; ignore_errors=no }",
    ]
  ) {
    const fake = makeDeps({
      exec: (argv) =>
        isShow(argv) ? { code: 0, stdout } : controllerHost(true)(argv),
    });
    const model = createModel(fake.deps);
    const { context } = createModelTestContext();
    await assertRejects(
      () => model.methods.install.execute(installArgs(), context),
      Error,
      "could not read how k0scontroller is installed",
    );
  }
});
