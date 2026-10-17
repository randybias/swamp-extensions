/**
 * Swamp extension model for a k0s Kubernetes cluster reached over SSH.
 *
 * One definition serves any host: the SSH target and cluster inputs arrive with
 * every call, and state is keyed by the target host. The model installs a
 * SHA-pinned k0s binary, renders and installs `k0s.yaml`, waits for readiness,
 * reads the admin kubeconfig, reconciles manifest stacks and Helm charts, and
 * resets the node. All remote work goes through an injectable transport, so
 * unit tests assemble argv and render configuration without a network.
 *
 * @module
 */

import { z } from "npm:zod@4.3.6";
import {
  hasUrlCredentials,
  HOST_RE,
  isCidr,
  isConcreteManifestPath,
  isIp,
  isSafeFilename,
  MANIFEST_PATH_RE,
  NAME_RE,
  normalizeManifestPath,
  SAFE_URL_RE,
  USER_RE,
} from "./_lib/grammar.ts";
import {
  apiServerUrl,
  archFromUname,
  type BinaryFetcher,
  chartBaseName,
  type ChartStatus,
  classifyControllerExecStart,
  type ControllerMode,
  defaultFetcher,
  downloadUrl,
  type HelmRelease,
  installArgs,
  instanceName,
  isBoundedJsonValue,
  K0S_BINARY_PATH,
  K0S_CONFIG_PATH,
  K0S_MANIFEST_DIR,
  K0S_VERSION_RE,
  K0S_WORKER_TOKEN_PATH,
  type K0sConfigInput,
  type NodeStatus,
  ok,
  parseCharts,
  parseHelmReleases,
  parseKubeconfigServer,
  parseNameList,
  parseNodes,
  parsePods,
  parseSha256,
  type PodStatus,
  renderK0sConfig,
  serviceName,
  SHA256_RE,
  systemPodsHealthy,
  verifyBinary,
  withServer,
} from "./_lib/k0s.ts";
import { assertRemotePath, sha256Hex, type SshTarget } from "./_lib/ssh.ts";
import { createSshTransport, type SshTransport } from "./_lib/transport.ts";

// deno-lint-ignore no-explicit-any
type Ctx = any;

const encoder = new TextEncoder();

/** Directory holding k0s.yaml and the worker token. */
const K0S_CONFIG_DIR = "/etc/k0s";
/** Mode for every upload that can carry a secret: root-only. */
const SECRET_MODE = "0600";

const VERSION = z.string().max(64).regex(K0S_VERSION_RE).describe(
  "Pinned k0s release, e.g. v1.31.2+k0s.0.",
);
const SHA256 = z.string().regex(SHA256_RE).describe(
  "Required SHA-256 of the release binary; install refuses on a mismatch.",
);
const NAME = z.string().regex(NAME_RE).describe("DNS-1123 label.");
const URL = z.string().max(2048).regex(SAFE_URL_RE).refine(
  (value) => !hasUrlCredentials(value),
  "URL must not carry user info, a query or a fragment; wire credentials as separate sensitive inputs",
).describe("HTTPS URL with no user info, query or fragment.");
const CIDR = z.string().refine(isCidr, "must be a CIDR").describe(
  "Network CIDR.",
);

const SSH = z.strictObject({
  host: z.string().regex(HOST_RE).max(255).describe(
    "Hostname or IP literal reached over SSH.",
  ),
  user: z.string().regex(USER_RE).describe(
    "Remote user, typically root, able to install services.",
  ),
  port: z.number().int().min(1).max(65535).default(22).describe("SSH port."),
  host_key_policy: z.enum(["strict", "insecure_tofu"]).describe(
    "strict pins host_keys and refuses a mismatch; insecure_tofu records the host keys on first use, then pins every later connection to the recorded keys. There is no silent default.",
  ),
  host_keys: z.array(z.string().max(4096)).max(64).nullish().describe(
    "Pinned host keys in ssh-keyscan format; required when host_key_policy is strict.",
  ),
  private_key: z.string().max(32768).meta({ sensitive: true }).describe(
    "PEM private key, delivered to ssh-agent over stdin; never placed on a command line.",
  ),
  connect_timeout_s: z.number().int().min(1).max(120).default(15).describe(
    "SSH connection timeout in seconds.",
  ),
}).refine(
  (ssh) => ssh.host_key_policy !== "strict" || (ssh.host_keys?.length ?? 0) > 0,
  { message: "host_key_policy strict requires host_keys", path: ["host_keys"] },
);

const HELM_CHART = z.strictObject({
  chart: z.string().regex(
    /^[a-z0-9](?:[a-z0-9._-]{0,62})(?:\/[a-z0-9](?:[a-z0-9._-]{0,62}))?$/,
  ).describe(
    "Chart name, optionally written repo/chart; k0s is always given the generated repository name as the prefix.",
  ),
  repo: URL.describe("HTTPS chart repository URL."),
  version: z.string().regex(/^[A-Za-z0-9][A-Za-z0-9.+-]{0,63}$/).describe(
    "Chart version.",
  ),
  namespace: NAME.describe("Namespace the chart is installed into."),
  values: z.record(z.string().max(128), z.unknown()).refine(
    isBoundedJsonValue,
    "values must be a bounded JSON object (depth 8, 128 entries per level, 64 KiB)",
  ).meta({ sensitive: true }).nullish().describe(
    "Chart values as an object; treated as sensitive because chart values often carry passwords.",
  ),
});

const MANIFEST_FILE = z.strictObject({
  path: z.string().regex(MANIFEST_PATH_RE).refine(
    isConcreteManifestPath,
    "must name one file below the stack directory: not empty, '.', '..' or a directory",
  ).describe("Path relative to the stack directory."),
  content: z.string().max(262144).meta({ sensitive: true }).describe(
    "Manifest text; it may carry Secret data, so it is treated as sensitive and never logged.",
  ),
});

const MANIFEST_STACK = z.strictObject({
  name: NAME.describe("DNS-1123 label naming the stack."),
  files: z.array(MANIFEST_FILE).min(1).max(64).describe("Stack files."),
}).superRefine((stack, ctx) => {
  const seen = new Set<string>();
  stack.files.forEach((file, index) => {
    const key = normalizeManifestPath(file.path);
    if (seen.has(key)) {
      ctx.addIssue({
        code: "custom",
        message: `duplicate manifest path after normalization: ${file.path}`,
        path: ["files", index, "path"],
      });
    }
    seen.add(key);
  });
});

const clusterFields = {
  cluster_name: NAME.default("k0s").describe(
    "Cluster name written to metadata.name.",
  ),
  api_sans: z.array(z.string().max(253).regex(HOST_RE)).max(64).default([])
    .describe(
      "API server certificate SANs: hostnames or IP literals.",
    ),
  api_address: z.string().max(45).refine(isIp, "must be an IP address")
    .nullish().describe(
      "Address the API server binds and advertises, written to spec.api.address and added to the SANs; the kubeconfig's server URL is built from it. Use the private or mesh address to keep the API off the public one.",
    ),
  api_port: z.number().int().min(1).max(65535).default(6443).describe(
    "API server port.",
  ),
  pod_cidr: CIDR.describe("Pod network CIDR; required."),
  service_cidr: CIDR.describe("Service network CIDR; required."),
  storage_type: z.enum(["etcd", "kine"]).default("etcd").describe(
    "Datastore backend.",
  ),
  telemetry_enabled: z.boolean().default(false).describe(
    "Whether anonymous telemetry is enabled.",
  ),
  external_address: z.string().max(253).describe(
    "Advertised API address for clients, for example an external load balancer or VIP; written to spec.api.externalAddress. Do not combine with node_local_load_balancing.",
  ).nullish(),
  node_local_load_balancing: z.boolean().default(false).describe(
    "Enable k0s node-local load balancing (EnvoyProxy) so every node reaches the API locally; off keeps the previous behaviour.",
  ),
  control_plane_load_balancing: z.strictObject({
    virtual_ip: z.string().max(45).refine(isIp, "must be an IP address")
      .describe("VIP shared by the controllers (keepalived)."),
    auth_pass: z.string().min(1).max(8).meta({ sensitive: true }).describe(
      "keepalived VRRP auth password, at most 8 characters; wire with a vault reference.",
    ),
  }).describe("Control-plane keepalived VIP; omit for none.").nullish(),
};

const RenderArgs = z.strictObject({
  k0s_version: VERSION,
  ...clusterFields,
  manifests: z.array(MANIFEST_STACK).max(64).default([]).describe(
    "Manifest stacks whose layout is planned; k0s reads them as files, not from k0s.yaml.",
  ),
  helm: z.array(HELM_CHART).max(64).default([]).describe(
    "Helm extensions declared in k0s.yaml.",
  ),
});

const InstallArgs = z.strictObject({
  ssh: SSH,
  k0s_version: VERSION,
  k0s_binary_sha256: SHA256,
  k0s_download_url: URL.nullish().describe(
    "Optional binary URL override; the SHA-256 check still applies.",
  ),
  k0s_download_token: z.string().max(4096).meta({ sensitive: true }).nullish()
    .describe(
      "Bearer token for a private release mirror, sent as an Authorization header; wire with a vault.get(...) expression.",
    ),
  role: z.enum(["single", "controller", "worker"]).default("single").describe(
    "single installs a controller that also runs a worker; worker joins an existing cluster with join_token.",
  ),
  join_token: z.string().max(16384).meta({ sensitive: true }).nullish()
    .describe(
      "Join token for role worker, written to a root-only token file over stdin; never placed on a command line.",
    ),
  force_reinstall: z.boolean().default(false).describe(
    "Reinstall over an existing service of the same role rather than adopting it.",
  ),
  confirm_role_change: z.string().optional().describe(
    "Set to the SSH host to replace an installed role with a different one. IRREVERSIBLE: the old role is stopped and reset, destroying its data, only after the replacement binary is downloaded and verified. Without it a role change is refused.",
  ),
  ...clusterFields,
  helm: z.array(HELM_CHART).max(64).default([]).describe(
    "Helm extensions declared in k0s.yaml.",
  ),
});

const WaitReadyArgs = z.strictObject({
  ssh: SSH,
  ready_timeout_s: z.number().int().min(10).max(7200).default(600).describe(
    "Give up after this many seconds.",
  ),
  poll_interval_s: z.number().int().min(1).max(300).default(10).describe(
    "Seconds between polls.",
  ),
  require_system_pods: z.boolean().default(true).describe(
    "Also require every kube-system pod to be running or finished.",
  ),
});

const KubeconfigArgs = z.strictObject({
  ssh: SSH,
  api_address: z.string().max(45).refine(isIp, "must be an IP address")
    .nullish().describe(
      "The cluster's api_address. When given, the returned and stored kubeconfig's server URL is built from it (with api_port) instead of whatever address k0s wrote.",
    ),
  api_port: z.number().int().min(1).max(65535).default(6443).describe(
    "API server port used with api_address.",
  ),
  store_in_vault: z.strictObject({
    vault: z.string().regex(/^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$/).describe(
      "Name of an existing swamp vault.",
    ),
    key: z.string().regex(/^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$/).describe(
      "Secret key to write the kubeconfig to.",
    ),
  }).nullish().describe(
    "Write the kubeconfig to this vault key instead of keeping it in the stored record, so a later step can read it with a vault.get(...) reference and the value never passes through workflow data.",
  ),
});

const ApplyManifestsArgs = z.strictObject({ ssh: SSH, stack: MANIFEST_STACK });

const ApplyHelmArgs = z.strictObject({
  ssh: SSH,
  ...clusterFields,
  helm: z.array(HELM_CHART).min(1).max(64).describe(
    "Helm extensions to declare and reconcile.",
  ),
  reconcile_timeout_s: z.number().int().min(10).max(3600).default(300).describe(
    "Give up after this many seconds.",
  ),
  poll_interval_s: z.number().int().min(1).max(300).default(10).describe(
    "Seconds between polls.",
  ),
});

const GetArgs = z.strictObject({ ssh: SSH });
const SyncArgs = z.strictObject({ ssh: SSH });
const ResetArgs = z.strictObject({
  ssh: SSH,
  confirm_host: z.string().describe(
    "Must equal the SSH host; guards against resetting the wrong machine.",
  ),
});

const StateSchema = z.strictObject({
  host: z.string(),
  port: z.number().int(),
  user: z.string(),
  role: z.enum(["single", "controller", "worker"]).nullable(),
  k0s_version: z.string().nullable(),
  binary_sha256: z.string().nullable(),
  config_sha256: z.string().nullable(),
  config_file_sha256: z.string().nullable().meta({ sensitive: true }),
  service: z.string().nullable(),
  installed: z.boolean(),
  adopted: z.boolean(),
  cleanup_pending: z.boolean().optional(),
  binary_removed: z.boolean().optional(),
  binary_removal_reason: z.string().optional(),
  observed_at: z.string(),
});

const HostKeysSchema = z.strictObject({
  host: z.string(),
  port: z.number().int(),
  user: z.string(),
  host_keys: z.array(z.string()),
  recorded_at: z.string(),
});

const KubeconfigSchema = z.strictObject({
  host: z.string(),
  port: z.number().int(),
  user: z.string(),
  server: z.string().nullable(),
  sha256: z.string(),
  kubeconfig: z.string().optional().meta({ sensitive: true }),
  vault: z.string().optional(),
  vault_key: z.string().optional(),
  observed_at: z.string(),
});

const PodViewSchema = z.strictObject({
  namespace: z.string(),
  name: z.string(),
  phase: z.string(),
  ready: z.boolean(),
});

const NodeViewSchema = z.strictObject({
  name: z.string(),
  ready: z.boolean(),
});

const ReadinessSchema = z.strictObject({
  host: z.string(),
  port: z.number().int(),
  user: z.string(),
  ready: z.boolean(),
  node: NodeViewSchema.nullable(),
  system_pods: z.array(PodViewSchema),
  waited_seconds: z.number(),
  observed_at: z.string(),
});

const ManifestStateSchema = z.strictObject({
  host: z.string(),
  port: z.number().int(),
  user: z.string(),
  stack: z.string(),
  files: z.array(
    z.strictObject({
      path: z.string(),
      sha256: z.string().meta({ sensitive: true }),
    }),
  ),
  applied: z.boolean(),
  observed_at: z.string(),
});

const HelmStateSchema = z.strictObject({
  host: z.string(),
  port: z.number().int(),
  user: z.string(),
  charts: z.array(
    z.strictObject({
      name: z.string(),
      chartname: z.string(),
      version: z.string(),
      namespace: z.string(),
      status: z.string(),
    }),
  ),
  reconciled: z.boolean(),
  observed_at: z.string(),
});

const StatusSchema = z.strictObject({
  host: z.string(),
  port: z.number().int(),
  user: z.string(),
  installed: z.boolean(),
  k0s_version: z.string().nullable(),
  node: NodeViewSchema.nullable(),
  nodes: z.array(NodeViewSchema),
  system_pods: z.array(PodViewSchema),
  config_file_sha256: z.string().nullable().meta({ sensitive: true }),
  stacks: z.array(z.string()),
  helm_releases: z.array(
    z.strictObject({
      name: z.string(),
      namespace: z.string(),
      status: z.string(),
    }),
  ),
  observed_at: z.string(),
});

/** Dependencies of the model; all are replaceable in tests. */
export interface K0sDeps {
  /** Remote transport. */
  ssh: SshTransport;
  /** Fetches the pinned release binary. */
  fetch: BinaryFetcher;
  /** Current time in milliseconds. */
  now: () => number;
  /** Sleeps for a number of milliseconds. */
  sleep: (ms: number) => Promise<void>;
}

/** Production dependencies: real transport, network, clock and sleep. */
export const defaultK0sDeps: K0sDeps = {
  ssh: createSshTransport(),
  fetch: defaultFetcher,
  now: () => Date.now(),
  sleep: (ms) => new Promise((resolve) => setTimeout(resolve, ms)),
};

function iso(ms: number): string {
  return new Date(ms).toISOString();
}

/** SSH settings as parsed from a method's arguments. */
type SshArgs = z.infer<typeof SSH>;

function targetOf(ssh: SshArgs): SshTarget {
  return {
    host: ssh.host.toLowerCase(),
    user: ssh.user,
    port: ssh.port,
    host_key_policy: ssh.host_key_policy,
    host_keys: ssh.host_keys ?? undefined,
    private_key: ssh.private_key,
    connect_timeout_s: ssh.connect_timeout_s,
  };
}

/**
 * Identity of one SSH target for stored records: user, host and port joined
 * with `~`, which none of them can contain. A host name never has `_` and an
 * IPv6 literal's `:` becomes `_`, so two targets never share an id and
 * `host:22` and `host:2222` never overwrite each other.
 */
export function targetId(
  target: Pick<SshTarget, "host" | "port" | "user">,
): string {
  return instanceName(
    `${target.user}~${
      target.host.toLowerCase().replaceAll(":", "_")
    }~${target.port}`,
  );
}

/** Where the identity fields of a record come from. */
function whoOf(target: SshTarget) {
  return { host: target.host, port: target.port, user: target.user };
}

/**
 * Pins the target's host keys. A strict target, or one with caller-supplied
 * keys, is used as given. Under `insecure_tofu` the keys recorded on first use
 * are read back and every connection is pinned to them; with none recorded the
 * host is asked once, the answer is stored before any secret is sent, and
 * every later connection, in this call and in later ones, must match it.
 */
async function resolveTarget(
  deps: K0sDeps,
  context: Ctx,
  ssh: SshArgs,
): Promise<{ target: SshTarget; handles: unknown[] }> {
  const base = targetOf(ssh);
  if (base.host_key_policy === "strict" || (base.host_keys?.length ?? 0) > 0) {
    return { target: base, handles: [] };
  }
  const name = `${targetId(base)}~hostkeys`;
  const recorded = await context.readResource(name) as
    | { host_keys?: string[] }
    | null;
  if (recorded?.host_keys && recorded.host_keys.length > 0) {
    return { target: { ...base, host_keys: recorded.host_keys }, handles: [] };
  }
  const learned = await deps.ssh.learnHostKeys(
    base,
    base.connect_timeout_s ?? 15,
  );
  if (learned.length === 0) {
    throw new Error(
      `no SSH host keys were offered by ${base.host}:${base.port}`,
    );
  }
  const handle = await context.writeResource(
    "hostkeys",
    name,
    HostKeysSchema.parse({
      ...whoOf(base),
      host_keys: learned,
      recorded_at: iso(deps.now()),
    }),
  );
  return { target: { ...base, host_keys: learned }, handles: [handle] };
}

/** Creates a root-only directory (and any missing parents) on the host. */
async function ensurePrivateDir(
  deps: K0sDeps,
  target: SshTarget,
  dir: string,
): Promise<void> {
  assertRemotePath(`${dir}/x`);
  const made = await deps.ssh.exec(target, ["mkdir", "-p", dir]);
  const mode = ok(made)
    ? await deps.ssh.exec(target, ["chmod", "0700", dir])
    : made;
  if (!ok(mode)) {
    throw new Error(`could not create ${dir} on ${target.host}`);
  }
}

/**
 * Waits until the unit is active and, for a controller, the API reports
 * ready. A restart or start whose result nobody checked would leave state
 * claiming a configuration that never loaded.
 */
async function waitUnitHealthy(
  deps: K0sDeps,
  target: SshTarget,
  service: string,
  timeoutS = 90,
): Promise<void> {
  const deadline = deps.now() + timeoutS * 1000;
  let last = "the unit is not active";
  while (true) {
    const active = await deps.ssh.exec(target, [
      "systemctl",
      "is-active",
      service,
    ]);
    if (ok(active)) {
      if (service !== "k0scontroller") return;
      const ready = await deps.ssh.exec(target, [
        K0S_BINARY_PATH,
        "kubectl",
        "get",
        "--raw=/readyz",
      ]);
      if (ok(ready)) return;
      last = "the API server is not ready";
    }
    if (deps.now() >= deadline) {
      throw new Error(
        `${service} on ${target.host} did not become healthy within ${timeoutS}s: ${last}`,
      );
    }
    await deps.sleep(2000);
  }
}

/** Restarts a unit, fails on a non-zero exit, and waits until it is healthy. */
async function restartAndVerify(
  deps: K0sDeps,
  target: SshTarget,
  service: string,
): Promise<void> {
  const restarted = await deps.ssh.exec(target, [
    "systemctl",
    "restart",
    service,
  ]);
  if (!ok(restarted)) {
    throw new Error(
      `systemctl restart ${service} failed on ${target.host} (exit ${restarted.exit_code}); the new configuration was not loaded`,
    );
  }
  await waitUnitHealthy(deps, target, service);
}

function renderInput(args: {
  cluster_name: string;
  api_address?: string | null;
  api_port: number;
  api_sans: string[];
  pod_cidr: string;
  service_cidr: string;
  storage_type: "etcd" | "kine";
  telemetry_enabled: boolean;
  external_address?: string | null;
  node_local_load_balancing?: boolean;
  control_plane_load_balancing?: {
    virtual_ip: string;
    auth_pass: string;
  } | null;
  helm: z.infer<typeof HELM_CHART>[];
}): K0sConfigInput {
  return {
    cluster_name: args.cluster_name,
    ...(args.api_address ? { api_address: args.api_address } : {}),
    api_port: args.api_port,
    api_sans: args.api_sans,
    pod_cidr: args.pod_cidr,
    service_cidr: args.service_cidr,
    storage_type: args.storage_type,
    telemetry_enabled: args.telemetry_enabled,
    ...(args.external_address
      ? { external_address: args.external_address }
      : {}),
    ...(args.node_local_load_balancing
      ? { node_local_load_balancing: true }
      : {}),
    ...(args.control_plane_load_balancing
      ? { control_plane_load_balancing: args.control_plane_load_balancing }
      : {}),
    helm: args.helm.map((chart) => ({
      chart: chart.chart,
      repo: chart.repo,
      version: chart.version,
      namespace: chart.namespace,
      values: chart.values ?? undefined,
    })),
  };
}

async function remoteConfigSha(
  deps: K0sDeps,
  target: SshTarget,
): Promise<string | null> {
  const result = await deps.ssh.exec(target, ["sha256sum", K0S_CONFIG_PATH]);
  return ok(result) ? parseSha256(result.stdout) : null;
}

async function remoteStacks(
  deps: K0sDeps,
  target: SshTarget,
): Promise<string[]> {
  const result = await deps.ssh.exec(target, ["ls", "-1", K0S_MANIFEST_DIR]);
  return ok(result) ? parseNameList(result.stdout) : [];
}

async function remoteHelmReleases(
  deps: K0sDeps,
  target: SshTarget,
): Promise<HelmRelease[]> {
  const result = await deps.ssh.exec(target, [
    K0S_BINARY_PATH,
    "kubectl",
    "get",
    "secrets",
    "-A",
    "-o",
    "json",
  ]);
  return ok(result) ? parseHelmReleases(result.stdout) : [];
}

async function remoteNodes(
  deps: K0sDeps,
  target: SshTarget,
): Promise<NodeStatus[]> {
  const result = await deps.ssh.exec(target, [
    K0S_BINARY_PATH,
    "kubectl",
    "get",
    "nodes",
    "-o",
    "json",
  ]);
  return ok(result) ? parseNodes(result.stdout) : [];
}

async function remotePods(
  deps: K0sDeps,
  target: SshTarget,
): Promise<PodStatus[]> {
  const result = await deps.ssh.exec(target, [
    K0S_BINARY_PATH,
    "kubectl",
    "get",
    "pods",
    "-n",
    "kube-system",
    "-o",
    "json",
  ]);
  return ok(result) ? parsePods(result.stdout) : [];
}

async function remoteCharts(
  deps: K0sDeps,
  target: SshTarget,
): Promise<ChartStatus[]> {
  const result = await deps.ssh.exec(target, [
    K0S_BINARY_PATH,
    "kubectl",
    "get",
    "charts.helm.k0sproject.io",
    "-n",
    "kube-system",
    "-o",
    "json",
  ]);
  return ok(result) ? parseCharts(result.stdout) : [];
}

/**
 * Whether a systemd unit exists. Only systemd's explicit "no such unit"
 * answer counts as absent; any other failure (a bus error, a dropped
 * connection) is raised, never read as "not installed".
 */
async function unitExists(
  deps: K0sDeps,
  target: SshTarget,
  unit: string,
): Promise<boolean> {
  const result = await deps.ssh.exec(target, ["systemctl", "cat", unit]);
  if (ok(result)) return true;
  if (
    result.exit_code === 1 &&
    /No files found|not found|could not be found|No such file/i.test(
      `${result.stderr}\n${result.stdout}`,
    )
  ) {
    return false;
  }
  throw new Error(
    `could not tell whether ${unit} exists on ${target.host} (systemctl cat exit ${result.exit_code})`,
  );
}

/** How the installed k0scontroller unit was set up, read from its command line. */
async function controllerMode(
  deps: K0sDeps,
  target: SshTarget,
): Promise<ControllerMode> {
  const shown = await deps.ssh.exec(target, [
    "systemctl",
    "show",
    "-p",
    "ExecStart",
    "--value",
    "k0scontroller",
  ]);
  if (!ok(shown)) {
    throw new Error(
      `could not read how k0scontroller is installed on ${target.host}`,
    );
  }
  try {
    return classifyControllerExecStart(shown.stdout);
  } catch {
    throw new Error(
      `could not read how k0scontroller is installed on ${target.host}`,
    );
  }
}

/**
 * Uploads k0s.yaml and, when it changed, restarts the unit and waits for it to
 * be healthy. If the restart fails, the previous file is put back and the unit
 * restarted again on a best-effort basis, so a bad config does not stay on the
 * host. Returns whether the file changed.
 */
async function applyConfig(
  deps: K0sDeps,
  target: SshTarget,
  service: string,
  yaml: string,
): Promise<boolean> {
  await ensurePrivateDir(deps, target, K0S_CONFIG_DIR);
  const before = await deps.ssh.exec(target, ["cat", K0S_CONFIG_PATH]);
  const previous = ok(before) ? before.stdout : null;
  const put = await deps.ssh.upload(target, {
    path: K0S_CONFIG_PATH,
    content: encoder.encode(yaml),
    mode: SECRET_MODE,
  });
  if (!put.changed) return false;
  try {
    await restartAndVerify(deps, target, service);
  } catch (error) {
    let note = "the previous k0s.yaml could not be restored";
    if (previous === null) {
      // There was no config before: do not leave the unverified one behind.
      try {
        await deps.ssh.exec(target, ["rm", "-f", K0S_CONFIG_PATH]);
        note = "the new k0s.yaml was removed";
      } catch {
        note = "the new k0s.yaml could not be removed";
      }
    } else {
      try {
        await deps.ssh.upload(target, {
          path: K0S_CONFIG_PATH,
          content: encoder.encode(previous),
          mode: SECRET_MODE,
        });
        await deps.ssh.exec(target, ["systemctl", "restart", service]);
        note = "the previous k0s.yaml was restored";
      } catch {
        // keep the note above; the original failure is what matters
      }
    }
    throw new Error(`${(error as Error).message}; ${note}`);
  }
  return true;
}

/** Reads everything `get` and `sync` report. */
async function readLive(
  deps: K0sDeps,
  target: SshTarget,
  now: number,
): Promise<z.infer<typeof StatusSchema>> {
  const versionResult = await deps.ssh.exec(target, [
    K0S_BINARY_PATH,
    "version",
  ]);
  const installed = ok(versionResult) && versionResult.stdout.trim() !== "";
  const nodes = installed ? await remoteNodes(deps, target) : [];
  const pods = installed ? await remotePods(deps, target) : [];
  return StatusSchema.parse({
    ...whoOf(target),
    installed,
    k0s_version: installed
      ? versionResult.stdout.trim().split(/\s+/).pop() ?? null
      : null,
    node: nodes.find((node) => node.ready) ?? nodes[0] ?? null,
    nodes,
    system_pods: pods,
    config_file_sha256: installed ? await remoteConfigSha(deps, target) : null,
    stacks: installed ? await remoteStacks(deps, target) : [],
    helm_releases: installed
      ? (await remoteHelmReleases(deps, target)).map((release) => ({
        name: release.name,
        namespace: release.namespace,
        status: release.status,
      }))
      : [],
    observed_at: iso(now),
  });
}

/** `systemctl is-active` reported a state that is neither running nor stopped. */
export class ResetStateError extends Error {
  /** Creates a typed error for an indeterminate unit state. */
  constructor(message: string) {
    super(message);
    this.name = "ResetStateError";
  }
}

/** A reset cleanup step failed after k0s was already reset. */
export class ResetCleanupError extends Error {
  /** Creates a typed error for a failed post-reset cleanup. */
  constructor(message: string) {
    super(message);
    this.name = "ResetCleanupError";
  }
}

/**
 * Removes what `k0s reset` leaves behind: the /etc/k0s directory (k0s's own
 * containerd* placeholders live there) and the k0s binary, but only when the
 * recorded digest still matches, so a binary this model did not install is
 * never removed. Throws {@link ResetCleanupError} when a step fails, so the
 * caller can record that cleanup is still pending.
 */
async function cleanupK0sResidue(
  deps: K0sDeps,
  target: SshTarget,
  recorded: { binary_sha256?: string | null } | null,
  context: Ctx,
): Promise<{ binary_removed: boolean; reason?: string }> {
  const dirGone = await deps.ssh.exec(target, ["rm", "-rf", K0S_CONFIG_DIR]);
  if (!ok(dirGone)) {
    throw new ResetCleanupError(
      `could not remove ${K0S_CONFIG_DIR} on ${target.host} (exit ${dirGone.exit_code})`,
    );
  }
  if (!recorded?.binary_sha256) return { binary_removed: false };
  const sum = await deps.ssh.exec(target, ["sha256sum", K0S_BINARY_PATH]);
  if (!ok(sum)) {
    throw new ResetCleanupError(
      `could not hash ${K0S_BINARY_PATH} on ${target.host} (exit ${sum.exit_code})`,
    );
  }
  const remote = sum.stdout.trim().split(/\s+/)[0]?.toLowerCase();
  if (remote !== recorded.binary_sha256.toLowerCase()) {
    context.logger.info(
      "Leaving {path} on {host}: its digest is not the installed binary",
      { path: K0S_BINARY_PATH, host: target.host },
    );
    return {
      binary_removed: false,
      reason: "binary sha does not match install",
    };
  }
  const binGone = await deps.ssh.exec(target, ["rm", "-f", K0S_BINARY_PATH]);
  if (!ok(binGone)) {
    throw new ResetCleanupError(
      `could not remove the k0s binary on ${target.host} (exit ${binGone.exit_code})`,
    );
  }
  return { binary_removed: true };
}

function buildK0sModel(deps: K0sDeps) {
  return {
    type: "@randybias/k0s-cluster",
    version: "2026.10.17.3",
    upgrades: [
      {
        toVersion: "2026.10.17.2",
        description:
          "reset now also removes /etc/k0s and the k0s binary it installed; stored attributes are unchanged",
        upgradeAttributes: (old: Record<string, unknown>) => old,
      },
      {
        toVersion: "2026.10.17.3",
        description:
          "optional HA config inputs (external_address, node_local_load_balancing, control_plane_load_balancing); stored attributes are unchanged",
        upgradeAttributes: (old: Record<string, unknown>) => old,
      },
    ],
    description:
      "Install, inspect and reset a SHA-256-pinned k0s Kubernetes cluster on one host over SSH, including the rendered k0s.yaml, readiness, the admin kubeconfig, manifest stacks and Helm charts. One definition serves any host; state is keyed by the target host.",
    globalArguments: z.strictObject({}),
    resources: {
      state: {
        description: "Installed k0s cluster state for one host",
        schema: StateSchema,
        lifetime: "infinite" as const,
        garbageCollection: 10,
      },
      hostkeys: {
        description:
          "SSH host keys recorded on first use and pinned for every later connection",
        schema: HostKeysSchema,
        lifetime: "infinite" as const,
        garbageCollection: 10,
      },
      kubeconfig: {
        description:
          "Admin kubeconfig for one host; the kubeconfig field is sensitive",
        schema: KubeconfigSchema,
        lifetime: "infinite" as const,
        garbageCollection: 10,
      },
      readiness: {
        description: "Readiness evidence for one host",
        schema: ReadinessSchema,
        lifetime: "infinite" as const,
        garbageCollection: 10,
      },
      manifests: {
        description: "Applied manifest stack state for one host",
        schema: ManifestStateSchema,
        lifetime: "infinite" as const,
        garbageCollection: 10,
      },
      helm: {
        description: "Reconciled Helm charts for one host",
        schema: HelmStateSchema,
        lifetime: "infinite" as const,
        garbageCollection: 10,
      },
      status: {
        description: "Observed k0s cluster status for one host",
        schema: StatusSchema,
        lifetime: "infinite" as const,
        garbageCollection: 10,
      },
    },
    files: {
      config: {
        description: "Rendered k0s.yaml for one cluster",
        contentType: "application/yaml",
        lifetime: "infinite" as const,
        garbageCollection: 10,
      },
    },
    methods: {
      render_config: {
        description:
          "READ-ONLY. Render the deterministic k0s.yaml for the given cluster inputs and store it as a file. Manifest stacks are not part of k0s.yaml (k0s reads them from its manifest directory), so their planned layout is returned separately.",
        arguments: RenderArgs,
        execute: async (args: z.infer<typeof RenderArgs>, context: Ctx) => {
          const input = renderInput(args);
          const yaml = renderK0sConfig(input);
          const hasValues = args.helm.some((chart) =>
            chart.values != null && Object.keys(chart.values).length > 0
          );
          // Helm values often carry passwords, so a render that includes them
          // is never persisted or returned; callers get a redacted copy and a
          // flag saying so.
          const returnedYaml = hasValues
            ? renderK0sConfig({
              ...input,
              helm: input.helm.map((chart) => ({
                ...chart,
                values: undefined,
              })),
            })
            : yaml;
          // The digest covers the values-free render, so it reveals nothing
          // about chart values that may be secret.
          const configSha = await sha256Hex(encoder.encode(returnedYaml));
          const dataHandles: unknown[] = [];
          if (!hasValues) {
            const writer = context.createFileWriter(
              "config",
              `${instanceName(args.cluster_name)}-config`,
            );
            dataHandles.push(await writer.writeText(returnedYaml));
          }
          // File digests are omitted: manifest text may carry secrets.
          const manifestPlan = args.manifests.map((stack) => ({
            stack: stack.name,
            files: stack.files.map((file) => ({
              path: normalizeManifestPath(file.path),
            })),
          }));
          context.logger.info("Rendered k0s.yaml for {cluster}: {sha256}", {
            cluster: args.cluster_name,
            sha256: configSha,
          });
          return {
            dataHandles,
            result: {
              k0s_version: args.k0s_version,
              k0s_yaml: returnedYaml,
              config_sha256: configSha,
              values_redacted: hasValues,
              manifests: manifestPlan,
              helm_charts: args.helm.map((chart) => ({
                chart: chart.chart,
                version: chart.version,
                namespace: chart.namespace,
              })),
            },
          };
        },
      },

      install: {
        kind: "action" as const,
        description:
          "DESTRUCTIVE. Fetch the pinned k0s binary, verify its SHA-256, upload it with k0s.yaml and install the role, then start the service. Idempotent: a re-run adopts the running service and never installs a second node. Refuses to change an installed role unless confirm_role_change names the host; the replacement is downloaded and verified before the old role is torn down.",
        arguments: InstallArgs,
        execute: async (args: z.infer<typeof InstallArgs>, context: Ctx) => {
          const { target, handles } = await resolveTarget(
            deps,
            context,
            args.ssh,
          );
          const now = deps.now();
          const service = serviceName(args.role);
          const otherService = service === "k0sworker"
            ? "k0scontroller"
            : "k0sworker";
          context.logger.info(
            "Installing k0s {version} as {role} on {host}",
            { version: args.k0s_version, role: args.role, host: target.host },
          );
          if (args.role === "worker" && !args.join_token) {
            throw new Error("role worker requires join_token");
          }

          // Look at both role units before touching anything: a controller
          // re-applied as a worker must not get a second, competing role.
          const otherInstalled = await unitExists(deps, target, otherService);
          let migrating = false;
          // The role unit that a migration stops and resets.
          let replaced = otherService;
          if (otherInstalled) {
            if (
              args.confirm_role_change?.toLowerCase() !== target.host
            ) {
              throw new Error(
                `${target.host} already has ${otherService} installed; refusing to install ${service} beside it. Set confirm_role_change to ${target.host} to replace it (IRREVERSIBLE: this resets the existing role).`,
              );
            }
            migrating = true;
          }

          const yaml = renderK0sConfig(renderInput(args));
          const configFileSha = await sha256Hex(encoder.encode(yaml));
          const configSha = await sha256Hex(
            encoder.encode(
              renderK0sConfig({
                ...renderInput(args),
                helm: renderInput(args).helm.map((chart) => ({
                  ...chart,
                  values: undefined,
                })),
              }),
            ),
          );
          // A unit that exists but is stopped is adopted and started, not
          // reinstalled over: `k0s install` would fail on it.
          let unitPresent = !migrating &&
            await unitExists(deps, target, service);
          let alreadyActive = unitPresent && ok(
            await deps.ssh.exec(target, ["systemctl", "is-active", service]),
          );
          // `single` and `controller` share one unit, so a unit that exists
          // may still have been installed in the other mode. That is a role
          // change like any other.
          if (unitPresent && service === "k0scontroller") {
            const mode = await controllerMode(deps, target);
            const wanted: ControllerMode = args.role === "single"
              ? "single"
              : "controller";
            if (mode !== wanted) {
              if (args.confirm_role_change?.toLowerCase() !== target.host) {
                throw new Error(
                  `${target.host} has k0scontroller installed as ${mode}${
                    mode === "controller+worker"
                      ? " (a worker that kept the control-plane taint, so no workload schedules)"
                      : ""
                  }; refusing to install it as ${args.role}. Set confirm_role_change to ${target.host} to replace it (IRREVERSIBLE: this resets the existing role).`,
                );
              }
              migrating = true;
              replaced = service;
              unitPresent = false;
              alreadyActive = false;
            }
          }
          const result = {
            host: target.host,
            k0s_version: args.k0s_version,
            role: args.role,
            config_sha256: configSha,
          };

          if (unitPresent && !args.force_reinstall) {
            const remoteBinary = parseSha256(
              (await deps.ssh.exec(target, ["sha256sum", K0S_BINARY_PATH]))
                .stdout,
            );
            if (remoteBinary !== args.k0s_binary_sha256.toLowerCase()) {
              throw new Error(
                `refusing to adopt ${target.host}: the installed k0s binary does not match the pinned SHA-256`,
              );
            }
            const versionResult = await deps.ssh.exec(target, [
              K0S_BINARY_PATH,
              "version",
            ]);
            const installedVersion = versionResult.stdout.trim().split(/\s+/)
              .pop();
            if (!ok(versionResult) || installedVersion !== args.k0s_version) {
              throw new Error(
                `refusing to adopt ${target.host}: the installed k0s version is ${
                  installedVersion ?? "unknown"
                }, not ${args.k0s_version}`,
              );
            }
            let adopted = true;
            if (!alreadyActive) {
              await ensurePrivateDir(deps, target, K0S_CONFIG_DIR);
              await deps.ssh.upload(target, {
                path: K0S_CONFIG_PATH,
                content: encoder.encode(yaml),
                mode: SECRET_MODE,
              });
              const started = await deps.ssh.exec(target, [
                "systemctl",
                "enable",
                "--now",
                service,
              ]);
              if (!ok(started)) {
                throw new Error(
                  `could not start ${service} on ${target.host} (exit ${started.exit_code})`,
                );
              }
              await waitUnitHealthy(deps, target, service, 60);
              adopted = false;
            } else if (await applyConfig(deps, target, service, yaml)) {
              // A failed restart means the new config never loaded: fail
              // here, before any state claims it did.
              adopted = false;
            }
            context.logger.info(
              "k0s is already active on {host}; adopting the install",
              { host: target.host },
            );
            const handle = await context.writeResource(
              "state",
              targetId(target),
              StateSchema.parse({
                ...whoOf(target),
                role: args.role,
                k0s_version: args.k0s_version,
                binary_sha256: args.k0s_binary_sha256.toLowerCase(),
                config_sha256: configSha,
                config_file_sha256: configFileSha,
                service,
                installed: true,
                adopted,
                observed_at: iso(now),
              }),
            );
            return { dataHandles: [...handles, handle], result };
          }

          const uname = await deps.ssh.exec(target, ["uname", "-m"]);
          if (!ok(uname)) {
            throw new Error(
              `could not read the architecture of ${target.host} (exit ${uname.exit_code})`,
            );
          }
          const arch = archFromUname(uname.stdout);
          const url = downloadUrl(
            args.k0s_version,
            arch,
            args.k0s_download_url ?? undefined,
          );
          const token = args.k0s_download_token ??
            Deno.env.get("K0S_DOWNLOAD_TOKEN");
          const bytes = await deps.fetch(
            url,
            token
              ? { headers: { Authorization: `Bearer ${token}` } }
              : undefined,
          );
          const binarySha = await verifyBinary(
            bytes,
            args.k0s_binary_sha256,
            url,
          );

          // Everything that can fail without touching the host is done: the
          // artifact is downloaded and verified. Only now is anything torn
          // down.
          if (migrating) {
            const otherActive = ok(
              await deps.ssh.exec(target, [
                "systemctl",
                "is-active",
                replaced,
              ]),
            );
            if (otherActive) {
              const stopped = await deps.ssh.exec(target, [
                K0S_BINARY_PATH,
                "stop",
              ]);
              if (!ok(stopped)) {
                throw new Error(
                  `k0s stop failed on ${target.host} (exit ${stopped.exit_code}); the old role was left in place`,
                );
              }
            }
            const wiped = await deps.ssh.exec(target, [
              K0S_BINARY_PATH,
              "reset",
            ]);
            if (!ok(wiped)) {
              throw new Error(
                `k0s reset failed on ${target.host} (exit ${wiped.exit_code}); the old role may be partly removed`,
              );
            }
          } else if (args.force_reinstall && alreadyActive) {
            const stopped = await deps.ssh.exec(target, [
              K0S_BINARY_PATH,
              "stop",
            ]);
            if (!ok(stopped)) {
              throw new Error(
                `k0s stop failed on ${target.host} (exit ${stopped.exit_code}); not reinstalling over a running service`,
              );
            }
          }
          try {
            await deps.ssh.upload(target, {
              path: K0S_BINARY_PATH,
              content: bytes,
              mode: "0755",
            });
            await ensurePrivateDir(deps, target, K0S_CONFIG_DIR);
            await deps.ssh.upload(target, {
              path: K0S_CONFIG_PATH,
              content: encoder.encode(yaml),
              mode: SECRET_MODE,
            });
            if (args.role === "worker") {
              // Sent only once the install is certain to proceed, never to a
              // host that is about to be adopted or refused.
              await deps.ssh.upload(target, {
                path: K0S_WORKER_TOKEN_PATH,
                content: encoder.encode(
                  args.join_token!.endsWith("\n")
                    ? args.join_token!
                    : `${args.join_token}\n`,
                ),
                mode: SECRET_MODE,
              });
            }

            const installed = await deps.ssh.exec(target, [
              K0S_BINARY_PATH,
              ...installArgs(args.role, args.force_reinstall),
            ]);
            if (!ok(installed)) {
              throw new Error(
                `k0s install failed on ${target.host} (exit ${installed.exit_code})`,
              );
            }
            const started = await deps.ssh.exec(target, [
              "systemctl",
              "enable",
              "--now",
              service,
            ]);
            if (!ok(started)) {
              throw new Error(
                `could not start ${service} on ${target.host} (exit ${started.exit_code})`,
              );
            }
            await waitUnitHealthy(deps, target, service, 60);
          } catch (error) {
            if (!migrating) throw error;
            // The old role is already gone and cannot be restored: say so
            // and record that nothing is installed, rather than leaving a
            // state that still claims the old role.
            let newUnit = false;
            try {
              newUnit = await unitExists(deps, target, service);
            } catch {
              // unknown: record nothing installed, the safer claim
            }
            await context.writeResource(
              "state",
              targetId(target),
              StateSchema.parse({
                ...whoOf(target),
                role: newUnit ? args.role : null,
                k0s_version: null,
                binary_sha256: null,
                config_sha256: null,
                config_file_sha256: null,
                service: newUnit ? service : null,
                installed: false,
                adopted: false,
                observed_at: iso(now),
              }),
            );
            throw new Error(
              `${
                (error as Error).message
              }; the previous ${replaced} role had already been reset and could not be restored. ${
                newUnit
                  ? `The new ${service} unit exists but did not come up`
                  : "No k0s role is installed"
              } on ${target.host}. Re-run install to finish the migration.`,
            );
          }
          context.logger.info(
            "k0s {version} installed and {service} started on {host}",
            { version: args.k0s_version, service, host: target.host },
          );
          const handle = await context.writeResource(
            "state",
            targetId(target),
            StateSchema.parse({
              ...whoOf(target),
              role: args.role,
              k0s_version: args.k0s_version,
              binary_sha256: binarySha,
              config_sha256: configSha,
              config_file_sha256: configFileSha,
              service,
              installed: true,
              adopted: false,
              observed_at: iso(now),
            }),
          );
          return { dataHandles: [...handles, handle], result };
        },
      },

      wait_ready: {
        kind: "action" as const,
        description:
          "READ-ONLY. Poll until a node reports Ready and the kube-system pods are running, up to ready_timeout_s. Returns ready false after the timeout; a connection, authentication or host-key failure is raised, never reported as not-ready. Stores readiness evidence.",
        arguments: WaitReadyArgs,
        execute: async (args: z.infer<typeof WaitReadyArgs>, context: Ctx) => {
          const { target, handles } = await resolveTarget(
            deps,
            context,
            args.ssh,
          );
          const started = deps.now();
          const deadline = started + args.ready_timeout_s * 1000;
          let nodes: NodeStatus[] = [];
          let pods: PodStatus[] = [];
          let ready = false;
          let readyNode: NodeStatus | null = null;
          let last = "not polled yet";
          while (deps.now() < deadline) {
            nodes = await remoteNodes(deps, target);
            readyNode = nodes.find((node) => node.ready) ?? null;
            if (!readyNode) {
              last = nodes.length === 0
                ? "no node has registered yet"
                : "no node reports Ready yet";
            } else {
              pods = await remotePods(deps, target);
              if (!args.require_system_pods || systemPodsHealthy(pods)) {
                ready = true;
                break;
              }
              last = "node is Ready but system pods are not all running";
            }
            context.logger.info("{host} not ready: {reason}", {
              host: target.host,
              reason: last,
            });
            await deps.sleep(args.poll_interval_s * 1000);
          }
          const finished = deps.now();
          const readiness = ReadinessSchema.parse({
            ...whoOf(target),
            ready,
            node: readyNode,
            system_pods: pods,
            waited_seconds: Math.round((finished - started) / 1000),
            observed_at: iso(finished),
          });
          const handle = await context.writeResource(
            "readiness",
            `${targetId(target)}~readiness`,
            readiness,
          );
          context.logger.info("Readiness for {host}: {ready}", {
            host: target.host,
            ready,
          });
          return {
            dataHandles: [...handles, handle],
            result: {
              ready,
              node: readyNode,
              system_pods: pods,
            },
          };
        },
      },

      kubeconfig: {
        kind: "action" as const,
        description:
          "READ-ONLY. Fetch the admin kubeconfig and keep it as a sensitive value, or write it to a vault key named by store_in_vault. The kubeconfig text never appears in the return value, logs or --json output; only its SHA-256, server URL and the vault key are returned.",
        arguments: KubeconfigArgs,
        execute: async (args: z.infer<typeof KubeconfigArgs>, context: Ctx) => {
          const { target, handles } = await resolveTarget(
            deps,
            context,
            args.ssh,
          );
          const result = await deps.ssh.exec(target, [
            K0S_BINARY_PATH,
            "kubeconfig",
            "admin",
          ]);
          if (!ok(result) || result.stdout.trim() === "") {
            throw new Error(
              `could not read the admin kubeconfig from ${target.host} (exit ${result.exit_code})`,
            );
          }
          // With an explicit API address the server URL is built from it, so
          // callers reach the cluster on that address whatever k0s wrote.
          const kubeconfig = args.api_address
            ? withServer(
              result.stdout,
              apiServerUrl(args.api_address, args.api_port),
            )
            : result.stdout;
          const digest = await sha256Hex(encoder.encode(kubeconfig));
          const server = parseKubeconfigServer(kubeconfig);
          const vault = args.store_in_vault ?? null;
          if (vault) {
            // swamp's vault service is not part of the documented method
            // context, so require it by shape and say so if it is missing.
            if (typeof context.vaultService?.put !== "function") {
              throw new Error(
                "this swamp version does not expose a vault service to methods; omit store_in_vault",
              );
            }
            try {
              await context.vaultService.put(
                vault.vault,
                vault.key,
                kubeconfig,
              );
            } catch {
              // The backend's own text is never reflected: it may quote any
              // fragment of the value. Vault and key names are validated.
              throw new Error(
                `could not write the kubeconfig to vault ${vault.vault} key ${vault.key}`,
              );
            }
          }
          const handled = await context.writeResource(
            "kubeconfig",
            `${targetId(target)}~kubeconfig`,
            KubeconfigSchema.parse({
              ...whoOf(target),
              server,
              sha256: digest,
              ...(vault
                ? { vault: vault.vault, vault_key: vault.key }
                : { kubeconfig }),
              observed_at: iso(deps.now()),
            }),
          );
          context.logger.info(
            "Stored a sensitive kubeconfig for {host}: server {server}, sha256 {sha256}, vault {vault}",
            {
              host: target.host,
              server: server ?? "unknown",
              sha256: digest,
              vault: vault ? `${vault.vault}/${vault.key}` : "none",
            },
          );
          return {
            dataHandles: [...handles, handled],
            result: {
              host: target.host,
              server,
              sha256: digest,
              ...(vault ? { vault: vault.vault, vault_key: vault.key } : {}),
            },
          };
        },
      },

      apply_manifests: {
        kind: "action" as const,
        description:
          "DESTRUCTIVE. Place a named manifest stack under the k0s manifest directory, uploading only changed files and removing files no longer declared. Idempotent: re-applying identical files changes nothing. Returns the stack, its files and whether anything changed.",
        arguments: ApplyManifestsArgs,
        execute: async (
          args: z.infer<typeof ApplyManifestsArgs>,
          context: Ctx,
        ) => {
          const { target, handles } = await resolveTarget(
            deps,
            context,
            args.ssh,
          );
          const stack = args.stack;
          const dir = `${K0S_MANIFEST_DIR}/${stack.name}`;
          await ensurePrivateDir(deps, target, dir);
          // `find -type f` lists nested files too; every path is validated
          // before any deletion so a hostile file name cannot escape the dir.
          const listing = await deps.ssh.exec(target, [
            "find",
            dir,
            "-type",
            "f",
          ]);
          if (!ok(listing)) {
            throw new Error(
              `could not list ${dir} on ${target.host} (exit ${listing.exit_code}); nothing was changed`,
            );
          }
          const existing = parseNameList(listing.stdout).map((path) =>
            path.startsWith(`${dir}/`) ? path.slice(dir.length + 1) : path
          );
          const desired = new Map(
            stack.files.map((file) => [
              normalizeManifestPath(file.path),
              file,
            ]),
          );
          const files: { path: string; sha256: string }[] = [];
          let applied = false;
          const sorted = [...stack.files].sort((a, b) =>
            normalizeManifestPath(a.path).localeCompare(
              normalizeManifestPath(b.path),
            )
          );
          const landed: string[] = [];
          for (const file of sorted) {
            const relative = normalizeManifestPath(file.path);
            const content = encoder.encode(file.content);
            const digest = await sha256Hex(content);
            files.push({ path: relative, sha256: digest });
            // Always go through upload: it converges bytes and mode, so a
            // file that already holds these bytes under a looser mode is
            // still tightened to 0600.
            try {
              await ensurePrivateDir(
                deps,
                target,
                `${dir}/${relative}`.slice(
                  0,
                  `${dir}/${relative}`.lastIndexOf("/"),
                ),
              );
              const put = await deps.ssh.upload(target, {
                path: `${dir}/${relative}`,
                content,
                mode: SECRET_MODE,
              });
              if (put.changed) applied = true;
              landed.push(relative);
            } catch (error) {
              // The stack is applied file by file, so say which files made
              // it: k0s may already be deploying a partial stack.
              throw new Error(
                `${
                  (error as Error).message
                }; stack ${stack.name} is partly applied on ${target.host}: ${landed.length} of ${sorted.length} files uploaded (${
                  landed.join(", ") || "none"
                }), failed at ${relative}. Re-run apply_manifests to finish.`,
              );
            }
          }
          for (const found of existing) {
            const relative = normalizeManifestPath(found);
            if (desired.has(relative)) continue;
            const segments = relative.split("/");
            if (
              relative === "" || segments.some((name) => !isSafeFilename(name))
            ) {
              throw new Error(
                `refusing to remove an unexpected stack entry: ${found}`,
              );
            }
            const stalePath = `${dir}/${relative}`;
            assertRemotePath(stalePath);
            const removed = await deps.ssh.exec(target, [
              "rm",
              "-f",
              stalePath,
            ]);
            if (!ok(removed)) {
              throw new Error(
                `could not remove stale manifest ${relative} (exit ${removed.exit_code})`,
              );
            }
            applied = true;
          }
          const handle = await context.writeResource(
            "manifests",
            `${targetId(target)}~stack~${stack.name}`,
            ManifestStateSchema.parse({
              ...whoOf(target),
              stack: stack.name,
              files,
              applied,
              observed_at: iso(deps.now()),
            }),
          );
          context.logger.info(
            "Manifest stack {stack} on {host}: {count} file(s), changed {applied}",
            {
              stack: stack.name,
              host: target.host,
              count: files.length,
              applied,
            },
          );
          return {
            dataHandles: [...handles, handle],
            result: {
              stack: stack.name,
              files: files.map((file) => ({ path: file.path })),
              applied,
            },
          };
        },
      },

      apply_helm: {
        kind: "action" as const,
        description:
          "DESTRUCTIVE. Reconcile the declared Helm extensions in k0s.yaml, restarting the controller only when the file changes, then wait until each release is present. Idempotent on an unchanged file. Fails if the controller does not restart healthy or a chart does not reconcile in time.",
        arguments: ApplyHelmArgs,
        execute: async (args: z.infer<typeof ApplyHelmArgs>, context: Ctx) => {
          const { target, handles } = await resolveTarget(
            deps,
            context,
            args.ssh,
          );
          const yaml = renderK0sConfig(renderInput(args));
          // A restart that failed means the chart config never loaded; the
          // previous config is put back.
          const applied = await applyConfig(
            deps,
            target,
            "k0scontroller",
            yaml,
          );
          const wanted = new Map(
            args.helm.map((chart) => [
              `${chart.namespace}/${chartBaseName(chart.chart)}`,
              chart,
            ]),
          );
          const deadline = deps.now() + args.reconcile_timeout_s * 1000;
          let releases: HelmRelease[] = [];
          let reconciled = false;
          let pending: string[] = [];
          while (true) {
            releases = await remoteHelmReleases(deps, target);
            const known = await remoteCharts(deps, target);
            pending = [];
            for (const [key, chart] of wanted) {
              const release = releases.find((r) =>
                `${r.namespace}/${r.name}` === key
              );
              const resource = known.find((c) =>
                `${c.namespace}/${c.name}` === key
              );
              if (release?.status === "failed") {
                throw new Error(
                  `Helm release ${key} failed on ${target.host}`,
                );
              }
              if (!release) {
                pending.push(`${key} (no release yet)`);
              } else if (release.status !== "deployed") {
                pending.push(`${key} (status ${release.status})`);
              } else if (resource?.version !== chart.version) {
                pending.push(
                  `${key} (chart version ${
                    resource?.version ?? "unknown"
                  }, wanted ${chart.version})`,
                );
              }
            }
            if (pending.length === 0) {
              reconciled = true;
              break;
            }
            if (deps.now() >= deadline) break;
            await deps.sleep(args.poll_interval_s * 1000);
          }
          if (!reconciled) {
            throw new Error(
              `Helm extensions did not reconcile on ${target.host} within ${args.reconcile_timeout_s}s: ${
                pending.join(", ")
              }`,
            );
          }
          const status = new Map(
            releases.map((release) => [
              `${release.namespace}/${release.name}`,
              release.status,
            ]),
          );
          const charts = args.helm.map((chart) => ({
            name: chartBaseName(chart.chart),
            chartname: chart.chart,
            version: chart.version,
            namespace: chart.namespace,
            status: status.get(
              `${chart.namespace}/${chartBaseName(chart.chart)}`,
            ) ?? "unknown",
          }));
          const handle = await context.writeResource(
            "helm",
            `${targetId(target)}~helm`,
            HelmStateSchema.parse({
              ...whoOf(target),
              charts,
              reconciled,
              observed_at: iso(deps.now()),
            }),
          );
          context.logger.info(
            "Reconciled {count} Helm chart(s) on {host}, config changed {applied}",
            { count: charts.length, host: target.host, applied },
          );
          return {
            dataHandles: [...handles, handle],
            result: { charts, reconciled },
          };
        },
      },

      get: {
        description:
          "READ-ONLY. Read the k0s version, node status, config digest, manifest stacks and Helm releases from the host and store them. Reports whether a kubeconfig has been recorded.",
        arguments: GetArgs,
        execute: async (args: z.infer<typeof GetArgs>, context: Ctx) => {
          const { target, handles } = await resolveTarget(
            deps,
            context,
            args.ssh,
          );
          const now = deps.now();
          const status = await readLive(deps, target, now);
          const recorded = await context.readResource(
            `${targetId(target)}~kubeconfig`,
          );
          const handle = await context.writeResource(
            "status",
            `${targetId(target)}~status`,
            status,
          );
          const { config_file_sha256: configFile, ...publicStatus } = status;
          context.logger.info("Read k0s status for {host}: version {version}", {
            host: target.host,
            version: status.k0s_version ?? "not installed",
          });
          return {
            dataHandles: [...handles, handle],
            result: {
              ...publicStatus,
              config_present: configFile !== null,
              kubeconfig_present: recorded !== null,
            },
          };
        },
      },

      sync: {
        description:
          "READ-ONLY. Compare the recorded install with the live host and report drift, refreshing the stored status. Returns whether the record is in sync and each difference.",
        arguments: SyncArgs,
        execute: async (args: z.infer<typeof SyncArgs>, context: Ctx) => {
          const { target, handles } = await resolveTarget(
            deps,
            context,
            args.ssh,
          );
          const now = deps.now();
          const status = await readLive(deps, target, now);
          const stored = await context.readResource(targetId(target));
          const diffs: string[] = [];
          if (!stored) {
            diffs.push("no recorded install; run install first");
          } else {
            if (stored.installed !== status.installed) {
              diffs.push(
                `installed ${stored.installed} -> ${status.installed}`,
              );
            }
            if (stored.k0s_version !== status.k0s_version) {
              diffs.push(
                `version ${stored.k0s_version ?? "none"} -> ${
                  status.k0s_version ?? "none"
                }`,
              );
            }
            if (stored.config_file_sha256 !== status.config_file_sha256) {
              diffs.push("config changed on the host since it was recorded");
            }
          }
          const handle = await context.writeResource(
            "status",
            `${targetId(target)}~status`,
            status,
          );
          context.logger.info("Synced {host}: in_sync {inSync}", {
            host: target.host,
            inSync: diffs.length === 0,
          });
          return {
            dataHandles: [...handles, handle],
            result: { in_sync: diffs.length === 0, diffs },
          };
        },
      },

      reset: {
        kind: "action" as const,
        description:
          "DESTRUCTIVE. Stop and uninstall k0s on the host and remove its configuration. Re-running on a host with no k0s unit is a clean no-op.",
        arguments: ResetArgs,
        execute: async (args: z.infer<typeof ResetArgs>, context: Ctx) => {
          if (args.confirm_host.toLowerCase() !== args.ssh.host.toLowerCase()) {
            throw new Error(
              `confirm_host ${args.confirm_host} does not match the SSH host ${args.ssh.host}`,
            );
          }
          const { target, handles } = await resolveTarget(
            deps,
            context,
            args.ssh,
          );
          if (args.confirm_host.toLowerCase() !== target.host) {
            throw new Error(
              `confirm_host ${args.confirm_host} does not match the SSH host ${target.host}`,
            );
          }
          const recorded = await context.readResource(targetId(target)) as
            | { binary_sha256?: string | null; cleanup_pending?: boolean }
            | null;
          const pending = Boolean(recorded?.binary_sha256) ||
            recorded?.cleanup_pending === true;
          const writeState = (
            extra: {
              binary_sha256?: string | null;
              cleanup_pending?: boolean;
              binary_removed?: boolean;
              binary_removal_reason?: string;
            },
          ) =>
            context.writeResource(
              "state",
              targetId(target),
              StateSchema.parse({
                ...whoOf(target),
                role: null,
                k0s_version: null,
                binary_sha256: null,
                config_sha256: null,
                config_file_sha256: null,
                service: null,
                installed: false,
                adopted: false,
                observed_at: iso(deps.now()),
                ...extra,
              }),
            );
          const singleUnit = serviceName("single");
          const workerUnit = serviceName("worker");
          const unit = (await unitExists(deps, target, singleUnit))
            ? singleUnit
            : (await unitExists(deps, target, workerUnit))
            ? workerUnit
            : null;
          if (!unit) {
            if (!pending) {
              context.logger.info(
                "No k0s service on {host}; reset is a no-op",
                { host: target.host },
              );
              const handle = await writeState({});
              return {
                dataHandles: [...handles, handle],
                result: { reset: false, binary_removed: false },
              };
            }
            // An earlier reset removed the unit but did not finish its cleanup.
            let cleanup: { binary_removed: boolean; reason?: string };
            try {
              cleanup = await cleanupK0sResidue(
                deps,
                target,
                recorded,
                context,
              );
            } catch (e) {
              await writeState({
                binary_sha256: recorded?.binary_sha256 ?? null,
                cleanup_pending: true,
              });
              throw e;
            }
            context.logger.info("Finished reset cleanup on {host}", {
              host: target.host,
            });
            const handle = await writeState({
              binary_removed: cleanup.binary_removed,
              ...(cleanup.reason
                ? { binary_removal_reason: cleanup.reason }
                : {}),
            });
            return {
              dataHandles: [...handles, handle],
              result: { reset: true, ...cleanup },
            };
          }
          // A k0s unit that is already stopped (after a crash or a reboot) makes
          // `k0s stop` exit non-zero with "already stopped"; skip it when the
          // unit is inactive, and never trust stderr text alone.
          const active = await deps.ssh.exec(target, [
            "systemctl",
            "is-active",
            unit,
          ]);
          const unitState = active.stdout.trim();
          const stoppedStates = ["inactive", "failed"];
          if (unitState === "active") {
            const stopped = await deps.ssh.exec(target, [
              K0S_BINARY_PATH,
              "stop",
            ]);
            if (!ok(stopped)) {
              const after = await deps.ssh.exec(target, [
                "systemctl",
                "is-active",
                unit,
              ]);
              const afterState = after.stdout.trim();
              if (afterState === "active") {
                throw new Error(
                  `k0s stop failed on ${target.host} (exit ${stopped.exit_code}) and ${unit} is still active`,
                );
              }
              if (!stoppedStates.includes(afterState)) {
                throw new ResetStateError(
                  `k0s stop failed on ${target.host} and ${unit} is ${
                    afterState || "in an unknown state"
                  } (systemctl is-active exit ${after.exit_code})`,
                );
              }
              context.logger.info(
                "k0s stop reported {code} but {unit} is {state}; continuing",
                { code: stopped.exit_code, unit, state: afterState },
              );
            }
          } else if (!stoppedStates.includes(unitState)) {
            throw new ResetStateError(
              `could not tell whether ${unit} is running on ${target.host}: systemctl is-active reported ${
                unitState || "no output"
              } (exit ${active.exit_code})`,
            );
          }
          const result = await deps.ssh.exec(target, [
            K0S_BINARY_PATH,
            "reset",
          ]);
          if (!ok(result)) {
            throw new Error(
              `k0s reset failed on ${target.host} (exit ${result.exit_code})`,
            );
          }
          const cleaned = await deps.ssh.exec(target, [
            "rm",
            "-f",
            K0S_CONFIG_PATH,
            K0S_WORKER_TOKEN_PATH,
          ]);
          if (!ok(cleaned)) {
            throw new Error(
              `could not remove the k0s configuration on ${target.host} (exit ${cleaned.exit_code})`,
            );
          }
          let cleanup: { binary_removed: boolean; reason?: string };
          try {
            cleanup = await cleanupK0sResidue(deps, target, recorded, context);
          } catch (e) {
            await writeState({
              binary_sha256: recorded?.binary_sha256 ?? null,
              cleanup_pending: true,
            });
            throw e;
          }
          context.logger.info("Reset k0s on {host}", { host: target.host });
          const handle = await writeState({
            binary_removed: cleanup.binary_removed,
            ...(cleanup.reason
              ? { binary_removal_reason: cleanup.reason }
              : {}),
          });
          return {
            dataHandles: [...handles, handle],
            result: { reset: true, ...cleanup },
          };
        },
      },
    },
  };
}

/** The shape of the k0s-cluster model definition. */
export type K0sClusterModel = ReturnType<typeof buildK0sModel>;

/** Builds the model with explicit dependencies; tests pass fakes. */
export function createModel(deps: K0sDeps): K0sClusterModel {
  return buildK0sModel(deps);
}

/** Production model definition. */
export const model = {
  ...buildK0sModel(defaultK0sDeps),
  type: "@randybias/k0s-cluster",
  version: "2026.10.17.3",
} satisfies K0sClusterModel;
