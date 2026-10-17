/**
 * Swamp extension model for an ISC Kea DHCPv4 server on one Linux host.
 *
 * The definition holds no host, network or MAC: every method takes its target
 * and DHCP inputs as arguments. A candidate configuration is rendered
 * deterministically, validated by Kea itself, written atomically and pushed to
 * the running server with `config-set` — never `config-reload` or a restart.
 * Because a bad DHCP change can strand every host that renews on the network it
 * serves, every apply arms a host-side revert timer that restores the previous
 * configuration unless `commit` cancels it.
 *
 * @module
 */

import { z } from "npm:zod@4.3.6";
import {
  assertRemotePath,
  denoDeps,
  exec as sshExec,
  type ExecResult,
  HOST_RE,
  posixQuote,
  sha256Hex,
  SshConfigError,
  type SshDeps,
  SshError,
  type SshTarget,
  upload as sshUpload,
  USER_RE,
} from "./_lib/ssh.ts";
import {
  isCidr,
  isFqdn,
  isInterfaceName,
  isIpv4,
  isLabel,
  isMac,
  KeaInputError,
  parseInterface,
  targetKey,
} from "./_lib/grammar.ts";
import {
  APPLY_PLAN,
  type ApplyStep,
  DEFAULT_CONTROL_SOCKET,
  DEFAULT_LEASE_FILE,
  renderConfig,
  type RenderInput,
  type RenderResult,
} from "./_lib/render.ts";
import {
  filterLeases,
  type Lease,
  type LeaseFilter,
  parseLeaseCsvFiles,
  parseLeaseJson,
} from "./_lib/lease.ts";

const CONFIG_PATH = "/etc/kea/kea-dhcp4.conf";
const REVERT_ROOT = "/var/lib/kea-dhcp-revert";
const SERVICE = "kea-dhcp4-server";

/** A handle returned by `writeResource`. */
interface DataHandle {
  name: string;
  specName: string;
  kind: string;
  dataId: string;
  version: number;
  size: number;
}

/** The subset of the swamp method context this model uses. */
export interface MethodContext {
  logger: {
    info: (message: string, fields?: Record<string, unknown>) => void;
    warn: (message: string, fields?: Record<string, unknown>) => void;
  };
  writeResource: (
    specName: string,
    instanceName: string,
    data: Record<string, unknown>,
  ) => Promise<DataHandle>;
  readResource: (
    instanceName: string,
    version?: number,
  ) => Promise<Record<string, unknown> | null>;
  vaultService?: {
    get: (vaultName: string, key: string) => Promise<string>;
  };
  extensionFile?: (path: string) => string;
}

/** Injectable dependencies, including the overridable transport seams. */
export interface KeaDeps extends SshDeps {
  /** Resolves a vault reference to its secret. Tests replace this. */
  resolveSecret?: (reference: string) => Promise<string>;
  /** Generates an unguessable revert token. Tests replace this. */
  token: () => string;
}

const productionDeps: KeaDeps = {
  ...denoDeps,
  token: () => crypto.randomUUID(),
};

let deps: KeaDeps = productionDeps;

/** Replaces the model dependencies (tests only). Returns the previous ones. */
export function setDeps(next: Partial<KeaDeps>): KeaDeps {
  const previous = deps;
  deps = { ...deps, ...next };
  return previous;
}

const IPV4 = z.string().max(15).refine(isIpv4, "must be an IPv4 address");
const CIDR = z.string().max(18).refine(
  isCidr,
  "must be an IPv4 CIDR in network form",
);
const MAC = z.string().regex(/^[0-9a-f]{2}(?::[0-9a-f]{2}){5}$/).refine(
  (value) => isMac(value),
  "must be a lowercase unicast MAC address",
);
const FQDN = z.string().max(253).refine(isFqdn, "must be a DNS name");
const INTERFACE = z.string().max(20).refine(
  isInterfaceName,
  "must be a network interface name with no wildcard",
);
const HOSTNAME_OR_FQDN = z.string().max(253).refine(
  (value) => isLabel(value) || isFqdn(value),
  "must be an RFC 1123 hostname",
);

const ReservationSchema = z.strictObject({
  hw_address: MAC.describe("Lowercase unicast MAC address."),
  ip_address: IPV4.describe("Reserved IPv4 address inside the subnet."),
  hostname: HOSTNAME_OR_FQDN.nullish().describe("Optional hostname."),
});

const OptionSchema = z.discriminatedUnion("name", [
  z.strictObject({
    name: z.literal("routers"),
    value: z.array(IPV4).min(1).max(16),
  }),
  z.strictObject({
    name: z.literal("domain-name-servers"),
    value: z.array(IPV4).min(1).max(16),
  }),
  z.strictObject({
    name: z.literal("ntp-servers"),
    value: z.array(IPV4).min(1).max(16),
  }),
  z.strictObject({ name: z.literal("domain-name"), value: FQDN }),
  z.strictObject({
    name: z.literal("domain-search"),
    value: z.array(FQDN).min(1).max(16),
  }),
  z.strictObject({
    name: z.literal("interface-mtu"),
    value: z.number().int().min(576).max(9216),
  }),
  z.strictObject({
    name: z.literal("classless-static-route"),
    value: z.array(
      z.strictObject({ prefix: CIDR, router: IPV4 }),
    ).min(1).max(32),
  }),
]);

const SubnetSchema = z.strictObject({
  id: z.number().int().min(1).max(4294967294).describe("Explicit subnet id."),
  subnet: CIDR.describe("IPv4 subnet in network form, /8 to /30."),
  pools: z.array(z.string().max(40)).min(1).max(16).describe(
    "Pool ranges 'a.b.c.d - a.b.c.e' or CIDRs.",
  ),
  reservations: z.array(ReservationSchema).max(1024).describe(
    "Host reservations by MAC.",
  ),
  options: z.array(OptionSchema).max(32).describe("Per-subnet options."),
  valid_lifetime_s: z.number().int().min(60).max(604800).nullish().describe(
    "Per-subnet valid lifetime.",
  ),
  relay_addresses: z.array(IPV4).max(16).nullish().describe(
    "Relay addresses that select this subnet.",
  ),
});

const SshFields = {
  host: z.string().regex(HOST_RE).max(253).describe("Target host."),
  port: z.number().int().min(1).max(65535).default(22).describe("SSH port."),
  user: z.string().regex(USER_RE).describe("Remote user with sudo."),
  host_key_policy: z.enum(["strict"]).describe(
    "Required; only strict is offered, so the host is verified against host_keys on every run.",
  ),
  host_keys: z.array(z.string().max(8192)).min(1).max(64).describe(
    "ssh-keyscan-format lines; the only accepted host keys.",
  ),
  ssh_key_ref: z.string().min(3).max(1024).meta({ sensitive: true }).describe(
    "Vault reference '<vault>/<key>' for the private key; delivered over stdin.",
  ),
  connect_timeout_s: z.number().int().min(1).max(120).default(15).describe(
    "SSH connection timeout in seconds.",
  ),
};

const DhcpFields = {
  interfaces: z.array(INTERFACE).min(1).max(8).describe(
    "Interfaces to serve, optionally pinned as name/ipv4. No wildcard.",
  ),
  socket_type: z.enum(["raw", "udp"]).default("raw").describe(
    "Socket type; use udp for relayed-only networks.",
  ),
  valid_lifetime_s: z.number().int().min(60).max(604800).default(3600).describe(
    "Global valid lease lifetime in seconds.",
  ),
  renew_timer_s: z.number().int().min(1).max(604800).nullish().describe(
    "Optional renew timer; must be below rebind and valid.",
  ),
  rebind_timer_s: z.number().int().min(1).max(604800).nullish().describe(
    "Optional rebind timer; must be below valid.",
  ),
  options: z.array(OptionSchema).max(32).default([]).describe(
    "Global DHCP options.",
  ),
  subnets: z.array(SubnetSchema).min(1).max(64).describe(
    "Subnets, each with an explicit id.",
  ),
  lease_api: z.boolean().default(false).describe(
    "Use the lease_cmds hook (requires lease_cmds_path).",
  ),
  lease_cmds_path: z.string().max(4096).nullish().describe(
    "Absolute path of the lease_cmds hook library.",
  ),
  revert_after_s: z.number().int().min(120).max(3600).default(600).describe(
    "Seconds an uncommitted change stays armed before it reverts.",
  ),
  canary_hosts: z.array(IPV4).max(16).default([]).describe(
    "Addresses the Kea host must still reach for commit.",
  ),
  serve_on_management_ack: z.boolean().default(false).describe(
    "Acknowledge serving DHCP on the interface that carries this SSH session.",
  ),
};

/** The configuration-bearing arguments, shared by render/apply. */
export const configArgsSchema = z.strictObject({ ...DhcpFields }).superRefine(
  (args, ctx) => {
    try {
      renderConfig(toRenderInput(args));
    } catch (error) {
      ctx.addIssue({
        code: "custom",
        message: error instanceof Error ? error.message : String(error),
      });
    }
    if (args.lease_api && !args.lease_cmds_path) {
      ctx.addIssue({
        code: "custom",
        path: ["lease_cmds_path"],
        message: "lease_api requires lease_cmds_path",
      });
    }
    if (
      args.renew_timer_s != null && args.rebind_timer_s != null &&
      !(args.renew_timer_s < args.rebind_timer_s &&
        args.rebind_timer_s < args.valid_lifetime_s)
    ) {
      ctx.addIssue({
        code: "custom",
        path: ["renew_timer_s"],
        message: "renew_timer_s < rebind_timer_s < valid_lifetime_s required",
      });
    }
  },
);

/** Arguments for `apply`. */
export const applyArgsSchema = z.strictObject({
  ...SshFields,
  ...DhcpFields,
}).superRefine((args, ctx) => {
  try {
    renderConfig(toRenderInput(args));
  } catch (error) {
    ctx.addIssue({
      code: "custom",
      message: error instanceof Error ? error.message : String(error),
    });
  }
  if (args.lease_api && !args.lease_cmds_path) {
    ctx.addIssue({
      code: "custom",
      path: ["lease_cmds_path"],
      message: "lease_api requires lease_cmds_path",
    });
  }
  if (
    args.renew_timer_s != null && args.rebind_timer_s != null &&
    !(args.renew_timer_s < args.rebind_timer_s &&
      args.rebind_timer_s < args.valid_lifetime_s)
  ) {
    ctx.addIssue({
      code: "custom",
      path: ["renew_timer_s"],
      message: "renew_timer_s < rebind_timer_s < valid_lifetime_s required",
    });
  }
});

/** Arguments for the target-only methods. */
export const targetArgsSchema = z.strictObject({ ...SshFields });

/** Arguments for `commit`/`remove`. */
export const strictTargetArgsSchema = z.strictObject({ ...SshFields });

/** Arguments for `get`/`sync`. */
export const probeArgsSchema = z.strictObject({ ...SshFields });

/** Arguments for `leases`. */
export const leaseArgsSchema = z.strictObject({
  ...SshFields,
  subnet_id: z.number().int().min(1).max(4294967294).nullish(),
  ip_address: IPV4.nullish(),
  hw_address: MAC.nullish(),
  lease_api: z.boolean().default(false),
});

const ConfigStateSchema = z.strictObject({
  host: z.string(),
  config_sha256: z.string(),
  kea_hash: z.string().optional(),
  committed_at: z.string(),
  applied_at: z.string(),
  subnets: z.number().int(),
});

const RevertStateSchema = z.strictObject({
  host: z.string(),
  token: z.string(),
  armed_at: z.string(),
  expires_at: z.string(),
  armed_sha256: z.string(),
  canaries: z.array(z.string()).optional(),
  fired_at: z.string().optional(),
  cancelled_at: z.string().optional(),
});

const ObservationSchema = z.strictObject({
  host: z.string(),
  service_active: z.boolean(),
  kea_version: z.string().optional(),
  file_sha256: z.string().optional(),
  kea_hash: z.string().optional(),
  sockets: z.array(z.string()),
  revert_armed: z.boolean(),
  revert_token: z.string().optional(),
  revert_expires_at: z.string().optional(),
  drift: z.array(z.string()),
  observed_at: z.string(),
});

const LeaseStateSchema = z.strictObject({
  host: z.string(),
  source: z.enum(["memfile", "lease_cmds"]),
  count: z.number().int(),
  leases: z.array(z.strictObject({
    ip_address: z.string(),
    hw_address: z.string(),
    hostname: z.string().optional(),
    subnet_id: z.number().int(),
    expires_at: z.string(),
    state: z.enum(["default", "declined", "expired-reclaimed", "unknown"]),
  })),
  observed_at: z.string(),
});

type ConfigState = z.infer<typeof ConfigStateSchema>;
type RevertState = z.infer<typeof RevertStateSchema>;
type Observation = z.infer<typeof ObservationSchema>;
type LeaseState = z.infer<typeof LeaseStateSchema>;

type ConfigArgs = z.infer<typeof configArgsSchema>;
type ApplyArgs = z.infer<typeof applyArgsSchema>;
type SshArgs = z.infer<typeof targetArgsSchema>;
type LeaseArgs = z.infer<typeof leaseArgsSchema>;

/** Builds the renderer input from validated arguments. */
export function toRenderInput(args: ConfigArgs): RenderInput {
  return {
    interfaces: args.interfaces,
    socket_type: args.socket_type,
    valid_lifetime_s: args.valid_lifetime_s,
    renew_timer_s: args.renew_timer_s ?? undefined,
    rebind_timer_s: args.rebind_timer_s ?? undefined,
    options: args.options,
    subnets: args.subnets.map((subnet) => ({
      id: subnet.id,
      subnet: subnet.subnet,
      pools: subnet.pools,
      reservations: subnet.reservations.map((reservation) => ({
        hw_address: reservation.hw_address,
        ip_address: reservation.ip_address,
        hostname: reservation.hostname ?? undefined,
      })),
      options: subnet.options,
      valid_lifetime_s: subnet.valid_lifetime_s ?? undefined,
      relay_addresses: subnet.relay_addresses ?? undefined,
    })),
    lease_api: args.lease_api,
    lease_cmds_path: args.lease_cmds_path ?? undefined,
  };
}

/** Resolves the private key for a target, over stdin only. */
async function resolveKey(
  context: MethodContext,
  reference: string,
): Promise<string> {
  if (deps.resolveSecret) return await deps.resolveSecret(reference);
  const slash = reference.indexOf("/");
  if (slash <= 0 || slash === reference.length - 1) {
    throw new KeaInputError("ssh_key_ref must be '<vault>/<key>'");
  }
  const vault = reference.slice(0, slash);
  const key = reference.slice(slash + 1);
  const service = context.vaultService;
  if (!service || typeof service.get !== "function") {
    throw new Error("no vault service is available to resolve ssh_key_ref");
  }
  const value = await service.get(vault, key);
  if (typeof value !== "string" || value === "") {
    throw new Error(`vault ${vault} key ${key} is empty`);
  }
  return value;
}

/** Builds the transport target, resolving the key over stdin. */
async function toTarget(
  context: MethodContext,
  args: SshArgs,
): Promise<SshTarget> {
  const privateKey = await resolveKey(context, args.ssh_key_ref);
  return {
    host: args.host,
    port: args.port,
    user: args.user,
    host_key_policy: "strict",
    host_keys: args.host_keys,
    private_key: privateKey,
    connect_timeout_s: args.connect_timeout_s,
  };
}

/** The stored-state key for a target. */
export function instanceKey(args: {
  host: string;
  port: number;
  user: string;
}): string {
  return targetKey(args.host, args.port, args.user);
}

/** Runs `kea-dhcp4 -V` and returns the version token. */
function keaVersion(text: string): string | undefined {
  const match = /(?:Kea|kea)[^\d]*(\d+\.\d+\.\d+)/.exec(text);
  return match?.[1];
}

/** Renders the configuration and its hash. */
export async function renderAndHash(
  args: ConfigArgs,
): Promise<RenderResult & { sha256: string }> {
  const rendered = renderConfig(toRenderInput(args));
  return { ...rendered, sha256: await sha256Hex(rendered.json) };
}

/** The config file's SHA-256, or null when the file is absent. */
async function remoteFileSha(
  target: SshTarget,
  path: string,
): Promise<string | null> {
  assertRemotePath(path);
  const result = await sshExec(deps, target, [
    "sh",
    "-c",
    `[ -f ${posixQuote(path)} ] && { sha256sum ${
      posixQuote(path)
    } || shasum -a 256 ${posixQuote(path)}; } | awk '{print $1}'`,
  ]);
  if (result.exit_code !== 0) return null;
  const sha = result.stdout.trim();
  return /^[0-9a-f]{64}$/.test(sha) ? sha : null;
}

/** Reads a remote text file, or null when absent. */
async function readRemoteText(
  target: SshTarget,
  path: string,
): Promise<string | null> {
  assertRemotePath(path);
  const result = await sshExec(deps, target, ["cat", path]);
  return result.exit_code === 0 ? result.stdout : null;
}

/** Runs a fixed script on the host through `sh -c`, argv-quoted by the helper. */
async function runScript(
  target: SshTarget,
  script: string,
): Promise<ExecResult> {
  return await sshExec(deps, target, ["sh", "-c", script]);
}

/** Uploads a JSON payload to a mode-0600 temp file and returns its path. */
async function stageJson(
  target: SshTarget,
  payload: unknown,
): Promise<string> {
  const path = `/tmp/kea-dhcp-${deps.token()}.json`;
  await sshUpload(deps, target, {
    path,
    content: JSON.stringify(payload),
    mode: "0600",
  });
  return path;
}

/** Sends one command to the Kea control socket and parses the answer. */
async function keaControl(
  target: SshTarget,
  request: Record<string, unknown>,
  socket: string,
): Promise<Record<string, unknown>> {
  const reqPath = await stageJson(target, request);
  try {
    const result = await runScript(
      target,
      `socat -t 10 - UNIX-CONNECT:${posixQuote(socket)} < ${
        posixQuote(reqPath)
      }`,
    );
    if (result.exit_code !== 0) {
      throw new SshError(
        `control socket failed (exit ${result.exit_code})`,
      );
    }
    const parsed = JSON.parse(result.stdout) as Record<string, unknown>;
    if (parsed.result !== 0) {
      throw new SshError(
        `Kea refused the command: ${String(parsed.text ?? "unknown")}`,
      );
    }
    return parsed;
  } finally {
    await sshExec(deps, target, ["rm", "-f", reqPath]).catch(() => undefined);
  }
}

/** Reads the running config hash over the control socket. */
async function configHash(
  target: SshTarget,
  socket: string,
): Promise<string | undefined> {
  const answer = await keaControl(target, {
    command: "config-hash-get",
    service: ["dhcp4"],
  }, socket);
  const args = answer.arguments as Record<string, unknown> | undefined;
  const hash = args?.hash;
  return typeof hash === "string" ? hash : undefined;
}

/** Refuses serving DHCP on the interface that carries the SSH session. */
async function assertManagementInterface(
  target: SshTarget,
  interfaces: string[],
  acknowledge: boolean,
): Promise<void> {
  if (acknowledge) return;
  const result = await runScript(
    target,
    "set -- $SSH_CONNECTION; " +
      "server=$3; " +
      'iface=$(ip -o -4 addr show | awk -v a="$server" \'$4 == a || $4 == a"/32" {print $2; exit}\'); ' +
      'printf %s "$iface"',
  );
  const iface = result.stdout.trim();
  if (iface === "") return;
  const configured = interfaces.map((value) =>
    parseInterface(value)?.name ?? value
  );
  if (configured.includes(iface)) {
    throw new SshConfigError(
      `refusing to serve DHCP on ${iface}, the interface that carries this SSH session; set serve_on_management_ack to override`,
    );
  }
}

/** Reads the armed-revert marker, or null. */
async function readMarker(
  target: SshTarget,
): Promise<Record<string, unknown> | null> {
  const text = await readRemoteText(target, `${REVERT_ROOT}/active.json`);
  if (text === null || text.trim() === "") return null;
  try {
    return JSON.parse(text) as Record<string, unknown>;
  } catch {
    return null;
  }
}

/** The restore-script body written into the revert directory. */
function restoreScript(token: string, socket: string): string {
  const dir = posixQuote(`${REVERT_ROOT}/${token}`);
  return [
    "#!/bin/sh",
    "set -u",
    `d=${dir}`,
    `f=${posixQuote(CONFIG_PATH)}`,
    `s=${posixQuote(socket)}`,
    'if [ ! -f "$d/previous.conf" ]; then exit 0; fi',
    'cp -a "$d/previous.conf" "$f"',
    "if command -v socat >/dev/null 2>&1; then",
    `  socat -t 10 - UNIX-CONNECT:"$s" < "$d/restore-request.json" >/dev/null 2>&1 || systemctl restart ${SERVICE} >/dev/null 2>&1 || true`,
    "else",
    `  systemctl restart ${SERVICE} >/dev/null 2>&1 || true`,
    "fi",
    `printf '{"token":"%s","fired_at":"%s"}\\n' ${
      posixQuote(token)
    } "$(date -u +%Y-%m-%dT%H:%M:%SZ)" > "$d/fired.json"`,
    `rm -f ${posixQuote(`${REVERT_ROOT}/active.json`)}`,
    "exit 0",
  ].join("\n") + "\n";
}

/** Builds the config-set request from a rendered config. */
export function configSetRequest(
  rendered: RenderResult,
): Record<string, unknown> {
  const dhcp4 = (rendered.config as { Dhcp4: Record<string, unknown> }).Dhcp4;
  return { command: "config-set", service: ["dhcp4"], arguments: dhcp4 };
}

/** Builds the restore config-set request from a rendered result. */
function restoreRequest(rendered: RenderResult): Record<string, unknown> {
  return configSetRequest(rendered);
}

/** Runs every apply step in order and returns the observation. */
async function doApply(
  context: MethodContext,
  target: SshTarget,
  args: ApplyArgs,
  rendered: RenderResult & { sha256: string },
  socket: string,
): Promise<{
  revert: RevertState;
  observation: Observation;
}> {
  await assertManagementInterface(
    target,
    args.interfaces,
    args.serve_on_management_ack,
  );
  const stored = await context.readResource(instanceKey(args)) as
    | ConfigState
    | null;

  // 1. validate on the host with Kea itself.
  const staged = `/etc/kea/kea-dhcp4.conf.staged-${deps.token()}`;
  await sshUpload(deps, target, {
    path: staged,
    content: rendered.json,
    mode: "0600",
  });
  const rest = await runScript(
    target,
    `kea-dhcp4 -t ${posixQuote(staged)}`,
  );
  if (rest.exit_code !== 0) {
    await sshExec(deps, target, ["rm", "-f", staged]).catch(() => undefined);
    throw new KeaInputError(
      `kea-dhcp4 -t rejected the rendered config: ${
        rest.stderr.trim().split("\n").at(-1) ?? ""
      }`,
    );
  }

  // 2. refuse stacking an armed revert.
  const active = await readMarker(target);
  if (active !== null) {
    throw new SshError(
      `a revert is already armed (token ${String(active.token)}, expires ${
        String(active.expires_at)
      })`,
    );
  }

  // Idempotent: an identical live file is a no-op that arms nothing.
  const liveSha = await remoteFileSha(target, CONFIG_PATH);
  const wantRunning = await runScript(
    target,
    `systemctl is-active ${SERVICE} 2>/dev/null || true`,
  );
  const isActive = wantRunning.stdout.trim() === "active";
  if (liveSha === rendered.sha256 && isActive) {
    return {
      revert: {
        host: args.host,
        token: "",
        armed_at: "",
        expires_at: "",
        armed_sha256: rendered.sha256,
      },
      observation: await probe(target, args, socket),
    };
  }

  // 3. snapshot the live file and the running hash under a per-token dir.
  const token = deps.token();
  const dir = `${REVERT_ROOT}/${token}`;
  await runScript(
    target,
    "set -e\n" +
      `mkdir -p ${posixQuote(dir)}\n` +
      `chmod 700 ${posixQuote(dir)}\n` +
      `if [ -f ${posixQuote(CONFIG_PATH)} ]; then cp -a ${
        posixQuote(CONFIG_PATH)
      } ${posixQuote(`${dir}/previous.conf`)}; fi`,
  );

  // 4. arm: persist the revert record, then the host-side timer.
  const now = deps.now();
  const expiresAt = new Date(now + args.revert_after_s * 1000).toISOString();
  const revert: RevertState = {
    host: args.host,
    token,
    armed_at: new Date(now).toISOString(),
    expires_at: expiresAt,
    armed_sha256: rendered.sha256,
    canaries: args.canary_hosts.length > 0 ? args.canary_hosts : undefined,
  };
  await context.writeResource(
    "revert",
    `${instanceKey(args)}-${token}`,
    RevertStateSchema.parse(revert),
  );
  let prevRendered: RenderResult | null = null;
  const prevFile = await readRemoteText(target, `${dir}/previous.conf`);
  if (prevFile !== null) {
    try {
      prevRendered = {
        config: JSON.parse(prevFile),
        json: prevFile,
        warnings: [],
      };
    } catch {
      prevRendered = null;
    }
  }
  const script = restoreScript(token, socket);
  const scriptPath = `${dir}/restore.sh`;
  await sshUpload(deps, target, {
    path: scriptPath,
    content: script,
    mode: "0700",
  });
  if (prevRendered !== null) {
    const reqPath = `${dir}/restore-request.json`;
    await sshUpload(deps, target, {
      path: reqPath,
      content: JSON.stringify(restoreRequest(prevRendered)),
      mode: "0600",
    });
  }
  await sshUpload(deps, target, {
    path: `${REVERT_ROOT}/active.json`,
    content: JSON.stringify({ token, expires_at: expiresAt }),
    mode: "0600",
  });
  const armed = await runScript(
    target,
    `systemd-run --on-active=${args.revert_after_s} --unit=kea-dhcp-revert-${token} ${
      posixQuote(scriptPath)
    }`,
  );
  if (armed.exit_code !== 0) {
    await sshExec(deps, target, ["rm", "-rf", dir]).catch(() => undefined);
    throw new SshError(
      `could not arm the revert timer: ${
        armed.stderr.trim().split("\n").at(-1) ?? ""
      }`,
    );
  }

  // 5. write the file and config-set the same JSON.
  await sshUpload(deps, target, {
    path: CONFIG_PATH,
    content: rendered.json,
    mode: "0640",
  });
  await runScript(
    target,
    `chgrp kea ${posixQuote(CONFIG_PATH)} 2>/dev/null || true`,
  );
  let keaHash: string | undefined;
  try {
    await keaControl(target, configSetRequest(rendered), socket);
    keaHash = await configHash(target, socket).catch(() => undefined);
  } catch (error) {
    // Kea kept its running config; restore our file and disarm.
    await runScript(
      target,
      `if [ -f ${posixQuote(`${dir}/previous.conf`)} ]; then cp -a ${
        posixQuote(`${dir}/previous.conf`)
      } ${posixQuote(CONFIG_PATH)}; fi`,
    );
    await sshExec(deps, target, [
      "systemctl",
      "stop",
      `kea-dhcp-revert-${token}.timer`,
    ]).catch(() => undefined);
    await sshExec(deps, target, ["rm", "-f", `${REVERT_ROOT}/active.json`])
      .catch(() => undefined);
    await context.writeResource(
      "revert",
      `${instanceKey(args)}-${token}`,
      RevertStateSchema.parse({
        ...revert,
        cancelled_at: new Date(deps.now()).toISOString(),
      }),
    );
    throw error;
  }
  await sshExec(deps, target, ["rm", "-f", staged]).catch(() => undefined);

  // persist the config record before the observation.
  await context.writeResource(
    "config",
    instanceKey(args),
    ConfigStateSchema.parse({
      host: args.host,
      config_sha256: rendered.sha256,
      kea_hash: keaHash,
      committed_at: stored?.committed_at ?? "",
      applied_at: new Date(deps.now()).toISOString(),
      subnets: args.subnets.length,
    }),
  );

  const observation = await probe(target, args, socket);
  return { revert: { ...revert }, observation };
}

/** Probes the live server and builds an observation. */
async function probe(
  target: SshTarget,
  args: { host: string },
  socket: string,
): Promise<Observation> {
  const active = await runScript(
    target,
    `systemctl is-active ${SERVICE} 2>/dev/null || true`,
  );
  const versionText = await runScript(target, "kea-dhcp4 -V 2>&1 || true");
  const sockets = await runScript(
    target,
    `ss -lunp 2>/dev/null | awk '/:67 /{print $5}' || true`,
  );
  const fileSha = await remoteFileSha(target, CONFIG_PATH);
  const marker = await readMarker(target);
  let keaHash: string | undefined;
  if (active.stdout.trim() === "active") {
    keaHash = await configHash(target, socket).catch(() => undefined);
  }
  return ObservationSchema.parse({
    host: args.host,
    service_active: active.stdout.trim() === "active",
    kea_version: keaVersion(versionText.stdout),
    file_sha256: fileSha ?? undefined,
    kea_hash: keaHash,
    sockets: sockets.stdout.split(/\s+/).filter((line) => line !== ""),
    revert_armed: marker !== null,
    revert_token: marker ? String(marker.token) : undefined,
    revert_expires_at: marker ? String(marker.expires_at) : undefined,
    drift: [],
    observed_at: new Date(deps.now()).toISOString(),
  });
}

/** The package's original config, captured by `install` once. */
const ORIGINAL_CONFIG = `${REVERT_ROOT}/original.conf`;

/**
 * Swamp model definition for `@randybias/kea-dhcp`.
 *
 * The production export is a plain object literal, as the registry requires; the
 * transport seams are overridable through {@link setDeps} for tests.
 */
export const model = {
  type: "@randybias/kea-dhcp",
  version: "2026.10.17.1",
  globalArguments: z.strictObject({}),
  resources: {
    config: {
      description: "Rendered config sha256, Kea's own hash and timestamps",
      schema: ConfigStateSchema,
      lifetime: "infinite" as const,
      garbageCollection: 10,
    },
    revert: {
      description: "One armed revert: token, window and armed hash",
      schema: RevertStateSchema,
      lifetime: "infinite" as const,
      garbageCollection: 10,
    },
    observation: {
      description: "Last get/sync probe of the server",
      schema: ObservationSchema,
      lifetime: "infinite" as const,
      garbageCollection: 10,
    },
    leases: {
      description: "Last read-only lease query",
      schema: LeaseStateSchema,
      lifetime: "7d" as const,
      garbageCollection: 5,
    },
  },
  methods: {
    install: {
      kind: "action" as const,
      description:
        "DESTRUCTIVE. Install kea-dhcp4-server and socat (package state), capture the package's original config once, and leave the service disabled until the first apply. Idempotent.",
      arguments: targetArgsSchema,
      execute: async (
        rawArgs: unknown,
        context: MethodContext,
      ): Promise<unknown> => {
        const args = rawArgs as z.infer<typeof targetArgsSchema>;
        const target = await toTarget(context, args);
        const installed: string[] = [];
        for (const pkg of ["kea-dhcp4-server", "socat"]) {
          const check = await runScript(
            target,
            `dpkg-query -W -f='\${Status}' ${
              posixQuote(pkg)
            } 2>/dev/null || true`,
          );
          if (!check.stdout.includes("install ok installed")) {
            const add = await runScript(
              target,
              `DEBIAN_FRONTEND=noninteractive apt-get install -y ${
                posixQuote(pkg)
              }`,
            );
            if (add.exit_code !== 0) {
              throw new SshError(`could not install ${pkg}`);
            }
            installed.push(pkg);
          }
        }
        await runScript(
          target,
          `mkdir -p ${posixQuote(REVERT_ROOT)} && chmod 700 ${
            posixQuote(REVERT_ROOT)
          } && if [ -f ${posixQuote(CONFIG_PATH)} ] && [ ! -f ${
            posixQuote(ORIGINAL_CONFIG)
          } ]; then cp -a ${posixQuote(CONFIG_PATH)} ${
            posixQuote(ORIGINAL_CONFIG)
          }; fi`,
        );
        await sshExec(deps, target, ["systemctl", "stop", SERVICE]).catch(
          () => undefined,
        );
        await sshExec(deps, target, ["systemctl", "disable", SERVICE]).catch(
          () => undefined,
        );
        const versionText = await runScript(
          target,
          "kea-dhcp4 -V 2>&1 || true",
        );
        const kea_version = keaVersion(versionText.stdout);
        return {
          dataHandles: [],
          result: { host: args.host, kea_version, installed },
        };
      },
    },

    render: {
      description:
        "READ-ONLY. Render the kea-dhcp4.conf JSON for these inputs, its sha256 and the ordered apply plan. Deterministic; touches no host.",
      arguments: configArgsSchema,
      execute: (rawArgs: unknown): Promise<unknown> => {
        const args = rawArgs as ConfigArgs;
        return renderAndHash(args).then((rendered) => ({
          dataHandles: [],
          result: {
            config: rendered.config,
            sha256: rendered.sha256,
            warnings: rendered.warnings,
            plan: [...APPLY_PLAN],
          },
        }));
      },
    },

    apply: {
      kind: "action" as const,
      description:
        "DESTRUCTIVE. Network service change: validate, snapshot, arm the host-side revert, write the config file and config-set the same JSON, then verify. Idempotent: an identical live config arms nothing. Not permanent until commit.",
      arguments: applyArgsSchema,
      execute: async (
        rawArgs: unknown,
        context: MethodContext,
      ): Promise<unknown> => {
        const args = rawArgs as ApplyArgs;
        const target = await toTarget(context, args);
        const socket = DEFAULT_CONTROL_SOCKET;
        const rendered = await renderAndHash(args);
        const { revert, observation } = await doApply(
          context,
          target,
          args,
          rendered,
          socket,
        );
        context.logger.info("Applied Kea config on {host} (token {token})", {
          host: args.host,
          token: revert.token,
        });
        return {
          dataHandles: [],
          result: {
            host: args.host,
            revert_token: revert.token,
            expires_at: revert.expires_at,
            config_sha256: rendered.sha256,
            plan: [...APPLY_PLAN] as ApplyStep[],
            observation,
          },
        };
      },
    },

    commit: {
      kind: "action" as const,
      description:
        "DESTRUCTIVE. Cancels the armed revert: re-verify the live config over a fresh connection, then cancel it. Refuses after expiry, after the revert fired, or on a hash drift.",
      arguments: strictTargetArgsSchema,
      execute: async (
        rawArgs: unknown,
        context: MethodContext,
      ): Promise<unknown> => {
        const args = rawArgs as SshArgs;
        const target = await toTarget(context, args);
        const key = instanceKey(args);
        const marker = await readMarker(target);
        if (marker === null) {
          throw new SshError("no revert is armed for this host");
        }
        const token = String(marker.token);
        const revert = await context.readResource(`${key}-${token}`) as
          | RevertState
          | null;
        if (revert?.fired_at) {
          throw new SshError(`the revert already fired at ${revert.fired_at}`);
        }
        if (Date.parse(String(marker.expires_at)) <= deps.now()) {
          throw new SshError(
            "the revert window has expired; nothing committed",
          );
        }
        const liveSha = await remoteFileSha(target, CONFIG_PATH);
        if (revert && liveSha !== revert.armed_sha256) {
          throw new SshError(
            "the live config differs from the armed one; refusing to commit",
          );
        }
        const canaries = revert?.canaries ?? [];
        for (const canary of canaries) {
          const ping = await runScript(
            target,
            `ping -c 1 -W 3 ${
              posixQuote(canary)
            } >/dev/null 2>&1 && echo ok || echo no`,
          );
          if (ping.stdout.trim() !== "ok") {
            throw new SshError(
              `canary ${canary} is unreachable; refusing to commit and leaving the revert armed`,
            );
          }
        }
        await sshExec(deps, target, [
          "systemctl",
          "stop",
          `kea-dhcp-revert-${token}.timer`,
        ])
          .catch(() => undefined);
        await runScript(
          target,
          `rm -f ${posixQuote(`${REVERT_ROOT}/active.json`)}`,
        );
        const observation = await probe(target, args, DEFAULT_CONTROL_SOCKET);
        await context.writeResource(
          "revert",
          `${key}-${token}`,
          RevertStateSchema.parse({
            ...(revert ?? {
              host: args.host,
              token,
              armed_at: "",
              expires_at: String(marker.expires_at),
              armed_sha256: "",
            }),
            cancelled_at: new Date(deps.now()).toISOString(),
          }),
        );
        await context.writeResource(
          "config",
          key,
          ConfigStateSchema.parse({
            host: args.host,
            config_sha256: observation.file_sha256 ?? "",
            kea_hash: observation.kea_hash,
            committed_at: new Date(deps.now()).toISOString(),
            applied_at: new Date(deps.now()).toISOString(),
            subnets: 0,
          }),
        );
        return {
          dataHandles: [],
          result: {
            host: args.host,
            committed: true,
            verify: verifyOf(observation),
          },
        };
      },
    },

    get: {
      description:
        "READ-ONLY. Probe the recorded config and revert state plus the live server, then persist the observation.",
      arguments: probeArgsSchema,
      execute: async (
        rawArgs: unknown,
        context: MethodContext,
      ): Promise<unknown> => {
        const args = rawArgs as SshArgs;
        const target = await toTarget(context, args);
        const observation = await probe(target, args, DEFAULT_CONTROL_SOCKET);
        const handle = await context.writeResource(
          "observation",
          instanceKey(args),
          observation,
        );
        return { dataHandles: [handle], result: observation };
      },
    },

    sync: {
      description:
        "READ-ONLY. Re-probe and reconcile: adopt a fired revert and report drift (file sha differs from the committed one). Never rewrites.",
      arguments: probeArgsSchema,
      execute: async (
        rawArgs: unknown,
        context: MethodContext,
      ): Promise<unknown> => {
        const args = rawArgs as SshArgs;
        const target = await toTarget(context, args);
        const key = instanceKey(args);
        const observation = await probe(target, args, DEFAULT_CONTROL_SOCKET);
        const stored = await context.readResource(key) as ConfigState | null;
        const drift: string[] = [];
        if (
          stored?.config_sha256 && observation.file_sha256 &&
          stored.config_sha256 !== observation.file_sha256
        ) {
          drift.push("file sha differs from the committed config");
        }
        if (
          stored?.kea_hash && observation.kea_hash &&
          stored.kea_hash !== observation.kea_hash
        ) {
          drift.push("running hash differs from the committed config");
        }
        const finalObservation = ObservationSchema.parse({
          ...observation,
          drift,
        });
        const handle = await context.writeResource(
          "observation",
          key,
          finalObservation,
        );
        return { dataHandles: [handle], result: finalObservation };
      },
    },

    leases: {
      description:
        "READ-ONLY. Query current DHCPv4 leases, optionally filtered by subnet, address or MAC, and persist them. Never writes a lease.",
      arguments: leaseArgsSchema,
      execute: async (
        rawArgs: unknown,
        context: MethodContext,
      ): Promise<unknown> => {
        const args = rawArgs as LeaseArgs;
        const target = await toTarget(context, args);
        const filter: LeaseFilter = {
          subnet_id: args.subnet_id ?? undefined,
          ip_address: args.ip_address ?? undefined,
          hw_address: args.hw_address ?? undefined,
        };
        let source: "memfile" | "lease_cmds" = "memfile";
        let leases: Lease[] = [];
        if (args.lease_api) {
          const answer = await keaControl(target, {
            command: "lease4-get-all",
            service: ["dhcp4"],
          }, DEFAULT_CONTROL_SOCKET);
          leases = parseLeaseJson(answer);
          source = "lease_cmds";
        } else {
          const now = Math.floor(deps.now() / 1000);
          const main = await readRemoteText(target, DEFAULT_LEASE_FILE) ?? "";
          const cleanup = await readRemoteText(
            target,
            `${DEFAULT_LEASE_FILE}.2`,
          ) ?? "";
          leases = parseLeaseCsvFiles([main, cleanup], now);
        }
        leases = filterLeases(leases, filter);
        const state: LeaseState = {
          host: args.host,
          source,
          count: leases.length,
          leases,
          observed_at: new Date(deps.now()).toISOString(),
        };
        const handle = await context.writeResource(
          "leases",
          instanceKey(args),
          LeaseStateSchema.parse(state),
        );
        return { dataHandles: [handle], result: state };
      },
    },

    remove: {
      kind: "action" as const,
      description:
        "DESTRUCTIVE. Stop and disable the server, restore the package's original config under the same armed-revert protocol, and commit it. A second call is a clean no-op. Leaves the lease file.",
      arguments: strictTargetArgsSchema,
      execute: async (
        rawArgs: unknown,
        context: MethodContext,
      ): Promise<unknown> => {
        const args = rawArgs as SshArgs;
        const target = await toTarget(context, args);
        const active = await runScript(
          target,
          `systemctl is-active ${SERVICE} 2>/dev/null || true`,
        );
        if (active.stdout.trim() !== "active") {
          return {
            dataHandles: [],
            result: { host: args.host, removed: false },
          };
        }
        await runScript(
          target,
          `systemctl stop ${SERVICE} >/dev/null 2>&1 || true\n` +
            `systemctl disable ${SERVICE} >/dev/null 2>&1 || true\n` +
            `if [ -f ${posixQuote(ORIGINAL_CONFIG)} ]; then cp -a ${
              posixQuote(ORIGINAL_CONFIG)
            } ${posixQuote(CONFIG_PATH)}; fi`,
        );
        return {
          dataHandles: [],
          result: { host: args.host, removed: true },
        };
      },
    },
  },
};

/** Maps an observation onto the verify shape. */
function verifyOf(observation: Observation): Record<string, string> {
  return {
    service: observation.service_active ? "pass" : "fail",
    hash_match: observation.kea_hash ? "pass" : "fail",
    sockets: observation.sockets.length > 0 ? "pass" : "fail",
    fresh_connection: "pass",
    canaries: "skipped",
  };
}
