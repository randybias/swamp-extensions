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
  isHookLibraryPath,
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
  user: z.string().regex(USER_RE).describe(
    "Remote user; must be root (every step is privileged and no sudo is used).",
  ),
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
  lease_cmds_path: z.string().max(4096).refine(
    isHookLibraryPath,
    "must be an absolute libdhcp_*.so path under a hooks directory",
  ).nullish().describe(
    "Absolute path of the packaged lease_cmds hook library.",
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
  intent: z.enum(["apply", "remove"]).optional(),
  prior_enabled: z.boolean().optional(),
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

/** The host script that prints the interface carrying the SSH session. */
export function managementScript(): string {
  return [
    "set -- $SSH_CONNECTION",
    "peer=$1",
    'if [ -z "$peer" ]; then printf %s UNKNOWN; exit 0; fi',
    'iface=$(ip -o route get "$peer" 2>/dev/null | awk \'{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}\')',
    'if [ -z "$iface" ]; then',
    '  iface=$(ip -o -4 addr show 2>/dev/null | awk -v a="$peer" \'{split($4,x,"/"); if(x[1]==a){print $2; exit}}\')',
    "fi",
    'printf %s "$iface"',
  ].join("\n");
}

/**
 * Refuses serving DHCP on the interface that carries the SSH session.
 *
 * The interface is resolved by asking the route table which device reaches the
 * SSH peer (so a NAT'd address still resolves), falling back to matching the
 * peer address against the local addresses with the prefix stripped. When it
 * cannot be determined the method refuses unless the caller acknowledged.
 */
async function assertManagementInterface(
  target: SshTarget,
  interfaces: string[],
  acknowledge: boolean,
): Promise<void> {
  if (acknowledge) return;
  const result = await runScript(target, managementScript());
  const iface = result.stdout.trim();
  if (iface === "" || iface === "UNKNOWN") {
    throw new SshConfigError(
      "could not determine the interface that carries this SSH session; refusing to apply unless serve_on_management_ack is set",
    );
  }
  const configured = interfaces.map((value) =>
    parseInterface(value)?.name ?? value
  );
  if (configured.includes(iface)) {
    throw new SshConfigError(
      `refusing to serve DHCP on ${iface}, the interface that carries this SSH session; set serve_on_management_ack to override`,
    );
  }
}

/** The transient unit name for an armed revert timer. */
function timerName(token: string): string {
  return `kea-dhcp-revert-${token}`;
}

/** True when the Kea service is active. */
async function serviceActive(target: SshTarget): Promise<boolean> {
  const result = await runScript(
    target,
    `systemctl is-active ${SERVICE} 2>/dev/null || true`,
  );
  return result.stdout.trim() === "active";
}

/** True when the Kea service is enabled at boot. */
async function serviceEnabled(target: SshTarget): Promise<boolean> {
  const result = await runScript(
    target,
    `systemctl is-enabled ${SERVICE} 2>/dev/null || true`,
  );
  return result.stdout.trim() === "enabled";
}

/** Reads the `result` value from a fired.json body, or null. */
function firedResult(text: string): string | null {
  try {
    const body = JSON.parse(text) as { result?: unknown };
    return typeof body.result === "string" ? body.result : null;
  } catch {
    return null;
  }
}

/**
 * Resolves the group that must own the config file so the service can read it.
 * The unit's `User=` is authoritative; `/var/lib/kea` is the fallback.
 */
async function resolveServiceGroup(target: SshTarget): Promise<string> {
  const result = await runScript(target, groupScript());
  const group = result.stdout.trim();
  if (!/^[A-Za-z0-9_.-]+$/.test(group)) {
    throw new SshError(
      "could not resolve the Kea service group; check `systemctl show -p User kea-dhcp4-server`",
    );
  }
  return group;
}

/** The host script that validates a lease_cmds hook library path. */
export function hookLibraryScript(path: string): string {
  return [
    `p=${posixQuote(path)}`,
    '[ -f "$p" ] || { printf %s missing; exit 0; }',
    '[ -L "$p" ] && { printf %s symlink; exit 0; }',
    'owner=$(stat -c %U "$p" 2>/dev/null || true); [ "$owner" = root ] || { printf %s "owner=$owner"; exit 0; }',
    'w=$(find "$p" -maxdepth 0 -perm /022 2>/dev/null || true); [ -z "$w" ] || { printf %s writable; exit 0; }',
    "libs=$(dpkg -L kea-common kea-dhcp4-server 2>/dev/null | grep -m1 '/hooks/.*\\.so$' || true)",
    'if [ -z "$libs" ]; then libs=$(find /usr/lib -maxdepth 6 -path "*/kea/hooks/libdhcp_*.so" 2>/dev/null | head -n1); fi',
    'if [ -z "$libs" ]; then printf %s no-hooks-dir; exit 0; fi',
    'hooks=$(dirname "$libs")',
    'case "$(readlink -f "$p")" in "$hooks"/*) ;; *) printf %s "outside=$hooks"; exit 0;; esac',
    "printf %s ok",
  ].join("\n");
}

/** The host script that prints the group the Kea service runs as. */
export function groupScript(): string {
  return [
    `u=$(systemctl show -p User --value ${SERVICE} 2>/dev/null || true)`,
    'if [ -z "$u" ]; then u=root; fi',
    'if [ "$u" = root ]; then g=root; else g=$(id -gn "$u" 2>/dev/null || true); fi',
    'if [ -z "$g" ]; then g=$(stat -c %G /var/lib/kea 2>/dev/null || true); fi',
    'printf %s "$g"',
  ].join("\n");
}

/**
 * Refuses a lease_cmds hook unless it is the packaged library in the host's
 * hooks directory, owned by root and not writable by group or others. Loading a
 * hook runs its code as root during `kea-dhcp4 -t`, so an arbitrary path is a
 * privilege-escalation vector.
 */
async function assertHookLibrary(
  target: SshTarget,
  path: string,
): Promise<void> {
  assertRemotePath(path);
  const result = await runScript(target, hookLibraryScript(path));
  if (result.stdout.trim() !== "ok") {
    throw new KeaInputError(
      `lease_cmds_path rejected (${result.stdout.trim()}); it must be the packaged library in the host hooks directory`,
    );
  }
}

/** The claim script: refuse-active and snapshot atomically under flock. */
export function claimScript(dir: string, activeJson: string): string {
  return [
    "set -e",
    "lk=/run/kea-dhcp-revert.lock",
    'exec 9>"$lk"',
    "flock -w 30 9 || exit 8",
    `if [ -f ${posixQuote(`${REVERT_ROOT}/active.json`)} ]; then exit 9; fi`,
    `mkdir -p ${posixQuote(dir)}`,
    `chmod 700 ${posixQuote(dir)}`,
    `if [ -f ${posixQuote(CONFIG_PATH)} ]; then cp -a ${
      posixQuote(CONFIG_PATH)
    } ${posixQuote(`${dir}/previous.conf`)}; fi`,
    `en=$(systemctl is-enabled ${SERVICE} 2>/dev/null || true)`,
    `printf '{"enabled":"%s"}\\n' "$en" > ${posixQuote(`${dir}/prior.json`)}`,
    `printf '%s\\n' ${posixQuote(activeJson)} > ${
      posixQuote(`${REVERT_ROOT}/active.json`)
    }`,
  ].join("\n");
}

/** Reads the `fired_at` value from a fired.json body, or null. */
function parseFiredAt(text: string): string | null {
  try {
    const body = JSON.parse(text) as { fired_at?: unknown };
    return typeof body.fired_at === "string" ? body.fired_at : null;
  } catch {
    return null;
  }
}

/** The fired markers under the revert root, as {token, fired_at, result}. */
async function readFiredMarkers(
  target: SshTarget,
): Promise<{ token: string; fired_at: string; result: string }[]> {
  const result = await runScript(
    target,
    `for p in ${REVERT_ROOT}/*/fired.json; do [ -f "$p" ] && cat "$p"; done 2>/dev/null || true`,
  );
  const markers: { token: string; fired_at: string; result: string }[] = [];
  for (const line of result.stdout.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (trimmed === "") continue;
    try {
      const body = JSON.parse(trimmed) as {
        token?: unknown;
        fired_at?: unknown;
        result?: unknown;
      };
      if (typeof body.token === "string" && typeof body.fired_at === "string") {
        markers.push({
          token: body.token,
          fired_at: body.fired_at,
          result: typeof body.result === "string" ? body.result : "unknown",
        });
      }
    } catch {
      // Ignore a malformed marker; get reports the raw state.
    }
  }
  return markers;
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

/**
 * The restore-script body written into the revert directory.
 *
 * It restores the previous file, returns the service to its prior running and
 * enabled state, then decides pass/fail from the post-state (file sha, service
 * state, enabled state and a socket answer) and records it in fired.json. It
 * takes the same flock as a commit and exits without reverting if a committed
 * marker exists, so a commit and a revert can never both act. It always clears
 * active.json; a failed restore leaves a recovery note beside it.
 */
export function restoreScript(
  token: string,
  socket: string,
  priorActive: boolean,
  priorEnabled: boolean,
): string {
  const dir = posixQuote(`${REVERT_ROOT}/${token}`);
  return [
    "#!/bin/sh",
    "set -u",
    `d=${dir}`,
    `f=${posixQuote(CONFIG_PATH)}`,
    `a=${posixQuote(`${REVERT_ROOT}/active.json`)}`,
    `s=${posixQuote(socket)}`,
    `svc=${SERVICE}`,
    "result=pass",
    'detail=""',
    "finish() {",
    `  printf '{"token":"%s","fired_at":"%s","result":"%s","detail":"%s"}\\n' ${
      posixQuote(token)
    } "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$result" "$detail" > "$d/fired.json"`,
    '  if [ "$result" != pass ]; then',
    '    printf \'Restore failed (%s). The previous config is %s/previous.conf; recovery: inspect %s, restore previous.conf by hand if needed, then run systemctl restart %s.\\n\' "$detail" "$d" "$f" "$svc" > "$d/recovery.txt"',
    "  fi",
    '  rm -f "$a"',
    "  exit 0",
    "}",
    "exec 9>/run/kea-dhcp-revert.lock",
    "if ! flock -w 30 9; then result=fail; detail=lock; finish; fi",
    'if [ -f "$d/committed" ] || [ ! -f "$a" ]; then exit 0; fi',
    'if [ -f "$d/previous.conf" ]; then',
    '  cp -a "$d/previous.conf" "$f" 2>/dev/null || { result=fail; detail="$detail restore-copy"; }',
    "else",
    '  rm -f "$f" 2>/dev/null || { result=fail; detail="$detail remove-config"; }',
    "fi",
    'if [ -f "$d/previous.conf" ]; then',
    `  want=$(sha256sum "$d/previous.conf" 2>/dev/null | awk '{print $1}')`,
    `  got=$(sha256sum "$f" 2>/dev/null | awk '{print $1}')`,
    '  [ "$want" = "$got" ] || { result=fail; detail="$detail file-sha"; }',
    "fi",
    `if [ ${priorActive ? "1" : "0"} = 1 ]; then`,
    '  if command -v socat >/dev/null 2>&1 && [ -f "$d/restore-request.json" ]; then',
    '    ans=$(socat -t 10 - UNIX-CONNECT:"$s" < "$d/restore-request.json" 2>/dev/null || true)',
    `    printf %s "$ans" | grep -Eq '"result": *0' || systemctl restart "$svc" >/dev/null 2>&1 || true`,
    "  else",
    '    systemctl restart "$svc" >/dev/null 2>&1 || true',
    "  fi",
    '  systemctl is-active --quiet "$svc" || { result=fail; detail="$detail service-inactive"; }',
    '  if [ "$result" = pass ] && [ -f "$d/hash-request.json" ] && command -v socat >/dev/null 2>&1; then',
    '    ans=$(socat -t 10 - UNIX-CONNECT:"$s" < "$d/hash-request.json" 2>/dev/null || true)',
    `    printf %s "$ans" | grep -Eq '"result": *0' || { result=fail; detail="$detail socket-no-answer"; }`,
    "  fi",
    "else",
    '  systemctl stop "$svc" >/dev/null 2>&1 || true',
    '  systemctl is-active --quiet "$svc" && { result=fail; detail="$detail service-still-active"; }',
    "fi",
    `if [ ${priorEnabled ? "1" : "0"} = 1 ]; then`,
    '  systemctl enable "$svc" >/dev/null 2>&1 || true',
    "else",
    '  systemctl disable "$svc" >/dev/null 2>&1 || true',
    "fi",
    'cur=$(systemctl is-enabled "$svc" 2>/dev/null || true)',
    `if [ ${priorEnabled ? "1" : "0"} = 1 ]; then`,
    '  [ "$cur" = enabled ] || { result=fail; detail="$detail enable-state"; }',
    "else",
    '  [ "$cur" = disabled ] || { result=fail; detail="$detail disable-state"; }',
    "fi",
    "finish",
  ].join("\n") + "\n";
}

/**
 * Builds the config-set request from a rendered config. Kea expects the whole
 * top-level object (`{"Dhcp4": {...}}`), not the inner `Dhcp4` body; sending
 * the body answers `Missing mandatory 'Dhcp4' parameter.`
 */
export function configSetRequest(
  rendered: RenderResult,
): Record<string, unknown> {
  return {
    command: "config-set",
    service: ["dhcp4"],
    arguments: rendered.config,
  };
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
  if (args.lease_api && args.lease_cmds_path) {
    await assertHookLibrary(target, args.lease_cmds_path);
  }
  const stored = await context.readResource(instanceKey(args)) as
    | ConfigState
    | null;

  // 1. validate on the host with Kea itself.
  const staged = `/etc/kea/kea-dhcp4.conf.staged-${deps.token()}`;
  let stagedMoved = false;
  try {
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
      throw new KeaInputError(
        `kea-dhcp4 -t rejected the rendered config: ${
          rest.stderr.trim().split("\n").at(-1) ?? ""
        }`,
      );
    }

    // Idempotent: an identical live file is a no-op that arms nothing.
    const liveSha = await remoteFileSha(target, CONFIG_PATH);
    const isActive = await serviceActive(target);
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

    // 2. claim the revert (refuse-active + snapshot) atomically.
    const token = deps.token();
    const dir = `${REVERT_ROOT}/${token}`;
    const now = deps.now();
    const expiresAt = new Date(now + args.revert_after_s * 1000).toISOString();
    const activeJson = JSON.stringify({ token, expires_at: expiresAt });
    const claim = await runScript(target, claimScript(dir, activeJson));
    if (claim.exit_code === 9) {
      const active = await readMarker(target);
      throw new SshError(
        `a revert is already armed (token ${String(active?.token)}, expires ${
          String(active?.expires_at)
        })`,
      );
    }
    if (claim.exit_code !== 0) {
      throw new SshError(
        `could not claim the revert: ${
          claim.stderr.trim().split("\n").at(-1) ?? ""
        }`,
      );
    }
    const priorEnabled = await serviceEnabled(target);
    const revert: RevertState = {
      host: args.host,
      token,
      armed_at: new Date(now).toISOString(),
      expires_at: expiresAt,
      armed_sha256: rendered.sha256,
      canaries: args.canary_hosts.length > 0 ? args.canary_hosts : undefined,
      intent: "apply",
      prior_enabled: priorEnabled,
    };
    await context.writeResource(
      "revert",
      `${instanceKey(args)}-${token}`,
      RevertStateSchema.parse(revert),
    );

    // 3. arm: upload the restore assets, then the host-side timer.
    const scriptPath = `${dir}/restore.sh`;
    let prevRendered: RenderResult | null = null;
    try {
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
      await sshUpload(deps, target, {
        path: scriptPath,
        content: restoreScript(token, socket, isActive, priorEnabled),
        mode: "0700",
      });
      if (prevRendered !== null) {
        await sshUpload(deps, target, {
          path: `${dir}/restore-request.json`,
          content: JSON.stringify(configSetRequest(prevRendered)),
          mode: "0600",
        });
      }
      await sshUpload(deps, target, {
        path: `${dir}/hash-request.json`,
        content: JSON.stringify({
          command: "config-hash-get",
          service: ["dhcp4"],
        }),
        mode: "0600",
      });
    } catch (error) {
      await abortClaim(context, target, args, dir, token, revert);
      throw error;
    }
    const armed = await runScript(
      target,
      `systemd-run --on-active=${args.revert_after_s} --unit=${
        timerName(token)
      } ${posixQuote(scriptPath)}`,
    );
    if (armed.exit_code !== 0) {
      await abortClaim(context, target, args, dir, token, revert);
      throw new SshError(
        `could not arm the revert timer: ${
          armed.stderr.trim().split("\n").at(-1) ?? ""
        }`,
      );
    }

    // 4. install the file with the service group, atomically.
    const group = await resolveServiceGroup(target);
    const install = await runScript(
      target,
      installFileScript(staged, group),
    );
    if (install.exit_code !== 0) {
      await disarmAndRestore(context, target, args, dir, token, revert);
      throw new SshError(
        `could not install the config file: ${
          install.stderr.trim().split("\n").at(-1) ?? ""
        }`,
      );
    }
    stagedMoved = true;

    // 5. push the same JSON: config-set when running, start when not.
    let keaHash: string | undefined;
    try {
      if (isActive) {
        await keaControl(target, configSetRequest(rendered), socket);
      } else {
        const start = await runScript(target, `systemctl start ${SERVICE}`);
        if (start.exit_code !== 0) {
          throw new SshError(
            `could not start ${SERVICE}: ${
              start.stderr.trim().split("\n").at(-1) ?? ""
            }`,
          );
        }
      }
      keaHash = await waitForHash(target, socket);
    } catch (error) {
      await disarmAndRestore(context, target, args, dir, token, revert);
      throw error;
    }

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
  } finally {
    if (!stagedMoved) {
      await sshExec(deps, target, ["rm", "-f", staged]).catch(() => undefined);
    }
  }
}

/** The commit critical section, serialized with the revert timer. */
export function commitScript(
  dir: string,
  token: string,
  armedSha: string,
): string {
  const timer = timerName(token);
  return [
    "set -u",
    "lk=/run/kea-dhcp-revert.lock",
    'exec 9>"$lk"',
    "flock -w 30 9 || { printf %s lock-failed; exit 0; }",
    `if [ -f ${
      posixQuote(`${dir}/fired.json`)
    } ]; then printf %s fired; exit 0; fi`,
    `systemctl stop ${timer}.timer >/dev/null 2>&1 || true`,
    `if [ -f ${
      posixQuote(`${dir}/fired.json`)
    } ]; then printf %s fired; exit 0; fi`,
    `if systemctl is-active --quiet ${timer}.service; then printf %s service-active; exit 0; fi`,
    `if systemctl is-active --quiet ${timer}.timer; then printf %s timer-active; exit 0; fi`,
    `got=$(sha256sum ${
      posixQuote(CONFIG_PATH)
    } 2>/dev/null | awk '{print $1}')`,
    `if [ "$got" != ${
      posixQuote(armedSha)
    } ]; then printf %s drifted; exit 0; fi`,
    `printf committed > ${posixQuote(`${dir}/committed`)}`,
    `rm -f ${posixQuote(`${REVERT_ROOT}/active.json`)}`,
    "printf %s committed",
  ].join("\n");
}

/** Removes the claim's marker and records the revert as cancelled. */
async function abortClaim(
  context: MethodContext,
  target: SshTarget,
  args: { host: string; port: number; user: string },
  dir: string,
  token: string,
  revert: RevertState,
): Promise<void> {
  await sshExec(deps, target, ["rm", "-rf", dir]).catch(() => undefined);
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
}

/**
 * Undoes an uncommitted apply/remove after a failure, using the same
 * restore.sh the timer would run. It only disarms when the restore judged the
 * post-state a pass; otherwise the timer stays armed and the recovery note is
 * surfaced.
 */
async function disarmAndRestore(
  context: MethodContext,
  target: SshTarget,
  args: { host: string; port: number; user: string },
  dir: string,
  token: string,
  revert: RevertState,
): Promise<void> {
  await runScript(target, `sh ${posixQuote(`${dir}/restore.sh`)}`);
  const fired = await readRemoteText(target, `${dir}/fired.json`);
  const result = fired !== null ? firedResult(fired) : null;
  if (result !== "pass") {
    const recovery = await readRemoteText(target, `${dir}/recovery.txt`);
    throw new SshError(
      `the revert restore did not pass (${
        result ?? "no marker"
      }); the timer is left armed; recovery: ${
        recovery?.trim() ?? `${dir}/recovery.txt`
      }`,
    );
  }
  await sshExec(deps, target, [
    "systemctl",
    "stop",
    `${timerName(token)}.timer`,
  ])
    .catch(() => undefined);
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
}

/** The host script that sets the service group and atomically installs a file. */
export function installFileScript(staged: string, group: string): string {
  return [
    "set -e",
    `chgrp ${posixQuote(group)} ${posixQuote(staged)}`,
    `chmod 0640 ${posixQuote(staged)}`,
    `mv -T ${posixQuote(staged)} ${posixQuote(CONFIG_PATH)}`,
  ].join("\n");
}

/** Polls the control socket until it answers a config hash. */
async function waitForHash(
  target: SshTarget,
  socket: string,
): Promise<string | undefined> {
  for (let i = 0; i < 10; i++) {
    const hash = await configHash(target, socket).catch(() => undefined);
    if (hash !== undefined) return hash;
    await deps.sleep(500);
  }
  return undefined;
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
        "DESTRUCTIVE. Cancels the armed revert: gate on a passing verify, then take the revert lock, stop the host timer and clear the marker. Refuses when the revert already fired or its service started, the timer cannot be stopped, the revert record is missing, the live config drifted, or any verify check fails.",
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
        const dir = `${REVERT_ROOT}/${token}`;
        const revert = await context.readResource(`${key}-${token}`) as
          | RevertState
          | null;
        if (revert === null) {
          throw new SshError(
            "the revert record is missing; refusing to commit",
          );
        }
        if (revert.cancelled_at) {
          throw new SshError("this revert was already cancelled or committed");
        }
        const firedNow = await readRemoteText(target, `${dir}/fired.json`);
        if (firedNow !== null) {
          const firedAt = parseFiredAt(firedNow) ??
            new Date(deps.now()).toISOString();
          await context.writeResource(
            "revert",
            `${key}-${token}`,
            RevertStateSchema.parse({ ...revert, fired_at: firedAt }),
          );
          throw new SshError(`the revert already fired at ${firedAt}`);
        }
        const liveSha = await remoteFileSha(target, CONFIG_PATH);
        if (liveSha !== revert.armed_sha256) {
          throw new SshError(
            "the live config differs from the armed one; refusing to commit",
          );
        }

        const removal = revert.intent === "remove";
        const storedConfig = await context.readResource(key) as
          | ConfigState
          | null;

        // Require the running config to match and the service to be live, and
        // enable it, before the commit is allowed to proceed.
        let runningHash: string | undefined;
        if (!removal) {
          if (!(await serviceActive(target))) {
            throw new SshError(
              "the service is not active; refusing to commit",
            );
          }
          const recorded = storedConfig?.kea_hash;
          if (!recorded) {
            throw new SshError(
              "no applied config hash is recorded; refusing to commit",
            );
          }
          runningHash = await waitForHash(target, DEFAULT_CONTROL_SOCKET);
          if (runningHash === undefined) {
            throw new SshError(
              "the control socket did not answer a config hash; refusing to commit",
            );
          }
          if (runningHash !== recorded) {
            throw new SshError(
              "the running config differs from the applied one; refusing to commit",
            );
          }
          const enabled = await sshExec(deps, target, [
            "systemctl",
            "enable",
            SERVICE,
          ]);
          if (enabled.exit_code !== 0) {
            throw new SshError(
              "could not enable the service; refusing to commit",
            );
          }
        }
        for (const canary of revert.canaries ?? []) {
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

        // Verify is a gate: any failed field refuses and leaves the revert.
        const observation = await probe(target, args, DEFAULT_CONTROL_SOCKET);
        const fresh = await sshExec(deps, target, ["true"]);
        const verify = verifyOf(
          observation,
          revert,
          runningHash,
          !removal,
          fresh.exit_code === 0,
        );
        const failures = Object.entries(verify)
          .filter(([, value]) => value === "fail")
          .map(([name]) => name);
        if (failures.length > 0) {
          throw new SshError(
            `verify failed (${
              failures.join(", ")
            }); refusing to commit and leaving the revert armed`,
          );
        }

        // Commit critical section, serialized with the revert timer.
        const status = await runScript(
          target,
          commitScript(dir, token, revert.armed_sha256),
        );
        const outcome = status.stdout.trim();
        if (outcome !== "committed") {
          if (outcome === "fired") {
            const firedAt = new Date(deps.now()).toISOString();
            await context.writeResource(
              "revert",
              `${key}-${token}`,
              RevertStateSchema.parse({ ...revert, fired_at: firedAt }),
            );
            throw new SshError(`the revert already fired at ${firedAt}`);
          }
          throw new SshError(
            `could not commit the revert (${outcome}); it is still armed`,
          );
        }

        await context.writeResource(
          "revert",
          `${key}-${token}`,
          RevertStateSchema.parse({
            ...revert,
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
            subnets: removal ? 0 : (storedConfig?.subnets ?? 0),
          }),
        );
        return {
          dataHandles: [],
          result: { host: args.host, committed: true, verify },
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
        "READ-ONLY. Re-probe, adopt any fired revert into its record and report drift (file sha differs from the committed one). Never rewrites.",
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
        // Adopt any fired revert so a later commit knows it already fired.
        for (const marker of await readFiredMarkers(target)) {
          const record = await context.readResource(
            `${key}-${marker.token}`,
          ) as RevertState | null;
          if (record && !record.fired_at) {
            await context.writeResource(
              "revert",
              `${key}-${marker.token}`,
              RevertStateSchema.parse({
                ...record,
                fired_at: marker.fired_at,
              }),
            );
          }
          drift.push(
            `revert ${marker.token} fired at ${marker.fired_at} (${marker.result})`,
          );
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
        "DESTRUCTIVE. Stop and disable the server and converge it back to the package's original config under the armed-revert protocol; call commit to make the removal permanent. Idempotent.",
      arguments: strictTargetArgsSchema,
      execute: async (
        rawArgs: unknown,
        context: MethodContext,
      ): Promise<unknown> => {
        const args = rawArgs as SshArgs;
        const target = await toTarget(context, args);
        const socket = DEFAULT_CONTROL_SOCKET;
        const key = instanceKey(args);
        const originalSha = await remoteFileSha(target, ORIGINAL_CONFIG);
        const original = await readRemoteText(target, ORIGINAL_CONFIG);
        if (originalSha === null || original === null) {
          throw new SshError(
            "no captured original config; run install before remove",
          );
        }
        // The stock config has // comments, so it is not JSON; kea-dhcp4 -t on
        // the staged copy is the validation.
        const isActive = await serviceActive(target);
        const liveSha = await remoteFileSha(target, CONFIG_PATH);
        const marker = await readMarker(target);
        if (!isActive && liveSha === originalSha && marker === null) {
          return {
            dataHandles: [],
            result: { host: args.host, removed: false },
          };
        }

        const staged = `/etc/kea/kea-dhcp4.conf.staged-${deps.token()}`;
        let stagedMoved = false;
        try {
          await sshUpload(deps, target, {
            path: staged,
            content: original,
            mode: "0600",
          });
          const rest = await runScript(
            target,
            `kea-dhcp4 -t ${posixQuote(staged)}`,
          );
          if (rest.exit_code !== 0) {
            throw new KeaInputError(
              `kea-dhcp4 -t rejected the captured original config: ${
                rest.stderr.trim().split("\n").at(-1) ?? ""
              }`,
            );
          }

          const token = deps.token();
          const dir = `${REVERT_ROOT}/${token}`;
          const now = deps.now();
          const expiresAt = new Date(now + 600 * 1000).toISOString();
          const claim = await runScript(
            target,
            claimScript(dir, JSON.stringify({ token, expires_at: expiresAt })),
          );
          if (claim.exit_code === 9) {
            const active = await readMarker(target);
            throw new SshError(
              `a revert is already armed (token ${String(active?.token)})`,
            );
          }
          if (claim.exit_code !== 0) {
            throw new SshError(
              `could not claim the revert: ${
                claim.stderr.trim().split("\n").at(-1) ?? ""
              }`,
            );
          }
          const priorEnabled = await serviceEnabled(target);
          const revert: RevertState = {
            host: args.host,
            token,
            armed_at: new Date(now).toISOString(),
            expires_at: expiresAt,
            armed_sha256: originalSha,
            intent: "remove",
            prior_enabled: priorEnabled,
          };
          await context.writeResource(
            "revert",
            `${key}-${token}`,
            RevertStateSchema.parse(revert),
          );

          let prevRendered: RenderResult | null = null;
          try {
            const prevFile = await readRemoteText(
              target,
              `${dir}/previous.conf`,
            );
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
            await sshUpload(deps, target, {
              path: `${dir}/restore.sh`,
              content: restoreScript(token, socket, isActive, priorEnabled),
              mode: "0700",
            });
            if (prevRendered !== null) {
              await sshUpload(deps, target, {
                path: `${dir}/restore-request.json`,
                content: JSON.stringify(configSetRequest(prevRendered)),
                mode: "0600",
              });
            }
            await sshUpload(deps, target, {
              path: `${dir}/hash-request.json`,
              content: JSON.stringify({
                command: "config-hash-get",
                service: ["dhcp4"],
              }),
              mode: "0600",
            });
          } catch (error) {
            await abortClaim(context, target, args, dir, token, revert);
            throw error;
          }
          const armed = await runScript(
            target,
            `systemd-run --on-active=600 --unit=${timerName(token)} ${
              posixQuote(`${dir}/restore.sh`)
            }`,
          );
          if (armed.exit_code !== 0) {
            await abortClaim(context, target, args, dir, token, revert);
            throw new SshError(
              `could not arm the revert timer: ${
                armed.stderr.trim().split("\n").at(-1) ?? ""
              }`,
            );
          }

          const group = await resolveServiceGroup(target);
          const install = await runScript(
            target,
            installFileScript(staged, group),
          );
          if (install.exit_code !== 0) {
            await disarmAndRestore(context, target, args, dir, token, revert);
            throw new SshError(
              `could not install the original config: ${
                install.stderr.trim().split("\n").at(-1) ?? ""
              }`,
            );
          }
          stagedMoved = true;

          const stop = await runScript(target, `systemctl stop ${SERVICE}`);
          const disable = await runScript(
            target,
            `systemctl disable ${SERVICE}`,
          );
          if (stop.exit_code !== 0 || disable.exit_code !== 0) {
            await disarmAndRestore(context, target, args, dir, token, revert);
            throw new SshError(
              "could not stop and disable the Kea service; removal aborted",
            );
          }
          const observation = await probe(target, args, socket);
          await context.writeResource(
            "config",
            key,
            ConfigStateSchema.parse({
              host: args.host,
              config_sha256: originalSha,
              kea_hash: observation.kea_hash,
              committed_at: "",
              applied_at: new Date(deps.now()).toISOString(),
              subnets: 0,
            }),
          );
          return {
            dataHandles: [],
            result: {
              host: args.host,
              removed: true,
              revert_token: token,
              expires_at: expiresAt,
              observation,
            },
          };
        } finally {
          if (!stagedMoved) {
            await sshExec(deps, target, ["rm", "-f", staged]).catch(() =>
              undefined
            );
          }
        }
      },
    },
  },
};

/** Maps an observation onto the verify shape for a commit. */
function verifyOf(
  observation: Observation,
  revert: RevertState,
  runningHash: string | undefined,
  expectActive: boolean,
  freshConnection: boolean,
): Record<string, string> {
  const serviceOk = expectActive
    ? observation.service_active
    : !observation.service_active;
  const socketsOk = expectActive
    ? observation.sockets.length > 0
    : observation.sockets.length === 0;
  const hashOk = expectActive
    ? observation.kea_hash !== undefined &&
      (runningHash === undefined || observation.kea_hash === runningHash)
    : true;
  return {
    service: serviceOk ? "pass" : "fail",
    hash_match: hashOk ? "pass" : "fail",
    file_match: observation.file_sha256 === revert.armed_sha256
      ? "pass"
      : "fail",
    sockets: socketsOk ? "pass" : "fail",
    fresh_connection: freshConnection ? "pass" : "fail",
    canaries: (revert.canaries?.length ?? 0) > 0 ? "pass" : "skipped",
  };
}
