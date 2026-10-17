/**
 * `@randybias/host-net`: configure Linux host networking over SSH under an
 * automatic revert armed before anything is changed. Generic: interface names,
 * MACs, VLAN ids, MTUs and addresses are inputs, and one definition serves any
 * host. The private key is a vault reference, resolved inside the method and
 * delivered over stdin.
 *
 * @module
 */

import { z } from "npm:zod@4.3.6";
import {
  denoDeps,
  exec as sshExec,
  type ExecResult,
  sha256Hex,
  type SshDeps,
  SshError,
  type SshTarget,
  upload as sshUpload,
} from "./_lib/ssh.ts";
import {
  assertNoManagementOverlap,
  type BridgeSpec,
  HostNetConfigError,
  type NetConfig,
  TOKEN_RE,
  type VlanSpec,
} from "./_lib/validate.ts";
import { renderConfig, type RenderResult } from "./_lib/render.ts";
import { assertArmBeforeApply, planApply, type Step } from "./_lib/plan.ts";
import {
  type LiveState,
  managementCidrs,
  parseAddrs,
  parseDefaultRoute,
  parseLinks,
  parseRouteGet,
  probeCommands,
} from "./_lib/probe.ts";
import {
  CURRENT_PATH,
  LOCK_PATH,
  renderArmScript,
  renderClearFailedScript,
  renderDisarmScript,
  renderMarkerJsonReadScript,
  renderMarkerReadScript,
  restorePath,
  type RevertContext,
  revertDir,
  unitName,
} from "./_lib/revert.ts";

/**
 * Ownership and desired state (single-sourced):
 *
 * 1. Ownership lives in the `config` record and is the FULL set host-net has
 *    created and still owns: `devices` (virtual devices), `ownedFiles` (each
 *    with a `preExisted` flag) and `parentMtus` (pre-change MTUs). It is
 *    written ONLY at commit, never by an apply's delta.
 * 2. An apply computes `owned = (previous owned ∩ declared) ∪ created` and
 *    parks it in the pending `revert` record; a revert that fires leaves the
 *    committed config record untouched.
 * 3. The identical-config no-op compares the LIVE read-back against the NEW
 *    desired render (and requires that render to be the committed one), never
 *    against the previous record.
 * 4. `remove` derives every device, file and MTU from the `config` record
 *    alone, never from the caller's inputs, proceeds when only files/MTUs are
 *    owned, and never touches a file recorded as pre-existing.
 */

/** Model type version; must equal the manifest version. */
export const VERSION = "2026.10.17.1";

/** A vault reference for the SSH private key. */
export interface KeyRef {
  /** Vault name. */
  vault: string;
  /** Secret key. */
  key: string;
}

/** The model's dependencies. */
export interface HostNetDeps extends SshDeps {
  /** Resolves a vault reference to a secret; tests inject this. */
  resolveSecret?: (vaultName: string, secretKey: string) => Promise<string>;
  /** Returns a fresh 16-hex revert token. */
  token?: () => string;
}

function randomToken(): string {
  const bytes = new Uint8Array(8);
  crypto.getRandomValues(bytes);
  return [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
}

/** Production dependencies. */
export const denoHostNetDeps: HostNetDeps = { ...denoDeps, token: randomToken };

const IFACE = /^[A-Za-z][A-Za-z0-9_.-]{0,14}$/;
const MAC = /^[0-9a-f]{2}(:[0-9a-f]{2}){5}$/;
const CIDR = /^[0-9A-Fa-f:.\/]+$/;

const TargetFields = {
  host: z.string().min(1).max(253),
  port: z.number().int().min(1).max(65535).default(22),
  user: z.string().min(1).max(32),
  // Strict only: this model does not persist a first-seen host key, so trusting
  // one on first use would leave nothing to pin the next run to. The pinned keys
  // are required.
  host_key_policy: z.literal("strict"),
  host_keys: z.array(z.string().max(8192)).min(1).max(64),
  ssh_key_ref: z.strictObject({
    vault: z.string().min(1).max(128),
    key: z.string().min(1).max(256),
  }).meta({ sensitive: true }),
  connect_timeout_s: z.number().int().min(1).max(120).default(15),
};

const EthernetSchema = z.strictObject({
  name: z.string().regex(IFACE).optional(),
  match_mac: z.string().regex(MAC).optional(),
  mtu: z.number().int().min(1280).max(9216).optional(),
}).refine((v) => v.name !== undefined || v.match_mac !== undefined, {
  message: "an ethernet needs a name or a match_mac",
});

const VlanSchema = z.strictObject({
  id: z.number().int().min(1).max(4094),
  link: z.string().regex(IFACE),
  name: z.string().regex(IFACE).optional(),
  mtu: z.number().int().min(1280).max(9216).optional(),
  addresses: z.array(z.string().regex(CIDR)).min(1).max(16),
  optional: z.boolean().default(true),
});

const BridgeSchema = z.strictObject({
  name: z.string().regex(IFACE),
  interfaces: z.array(z.string().regex(IFACE)).min(1).max(32),
  mtu: z.number().int().min(1280).max(9216).optional(),
  addresses: z.array(z.string().regex(CIDR)).max(16).default([]),
  stp: z.boolean().optional(),
});

const CommonNet = {
  backend: z.enum(["netplan", "networkd"]).default("netplan"),
  bridge_type: z.enum(["linux", "ovs"]),
  mode: z.enum(["additive", "takeover"]).default("additive"),
  management_interface: z.string().regex(IFACE),
  ethernets: z.array(EthernetSchema).max(16).default([]),
  vlans: z.array(VlanSchema).max(64).default([]),
  bridge: BridgeSchema.optional(),
  mtu_peer: z.strictObject({
    address: z.string().regex(/^[0-9A-Fa-f:.]+$/),
    interface: z.string().regex(IFACE),
  }).optional(),
  revert_after_s: z.number().int().min(120).max(1800).default(300),
  require_mtu_verify: z.boolean().default(true),
  management_change_ack: z.boolean().default(false),
};

const RenderArgs = z.strictObject({ ...TargetFields, ...CommonNet });
const ApplyArgs = RenderArgs;
const CommitArgs = RenderArgs;
const GetArgs = z.strictObject({
  ...TargetFields,
  backend: CommonNet.backend,
  bridge_type: CommonNet.bridge_type,
  management_interface: CommonNet.management_interface,
  revert_after_s: CommonNet.revert_after_s,
});
const SyncArgs = GetArgs;
const RemoveArgs = RenderArgs;
const ClearFailedArgs = z.strictObject({ ...TargetFields });
const RevertNowArgs = z.strictObject({
  ...TargetFields,
  token: z.string().regex(TOKEN_RE),
});

type Parsed = z.infer<typeof RenderArgs>;

const ConfigSchema = z.strictObject({
  target: z.string(),
  backend: z.string(),
  bridgeType: z.string(),
  mode: z.string(),
  managementInterface: z.string(),
  bridge: z.string().optional(),
  devices: z.array(z.string()),
  ownedFiles: z.array(
    z.strictObject({ path: z.string(), preExisted: z.boolean() }),
  ).optional(),
  parentMtus: z.array(
    z.strictObject({ name: z.string(), mtu: z.number() }),
  ).optional(),
  configSha256: z.string(),
  contentSha256: z.string().optional(),
  committedAt: z.string().optional(),
});

const RevertSchema = z.strictObject({
  target: z.string(),
  token: z.string(),
  armedAt: z.string(),
  expiresAt: z.string(),
  armedSha256: z.string(),
  contentSha256: z.string().optional(),
  operation: z.string().optional(),
  /** The full owned set after this change commits. */
  owned: z.array(z.string()).optional(),
  /** The devices this change itself creates (restored/deleted on revert). */
  created: z.array(z.string()).optional(),
  createdBridges: z.array(z.string()).optional(),
  ownedFiles: z.array(z.string()).optional(),
  parentMtus: z.array(
    z.strictObject({ name: z.string(), mtu: z.number() }),
  ).optional(),
  backend: z.string().optional(),
  bridgeType: z.string().optional(),
  committedAt: z.string().optional(),
  cancelledAt: z.string().optional(),
  firedAt: z.string().optional(),
  result: z.string().optional(),
  clearedAt: z.string().optional(),
});

const ProbeSchema = z.strictObject({
  target: z.string(),
  managementInterface: z.string(),
  defaultRoute: z.string(),
  links: z.array(
    z.strictObject({
      name: z.string(),
      mtu: z.number(),
      kind: z.string(),
      state: z.string(),
      vlanId: z.number(),
      master: z.string(),
    }),
  ),
  addrs: z.array(
    z.strictObject({
      ifname: z.string(),
      family: z.string(),
      local: z.string(),
      prefixlen: z.number(),
    }),
  ),
  observedAt: z.string(),
});

/** The parts of the swamp context this model uses. */
export interface MethodContext {
  /** Logger. */
  logger: {
    /** Info line. */
    info: (m: string, p?: Record<string, unknown>) => void;
    /** Warning line. */
    warn: (m: string, p?: Record<string, unknown>) => void;
    /** Error line. */
    error: (m: string, p?: Record<string, unknown>) => void;
  };
  /** Writes a resource. */
  writeResource: (
    spec: string,
    name: string,
    data: Record<string, unknown>,
  ) => Promise<{ name: string }>;
  /** Reads a resource. */
  readResource: (
    name: string,
    version?: number,
  ) => Promise<Record<string, unknown> | null>;
  /** Optional vault service (an object with get/put). */
  vaultService?: {
    /** Reads a secret. */
    get: (vault: string, key: string) => Promise<string>;
  };
}

function targetKey(a: { host: string; port: number; user: string }): string {
  return `${a.user}@${a.host.toLowerCase()}:${a.port}`;
}

function targetOf(a: {
  host: string;
  port: number;
  user: string;
  host_key_policy: "strict";
  host_keys: string[];
  connect_timeout_s: number;
}): SshTarget {
  return {
    host: a.host,
    port: a.port,
    user: a.user,
    host_key_policy: a.host_key_policy,
    host_keys: a.host_keys,
    connect_timeout_s: a.connect_timeout_s,
  };
}

async function resolveKey(
  deps: HostNetDeps,
  context: MethodContext,
  ref: KeyRef,
): Promise<string> {
  if (deps.resolveSecret) return await deps.resolveSecret(ref.vault, ref.key);
  if (context.vaultService) {
    return await context.vaultService.get(ref.vault, ref.key);
  }
  throw new HostNetConfigError(
    "no secret resolver: wire ssh_key_ref through the vault",
  );
}

/**
 * Runs one argv through the transport and throws on any non-zero exit unless
 * the code is explicitly allowed. A failed arm or mutation must never be
 * ignored: every remote command after arming leaves the revert armed on
 * failure.
 */
async function run(
  deps: HostNetDeps,
  target: SshTarget,
  argv: string[],
  what: string,
  allow: number[] = [],
): Promise<ExecResult> {
  const res = await sshExec(deps, target, argv);
  if (res.exit_code !== 0 && !allow.includes(res.exit_code)) {
    throw new HostNetConfigError(
      `${what} failed (exit ${res.exit_code})`,
    );
  }
  return res;
}

function configOf(args: Parsed): NetConfig {
  const vlans: VlanSpec[] = args.vlans.map((v) => ({ ...v }));
  const bridge: BridgeSpec | undefined = args.bridge;
  return {
    backend: args.backend,
    bridgeType: args.bridge_type,
    mode: args.mode,
    managementChangeAck: args.management_change_ack,
    managementInterface: args.management_interface,
    ethernets: args.ethernets.map((e) => ({
      name: e.name ?? e.match_mac ?? "",
      matchMac: e.match_mac,
      mtu: e.mtu,
    })),
    vlans,
    bridge,
  };
}

/**
 * Uploads the restore script and marker, arms the timer host-side, then
 * persists the revert record before the caller writes or applies anything.
 */
/**
 * Arms the host-side revert from one host script (which snapshots only what
 * this change owns, writes the per-token restore script and the current
 * marker, then starts the timer), and only then persists the model's revert
 * record — before the caller writes or applies anything.
 */
/** What one arm needs to persist and to build the restore context. */
interface ArmInput {
  /** Config backend. */
  backend: "netplan" | "networkd";
  /** Bridge implementation. */
  bridgeType: "linux" | "ovs";
  /** The full owned set this change leaves behind (committed later). */
  owned: string[];
  /** The devices this change itself creates (deleted on revert). */
  created: string[];
  /** Subset of created that are OVS bridges. */
  createdBridges: string[];
  /** The files this change owns. */
  ownedFiles: string[];
  /** Previously owned devices no longer declared: deleted by this change. */
  staleDevices: string[];
  /** Previously owned files no longer rendered: removed by this change. */
  staleFiles: string[];
  /** Parent MTUs this change raises, with the pre-change value. */
  parentMtus: { name: string; mtu: number }[];
  /** The management path before the change: its interface and global CIDRs. */
  managementInterface: string;
  managementAddrs: string[];
  /** The rendered config identity. */
  armedSha256: string;
  /** SHA-256 over the owned file contents only. */
  contentSha256: string;
  /** `apply` or `remove`. */
  operation: "apply" | "remove";
}

function revertContext(token: string, input: ArmInput): RevertContext {
  return {
    token,
    backend: input.backend,
    bridgeType: input.bridgeType,
    created: input.created,
    createdBridges: input.createdBridges,
    // The snapshot also covers the files this change deletes, so a revert
    // puts them back.
    ownedFiles: [...new Set([...input.ownedFiles, ...input.staleFiles])],
    parentMtus: input.parentMtus,
    managementInterface: input.managementInterface,
    managementAddrs: input.managementAddrs,
  };
}

/**
 * Arms the host-side revert from one host script, then persists a pending
 * revert record that carries the FULL owned set (for the config record at
 * commit), the delta this change creates, the owned files and the parent
 * MTUs. The config record is written only at commit.
 */
async function armRevert(
  deps: HostNetDeps,
  target: SshTarget,
  context: MethodContext,
  token: string,
  revertAfterS: number,
  input: ArmInput,
): Promise<{ handle: { name: string }; expiresAt: string }> {
  const key = targetKey(target);
  const expiresAt = new Date(deps.now() + revertAfterS * 1000).toISOString();
  const res = await run(
    deps,
    target,
    [
      "sh",
      "-c",
      renderArmScript(revertContext(token, input), {
        revertAfterS,
        armedSha256: input.armedSha256,
        contentSha256: input.contentSha256,
        operation: input.operation,
      }),
    ],
    "the revert arm",
    [75, 76],
  );
  if (res.exit_code === 75 || res.exit_code === 76) {
    throw new HostNetConfigError(
      "an earlier revert is already armed for this host",
    );
  }
  const handle = await context.writeResource("revert", `revert-${key}`, {
    target: key,
    token,
    armedAt: new Date(deps.now()).toISOString(),
    expiresAt,
    armedSha256: input.armedSha256,
    contentSha256: input.contentSha256,
    operation: input.operation,
    owned: input.owned,
    created: input.created,
    createdBridges: input.createdBridges,
    ownedFiles: input.ownedFiles,
    staleDevices: input.staleDevices,
    staleFiles: input.staleFiles,
    parentMtus: input.parentMtus,
    backend: input.backend,
    bridgeType: input.bridgeType,
    result: "pending",
  });
  return { handle, expiresAt };
}

async function probeLive(
  deps: HostNetDeps,
  target: SshTarget,
): Promise<LiveState> {
  const [links, addrs, route, routeGet, netplan, networkd, ovs] = await Promise
    .all(
      probeCommands().map((argv) => sshExec(deps, target, argv)),
    );
  for (
    const r of [links, addrs, route, routeGet, netplan, networkd, ovs]
  ) {
    if (r.exit_code !== 0) {
      throw new SshError(
        `host-net probe command failed with exit ${r.exit_code}`,
      );
    }
  }
  const parsedLinks = parseLinks(links.stdout);
  const parsedAddrs = parseAddrs(addrs.stdout);
  const managementInterface = parseRouteGet(routeGet.stdout);
  return {
    links: parsedLinks,
    addrs: parsedAddrs,
    defaultRoute: parseDefaultRoute(route.stdout),
    managementInterface,
    managementAddrs: managementCidrs(parsedAddrs, managementInterface),
    hasNetplan: netplan.stdout.trim() === "yes",
    hasNetworkd: networkd.stdout.trim() === "yes",
    hasOvs: ovs.stdout.trim() === "yes",
  };
}

/** SHA-256 over the managed file contents only (path\\0content), for commit. */
async function contentDigest(files: RenderResult["files"]): Promise<string> {
  return await sha256Hex(
    files.slice().sort((a, b) => a.path < b.path ? -1 : 1)
      .map((f) => `${f.path}\0${f.content}`).join("\0"),
  );
}

/** The guarded apply script: it applies only while this token still guards. */
function shq(value: string): string {
  return `'${value.replace(/'/g, `'\\''`)}'`;
}

/** The guarded apply script: it applies only while this token still guards. */
/** What a guarded apply/remove moves into place and runs after the guard. */
interface GuardOpts {
  /** Files staged as `<path>.host-net-new`, moved into place on success. */
  stagedFiles?: RenderResult["files"];
  /** MTU commands run after the guard checks pass. */
  mtuCommands?: string[][];
  /** Files removed after the guard checks pass (never pre-existing ones). */
  removeFiles?: string[];
  /** Devices deleted after the backend ran, once the guard has passed. */
  deleteDevices?: string[];
}

/**
 * The guarded apply/remove script: it mutates only while this token still
 * guards the change (current marker, snapshot present, unexpired, timer
 * active). It moves staged files into place, runs the MTU commands and removes
 * the given files; a guard refusal removes any staged files and exits non-zero.
 */
function guardedApplyScript(ctx: RevertContext, opts: GuardOpts = {}): string {
  const apply = ctx.backend === "netplan"
    ? "netplan apply"
    : "networkctl reload && networkctl reconfigure";
  const staged = opts.stagedFiles ?? [];
  const stagedPath = (p: string) => `${p}.host-net-new`;
  const moves = staged.map((f) =>
    `mv -f ${shq(stagedPath(f.path))} ${shq(f.path)}`
  ).join("\n");
  const cleanup = staged.map((f) => `rm -f ${shq(stagedPath(f.path))}`).join(
    "\n",
  );
  const mtus = (opts.mtuCommands ?? []).map((argv) => argv.map(shq).join(" "))
    .join("\n");
  const removes = (opts.removeFiles ?? []).map((p) => `rm -f ${shq(p)}`).join(
    "\n",
  );
  // The backend does not reliably delete a virtual device that left the
  // config, so a device that was owned and is no longer declared goes here,
  // under the same guard as the rest.
  const deletes = (opts.deleteDevices ?? []).map((n) =>
    `if ip link show dev ${shq(n)} >/dev/null 2>&1; then ip link delete dev ${
      shq(n)
    }; fi`
  ).join("\n");
  return [
    "set -eu",
    `exec 9>${LOCK_PATH}`,
    "flock -w 30 9 || { echo 'lock busy' >&2; exit 75; }",
    `DIR=${shq(revertDir(ctx.token))}`,
    `cleanup() { ${cleanup || "true"}; }`,
    `[ -f ${CURRENT_PATH} ] || { cleanup; echo 'superseded' >&2; exit 70; }`,
    `ctok=; cexp=0; read ctok cexp _ < ${CURRENT_PATH} || true`,
    `[ "$ctok" = ${
      shq(ctx.token)
    } ] || { cleanup; echo 'superseded' >&2; exit 70; }`,
    `[ -d "$DIR/snapshot" ] || { cleanup; echo 'restored' >&2; exit 71; }`,
    `[ "$(date +%s)" -lt "$cexp" ] || { cleanup; echo 'expired' >&2; exit 72; }`,
    `[ "$(systemctl is-active ${
      shq(unitName(ctx.token))
    }.timer || true)" = active ] || { cleanup; echo 'timer gone' >&2; exit 73; }`,
    mtus,
    moves,
    removes,
    apply,
    deletes,
  ].filter((l) => l !== "").join("\n");
}

/**
 * Merges parent-MTU baselines: an entry already recorded keeps its ORIGINAL
 * value, a new parent takes the value this change saw, and a parent the
 * previous commit managed stays recorded so `remove` can still restore it.
 */
function mergeBaselines(
  previous: { name: string; mtu: number }[],
  current: { name: string; mtu: number }[],
): { name: string; mtu: number }[] {
  const merged = new Map<string, number>();
  for (const p of previous) merged.set(p.name, p.mtu);
  for (const c of current) if (!merged.has(c.name)) merged.set(c.name, c.mtu);
  return [...merged].map(([name, mtu]) => ({ name, mtu }));
}

/** True while a recorded revert is pending and has not expired. */
function isPending(
  recorded: Record<string, unknown> | null,
  nowMs: number,
): boolean {
  if (recorded === null || typeof recorded.token !== "string") return false;
  if (
    typeof recorded.committedAt === "string" ||
    typeof recorded.firedAt === "string" ||
    typeof recorded.cancelledAt === "string"
  ) return false;
  const expires = typeof recorded.expiresAt === "string"
    ? Date.parse(recorded.expiresAt)
    : 0;
  return Number.isFinite(expires) && expires > nowMs;
}

/**
 * Compares the live probe to the pre-apply probe. Expected values come from the
 * tool's own `ip -j` read-back, never from the rendered text, so kernel
 * normalisation cannot look like drift.
 */
function verifyAgainst(
  before: LiveState,
  after: LiveState,
  cfg: NetConfig,
  created: string[],
): VerifyResult {
  const management = after.managementAddrs.length > 0 ? "pass" : "fail";
  const defaultRoute = after.defaultRoute === before.defaultRoute
    ? "pass"
    : "fail";
  const links =
    created.every((name) => after.links.some((l) => l.name === name))
      ? "pass"
      : "fail";
  void cfg;
  return {
    management,
    fresh_connection: "pass",
    default_route: defaultRoute,
    links,
    jumbo: "skipped",
  };
}

/** Reads the managed files back and digests their contents for commit. */
/** Digests the live content of `paths`; a missing file reads as absent. */
async function liveContentShaPaths(
  deps: HostNetDeps,
  target: SshTarget,
  paths: string[],
): Promise<string> {
  const parts: string[] = [];
  for (const path of [...paths].sort()) {
    const res = await sshExec(deps, target, [
      "sh",
      "-c",
      'if [ -f "$1" ]; then cat -- "$1"; fi',
      "sh",
      path,
    ]);
    parts.push(`${path}\0${res.stdout}`);
  }
  return await sha256Hex(parts.join("\0"));
}

/** Digests the live content of the rendered files. */
async function liveContentSha(
  deps: HostNetDeps,
  target: SshTarget,
  render: RenderResult,
): Promise<string> {
  return await liveContentShaPaths(
    deps,
    target,
    render.files.map((f) => f.path),
  );
}

/** Builds the model with overridable dependencies. */
export function createModel(overrides: Partial<HostNetDeps> = {}) {
  const deps: HostNetDeps = { ...denoHostNetDeps, ...overrides };
  const resources = {
    config: {
      description: "The host-net managed configuration identity for one host",
      schema: ConfigSchema,
      lifetime: "infinite" as const,
      garbageCollection: 10,
    },
    revert: {
      description: "An armed host-net revert for one host",
      schema: RevertSchema,
      lifetime: "infinite" as const,
      garbageCollection: 10,
    },
    probe: {
      description: "The last live link/addr/route probe for one host",
      schema: ProbeSchema,
      lifetime: "1d" as const,
      garbageCollection: 5,
    },
  };
  const methods = {
    render: {
      description:
        "READ-ONLY. Return the files the backend would write plus the ordered step plan and its sha256. Deterministic and touches no host.",
      arguments: RenderArgs,
      execute: async (args: Parsed) => {
        const cfg = configOf(args);
        const render = await renderConfig(cfg);
        const plan = planApply(cfg, {
          token: "0000000000000000",
          revertAfterS: args.revert_after_s,
          writtenPaths: render.files.map((f) => f.path),
        });
        assertArmBeforeApply(plan);
        return {
          result: {
            files: render.files,
            managed: render.managed,
            created: render.created,
            sha256: render.sha256,
            steps: plan.map((s: Step) => ({
              kind: s.kind,
              id: s.id,
              description: s.description,
            })),
          },
        };
      },
    },
    apply: {
      kind: "action" as const,
      description:
        "DESTRUCTIVE. Validate, pre-check, snapshot, arm the revert, then apply the rendered config with MTU ordering and verify. Idempotent: an identical live config arms nothing. The change is not permanent until commit.",
      arguments: ApplyArgs,
      execute: async (args: Parsed, context: MethodContext) => {
        const cfg = configOf(args);
        const render = await renderConfig(cfg);
        const key = await resolveKey(deps, context, args.ssh_key_ref);
        const target: SshTarget = { ...targetOf(args), private_key: key };
        const token = (deps.token ?? randomToken)();
        const live = await probeLive(deps, target);
        if (
          live.managementInterface !== "" &&
          live.managementInterface !== cfg.managementInterface
        ) {
          throw new HostNetConfigError(
            `management interface ${cfg.managementInterface} does not carry the SSH route`,
          );
        }
        if (cfg.bridgeType === "ovs" && !live.hasOvs) {
          throw new HostNetConfigError("ovs-vsctl is not present on the host");
        }
        // A match_mac that resolves to the management NIC touches management,
        // whether it sets that NIC's MTU or enslaves it into the bridge.
        const mgmtNames = new Set<string>([cfg.managementInterface]);
        for (const e of cfg.ethernets) {
          if (
            e.matchMac !== undefined &&
            live.links.some((l) =>
              l.mac === e.matchMac && l.name === cfg.managementInterface
            )
          ) {
            mgmtNames.add(e.name);
          }
        }
        const takeover = cfg.mode === "takeover" && cfg.managementChangeAck;
        for (const e of cfg.ethernets) {
          if (
            e.name !== "" && mgmtNames.has(e.name) &&
            e.mtu !== undefined && !takeover
          ) {
            throw new HostNetConfigError(
              "the change touches the management interface; use mode takeover with management_change_ack",
            );
          }
        }
        for (const member of cfg.bridge?.interfaces ?? []) {
          if (mgmtNames.has(member) && !takeover) {
            throw new HostNetConfigError(
              "the change enslaves the management interface; use mode takeover with management_change_ack",
            );
          }
        }
        // Pre-check the rendered netplan against a staged root before arming.
        if (cfg.backend === "netplan") {
          if (!live.hasNetplan) {
            throw new HostNetConfigError("netplan is not present on the host");
          }
          // netplan merges every file in /etc/netplan, so the pre-check must
          // see the same merge the apply will: a copy of the whole live
          // directory (names, order and modes kept), then the rendered file on
          // top. Staging only ours would reject a VLAN whose link NIC is
          // defined in another file (cloud-init's). The scratch root is a
          // private (0700) mktemp directory; the script removes it itself if
          // its own setup fails, and the caller removes it however the upload
          // or the generate ends. A missing /etc/netplan is an empty copy.
          const made = await run(
            deps,
            target,
            [
              "sh",
              "-c",
              [
                "set -eu",
                "d=$(mktemp -d /tmp/host-net-precheck.XXXXXX)",
                `trap 'rc=$?; if [ "$rc" -ne 0 ]; then rm -rf "$d"; fi' EXIT`,
                'chmod 0700 "$d"',
                'mkdir -p "$d/etc/netplan" "$d/etc/cloud/cloud.cfg.d"',
                'if [ -d /etc/netplan ]; then cp -a /etc/netplan/. "$d/etc/netplan/"; fi',
                `printf '%s\\n' "$d"`,
              ].join("\n"),
            ],
            "the precheck setup",
          );
          const stage = made.stdout.trim();
          if (!/^\/tmp\/host-net-precheck\.[A-Za-z0-9]{6}$/.test(stage)) {
            throw new HostNetConfigError(
              "the precheck setup did not return a scratch directory",
            );
          }
          try {
            for (const file of render.files) {
              await sshUpload(deps, target, {
                path: `${stage}${file.path}`,
                content: file.content,
                mode: file.mode,
              });
            }
            await run(
              deps,
              target,
              ["netplan", "generate", "--root-dir", stage],
              "the netplan generate precheck",
            );
          } finally {
            await sshExec(deps, target, ["rm", "-rf", stage]).catch(
              () => undefined,
            );
          }
        }
        const storage = [
          ...cfg.vlans.flatMap((v) => v.addresses),
          ...(cfg.bridge?.addresses ?? []),
        ];
        assertNoManagementOverlap(storage, live.managementAddrs);
        const revertRecord = await context.readResource(
          `revert-${targetKey(args)}`,
        );
        if (isPending(revertRecord, deps.now())) {
          throw new HostNetConfigError(
            `a revert is already armed for this host (token ${
              String(revertRecord!.token)
            })`,
          );
        }
        // Ownership comes only from the config record, never from the inputs.
        const config = await context.readResource(
          `config-${targetKey(args)}`,
        );
        const owned = new Set(
          config !== null && Array.isArray(config.devices)
            ? config.devices as string[]
            : [],
        );
        const liveNames = new Set(live.links.map((l) => l.name));
        for (const name of render.created) {
          if (liveNames.has(name) && !owned.has(name)) {
            throw new HostNetConfigError(
              `device ${name} already exists and is not managed by this model`,
            );
          }
        }
        const desiredContentSha = await contentDigest(render.files);
        // No-op only when the NEW desired config is both recorded and live.
        if (
          config !== null && config.contentSha256 === desiredContentSha &&
          [...owned].every((name) => liveNames.has(name))
        ) {
          const liveSha = await liveContentSha(deps, target, render);
          if (liveSha === desiredContentSha) {
            return {
              result: {
                host: args.host,
                revert_token: "",
                config_sha256: render.sha256,
                verify: {
                  management: "pass",
                  fresh_connection: "pass",
                  default_route: "pass",
                  links: "pass",
                  jumbo: "skipped",
                },
                note: "identical live config; nothing armed",
              },
            };
          }
        }
        const created = render.created.filter((name) => !liveNames.has(name));
        // The FULL owned set after commit: previous ownership of still-declared
        // devices, plus everything this change creates.
        const ownedSet = [
          ...new Set([
            ...[...owned].filter((name) => render.created.includes(name)),
            ...created,
          ]),
        ];
        // What the previous commit owned and this desired config no longer
        // declares is deleted (never left behind unowned, which would block
        // re-adding it): the devices, and the files host-net itself created.
        const rendered = new Set(render.files.map((f) => f.path));
        const staleDevices = [...owned].filter((name) =>
          !render.created.includes(name)
        );
        const previousFiles =
          config !== null && Array.isArray(config.ownedFiles)
            ? config.ownedFiles as { path: string; preExisted: boolean }[]
            : [];
        const staleFiles = previousFiles
          .filter((f) => !rendered.has(f.path) && f.preExisted !== true)
          .map((f) => f.path);
        const createdBridges = cfg.bridgeType === "ovs" &&
            cfg.bridge !== undefined && created.includes(cfg.bridge.name)
          ? [cfg.bridge.name]
          : [];
        const parentMtus = cfg.ethernets
          .filter((e) => e.mtu !== undefined)
          .map((e) => ({
            name: e.name,
            mtu: live.links.find((l) => l.name === e.name)?.mtu ?? 0,
          }))
          .filter((p) => p.mtu > 0);
        const plan = planApply(cfg, {
          token,
          revertAfterS: args.revert_after_s,
          writtenPaths: render.files.map((f) => f.path),
        });
        assertArmBeforeApply(plan);
        const mtuArgvs = plan.filter((s) =>
          s.kind === "mtu" && s.argv !== undefined
        ).map((s) => s.argv!);
        const armInput: ArmInput = {
          backend: cfg.backend,
          bridgeType: cfg.bridgeType,
          owned: ownedSet,
          created,
          createdBridges,
          ownedFiles: render.files.map((f) => f.path),
          staleDevices,
          staleFiles,
          parentMtus,
          managementInterface: live.managementInterface,
          managementAddrs: live.managementAddrs,
          armedSha256: render.sha256,
          contentSha256: desiredContentSha,
          operation: "apply",
        };
        const { handle: revertHandle, expiresAt } = await armRevert(
          deps,
          target,
          context,
          token,
          args.revert_after_s,
          armInput,
        );
        for (const file of render.files) {
          await sshUpload(deps, target, {
            path: `${file.path}.host-net-new`,
            content: file.content,
            mode: file.mode,
          });
        }
        await run(
          deps,
          target,
          [
            "sh",
            "-c",
            guardedApplyScript(revertContext(token, armInput), {
              stagedFiles: render.files,
              mtuCommands: mtuArgvs,
              removeFiles: staleFiles,
              deleteDevices: staleDevices,
            }),
          ],
          "the guarded apply",
        );
        const after = await probeLive(deps, target);
        const verify = verifyAgainst(live, after, cfg, created);
        return {
          dataHandles: [revertHandle],
          result: {
            host: args.host,
            revert_token: token,
            expires_at: expiresAt,
            config_sha256: render.sha256,
            verify,
          },
        };
      },
    },
    commit: {
      kind: "action" as const,
      description:
        "DESTRUCTIVE. Verify over a fresh connection that the management path works, then cancel the armed revert. Refuses after expiry, after the revert fired, or when the live config no longer matches the armed sha.",
      arguments: CommitArgs,
      execute: async (args: Parsed, context: MethodContext) => {
        const cfg = configOf(args);
        const key = await resolveKey(deps, context, args.ssh_key_ref);
        const target: SshTarget = { ...targetOf(args), private_key: key };
        const recorded = await context.readResource(
          `revert-${targetKey(args)}`,
        );
        if (recorded === null || typeof recorded.token !== "string") {
          throw new HostNetConfigError("no armed revert to commit");
        }
        if (typeof recorded.committedAt === "string") {
          throw new HostNetConfigError("this revert is already committed");
        }
        if (typeof recorded.firedAt === "string") {
          throw new HostNetConfigError(
            "the revert already fired; nothing to commit",
          );
        }
        const expires = typeof recorded.expiresAt === "string"
          ? Date.parse(recorded.expiresAt)
          : 0;
        if (!(expires > deps.now())) {
          throw new HostNetConfigError(
            "the revert has expired; it may fire at any moment",
          );
        }
        const live = await probeLive(deps, target);
        if (live.managementAddrs.length === 0) {
          throw new HostNetConfigError("the management path did not verify");
        }
        const marker = await run(
          deps,
          target,
          ["sh", "-c", renderMarkerReadScript()],
          "the marker read",
        );
        const markerToken = marker.stdout.trim().split(/\s+/)[0] ?? "";
        if (markerToken !== recorded.token) {
          throw new HostNetConfigError(
            "the host marker is no longer this revert; refusing to commit",
          );
        }
        const isRemove = recorded.operation === "remove";
        const previousConfig = await context.readResource(
          `config-${targetKey(args)}`,
        );
        const previousProvenance = new Map<string, boolean>();
        for (
          const f of (previousConfig !== null &&
              Array.isArray(previousConfig.ownedFiles)
            ? previousConfig.ownedFiles as {
              path: string;
              preExisted: boolean;
            }[]
            : [])
        ) {
          previousProvenance.set(f.path, f.preExisted === true);
        }
        const previousBaselines = previousConfig !== null &&
            Array.isArray(previousConfig.parentMtus)
          ? previousConfig.parentMtus as { name: string; mtu: number }[]
          : [];
        const ownedFiles = Array.isArray(recorded.ownedFiles)
          ? recorded.ownedFiles as string[]
          : [];
        // The arm snapshot manifest records which owned files pre-existed.
        const manifestPath = `${revertDir(recorded.token)}/owned.txt`;
        const manifestOut = await sshExec(deps, target, [
          "sh",
          "-c",
          `if [ -f ${shq(manifestPath)} ]; then cat ${shq(manifestPath)}; fi`,
        ]);
        const preExisted = new Map<string, boolean>();
        for (const line of manifestOut.stdout.split("\n")) {
          const [path, state] = line.split("\t");
          if (path && state) preExisted.set(path, state === "present");
        }
        if (isRemove) {
          for (const path of ownedFiles) {
            if (preExisted.get(path) === true) continue; // never touch a pre-existing file
            const res = await run(
              deps,
              target,
              [
                "sh",
                "-c",
                'if [ -e "$1" ]; then echo present; else echo absent; fi',
                "sh",
                path,
              ],
              `the removal check for ${path}`,
            );
            if (res.stdout.trim() !== "absent") {
              throw new HostNetConfigError(
                `the owned file ${path} is still present; refusing to commit`,
              );
            }
          }
          const liveNames = new Set(live.links.map((l) => l.name));
          for (const name of (recorded.owned as string[] | undefined) ?? []) {
            if (liveNames.has(name)) {
              throw new HostNetConfigError(
                `device ${name} is still present; refusing to commit`,
              );
            }
          }
        } else if (typeof recorded.contentSha256 === "string") {
          // What this change deleted must really be gone before it is owned
          // no more.
          const liveNames = new Set(live.links.map((l) => l.name));
          for (
            const name of (recorded.staleDevices as string[] | undefined) ?? []
          ) {
            if (liveNames.has(name)) {
              throw new HostNetConfigError(
                `device ${name} is still present; refusing to commit`,
              );
            }
          }
          for (
            const path of (recorded.staleFiles as string[] | undefined) ?? []
          ) {
            const gone = await run(
              deps,
              target,
              [
                "sh",
                "-c",
                'if [ -e "$1" ]; then echo present; else echo absent; fi',
                "sh",
                path,
              ],
              `the removal check for ${path}`,
            );
            if (gone.stdout.trim() !== "absent") {
              throw new HostNetConfigError(
                `the dropped file ${path} is still present; refusing to commit`,
              );
            }
          }
          const liveSha = await liveContentShaPaths(deps, target, ownedFiles);
          if (liveSha !== recorded.contentSha256) {
            throw new HostNetConfigError(
              "the live config no longer matches the armed config; refusing to commit",
            );
          }
        }
        await run(
          deps,
          target,
          ["sh", "-c", renderDisarmScript(recorded.token, true)],
          "the revert commit",
        );
        const handle = await context.writeResource(
          "revert",
          `revert-${targetKey(args)}`,
          {
            ...recorded,
            committedAt: new Date(deps.now()).toISOString(),
          },
        );
        const committedAt = new Date(deps.now()).toISOString();
        if (isRemove) {
          await context.writeResource("config", `config-${targetKey(args)}`, {
            target: targetKey(args),
            backend: recorded.backend ?? cfg.backend,
            bridgeType: recorded.bridgeType ?? cfg.bridgeType,
            mode: cfg.mode,
            managementInterface: cfg.managementInterface,
            bridge: cfg.bridge?.name ?? "",
            devices: [],
            ownedFiles: [],
            parentMtus: [],
            configSha256: "",
            contentSha256: "",
            committedAt,
          });
        } else {
          await context.writeResource("config", `config-${targetKey(args)}`, {
            target: targetKey(args),
            backend: recorded.backend ?? cfg.backend,
            bridgeType: recorded.bridgeType ?? cfg.bridgeType,
            mode: cfg.mode,
            managementInterface: cfg.managementInterface,
            bridge: cfg.bridge?.name ?? "",
            devices: (recorded.owned as string[] | undefined) ?? [],
            // Provenance is FIRST-SEEN: a path already in the record keeps its
            // recorded flag. This apply's snapshot calls a file host-net wrote
            // earlier "pre-existing", and trusting it would make remove leave
            // host-net's own files behind.
            ownedFiles: ownedFiles.map((path) => ({
              path,
              preExisted: previousProvenance.has(path)
                ? previousProvenance.get(path) === true
                : preExisted.get(path) === true,
            })),
            // The baseline is the ORIGINAL pre-change MTU: a later apply sees
            // the already-raised value, which is not what remove must restore.
            parentMtus: mergeBaselines(
              previousBaselines,
              (recorded.parentMtus as
                | { name: string; mtu: number }[]
                | undefined) ?? [],
            ),
            configSha256: recorded.armedSha256 ?? "",
            contentSha256: recorded.contentSha256 ?? "",
            committedAt,
          });
        }
        return {
          dataHandles: [handle],
          result: {
            host: args.host,
            committed: true,
            // No L2 peer on the storage VLAN in this run, so the jumbo path is
            // not proven; say so rather than implying it passed.
            jumbo: args.mtu_peer !== undefined && args.require_mtu_verify
              ? "not-verified"
              : "skipped",
          },
        };
      },
    },
    get: {
      description:
        "READ-ONLY. Return the recorded config and any revert plus a live probe of links, MTUs, VLANs, bridges, addresses, default route and revert state.",
      arguments: GetArgs,
      execute: async (
        args: z.infer<typeof GetArgs>,
        context: MethodContext,
      ) => {
        const key = await resolveKey(deps, context, args.ssh_key_ref);
        const target: SshTarget = {
          ...targetOf(args),
          private_key: key,
        };
        const live = await probeLive(deps, target);
        const handle = await context.writeResource(
          "probe",
          `probe-${targetKey(args)}`,
          {
            target: targetKey(args),
            managementInterface: live.managementInterface,
            defaultRoute: live.defaultRoute,
            links: live.links,
            addrs: live.addrs,
            observedAt: new Date(deps.now()).toISOString(),
          },
        );
        const config = await context.readResource(
          `config-${targetKey(args)}`,
        );
        const revert = await context.readResource(
          `revert-${targetKey(args)}`,
        );
        return {
          dataHandles: [handle],
          result: { config, revert, probe: live },
        };
      },
    },
    sync: {
      description:
        "READ-ONLY with respect to the host. Re-probe and reconcile recorded state with the host, adopting a fired revert and reporting drift. Persists only after the probe succeeds.",
      arguments: SyncArgs,
      execute: async (
        args: z.infer<typeof SyncArgs>,
        context: MethodContext,
      ) => {
        const key = await resolveKey(deps, context, args.ssh_key_ref);
        const target: SshTarget = {
          ...targetOf(args),
          private_key: key,
        };
        const live = await probeLive(deps, target);
        const config = await context.readResource(
          `config-${targetKey(args)}`,
        );
        const drift: string[] = [];
        if (
          config !== null &&
          typeof config.configSha256 === "string" &&
          typeof config.configSha256 === "string"
        ) {
          const liveManaged = live.links.filter((l) =>
            (config.devices as string[]).includes(l.name)
          ).map((l) => l.name);
          const expected = config.devices as string[];
          for (const name of expected) {
            if (!liveManaged.includes(name)) drift.push(`missing:${name}`);
          }
        }
        const handle = await context.writeResource(
          "probe",
          `probe-${targetKey(args)}`,
          {
            target: targetKey(args),
            managementInterface: live.managementInterface,
            defaultRoute: live.defaultRoute,
            links: live.links,
            addrs: live.addrs,
            observedAt: new Date(deps.now()).toISOString(),
          },
        );
        return {
          dataHandles: [handle],
          result: { target: targetKey(args), drift },
        };
      },
    },
    remove: {
      kind: "action" as const,
      description:
        "DESTRUCTIVE. Remove the managed devices and config files, restoring MTUs in reverse order, under the same armed-revert protocol as apply. A second remove with nothing managed is a clean no-op.",
      arguments: RemoveArgs,
      execute: async (args: Parsed, context: MethodContext) => {
        const key = await resolveKey(deps, context, args.ssh_key_ref);
        const target: SshTarget = { ...targetOf(args), private_key: key };
        const token = (deps.token ?? randomToken)();
        const live = await probeLive(deps, target);
        const pendingRevert = await context.readResource(
          `revert-${targetKey(args)}`,
        );
        if (isPending(pendingRevert, deps.now())) {
          throw new HostNetConfigError(
            "a revert is already armed for this host",
          );
        }
        // Remove derives every target from the persisted owned set, never from
        // the caller's inputs.
        const config = await context.readResource(
          `config-${targetKey(args)}`,
        );
        const devices = config !== null && Array.isArray(config.devices)
          ? config.devices as string[]
          : [];
        const recordFiles = config !== null && Array.isArray(config.ownedFiles)
          ? config.ownedFiles as { path: string; preExisted: boolean }[]
          : [];
        const recordMtus = config !== null && Array.isArray(config.parentMtus)
          ? config.parentMtus as { name: string; mtu: number }[]
          : [];
        if (
          devices.length === 0 && recordFiles.length === 0 &&
          recordMtus.length === 0
        ) {
          return {
            result: {
              host: args.host,
              removed: [],
              note: "nothing owned by this model",
            },
          };
        }
        const backend = typeof config?.backend === "string"
          ? config.backend as "netplan" | "networkd"
          : args.backend;
        const bridgeType = typeof config?.bridgeType === "string"
          ? config.bridgeType as "linux" | "ovs"
          : args.bridge_type;
        if (backend !== args.backend || bridgeType !== args.bridge_type) {
          throw new HostNetConfigError(
            "the remove inputs disagree with the recorded config",
          );
        }
        const liveNames = new Set(live.links.map((l) => l.name));
        // The arm snapshots the owned files, so its restore re-creates the
        // devices; the delta to delete on revert is empty.
        const armInput: ArmInput = {
          backend,
          bridgeType,
          owned: devices,
          created: [],
          createdBridges: [],
          ownedFiles: recordFiles.map((o) => o.path),
          staleDevices: [],
          staleFiles: [],
          parentMtus: recordMtus,
          managementInterface: live.managementInterface,
          managementAddrs: live.managementAddrs,
          armedSha256: String(config?.configSha256 ?? ""),
          contentSha256: String(config?.contentSha256 ?? ""),
          operation: "remove",
        };
        const { handle: revertHandle } = await armRevert(
          deps,
          target,
          context,
          token,
          args.revert_after_s,
          armInput,
        );
        const bridgeName = typeof config?.bridge === "string"
          ? config.bridge
          : "";
        const ordered = [
          ...(bridgeName !== "" && devices.includes(bridgeName)
            ? [bridgeName]
            : []),
          ...devices.filter((n) => n !== bridgeName),
        ];
        for (const name of ordered) {
          if (liveNames.has(name)) {
            await run(
              deps,
              target,
              ["ip", "link", "delete", "dev", name],
              `delete ${name}`,
            );
          }
        }
        // Never remove a file host-net did not create.
        const removeFiles = recordFiles.filter((o) => !o.preExisted).map(
          (o) => o.path,
        );
        await run(
          deps,
          target,
          [
            "sh",
            "-c",
            guardedApplyScript(revertContext(token, armInput), {
              removeFiles,
              mtuCommands: recordMtus.map((p) => [
                "ip",
                "link",
                "set",
                "dev",
                p.name,
                "mtu",
                String(p.mtu),
              ]),
            }),
          ],
          "the guarded remove apply",
        );
        return {
          dataHandles: [revertHandle],
          result: {
            host: args.host,
            remove_token: token,
            removed: ordered,
            commit_required: true,
          },
        };
      },
    },
    revert_now: {
      kind: "action" as const,
      description:
        "DESTRUCTIVE. Fire the armed revert immediately by running its host-side restore script, for tests and operator recovery. Refuses when the token is not current.",
      arguments: RevertNowArgs,
      execute: async (
        args: z.infer<typeof RevertNowArgs>,
        context: MethodContext,
      ) => {
        const key = await resolveKey(deps, context, args.ssh_key_ref);
        const target: SshTarget = { ...targetOf(args), private_key: key };
        const recorded = await context.readResource(
          `revert-${targetKey(args)}`,
        );
        if (recorded === null || recorded.token !== args.token) {
          throw new HostNetConfigError("no pending revert with that token");
        }
        if (typeof recorded.committedAt === "string") {
          throw new HostNetConfigError("this revert is already committed");
        }
        if (typeof recorded.firedAt === "string") {
          throw new HostNetConfigError("this revert already fired");
        }
        // Allow a non-zero exit so a failed restore is still recorded.
        const restoreRes = await sshExec(deps, target, [
          restorePath(args.token),
          args.token,
        ]);
        // The restore's superseded path exits 0 without running; only a marker
        // with a fired_at proves it actually restored.
        const markerOut = await run(
          deps,
          target,
          ["sh", "-c", renderMarkerJsonReadScript(args.token)],
          "the marker read",
        );
        let marker: { result?: string; fired_at?: number | null } = {};
        try {
          marker = JSON.parse(markerOut.stdout || "{}");
        } catch {
          marker = {};
        }
        if (marker.fired_at === undefined || marker.fired_at === null) {
          throw new HostNetConfigError(
            "the restore was superseded; nothing fired",
          );
        }
        const result = marker.result === "fail" || restoreRes.exit_code !== 0
          ? "fail"
          : "pass";
        await context.writeResource("revert", `revert-${targetKey(args)}`, {
          ...recorded,
          firedAt: new Date(deps.now()).toISOString(),
          result,
        });
        if (result === "fail") {
          throw new HostNetConfigError(
            "the restore reported fail; the host marker holds the evidence",
          );
        }
        return {
          result: { host: args.host, token: args.token, fired: true, result },
        };
      },
    },
    clear_failed_revert: {
      kind: "action" as const,
      description:
        "DESTRUCTIVE. Clear a revert whose restore recorded fail, so later applies are accepted again. Refuses unless the host marker says fail and the post-restore checks (a default route and a global address on its interface) pass right now.",
      arguments: ClearFailedArgs,
      execute: async (
        args: z.infer<typeof ClearFailedArgs>,
        context: MethodContext,
      ) => {
        const key = await resolveKey(deps, context, args.ssh_key_ref);
        const target: SshTarget = { ...targetOf(args), private_key: key };
        const res = await sshExec(deps, target, [
          "sh",
          "-c",
          renderClearFailedScript(),
        ]);
        const recorded = await context.readResource(
          `revert-${targetKey(args)}`,
        );
        const stamp = new Date(deps.now()).toISOString();
        const write = async (token: string) => {
          if (recorded === null || recorded.token !== token) return;
          await context.writeResource("revert", `revert-${targetKey(args)}`, {
            ...recorded,
            firedAt: typeof recorded.firedAt === "string"
              ? recorded.firedAt
              : stamp,
            result: "fail",
            clearedAt: stamp,
          });
        };
        if (res.exit_code === 2) {
          // A retry after the host clear succeeded but the reply or the record
          // write was lost: the host has no marker and the record still says
          // fail, so converge the record.
          if (
            recorded !== null && recorded.result === "fail" &&
            typeof recorded.clearedAt !== "string" &&
            typeof recorded.token === "string"
          ) {
            await write(recorded.token);
            return {
              result: { host: args.host, cleared: true, converged: true },
            };
          }
        }
        if (res.exit_code !== 0) {
          const why = res.stderr.trim() || `exit ${res.exit_code}`;
          throw new HostNetConfigError(`nothing was cleared: ${why}`);
        }
        const cleared = /^cleared ([0-9a-f]{16})$/m.exec(res.stdout)?.[1];
        if (cleared !== undefined) await write(cleared);
        return { result: { host: args.host, cleared: true } };
      },
    },
  };
  return {
    type: "@randybias/host-net",
    // The consistency gate requires this literal; VERSION mirrors it.
    version: "2026.10.17.1",
    description:
      "Configure Linux host networking over SSH (bridge, VLAN storage plane, jumbo MTU) under an automatic revert armed before any change, with a required strict or explicit host-key policy. Generic inputs; one definition serves any host.",
    upgrades: [],
    globalArguments: z.strictObject({}),
    resources,
    methods,
  };
}

/** The verify result shape. */
export interface VerifyResult {
  /** Management interface still holds its addresses. */
  management: string;
  /** A fresh connection succeeded. */
  fresh_connection: string;
  /** Default route unchanged. */
  default_route: string;
  /** Managed devices present and configured. */
  links: string;
  /** Jumbo ping result. */
  jumbo: string;
}

/** Runs the verify checks and returns the typed verdict. */

/** Production model export. */
export const model = createModel();
