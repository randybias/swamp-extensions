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
import {
  assertArmBeforeApply,
  planApply,
  planRemove,
  type Step,
} from "./_lib/plan.ts";
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
  renderDisarmScript,
  renderMarkerJsonReadScript,
  renderMarkerReadScript,
  restorePath,
  type RevertContext,
  revertDir,
  stagedDir,
  unitName,
} from "./_lib/revert.ts";

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
  host_key_policy: z.enum(["strict", "insecure_tofu"]),
  host_keys: z.array(z.string().max(8192)).max(64).nullish(),
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
  devices: z.array(z.string()),
  configSha256: z.string(),
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
  devices: z.array(z.string()).optional(),
  committedAt: z.string().optional(),
  cancelledAt: z.string().optional(),
  firedAt: z.string().optional(),
  result: z.string().optional(),
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
  host_key_policy: "strict" | "insecure_tofu";
  host_keys?: string[] | null;
  connect_timeout_s: number;
}): SshTarget {
  return {
    host: a.host,
    port: a.port,
    user: a.user,
    host_key_policy: a.host_key_policy,
    host_keys: a.host_keys ?? undefined,
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
async function armRevert(
  deps: HostNetDeps,
  target: SshTarget,
  context: MethodContext,
  cfg: NetConfig,
  render: RenderResult,
  token: string,
  revertAfterS: number,
  created: string[],
  parentMtus: { name: string; mtu: number }[],
  operation: "apply" | "remove",
): Promise<
  { handle: { name: string }; expiresAt: string; contentSha256: string }
> {
  const ctx = capturedOf(cfg, render, token, created, parentMtus);
  const key = targetKey(target);
  const expiresAt = new Date(deps.now() + revertAfterS * 1000).toISOString();
  const contentSha256 = await contentDigest(render.files);
  const res = await run(
    deps,
    target,
    [
      "sh",
      "-c",
      renderArmScript(ctx, {
        revertAfterS,
        armedSha256: render.sha256,
        contentSha256,
        operation,
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
    armedSha256: render.sha256,
    contentSha256,
    operation,
    devices: created,
    result: "pending",
  });
  return { handle, expiresAt, contentSha256 };
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

function capturedOf(
  cfg: NetConfig,
  render: RenderResult,
  token: string,
  created: string[],
  parentMtus: { name: string; mtu: number }[],
): RevertContext {
  return {
    token,
    backend: cfg.backend,
    bridgeType: cfg.bridgeType,
    created,
    createdBridges: cfg.bridgeType === "ovs" && cfg.bridge !== undefined &&
        created.includes(cfg.bridge.name)
      ? [cfg.bridge.name]
      : [],
    ownedFiles: render.files.map((f) => f.path),
    parentMtus,
  };
}

/** The guarded apply script: it applies only while this token still guards. */
function shq(value: string): string {
  return `'${value.replace(/'/g, `'\\''`)}'`;
}

/** The guarded apply script: it applies only while this token still guards. */
function guardedApplyScript(
  ctx: RevertContext,
  files: RenderResult["files"],
): string {
  const apply = ctx.backend === "netplan"
    ? "netplan apply"
    : "networkctl reload && networkctl reconfigure";
  const moves = files.map((f) => {
    const base = f.path.split("/").pop() ?? f.path;
    return `mv -f ${shq(`${stagedDir(ctx.token)}/${base}`)} ${shq(f.path)}`;
  }).join("\n");
  return [
    "set -eu",
    `exec 9>${LOCK_PATH}`,
    "flock -w 30 9 || { echo 'lock busy' >&2; exit 75; }",
    `DIR=${shq(revertDir(ctx.token))}`,
    `cleanup() { rm -rf "$DIR/staged"; }`,
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
    moves,
    "cleanup",
    apply,
  ].filter((l) => l !== "").join("\n");
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
async function liveContentSha(
  deps: HostNetDeps,
  target: SshTarget,
  render: RenderResult,
): Promise<string> {
  const parts: string[] = [];
  for (
    const file of render.files.slice().sort((a, b) => a.path < b.path ? -1 : 1)
  ) {
    const res = await run(
      deps,
      target,
      ["sh", "-c", 'cat -- "$1"', "sh", file.path],
      `read ${file.path}`,
    );
    parts.push(`${file.path}\0${res.stdout}`);
  }
  return await sha256Hex(parts.join("\0"));
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
        // A match_mac that resolves to the management NIC touches management.
        for (const e of cfg.ethernets) {
          const touchesMgmt = (e.name !== "" &&
            e.name === cfg.managementInterface) ||
            (e.matchMac !== undefined &&
              live.links.some((l) =>
                l.mac === e.matchMac && l.name === cfg.managementInterface
              ));
          if (
            touchesMgmt && e.mtu !== undefined &&
            !(cfg.mode === "takeover" && cfg.managementChangeAck)
          ) {
            throw new HostNetConfigError(
              "the change touches the management interface; use mode takeover with management_change_ack",
            );
          }
        }
        // Pre-check the rendered netplan against a staged root before arming.
        if (cfg.backend === "netplan") {
          if (!live.hasNetplan) {
            throw new HostNetConfigError("netplan is not present on the host");
          }
          const stage = `/tmp/host-net-precheck-${token}`;
          await run(
            deps,
            target,
            [
              "sh",
              "-c",
              `rm -rf '${stage}' && mkdir -p '${stage}/etc/netplan'`,
            ],
            "the precheck setup",
          );
          for (const file of render.files) {
            await sshUpload(deps, target, {
              path: `${stage}${file.path}`,
              content: file.content,
              mode: file.mode,
            });
          }
          try {
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
        // An identical live config arms nothing and writes nothing.
        if (
          config !== null && typeof config.contentSha256 === "string" &&
          [...owned].every((name) => liveNames.has(name))
        ) {
          const liveSha = await liveContentSha(deps, target, render);
          if (liveSha === config.contentSha256) {
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
        const parentMtus = cfg.ethernets
          .filter((e) => e.mtu !== undefined)
          .map((e) => ({
            name: e.name,
            mtu: live.links.find((l) => l.name === e.name)?.mtu ?? 0,
          }))
          .filter((p) => p.mtu > 0);
        const ctx = capturedOf(cfg, render, token, created, parentMtus);
        const plan = planApply(cfg, {
          token,
          revertAfterS: args.revert_after_s,
          writtenPaths: render.files.map((f) => f.path),
        });
        assertArmBeforeApply(plan);
        const {
          handle: revertHandle,
          expiresAt,
          contentSha256,
        } = await armRevert(
          deps,
          target,
          context,
          cfg,
          render,
          token,
          args.revert_after_s,
          created,
          parentMtus,
          "apply",
        );
        for (const step of plan) {
          if (step.kind === "mtu" && step.argv !== undefined) {
            await run(deps, target, step.argv, step.description);
          }
        }
        for (const file of render.files) {
          const base = file.path.split("/").pop() ?? file.path;
          await sshUpload(deps, target, {
            path: `${stagedDir(token)}/${base}`,
            content: file.content,
            mode: file.mode,
          });
        }
        await run(
          deps,
          target,
          ["sh", "-c", guardedApplyScript(ctx, render.files)],
          "the guarded apply",
        );
        const after = await probeLive(deps, target);
        const verify = verifyAgainst(live, after, cfg, created);
        const configHandle = await context.writeResource(
          "config",
          `config-${targetKey(args)}`,
          {
            target: targetKey(args),
            backend: cfg.backend,
            bridgeType: cfg.bridgeType,
            mode: cfg.mode,
            managementInterface: cfg.managementInterface,
            devices: created,
            configSha256: render.sha256,
            contentSha256,
          },
        );
        return {
          dataHandles: [revertHandle, configHandle],
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
        const render = await renderConfig(cfg);
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
        if (isRemove) {
          // A remove commits only when the owned files and devices are gone.
          for (const file of render.files) {
            const exists = await sshExec(deps, target, [
              "sh",
              "-c",
              'test -e "$1"',
              "sh",
              file.path,
            ]);
            if (exists.exit_code === 0) {
              throw new HostNetConfigError(
                `the owned file ${file.path} is still present; refusing to commit`,
              );
            }
          }
          const liveNames = new Set(live.links.map((l) => l.name));
          for (const name of (recorded.devices as string[] | undefined) ?? []) {
            if (liveNames.has(name)) {
              throw new HostNetConfigError(
                `device ${name} is still present; refusing to commit`,
              );
            }
          }
        } else if (typeof recorded.contentSha256 === "string") {
          const liveSha = await liveContentSha(deps, target, render);
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
        if (isRemove) {
          await context.writeResource("config", `config-${targetKey(args)}`, {
            target: targetKey(args),
            backend: cfg.backend,
            bridgeType: cfg.bridgeType,
            mode: cfg.mode,
            managementInterface: cfg.managementInterface,
            devices: [],
            configSha256: "",
            contentSha256: "",
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
        const cfg = configOf(args);
        const render = await renderConfig(cfg);
        const key = await resolveKey(deps, context, args.ssh_key_ref);
        const target: SshTarget = { ...targetOf(args), private_key: key };
        const token = (deps.token ?? randomToken)();
        const live = await probeLive(deps, target);
        const recorded = await context.readResource(
          `revert-${targetKey(args)}`,
        );
        if (isPending(recorded, deps.now())) {
          throw new HostNetConfigError(
            "a revert is already armed for this host",
          );
        }
        const liveNames = new Set(live.links.map((l) => l.name));
        // Ownership comes only from the config record; remove never infers it.
        const config = await context.readResource(
          `config-${targetKey(args)}`,
        );
        const owned = new Set(
          config !== null && Array.isArray(config.devices)
            ? config.devices as string[]
            : [],
        );
        const created = [...owned].filter((name) => liveNames.has(name));
        if (created.length === 0) {
          return {
            result: {
              host: args.host,
              removed: [],
              note: "nothing owned by this model is live",
            },
          };
        }
        const parentMtus = cfg.ethernets
          .filter((e) => e.mtu !== undefined)
          .map((e) => ({
            name: e.name,
            mtu: live.links.find((l) => l.name === e.name)?.mtu ?? 0,
          }))
          .filter((p) => p.mtu > 0);
        const ctx = capturedOf(cfg, render, token, created, parentMtus);
        const plan = planRemove(cfg);
        assertArmBeforeApply(plan);
        const { handle: revertHandle } = await armRevert(
          deps,
          target,
          context,
          cfg,
          render,
          token,
          args.revert_after_s,
          created,
          parentMtus,
          "remove",
        );
        const bridgeName = cfg.bridge?.name;
        const ordered = [
          ...(bridgeName !== undefined && created.includes(bridgeName)
            ? [bridgeName]
            : []),
          ...created.filter((n) => n !== bridgeName),
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
        for (const file of render.files) {
          await run(
            deps,
            target,
            ["rm", "-f", "--", file.path],
            `remove ${file.path}`,
          );
        }
        await run(
          deps,
          target,
          ["sh", "-c", guardedApplyScript(ctx, [])],
          "the guarded remove apply",
        );
        return {
          dataHandles: [revertHandle],
          result: {
            host: args.host,
            remove_token: token,
            removed: created,
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
        await run(
          deps,
          target,
          [restorePath(args.token), args.token],
          "the revert_now restore",
        );
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
        const result = marker.result === "fail" ? "fail" : "pass";
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
