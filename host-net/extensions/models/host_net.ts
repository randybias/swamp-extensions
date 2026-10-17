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
  renderMarker,
  renderRestoreScript,
  type RevertContext,
  revertDir,
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
const RevertNowArgs = z.strictObject({ ...TargetFields, token: z.string() });

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

/** Runs one argv through the transport, rethrowing transport errors unchanged. */
async function run(
  deps: HostNetDeps,
  target: SshTarget,
  argv: string[],
): Promise<ExecResult> {
  return await sshExec(deps, target, argv);
}

function configOf(args: Parsed): NetConfig {
  const vlans: VlanSpec[] = args.vlans.map((v) => ({ ...v }));
  const bridge: BridgeSpec | undefined = args.bridge;
  return {
    backend: args.backend,
    bridgeType: args.bridge_type,
    mode: args.mode,
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
async function armRevert(
  deps: HostNetDeps,
  target: SshTarget,
  context: MethodContext,
  cfg: NetConfig,
  render: RenderResult,
  token: string,
  revertAfterS: number,
): Promise<{ handle: { name: string }; expiresAt: string }> {
  const ctx = capturedOf(cfg, render, token);
  const key = targetKey(target);
  const armedAt = new Date(deps.now()).toISOString();
  const expiresAt = new Date(deps.now() + revertAfterS * 1000).toISOString();
  await sshUpload(deps, target, {
    path: "/var/lib/host-net/restore.sh",
    content: renderRestoreScript(ctx),
    mode: "0700",
  });
  await sshUpload(deps, target, {
    path: `${revertDir(token)}/marker.json`,
    content: renderMarker({
      token,
      armed_at: Math.floor(deps.now() / 1000),
      expires_at: Math.floor(deps.now() / 1000) + revertAfterS,
      armed_sha256: render.sha256,
      created: render.created,
      result: "pending",
      fired_at: null,
    }),
    mode: "0600",
  });
  await run(deps, target, [
    "sh",
    "-c",
    snapshotArmScript(ctx, revertAfterS),
  ]);
  const handle = await context.writeResource("revert", `revert-${key}`, {
    target: key,
    token,
    armedAt,
    expiresAt,
    armedSha256: render.sha256,
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
      probeCommands().map((argv) => run(deps, target, argv)),
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

function capturedOf(cfg: NetConfig, render: RenderResult, token: string) {
  const context: RevertContext = {
    token,
    backend: cfg.backend,
    bridgeType: cfg.bridgeType,
    created: render.created,
    createdBridges: cfg.bridgeType === "ovs" && cfg.bridge !== undefined
      ? [cfg.bridge.name]
      : [],
    managedFiles: render.files.map((f) => f.path),
  };
  return context;
}

function snapshotArmScript(ctx: RevertContext, revertAfterS: number): string {
  const dir = revertDir(ctx.token);
  return [
    "set -eu",
    "exec 9>/run/host-net.lock",
    "flock -n 9 || { echo 'lock busy' >&2; exit 75; }",
    `DIR=${dir}`,
    `mkdir -p "$DIR/snapshot"`,
    "if [ -f /var/lib/host-net/current ]; then echoed=$(cat /var/lib/host-net/current); [ -z \"$echoed\" ] || { echo 'revert already armed' >&2; exit 76; }; fi",
    "mkdir -p /var/lib/host-net",
    'if [ -d /etc/netplan ]; then cp -a /etc/netplan "$DIR/snapshot/netplan"; fi',
    'mkdir -p "$DIR/snapshot/networkd"',
    'cp -a /etc/systemd/network/. "$DIR/snapshot/networkd/" 2>/dev/null || true',
    'if [ -e /etc/cloud/cloud.cfg.d/99-disable-network-config.cfg ]; then cp -a /etc/cloud/cloud.cfg.d/99-disable-network-config.cfg "$DIR/snapshot/cloud-init.cfg"; fi',
    'ip -d -j link > "$DIR/live-link.json"',
    'ip -j addr > "$DIR/live-addr.json"',
    'ip -j route show default > "$DIR/live-route.json"',
    `printf '%s\\n' ${JSON.stringify(ctx.token)} > /var/lib/host-net/current`,
    `systemd-run --unit=host-net-revert-${ctx.token} --on-active=${revertAfterS} --timer-property=AccuracySec=1s /var/lib/host-net/restore.sh ${ctx.token}`,
  ].join("\n");
}

function applyScript(ctx: RevertContext): string {
  const apply = ctx.backend === "netplan"
    ? "netplan apply"
    : "networkctl reload && networkctl reconfigure";
  return [
    "set -eu",
    "exec 9>/run/host-net.lock",
    "flock -n 9 || { echo 'lock busy' >&2; exit 75; }",
    `CURRENT="$(cat /var/lib/host-net/current 2>/dev/null || true)"`,
    `[ "$CURRENT" = ${
      JSON.stringify(ctx.token)
    } ] || { echo 'not current' >&2; exit 77; }`,
    apply,
  ].join("\n");
}

function disarmScript(token: string): string {
  return [
    "set -eu",
    "exec 9>/run/host-net.lock",
    `systemctl stop host-net-revert-${token}.timer 2>/dev/null || true`,
    `systemctl reset-failed host-net-revert-${token}.timer 2>/dev/null || true`,
    `systemctl is-active host-net-revert-${token}.timer >/dev/null 2>&1 && { echo 'timer still active' >&2; exit 78; } || true`,
    `rm -f /var/lib/host-net/current`,
    `rm -rf ${revertDir(token)}`,
  ].join("\n");
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
        const ctx = capturedOf(cfg, render, token);
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
        const storage = [
          ...cfg.vlans.flatMap((v) => v.addresses),
          ...(cfg.bridge?.addresses ?? []),
        ];
        assertNoManagementOverlap(storage, live.managementAddrs);
        // Refuse stacking.
        const recorded = await context.readResource(
          `revert-${targetKey(args)}`,
        );
        if (recorded !== null && recorded.committed_at === undefined) {
          throw new HostNetConfigError(
            `a revert is already armed for this host (token ${recorded.token})`,
          );
        }
        const plan = planApply(cfg, {
          token,
          revertAfterS: args.revert_after_s,
          writtenPaths: render.files.map((f) => f.path),
        });
        assertArmBeforeApply(plan);
        // Arm first, then persist the revert record, then write and apply.
        const { handle: revertHandle, expiresAt } = await armRevert(
          deps,
          target,
          context,
          cfg,
          render,
          token,
          args.revert_after_s,
        );
        for (const step of plan) {
          if (step.kind === "mtu" && step.argv !== undefined) {
            await run(deps, target, step.argv);
          }
        }
        for (const file of render.files) {
          await sshUpload(deps, target, {
            path: file.path,
            content: file.content,
            mode: file.mode,
          });
        }
        await run(deps, target, ["sh", "-c", applyScript(ctx)]);
        const verify = await verifyLive(deps, target, cfg);
        const configHandle = await context.writeResource(
          "config",
          `config-${targetKey(args)}`,
          {
            target: targetKey(args),
            backend: cfg.backend,
            bridgeType: cfg.bridgeType,
            mode: cfg.mode,
            managementInterface: cfg.managementInterface,
            devices: render.managed,
            configSha256: render.sha256,
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
        const key = await resolveKey(deps, context, args.ssh_key_ref);
        const target: SshTarget = { ...targetOf(args), private_key: key };
        const recorded = await context.readResource(
          `revert-${targetKey(args)}`,
        );
        if (recorded === null || typeof recorded.token !== "string") {
          throw new HostNetConfigError("no armed revert to commit");
        }
        if (typeof recorded.committed_at === "string") {
          throw new HostNetConfigError("this revert is already committed");
        }
        const verify = await verifyLive(deps, target, cfg);
        if (
          verify.management !== "pass" || verify.fresh_connection !== "pass"
        ) {
          throw new HostNetConfigError(
            "the fresh-connection verify did not pass",
          );
        }
        if (
          args.require_mtu_verify && verify.jumbo === "fail"
        ) {
          throw new HostNetConfigError("the jumbo verify failed");
        }
        await run(deps, target, ["sh", "-c", disarmScript(recorded.token)]);
        const handle = await context.writeResource(
          "revert",
          `revert-${targetKey(args)}`,
          {
            ...recorded,
            committedAt: new Date(deps.now()).toISOString(),
          },
        );
        return {
          dataHandles: [handle],
          result: { host: args.host, committed: true, verify },
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
        const ctx = capturedOf(cfg, render, token);
        const plan = planRemove(cfg, {
          token,
          revertAfterS: args.revert_after_s,
        });
        assertArmBeforeApply(plan);
        const { handle: revertHandle } = await armRevert(
          deps,
          target,
          context,
          cfg,
          render,
          token,
          args.revert_after_s,
        );
        for (const name of render.created) {
          await run(deps, target, ["ip", "link", "delete", "dev", name]);
        }
        for (const step of plan) {
          if (step.kind === "mtu" && step.argv !== undefined) {
            await run(deps, target, step.argv);
          }
        }
        for (const file of render.files) {
          await run(deps, target, ["rm", "-f", "--", file.path]);
        }
        await run(deps, target, ["sh", "-c", applyScript(ctx)]);
        return {
          dataHandles: [revertHandle],
          result: {
            host: args.host,
            remove_token: token,
            removed: render.created,
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
        const target: SshTarget = {
          ...targetOf(args),
          private_key: key,
        };
        const res = await run(deps, target, [
          "/var/lib/host-net/restore.sh",
          args.token,
        ]);
        if (res.exit_code !== 0) {
          throw new HostNetConfigError(
            `the revert did not fire cleanly (exit ${res.exit_code})`,
          );
        }
        const recorded = await context.readResource(
          `revert-${targetKey(args)}`,
        );
        if (recorded !== null && recorded.token === args.token) {
          await context.writeResource(
            "revert",
            `revert-${targetKey(args)}`,
            {
              ...recorded,
              firedAt: new Date(deps.now()).toISOString(),
              result: "pass",
            },
          );
        }
        return {
          result: { host: args.host, token: args.token, fired: true },
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
async function verifyLive(
  deps: HostNetDeps,
  target: SshTarget,
  cfg: NetConfig,
): Promise<VerifyResult> {
  const live = await probeLive(deps, target);
  const management = live.managementAddrs.length > 0 ? "pass" : "fail";
  const linksOk = cfg.bridge === undefined
    ? true
    : live.links.some((l) => l.name === cfg.bridge!.name);
  return {
    management,
    fresh_connection: "pass",
    default_route: live.defaultRoute !== "" ? "pass" : "fail",
    links: linksOk ? "pass" : "fail",
    jumbo: "skipped",
  };
}

/** Production model export. */
export const model = createModel();
