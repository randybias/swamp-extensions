/**
 * Swamp extension model for a WireGuard mesh node.
 *
 * One definition renders and applies the config of any node of any mesh: the
 * mesh data and the target node arrive as method arguments. Rendering is pure;
 * pushing goes through an injectable SSH transport.
 *
 * @module
 */

import { z } from "npm:zod@4.3.6";
import {
  applyScript,
  CONFIRM_REFUSED,
  confirmScript,
  DEFAULT_COMMAND_TIMEOUT_S,
  deleteScript,
  getScript,
  isHostKeyLine,
  parseDump,
  parseRollbackDir,
  sha256Hex,
  type SshTarget,
  sshTransport,
  type Transport,
  TransportError,
  type TransportResult,
} from "./_lib/push.ts";
import { denoDeps, type SshDeps } from "./_lib/ssh.ts";
import {
  IFACE_RE,
  KeySchema,
  type Mesh,
  MeshSchema,
  NodeSchema,
  renderNode,
} from "./_lib/render.ts";

const GlobalArgsSchema = z.strictObject({});

/** A legacy `{type, key}` host key: exactly those two keys, both strings. */
function isLegacyKey(v: unknown): v is { type: string; key: string } {
  if (v === null || typeof v !== "object" || Array.isArray(v)) return false;
  const keys = Object.keys(v);
  const o = v as Record<string, unknown>;
  return keys.length === 2 && keys.includes("type") && keys.includes("key") &&
    typeof o.type === "string" && typeof o.key === "string";
}

const SshSchema = z.strictObject({
  host: z.string().min(1).max(253),
  user: z.string().regex(/^[a-z_][a-z0-9_-]{0,31}$/),
  port: z.number().int().min(1).max(65535).default(22),
  // A preprocess (not a transform) keeps the enum and description visible to
  // `swamp model type describe`; `accept-new` maps to insecure_tofu and
  // `insecure` is refused with a clear message.
  host_key_policy: z.preprocess(
    (v) => (v === "accept-new" ? "insecure_tofu" : v),
    z.enum(["strict", "insecure_tofu"], {
      error: (issue: { input?: unknown }) =>
        issue.input === "insecure"
          ? "host_key_policy insecure was removed; use insecure_tofu (learns and pins the first key) or strict"
          : undefined,
    }).describe(
      "How the node's SSH host key is checked; there is no default. insecure_tofu learns the first keys seen and pins them for later steps.",
    ),
  ),
  // A preprocess turns the legacy `{type, key}` objects into ssh-keyscan lines
  // so the item shape still renders; the grammar is enforced on the line.
  host_keys: z.preprocess(
    (v) =>
      Array.isArray(v)
        ? v.map((item) => isLegacyKey(item) ? `${item.type} ${item.key}` : item)
        : v,
    z.array(z.string().max(8192).refine(isHostKeyLine, "an ssh-keyscan line"))
      .max(64).default([]),
  ).describe(
    "Pinned ssh-keyscan-format lines; required for strict.",
  ),
  private_key: z.string().max(65536).meta({ sensitive: true }).optional()
    .describe(
      "SSH private key, loaded into a temporary ssh-agent over stdin. Pass a vault reference.",
    ),
  connect_timeout_s: z.number().int().min(1).max(120).default(15).describe(
    "Connection timeout in seconds.",
  ),
  command_timeout_s: z.number().int().min(10).max(3600).default(
    DEFAULT_COMMAND_TIMEOUT_S,
  ).describe(
    "Deadline in seconds for one remote command; a hung session is killed and reported as a transport error.",
  ),
  max_output_bytes: z.number().int().min(1).max(104857600).optional().describe(
    "Cap in bytes on captured output.",
  ),
});

const IfaceSchema = z.string().regex(IFACE_RE).default("wg0");

const PeerSummary = z.strictObject({
  name: z.string(),
  public_key: z.string(),
  allowed_ips: z.array(z.string()),
  endpoint: z.string().optional(),
  keepalive: z.number().optional(),
  carries: z.array(z.string()).optional(),
});

const RenderedSchema = z.strictObject({
  node: z.string(),
  interface: z.string(),
  config: z.string(),
  config_sha256: z.string(),
  peers: z.array(PeerSummary),
  excluded: z.array(z.string()),
  node_endpoint: z.string().optional(),
});

const StateSchema = z.strictObject({
  node: z.string(),
  interface: z.string(),
  status: z.enum(["applied", "deleted"]),
  peers: z.array(z.string()),
  config_sha256: z.string().optional(),
  observed_at: z.string(),
});

const LiveSchema = z.strictObject({
  node: z.string(),
  interface: z.string(),
  peers: z.array(z.strictObject({
    public_key: z.string(),
    endpoint: z.string().optional(),
    allowed_ips: z.array(z.string()),
    latest_handshake: z.number(),
  })),
  observed_at: z.string(),
});

/** What may be read back: 2026.10.17.4 stored `{type, key}` objects. */
const StoredHostKeysSchema = z.strictObject({
  node: z.string(),
  host: z.string(),
  port: z.number().int(),
  host_keys: z.array(
    z.union([
      z.string().max(8192),
      z.strictObject({ type: z.string().max(64), key: z.string().max(8192) }),
    ]),
  ).max(64),
  observed_at: z.string(),
});

/** A resource-name-safe key for one host and port; injective for valid hosts. */
function endpointKey(host: string, port: number): string {
  const h = host.toLowerCase().replace(
    /[^a-z0-9.-]/g,
    (c) => `_${c.charCodeAt(0).toString(16)}_`,
  );
  return `${h}-${port}`;
}

const HostKeysSchema = z.strictObject({
  node: z.string(),
  host: z.string(),
  port: z.number().int(),
  host_keys: z.array(z.string().max(8192)).max(64),
  observed_at: z.string(),
});

/** Stored state of one node. */
export type NodeState = z.infer<typeof StateSchema>;

/** Overridable dependencies. */
export interface Deps {
  /** The canonical vendored SSH transport dependencies (the spawner seam). */
  ssh: SshDeps;
  /** Current time. */
  now: () => Date;
  /** Builds the transport for a target; replaces ssh entirely in tests. */
  transport?: (t: SshTarget, sshKey?: string) => Transport;
}

// deno-lint-ignore no-explicit-any
type Ctx = any;

const RenderArgs = MeshSchema.extend({
  // Accepted so one input file serves render and apply; render ignores both.
  private_key: KeySchema.meta({ sensitive: true }).optional(),
  ssh: SshSchema.optional(),
});
const ApplyArgs = MeshSchema.extend({
  private_key: KeySchema.meta({ sensitive: true }).describe(
    "Node private key; pass a vault reference. Sent over stdin, never argv.",
  ),
  ssh: SshSchema,
});
const GetArgs = z.strictObject({
  node: NodeSchema.shape.name,
  interface: IfaceSchema,
  ssh: SshSchema,
});
const DeleteArgs = GetArgs.extend({
  acknowledge_reachability_risk: z.boolean().describe(
    "Must be true. Confirms the SSH management path may run over the interface being removed; a remote rollback restores it if this session is cut.",
  ),
  rollback_seconds: z.number().int().min(30).max(3600).default(120).describe(
    "Seconds the remote rollback waits before restoring the interface unless teardown is verified.",
  ),
});

/** The model type, as a top-level literal so swamp can index it statically. */
export const type = "@randybias/wireguard-mesh";

/** Builds the model with overridable dependencies. */
export function createModel(deps: Partial<Deps> = {}) {
  const d: Deps = {
    ssh: deps.ssh ?? denoDeps,
    now: deps.now ?? (() => new Date()),
    transport: deps.transport,
  };
  const transportFor = (ssh: z.infer<typeof SshSchema>): Transport => {
    const target: SshTarget = {
      host: ssh.host,
      user: ssh.user,
      port: ssh.port,
      host_key_policy: ssh.host_key_policy,
      host_keys: ssh.host_keys,
      ...(ssh.private_key !== undefined
        ? { private_key: ssh.private_key }
        : {}),
      connect_timeout_s: ssh.connect_timeout_s,
      command_timeout_s: ssh.command_timeout_s,
      ...(ssh.max_output_bytes !== undefined
        ? { max_output_bytes: ssh.max_output_bytes }
        : {}),
    };
    return d.transport ? d.transport(target) : sshTransport(target, d.ssh);
  };
  const renderOf = async (mesh: Mesh) => {
    const r = renderNode(mesh);
    return {
      node: mesh.node.name,
      interface: mesh.interface,
      config: r.config,
      config_sha256: await sha256Hex(r.config),
      peers: r.peers,
      excluded: r.excluded,
      ...(r.node_endpoint ? { node_endpoint: r.node_endpoint } : {}),
    };
  };
  const failRemote = (res: { code: number; stderr: string }, what: string) => {
    throw new TransportError(
      "remote",
      `${what} failed on the node (exit ${res.code})`,
    );
  };
  const noChange = (res: TransportResult) => /^changed=0$/m.test(res.stdout);

  /**
   * Confirms a successful mutation over a FRESH management connection and
   * disarms the matching rollback. If the fresh connection or the disarm
   * script fails, the rollback is left armed and restores the previous state.
   */
  const confirmReachability = async (
    target: z.infer<typeof SshSchema>,
    iface: string,
    stdout: string,
    what: string,
  ): Promise<void> => {
    const rb = parseRollbackDir(stdout, iface);
    if (!rb) {
      throw new TransportError(
        "remote",
        `${what} did not report its rollback directory, so reachability cannot be confirmed; the rollback stays armed`,
      );
    }
    try {
      const res = await transportFor(target)(confirmScript(iface, rb));
      if (res.code === CONFIRM_REFUSED.gone) {
        throw new TransportError(
          "remote",
          `${what} was undone: the node's rollback ran before the change could be confirmed, so the previous state is back and nothing was recorded`,
        );
      }
      if (res.code === CONFIRM_REFUSED.superseded) {
        throw new TransportError(
          "remote",
          `${what} was superseded by a newer change on the node and cannot be confirmed; nothing was recorded`,
        );
      }
      if (res.code !== 0) {
        throw new TransportError(
          "remote",
          `${what} could not be confirmed on a fresh connection (exit ${res.code}); the rollback will restore the previous state`,
        );
      }
    } catch (e) {
      if (e instanceof TransportError && e.reason !== "remote") {
        throw new TransportError(
          e.reason,
          `${what} changed the node but a fresh management connection failed (${e.reason}); the rollback will restore it`,
        );
      }
      throw e;
    }
  };

  /**
   * Normalizes a stored host-key record to port-aware ssh-keyscan lines: a
   * published 2026.10.17.4 record held `[{type,key}]` objects with no host
   * field, which the canonical transport would read as `[object Object]`.
   */
  const normalizeStoredKeys = (
    keys: unknown[],
    host: string,
    port: number,
  ): string[] => {
    const field = port === 22 ? host : `[${host}]:${port}`;
    const out: string[] = [];
    for (const key of keys) {
      if (typeof key === "string") {
        if (isHostKeyLine(key)) out.push(key);
        continue;
      }
      if (key !== null && typeof key === "object") {
        const type = (key as { type?: unknown }).type;
        const blob = (key as { key?: unknown }).key;
        if (typeof type === "string" && typeof blob === "string") {
          const line = `${field} ${type} ${blob}`;
          // A stored value with whitespace or a newline is not a valid pin.
          if (isHostKeyLine(line)) out.push(line);
        }
      }
    }
    return out;
  };

  /**
   * Resolves trust-on-first-use for `accept-new`: a key accepted on an earlier
   * run is pinned here, so a key that later changes is refused rather than
   * retrusted. Returns a target and a callback that records newly accepted
   * keys after the connection succeeds.
   */
  const establish = async (
    context: Ctx,
    name: string,
    ssh: z.infer<typeof SshSchema>,
  ): Promise<
    {
      target: z.infer<typeof SshSchema>;
      remember: (res: TransportResult) => Promise<z.infer<typeof SshSchema>>;
    }
  > => {
    if (ssh.host_key_policy !== "insecure_tofu") {
      return { target: ssh, remember: () => Promise.resolve(ssh) };
    }
    const recordName = `${name}-hostkeys-${endpointKey(ssh.host, ssh.port)}`;
    const unreadable = () =>
      new TransportError(
        "host-key",
        `stored host-key record for ${name} (${ssh.host}:${ssh.port}) is unreadable; delete it to re-learn`,
      );
    // The pin for THIS endpoint: its own keyed record, else a per-node record
    // written by 2026.10.17.4 and earlier when it names the same host and port.
    // A record for another endpoint is never read here and never overwritten.
    let stored: z.infer<typeof StoredHostKeysSchema> | undefined;
    let legacy = false;
    const keyed = await context.readResource(recordName);
    if (keyed !== null && keyed !== undefined) {
      const parsed = StoredHostKeysSchema.safeParse(keyed);
      if (
        !parsed.success || parsed.data.host !== ssh.host ||
        parsed.data.port !== ssh.port
      ) throw unreadable();
      stored = parsed.data;
    } else {
      const old = await context.readResource(`${name}-hostkeys`);
      if (old !== null && old !== undefined) {
        const parsed = StoredHostKeysSchema.safeParse(old);
        if (!parsed.success) throw unreadable();
        if (parsed.data.host === ssh.host && parsed.data.port === ssh.port) {
          stored = parsed.data;
          legacy = true;
        }
      }
    }
    if (stored) {
      const lines = normalizeStoredKeys(
        stored.host_keys as unknown[],
        stored.host,
        stored.port,
      );
      // A record exists for this endpoint but nothing in it is a usable pin.
      // Fail closed rather than re-learning (and overwriting) on a later run.
      if (lines.length === 0) throw unreadable();
      const pinned = stored;
      return {
        target: { ...ssh, host_key_policy: "strict", host_keys: lines },
        // Move a per-node (or object-form) record to this endpoint's own key
        // only after the operation has succeeded.
        remember: async () => {
          if (
            legacy ||
            (pinned.host_keys as unknown[]).some((k) => typeof k !== "string")
          ) {
            await context.writeResource("hostkeys", recordName, {
              node: name,
              host: pinned.host,
              port: pinned.port,
              host_keys: lines,
              observed_at: d.now().toISOString(),
            });
          }
          return {
            ...ssh,
            host_key_policy: "strict" as const,
            host_keys: lines,
          };
        },
      };
    }
    return {
      target: ssh,
      remember: async (res) => {
        const keys = (res.known_hosts ?? "").split(/\r?\n/)
          .map((line) => line.trim()).filter((line) => line !== "");
        if (keys.length === 0) {
          // Without the accepted key there is nothing to pin the later steps
          // of this operation to, so none may run on trust-on-first-use.
          throw new TransportError(
            "host-key",
            "no host key was recorded for this first connection; later steps need a pinned key",
          );
        }
        await context.writeResource("hostkeys", recordName, {
          node: name,
          host: ssh.host,
          port: ssh.port,
          host_keys: keys,
          observed_at: d.now().toISOString(),
        });
        return { ...ssh, host_key_policy: "strict" as const, host_keys: keys };
      },
    };
  };

  return {
    type,
    version: "2026.10.17.6",
    description:
      "Render one WireGuard node's wg0.conf from mesh data and apply it to that node over SSH. One generic model for any node of any mesh; the private key is delivered over stdin and never appears in the config text.",
    upgrades: [
      {
        toVersion: "2026.10.17.2",
        description:
          "Security and idempotency fixes (host-key pinning, atomic reload, armed rollback); no stored-attribute changes",
        upgradeAttributes: (old: Record<string, unknown>) => old,
      },
      {
        toVersion: "2026.10.17.3",
        description:
          "apply/rollback correctness fixes (atomic file restore, live-convergence no-op, replacement teardown, remote lock); no stored-attribute changes",
        upgradeAttributes: (old: Record<string, unknown>) => old,
      },
      {
        toVersion: "2026.10.17.4",
        description:
          "Route reconciliation, generation-guarded rollback under the lock, and fresh-connection confirmation; no stored-attribute changes",
        upgradeAttributes: (old: Record<string, unknown>) => old,
      },
      {
        toVersion: "2026.10.17.5",
        description:
          "Replaced the local SSH transport with the canonical vendored ssh.ts (typed exit-255 error, authoritative host-key pins, no content digest on argv); host_key_policy is strict|insecure_tofu (accept-new maps to insecure_tofu, insecure is refused); legacy {type,key} host_keys are converted to ssh-keyscan lines on read. TOFU pins are kept per node, host and port (<node>-hostkeys-<host>-<port>); a <node>-hostkeys record written by 2026.10.17.4 pins its own host and port and moves to the keyed record on first use, and a record for another endpoint is never overwritten.",
        upgradeAttributes: (old: Record<string, unknown>) => old,
      },
      {
        toVersion: "2026.10.17.6",
        description:
          "Re-vendored the canonical ssh.ts (blob 8f132c43) and dropped the remote temp-file workaround: the private key and config are streamed straight into the remote command over stdin, so no secret bytes touch remote disk; every remote command carries a bounded timeout. No stored-attribute changes.",
        upgradeAttributes: (old: Record<string, unknown>) => old,
      },
    ],
    globalArguments: GlobalArgsSchema,
    resources: {
      state: {
        description: "Last applied or deleted config of one node",
        schema: StateSchema,
        lifetime: "infinite" as const,
        garbageCollection: 10,
      },
      rendered: {
        description: "Rendered config text and resolved peers of one node",
        schema: RenderedSchema,
        lifetime: "infinite" as const,
        garbageCollection: 5,
      },
      live: {
        description: "Interface state read back from one node",
        schema: LiveSchema,
        lifetime: "infinite" as const,
        garbageCollection: 5,
      },
      hostkeys: {
        description:
          "SSH host keys accepted for one node, pinned on later runs",
        schema: HostKeysSchema,
        lifetime: "infinite" as const,
        garbageCollection: 10,
      },
    },
    methods: {
      render: {
        description:
          "READ-ONLY. Render one node's wg0.conf from the mesh and return it with the resolved peers; the same inputs give identical bytes. The private key is never in the text: the config reads it from a key file on the node.",
        arguments: RenderArgs,
        execute: async (args: z.input<typeof RenderArgs>, context: Ctx) => {
          // `private_key` and `ssh` are accepted but ignored: rendering is pure
          // and offline and never puts the key in the text.
          const { private_key: _pk, ssh: _ssh, ...mesh } = RenderArgs.parse(
            args,
          );
          const out = await renderOf(mesh);
          const handle = await context.writeResource(
            "rendered",
            mesh.node.name,
            out,
          );
          return { dataHandles: [handle] };
        },
      },

      apply: {
        kind: "action" as const,
        description:
          "DESTRUCTIVE. Render the node's config and push it over SSH, recreating the interface when its address or routes change and restoring both files on any failure; idempotent for a proven-converged node, but an unconfirmed earlier change is never a no-op. Never capture --json output of a run with a literal private key.",
        arguments: ApplyArgs,
        execute: async (args: z.input<typeof ApplyArgs>, context: Ctx) => {
          const { private_key, ssh, ...mesh } = ApplyArgs.parse(args);
          const out = await renderOf(mesh);
          const { target, remember } = await establish(
            context,
            mesh.node.name,
            ssh,
          );
          const res = await transportFor(target)(
            applyScript(mesh.interface),
            `${private_key}\n${out.config}`,
          );
          const pinned = await remember(res);
          if (res.code !== 0) failRemote(res, "apply");
          if (noChange(res)) {
            context.logger.info("No change on {node}", {
              node: mesh.node.name,
            });
            return { dataHandles: [] };
          }
          await confirmReachability(
            pinned,
            mesh.interface,
            res.stdout,
            "apply",
          );
          context.logger.info("Applied {node}", { node: mesh.node.name });
          const state: NodeState = {
            node: mesh.node.name,
            interface: mesh.interface,
            status: "applied",
            peers: out.peers.map((p) => p.name),
            config_sha256: out.config_sha256,
            observed_at: d.now().toISOString(),
          };
          const handle = await context.writeResource(
            "state",
            mesh.node.name,
            state,
          );
          return { dataHandles: [handle] };
        },
      },

      get: {
        description:
          "READ-ONLY. Read the node's interface state with wg show: peers, endpoints, allowed IPs and latest handshake. Fails with a typed error when the node is unreachable.",
        arguments: GetArgs,
        execute: async (args: z.input<typeof GetArgs>, context: Ctx) => {
          const a = GetArgs.parse(args);
          const { target, remember } = await establish(
            context,
            a.node,
            a.ssh,
          );
          const res = await transportFor(target)(getScript(a.interface));
          await remember(res);
          if (res.code !== 0) failRemote(res, "wg show");
          const handle = await context.writeResource("live", a.node, {
            node: a.node,
            interface: a.interface,
            peers: parseDump(res.stdout),
            observed_at: d.now().toISOString(),
          });
          return { dataHandles: [handle] };
        },
      },

      delete: {
        // A "delete" kind would tombstone every node this definition holds.
        kind: "action" as const,
        description:
          "DESTRUCTIVE. Bring the node's interface down and remove its config and key file, arming a remote rollback first and requiring acknowledge_reachability_risk; an interface already down and gone is a clean no-op.",
        arguments: DeleteArgs,
        execute: async (args: z.input<typeof DeleteArgs>, context: Ctx) => {
          const a = DeleteArgs.parse(args);
          if (!a.acknowledge_reachability_risk) {
            throw new Error(
              "delete requires acknowledge_reachability_risk=true: the SSH path may run over the interface being removed",
            );
          }
          const { target, remember } = await establish(
            context,
            a.node,
            a.ssh,
          );
          const res = await transportFor(target)(
            deleteScript(a.interface, a.rollback_seconds),
          );
          const pinned = await remember(res);
          if (res.code !== 0) failRemote(res, "delete");
          if (noChange(res)) {
            context.logger.info("No change on {node}", { node: a.node });
            return { dataHandles: [] };
          }
          await confirmReachability(pinned, a.interface, res.stdout, "delete");
          context.logger.info("Deleted {node}", { node: a.node });
          const state: NodeState = {
            node: a.node,
            interface: a.interface,
            status: "deleted",
            peers: [],
            observed_at: d.now().toISOString(),
          };
          const handle = await context.writeResource("state", a.node, state);
          return { dataHandles: [handle] };
        },
      },
    },
  };
}

/** Model definition for `@randybias/wireguard-mesh`. */
export const model = {
  ...createModel(),
  type: "@randybias/wireguard-mesh",
  version: "2026.10.17.6",
} satisfies ReturnType<typeof createModel>;
