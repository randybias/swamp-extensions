/**
 * Swamp extension model for one Syncthing node's device and folder peering,
 * driven through the Syncthing REST API.
 *
 * The API key travels only in the `X-API-Key` header. A local call sends it as
 * an in-memory request header; a remote call runs `curl --config -` on the host,
 * so the key is delivered over stdin. Plain HTTP is allowed only on a loopback
 * address. Every method is idempotent and state is keyed by a SHA-256 of the
 * node label and endpoint, never by a name alone.
 *
 * @module
 */

import { z } from "npm:zod@4.3.6";
import {
  buildDeviceSpec,
  buildFolderSpec,
  createClient,
  denoSyncthingDeps,
  deviceBody,
  deviceMatches,
  type DeviceSpec,
  folderBody,
  folderMatches,
  type FolderSpec,
  folderSpecOf,
  normalizeApiUrl,
  type SyncthingAccess,
  type SyncthingClient,
  type SyncthingDeps,
  SyncthingError,
} from "./_lib/syncthing.ts";
import {
  HOST_RE,
  type HostKeyPolicy,
  sha256Hex,
  SshConfigError,
  SshError,
  type SshTarget,
  USER_RE,
} from "./_lib/ssh.ts";

/** A handle returned by `writeResource`. */
export interface DataHandle {
  /** Data artifact name. */
  name: string;
  /** Declared resource spec name. */
  specName: string;
  /** `"resource"` or `"file"`. */
  kind: string;
  /** Unique data id. */
  dataId: string;
  /** Version number of this write. */
  version: number;
  /** Size of the written content in bytes. */
  size: number;
}

/** What a method returns to swamp. */
export interface MethodResult {
  /** Resources written by the method. */
  dataHandles?: DataHandle[];
  /** Typed result for the caller. */
  result?: unknown;
}

/** The subset of the swamp method context this model uses. */
export interface MethodContext {
  /** Structured logger. */
  logger: {
    /** Info level. */
    info: (message: string, fields?: Record<string, unknown>) => void;
    /** Warn level. */
    warn: (message: string, fields?: Record<string, unknown>) => void;
  };
  /** Persists one resource and returns its handle. */
  writeResource: (
    specName: string,
    instanceName: string,
    data: Record<string, unknown>,
  ) => Promise<DataHandle>;
}

/** A resource specification exposed by the model. */
export interface ResourceSpec {
  /** Human-readable description. */
  description: string;
  /** Zod schema the resource is validated against. */
  schema: z.ZodType;
  /** Retention lifetime. */
  lifetime: string;
  /** Number of versions to keep. */
  garbageCollection: number;
}

/** A method exposed by the model. */
export interface PeerMethod {
  /** `action` for a non-lifecycle verb. */
  kind?: "action";
  /** Description. */
  description: string;
  /** Argument schema. */
  arguments: z.ZodType;
  /** Runs the method. */
  execute: (args: unknown, context: MethodContext) => Promise<MethodResult>;
}

/** The model definition returned by {@link createModel}. */
export interface PeerModel {
  /** Model type. */
  type: string;
  /** CalVer version. */
  version: string;
  /** One-line summary. */
  description: string;
  /** Empty globals. */
  globalArguments: z.ZodType;
  /** Resource specs. */
  resources: Record<string, ResourceSpec>;
  /** Methods. */
  methods: Record<string, PeerMethod>;
}

const SSH_FIELDS = {
  host: z.string().regex(HOST_RE).max(253).nullish().describe(
    "SSH target host; required for the ssh transport.",
  ),
  port: z.number().int().min(1).max(65535).default(22).describe("SSH port."),
  user: z.string().regex(USER_RE).nullish().describe(
    "SSH user; required for the ssh transport.",
  ),
  host_key_policy: z.enum(["strict"]).nullish().describe(
    "Required for the ssh transport, and only strict is offered: the host is verified against host_keys on every run.",
  ),
  host_keys: z.array(z.string().max(8192)).min(1).max(64).nullish().describe(
    "ssh-keyscan-format lines; required for the ssh transport, and the only accepted host keys.",
  ),
  private_key: z.string().max(65536).meta({ sensitive: true }).nullish()
    .describe("Private key text; delivered over stdin to a short-lived agent."),
  password: z.string().max(4096).meta({ sensitive: true }).nullish().describe(
    "Password, delivered through an askpass helper; prefer private_key.",
  ),
  connect_timeout_s: z.number().int().min(1).max(120).default(15).describe(
    "SSH connection timeout in seconds.",
  ),
};

const ACCESS_FIELDS = {
  ...SSH_FIELDS,
  access: z.enum(["local", "ssh"]).describe(
    "How the API is reached: local means fetch directly, ssh runs curl on the host.",
  ),
  node: z.string().regex(/^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/).describe(
    "Logical node label used in stored-state keys.",
  ),
  api_url: z.string().max(2048).default("http://127.0.0.1:8384").describe(
    "Syncthing API origin; plain HTTP only on loopback, otherwise HTTPS.",
  ),
  api_key: z.string().min(8).max(128).meta({ sensitive: true }).describe(
    "Syncthing API key. Sent only in the X-API-Key header; wire a vault reference.",
  ),
  timeout_s: z.number().int().min(1).max(600).default(30).describe(
    "Per-request timeout in seconds, applied to fetch and to curl.",
  ),
};

const DEVICE_FIELDS = {
  device_id: z.string().max(64).describe("Peer device id."),
  name: z.string().min(1).max(256).describe("Peer display name."),
  addresses: z.array(z.string().max(256)).max(16).nullish().describe(
    "Listen addresses; default is ['dynamic'].",
  ),
  introducer: z.boolean().nullish().describe("Introducer flag; default false."),
  paused: z.boolean().nullish().describe("Paused flag; default false."),
};

const FOLDER_FIELDS = {
  folder_id: z.string().max(255).describe("Folder id."),
  label: z.string().min(1).max(256).describe("Folder label."),
  path: z.string().max(4096).describe("Absolute local path."),
  type: z.enum(["sendreceive", "sendonly", "receiveonly"]).nullish().describe(
    "Folder type; default sendreceive.",
  ),
  devices: z.array(z.string().max(64)).max(64).nullish().describe(
    "Peer device ids the folder is shared with.",
  ),
  paused: z.boolean().nullish().describe("Paused flag; default false."),
};

const GetArgsSchema = z.strictObject({ ...ACCESS_FIELDS });
const SyncArgsSchema = z.strictObject({ ...ACCESS_FIELDS });
const EnsureDeviceArgsSchema = z.strictObject({
  ...ACCESS_FIELDS,
  ...DEVICE_FIELDS,
});
const RemoveDeviceArgsSchema = z.strictObject({
  ...ACCESS_FIELDS,
  device_id: DEVICE_FIELDS.device_id,
});
const EnsureFolderArgsSchema = z.strictObject({
  ...ACCESS_FIELDS,
  ...FOLDER_FIELDS,
});
const RemoveFolderArgsSchema = z.strictObject({
  ...ACCESS_FIELDS,
  folder_id: FOLDER_FIELDS.folder_id,
});

/** Strict schema for `get`/`sync`. */
export const getArgsSchema = GetArgsSchema;
/** Strict schema for `sync`. */
export const syncArgsSchema = SyncArgsSchema;
/** Strict schema for `ensure_device`. */
export const ensureDeviceArgsSchema = EnsureDeviceArgsSchema;
/** Strict schema for `remove_device`. */
export const removeDeviceArgsSchema = RemoveDeviceArgsSchema;
/** Strict schema for `ensure_folder`. */
export const ensureFolderArgsSchema = EnsureFolderArgsSchema;
/** Strict schema for `remove_folder`. */
export const removeFolderArgsSchema = RemoveFolderArgsSchema;

const NodeStateSchema = z.strictObject({
  node: z.string(),
  api_url: z.string(),
  my_id: z.string().optional(),
  version: z.string().optional(),
  reachable: z.boolean(),
  device_count: z.number().int(),
  folder_count: z.number().int(),
  error: z.string().optional(),
  status: z.enum(["present", "unreachable", "not_found"]),
  observed_at: z.string(),
});

const DeviceStateSchema = z.strictObject({
  node: z.string(),
  device_id: z.string(),
  name: z.string(),
  addresses: z.array(z.string()),
  introducer: z.boolean(),
  paused: z.boolean(),
  changed: z.boolean(),
  status: z.enum(["present", "not_found", "removed"]),
  observed_at: z.string(),
});

const FolderStateSchema = z.strictObject({
  node: z.string(),
  folder_id: z.string(),
  label: z.string(),
  path: z.string(),
  type: z.string(),
  device_ids: z.array(z.string()),
  paused: z.boolean(),
  changed: z.boolean(),
  status: z.enum(["present", "not_found", "removed"]),
  observed_at: z.string(),
});

/** Stored state of one node. */
export type NodeState = z.infer<typeof NodeStateSchema>;
/** Stored state of one peer device. */
export type DeviceState = z.infer<typeof DeviceStateSchema>;
/** Stored state of one shared folder. */
export type FolderState = z.infer<typeof FolderStateSchema>;

interface AccessArgs {
  access: SyncthingAccess;
  node: string;
  api_url: string;
  api_key: string;
  timeout_s: number;
  host?: string | null;
  port: number;
  user?: string | null;
  host_key_policy?: HostKeyPolicy | null;
  host_keys?: string[] | null;
  private_key?: string | null;
  password?: string | null;
  connect_timeout_s: number;
}

interface EnsureDeviceArgs extends AccessArgs {
  device_id: string;
  name: string;
  addresses?: string[] | null;
  introducer?: boolean | null;
  paused?: boolean | null;
}

interface EnsureFolderArgs extends AccessArgs {
  folder_id: string;
  label: string;
  path: string;
  type?: "sendreceive" | "sendonly" | "receiveonly" | null;
  devices?: string[] | null;
  paused?: boolean | null;
}

/** Validates the target and builds an SSH target for the ssh transport. */
function sshTargetOf(args: AccessArgs): SshTarget | undefined {
  if (args.access !== "ssh") return undefined;
  if (!args.host || !args.user) {
    throw new SshConfigError(
      "the ssh transport requires host and user",
    );
  }
  if (args.host_key_policy !== "strict") {
    throw new SshConfigError(
      "the ssh transport only offers host_key_policy strict",
    );
  }
  const hostKeys = args.host_keys ?? undefined;
  if (!hostKeys || hostKeys.length === 0) {
    throw new SshConfigError(
      "the ssh transport requires a non-empty host_keys list",
    );
  }
  if (args.private_key && args.password) {
    throw new SshConfigError("pass private_key or password, not both");
  }
  return {
    host: args.host,
    port: args.port ?? 22,
    user: args.user,
    host_key_policy: "strict",
    host_keys: hostKeys,
    private_key: args.private_key ?? undefined,
    password: args.password ?? undefined,
    connect_timeout_s: args.connect_timeout_s ?? 15,
  };
}

/**
 * True only for a connect or timeout failure. Everything else — a 4xx/5xx
 * response, a refused redirect, a TLS failure, a bad key or a malformed body —
 * is rethrown so `sync` never hides a real problem as "unreachable".
 */
function isUnreachable(error: unknown): boolean {
  if (error instanceof SshConfigError) return false;
  if (error instanceof SyncthingError) return false;
  if (error instanceof SshError) {
    if (/could not connect|ssh transport failed/i.test(error.message)) {
      return true;
    }
    // curl 6 (DNS), 7 (connect) and 28 (timeout).
    const curl = /remote curl failed \(exit (\d+)\)/.exec(error.message);
    return curl !== null && ["6", "7", "28"].includes(curl[1]);
  }
  if (error instanceof TypeError) {
    const cause =
      (error as { cause?: { name?: string; code?: string; message?: string } })
        .cause;
    const text = [error.message, cause?.name, cause?.code, cause?.message]
      .filter((part) => typeof part === "string")
      .join(" ");
    return /connection refused|failed to lookup|name or service not known|dns error|could not resolve|timed? ?out|timeout|network is unreachable|no route to host|connection reset/i
      .test(text);
  }
  return false;
}

/** Builds the client for one call. */
function clientOf(
  deps: SyncthingDeps,
  args: AccessArgs,
): SyncthingClient {
  return createClient(
    deps,
    args.access,
    {
      apiUrl: args.api_url,
      apiKey: args.api_key,
      timeoutMs: (args.timeout_s ?? 30) * 1000,
    },
    sshTargetOf(args),
  );
}

/** The SHA-256-based instance name for one node endpoint. */
export async function nodeInstance(
  node: string,
  apiUrl: string,
): Promise<string> {
  const digest = await sha256Hex(`${node}\u0000${normalizeApiUrl(apiUrl)}`);
  return `syncthing-${digest.slice(0, 32)}`;
}

/** A stored-state key for one child with a length-prefixed id. */
function childInstance(nodeHash: string, kind: string, id: string): string {
  return `${nodeHash}-${kind}${id.length}-${id}`;
}

/** Reads the system status. */
async function readStatus(client: SyncthingClient): Promise<unknown> {
  const result = await client.request("GET", "/rest/system/status");
  if (result.status !== 200) {
    throw new SyncthingError(
      `system status returned ${result.status}`,
      result.status,
    );
  }
  return result.body;
}

/** Reads the device list, falling back to the whole config. */
async function listDevices(client: SyncthingClient): Promise<unknown[]> {
  const result = await client.request("GET", "/rest/config/devices");
  if (result.status === 200 && Array.isArray(result.body)) return result.body;
  if (result.status === 404 || result.status === 405) {
    const config = await client.request("GET", "/rest/system/config");
    if (
      config.status === 200 && config.body && typeof config.body === "object"
    ) {
      const devices = (config.body as Record<string, unknown>).devices;
      if (Array.isArray(devices)) return devices;
    }
  }
  throw new SyncthingError(
    `device list returned ${result.status}`,
    result.status,
  );
}

/** Reads the folder list, falling back to the whole config. */
async function listFolders(client: SyncthingClient): Promise<unknown[]> {
  const result = await client.request("GET", "/rest/config/folders");
  if (result.status === 200 && Array.isArray(result.body)) return result.body;
  if (result.status === 404 || result.status === 405) {
    const config = await client.request("GET", "/rest/system/config");
    if (
      config.status === 200 && config.body && typeof config.body === "object"
    ) {
      const folders = (config.body as Record<string, unknown>).folders;
      if (Array.isArray(folders)) return folders;
    }
  }
  throw new SyncthingError(
    `folder list returned ${result.status}`,
    result.status,
  );
}

/** One observation of a node: status, device list, folder list and own id. */
interface Observation {
  status: Record<string, unknown>;
  devices: unknown[];
  folders: unknown[];
  myId?: string;
}

/** Reads status, devices and folders as one observation. */
async function observe(client: SyncthingClient): Promise<Observation> {
  const raw = await readStatus(client);
  const status = raw && typeof raw === "object"
    ? raw as Record<string, unknown>
    : {};
  const devices = await listDevices(client);
  const folders = await listFolders(client);
  return {
    status,
    devices,
    folders,
    myId: typeof status.myID === "string" ? status.myID : undefined,
  };
}

/** Reads one device config; null on 404. */
async function readDevice(
  client: SyncthingClient,
  deviceId: string,
): Promise<unknown> {
  const result = await client.request(
    "GET",
    `/rest/config/devices/${encodeURIComponent(deviceId)}`,
  );
  if (result.status === 404) return null;
  if (result.status !== 200) {
    throw new SyncthingError(
      `device read returned ${result.status}`,
      result.status,
    );
  }
  return result.body;
}

/** Reads one folder config; null on 404. */
async function readFolder(
  client: SyncthingClient,
  folderId: string,
): Promise<unknown> {
  const result = await client.request(
    "GET",
    `/rest/config/folders/${encodeURIComponent(folderId)}`,
  );
  if (result.status === 404) return null;
  if (result.status !== 200) {
    throw new SyncthingError(
      `folder read returned ${result.status}`,
      result.status,
    );
  }
  return result.body;
}

/** Writes a node state record. */
async function writeNode(
  context: MethodContext,
  args: AccessArgs,
  instance: string,
  state: Omit<NodeState, "node" | "api_url" | "observed_at">,
  observedAt: string,
): Promise<DataHandle> {
  return await context.writeResource(
    "node",
    instance,
    NodeStateSchema.parse({
      node: args.node,
      api_url: normalizeApiUrl(args.api_url),
      observed_at: observedAt,
      ...state,
    }),
  );
}

/** Writes a device state record. */
async function writeDevice(
  context: MethodContext,
  args: AccessArgs,
  instance: string,
  spec: DeviceSpec,
  state: { changed: boolean; status: DeviceState["status"] },
  observedAt: string,
): Promise<DataHandle> {
  return await context.writeResource(
    "device",
    instance,
    DeviceStateSchema.parse({
      node: args.node,
      device_id: spec.deviceId,
      name: spec.name,
      addresses: spec.addresses,
      introducer: spec.introducer,
      paused: spec.paused,
      observed_at: observedAt,
      ...state,
    }),
  );
}

/** Writes a folder state record. */
async function writeFolder(
  context: MethodContext,
  args: AccessArgs,
  instance: string,
  spec: FolderSpec,
  state: { changed: boolean; status: FolderState["status"] },
  observedAt: string,
): Promise<DataHandle> {
  return await context.writeResource(
    "folder",
    instance,
    FolderStateSchema.parse({
      node: args.node,
      folder_id: spec.folderId,
      label: spec.label,
      path: spec.path,
      type: spec.type,
      device_ids: spec.devices,
      paused: spec.paused,
      observed_at: observedAt,
      ...state,
    }),
  );
}

/** Maps a live device config onto a spec, for storage after a removal. */
function specOfDevice(body: unknown, fallback: DeviceSpec): DeviceSpec {
  if (!body || typeof body !== "object") return fallback;
  const record = body as Record<string, unknown>;
  return {
    deviceId: typeof record.deviceID === "string"
      ? record.deviceID
      : fallback.deviceId,
    name: typeof record.name === "string" ? record.name : fallback.name,
    addresses: Array.isArray(record.addresses)
      ? record.addresses.map(String)
      : fallback.addresses,
    introducer: record.introducer === true,
    paused: record.paused === true,
  };
}

/**
 * Builds the model with injectable dependencies. The production export is
 * `createModel()`; tests pass a fake fetch, runner, clock and sleep.
 */
export function createModel(
  deps: SyncthingDeps = denoSyncthingDeps,
): PeerModel {
  return {
    type: "@randybias/syncthing-peer",
    version: "2026.10.17.1",
    description:
      "Ensure a peer device and a shared folder on one Syncthing node through its REST API, reached locally or over SSH, and inspect or remove them. The API key travels only in the X-API-Key header, plain HTTP is loopback-only, and state is keyed by a SHA-256 of the node label and endpoint.",
    globalArguments: z.strictObject({}),
    resources: {
      node: {
        description: "Syncthing node status: my id, version and counts",
        schema: NodeStateSchema,
        lifetime: "infinite",
        garbageCollection: 10,
      },
      device: {
        description: "One peer device config and its change flag",
        schema: DeviceStateSchema,
        lifetime: "infinite",
        garbageCollection: 10,
      },
      folder: {
        description: "One shared folder config and its change flag",
        schema: FolderStateSchema,
        lifetime: "infinite",
        garbageCollection: 10,
      },
    },
    methods: {
      get: {
        description:
          "READ-ONLY. Read node status, devices and folders and store the summary. Fails when the node does not answer.",
        arguments: GetArgsSchema,
        execute: async (
          rawArgs: unknown,
          context: MethodContext,
        ): Promise<MethodResult> => {
          const args = rawArgs as AccessArgs;
          const client = clientOf(deps, args);
          const instance = await nodeInstance(args.node, args.api_url);
          const observation = await observe(client);
          const version = typeof observation.status.version === "string"
            ? observation.status.version
            : undefined;
          const handle = await writeNode(context, args, instance, {
            my_id: observation.myId,
            version,
            reachable: true,
            device_count: observation.devices.length,
            folder_count: observation.folders.length,
            status: "present",
          }, new Date(deps.now()).toISOString());
          context.logger.info("Syncthing node {node} has {devices} devices", {
            node: args.node,
            devices: observation.devices.length,
          });
          return {
            dataHandles: [handle],
            result: {
              my_id: observation.myId,
              version,
              device_count: observation.devices.length,
              folder_count: observation.folders.length,
            },
          };
        },
      },

      sync: {
        description:
          "READ-ONLY. Refresh node status, devices and folders; records reachable false instead of failing when the node is down.",
        arguments: SyncArgsSchema,
        execute: async (
          rawArgs: unknown,
          context: MethodContext,
        ): Promise<MethodResult> => {
          const args = rawArgs as AccessArgs;
          const client = clientOf(deps, args);
          const instance = await nodeInstance(args.node, args.api_url);
          try {
            const observation = await observe(client);
            const version = typeof observation.status.version === "string"
              ? observation.status.version
              : undefined;
            const handle = await writeNode(context, args, instance, {
              my_id: observation.myId,
              version,
              reachable: true,
              device_count: observation.devices.length,
              folder_count: observation.folders.length,
              status: "present",
            }, new Date(deps.now()).toISOString());
            return {
              dataHandles: [handle],
              result: {
                reachable: true,
                device_count: observation.devices.length,
              },
            };
          } catch (error) {
            // Only a connect or timeout failure means the node is down; an HTTP
            // error, a TLS failure or a configuration error is rethrown.
            if (!isUnreachable(error)) throw error;
            const message = error instanceof Error
              ? error.message
              : String(error);
            const handle = await writeNode(context, args, instance, {
              reachable: false,
              device_count: 0,
              folder_count: 0,
              error: message.slice(0, 300),
              status: "unreachable",
            }, new Date(deps.now()).toISOString());
            context.logger.warn("Syncthing node {node} unreachable", {
              node: args.node,
            });
            return {
              dataHandles: [handle],
              result: { reachable: false, error: message },
            };
          }
        },
      },

      ensure_device: {
        kind: "action",
        description:
          "DESTRUCTIVE. Ensure one peer device config exists exactly as declared: create it or update a differing one, never a second. Idempotent; returns changed false when it already matches.",
        arguments: EnsureDeviceArgsSchema,
        execute: async (
          rawArgs: unknown,
          context: MethodContext,
        ): Promise<MethodResult> => {
          const args = rawArgs as EnsureDeviceArgs;
          const spec = buildDeviceSpec({
            deviceId: args.device_id,
            name: args.name,
            addresses: args.addresses,
            introducer: args.introducer,
            paused: args.paused,
          });
          const client = clientOf(deps, args);
          const nodeHash = await nodeInstance(args.node, args.api_url);
          const instance = childInstance(nodeHash, "d", spec.deviceId);
          const observedAt = new Date(deps.now()).toISOString();
          const existing = await readDevice(client, spec.deviceId);
          if (existing !== null && deviceMatches(existing, spec)) {
            const handle = await writeDevice(context, args, instance, spec, {
              changed: false,
              status: "present",
            }, observedAt);
            return {
              dataHandles: [handle],
              result: { changed: false, device_id: spec.deviceId },
            };
          }
          // PATCH an existing device so fields this model does not declare are
          // left alone; PUT only creates.
          const method = existing === null ? "PUT" : "PATCH";
          const put = await client.request(
            method,
            `/rest/config/devices/${encodeURIComponent(spec.deviceId)}`,
            deviceBody(spec),
          );
          if (put.status < 200 || put.status > 299) {
            throw new SyncthingError(
              `device upsert returned ${put.status}`,
              put.status,
            );
          }
          const after = await readDevice(client, spec.deviceId);
          if (after === null || !deviceMatches(after, spec)) {
            throw new SyncthingError(
              `device ${spec.deviceId} did not converge`,
            );
          }
          const handle = await writeDevice(
            context,
            args,
            instance,
            specOfDevice(after, spec),
            { changed: true, status: "present" },
            observedAt,
          );
          context.logger.info("Ensured device {device}", {
            device: spec.deviceId,
          });
          return {
            dataHandles: [handle],
            result: { changed: true, device_id: spec.deviceId },
          };
        },
      },

      remove_device: {
        kind: "action",
        description:
          "DESTRUCTIVE. Remove one peer device config and prove it is gone. Idempotent: an already-absent device is a clean no-op.",
        arguments: RemoveDeviceArgsSchema,
        execute: async (
          rawArgs: unknown,
          context: MethodContext,
        ): Promise<MethodResult> => {
          const args = rawArgs as AccessArgs & { device_id: string };
          const spec = buildDeviceSpec({
            deviceId: args.device_id,
            name: args.device_id,
          });
          const client = clientOf(deps, args);
          const nodeHash = await nodeInstance(args.node, args.api_url);
          const instance = childInstance(nodeHash, "d", args.device_id);
          const observedAt = new Date(deps.now()).toISOString();
          const existing = await readDevice(client, args.device_id);
          if (existing === null) {
            const handle = await writeDevice(context, args, instance, spec, {
              changed: false,
              status: "not_found",
            }, observedAt);
            return {
              dataHandles: [handle],
              result: { changed: false, device_id: args.device_id },
            };
          }
          const del = await client.request(
            "DELETE",
            `/rest/config/devices/${encodeURIComponent(args.device_id)}`,
          );
          // A 404 here means a concurrent delete already removed it.
          if (del.status !== 404 && (del.status < 200 || del.status > 299)) {
            throw new SyncthingError(
              `device delete returned ${del.status}`,
              del.status,
            );
          }
          if (await readDevice(client, args.device_id) !== null) {
            throw new SyncthingError(
              `device ${args.device_id} is still present`,
            );
          }
          const removedSpec = specOfDevice(existing, spec);
          const handle = await writeDevice(
            context,
            args,
            instance,
            removedSpec,
            { changed: true, status: "removed" },
            observedAt,
          );
          context.logger.info("Removed device {device}", {
            device: args.device_id,
          });
          return {
            dataHandles: [handle],
            result: { changed: true, device_id: args.device_id },
          };
        },
      },

      ensure_folder: {
        kind: "action",
        description:
          "DESTRUCTIVE. Ensure one shared folder exists exactly as declared, with the given peer device ids: create it or update a differing one. Idempotent; returns changed false when it already matches.",
        arguments: EnsureFolderArgsSchema,
        execute: async (
          rawArgs: unknown,
          context: MethodContext,
        ): Promise<MethodResult> => {
          const args = rawArgs as EnsureFolderArgs;
          const spec = buildFolderSpec({
            folderId: args.folder_id,
            label: args.label,
            path: args.path,
            type: args.type,
            devices: args.devices,
            paused: args.paused,
          });
          const client = clientOf(deps, args);
          const nodeHash = await nodeInstance(args.node, args.api_url);
          const instance = childInstance(nodeHash, "f", spec.folderId);
          const observedAt = new Date(deps.now()).toISOString();
          // Syncthing always adds the node's own device to a folder, so the
          // comparison ignores it on both sides.
          const status = await readStatus(client);
          const myId = status && typeof status === "object"
            ? (status as Record<string, unknown>).myID
            : undefined;
          const ownId = typeof myId === "string" ? myId : undefined;
          const existing = await readFolder(client, spec.folderId);
          if (existing !== null && folderMatches(existing, spec, ownId)) {
            const handle = await writeFolder(
              context,
              args,
              instance,
              folderSpecOf(existing, spec, ownId),
              { changed: false, status: "present" },
              observedAt,
            );
            return {
              dataHandles: [handle],
              result: { changed: false, folder_id: spec.folderId },
            };
          }
          const method = existing === null ? "PUT" : "PATCH";
          const put = await client.request(
            method,
            `/rest/config/folders/${encodeURIComponent(spec.folderId)}`,
            folderBody(spec),
          );
          if (put.status < 200 || put.status > 299) {
            throw new SyncthingError(
              `folder upsert returned ${put.status}`,
              put.status,
            );
          }
          const after = await readFolder(client, spec.folderId);
          if (after === null || !folderMatches(after, spec, ownId)) {
            throw new SyncthingError(
              `folder ${spec.folderId} did not converge`,
            );
          }
          const handle = await writeFolder(
            context,
            args,
            instance,
            folderSpecOf(after, spec, ownId),
            { changed: true, status: "present" },
            observedAt,
          );
          context.logger.info("Ensured folder {folder}", {
            folder: spec.folderId,
          });
          return {
            dataHandles: [handle],
            result: { changed: true, folder_id: spec.folderId },
          };
        },
      },

      remove_folder: {
        kind: "action",
        description:
          "DESTRUCTIVE. Remove one shared folder and prove it is gone. Idempotent: an already-absent folder is a clean no-op.",
        arguments: RemoveFolderArgsSchema,
        execute: async (
          rawArgs: unknown,
          context: MethodContext,
        ): Promise<MethodResult> => {
          const args = rawArgs as AccessArgs & { folder_id: string };
          const spec = buildFolderSpec({
            folderId: args.folder_id,
            label: args.folder_id,
            path: `/${args.folder_id}`,
          });
          const client = clientOf(deps, args);
          const nodeHash = await nodeInstance(args.node, args.api_url);
          const instance = childInstance(nodeHash, "f", args.folder_id);
          const observedAt = new Date(deps.now()).toISOString();
          const status = await readStatus(client);
          const myIdRaw = status && typeof status === "object"
            ? (status as Record<string, unknown>).myID
            : undefined;
          const ownId = typeof myIdRaw === "string" ? myIdRaw : undefined;
          const existing = await readFolder(client, args.folder_id);
          if (existing === null) {
            const handle = await writeFolder(context, args, instance, spec, {
              changed: false,
              status: "not_found",
            }, observedAt);
            return {
              dataHandles: [handle],
              result: { changed: false, folder_id: args.folder_id },
            };
          }
          const del = await client.request(
            "DELETE",
            `/rest/config/folders/${encodeURIComponent(args.folder_id)}`,
          );
          // A 404 here means a concurrent delete already removed it.
          if (del.status !== 404 && (del.status < 200 || del.status > 299)) {
            throw new SyncthingError(
              `folder delete returned ${del.status}`,
              del.status,
            );
          }
          if (await readFolder(client, args.folder_id) !== null) {
            throw new SyncthingError(
              `folder ${args.folder_id} is still present`,
            );
          }
          const handle = await writeFolder(
            context,
            args,
            instance,
            folderSpecOf(existing, spec, ownId),
            { changed: true, status: "removed" },
            observedAt,
          );
          context.logger.info("Removed folder {folder}", {
            folder: args.folder_id,
          });
          return {
            dataHandles: [handle],
            result: { changed: true, folder_id: args.folder_id },
          };
        },
      },
    },
  };
}

/** Production model: the factory with no overrides. */
export const model: PeerModel = createModel();
