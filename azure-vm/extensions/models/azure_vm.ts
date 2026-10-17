/**
 * Swamp extension model for an Azure virtual machine, driven through the Azure
 * Resource Manager REST API with a service principal from a vault.
 *
 * The definition is generic: global arguments are empty and every method takes
 * its own tenant, subscription, resource group and VM name. Authentication uses
 * an OAuth2 client-credentials token whose secret travels only in the HTTPS
 * POST body; the token lives in memory for one call. Stored state is keyed by
 * subscription, resource group and name, so one definition serves any fleet.
 *
 * @module
 */

import { z } from "npm:zod@4.3.6";
import {
  type ArmClient,
  type ArmDeps,
  type ArmResult,
  createArmClient,
  denoArmDeps,
  isNotFound,
  pollUntil,
} from "./_lib/arm.ts";
import {
  assertGuid,
  assertLocation,
  assertName,
  assertResourceGroup,
  assertSshPublicKey,
  GUID_RE,
  NAME_RE,
  RESOURCE_GROUP_RE,
  resourceInstanceName,
} from "./_lib/validate.ts";

/** Azure Compute API version this model pins. */
export const VM_API_VERSION = "2024-07-01";

const LOCATION_RE = /^[a-z0-9][a-z0-9-]{0,63}$/;
const IMAGE_FIELD_RE = /^[A-Za-z0-9._-]{1,128}$/;
const ADMIN_USER_RE = /^[a-z_][a-z0-9_-]{0,31}$/;
const ARM_ID_RE = /^\/[A-Za-z0-9._\-/]{1,1023}$/;

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
export interface VmMethod {
  /** `action` for a non-lifecycle verb; `delete` is an action. */
  kind?: "action" | "create" | "update" | "query";
  /** Description. */
  description: string;
  /** Argument schema. */
  arguments: z.ZodType;
  /** Runs the method. */
  execute: (args: unknown, context: MethodContext) => Promise<MethodResult>;
}

/** The model definition returned by {@link createModel}. */
export interface VmModel {
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
  methods: Record<string, VmMethod>;
}

const AuthFields = {
  tenantId: z.string().regex(GUID_RE).describe(
    "Entra tenant id; a vault reference is fine.",
  ),
  clientId: z.string().regex(GUID_RE).describe(
    "Service-principal application (client) id.",
  ),
  clientSecret: z.string().min(1).max(4096).meta({ sensitive: true }).describe(
    "Service-principal client secret. Wire a vault reference; it is sent only in the token POST body.",
  ),
  subscriptionId: z.string().regex(GUID_RE).describe(
    "Target Azure subscription id.",
  ),
};

const TargetFields = {
  resourceGroup: z.string().regex(RESOURCE_GROUP_RE).max(90).describe(
    "Resource group name.",
  ),
  name: z.string().regex(NAME_RE).max(64).describe("Virtual machine name."),
};

const PollFields = {
  timeoutMs: z.number().int().min(1000).max(3_600_000).default(900_000)
    .describe("Total settle budget in milliseconds."),
  pollIntervalMs: z.number().int().min(250).max(60_000).default(5000).describe(
    "First poll interval in milliseconds.",
  ),
};

const ReadArgsSchema = z.strictObject({ ...AuthFields, ...TargetFields });

const CreateArgsSchema = z.strictObject({
  ...AuthFields,
  ...TargetFields,
  location: z.string().regex(LOCATION_RE).describe(
    "Azure region, e.g. eastus2.",
  ),
  vmSize: z.string().regex(IMAGE_FIELD_RE).describe(
    "VM size, e.g. Standard_B2s.",
  ),
  image: z.strictObject({
    publisher: z.string().regex(IMAGE_FIELD_RE).describe("Image publisher."),
    offer: z.string().regex(IMAGE_FIELD_RE).describe("Image offer."),
    sku: z.string().regex(IMAGE_FIELD_RE).describe("Image SKU."),
    version: z.string().regex(IMAGE_FIELD_RE).describe(
      "Image version, or latest.",
    ),
  }).describe("Marketplace image reference."),
  adminUsername: z.string().regex(ADMIN_USER_RE).describe(
    "Linux admin username.",
  ),
  sshPublicKey: z.string().max(4096).refine(
    (value) => {
      try {
        assertSshPublicKey(value);
        return true;
      } catch {
        return false;
      }
    },
    "must be one SSH public-key line",
  ).describe(
    "SSH public key for the admin user; password auth is not offered.",
  ),
  networkInterfaceId: z.string().max(1024).refine(
    (value) => ARM_ID_RE.test(value) && !value.split("/").includes(".."),
    "must be an absolute ARM resource id",
  ).describe("Existing network interface to attach."),
  osDiskSizeGb: z.number().int().min(1).max(4095).optional().describe(
    "OS disk size in GB.",
  ),
  tags: z.record(
    z.string().regex(/^[A-Za-z0-9._-]{1,64}$/),
    z.string().max(256),
  ).optional().describe("Resource tags."),
  ...PollFields,
});

const ActionArgsSchema = z.strictObject({
  ...AuthFields,
  ...TargetFields,
  ...PollFields,
});

const DeallocateArgsSchema = z.strictObject({
  ...AuthFields,
  ...TargetFields,
  hibernate: z.boolean().default(false).describe(
    "Hibernate instead of deallocate; the VM must allow hibernation.",
  ),
  ...PollFields,
});

/** Strict schema for get/sync arguments. */
export const readArgsSchema = ReadArgsSchema;

/** Strict schema for create arguments. */
export const createArgsSchema = CreateArgsSchema;

/** Strict schema for start/stop/delete arguments. */
export const actionArgsSchema = ActionArgsSchema;

/** Strict schema for deallocate arguments. */
export const deallocateArgsSchema = DeallocateArgsSchema;

const VmStateSchema = z.strictObject({
  subscriptionId: z.string(),
  resourceGroup: z.string(),
  name: z.string(),
  id: z.string().optional(),
  location: z.string().optional(),
  vmSize: z.string().optional(),
  provisioningState: z.string().optional(),
  powerState: z.string().optional(),
  status: z.enum(["present", "not_found", "deleted"]),
  tags: z.record(z.string(), z.string()).optional(),
  observedAt: z.string(),
});

/** Stored state of one VM. */
export type VmState = z.infer<typeof VmStateSchema>;

/** Arguments common to every method. */
interface AuthArgs {
  tenantId: string;
  clientId: string;
  clientSecret: string;
  subscriptionId: string;
}

interface TargetArgs extends AuthArgs {
  resourceGroup: string;
  name: string;
}

/** The fields that build the VM request body. */
interface VmBodyArgs {
  name: string;
  location: string;
  vmSize: string;
  image: { publisher: string; offer: string; sku: string; version: string };
  adminUsername: string;
  sshPublicKey: string;
  networkInterfaceId: string;
  osDiskSizeGb?: number;
  tags?: Record<string, string>;
}

interface CreateArgs extends TargetArgs {
  location: string;
  vmSize: string;
  image: { publisher: string; offer: string; sku: string; version: string };
  adminUsername: string;
  sshPublicKey: string;
  networkInterfaceId: string;
  osDiskSizeGb?: number;
  tags?: Record<string, string>;
  timeoutMs: number;
  pollIntervalMs: number;
}

interface ActionArgs extends TargetArgs {
  timeoutMs: number;
  pollIntervalMs: number;
}

interface DeallocateArgs extends ActionArgs {
  hibernate: boolean;
}

/** Validates the target and returns the ARM resource path. */
function vmPath(args: TargetArgs): string {
  assertGuid(args.subscriptionId, "subscriptionId");
  assertResourceGroup(args.resourceGroup);
  assertName(args.name, "name");
  return `/subscriptions/${args.subscriptionId}` +
    `/resourceGroups/${args.resourceGroup}` +
    `/providers/Microsoft.Compute/virtualMachines/${args.name}`;
}

/** The VM URL with the pinned API version and an optional extra query. */
export function vmUrl(args: TargetArgs, extra = ""): string {
  return `${vmPath(args)}?api-version=${VM_API_VERSION}${extra}`;
}

/** The ARM error body, or `{}`. */
function properties(body: unknown): Record<string, unknown> {
  if (body && typeof body === "object") {
    const props = (body as Record<string, unknown>).properties;
    if (props && typeof props === "object") {
      return props as Record<string, unknown>;
    }
  }
  return {};
}

/** Power state from `properties.instanceView.statuses`, if present. */
export function powerStateOf(body: unknown): string | undefined {
  const statuses = properties(body).instanceView;
  if (!statuses || typeof statuses !== "object") return undefined;
  const list = (statuses as Record<string, unknown>).statuses;
  if (!Array.isArray(list)) return undefined;
  for (const entry of list) {
    if (entry && typeof entry === "object") {
      const code = (entry as Record<string, unknown>).code;
      if (typeof code === "string" && code.startsWith("PowerState/")) {
        return code.slice("PowerState/".length);
      }
    }
  }
  return undefined;
}

/** Maps an ARM VM body onto stored state. */
export function toState(
  args: TargetArgs,
  body: unknown,
  status: VmState["status"],
  observedAt: string,
): VmState {
  const record = body && typeof body === "object"
    ? body as Record<string, unknown>
    : {};
  const props = properties(body);
  const hardware = props.hardwareProfile;
  const vmSize = hardware && typeof hardware === "object"
    ? (hardware as Record<string, unknown>).vmSize
    : undefined;
  const tags = record.tags && typeof record.tags === "object" &&
      !Array.isArray(record.tags)
    ? Object.fromEntries(
      Object.entries(record.tags as Record<string, unknown>)
        .filter(([, value]) => typeof value === "string"),
    ) as Record<string, string>
    : undefined;
  const state: Record<string, unknown> = {
    subscriptionId: args.subscriptionId,
    resourceGroup: args.resourceGroup,
    name: args.name,
    status,
    observedAt,
  };
  const id = record.id;
  if (typeof id === "string") state.id = id;
  const location = record.location;
  if (typeof location === "string") state.location = location;
  if (typeof vmSize === "string") state.vmSize = vmSize;
  const provisioning = props.provisioningState;
  if (typeof provisioning === "string") state.provisioningState = provisioning;
  const power = powerStateOf(body);
  if (power !== undefined) state.powerState = power;
  if (tags && Object.keys(tags).length > 0) state.tags = tags;
  return VmStateSchema.parse(state);
}

/** Builds the ARM request body for a new VM; pure and testable. */
export function buildVmBody(args: VmBodyArgs): Record<string, unknown> {
  assertName(args.name, "name");
  assertLocation(args.location);
  assertSshPublicKey(args.sshPublicKey);
  const osDisk: Record<string, unknown> = { createOption: "FromImage" };
  if (args.osDiskSizeGb !== undefined) osDisk.diskSizeGB = args.osDiskSizeGb;
  const body: Record<string, unknown> = {
    location: args.location,
    properties: {
      hardwareProfile: { vmSize: args.vmSize },
      storageProfile: {
        imageReference: {
          publisher: args.image.publisher,
          offer: args.image.offer,
          sku: args.image.sku,
          version: args.image.version,
        },
        osDisk,
      },
      osProfile: {
        computerName: args.name,
        adminUsername: args.adminUsername,
        linuxConfiguration: {
          disablePasswordAuthentication: true,
          ssh: {
            publicKeys: [{
              path: `/home/${args.adminUsername}/.ssh/authorized_keys`,
              keyData: args.sshPublicKey,
            }],
          },
        },
      },
      networkProfile: {
        networkInterfaces: [{
          id: args.networkInterfaceId,
          properties: { primary: true },
        }],
      },
    },
  };
  if (args.tags !== undefined) body.tags = args.tags;
  return body;
}

/** Reads a VM, returning null on a 404. */
async function readVm(
  client: ArmClient,
  args: TargetArgs,
): Promise<ArmResult | null> {
  try {
    return await client.get(vmUrl(args, "&$expand=instanceView"));
  } catch (error) {
    if (isNotFound(error)) return null;
    throw error;
  }
}

/** Polls until a probe returns a value or the budget expires. */
function settle<T>(
  deps: ArmDeps,
  args: ActionArgs,
  label: string,
  probe: () => Promise<T | null>,
): Promise<T> {
  return pollUntil(deps, {
    deadlineMs: args.timeoutMs,
    intervalMs: args.pollIntervalMs,
    label,
  }, probe);
}

/**
 * Builds the model with injectable dependencies. The production export is
 * `createModel()`; tests pass a fake fetch, clock and sleep.
 */
export function createModel(deps: ArmDeps = denoArmDeps): VmModel {
  return {
    type: "@randybias/azure-vm",
    version: "2026.10.17.1",
    description:
      "Create, adopt, start, deallocate, stop, inspect and delete an Azure virtual machine through the Azure Resource Manager REST API with a service principal from a vault, keyed by subscription, resource group and name.",
    globalArguments: z.strictObject({}),
    resources: {
      vm: {
        description:
          "Azure VM state: id, location, size, provisioning and power state",
        schema: VmStateSchema,
        lifetime: "infinite",
        garbageCollection: 10,
      },
    },
    methods: {
      get: {
        description:
          "READ-ONLY. Fetch one virtual machine from Azure and store its state. Fails when the VM does not exist.",
        arguments: ReadArgsSchema,
        execute: async (
          rawArgs: unknown,
          context: MethodContext,
        ): Promise<MethodResult> => {
          const args = rawArgs as TargetArgs;
          const client = createArmClient(deps, args);
          const result = await client.get(vmUrl(args, "&$expand=instanceView"));
          const state = toState(
            args,
            result.body,
            "present",
            new Date(deps.now()).toISOString(),
          );
          const handle = await context.writeResource(
            "vm",
            resourceInstanceName(
              args.subscriptionId,
              args.resourceGroup,
              args.name,
            ),
            state,
          );
          context.logger.info("VM {name} is {power}", {
            name: args.name,
            power: state.powerState ?? state.provisioningState,
          });
          return { dataHandles: [handle], result: state };
        },
      },

      sync: {
        description:
          "READ-ONLY. Refresh stored VM state; records status not_found instead of failing when the VM is gone.",
        arguments: ReadArgsSchema,
        execute: async (
          rawArgs: unknown,
          context: MethodContext,
        ): Promise<MethodResult> => {
          const args = rawArgs as TargetArgs;
          const client = createArmClient(deps, args);
          const result = await readVm(client, args);
          const state = result === null
            ? toState(
              args,
              null,
              "not_found",
              new Date(deps.now()).toISOString(),
            )
            : toState(
              args,
              result.body,
              "present",
              new Date(deps.now()).toISOString(),
            );
          const handle = await context.writeResource(
            "vm",
            resourceInstanceName(
              args.subscriptionId,
              args.resourceGroup,
              args.name,
            ),
            state,
          );
          context.logger.info("VM {name} status {status}", {
            name: args.name,
            status: state.status,
          });
          return { dataHandles: [handle], result: state };
        },
      },

      create: {
        kind: "action",
        description:
          "Create the VM, or adopt the existing one with the same name and never create a second. Idempotent; waits until provisioning succeeds and returns the stored state.",
        arguments: CreateArgsSchema,
        execute: async (
          rawArgs: unknown,
          context: MethodContext,
        ): Promise<MethodResult> => {
          const args = rawArgs as CreateArgs;
          const client = createArmClient(deps, args);
          const existing = await readVm(client, args);
          if (existing !== null) {
            const state = toState(
              args,
              existing.body,
              "present",
              new Date(deps.now()).toISOString(),
            );
            context.logger.info("VM {name} already exists; adopting", {
              name: args.name,
            });
            const handle = await context.writeResource(
              "vm",
              resourceInstanceName(
                args.subscriptionId,
                args.resourceGroup,
                args.name,
              ),
              state,
            );
            return { dataHandles: [handle], result: state };
          }
          await client.put(vmUrl(args), buildVmBody(args));
          const state = await settle(
            deps,
            args,
            `VM ${args.name} provisioning`,
            async () => {
              const current = await readVm(client, args);
              if (current === null) return null;
              const candidate = toState(
                args,
                current.body,
                "present",
                new Date(deps.now()).toISOString(),
              );
              if (candidate.provisioningState === "Failed") {
                throw new Error(
                  `VM ${args.name} provisioning reached Failed`,
                );
              }
              return candidate.provisioningState === "Succeeded"
                ? candidate
                : null;
            },
          );
          context.logger.info("VM {name} provisioned", { name: args.name });
          const handle = await context.writeResource(
            "vm",
            resourceInstanceName(
              args.subscriptionId,
              args.resourceGroup,
              args.name,
            ),
            state,
          );
          return { dataHandles: [handle], result: state };
        },
      },

      start: {
        kind: "action",
        description:
          "Start a stopped or deallocated VM and wait until its power state is running. Idempotent when the VM is already running.",
        arguments: ActionArgsSchema,
        execute: async (
          rawArgs: unknown,
          context: MethodContext,
        ): Promise<MethodResult> => {
          const args = rawArgs as ActionArgs;
          const client = createArmClient(deps, args);
          const existing = await readVm(client, args);
          if (existing === null) {
            throw new Error(`VM ${args.name} does not exist`);
          }
          if (powerStateOf(existing.body) === "running") {
            const state = toState(
              args,
              existing.body,
              "present",
              new Date(deps.now()).toISOString(),
            );
            const handle = await context.writeResource(
              "vm",
              resourceInstanceName(
                args.subscriptionId,
                args.resourceGroup,
                args.name,
              ),
              state,
            );
            return { dataHandles: [handle], result: state };
          }
          await client.post(
            `${vmPath(args)}/start?api-version=${VM_API_VERSION}`,
          );
          const state = await settle(
            deps,
            args,
            `VM ${args.name} start`,
            async () => {
              const current = await readVm(client, args);
              if (current === null) return null;
              return powerStateOf(current.body) === "running"
                ? toState(
                  args,
                  current.body,
                  "present",
                  new Date(deps.now()).toISOString(),
                )
                : null;
            },
          );
          const handle = await context.writeResource(
            "vm",
            resourceInstanceName(
              args.subscriptionId,
              args.resourceGroup,
              args.name,
            ),
            state,
          );
          return { dataHandles: [handle], result: state };
        },
      },

      deallocate: {
        kind: "action",
        description:
          "DESTRUCTIVE. Deallocate a VM, releasing compute and stopping charges, and wait until it is deallocated. Optionally hibernate instead; the workload stops.",
        arguments: DeallocateArgsSchema,
        execute: async (
          rawArgs: unknown,
          context: MethodContext,
        ): Promise<MethodResult> => {
          const args = rawArgs as DeallocateArgs;
          const client = createArmClient(deps, args);
          const query = args.hibernate
            ? `?hibernate=true&api-version=${VM_API_VERSION}`
            : `?api-version=${VM_API_VERSION}`;
          await client.post(`${vmPath(args)}/deallocate${query}`);
          const expected = "deallocated";
          const state = await settle(
            deps,
            args,
            `VM ${args.name} deallocate`,
            async () => {
              const current = await readVm(client, args);
              if (current === null) return null;
              return powerStateOf(current.body) === expected
                ? toState(
                  args,
                  current.body,
                  "present",
                  new Date(deps.now()).toISOString(),
                )
                : null;
            },
          );
          context.logger.info("VM {name} deallocated", { name: args.name });
          const handle = await context.writeResource(
            "vm",
            resourceInstanceName(
              args.subscriptionId,
              args.resourceGroup,
              args.name,
            ),
            state,
          );
          return { dataHandles: [handle], result: state };
        },
      },

      stop: {
        kind: "action",
        description:
          "DESTRUCTIVE. Power off a VM without deallocating, so compute charges continue, and wait until its power state is stopped; the workload stops.",
        arguments: ActionArgsSchema,
        execute: async (
          rawArgs: unknown,
          context: MethodContext,
        ): Promise<MethodResult> => {
          const args = rawArgs as ActionArgs;
          const client = createArmClient(deps, args);
          await client.post(
            `${vmPath(args)}/powerOff?api-version=${VM_API_VERSION}`,
          );
          const state = await settle(
            deps,
            args,
            `VM ${args.name} power off`,
            async () => {
              const current = await readVm(client, args);
              if (current === null) return null;
              return powerStateOf(current.body) === "stopped"
                ? toState(
                  args,
                  current.body,
                  "present",
                  new Date(deps.now()).toISOString(),
                )
                : null;
            },
          );
          const handle = await context.writeResource(
            "vm",
            resourceInstanceName(
              args.subscriptionId,
              args.resourceGroup,
              args.name,
            ),
            state,
          );
          return { dataHandles: [handle], result: state };
        },
      },

      delete: {
        // A method literally named delete is a lifecycle verb; declaring it an
        // action keeps it from tombstoning every record the definition holds.
        kind: "action",
        description:
          "DESTRUCTIVE. Delete this model's VM and wait until Azure no longer returns it. Idempotent: an already-absent VM is a clean no-op.",
        arguments: ActionArgsSchema,
        execute: async (
          rawArgs: unknown,
          context: MethodContext,
        ): Promise<MethodResult> => {
          const args = rawArgs as ActionArgs;
          const client = createArmClient(deps, args);
          const instance = resourceInstanceName(
            args.subscriptionId,
            args.resourceGroup,
            args.name,
          );
          const existing = await readVm(client, args);
          if (existing === null) {
            context.logger.info("VM {name} already absent", {
              name: args.name,
            });
            const state = toState(
              args,
              null,
              "deleted",
              new Date(deps.now()).toISOString(),
            );
            const handle = await context.writeResource("vm", instance, state);
            return { dataHandles: [handle], result: state };
          }
          await client.del(vmUrl(args));
          await settle(
            deps,
            args,
            `VM ${args.name} deletion`,
            async () => await readVm(client, args) === null ? true : null,
          );
          const state = toState(
            args,
            existing.body,
            "deleted",
            new Date(deps.now()).toISOString(),
          );
          context.logger.info("VM {name} deleted", { name: args.name });
          const handle = await context.writeResource("vm", instance, state);
          return { dataHandles: [handle], result: state };
        },
      },
    },
  };
}

/** Production model: the factory with no overrides. */
export const model: VmModel = createModel();
