/**
 * Swamp extension model for an Azure network security group and its rules,
 * driven through the Azure Resource Manager REST API with a service principal
 * from a vault.
 *
 * The definition is generic: global arguments are empty and every method takes
 * its own tenant, subscription, resource group and NSG name. Authentication
 * uses an OAuth2 client-credentials token whose secret travels only in the
 * HTTPS POST body. Stored state is keyed by subscription, resource group and
 * name, with rules keyed by their parent plus rule name.
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
  assertAddressPrefix,
  assertCidr,
  assertGuid,
  assertName,
  assertPortRange,
  assertPriority,
  assertResourceGroup,
  canonicalList,
  childInstanceName,
  GrammarError,
  GUID_RE,
  isAddressPrefix,
  isPortRange,
  NAME_RE,
  resourceInstanceName,
} from "./_lib/validate.ts";

/** Azure Network API version this model pins. */
export const NSG_API_VERSION = "2024-05-01";

const RESOURCE_GROUP_RE = /^[A-Za-z0-9._()-]{1,90}$/;

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
export interface NsgMethod {
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
export interface NsgModel {
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
  methods: Record<string, NsgMethod>;
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
  nsgName: z.string().regex(NAME_RE).max(64).describe(
    "Network security group name.",
  ),
};

const addressPrefix = z.string().max(64).refine(
  isAddressPrefix,
  "must be '*', a service tag or a CIDR",
);
const portRange = z.string().max(16).refine(
  isPortRange,
  "must be '*', a port or 'low-high'",
);

const RuleFields = {
  ruleName: z.string().regex(NAME_RE).max(64).describe("Security rule name."),
  priority: z.number().int().min(100).max(4096).describe("Rule priority."),
  direction: z.enum(["Inbound", "Outbound"]).describe("Traffic direction."),
  access: z.enum(["Allow", "Deny"]).describe("Allow or deny the match."),
  protocol: z.enum(["Tcp", "Udp", "Icmp", "*", "Ah", "Esp"]).describe(
    "IP protocol.",
  ),
  sourceAddressPrefixes: z.array(addressPrefix).min(1).max(64).describe(
    "Source address prefixes.",
  ),
  destinationAddressPrefixes: z.array(addressPrefix).min(1).max(64).describe(
    "Destination address prefixes.",
  ),
  sourcePortRanges: z.array(portRange).min(1).max(64).describe(
    "Source port ranges.",
  ),
  destinationPortRanges: z.array(portRange).min(1).max(64).describe(
    "Destination port ranges.",
  ),
  description: z.string().max(140).optional().describe("Rule description."),
};

const PollFields = {
  timeoutMs: z.number().int().min(1000).max(3_600_000).default(900_000)
    .describe("Total settle budget in milliseconds."),
  pollIntervalMs: z.number().int().min(250).max(60_000).default(5000).describe(
    "First poll interval in milliseconds.",
  ),
};

const ReadArgsSchema = z.strictObject({ ...AuthFields, ...TargetFields });

const RuleArgsSchema = z.strictObject({
  ...AuthFields,
  ...TargetFields,
  ...RuleFields,
  ...PollFields,
});

const RemoveRuleArgsSchema = z.strictObject({
  ...AuthFields,
  ...TargetFields,
  ruleName: z.string().regex(NAME_RE).max(64).describe("Security rule name."),
  ...PollFields,
});

const ApplyRuleSetArgsSchema = z.strictObject({
  ...AuthFields,
  ...TargetFields,
  rules: z.array(z.strictObject(RuleFields)).min(1).max(200).describe(
    "Declared security rules.",
  ),
  apply: z.boolean().default(false).describe(
    "Compute and record the plan only unless this is explicitly true.",
  ),
  ...PollFields,
});

const DeleteArgsSchema = z.strictObject({
  ...AuthFields,
  ...TargetFields,
  ...PollFields,
});

/** Strict schema for get/sync arguments. */
export const readArgsSchema = ReadArgsSchema;

/** Strict schema for ensure_rule arguments. */
export const ruleArgsSchema = RuleArgsSchema;

/** Strict schema for remove_rule arguments. */
export const removeRuleArgsSchema = RemoveRuleArgsSchema;

/** Strict schema for apply_rule_set arguments. */
export const applyRuleSetArgsSchema = ApplyRuleSetArgsSchema;

/** Strict schema for delete arguments. */
export const deleteArgsSchema = DeleteArgsSchema;

const NsgStateSchema = z.strictObject({
  subscriptionId: z.string(),
  resourceGroup: z.string(),
  name: z.string(),
  id: z.string().optional(),
  location: z.string().optional(),
  provisioningState: z.string().optional(),
  ruleCount: z.number().int().optional(),
  status: z.enum(["present", "not_found", "deleted"]),
  observedAt: z.string(),
});

const RuleStateSchema = z.strictObject({
  subscriptionId: z.string(),
  resourceGroup: z.string(),
  nsgName: z.string(),
  name: z.string(),
  priority: z.number().int().optional(),
  direction: z.string().optional(),
  access: z.string().optional(),
  protocol: z.string().optional(),
  sourceAddressPrefixes: z.array(z.string()).optional(),
  destinationAddressPrefixes: z.array(z.string()).optional(),
  sourcePortRanges: z.array(z.string()).optional(),
  destinationPortRanges: z.array(z.string()).optional(),
  description: z.string().optional(),
  provisioningState: z.string().optional(),
  status: z.enum(["present", "not_found", "deleted"]),
  changed: z.boolean(),
  observedAt: z.string(),
});

const RuleSetPlanSchema = z.strictObject({
  subscriptionId: z.string(),
  resourceGroup: z.string(),
  nsgName: z.string(),
  apply: z.boolean(),
  create: z.array(z.string()),
  update: z.array(z.string()),
  unchanged: z.array(z.string()),
  undeclared: z.array(z.string()),
  collisions: z.array(z.string()),
  applied: z.array(z.string()),
  observedAt: z.string(),
});

/** Stored state of one NSG. */
export type NsgState = z.infer<typeof NsgStateSchema>;

/** Stored state of one NSG rule. */
export type RuleState = z.infer<typeof RuleStateSchema>;

interface AuthArgs {
  tenantId: string;
  clientId: string;
  clientSecret: string;
  subscriptionId: string;
}

interface TargetArgs extends AuthArgs {
  resourceGroup: string;
  nsgName: string;
}

interface RuleArgs extends TargetArgs {
  ruleName: string;
  priority: number;
  direction: "Inbound" | "Outbound";
  access: "Allow" | "Deny";
  protocol: "Tcp" | "Udp" | "Icmp" | "*" | "Ah" | "Esp";
  sourceAddressPrefixes: string[];
  destinationAddressPrefixes: string[];
  sourcePortRanges: string[];
  destinationPortRanges: string[];
  description?: string;
  timeoutMs?: number;
  pollIntervalMs?: number;
}

interface RemoveRuleArgs extends TargetArgs {
  ruleName: string;
  timeoutMs?: number;
  pollIntervalMs?: number;
}

interface ApplyRuleSetArgs extends TargetArgs {
  rules: RuleArgs[];
  apply: boolean;
  timeoutMs?: number;
  pollIntervalMs?: number;
}

interface DeleteArgs extends TargetArgs {
  timeoutMs: number;
  pollIntervalMs: number;
}

/** Validates the target and returns the NSG ARM path. */
function nsgPath(args: TargetArgs): string {
  assertGuid(args.subscriptionId, "subscriptionId");
  assertResourceGroup(args.resourceGroup);
  assertName(args.nsgName, "nsgName");
  return `/subscriptions/${args.subscriptionId}` +
    `/resourceGroups/${args.resourceGroup}` +
    `/providers/Microsoft.Network/networkSecurityGroups/${args.nsgName}`;
}

/** The NSG URL with the pinned API version. */
export function nsgUrl(args: TargetArgs): string {
  return `${nsgPath(args)}?api-version=${NSG_API_VERSION}`;
}

/** The security-rule collection URL. */
export function rulesUrl(args: TargetArgs): string {
  return `${nsgPath(args)}/securityRules?api-version=${NSG_API_VERSION}`;
}

/** One security-rule URL. */
export function ruleUrl(args: TargetArgs, ruleName: string): string {
  assertName(ruleName, "ruleName");
  return `${
    nsgPath(args)
  }/securityRules/${ruleName}?api-version=${NSG_API_VERSION}`;
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

/**
 * Renders one address field. Azure only accepts a tag or `*` in the singular
 * field, so a single value always uses it and a plural list must be all CIDRs.
 */
function addressField(
  values: string[],
  plural: string,
  singular: string,
): Record<string, unknown> {
  if (values.length === 1) return { [singular]: values[0] };
  for (const value of values) assertCidr(value, plural);
  return { [plural]: values };
}

/** Renders one port field as the singular or plural form, as Azure expects. */
function portField(
  values: string[],
  plural: string,
  singular: string,
): Record<string, unknown> {
  if (values.length === 1) return { [singular]: values[0] };
  for (const value of values) {
    if (value === "*") {
      throw new GrammarError(
        `${plural} may not contain '*' when more than one value is given`,
      );
    }
  }
  return { [plural]: values };
}

/**
 * Normalizes a singular or plural rule list to a string array. Azure returns
 * both forms on a read: a set singular value beside an empty plural array, or
 * the plural array beside a null singular. A non-empty plural wins, then the
 * singular string.
 */
function fieldList(
  props: Record<string, unknown>,
  plural: string,
  singular: string,
): string[] | undefined {
  const pluralValue = props[plural];
  if (Array.isArray(pluralValue) && pluralValue.length > 0) {
    return pluralValue.map(String);
  }
  const singularValue = props[singular];
  if (typeof singularValue === "string") return [singularValue];
  return undefined;
}

/** Builds the ARM request body for one rule; pure and testable. */
export function buildRuleBody(rule: RuleArgs): Record<string, unknown> {
  assertName(rule.ruleName, "ruleName");
  assertPriority(rule.priority);
  for (const prefix of rule.sourceAddressPrefixes) {
    assertAddressPrefix(prefix, "sourceAddressPrefixes");
  }
  for (const prefix of rule.destinationAddressPrefixes) {
    assertAddressPrefix(prefix, "destinationAddressPrefixes");
  }
  for (const range of rule.sourcePortRanges) {
    assertPortRange(range, "sourcePortRanges");
  }
  for (const range of rule.destinationPortRanges) {
    assertPortRange(range, "destinationPortRanges");
  }
  const props: Record<string, unknown> = {
    priority: rule.priority,
    direction: rule.direction,
    access: rule.access,
    protocol: rule.protocol,
    ...addressField(
      rule.sourceAddressPrefixes,
      "sourceAddressPrefixes",
      "sourceAddressPrefix",
    ),
    ...addressField(
      rule.destinationAddressPrefixes,
      "destinationAddressPrefixes",
      "destinationAddressPrefix",
    ),
    ...portField(rule.sourcePortRanges, "sourcePortRanges", "sourcePortRange"),
    ...portField(
      rule.destinationPortRanges,
      "destinationPortRanges",
      "destinationPortRange",
    ),
  };
  if (rule.description !== undefined) props.description = rule.description;
  return { name: rule.ruleName, properties: props };
}

/** True when an existing ARM rule already matches `desired`. */
export function ruleMatches(existing: unknown, desired: RuleArgs): boolean {
  const props = properties(existing);
  if (props.priority !== desired.priority) return false;
  if (props.direction !== desired.direction) return false;
  if (props.access !== desired.access) return false;
  if (props.protocol !== desired.protocol) return false;
  const lists: [string, string, string[]][] = [
    [
      "sourceAddressPrefixes",
      "sourceAddressPrefix",
      desired.sourceAddressPrefixes,
    ],
    [
      "destinationAddressPrefixes",
      "destinationAddressPrefix",
      desired.destinationAddressPrefixes,
    ],
    ["sourcePortRanges", "sourcePortRange", desired.sourcePortRanges],
    [
      "destinationPortRanges",
      "destinationPortRange",
      desired.destinationPortRanges,
    ],
  ];
  for (const [plural, singular, expected] of lists) {
    const actual = fieldList(props, plural, singular);
    if (actual === undefined) return false;
    if (canonicalList(actual) !== canonicalList(expected)) return false;
  }
  const wantedDescription = desired.description ?? "";
  const actualDescription = typeof props.description === "string"
    ? props.description
    : "";
  return wantedDescription === actualDescription;
}

/** Maps an ARM NSG body onto stored state. */
export function toNsgState(
  args: TargetArgs,
  body: unknown,
  status: NsgState["status"],
  observedAt: string,
): NsgState {
  const record = body && typeof body === "object"
    ? body as Record<string, unknown>
    : {};
  const props = properties(body);
  const state: Record<string, unknown> = {
    subscriptionId: args.subscriptionId,
    resourceGroup: args.resourceGroup,
    name: args.nsgName,
    status,
    observedAt,
  };
  if (typeof record.id === "string") state.id = record.id;
  if (typeof record.location === "string") state.location = record.location;
  if (typeof props.provisioningState === "string") {
    state.provisioningState = props.provisioningState;
  }
  if (Array.isArray(props.securityRules)) {
    state.ruleCount = props.securityRules.length;
  }
  return NsgStateSchema.parse(state);
}

/** Maps an ARM rule body onto stored state. */
export function toRuleState(
  args: TargetArgs,
  ruleName: string,
  body: unknown,
  status: RuleState["status"],
  changed: boolean,
  observedAt: string,
): RuleState {
  const props = properties(body);
  const state: Record<string, unknown> = {
    subscriptionId: args.subscriptionId,
    resourceGroup: args.resourceGroup,
    nsgName: args.nsgName,
    name: ruleName,
    status,
    changed,
    observedAt,
  };
  if (typeof props.priority === "number") state.priority = props.priority;
  for (const field of ["direction", "access", "protocol", "description"]) {
    if (typeof props[field] === "string") state[field] = props[field];
  }
  const lists: [string, string][] = [
    ["sourceAddressPrefixes", "sourceAddressPrefix"],
    ["destinationAddressPrefixes", "destinationAddressPrefix"],
    ["sourcePortRanges", "sourcePortRange"],
    ["destinationPortRanges", "destinationPortRange"],
  ];
  for (const [plural, singular] of lists) {
    const list = fieldList(props, plural, singular);
    if (list !== undefined) state[plural] = list;
  }
  if (typeof props.provisioningState === "string") {
    state.provisioningState = props.provisioningState;
  }
  return RuleStateSchema.parse(state);
}

/** Reads an NSG, returning null on a 404. */
async function readNsg(
  client: ArmClient,
  args: TargetArgs,
): Promise<ArmResult | null> {
  try {
    return await client.get(nsgUrl(args));
  } catch (error) {
    if (isNotFound(error)) return null;
    throw error;
  }
}

/** Reads one rule, returning null on a 404. */
async function readRule(
  client: ArmClient,
  args: TargetArgs,
  ruleName: string,
): Promise<ArmResult | null> {
  try {
    return await client.get(ruleUrl(args, ruleName));
  } catch (error) {
    if (isNotFound(error)) return null;
    throw error;
  }
}

/** Reads the security-rule collection as an array of raw rules. */
async function listRules(
  client: ArmClient,
  args: TargetArgs,
): Promise<Record<string, unknown>[]> {
  const result = await client.get(rulesUrl(args));
  const body = result.body;
  if (!body || typeof body !== "object") return [];
  const value = (body as Record<string, unknown>).value;
  return Array.isArray(value)
    ? value.filter((entry): entry is Record<string, unknown> =>
      entry !== null && typeof entry === "object"
    )
    : [];
}

/** Writes one NSG state record. */
async function writeNsg(
  context: MethodContext,
  args: TargetArgs,
  body: unknown,
  status: NsgState["status"],
  observedAt: string,
): Promise<DataHandle> {
  return await context.writeResource(
    "nsg",
    resourceInstanceName(args.subscriptionId, args.resourceGroup, args.nsgName),
    toNsgState(args, body, status, observedAt),
  );
}

/** Writes one rule state record. */
async function writeRule(
  context: MethodContext,
  args: TargetArgs,
  ruleName: string,
  body: unknown,
  status: RuleState["status"],
  changed: boolean,
  observedAt: string,
): Promise<DataHandle> {
  return await context.writeResource(
    "rule",
    childInstanceName(
      args.subscriptionId,
      args.resourceGroup,
      args.nsgName,
      ruleName,
    ),
    toRuleState(args, ruleName, body, status, changed, observedAt),
  );
}

/** The rule name carried in an ARM rule body. */
function nameOf(body: unknown): string {
  if (body && typeof body === "object") {
    const name = (body as Record<string, unknown>).name;
    if (typeof name === "string") return name;
  }
  return "";
}

/**
 * Waits until a rule write reaches Succeeded and the live rule matches the
 * desired one. A GET right after an async PUT can still return the old rule,
 * and a Failed or Canceled state ends the wait immediately.
 */
async function awaitRule(
  deps: ArmDeps,
  client: ArmClient,
  args: TargetArgs & { timeoutMs?: number; pollIntervalMs?: number },
  desired: RuleArgs,
  label: string,
): Promise<ArmResult> {
  return await pollUntil(deps, {
    deadlineMs: args.timeoutMs ?? 900_000,
    intervalMs: args.pollIntervalMs ?? 5000,
    label,
  }, async () => {
    const current = await readRule(client, args, desired.ruleName);
    if (current === null) return null;
    const state = properties(current.body).provisioningState;
    if (state === "Failed" || state === "Canceled") {
      throw new GrammarError(`rule ${desired.ruleName} reached ${state}`);
    }
    return state === "Succeeded" && ruleMatches(current.body, desired)
      ? current
      : null;
  });
}

/** Waits until a rule is absent after a delete. */
async function awaitRuleGone(
  deps: ArmDeps,
  client: ArmClient,
  args: TargetArgs & { timeoutMs?: number; pollIntervalMs?: number },
  ruleName: string,
  label: string,
): Promise<void> {
  await pollUntil(deps, {
    deadlineMs: args.timeoutMs ?? 900_000,
    intervalMs: args.pollIntervalMs ?? 5000,
    label,
  }, async () => await readRule(client, args, ruleName) === null ? true : null);
}

/**
 * The priority collisions that make a sequential apply unsafe: duplicate names
 * or priorities inside the declared set, or a declared priority already held by
 * a rule that is not being moved.
 */
function ruleSetCollisions(
  rules: RuleArgs[],
  existing: Record<string, unknown>[],
): string[] {
  const out: string[] = [];
  const names = new Map<string, number>();
  const priorities = new Map<string, string>();
  for (const rule of rules) {
    names.set(rule.ruleName, (names.get(rule.ruleName) ?? 0) + 1);
    const key = `${rule.direction}|${rule.priority}`;
    const holder = priorities.get(key);
    if (holder !== undefined) {
      out.push(
        `duplicate priority ${rule.priority} for ${rule.direction}: ${holder} and ${rule.ruleName}`,
      );
    } else priorities.set(key, rule.ruleName);
  }
  for (const [name, count] of names) {
    if (count > 1) out.push(`duplicate ruleName ${name} (${count} times)`);
  }
  for (const rule of rules) {
    for (const entry of existing) {
      const name = nameOf(entry);
      if (name === rule.ruleName) continue;
      const props = properties(entry);
      if (
        props.direction === rule.direction && props.priority === rule.priority
      ) {
        out.push(
          `priority ${rule.priority} for ${rule.direction} is held by existing rule ${name} and declared by ${rule.ruleName}`,
        );
      }
    }
  }
  return [...new Set(out)].sort();
}

/**
 * Builds the model with injectable dependencies. The production export is
 * `createModel()`; tests pass a fake fetch, clock and sleep.
 */
export function createModel(deps: ArmDeps = denoArmDeps): NsgModel {
  return {
    type: "@randybias/azure-nsg",
    version: "2026.10.17.1",
    description:
      "Inspect and delete an Azure network security group and converge its security rules through the Azure Resource Manager REST API with a service principal from a vault, keyed by subscription, resource group and name.",
    globalArguments: z.strictObject({}),
    resources: {
      nsg: {
        description:
          "Azure NSG state: id, location, provisioning state and rule count",
        schema: NsgStateSchema,
        lifetime: "infinite",
        garbageCollection: 10,
      },
      rule: {
        description: "One converged NSG security rule and its change flag",
        schema: RuleStateSchema,
        lifetime: "infinite",
        garbageCollection: 10,
      },
      ruleSet: {
        description: "The plan and applied set of one apply_rule_set call",
        schema: RuleSetPlanSchema,
        lifetime: "infinite",
        garbageCollection: 10,
      },
    },
    methods: {
      get: {
        description:
          "READ-ONLY. Fetch one NSG from Azure and store its state. Fails when the NSG does not exist.",
        arguments: ReadArgsSchema,
        execute: async (
          rawArgs: unknown,
          context: MethodContext,
        ): Promise<MethodResult> => {
          const args = rawArgs as TargetArgs;
          const client = createArmClient(deps, args);
          const result = await client.get(nsgUrl(args));
          const handle = await writeNsg(
            context,
            args,
            result.body,
            "present",
            new Date(deps.now()).toISOString(),
          );
          context.logger.info("NSG {name} found", { name: args.nsgName });
          return {
            dataHandles: [handle],
            result: toNsgState(
              args,
              result.body,
              "present",
              new Date(deps.now()).toISOString(),
            ),
          };
        },
      },

      sync: {
        description:
          "READ-ONLY. Refresh stored NSG state; records status not_found instead of failing when the NSG is gone.",
        arguments: ReadArgsSchema,
        execute: async (
          rawArgs: unknown,
          context: MethodContext,
        ): Promise<MethodResult> => {
          const args = rawArgs as TargetArgs;
          const client = createArmClient(deps, args);
          const result = await readNsg(client, args);
          const status = result === null ? "not_found" : "present";
          const observedAt = new Date(deps.now()).toISOString();
          const handle = await writeNsg(
            context,
            args,
            result?.body ?? null,
            status,
            observedAt,
          );
          context.logger.info("NSG {name} status {status}", {
            name: args.nsgName,
            status,
          });
          return {
            dataHandles: [handle],
            result: toNsgState(args, result?.body ?? null, status, observedAt),
          };
        },
      },

      ensure_rule: {
        kind: "action",
        description:
          "DESTRUCTIVE. Create or converge one security rule by name and store its state. Idempotent: an identical rule is a no-op with changed false.",
        arguments: RuleArgsSchema,
        execute: async (
          rawArgs: unknown,
          context: MethodContext,
        ): Promise<MethodResult> => {
          const args = rawArgs as RuleArgs;
          const client = createArmClient(deps, args);
          const existing = await readRule(client, args, args.ruleName);
          if (existing !== null && ruleMatches(existing.body, args)) {
            const handle = await writeRule(
              context,
              args,
              args.ruleName,
              existing.body,
              "present",
              false,
              new Date(deps.now()).toISOString(),
            );
            context.logger.info("Rule {rule} already current", {
              rule: args.ruleName,
            });
            return {
              dataHandles: [handle],
              result: { changed: false, name: args.ruleName },
            };
          }
          await client.put(ruleUrl(args, args.ruleName), buildRuleBody(args));
          const applied = await awaitRule(
            deps,
            client,
            args,
            args,
            `Rule ${args.ruleName} update`,
          );
          const handle = await writeRule(
            context,
            args,
            args.ruleName,
            applied.body,
            "present",
            true,
            new Date(deps.now()).toISOString(),
          );
          context.logger.info("Rule {rule} converged", { rule: args.ruleName });
          return {
            dataHandles: [handle],
            result: { changed: true, name: args.ruleName },
          };
        },
      },

      remove_rule: {
        kind: "action",
        description:
          "DESTRUCTIVE. Delete one security rule by name. Idempotent: an already-absent rule is a clean no-op with changed false.",
        arguments: RemoveRuleArgsSchema,
        execute: async (
          rawArgs: unknown,
          context: MethodContext,
        ): Promise<MethodResult> => {
          const args = rawArgs as RemoveRuleArgs;
          const client = createArmClient(deps, args);
          const existing = await readRule(client, args, args.ruleName);
          const observedAt = new Date(deps.now()).toISOString();
          if (existing === null) {
            const handle = await writeRule(
              context,
              args,
              args.ruleName,
              null,
              "not_found",
              false,
              observedAt,
            );
            context.logger.info("Rule {rule} already absent", {
              rule: args.ruleName,
            });
            return {
              dataHandles: [handle],
              result: { changed: false, name: args.ruleName },
            };
          }
          await client.del(ruleUrl(args, args.ruleName));
          await awaitRuleGone(
            deps,
            client,
            args,
            args.ruleName,
            `Rule ${args.ruleName} removal`,
          );
          const handle = await writeRule(
            context,
            args,
            args.ruleName,
            existing.body,
            "deleted",
            true,
            observedAt,
          );
          context.logger.info("Rule {rule} removed", { rule: args.ruleName });
          return {
            dataHandles: [handle],
            result: { changed: true, name: args.ruleName },
          };
        },
      },

      apply_rule_set: {
        kind: "action",
        description:
          "DESTRUCTIVE. Converge a declared set of security rules: create missing, update differing, leave undeclared rules alone. Plans first and only changes anything when apply is explicitly true.",
        arguments: ApplyRuleSetArgsSchema,
        execute: async (
          rawArgs: unknown,
          context: MethodContext,
        ): Promise<MethodResult> => {
          const args = rawArgs as ApplyRuleSetArgs;
          const client = createArmClient(deps, args);
          const existing = await listRules(client, args);
          const byName = new Map<string, Record<string, unknown>>();
          for (const rule of existing) byName.set(nameOf(rule), rule);
          const declared = new Set(args.rules.map((rule) => rule.ruleName));
          const plan = {
            create: [] as string[],
            update: [] as string[],
            unchanged: [] as string[],
            undeclared: existing.map(nameOf).filter((name) =>
              name !== "" && !declared.has(name)
            ),
            collisions: [] as string[],
            applied: [] as string[],
          };
          for (const rule of args.rules) {
            const current = byName.get(rule.ruleName);
            if (current === undefined) plan.create.push(rule.ruleName);
            else if (ruleMatches(current, rule)) {
              plan.unchanged.push(rule.ruleName);
            } else plan.update.push(rule.ruleName);
          }
          plan.collisions = ruleSetCollisions(args.rules, existing);
          // Build every desired body before any PUT, so a grammar or plural-list
          // violation is recorded and refuses the whole set with zero writes.
          const bodies = new Map<string, Record<string, unknown>>();
          for (const rule of args.rules) {
            try {
              bodies.set(rule.ruleName, buildRuleBody(rule));
            } catch (error) {
              plan.collisions.push(
                `invalid rule ${rule.ruleName}: ${
                  error instanceof Error ? error.message : String(error)
                }`,
              );
            }
          }
          plan.collisions = [...new Set(plan.collisions)].sort();
          if (args.apply && plan.collisions.length === 0) {
            for (const rule of args.rules) {
              if (plan.unchanged.includes(rule.ruleName)) continue;
              await client.put(
                ruleUrl(args, rule.ruleName),
                bodies.get(rule.ruleName) as Record<string, unknown>,
              );
              await awaitRule(
                deps,
                client,
                args,
                rule,
                `Rule ${rule.ruleName} update`,
              );
              plan.applied.push(rule.ruleName);
            }
          }
          const observedAt = new Date(deps.now()).toISOString();
          const handle = await context.writeResource(
            "ruleSet",
            resourceInstanceName(
              args.subscriptionId,
              args.resourceGroup,
              args.nsgName,
            ),
            RuleSetPlanSchema.parse({
              subscriptionId: args.subscriptionId,
              resourceGroup: args.resourceGroup,
              nsgName: args.nsgName,
              apply: args.apply,
              create: plan.create,
              update: plan.update,
              unchanged: plan.unchanged,
              undeclared: plan.undeclared,
              collisions: plan.collisions,
              applied: plan.applied,
              observedAt,
            }),
          );
          if (args.apply && plan.collisions.length > 0) {
            throw new GrammarError(
              `apply_rule_set refused ${plan.collisions.length} priority collision(s); no rule was changed`,
            );
          }
          context.logger.info(
            "Rule set plan for {nsg}: create {create}, update {update}, unchanged {unchanged}",
            {
              nsg: args.nsgName,
              create: plan.create.length,
              update: plan.update.length,
              unchanged: plan.unchanged.length,
            },
          );
          return { dataHandles: [handle], result: plan };
        },
      },

      delete: {
        // A method literally named delete is a lifecycle verb; declaring it an
        // action keeps it from tombstoning every record the definition holds.
        kind: "action",
        description:
          "DESTRUCTIVE. Delete this model's NSG and wait until Azure no longer returns it. Idempotent: an already-absent NSG is a clean no-op.",
        arguments: DeleteArgsSchema,
        execute: async (
          rawArgs: unknown,
          context: MethodContext,
        ): Promise<MethodResult> => {
          const args = rawArgs as DeleteArgs;
          const client = createArmClient(deps, args);
          const instance = resourceInstanceName(
            args.subscriptionId,
            args.resourceGroup,
            args.nsgName,
          );
          const existing = await readNsg(client, args);
          if (existing === null) {
            context.logger.info("NSG {name} already absent", {
              name: args.nsgName,
            });
            const handle = await context.writeResource(
              "nsg",
              instance,
              toNsgState(
                args,
                null,
                "deleted",
                new Date(deps.now()).toISOString(),
              ),
            );
            return {
              dataHandles: [handle],
              result: { status: "deleted", deleted: false },
            };
          }
          await client.del(nsgUrl(args));
          await pollUntil(deps, {
            deadlineMs: args.timeoutMs,
            intervalMs: args.pollIntervalMs,
            label: `NSG ${args.nsgName} deletion`,
          }, async () => await readNsg(client, args) === null ? true : null);
          const handle = await context.writeResource(
            "nsg",
            instance,
            toNsgState(
              args,
              existing.body,
              "deleted",
              new Date(deps.now()).toISOString(),
            ),
          );
          context.logger.info("NSG {name} deleted", { name: args.nsgName });
          return {
            dataHandles: [handle],
            result: { status: "deleted", deleted: true },
          };
        },
      },
    },
  };
}

/** Production model: the factory with no overrides. */
export const model = {
  ...createModel(),
  type: "@randybias/azure-nsg",
  version: "2026.10.17.1",
} satisfies NsgModel;
