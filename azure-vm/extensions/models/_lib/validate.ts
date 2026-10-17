/**
 * Input grammars for the Azure extensions.
 *
 * Every caller value that reaches a URL path, a JSON body or a stored key is
 * validated here. The predicates are pure so the model schemas and the mapping
 * functions can share them.
 *
 * @module
 */

/** A validation failure; retrying will not fix it. */
export class GrammarError extends Error {
  /** Creates a grammar error. */
  constructor(message: string) {
    super(message);
    this.name = "GrammarError";
  }
}

/** RFC 4122 GUID, any version. */
export const GUID_RE =
  /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/;

/** An Azure resource name: 1-64 letters, digits, dot, underscore or hyphen. */
export const NAME_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;

/** A resource-group or subnet name: 1-90, no trailing period. */
export const RESOURCE_GROUP_RE = /^[A-Za-z0-9._()-]{1,90}$/;

/** A location token, e.g. `eastus2`. */
export const LOCATION_RE = /^[a-z0-9][a-z0-9-]{0,63}$/;

/** An ARM resource id path, with no traversal. */
export const ARM_ID_RE = /^\/[A-Za-z0-9._\-/]{1,1023}$/;

/** A single SSH public-key line, with no option prefix. */
export const SSH_PUBLIC_KEY_RE =
  /^(?:ssh-rsa|ssh-ed25519|ecdsa-sha2-nistp256|ssh-dss) [A-Za-z0-9+/]+={0,3}(?: [^\r\n]*)?$/;

/** True when `value` is a GUID. */
export function isGuid(value: string): boolean {
  return GUID_RE.test(value);
}

/** Throws unless `value` is a GUID. */
export function assertGuid(value: string, field: string): void {
  if (typeof value !== "string" || !GUID_RE.test(value)) {
    throw new GrammarError(`${field} must be an RFC 4122 GUID`);
  }
}

/** Throws unless `value` is an Azure resource name. */
export function assertName(value: string, field: string): void {
  if (typeof value !== "string" || !NAME_RE.test(value)) {
    throw new GrammarError(
      `${field} must be 1-64 letters, digits, dot, underscore or hyphen and start with a letter or digit`,
    );
  }
}

/** Throws unless `value` is a resource-group name. */
export function assertResourceGroup(value: string): void {
  if (
    typeof value !== "string" || !RESOURCE_GROUP_RE.test(value) ||
    value.endsWith(".")
  ) {
    throw new GrammarError(
      "resourceGroup must be 1-90 letters, digits, dot, underscore, hyphen or parentheses, with no trailing period",
    );
  }
}

/** Throws unless `value` is a location token. */
export function assertLocation(value: string): void {
  if (typeof value !== "string" || !LOCATION_RE.test(value)) {
    throw new GrammarError(
      "location must be a lowercase Azure region such as eastus2",
    );
  }
}

/** Throws unless `value` is an ARM resource id with no traversal. */
export function assertArmId(value: string, field: string): void {
  if (
    typeof value !== "string" || !ARM_ID_RE.test(value) ||
    value.split("/").includes("..")
  ) {
    throw new GrammarError(`${field} must be an absolute ARM resource id`);
  }
}

/** Throws unless `value` is one SSH public-key line. */
export function assertSshPublicKey(value: string): void {
  if (typeof value !== "string" || !SSH_PUBLIC_KEY_RE.test(value)) {
    throw new GrammarError(
      "sshPublicKey must be one '<type> <base64> [comment]' line with no options",
    );
  }
}

const IPV4_CIDR_RE = /^\d{1,3}(?:\.\d{1,3}){3}\/\d{1,2}$/;
const IPV6_CIDR_RE = /^[0-9a-fA-F:]+\/\d{1,3}$/;
const TAG_RE = /^[A-Za-z][A-Za-z0-9]{0,63}$/;

/** True when `value` is an Azure address prefix: `*`, a tag or a CIDR. */
export function isAddressPrefix(value: string): boolean {
  if (typeof value !== "string" || value === "") return false;
  if (value === "*") return true;
  if (value.includes(".") && IPV4_CIDR_RE.test(value)) {
    const [addr, prefix] = value.split("/");
    const octets = addr.split(".").map(Number);
    const bits = Number(prefix);
    return octets.every((o) => Number.isInteger(o) && o >= 0 && o <= 255) &&
      Number.isInteger(bits) && bits >= 0 && bits <= 32;
  }
  if (value.includes(":") && IPV6_CIDR_RE.test(value)) {
    return Number(value.split("/")[1]) <= 128;
  }
  return TAG_RE.test(value);
}

/** Throws unless `value` is an address prefix. */
export function assertAddressPrefix(value: string, field: string): void {
  if (!isAddressPrefix(value)) {
    throw new GrammarError(
      `${field} must be '*', a service tag or an IPv4/IPv6 CIDR`,
    );
  }
}

const PORT_RE = /^(?:\*|\d{1,5}(?:-\d{1,5})?)$/;

/** True when `value` is `*`, a port or a port range. */
export function isPortRange(value: string): boolean {
  if (typeof value !== "string" || !PORT_RE.test(value)) return false;
  if (value === "*") return true;
  const [low, high] = value.split("-").map(Number);
  if (low < 0 || low > 65535) return false;
  if (high !== undefined && (high < low || high > 65535)) return false;
  return true;
}

/** Throws unless `value` is a port or port range. */
export function assertPortRange(value: string, field: string): void {
  if (!isPortRange(value)) {
    throw new GrammarError(`${field} must be '*', a port or 'low-high'`);
  }
}

/** Throws unless `value` is a rule priority in 100-4096. */
export function assertPriority(value: number): void {
  if (!Number.isInteger(value) || value < 100 || value > 4096) {
    throw new GrammarError("priority must be an integer from 100 to 4096");
  }
}

/**
 * The unambiguous stored-state key for an Azure resource. Length-prefixed,
 * labeled components keep two targets with similar names apart.
 */
export function resourceInstanceName(
  subscriptionId: string,
  resourceGroup: string,
  name: string,
): string {
  return `s${subscriptionId.length}-${subscriptionId}` +
    `-g${resourceGroup.length}-${resourceGroup}` +
    `-n${name.length}-${name}`;
}

/** The stored-state key for one child resource such as an NSG rule. */
export function childInstanceName(
  subscriptionId: string,
  resourceGroup: string,
  parent: string,
  child: string,
): string {
  return `${resourceInstanceName(subscriptionId, resourceGroup, parent)}` +
    `-c${child.length}-${child}`;
}

/** Sorts a string array and returns a stable JSON fragment for comparison. */
export function canonicalList(values: readonly string[]): string {
  return JSON.stringify([...values].sort());
}
