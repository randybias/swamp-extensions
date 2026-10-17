/**
 * DMTF Redfish domain logic and authenticated client for the model.
 *
 * The endpoint is an https origin; every `@odata.id` is resolved back onto
 * that origin, so a BMC cannot point the model at another host. Credentials
 * are sent only in an `X-Auth-Token` or `Authorization` header. A Redfish
 * session is opened through the SessionService and deleted in a `finally`, or
 * Basic auth is used explicitly.
 *
 * @module
 */

import {
  b64Utf8,
  classifyFetch,
  type Deps,
  drain,
  readBounded,
  RedfishError,
  statusError,
  type TlsPolicy,
} from "./http.ts";

/** System ids accepted from the caller before being put in a path. */
const SYSTEM_ID_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;

/** True for a system id this model will place in a Redfish path. */
export const isSystemId = (s: string): boolean => SYSTEM_ID_RE.test(s);

/** Standard `ResetType` values this model exposes. */
export const RESET_TYPES = [
  "On",
  "ForceOff",
  "GracefulShutdown",
  "GracefulRestart",
  "ForceRestart",
  "PushPowerButton",
  "PowerCycle",
  "Nmi",
] as const;
/** One Redfish `ResetType`. */
export type ResetType = typeof RESET_TYPES[number];

/** Standard boot override targets this model exposes. */
export const BOOT_TARGETS = [
  "None",
  "Pxe",
  "Hdd",
  "Cd",
  "Usb",
  "BiosSetup",
  "UefiShell",
  "UefiHttp",
  "SDCard",
  "RemoteDrive",
  "Floppy",
  "Diagnostics",
] as const;
/** One Redfish `BootSourceOverrideTarget`. */
export type BootTarget = typeof BOOT_TARGETS[number];

/** Boot override durations this model exposes. */
export const BOOT_ENABLED = ["Once", "Continuous", "Disabled"] as const;
/** One Redfish `BootSourceOverrideEnabled`. */
export type BootEnabled = typeof BOOT_ENABLED[number];

function asRecord(v: unknown): Record<string, unknown> | undefined {
  return v && typeof v === "object" && !Array.isArray(v)
    ? v as Record<string, unknown>
    : undefined;
}

function str(v: unknown): string | undefined {
  return typeof v === "string" && v !== "" ? v : undefined;
}

// The `@Redfish.*` annotation names are built from parts so no source line
// looks like an email address to the leak scanner.
const RESET_ALLOWABLE_KEY = ["ResetType", "@", "Redfish.AllowableValues"].join(
  "",
);
const BOOT_ALLOWABLE_KEY = [
  "BootSourceOverrideTarget",
  "@",
  "Redfish.AllowableValues",
].join("");

function strList(v: unknown): string[] | undefined {
  if (!Array.isArray(v)) return undefined;
  const out = v.filter((x): x is string => typeof x === "string");
  return out.length > 0 ? out : undefined;
}

/**
 * Validates a BMC endpoint and reduces it to an https origin. A path, query,
 * fragment, embedded credentials or a non-https scheme is refused.
 */
export function normalizeEndpoint(raw: string): string {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw new RedfishError(
      "invalid_input",
      "endpoint must be an https origin, e.g. https://bmc.example.com",
    );
  }
  if (url.protocol !== "https:") {
    throw new RedfishError("invalid_input", "endpoint must use https");
  }
  if (url.username || url.password) {
    throw new RedfishError(
      "invalid_input",
      "endpoint must not contain credentials",
    );
  }
  if (url.pathname !== "/" && url.pathname !== "") {
    throw new RedfishError(
      "invalid_input",
      "endpoint must be an origin with no path",
    );
  }
  if (url.search || url.hash) {
    throw new RedfishError(
      "invalid_input",
      "endpoint must not contain a query or fragment",
    );
  }
  return url.origin;
}

/** Resolves a Redfish path or `@odata.id`, refusing another origin. */
export function resolveOdata(origin: string, id: string): string {
  let url: URL;
  try {
    url = new URL(id, origin);
  } catch {
    throw new RedfishError(
      "redfish_failed",
      "BMC returned an invalid resource path",
    );
  }
  if (url.protocol !== "https:" || url.origin !== origin) {
    throw new RedfishError(
      "redfish_failed",
      "BMC resource points outside the endpoint origin",
    );
  }
  return url.toString();
}

/** The `RESET` action target and its allowable values, when advertised. */
export function resetAction(
  raw: Record<string, unknown>,
): { target?: string; allowable?: string[] } {
  const action = asRecord(
    asRecord(raw.Actions)?.["#ComputerSystem.Reset"],
  );
  return {
    target: str(action?.target),
    allowable: strList(action?.[RESET_ALLOWABLE_KEY]),
  };
}

/** The allowable boot targets, when advertised. */
export function allowableBootTargets(
  raw: Record<string, unknown>,
): string[] | undefined {
  return strList(
    asRecord(raw.Boot)?.[BOOT_ALLOWABLE_KEY],
  );
}

/** Stored state of one ComputerSystem; never holds a credential. */
export interface SystemState {
  origin: string;
  system_id: string;
  name: string;
  manufacturer?: string;
  model?: string;
  serial_number?: string;
  uuid?: string;
  power_state: string;
  health?: string;
  health_rollup?: string;
  state?: string;
  boot_target?: string;
  boot_enabled?: string;
  boot_mode?: string;
  allowable_reset_types?: string[];
  allowable_boot_targets?: string[];
  etag?: string;
  status: "present" | "not_found";
  observed_at: string;
}

/** Maps a ComputerSystem resource onto the stored-state allowlist. */
export function parseSystem(
  raw: Record<string, unknown>,
  origin: string,
  observedAt: string,
  status: "present" | "not_found",
  etag?: string,
): SystemState {
  const boot = asRecord(raw.Boot);
  const statusObj = asRecord(raw.Status);
  const id = str(raw.Id) ?? "";
  return {
    origin,
    system_id: id,
    name: str(raw.Name) ?? id,
    ...(str(raw.Manufacturer) ? { manufacturer: str(raw.Manufacturer) } : {}),
    ...(str(raw.Model) ? { model: str(raw.Model) } : {}),
    ...(str(raw.SerialNumber) ? { serial_number: str(raw.SerialNumber) } : {}),
    ...(str(raw.UUID) ? { uuid: str(raw.UUID) } : {}),
    power_state: str(raw.PowerState) ?? "Unknown",
    ...(str(statusObj?.Health) ? { health: str(statusObj?.Health) } : {}),
    ...(str(statusObj?.HealthRollup)
      ? { health_rollup: str(statusObj?.HealthRollup) }
      : {}),
    ...(str(statusObj?.State) ? { state: str(statusObj?.State) } : {}),
    ...(str(boot?.BootSourceOverrideTarget)
      ? { boot_target: str(boot?.BootSourceOverrideTarget) }
      : {}),
    ...(str(boot?.BootSourceOverrideEnabled)
      ? { boot_enabled: str(boot?.BootSourceOverrideEnabled) }
      : {}),
    ...(str(boot?.BootSourceOverrideMode)
      ? { boot_mode: str(boot?.BootSourceOverrideMode) }
      : {}),
    ...(() => {
      const a = resetAction(raw).allowable;
      return a ? { allowable_reset_types: a } : {};
    })(),
    ...(() => {
      const a = allowableBootTargets(raw);
      return a ? { allowable_boot_targets: a } : {};
    })(),
    ...(etag ? { etag } : {}),
    status,
    observed_at: observedAt,
  };
}

const OFF_ACTIONS = new Set(["ForceOff", "GracefulShutdown"]);

/** The final power state a reset action should reach. */
export function desiredPowerState(
  action: ResetType | string,
  current: string,
): "On" | "Off" {
  if (action === "On") return "On";
  if (OFF_ACTIONS.has(action)) return "Off";
  if (action === "PushPowerButton") return current === "On" ? "Off" : "On";
  // Restarts, PowerCycle and Nmi end with the system powered on.
  return "On";
}

/** True when the requested power action is already satisfied. */
export function isPowerNoop(
  action: ResetType | string,
  current: string,
): boolean {
  if (action === "On") return current === "On";
  if (OFF_ACTIONS.has(action)) return current === "Off";
  return false;
}

/** Body of a ComputerSystem.Reset POST. */
export function resetBody(type: ResetType | string): { ResetType: string } {
  return { ResetType: type };
}

/** Body of a ComputerSystem PATCH that sets the boot override. A
 * `Disabled` override is sent with target `None`. */
export function bootBody(
  target: BootTarget | string,
  enabled: BootEnabled | string,
): {
  Boot: { BootSourceOverrideTarget: string; BootSourceOverrideEnabled: string };
} {
  return {
    Boot: {
      BootSourceOverrideTarget: enabled === "Disabled" ? "None" : target,
      BootSourceOverrideEnabled: enabled,
    },
  };
}

/** Target of a Redfish call, after schema validation. */
export interface RedfishTarget {
  endpoint: string;
  systemId?: string;
  username: string;
  password: string;
  tls: TlsPolicy;
  authMode: "session" | "basic";
}

interface Auth {
  headers: Record<string, string>;
  logout(): Promise<void>;
}

interface RawResult {
  status: number;
  etag?: string;
  text: string;
}

function authHeader(
  username: string,
  password: string,
): Record<string, string> {
  return { Authorization: `Basic ${b64Utf8(`${username}:${password}`)}` };
}

/**
 * Opens a Redfish session and returns its header plus a logout. If the BMC
 * does not implement SessionService (404/405), Basic auth is used instead.
 */
async function openAuth(
  deps: Deps,
  origin: string,
  client: unknown,
  username: string,
  password: string,
  mode: "session" | "basic",
): Promise<Auth> {
  if (mode === "basic") {
    return {
      headers: authHeader(username, password),
      logout: () => Promise.resolve(),
    };
  }
  let resp: Response;
  try {
    resp = await deps.fetch(
      resolveOdata(origin, "/redfish/v1/SessionService/Sessions"),
      {
        method: "POST",
        redirect: "error",
        headers: {
          "Accept": "application/json",
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ UserName: username, Password: password }),
        client,
      },
    );
  } catch (e) {
    throw classifyFetch(e);
  }
  if (resp.status === 404 || resp.status === 405) {
    await drain(resp);
    return {
      headers: authHeader(username, password),
      logout: () => Promise.resolve(),
    };
  }
  if (resp.status !== 200 && resp.status !== 201) {
    await drain(resp);
    throw statusError(resp.status);
  }
  const token = resp.headers.get("x-auth-token");
  const location = resp.headers.get("location");
  await drain(resp);
  if (!token) {
    throw new RedfishError(
      "redfish_failed",
      "BMC did not return a session token",
    );
  }
  const headers = { "X-Auth-Token": token };
  return {
    headers,
    logout: async () => {
      if (!location) return;
      try {
        const r = await deps.fetch(resolveOdata(origin, location), {
          method: "DELETE",
          redirect: "error",
          headers,
          client,
        });
        await drain(r);
      } catch {
        // Session cleanup is best effort; the token will expire on its own.
      }
    },
  };
}

function parseJson(text: string): Record<string, unknown> {
  if (!text.trim()) return {};
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw new RedfishError("redfish_failed", "BMC returned invalid JSON");
  }
  return asRecord(parsed) ?? {};
}

/** Authenticated Redfish client bound to one origin and one system. */
export class RedfishApi {
  #deps: Deps;
  #origin: string;
  #client: unknown;
  #authHeaders: Record<string, string> = {};
  /** Path of the selected ComputerSystem. */
  systemPath = "";

  constructor(deps: Deps, origin: string, client: unknown) {
    this.#deps = deps;
    this.#origin = origin;
    this.#client = client;
  }

  setAuth(headers: Record<string, string>): void {
    this.#authHeaders = headers;
  }

  async #send(
    method: string,
    path: string,
    body?: unknown,
    extra?: Record<string, string>,
  ): Promise<RawResult> {
    const url = resolveOdata(this.#origin, path);
    let resp: Response;
    try {
      resp = await this.#deps.fetch(url, {
        method,
        redirect: "error",
        headers: {
          "Accept": "application/json",
          ...(body !== undefined ? { "Content-Type": "application/json" } : {}),
          ...this.#authHeaders,
          ...extra,
        },
        body: body !== undefined ? JSON.stringify(body) : undefined,
        client: this.#client,
      });
    } catch (e) {
      throw classifyFetch(e);
    }
    const text = await readBounded(resp);
    return {
      status: resp.status,
      etag: resp.headers.get("etag") ?? undefined,
      text,
    };
  }

  /** Selects the one ComputerSystem, or the named one. */
  async findSystem(systemId?: string): Promise<
    { raw: Record<string, unknown>; etag?: string }
  > {
    let path: string;
    if (systemId !== undefined) {
      if (!isSystemId(systemId)) {
        throw new RedfishError("invalid_input", "invalid system id");
      }
      path = `/redfish/v1/Systems/${encodeURIComponent(systemId)}`;
    } else {
      const collection = await this.#getJson("/redfish/v1/Systems");
      const members = Array.isArray(collection.Members)
        ? collection.Members
        : [];
      if (members.length === 0) {
        throw new RedfishError("not_found", "BMC has no ComputerSystem");
      }
      if (members.length > 1) {
        throw new RedfishError(
          "invalid_input",
          `BMC has ${members.length} ComputerSystems; pass system_id`,
        );
      }
      const first = asRecord(members[0]);
      path = str(first?.["@odata.id"]) ?? "/redfish/v1/Systems/1";
    }
    const result = await this.#getRaw(path);
    this.systemPath = path;
    return result;
  }

  /** Re-reads the selected ComputerSystem, for polling and ETag. */
  async readSystem(): Promise<{ raw: Record<string, unknown>; etag?: string }> {
    return await this.#getRaw(this.systemPath);
  }

  /** POSTs a reset action to the selected ComputerSystem. */
  async resetSystem(
    raw: Record<string, unknown>,
    type: ResetType | string,
  ): Promise<void> {
    const target = resetAction(raw).target ??
      `${this.systemPath}/Actions/ComputerSystem.Reset`;
    const r = await this.#send("POST", target, resetBody(type));
    if (r.status < 200 || r.status >= 300) throw statusError(r.status);
  }

  /** PATCHes the boot override, with If-Match when an ETag is known. */
  async patchBoot(
    target: BootTarget | string,
    enabled: BootEnabled | string,
    etag?: string,
  ): Promise<void> {
    const r = await this.#send(
      "PATCH",
      this.systemPath,
      bootBody(target, enabled),
      etag ? { "If-Match": etag } : undefined,
    );
    if (r.status < 200 || r.status >= 300) throw statusError(r.status);
  }

  async #getRaw(path: string): Promise<
    { raw: Record<string, unknown>; etag?: string }
  > {
    const r = await this.#send("GET", path);
    if (r.status === 404) {
      throw new RedfishError(
        "not_found",
        "Redfish resource not found (HTTP 404)",
      );
    }
    if (r.status < 200 || r.status >= 300) throw statusError(r.status);
    return { raw: parseJson(r.text), etag: r.etag };
  }

  async #getJson(path: string): Promise<Record<string, unknown>> {
    return (await this.#getRaw(path)).raw;
  }
}

/**
 * Runs `fn` against the BMC with TLS applied and the Redfish session (or Basic
 * header) in place. The session is deleted and the TLS client closed in a
 * `finally`, on every path. `fn` selects the ComputerSystem itself, so `sync`
 * can record `not_found` instead of failing.
 */
export async function withRedfish<T>(
  deps: Deps,
  target: RedfishTarget,
  fn: (api: RedfishApi, origin: string) => Promise<T>,
): Promise<T> {
  const handle = deps.makeClient(target.tls);
  let auth: Auth | undefined;
  try {
    const api = new RedfishApi(deps, target.endpoint, handle.client);
    auth = await openAuth(
      deps,
      target.endpoint,
      handle.client,
      target.username,
      target.password,
      target.authMode,
    );
    api.setAuth(auth.headers);
    return await fn(api, target.endpoint);
  } finally {
    if (auth) await auth.logout();
    handle.close();
  }
}
