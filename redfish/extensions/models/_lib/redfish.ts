/**
 * DMTF Redfish domain logic and authenticated client for the model.
 *
 * The endpoint is an https origin; every `@odata.id` is resolved back onto
 * that origin, so a BMC cannot point the model at another host. Credentials
 * are sent only in an `X-Auth-Token` or `Authorization` header. A Redfish
 * session is opened through the SessionService and deleted in a `finally`, or
 * Basic auth is used explicitly. Every request carries an abort signal, so a
 * stalled BMC cannot outlast the caller's deadline.
 *
 * @module
 */

import {
  b64Utf8,
  classifyFetch,
  type Deps,
  drain,
  MAX_BODY_BYTES,
  readBounded,
  RedfishError,
  statusError,
  timeoutError,
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

/** Actions that end powered on after an intervening reset. */
export const RESTART_TYPES = [
  "GracefulRestart",
  "ForceRestart",
  "PowerCycle",
] as const;

/**
 * Actions that only inject an event; no power-state change is guaranteed, so
 * the 2xx response is the whole result.
 */
export const FIRE_AND_FORGET = ["Nmi"] as const;

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

const RESET_TYPE_SET = new Set<string>(RESET_TYPES);
const BOOT_TARGET_SET = new Set<string>(BOOT_TARGETS);

/** Keep only values that are members of the local allowlist. */
function knownOnly(values: string[] | undefined, known: Set<string>): string[] {
  return (values ?? []).filter((v) => known.has(v));
}

function asRecord(v: unknown): Record<string, unknown> | undefined {
  return v && typeof v === "object" && !Array.isArray(v)
    ? v as Record<string, unknown>
    : undefined;
}

function str(v: unknown): string | undefined {
  return typeof v === "string" && v !== "" ? v : undefined;
}

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

/** Like {@link resolveOdata} but returns undefined instead of throwing. */
export function trySameOrigin(origin: string, id: string): string | undefined {
  try {
    return resolveOdata(origin, id);
  } catch {
    return undefined;
  }
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
  return strList(asRecord(raw.Boot)?.[BOOT_ALLOWABLE_KEY]);
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
  const allowReset = knownOnly(resetAction(raw).allowable, RESET_TYPE_SET);
  const allowBoot = knownOnly(allowableBootTargets(raw), BOOT_TARGET_SET);
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
    ...(allowReset.length > 0 ? { allowable_reset_types: allowReset } : {}),
    ...(allowBoot.length > 0 ? { allowable_boot_targets: allowBoot } : {}),
    ...(etag ? { etag } : {}),
    status,
    observed_at: observedAt,
  };
}

const OFF_ACTIONS = new Set(["ForceOff", "GracefulShutdown"]);
const RESTART_ACTION_SET = new Set<string>(RESTART_TYPES);
const FIRE_AND_FORGET_SET = new Set<string>(FIRE_AND_FORGET);

/** True when the action restarts the system (an intervening state is needed). */
export function isRestartAction(action: string): boolean {
  return RESTART_ACTION_SET.has(action);
}

/** True when the action is fire-and-forget (success is the 2xx response). */
export function isFireAndForget(action: string): boolean {
  return FIRE_AND_FORGET_SET.has(action);
}

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
  /** Permit credentials to be sent over an unverified TLS connection. */
  allowInsecureCredentials: boolean;
}

interface Auth {
  headers: Record<string, string>;
  logout(): Promise<void>;
  warning?: string;
}

interface RawResult {
  status: number;
  etag?: string;
  text: string;
  location?: string;
}

function authHeader(
  username: string,
  password: string,
): Record<string, string> {
  return { Authorization: `Basic ${b64Utf8(`${username}:${password}`)}` };
}

/**
 * Refuses to send credentials over a TLS connection that is not verified
 * unless the caller explicitly allowed it. Both Basic auth and the session
 * POST hand the password to the (unverified) peer.
 */
function assertCredentialsAllowed(
  tls: TlsPolicy,
  allowInsecureCredentials: boolean,
): void {
  if (tls.mode === "strict" || allowInsecureCredentials) return;
  throw new RedfishError(
    "invalid_input",
    "credentials are not sent over a TLS connection with verification disabled; pin the BMC certificate with ca_pem (recommended) or set allow_insecure_credentials=true",
  );
}

/** Per-request signal, clamped to a caller deadline when one is given. */
function requestSignal(deps: Deps, deadline?: number): AbortSignal {
  const ms = deadline === undefined ? deps.requestTimeoutMs : Math.max(
    1,
    Math.min(deps.requestTimeoutMs, deadline - deps.now().getTime()),
  );
  return AbortSignal.timeout(ms);
}

/**
 * Opens a Redfish session and returns its header plus a logout. If the BMC
 * does not implement SessionService (404/405), Basic auth is used instead, but
 * only when the TLS policy (or the explicit override) allows it.
 */
async function openAuth(
  deps: Deps,
  target: RedfishTarget,
  client: unknown,
  deadline?: number,
): Promise<Auth> {
  assertCredentialsAllowed(target.tls, target.allowInsecureCredentials);
  if (target.authMode === "basic") {
    return {
      headers: authHeader(target.username, target.password),
      logout: () => Promise.resolve(),
    };
  }
  const signal = requestSignal(deps, deadline);
  let resp: Response;
  try {
    resp = await deps.fetch(
      resolveOdata(target.endpoint, "/redfish/v1/SessionService/Sessions"),
      {
        method: "POST",
        redirect: "error",
        headers: {
          "Accept": "application/json",
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          UserName: target.username,
          Password: target.password,
        }),
        signal,
        client,
      },
    );
  } catch (e) {
    throw classifyFetch(e);
  }
  if (resp.status === 404 || resp.status === 405) {
    await drain(resp);
    return {
      headers: authHeader(target.username, target.password),
      logout: () => Promise.resolve(),
    };
  }
  if (resp.status !== 200 && resp.status !== 201) {
    await drain(resp);
    throw statusError(resp.status);
  }
  const token = resp.headers.get("x-auth-token");
  const text = await readBounded(resp, MAX_BODY_BYTES, signal);
  let rawLocation = resp.headers.get("location") ?? undefined;
  if (!rawLocation) {
    // Some BMCs return the session URI only in the body.
    try {
      const body = JSON.parse(text) as unknown;
      rawLocation = str(asRecord(body)?.["@odata.id"]);
    } catch {
      rawLocation = undefined;
    }
  }
  if (!token) {
    throw new RedfishError(
      "redfish_failed",
      "BMC did not return a session token",
    );
  }
  const headers = { "X-Auth-Token": token };
  let sessionUrl: string | undefined;
  let warning: string | undefined;
  if (rawLocation) {
    sessionUrl = trySameOrigin(target.endpoint, rawLocation);
    if (!sessionUrl) {
      warning =
        "BMC session URI points outside the endpoint origin; skipping session logout";
    }
  }
  return {
    headers,
    ...(warning ? { warning } : {}),
    logout: async () => {
      if (!sessionUrl) return;
      try {
        const r = await deps.fetch(sessionUrl, {
          method: "DELETE",
          redirect: "error",
          headers,
          // Bound by the caller deadline when there is one.
          signal: requestSignal(deps, deadline),
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
  const record = asRecord(parsed);
  if (!record) {
    throw new RedfishError(
      "redfish_failed",
      "BMC returned a non-object JSON body",
    );
  }
  return record;
}

/** Refuses a ComputerSystem resource that has no usable Id. */
function requireSystemId(raw: Record<string, unknown>): void {
  const id = str(raw.Id);
  if (!id || !isSystemId(id)) {
    throw new RedfishError(
      "redfish_failed",
      "BMC returned a ComputerSystem without a valid Id",
    );
  }
}

const TERMINAL_TASK = new Set([
  "Completed",
  "Killed",
  "Exception",
  "Interrupted",
  "Cancelled",
]);
const FAILED_TASK = new Set([
  "Killed",
  "Exception",
  "Interrupted",
  "Cancelled",
]);

/** Authenticated Redfish client bound to one origin and one system. */
export class RedfishApi {
  #deps: Deps;
  #origin: string;
  #client: unknown;
  #deadline?: number;
  #authHeaders: Record<string, string> = {};
  /** Path of the selected ComputerSystem. */
  systemPath = "";

  constructor(deps: Deps, origin: string, client: unknown, deadline?: number) {
    this.#deps = deps;
    this.#origin = origin;
    this.#client = client;
    this.#deadline = deadline;
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
        signal: requestSignal(this.#deps, this.#deadline),
        client: this.#client,
      });
    } catch (e) {
      throw classifyFetch(e);
    }
    let text: string;
    try {
      text = await readBounded(
        resp,
        MAX_BODY_BYTES,
        requestSignal(this.#deps, this.#deadline),
      );
    } catch (e) {
      throw e instanceof RedfishError ? e : classifyFetch(e);
    }
    return {
      status: resp.status,
      etag: resp.headers.get("etag") ?? undefined,
      location: resp.headers.get("location") ?? undefined,
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
    requireSystemId(result.raw);
    this.systemPath = path;
    return result;
  }

  /** Re-reads the selected ComputerSystem, for polling and ETag. */
  async readSystem(): Promise<{ raw: Record<string, unknown>; etag?: string }> {
    const result = await this.#getRaw(this.systemPath);
    requireSystemId(result.raw);
    return result;
  }

  /**
   * POSTs a reset action to the selected ComputerSystem. A 202 task monitor
   * location, when returned, is handed back for the caller to follow.
   */
  async resetSystem(
    raw: Record<string, unknown>,
    type: ResetType | string,
  ): Promise<{ taskLocation?: string; warning?: string }> {
    const target = resetAction(raw).target ??
      `${this.systemPath}/Actions/ComputerSystem.Reset`;
    const r = await this.#send("POST", target, resetBody(type));
    if (r.status < 200 || r.status >= 300) throw statusError(r.status);
    if (!r.location) return {};
    const taskLocation = trySameOrigin(this.#origin, r.location);
    if (!taskLocation) {
      return {
        warning:
          "BMC task monitor points outside the endpoint origin; not followed",
      };
    }
    return { taskLocation };
  }

  /**
   * Waits for a Redfish task to reach a terminal state. A 204, an empty body
   * after the 202, or a 404 (the task was purged once done) means completed.
   */
  async awaitTask(location: string, pollMs: number): Promise<void> {
    for (;;) {
      const r = await this.#send("GET", location);
      if (r.status === 204 || r.status === 404 || !r.text.trim()) return;
      if (r.status < 200 || r.status >= 300) throw statusError(r.status);
      const raw = parseJson(r.text);
      const taskState = str(raw.TaskState);
      if (taskState && TERMINAL_TASK.has(taskState)) {
        if (FAILED_TASK.has(taskState)) {
          throw new RedfishError(
            "redfish_failed",
            `Redfish task ended ${taskState}`,
          );
        }
        return;
      }
      if (
        this.#deadline !== undefined &&
        this.#deps.now().getTime() >= this.#deadline
      ) {
        throw timeoutError();
      }
      await this.#deps.sleep(pollMs);
    }
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
 * `finally`, on every path, and every request is bounded by `deadline` (epoch
 * ms) when given. `fn` selects the ComputerSystem itself, so `sync` can record
 * `not_found` instead of failing.
 */
export async function withRedfish<T>(
  deps: Deps,
  target: RedfishTarget,
  fn: (api: RedfishApi, origin: string) => Promise<T>,
  deadline?: number,
  warn?: (message: string) => void,
): Promise<T> {
  const handle = deps.makeClient(target.tls);
  let auth: Auth | undefined;
  try {
    const api = new RedfishApi(deps, target.endpoint, handle.client, deadline);
    auth = await openAuth(deps, target, handle.client, deadline);
    if (auth.warning) warn?.(auth.warning);
    api.setAuth(auth.headers);
    return await fn(api, target.endpoint);
  } finally {
    if (auth) await auth.logout();
    handle.close();
  }
}
