/**
 * Syncthing REST transport for swamp extensions.
 *
 * The API key travels only in the `X-API-Key` header: for a local call it is an
 * in-memory request header, and for a remote call it is written into a `curl
 * --config -` file delivered over stdin, so it never reaches a URL, a process
 * argument, a log or stored state. Plain HTTP is allowed only on a loopback
 * address; anything else must use HTTPS.
 *
 * @module
 */

import {
  type CommandRunner,
  denoDeps,
  exec as sshExec,
  SshConfigError,
  SshError,
  type SshTarget,
  upload as sshUpload,
} from "./ssh.ts";

/** Signature of the fetch implementation the local transport uses. */
export type FetchFn = (
  input: string,
  init?: RequestInit,
) => Promise<Response>;

/** Injectable dependencies of the Syncthing client. */
export interface SyncthingDeps {
  /** Performs local HTTPS/HTTP requests. */
  fetch: FetchFn;
  /** Runs the SSH client for the remote transport. */
  run: CommandRunner;
  /** Current time in milliseconds. */
  now: () => number;
  /** Sleeps for the given milliseconds. */
  sleep: (ms: number) => Promise<void>;
}

/** How the API is reached. */
export type SyncthingAccess = "local" | "ssh";

/** The API endpoint and its key. */
export interface SyncthingApi {
  /** Base URL, e.g. `http://127.0.0.1:8384`. */
  apiUrl: string;
  /** API key, sensitive. */
  apiKey: string;
  /** Per-request timeout in milliseconds; defaults to 30 s. */
  timeoutMs?: number;
}

/** One REST result. */
export interface SyncthingResult {
  /** HTTP status. */
  status: number;
  /** Parsed JSON, or the raw text when it is not JSON. */
  body: unknown;
}

/** An unexpected Syncthing API response. `status` 0 means no HTTP response. */
export class SyncthingError extends Error {
  /** HTTP status, or 0. */
  readonly status: number;

  /** Creates a Syncthing error. */
  constructor(message: string, status = 0) {
    super(
      status === 401 || status === 403
        ? `${message} (the API key was rejected)`
        : message,
    );
    this.name = "SyncthingError";
    this.status = status;
  }
}

/** The REST client. */
export interface SyncthingClient {
  /** Sends one request; never throws on a non-2xx. */
  request(
    method: string,
    path: string,
    body?: unknown,
  ): Promise<SyncthingResult>;
}

const LOOPBACK = /^(?:localhost|127(?:\.\d{1,3}){3}|\[::1\]|::1)$/i;
const API_KEY_RE = /^[A-Za-z0-9_-]{8,128}$/;
const DEVICE_ID_RE = /^[A-Z2-7]{7}(?:-[A-Z2-7]{7}){7}$/;
const FOLDER_ID_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,254}$/;

/** Throws unless `value` is a Syncthing device id. */
export function assertDeviceId(value: string): void {
  if (typeof value !== "string" || !DEVICE_ID_RE.test(value)) {
    throw new SshConfigError(
      "device_id must be a 56-character Syncthing device id in 8 hyphenated groups",
    );
  }
}

/** Throws unless `value` is a Syncthing folder id. */
export function assertFolderId(value: string): void {
  if (typeof value !== "string" || !FOLDER_ID_RE.test(value)) {
    throw new SshConfigError(
      "folder_id must be 1-255 letters, digits, dot, underscore or hyphen",
    );
  }
}

/** Throws unless `value` is an absolute path with no traversal. */
export function assertRemoteFolderPath(value: string): void {
  if (
    typeof value !== "string" || !/^\/[A-Za-z0-9._\/ -]{1,4095}$/.test(value) ||
    value.split("/").some((part) => part === ".." || part === ".")
  ) {
    throw new SshConfigError(
      "path must be an absolute path with no . or .. segment",
    );
  }
}

/** Throws unless `value` is a safe API key. */
export function assertApiKey(value: string): void {
  if (typeof value !== "string" || !API_KEY_RE.test(value)) {
    throw new SshConfigError(
      "api_key must be 8-128 letters, digits, underscore or hyphen",
    );
  }
}

/**
 * A device address: exactly `dynamic`, or a tcp/quic/relay URL with a plain
 * hostname, IPv4 or bracketed IPv6 host and a port 1-65535, with no userinfo or
 * query.
 */
export function isDeviceAddress(value: string): boolean {
  if (value === "dynamic") return true;
  const match = /^(?:tcp|quic|relay):\/\/([^/?#@]+):(\d{1,5})$/.exec(value);
  if (match === null) return false;
  const host = match[1];
  const port = Number(match[2]);
  if (!Number.isInteger(port) || port < 1 || port > 65535) return false;
  if (/^\[[0-9a-fA-F:.]+\]$/.test(host)) return true;
  return /^[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?$/.test(host);
}

/**
 * True when `value` is a non-blank label of printable ASCII. An allowlist, so
 * control characters, unicode and every other byte are refused.
 */
export function isSafeLabel(value: string): boolean {
  return typeof value === "string" && /^[\x20-\x7e]{1,256}$/.test(value) &&
    value.trim() !== "";
}

/**
 * Throws unless the API URL is safe: no userinfo, no query or fragment, and
 * plain HTTP only on loopback (anything else must be HTTPS).
 */
export function assertApiUrl(value: string): void {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new SshConfigError(`api_url is not a valid URL: ${value}`);
  }
  if (url.username !== "" || url.password !== "") {
    throw new SshConfigError("api_url must not carry userinfo");
  }
  if (url.search !== "" || url.hash !== "") {
    throw new SshConfigError("api_url must not carry a query or fragment");
  }
  if (url.pathname !== "/" && url.pathname !== "") {
    throw new SshConfigError("api_url must be an origin with no path");
  }
  if (url.protocol === "http:" && !LOOPBACK.test(url.hostname)) {
    throw new SshConfigError(
      "api_url must use HTTPS unless it is a loopback address",
    );
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") {
    throw new SshConfigError("api_url must use http or https");
  }
}

/** The canonical origin of an API URL: lowercased host, no trailing slash. */
export function normalizeApiUrl(value: string): string {
  return new URL(value).origin;
}

/** The last non-empty line of `text`, trimmed and capped. */
function lastLine(text: string, cap = 200): string {
  const lines = text.split(/\r?\n/).filter((line) => line.trim() !== "");
  return (lines.at(-1) ?? "").trim().slice(0, cap);
}

/** Parses JSON, or returns the raw text when it is not JSON. */
function parseBody(text: string): unknown {
  if (text === "") return null;
  try {
    return JSON.parse(text);
  } catch {
    return text;
  }
}

/** Quotes one value for a curl config file, refusing control characters. */
export function curlConfigValue(value: string): string {
  if (/[\r\n\0]/.test(value)) {
    throw new SshConfigError("a curl config value must not contain a newline");
  }
  return `"${value.replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"`;
}

/** Builds the `curl --config -` body for one request. */
export function curlRequestConfig(
  method: string,
  url: string,
  apiKey: string,
  body?: unknown,
  timeoutMs = 30_000,
): string {
  const seconds = Math.max(1, Math.ceil(timeoutMs / 1000));
  const connect = Math.max(1, Math.min(10, seconds));
  const lines = [
    "silent",
    "show-error",
    `request = ${curlConfigValue(method)}`,
    `url = ${curlConfigValue(url)}`,
    `header = ${curlConfigValue(`X-API-Key: ${apiKey}`)}`,
    `header = ${curlConfigValue("Accept: application/json")}`,
    `proto = ${curlConfigValue("=http,https")}`,
    `max-time = ${curlConfigValue(String(seconds))}`,
    `connect-timeout = ${curlConfigValue(String(connect))}`,
    `write-out = ${curlConfigValue("__SYNCTHING_STATUS__%{http_code}")}`,
  ];
  if (body !== undefined) {
    lines.push(
      `header = ${curlConfigValue("Content-Type: application/json")}`,
      `data-binary = ${curlConfigValue(JSON.stringify(body))}`,
    );
  }
  return `${lines.join("\n")}\n`;
}

const STATUS_MARKER = /__SYNCTHING_STATUS__(\d{3})\s*$/;

/** Splits curl output into its body and HTTP status. */
export function parseCurlOutput(stdout: string): SyncthingResult {
  const match = STATUS_MARKER.exec(stdout);
  if (match === null) {
    throw new SshError("curl output carried no HTTP status");
  }
  const body = stdout.slice(0, match.index).replace(/\n$/, "");
  return { status: Number(match[1]), body: parseBody(body) };
}

/**
 * Builds a client for one endpoint. A remote (`ssh`) call runs `curl --config
 * -` on the host, so the key travels in the config over stdin.
 */
export function createClient(
  deps: SyncthingDeps,
  access: SyncthingAccess,
  api: SyncthingApi,
  sshTarget?: SshTarget,
): SyncthingClient {
  assertApiUrl(api.apiUrl);
  assertApiKey(api.apiKey);
  const base = normalizeApiUrl(api.apiUrl);
  const timeoutMs = api.timeoutMs ?? 30_000;
  const request = async (
    method: string,
    path: string,
    body?: unknown,
  ): Promise<SyncthingResult> => {
    if (path !== "" && !path.startsWith("/")) {
      throw new SshConfigError(`request path must start with /: ${path}`);
    }
    if (access === "local") {
      const headers: Record<string, string> = {
        "X-API-Key": api.apiKey,
        accept: "application/json",
      };
      if (body !== undefined) headers["content-type"] = "application/json";
      const res = await deps.fetch(`${base}${path}`, {
        method,
        headers,
        body: body === undefined ? undefined : JSON.stringify(body),
        redirect: "manual",
        signal: AbortSignal.timeout(timeoutMs),
      });
      if (res.status >= 300 && res.status <= 399) {
        throw new SyncthingError(
          `refusing a redirect (${res.status}); the API key would be re-sent`,
          res.status,
        );
      }
      const text = await res.text();
      return { status: res.status, body: parseBody(text) };
    }
    if (sshTarget === undefined) {
      throw new SshConfigError("the ssh transport needs an SSH target");
    }
    const url = `${base}${path}`;
    const config = curlRequestConfig(method, url, api.apiKey, body, timeoutMs);
    // One shell resolves a 0700 per-user cache directory and sweeps configs left
    // by an earlier interrupted call; the config is uploaded there over stdin
    // under a random name; curl and its trap-based cleanup then run in one
    // remote shell, so a dropped session cannot strand the key file for long.
    const prepared = await sshExec(deps, sshTarget, [
      "sh",
      "-c",
      "umask 077\n" +
      'd="$HOME/.cache/syncthing-peer"\n' +
      'mkdir -p "$d" && [ -d "$d" ] && [ ! -L "$d" ] && [ -O "$d" ] && ' +
      'chmod 700 "$d" || exit 1\n' +
      'm=$(stat -c %a "$d" 2>/dev/null || stat -f %Lp "$d" 2>/dev/null)\n' +
      '[ "$m" = "700" ] || exit 1\n' +
      'find "$d" -maxdepth 1 -name "*.curlrc" -type f -mmin +5 -delete ' +
      '2>/dev/null && printf %s "$d"',
    ]);
    if (prepared.exit_code !== 0) {
      throw new SshError(
        `could not prepare the remote config directory (exit ${prepared.exit_code}): ${
          lastLine(prepared.stderr)
        }`,
      );
    }
    const dir = prepared.stdout.trim();
    if (!dir.endsWith("/.cache/syncthing-peer")) {
      throw new SshError("could not resolve the remote config directory");
    }
    const tempPath = `${dir}/${crypto.randomUUID()}.curlrc`;
    try {
      await sshUpload(deps, sshTarget, {
        path: tempPath,
        content: config,
        mode: "0600",
      });
      const result = await sshExec(deps, sshTarget, [
        "sh",
        "-c",
        'trap \'rm -f "$1"\' EXIT HUP INT TERM; curl -q --config "$1"',
        "sh",
        tempPath,
      ]);
      if (result.exit_code !== 0) {
        throw new SshError(
          `remote curl failed (exit ${result.exit_code}): ${
            lastLine(result.stderr)
          }`,
        );
      }
      const parsed = parseCurlOutput(result.stdout);
      if (parsed.status >= 300 && parsed.status <= 399) {
        throw new SyncthingError(
          `refusing a redirect (${parsed.status}); the API key would be re-sent`,
          parsed.status,
        );
      }
      return parsed;
    } catch (error) {
      await sshExec(deps, sshTarget, ["rm", "-f", tempPath]).catch(
        () => undefined,
      );
      throw error;
    }
  };
  return { request };
}

/** Production dependencies: real fetch, SSH runner, clock and sleep. */
export const denoSyncthingDeps: SyncthingDeps = {
  fetch: (input, init) => fetch(input, init),
  run: denoDeps.run,
  now: denoDeps.now,
  sleep: denoDeps.sleep,
};

const FOLDER_TYPES = new Set(["sendreceive", "sendonly", "receiveonly"]);

/** A desired device config, already validated. */
export interface DeviceSpec {
  /** Device id. */
  deviceId: string;
  /** Display name. */
  name: string;
  /** Listen addresses. */
  addresses: string[];
  /** Introducer flag. */
  introducer: boolean;
  /** Paused flag. */
  paused: boolean;
}

/** A desired folder config, already validated. */
export interface FolderSpec {
  /** Folder id. */
  folderId: string;
  /** Display label. */
  label: string;
  /** Absolute local path. */
  path: string;
  /** Folder type. */
  type: string;
  /** Device ids the folder is shared with. */
  devices: string[];
  /** Paused flag. */
  paused: boolean;
}

/** Validates and builds the ARM-style device body. */
export function buildDeviceSpec(input: {
  deviceId: string;
  name: string;
  addresses?: string[] | null;
  introducer?: boolean | null;
  paused?: boolean | null;
}): DeviceSpec {
  assertDeviceId(input.deviceId);
  if (!isSafeLabel(input.name)) {
    throw new SshConfigError(
      "device name must be non-blank with no control characters",
    );
  }
  const addresses = input.addresses ?? ["dynamic"];
  for (const address of addresses) {
    if (!isDeviceAddress(address)) {
      throw new SshConfigError(
        `device address must be exactly 'dynamic' or a tcp/quic/relay host:port URL: ${address}`,
      );
    }
  }
  return {
    deviceId: input.deviceId,
    name: input.name,
    addresses,
    introducer: input.introducer ?? false,
    paused: input.paused ?? false,
  };
}

/** Validates and builds the folder body. */
export function buildFolderSpec(input: {
  folderId: string;
  label: string;
  path: string;
  type?: string | null;
  devices?: string[] | null;
  paused?: boolean | null;
}): FolderSpec {
  assertFolderId(input.folderId);
  assertRemoteFolderPath(input.path);
  if (!isSafeLabel(input.label)) {
    throw new SshConfigError(
      "folder label must be non-blank with no control characters",
    );
  }
  const type = input.type ?? "sendreceive";
  if (!FOLDER_TYPES.has(type)) {
    throw new SshConfigError(
      `folder type must be one of ${[...FOLDER_TYPES].join(", ")}`,
    );
  }
  const devices = input.devices ?? [];
  for (const device of devices) assertDeviceId(device);
  return {
    folderId: input.folderId,
    label: input.label,
    path: input.path,
    type,
    devices,
    paused: input.paused ?? false,
  };
}

/** The device body Syncthing expects. */
export function deviceBody(spec: DeviceSpec): Record<string, unknown> {
  return {
    deviceID: spec.deviceId,
    name: spec.name,
    addresses: spec.addresses,
    introducer: spec.introducer,
    paused: spec.paused,
  };
}

/** The folder body Syncthing expects. */
export function folderBody(spec: FolderSpec): Record<string, unknown> {
  return {
    id: spec.folderId,
    label: spec.label,
    path: spec.path,
    type: spec.type,
    paused: spec.paused,
    devices: spec.devices.map((deviceID) => ({ deviceID })),
  };
}

/** Normalizes a folder's `devices` field to a device-id list. */
export function folderDevices(folder: unknown): string[] {
  if (!folder || typeof folder !== "object") return [];
  const devices = (folder as Record<string, unknown>).devices;
  if (!Array.isArray(devices)) return [];
  return devices.flatMap((entry) => {
    if (typeof entry === "string") return [entry];
    if (entry && typeof entry === "object") {
      const id = (entry as Record<string, unknown>).deviceID;
      return typeof id === "string" ? [id] : [];
    }
    return [];
  });
}

/** Compares a live device config with the desired one. */
export function deviceMatches(existing: unknown, spec: DeviceSpec): boolean {
  if (!existing || typeof existing !== "object") return false;
  const current = existing as Record<string, unknown>;
  if (current.name !== spec.name) return false;
  if (current.introducer !== spec.introducer) return false;
  if (current.paused !== spec.paused) return false;
  const addresses = Array.isArray(current.addresses)
    ? current.addresses.map(String)
    : [];
  return JSON.stringify([...addresses].sort()) ===
    JSON.stringify([...spec.addresses].sort());
}

/**
 * Compares a live folder config with the desired one. Syncthing always adds
 * the node's own device id to a folder's devices, so `ownDeviceId` is removed
 * from both sides before comparing.
 */
export function folderMatches(
  existing: unknown,
  spec: FolderSpec,
  ownDeviceId?: string,
): boolean {
  if (!existing || typeof existing !== "object") return false;
  const current = existing as Record<string, unknown>;
  if (current.label !== spec.label) return false;
  if (current.path !== spec.path) return false;
  if (current.type !== spec.type) return false;
  if (current.paused !== spec.paused) return false;
  const devices = folderDevices(existing).filter((id) => id !== ownDeviceId);
  const declared = spec.devices.filter((id) => id !== ownDeviceId);
  return JSON.stringify([...devices].sort()) ===
    JSON.stringify([...declared].sort());
}

/**
 * Derives a folder spec from a live read-back, so stored state reflects what
 * Syncthing normalized rather than what was requested. The node's own device id
 * is dropped from the recorded device list.
 */
export function folderSpecOf(
  body: unknown,
  fallback: FolderSpec,
  ownDeviceId?: string,
): FolderSpec {
  if (!body || typeof body !== "object") return fallback;
  const record = body as Record<string, unknown>;
  return {
    folderId: typeof record.id === "string" ? record.id : fallback.folderId,
    label: typeof record.label === "string" ? record.label : fallback.label,
    path: typeof record.path === "string" ? record.path : fallback.path,
    type: typeof record.type === "string" ? record.type : fallback.type,
    devices: folderDevices(body).filter((id) => id !== ownDeviceId),
    paused: record.paused === true,
  };
}
