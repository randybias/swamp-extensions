/**
 * Minimal Cherry Servers REST API client shared by the cherry-servers models.
 *
 * Authenticates with a bearer token sent only in the `Authorization` header,
 * retries rate-limited (429) requests with backoff, and turns 404 into `null`
 * for the `try*` helpers so callers can treat "gone" as data, not failure.
 *
 * @module
 */

/** Base URL of the Cherry Servers v1 API. */
export const API_BASE = "https://api.cherryservers.com/v1";

/** Environment variable consulted when no explicit token is supplied. */
export const TOKEN_ENV = "CHERRY_AUTH_TOKEN";

/** Signature of the fetch implementation the client uses. */
export type FetchFn = (
  input: string,
  init?: RequestInit,
) => Promise<Response>;

let fetchImpl: FetchFn = (input, init) => fetch(input, init);
let sleepImpl: (ms: number) => Promise<void> = (ms) =>
  new Promise((resolve) => setTimeout(resolve, ms));

/** Replaces the fetch implementation (tests only). Returns the previous one. */
export function setFetch(fn: FetchFn): FetchFn {
  const previous = fetchImpl;
  fetchImpl = fn;
  return previous;
}

/** Replaces the sleep implementation (tests only). Returns the previous one. */
export function setSleep(
  fn: (ms: number) => Promise<void>,
): (ms: number) => Promise<void> {
  const previous = sleepImpl;
  sleepImpl = fn;
  return previous;
}

/** Sleeps using the current (possibly test-injected) implementation. */
export function sleep(ms: number): Promise<void> {
  return sleepImpl(ms);
}

/** Error raised for any non-2xx API response other than a handled 404. */
export class CherryApiError extends Error {
  /** HTTP status code returned by the API. */
  readonly status: number;

  /** Creates an error for `method path` that returned `status`. */
  constructor(method: string, path: string, status: number, detail: string) {
    super(
      `Cherry Servers API error: ${method} ${path} returned ${status}: ${detail}`,
    );
    this.name = "CherryApiError";
    this.status = status;
  }
}

/** Resolves the API token: explicit argument first, then the environment. */
export function resolveToken(explicit?: string): string {
  const token = explicit ?? Deno.env.get(TOKEN_ENV);
  if (!token) {
    throw new Error(
      `No Cherry Servers API token. Set the model's 'token' global argument ` +
        `(wire it with a vault.get(...) expression) or the ${TOKEN_ENV} ` +
        `environment variable.`,
    );
  }
  return token;
}

/** Options for a single API request. */
export interface RequestOptions {
  /** API token; falls back to the environment when omitted. */
  token?: string;
  /** JSON request body. */
  body?: unknown;
  /** Query string parameters. */
  query?: Record<string, string>;
  /** Send the request without an Authorization header (public endpoints). */
  anonymous?: boolean;
}

const MAX_ATTEMPTS = 5;

/** Per-request timeout, so one hung connection cannot stall a method. */
export const REQUEST_TIMEOUT_MS = 30_000;

const SENSITIVE_WORDS =
  /password|passwd|passphrase|secret|token|bearer|authori[sz]ation|credential|user[_ -]?data|private|api[_ -]?key|ssh[_ -]?key|cloud-config/i;

/**
 * Returns a provider error message only when it is short plain prose that
 * cannot carry a value: letters, spaces and `.,()'-` only, no digits, quotes,
 * colons or `=`, and no sensitive words. Anything else is withheld whole,
 * because partial redaction of arbitrary text cannot be made complete.
 */
export function safeMessage(message: string): string | undefined {
  const m = message.replace(/\s+/g, " ").trim();
  if (m === "" || m.length > 120) return undefined;
  if (!/^[A-Za-z .,()'-]+$/.test(m)) return undefined;
  if (SENSITIVE_WORDS.test(m)) return undefined;
  return m;
}

/**
 * Describes an error response without echoing its body, which can repeat
 * request data such as user data or credentials. Only a JSON `code` of safe
 * characters and a `message` that passes {@link safeMessage} are kept.
 */
export function summarize(text: string): string {
  try {
    const parsed = JSON.parse(text) as Record<string, unknown>;
    const parts: string[] = [];
    const code = String(parsed.code ?? "");
    if (
      (typeof parsed.code === "string" || typeof parsed.code === "number") &&
      /^[A-Za-z0-9_.-]{1,40}$/.test(code)
    ) {
      parts.push(`code ${code}`);
    }
    if (typeof parsed.message === "string") {
      parts.push(safeMessage(parsed.message) ?? "message withheld");
    }
    return parts.length > 0 ? parts.join(": ") : "no error detail";
  } catch {
    return "non-JSON error body";
  }
}

/**
 * Sends one API request. Returns the parsed JSON body, or `null` for a 404.
 * Throws {@link CherryApiError} on any other non-2xx status.
 */
export async function request(
  method: string,
  path: string,
  options: RequestOptions = {},
): Promise<unknown | null> {
  const url = new URL(`${API_BASE}${path}`);
  for (const [key, value] of Object.entries(options.query ?? {})) {
    url.searchParams.set(key, value);
  }
  const headers: Record<string, string> = { "Accept": "application/json" };
  if (!options.anonymous) {
    headers["Authorization"] = `Bearer ${resolveToken(options.token)}`;
  }
  if (options.body !== undefined) {
    headers["Content-Type"] = "application/json";
  }

  for (let attempt = 1;; attempt++) {
    let resp: Response;
    try {
      resp = await fetchImpl(url.toString(), {
        method,
        headers,
        body: options.body === undefined
          ? undefined
          : JSON.stringify(options.body),
        signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
      });
    } catch (e) {
      if ((e as Error).name !== "TimeoutError") throw e;
      // A timed-out write may still have been applied by the API.
      throw new CherryApiError(
        method,
        path,
        0,
        method === "GET"
          ? `no response within ${REQUEST_TIMEOUT_MS / 1000}s`
          : `no response within ${
            REQUEST_TIMEOUT_MS / 1000
          }s; the request may still have been applied`,
      );
    }
    if (resp.status === 429 && attempt < MAX_ATTEMPTS) {
      await resp.body?.cancel();
      const retryAfter = Number(resp.headers.get("retry-after"));
      const waitMs = Number.isFinite(retryAfter) && retryAfter > 0
        ? retryAfter * 1000
        : 500 * 2 ** (attempt - 1);
      await sleepImpl(waitMs);
      continue;
    }
    if (resp.status === 404) {
      await resp.body?.cancel();
      return null;
    }
    let text: string;
    try {
      text = await resp.text();
    } catch (e) {
      if ((e as Error).name !== "TimeoutError") throw e;
      throw new CherryApiError(
        method,
        path,
        resp.status,
        `response body not received within ${REQUEST_TIMEOUT_MS / 1000}s`,
      );
    }
    if (!resp.ok) {
      throw new CherryApiError(method, path, resp.status, summarize(text));
    }
    if (text.length === 0) return {};
    try {
      return JSON.parse(text);
    } catch {
      throw new CherryApiError(method, path, resp.status, "invalid JSON body");
    }
  }
}

/** Sends a request and throws if the target does not exist. */
export async function requestExisting(
  method: string,
  path: string,
  options: RequestOptions = {},
): Promise<unknown> {
  const result = await request(method, path, options);
  if (result === null) {
    throw new CherryApiError(method, path, 404, "not found");
  }
  return result;
}

/**
 * Fetches every item from a collection endpoint that pages with
 * `limit`/`offset`, stopping at the first short page. Guarded against
 * runaway paging by a page cap.
 */
export async function listAll(
  path: string,
  options: RequestOptions = {},
): Promise<Record<string, unknown>[]> {
  const limit = 100;
  const items: Record<string, unknown>[] = [];
  const seen = new Set<string>();
  for (let page = 0; page < 1000; page++) {
    const result = await request("GET", path, {
      ...options,
      query: {
        ...options.query,
        limit: String(limit),
        offset: String(page * limit),
      },
    });
    if (result === null) {
      throw new CherryApiError("GET", path, 404, "collection not found");
    }
    if (!Array.isArray(result)) {
      throw new CherryApiError("GET", path, 200, "expected a JSON array");
    }
    let added = 0;
    for (const item of result as Record<string, unknown>[]) {
      const key = item.id === undefined
        ? JSON.stringify(item)
        : String(item.id);
      if (seen.has(key)) continue;
      seen.add(key);
      items.push(item);
      added++;
    }
    if (result.length < limit) return items;
    if (added === 0) {
      // A full page with nothing new means the endpoint ignored paging; the
      // list may be incomplete, so refuse rather than under-report.
      throw new Error(
        `${path} returned a repeated full page; cannot prove the list is complete`,
      );
    }
  }
  throw new Error(`Refusing to page past 1000 pages of ${path}`);
}

/** Converts an arbitrary name into a safe swamp data instance name. */
export function instanceName(name: string): string {
  return name.replace(/[\/\\]/g, "_").replace(/\.\./g, "_").replace(/\0/g, "");
}
