/**
 * Minimal Azure Resource Manager REST client for swamp extensions.
 *
 * Authentication is OAuth2 client credentials. The client secret travels only
 * in the HTTPS POST body of the token request — never a URL, a header or a
 * process argument — and the access token lives in memory for one method call.
 * The `fetch`, clock and sleep are injectable, so tests open no socket.
 *
 * The module is self-contained: it imports nothing from the rest of the
 * extension, so it can be copied unchanged into a sibling extension.
 *
 * @module
 */

/** Signature of the fetch implementation the client uses. */
export type FetchFn = (
  input: string,
  init?: RequestInit,
) => Promise<Response>;

/** Injectable dependencies of the client and its poll loops. */
export interface ArmDeps {
  /** Performs HTTPS requests. */
  fetch: FetchFn;
  /** Current time in milliseconds. */
  now: () => number;
  /** Sleeps for the given milliseconds. */
  sleep: (ms: number) => Promise<void>;
}

/** Service-principal identity used to obtain a token. */
export interface ArmAuth {
  /** Entra tenant id. */
  tenantId: string;
  /** Application (client) id. */
  clientId: string;
  /** Client secret; sensitive, body-only. */
  clientSecret: string;
}

/** Optional endpoints, for tests or sovereign clouds. */
export interface ArmOptions {
  /** Token authority; defaults to the public cloud. */
  authorityHost?: string;
  /** ARM endpoint; defaults to the public cloud. */
  armEndpoint?: string;
  /** OAuth2 scope; defaults to the ARM scope. */
  scope?: string;
}

/** Result of one ARM request. */
export interface ArmResult {
  /** HTTP status. */
  status: number;
  /** Parsed JSON body, or the raw text when it is not JSON. */
  body: unknown;
}

/** The client one method call uses. */
export interface ArmClient {
  /** Sends a request and returns its parsed result; throws on a non-2xx. */
  send(method: string, path: string, body?: unknown): Promise<ArmResult>;
  /** GETs a path; throws on a non-2xx. */
  get(path: string): Promise<ArmResult>;
  /** PUTs a path with a JSON body; throws on a non-2xx. */
  put(path: string, body: unknown): Promise<ArmResult>;
  /** POSTs a path with an optional JSON body; throws on a non-2xx. */
  post(path: string, body?: unknown): Promise<ArmResult>;
  /** DELETEs a path; throws on a non-2xx. */
  del(path: string): Promise<ArmResult>;
  /** Returns the cached access token, fetching it on first use. */
  token(): Promise<string>;
}

/** An ARM or token failure. `status` 0 means no HTTP response. */
export class ArmError extends Error {
  /** HTTP status, or 0 when there was no response. */
  readonly status: number;
  /** Azure error code, when the body carried one. */
  readonly code?: string;

  /** Creates an ARM error. */
  constructor(message: string, status: number, code?: string) {
    super(message);
    this.name = "ArmError";
    this.status = status;
    this.code = code;
  }
}

/** True when `error` is an ARM 404. */
export function isNotFound(error: unknown): boolean {
  return error instanceof ArmError && error.status === 404;
}

/** True when `error` is an ARM 409 (already exists / conflicting state). */
export function isConflict(error: unknown): boolean {
  return error instanceof ArmError && error.status === 409;
}

/** Replaces every occurrence of each secret in `text` with `***`. */
export function redact(text: string, secrets: readonly string[]): string {
  let out = text;
  for (const secret of secrets) {
    if (secret) out = out.split(secret).join("***");
  }
  return out;
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

/** Reads a short, secret-free error code from an Azure error body. */
function errorCode(body: unknown): string | undefined {
  if (body && typeof body === "object") {
    const code = (body as Record<string, unknown>).code;
    if (typeof code === "string" && /^[A-Za-z0-9_.-]{1,64}$/.test(code)) {
      return code;
    }
  }
  return undefined;
}

/** Reads a short, secret-free error message from an Azure error body. */
function errorMessage(body: unknown): string {
  if (body && typeof body === "object") {
    const message = (body as Record<string, unknown>).message;
    if (typeof message === "string" && message.length > 0) {
      return message.slice(0, 300);
    }
  }
  return typeof body === "string" ? body.slice(0, 300) : "no response body";
}

const DEFAULT_AUTHORITY = "https://login.microsoftonline.com";
const DEFAULT_ARM = "https://management.azure.com";
const DEFAULT_SCOPE = "https://management.azure.com/.default";

/**
 * Builds a client for one call. The token is fetched lazily and cached for the
 * life of the client only.
 */
export function createArmClient(
  deps: ArmDeps,
  auth: ArmAuth,
  options: ArmOptions = {},
): ArmClient {
  const authority = options.authorityHost ?? DEFAULT_AUTHORITY;
  const armEndpoint = options.armEndpoint ?? DEFAULT_ARM;
  const scope = options.scope ?? DEFAULT_SCOPE;
  const secrets = [auth.clientSecret];
  let tokenPromise: Promise<string> | undefined;

  const token = (): Promise<string> => {
    if (tokenPromise === undefined) {
      tokenPromise = fetchToken(deps, auth, authority, scope, secrets);
    }
    return tokenPromise;
  };

  const send = async (
    method: string,
    path: string,
    body?: unknown,
  ): Promise<ArmResult> => {
    const accessToken = await token();
    const headers: Record<string, string> = {
      authorization: `Bearer ${accessToken}`,
      accept: "application/json",
    };
    if (body !== undefined) headers["content-type"] = "application/json";
    const res = await deps.fetch(`${armEndpoint}${path}`, {
      method,
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    const text = await res.text();
    const parsed = parseBody(text);
    if (res.status < 200 || res.status > 299) {
      const code = errorCode(parsed);
      throw new ArmError(
        redact(
          `${method} ${path} returned ${res.status}: ${errorMessage(parsed)}`,
          secrets,
        ),
        res.status,
        code,
      );
    }
    return { status: res.status, body: parsed };
  };

  return {
    send,
    get: (path) => send("GET", path),
    put: (path, body) => send("PUT", path, body),
    post: (path, body) => send("POST", path, body),
    del: (path) => send("DELETE", path),
    token,
  };
}

/** Requests a client-credentials token with the secret in the POST body. */
async function fetchToken(
  deps: ArmDeps,
  auth: ArmAuth,
  authority: string,
  scope: string,
  secrets: readonly string[],
): Promise<string> {
  const url = `${authority}/${auth.tenantId}/oauth2/v2.0/token`;
  const form = new URLSearchParams({
    grant_type: "client_credentials",
    client_id: auth.clientId,
    client_secret: auth.clientSecret,
    scope,
  });
  const res = await deps.fetch(url, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: form.toString(),
  });
  const text = await res.text();
  const parsed = parseBody(text);
  if (res.status < 200 || res.status > 299) {
    throw new ArmError(
      redact(
        `token request returned ${res.status}: ${errorMessage(parsed)}`,
        secrets,
      ),
      res.status,
      errorCode(parsed),
    );
  }
  const accessToken = parsed && typeof parsed === "object"
    ? (parsed as Record<string, unknown>).access_token
    : undefined;
  if (typeof accessToken !== "string" || accessToken === "") {
    throw new ArmError("token response carried no access_token", 0);
  }
  return accessToken;
}

/** Options for {@link pollUntil}. */
export interface PollOptions {
  /** Total budget in milliseconds. */
  deadlineMs: number;
  /** First interval in milliseconds. */
  intervalMs: number;
  /** Ceiling for the exponential backoff; defaults to 30 s. */
  maxIntervalMs?: number;
  /** Human-readable subject used in the timeout error. */
  label: string;
}

/**
 * Polls `probe` with capped exponential backoff until it returns a non-null
 * value or the budget is spent. A probe that throws aborts the poll.
 */
export async function pollUntil<T>(
  deps: ArmDeps,
  options: PollOptions,
  probe: () => Promise<T | null>,
): Promise<T> {
  const started = deps.now();
  const ceiling = options.maxIntervalMs ?? Math.max(options.intervalMs, 30_000);
  let interval = options.intervalMs;
  for (;;) {
    const value = await probe();
    if (value !== null) return value;
    if (deps.now() - started >= options.deadlineMs) {
      throw new ArmError(
        `${options.label} did not settle within ${options.deadlineMs} ms`,
        0,
      );
    }
    await deps.sleep(interval);
    interval = Math.min(interval * 2, ceiling);
  }
}

/** Default fetch, for production. */
export const denoFetch: FetchFn = (input, init) => fetch(input, init);

/** Production dependencies: real fetch, clock and sleep. */
export const denoArmDeps: ArmDeps = {
  fetch: denoFetch,
  now: () => Date.now(),
  sleep: (ms: number) => new Promise((resolve) => setTimeout(resolve, ms)),
};
