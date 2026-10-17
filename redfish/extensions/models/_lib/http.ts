/**
 * HTTP transport for the Redfish model.
 *
 * The fetch implementation and the TLS client factory are injectable, so unit
 * tests start no socket. Response bodies are read with a hard byte cap, and a
 * failed request is mapped to a fixed, typed message: no response body, URL or
 * credential is ever echoed. Credentials travel only in an `Authorization` or
 * `X-Auth-Token` header, never in a URL.
 *
 * @module
 */

/** A fetch implementation; injectable so tests start no socket. */
export type FetchFn = (
  url: string,
  init: RequestInit & { client?: unknown },
) => Promise<Response>;

/** A created TLS client and its closer. */
export interface HttpClientHandle {
  /** Passed to fetch as `init.client`. */
  client: unknown;
  /** Frees the client's resources. */
  close(): void;
}

/** How the BMC's TLS certificate is validated. There is no default: the
 * caller must choose `strict` (system trust, or a pinned `caPem`) or the
 * explicit `insecure_skip_verify`. */
export type TlsPolicy =
  | { mode: "strict"; caPem?: string }
  | { mode: "insecure_skip_verify" };

/** Injectable dependencies. */
export interface Deps {
  /** Performs the HTTPS request. */
  fetch: FetchFn;
  /** Builds the TLS client for the chosen policy. */
  makeClient(tls: TlsPolicy): HttpClientHandle;
  /** Current time. */
  now(): Date;
  /** Waits between polls. */
  sleep(ms: number): Promise<void>;
}

const denoFetch: FetchFn = (url, init) => fetch(url, init as RequestInit);

const denoMakeClient = (tls: TlsPolicy): HttpClientHandle => {
  const client = Deno.createHttpClient({
    ...(tls.mode === "strict" && tls.caPem ? { caCerts: [tls.caPem] } : {}),
    ...(tls.mode === "insecure_skip_verify"
      ? { unsafelyDisableTlsVerification: true }
      : {}),
  });
  return { client, close: () => client.close() };
};

/** Production dependencies. */
export function defaultDeps(): Deps {
  return {
    fetch: denoFetch,
    makeClient: denoMakeClient,
    now: () => new Date(),
    sleep: (ms) => new Promise((resolve) => setTimeout(resolve, ms)),
  };
}

/** Failure classes a Redfish call can report. */
export type RedfishErrorCode =
  | "unreachable"
  | "tls"
  | "unauthorized"
  | "not_found"
  | "invalid_input"
  | "timeout"
  | "response_too_large"
  | "redfish_failed";

/** A typed failure whose message carries no credential or response body. */
export class RedfishError extends Error {
  /** The failure class. */
  readonly code: RedfishErrorCode;
  /** Creates a typed error. */
  constructor(code: RedfishErrorCode, message: string) {
    super(message);
    this.name = "RedfishError";
    this.code = code;
  }
}

/** Maximum response body kept in memory. */
export const MAX_BODY_BYTES = 1024 * 1024;

/**
 * Reads at most `max` bytes of a response body. A larger body is refused
 * instead of buffered, so a hostile or broken BMC cannot exhaust memory.
 */
export async function readBounded(
  resp: Response,
  max = MAX_BODY_BYTES,
): Promise<string> {
  if (!resp.body) return "";
  const reader = resp.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    if (!value) continue;
    total += value.byteLength;
    if (total > max) {
      await reader.cancel();
      throw new RedfishError(
        "response_too_large",
        `BMC response exceeded ${max} bytes`,
      );
    }
    chunks.push(value);
  }
  const merged = new Uint8Array(total);
  let offset = 0;
  for (const c of chunks) {
    merged.set(c, offset);
    offset += c.byteLength;
  }
  return new TextDecoder().decode(merged);
}

/** Discards a response body without buffering it. */
export async function drain(resp: Response): Promise<void> {
  try {
    await resp.body?.cancel();
  } catch {
    // The body was already consumed or the connection is gone.
  }
}

/**
 * Maps a thrown fetch failure to a typed error. Certificate problems become
 * `tls`; anything else is `unreachable`. The thrown message is never included.
 */
export function classifyFetch(e: unknown): RedfishError {
  const text = e instanceof Error ? e.message : "";
  if (/certificate|self.signed|x509|tls|ssl|verify/i.test(text)) {
    return new RedfishError(
      "tls",
      "TLS verification failed for the BMC endpoint",
    );
  }
  return new RedfishError("unreachable", "BMC endpoint unreachable");
}

/** Maps a non-2xx status to a typed error with a fixed message. */
export function statusError(status: number): RedfishError {
  if (status === 401 || status === 403) {
    return new RedfishError(
      "unauthorized",
      `BMC rejected the credentials (HTTP ${status})`,
    );
  }
  if (status === 404) {
    return new RedfishError(
      "not_found",
      "Redfish resource not found (HTTP 404)",
    );
  }
  return new RedfishError(
    "redfish_failed",
    `Redfish request failed (HTTP ${status})`,
  );
}

/** Standard base64 of a UTF-8 string. */
export function b64Utf8(s: string): string {
  let bin = "";
  for (const b of new TextEncoder().encode(s)) bin += String.fromCharCode(b);
  return btoa(bin);
}

/** Hex sha256 of a UTF-8 string. */
export async function sha256Hex(s: string): Promise<string> {
  const d = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(s),
  );
  return [...new Uint8Array(d)].map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}
