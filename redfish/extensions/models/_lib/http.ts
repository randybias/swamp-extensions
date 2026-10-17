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

/**
 * How the BMC's TLS certificate is validated: always against the system trust
 * store, or against a pinned `caPem` when one is given. There is no mode that
 * skips verification: Deno has no per-client switch for it (see the README).
 */
export interface TlsPolicy {
  mode: "strict";
  caPem?: string;
}

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
  /** Per-request deadline in milliseconds. */
  requestTimeoutMs: number;
}

const denoFetch: FetchFn = (url, init) => fetch(url, init as RequestInit);

const denoMakeClient = (tls: TlsPolicy): HttpClientHandle => {
  const client = Deno.createHttpClient({
    ...(tls.caPem ? { caCerts: [tls.caPem] } : {}),
  });
  return { client, close: () => client.close() };
};

/** Default per-request deadline. */
export const REQUEST_TIMEOUT_MS = 30_000;

/** Production dependencies. */
export function defaultDeps(): Deps {
  return {
    fetch: denoFetch,
    makeClient: denoMakeClient,
    now: () => new Date(),
    sleep: (ms) => new Promise((resolve) => setTimeout(resolve, ms)),
    requestTimeoutMs: REQUEST_TIMEOUT_MS,
  };
}

/** Failure classes a Redfish call can report. */
export type RedfishErrorCode =
  | "unreachable"
  | "tls"
  | "unauthorized"
  | "no_session_service"
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

/** A typed error for a request that did not finish in time. */
export function timeoutError(): RedfishError {
  return new RedfishError(
    "timeout",
    "BMC did not respond within the request timeout",
  );
}

/** Reads one chunk, rejecting as a typed timeout if `signal` aborts first. */
async function readWithSignal(
  reader: ReadableStreamDefaultReader<Uint8Array>,
  signal?: AbortSignal,
): Promise<ReadableStreamReadResult<Uint8Array>> {
  if (!signal) return await reader.read();
  if (signal.aborted) throw timeoutError();
  return await new Promise((resolve, reject) => {
    const onAbort = () => reject(timeoutError());
    signal.addEventListener("abort", onAbort, { once: true });
    reader.read().then(
      (r) => {
        signal.removeEventListener("abort", onAbort);
        resolve(r);
      },
      (e) => {
        signal.removeEventListener("abort", onAbort);
        // A stream aborted by the signal reports a DOMException; map it.
        reject(signal.aborted ? timeoutError() : e);
      },
    );
  });
}

/**
 * Reads at most `max` bytes of a response body. A larger body is refused
 * instead of buffered, so a hostile or broken BMC cannot exhaust memory. When
 * `signal` aborts (or is already aborted), the read fails as a typed timeout.
 */
export async function readBounded(
  resp: Response,
  max = MAX_BODY_BYTES,
  signal?: AbortSignal,
): Promise<string> {
  if (!resp.body) return "";
  const reader = resp.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await readWithSignal(reader, signal);
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

/** The message of an error and of every `cause` behind it (bounded). */
function causeChain(e: unknown): string[] {
  const out: string[] = [];
  let cur: unknown = e;
  for (let i = 0; i < 6 && cur !== undefined && cur !== null; i++) {
    if (cur instanceof Error) {
      out.push(`${cur.name} ${cur.message}`);
      cur = (cur as Error & { cause?: unknown }).cause;
    } else {
      out.push(String(cur));
      break;
    }
  }
  return out;
}

/**
 * Maps a thrown fetch failure to a typed error. Deno reports a TLS failure as
 * a generic `fetch failed` whose `cause` carries the certificate error, so the
 * whole cause chain is read. The message of the thrown error is never
 * included; each TLS class gets a fixed hint instead.
 */
export function classifyFetch(e: unknown): RedfishError {
  if (
    e instanceof Error &&
    (e.name === "AbortError" || e.name === "TimeoutError")
  ) {
    return timeoutError();
  }
  const text = causeChain(e).join(" | ");
  const tls = (hint: string) =>
    new RedfishError(
      "tls",
      `TLS verification failed for the BMC endpoint: ${hint}`,
    );
  if (/CaUsedAsEndEntity/i.test(text)) {
    return tls(
      "the BMC certificate is a CA certificate (CA:TRUE) used as the server certificate; use a CA:FALSE leaf, or pin a separate CA that signed it, in ca_pem",
    );
  }
  if (/UnknownIssuer|unknown ?ca|unable to get (local )?issuer/i.test(text)) {
    return tls(
      "the certificate was not issued by a trusted CA; pin the CA that signed it in ca_pem",
    );
  }
  if (/Expired|NotValidYet|not yet valid/i.test(text)) {
    return tls("the certificate is expired or not yet valid");
  }
  if (/NotValidForName|hostname|not valid for name|subject.?alt/i.test(text)) {
    return tls(
      "the certificate is not valid for the endpoint host name or address",
    );
  }
  if (
    /certificate|self.signed|x509|\btls\b|\bssl\b|handshake|verify|InvalidCertificate|invalid peer/i
      .test(text)
  ) {
    return tls("the certificate could not be verified");
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
