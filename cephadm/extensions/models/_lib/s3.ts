/**
 * The S3 plane of the RGW group: AWS Signature Version 4 signing (service
 * `s3`), a pinned XML parser, the shared bucket-presence classifier, Public
 * Access Block, ACL and versioning parsing, and the policy structural
 * validation and canonical form. No SSH and no admin keyring: every request is
 * signed with the bucket owner's S3 key pair, which is used only to compute
 * signatures and never appears in a record, log or error.
 *
 * All four RGW S3-plane methods share this module. Every request goes through
 * the injectable `fetch` seam (used by these methods only) with a fresh
 * connection, and no request URL is ever put into a record, log or error.
 *
 * Clean-room: behaviour comes only from the approved spec under
 * `docs/specs/cephadm/`, public S3/SigV4 and libvirt documentation.
 *
 * @module
 */

import { parse as parseXmlDocument } from "jsr:@std/xml@0.2.0";
import { fail } from "./errors.ts";
import { redactSecrets } from "./rgw.ts";

// ---------------------------------------------------------------------------
// HTTP seam
// ---------------------------------------------------------------------------

/** One HTTP request; `url` is never recorded, logged or put in an error. */
export interface HttpRequest {
  /** HTTP method. */
  method: string;
  /** Absolute URL, including the query string. */
  url: string;
  /** Request headers. */
  headers: Record<string, string>;
  /** Request body, when there is one. */
  body?: Uint8Array;
  /** Abort the request after this many milliseconds. */
  timeoutMs: number;
}

/** One HTTP answer. */
export interface HttpResponse {
  /** Status code. */
  status: number;
  /** Response headers, keys lowercased. */
  headers: Record<string, string>;
  /** Response body as text. */
  body: string;
}

/** A transport-level failure of the injected fetch seam. */
export class HttpError extends Error {
  /** `refused` only when nothing is listening; otherwise `unreachable`. */
  readonly kind: "refused" | "unreachable";
  /** Redacted, URL-free transport detail, safe to truncate into an error. */
  readonly detail: string;

  /** Builds a classified HTTP transport error. */
  constructor(kind: "refused" | "unreachable", detail: string) {
    super(`http transport ${kind}: ${detail}`);
    this.name = "HttpError";
    this.kind = kind;
    this.detail = detail;
  }
}

/** The injectable HTTP fetch seam used by the S3-plane methods only. */
export type FetchFn = (request: HttpRequest) => Promise<HttpResponse>;

/** Removes any absolute URL from transport detail so it can never be recorded. */
function stripUrls(text: string): string {
  return text.replace(/https?:\/\/[^\s"')]+/gi, "<url>").replace(/\s+/g, " ")
    .trim();
}

/** The most response body bytes the seam will buffer. */
export const MAX_RESPONSE_BYTES = 1_048_576;

/** Classifies a fetch rejection, producing a URL-free detail. */
function classifyFetchError(e: unknown): HttpError {
  if (e instanceof HttpError) return e;
  const message = e instanceof Error ? e.message : String(e);
  const clean = stripUrls(message).slice(0, 300);
  if (
    /connection refused|econnrefused|os error 111|connection reset/i.test(
      message,
    )
  ) {
    return new HttpError("refused", clean || "connection refused");
  }
  if (/abort|timed? ?out|deadline/i.test(message)) {
    return new HttpError("unreachable", clean || "the request timed out");
  }
  return new HttpError("unreachable", clean || "the connection failed");
}

/** Reads a response body up to `cap` bytes, refusing anything larger. */
async function readBounded(
  res: Response,
  cap: number,
): Promise<string> {
  const reader = res.body?.getReader();
  if (reader === undefined) return "";
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > cap) {
      await reader.cancel().catch(() => undefined);
      throw new HttpError(
        "unreachable",
        `the response body exceeded the ${cap}-byte cap`,
      );
    }
    chunks.push(value);
  }
  const merged = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    merged.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return new TextDecoder().decode(merged);
}

/** Production fetch seam: one fresh connection per request, no keep-alive. */
export const denoFetch: FetchFn = async (request) => {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), request.timeoutMs);
  try {
    const res = await fetch(request.url, {
      method: request.method,
      headers: { ...request.headers, Connection: "close" },
      body: request.body as unknown as BodyInit | undefined,
      redirect: "manual",
      signal: controller.signal,
    });
    const headers: Record<string, string> = {};
    res.headers.forEach((value, key) => {
      headers[key.toLowerCase()] = value;
    });
    return {
      status: res.status,
      headers,
      body: await readBounded(res, MAX_RESPONSE_BYTES),
    };
  } catch (e) {
    throw classifyFetchError(e);
  } finally {
    clearTimeout(timer);
  }
};

// ---------------------------------------------------------------------------
// Crypto
// ---------------------------------------------------------------------------

const encoder = new TextEncoder();

function hex(bytes: Uint8Array): string {
  let out = "";
  for (const b of bytes) out += b.toString(16).padStart(2, "0");
  return out;
}

async function sha256Hex(data: Uint8Array | string): Promise<string> {
  const bytes = typeof data === "string" ? encoder.encode(data) : data;
  return hex(
    new Uint8Array(
      await crypto.subtle.digest("SHA-256", bytes as unknown as BufferSource),
    ),
  );
}

async function hmacSha256(
  key: Uint8Array,
  message: string,
): Promise<Uint8Array> {
  const k = await crypto.subtle.importKey(
    "raw",
    key as unknown as BufferSource,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  return new Uint8Array(
    await crypto.subtle.sign("HMAC", k, encoder.encode(message)),
  );
}

/**
 * MD5 (RFC 1321), little-endian, used only for the mandated `Content-MD5`
 * header on `PutPublicAccessBlock`. Pure and self-contained; no dependency is
 * taken just for an obsolete digest.
 */
export function md5(input: Uint8Array): Uint8Array {
  const shifts = [
    7,
    12,
    17,
    22,
    7,
    12,
    17,
    22,
    7,
    12,
    17,
    22,
    7,
    12,
    17,
    22,
    5,
    9,
    14,
    20,
    5,
    9,
    14,
    20,
    5,
    9,
    14,
    20,
    5,
    9,
    14,
    20,
    4,
    11,
    16,
    23,
    4,
    11,
    16,
    23,
    4,
    11,
    16,
    23,
    4,
    11,
    16,
    23,
    6,
    10,
    15,
    21,
    6,
    10,
    15,
    21,
    6,
    10,
    15,
    21,
    6,
    10,
    15,
    21,
  ];
  const k = new Uint32Array(64);
  for (let i = 0; i < 64; i++) {
    k[i] = Math.floor(Math.abs(Math.sin(i + 1)) * 4294967296);
  }
  const len = input.length;
  const padLen = ((56 - ((len + 1) % 64)) + 64) % 64;
  const total = len + 1 + padLen + 8;
  const msg = new Uint8Array(total);
  msg.set(input, 0);
  msg[len] = 0x80;
  const bitLen = len * 8;
  const low = bitLen >>> 0;
  const high = Math.floor(bitLen / 4294967296) >>> 0;
  msg[total - 8] = low & 0xff;
  msg[total - 7] = (low >>> 8) & 0xff;
  msg[total - 6] = (low >>> 16) & 0xff;
  msg[total - 5] = (low >>> 24) & 0xff;
  msg[total - 4] = high & 0xff;
  msg[total - 3] = (high >>> 8) & 0xff;
  msg[total - 2] = (high >>> 16) & 0xff;
  msg[total - 1] = (high >>> 24) & 0xff;
  let a0 = 0x67452301, b0 = 0xefcdab89, c0 = 0x98badcfe, d0 = 0x10325476;
  const rol = (x: number, c: number) => ((x << c) | (x >>> (32 - c))) >>> 0;
  for (let off = 0; off < total; off += 64) {
    const m = new Uint32Array(16);
    for (let i = 0; i < 16; i++) {
      const j = off + i * 4;
      m[i] = (msg[j] | (msg[j + 1] << 8) | (msg[j + 2] << 16) |
        (msg[j + 3] << 24)) >>> 0;
    }
    let a = a0, b = b0, c = c0, d = d0;
    for (let i = 0; i < 64; i++) {
      let f: number, g: number;
      if (i < 16) {
        f = (b & c) | (~b & d);
        g = i;
      } else if (i < 32) {
        f = (d & b) | (~d & c);
        g = (5 * i + 1) % 16;
      } else if (i < 48) {
        f = b ^ c ^ d;
        g = (3 * i + 5) % 16;
      } else {
        f = c ^ (b | ~d);
        g = (7 * i) % 16;
      }
      f = (f + a + k[i] + m[g]) >>> 0;
      a = d;
      d = c;
      c = b;
      b = (b + rol(f, shifts[i])) >>> 0;
    }
    a0 = (a0 + a) >>> 0;
    b0 = (b0 + b) >>> 0;
    c0 = (c0 + c) >>> 0;
    d0 = (d0 + d) >>> 0;
  }
  const out = new Uint8Array(16);
  const words = [a0, b0, c0, d0];
  for (let i = 0; i < 4; i++) {
    out[i * 4] = words[i] & 0xff;
    out[i * 4 + 1] = (words[i] >>> 8) & 0xff;
    out[i * 4 + 2] = (words[i] >>> 16) & 0xff;
    out[i * 4 + 3] = (words[i] >>> 24) & 0xff;
  }
  return out;
}

/** Base64 of the MD5 of `bytes`, for a `Content-MD5` header. */
export function md5Base64(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...md5(bytes)));
}

// ---------------------------------------------------------------------------
// Argument validation
// ---------------------------------------------------------------------------

const REGION_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
const BUCKET_RE = /^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$/;
const IPV4_QUAD_RE = /^\d{1,3}(?:\.\d{1,3}){3}$/;

/** True when `v` is a printable-ASCII, non-space credential. */
export function isCredential(v: string): boolean {
  if (v.length < 1 || v.length > 512) return false;
  for (const ch of v) {
    const code = ch.codePointAt(0) ?? 0;
    if (code < 0x21 || code > 0x7e) return false;
  }
  return true;
}

/** True when `v` matches the region grammar (zonegroup api name). */
export function isRegion(v: string): boolean {
  return REGION_RE.test(v);
}

/** True when `v` matches the S3 bucket-name grammar. */
export function isBucketName(v: string): boolean {
  if (!BUCKET_RE.test(v)) return false;
  if (v.includes("..")) return false;
  if (IPV4_QUAD_RE.test(v)) return false;
  return true;
}

/** Normalises and validates an endpoint: https (or http for the plain probe). */
export function normaliseEndpoint(
  raw: string,
  scheme: "https" | "http",
  phase = "validate",
): string {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    fail(phase, "the endpoint is not a URL", { scheme });
  }
  if (url.protocol !== `${scheme}:`) {
    fail(phase, "the endpoint must use the required scheme", { scheme });
  }
  if (url.username !== "" || url.password !== "") {
    fail(phase, "the endpoint must not carry userinfo", { scheme });
  }
  if (url.pathname !== "" && url.pathname !== "/") {
    fail(phase, "the endpoint must be an origin with no path", { scheme });
  }
  if (url.search !== "" || url.hash !== "") {
    fail(phase, "the endpoint must have no query or fragment", { scheme });
  }
  return url.origin;
}

/** True when `raw` is a valid origin for `scheme` (for schema refines). */
export function isEndpointOrigin(
  raw: string,
  scheme: "https" | "http",
): boolean {
  try {
    normaliseEndpoint(raw, scheme, "validate");
    return true;
  } catch {
    return false;
  }
}

/** Validates the common S3 arguments and returns the normalised origin. */
export function validateCommon(args: {
  endpoint: string;
  region: string;
  bucket: string;
  accessKey: string;
  secretKey: string;
  requestTimeoutMs: number;
}): string {
  const origin = normaliseEndpoint(args.endpoint, "https");
  if (!isRegion(args.region)) fail("validate", "the region is not valid", {});
  if (!isBucketName(args.bucket)) {
    fail("validate", "the bucket name is not valid", {});
  }
  for (
    const [field, value] of [
      ["accessKey", args.accessKey],
      ["secretKey", args.secretKey],
    ] as const
  ) {
    if (!isCredential(value)) {
      fail("validate", "the credential is not valid", {
        field,
        length: value.length,
      });
    }
  }
  if (
    !Number.isInteger(args.requestTimeoutMs) ||
    args.requestTimeoutMs < 1000 || args.requestTimeoutMs > 300000
  ) {
    fail("validate", "requestTimeoutMs is out of range", {});
  }
  return origin;
}

// ---------------------------------------------------------------------------
// SigV4
// ---------------------------------------------------------------------------

/** Percent-encodes one value per the SigV4 rules. */
export function uriEncode(value: string, encodeSlash = true): string {
  let out = "";
  for (const byte of encoder.encode(value)) {
    const ch = String.fromCharCode(byte);
    if (
      (byte >= 0x41 && byte <= 0x5a) || (byte >= 0x61 && byte <= 0x7a) ||
      (byte >= 0x30 && byte <= 0x39) || ch === "_" || ch === "-" ||
      ch === "~" || ch === "."
    ) {
      out += ch;
    } else if (!encodeSlash && ch === "/") {
      out += ch;
    } else {
      out += `%${byte.toString(16).toUpperCase().padStart(2, "0")}`;
    }
  }
  return out;
}

function amzDate(timestamp: number): { full: string; short: string } {
  const iso = new Date(timestamp).toISOString();
  const short = iso.slice(0, 10).replace(/-/g, "");
  const full = `${short}T${iso.slice(11, 19).replace(/:/g, "")}Z`;
  return { full, short };
}

function canonicalQuery(query: Record<string, string>): string {
  return Object.keys(query).sort()
    .map((k) => `${uriEncode(k)}=${uriEncode(query[k])}`)
    .join("&");
}

/** The signed headers and URL a SigV4 request needs. */
export interface SignedRequest {
  /** The URL, origin + path + canonical query. */
  url: string;
  /** Headers to send, including `Authorization`; host is not sent explicitly. */
  headers: Record<string, string>;
}

/** Signs one request with AWS Signature Version 4 (service `s3`). */
export async function signRequest(opts: {
  method: string;
  origin: string;
  path: string;
  query: Record<string, string>;
  headers: Record<string, string>;
  body: Uint8Array;
  region: string;
  accessKey: string;
  secretKey: string;
  timestamp: number;
}): Promise<SignedRequest> {
  const host = new URL(opts.origin).host;
  const { full, short } = amzDate(opts.timestamp);
  const payloadHash = await sha256Hex(opts.body);
  const signed: Record<string, string> = {
    host,
    "x-amz-content-sha256": payloadHash,
    "x-amz-date": full,
  };
  for (const [k, v] of Object.entries(opts.headers)) {
    signed[k.toLowerCase()] = v.replace(/\s+/g, " ").trim();
  }
  const names = Object.keys(signed).sort();
  const canonicalHeaders = names.map((n) => `${n}:${signed[n]}\n`).join("");
  const signedHeaders = names.join(";");
  const canonicalUri = uriEncode(opts.path, false);
  const canonicalRequest = [
    opts.method,
    canonicalUri,
    canonicalQuery(opts.query),
    canonicalHeaders,
    signedHeaders,
    payloadHash,
  ].join("\n");
  const scope = `${short}/${opts.region}/s3/aws4_request`;
  const stringToSign = [
    "AWS4-HMAC-SHA256",
    full,
    scope,
    await sha256Hex(canonicalRequest),
  ].join("\n");
  let key: Uint8Array = encoder.encode(`AWS4${opts.secretKey}`);
  key = await hmacSha256(key, short);
  key = await hmacSha256(key, opts.region);
  key = await hmacSha256(key, "s3");
  key = await hmacSha256(key, "aws4_request");
  const signature = hex(await hmacSha256(key, stringToSign));
  const sent: Record<string, string> = { ...opts.headers };
  sent["x-amz-content-sha256"] = payloadHash;
  sent["x-amz-date"] = full;
  sent["Authorization"] =
    `AWS4-HMAC-SHA256 Credential=${opts.accessKey}/${scope}, ` +
    `SignedHeaders=${signedHeaders}, Signature=${signature}`;
  const qs = canonicalQuery(opts.query);
  return {
    url: `${opts.origin}${opts.path}${qs ? `?${qs}` : ""}`,
    headers: sent,
  };
}

// ---------------------------------------------------------------------------
// XML (pinned parser)
// ---------------------------------------------------------------------------

const S3_NS = "http://s3.amazonaws.com/doc/2006-03-01/";
const XSI_NS = "http://www.w3.org/2001/XMLSchema-instance";

/** One element from the pinned parser, with namespaces resolved. */
export interface XmlElement {
  /** Local name, any prefix stripped. */
  local: string;
  /** Concatenated, entity-decoded text of the element. */
  text: string;
  /** Child elements. */
  children: XmlElement[];
  /** Attributes keyed by local name when unambiguous, else raw key. */
  attrs: Record<string, string>;
  /** In-scope namespace prefix map. */
  namespaces: Record<string, string>;
}

interface RawNode {
  type?: string;
  name?: { local?: string; raw?: string };
  attributes?: Record<string, string>;
  children?: RawNode[];
  text?: string;
}

function convertXml(node: RawNode, scope: Record<string, string>): XmlElement {
  const namespaces = { ...scope };
  for (const [k, v] of Object.entries(node.attributes ?? {})) {
    if (k === "xmlns") namespaces[""] = v;
    else if (k.startsWith("xmlns:")) namespaces[k.slice(6)] = v;
  }
  const attrs: Record<string, string> = {};
  for (const [k, v] of Object.entries(node.attributes ?? {})) {
    if (k === "xmlns" || k.startsWith("xmlns:")) continue;
    const local = k.includes(":") ? k.slice(k.indexOf(":") + 1) : k;
    if (attrs[local] === undefined) attrs[local] = v;
    attrs[k] = v;
  }
  const rawChildren = node.children ?? [];
  return {
    local: node.name?.local ?? node.name?.raw ?? "",
    text: rawChildren.map((c) => c.type === "text" ? c.text ?? "" : "").join(
      "",
    ),
    children: rawChildren.filter((c) => c.type === "element")
      .map((c) => convertXml(c, namespaces)),
    attrs,
    namespaces,
  };
}

/** Parses an XML document with the pinned parser. */
export function parseS3Xml(text: string): XmlElement {
  const tree = parseXmlDocument(text) as { root?: RawNode };
  if (tree.root === undefined) throw new Error("empty XML document");
  return convertXml(tree.root, {});
}

/** The first child with the given local name. */
export function childOf(
  el: XmlElement,
  local: string,
): XmlElement | undefined {
  return el.children.find((c) => c.local === local);
}

/** Every child with the given local name. */
export function childrenOf(el: XmlElement, local: string): XmlElement[] {
  return el.children.filter((c) => c.local === local);
}

/** The trimmed text of the first child with the given local name. */
export function childText(el: XmlElement, local: string): string {
  return (childOf(el, local)?.text ?? "").trim();
}

/** The value of an attribute by local name, or "". */
export function attrOf(el: XmlElement, local: string): string {
  return el.attrs[local] ?? "";
}

/** The `xsi:type` value resolved through the XSI namespace (not the prefix). */
export function xsiTypeOf(el: XmlElement): string {
  for (const [key, value] of Object.entries(el.attrs)) {
    const idx = key.indexOf(":");
    if (idx < 0) continue;
    const prefix = key.slice(0, idx);
    const local = key.slice(idx + 1);
    if (local === "type" && el.namespaces[prefix] === XSI_NS) return value;
  }
  return "";
}

/** Reads `Error` -> `Code` from an S3 error document, or "". */
export function s3ErrorCode(body: string): string {
  if (body.trim() === "") return "";
  try {
    const root = parseS3Xml(body);
    if (root.local !== "Error") return "";
    return childText(root, "Code");
  } catch {
    return "";
  }
}

/** True when the document is an S3 2006-03-01 (or unnamespaced) root. */
export function isS3Document(root: XmlElement): boolean {
  const ns = root.namespaces[""];
  return ns === undefined || ns === S3_NS;
}

// ---------------------------------------------------------------------------
// Request layer / outcomes
// ---------------------------------------------------------------------------

/** The three outcomes a request can end in. */
export type Outcome =
  | {
    kind: "answered";
    status: number;
    headers: Record<string, string>;
    body: string;
  }
  | { kind: "refused"; detail: string }
  | { kind: "unreachable"; detail: string };

/** The validated request context shared by the four methods. */
export interface S3Context {
  /** Injected dependencies. */
  deps: { fetch: FetchFn; now: () => number };
  /** Normalised https origin. */
  origin: string;
  /** Zonegroup api name. */
  region: string;
  /** Bucket name. */
  bucket: string;
  /** Owner's access key id. */
  accessKey: string;
  /** Owner's secret; used only for signing. */
  secretKey: string;
  /** Per-request timeout. */
  timeoutMs: number;
}

/** Minimal logger shape. */
export interface S3Logger {
  /** Informational line. */
  info: (message: string, props?: Record<string, unknown>) => void;
  /** Warning line. */
  warn: (message: string, props?: Record<string, unknown>) => void;
}

/** The result of one request, with the status when answered. */
async function send(
  ctx: S3Context,
  opts: {
    method: string;
    origin?: string;
    path: string;
    query?: Record<string, string>;
    headers?: Record<string, string>;
    body?: Uint8Array;
    signed: boolean;
  },
): Promise<Outcome> {
  const origin = opts.origin ?? ctx.origin;
  const request = opts.signed
    ? await signRequest({
      method: opts.method,
      origin,
      path: opts.path,
      query: opts.query ?? {},
      headers: opts.headers ?? {},
      body: opts.body ?? new Uint8Array(),
      region: ctx.region,
      accessKey: ctx.accessKey,
      secretKey: ctx.secretKey,
      timestamp: ctx.deps.now(),
    })
    : {
      url: `${origin}${opts.path}` +
        (opts.query && Object.keys(opts.query).length > 0
          ? `?${canonicalQuery(opts.query)}`
          : ""),
      headers: { ...(opts.headers ?? {}) },
    };
  try {
    const res = await ctx.deps.fetch({
      method: opts.method,
      url: request.url,
      headers: request.headers,
      body: opts.body,
      timeoutMs: ctx.timeoutMs,
    });
    return {
      kind: "answered",
      status: res.status,
      headers: res.headers,
      body: res.body,
    };
  } catch (e) {
    if (e instanceof HttpError) {
      return {
        kind: e.kind,
        detail: redactSecrets(e.detail).slice(0, 300),
      };
    }
    return { kind: "unreachable", detail: "the endpoint was not reached" };
  }
}

function statusOf(outcome: Outcome): number {
  return outcome.kind === "answered" ? outcome.status : 0;
}

// ---------------------------------------------------------------------------
// Presence classifier
// ---------------------------------------------------------------------------

/** The shared bucket-presence classification. */
export type Presence =
  | "owned"
  | "absent"
  | "wrong-zonegroup"
  | "foreign"
  | "credentials-rejected"
  | "unreadable";

/** Classifies a bucket with a HEAD, tie-broken by a signed list. */
export async function classifyPresence(
  ctx: S3Context,
): Promise<{ presence: Presence; code: string }> {
  const head = await send(ctx, {
    method: "HEAD",
    path: `/${ctx.bucket}`,
    signed: true,
  });
  if (head.kind !== "answered") return { presence: "unreadable", code: "" };
  if (head.status === 200) return { presence: "owned", code: "" };
  if (head.status === 404) return { presence: "absent", code: "" };
  if (head.status === 301 || head.status === 307) {
    return { presence: "wrong-zonegroup", code: "" };
  }
  if (head.status === 403) {
    const list = await send(ctx, { method: "GET", path: "/", signed: true });
    if (list.kind === "answered" && list.status === 200) {
      return { presence: "foreign", code: "" };
    }
    if (list.kind === "answered" && list.status === 403) {
      return { presence: "credentials-rejected", code: s3ErrorCode(list.body) };
    }
    return { presence: "unreadable", code: "" };
  }
  return { presence: "unreadable", code: "" };
}

/** Fails with the phase that matches a non-owned presence class. */
function refusePresence(presence: Presence, code: string): never {
  if (presence === "absent") {
    fail(
      "absent",
      "the bucket does not exist; run cephRgwBucketEnsure first",
    );
  }
  if (presence === "foreign") {
    fail(
      "foreign",
      "the bucket belongs to another user; nothing was changed",
    );
  }
  if (presence === "credentials-rejected") {
    fail("credentials", "the gateway rejected the owner's credentials", {
      code: code || undefined,
    });
  }
  if (presence === "wrong-zonegroup") {
    fail("zonegroup", "the bucket lives in another zonegroup");
  }
  fail("read", "the bucket presence could not be read");
}

/** Requires the bucket to be owned, failing with the class's phase otherwise. */
async function requireOwned(
  ctx: S3Context,
): Promise<Presence> {
  const { presence, code } = await classifyPresence(ctx);
  if (presence !== "owned") refusePresence(presence, code);
  return presence;
}

// ---------------------------------------------------------------------------
// ACL
// ---------------------------------------------------------------------------

/** One ACL grant. */
export interface AclGrant {
  /** Grantee type, e.g. `CanonicalUser`. */
  granteeType: string;
  /** Grantee identity (ID, URI or email); entity-decoded. */
  grantee: string;
  /** Permission, e.g. `FULL_CONTROL`. */
  permission: string;
}

/** An ACL: owner plus grants. */
export interface Acl {
  /** Owner canonical id. */
  ownerId: string;
  /** Grants. */
  grants: AclGrant[];
}

/** Parses an `AccessControlPolicy` document, resolving `xsi:type` by namespace. */
export function parseAcl(xml: string, phase = "parse"): Acl {
  let root: XmlElement;
  try {
    root = parseS3Xml(xml);
  } catch {
    fail(phase, "the ACL document could not be parsed", {});
  }
  if (root.local !== "AccessControlPolicy") {
    fail(phase, "the ACL document has the wrong root", {});
  }
  const owner = childOf(root, "Owner");
  const ownerId = owner ? childText(owner, "ID") : "";
  if (ownerId === "") fail(phase, "the ACL has no owner id", {});
  const list = childOf(root, "AccessControlList");
  const grants: AclGrant[] = [];
  for (const grant of childrenOf(list ?? root, "Grant")) {
    const grantee = childOf(grant, "Grantee");
    if (grantee === undefined) fail(phase, "an ACL grant has no grantee", {});
    const type = xsiTypeOf(grantee);
    if (type === "") fail(phase, "an ACL grantee has no type", {});
    const identity = childText(grantee, "ID") || childText(grantee, "URI") ||
      childText(grantee, "EmailAddress");
    const permission = childText(grant, "Permission");
    if (identity === "" || permission === "") {
      fail(phase, "an ACL grant is incomplete", {});
    }
    grants.push({ granteeType: type, grantee: identity, permission });
  }
  return { ownerId, grants };
}

/** True when the ACL is exactly one owner FULL_CONTROL grant. */
export function isPrivateAcl(acl: Acl): boolean {
  return acl.grants.length === 1 &&
    acl.grants[0].granteeType === "CanonicalUser" &&
    acl.grants[0].grantee === acl.ownerId &&
    acl.grants[0].permission === "FULL_CONTROL";
}

/** Reads and parses the bucket ACL (must be 200). */
async function readAcl(ctx: S3Context): Promise<Acl> {
  const res = await send(ctx, {
    method: "GET",
    path: `/${ctx.bucket}`,
    query: { acl: "" },
    signed: true,
  });
  if (res.kind !== "answered" || res.status !== 200) {
    fail("read", "the bucket ACL could not be read", {
      status: statusOf(res),
    });
  }
  return parseAcl(res.body);
}

// ---------------------------------------------------------------------------
// Public Access Block
// ---------------------------------------------------------------------------

/** The four Public Access Block flags. */
export interface Pab {
  /** BlockPublicAcls. */
  blockPublicAcls: boolean;
  /** IgnorePublicAcls. */
  ignorePublicAcls: boolean;
  /** BlockPublicPolicy. */
  blockPublicPolicy: boolean;
  /** RestrictPublicBuckets. */
  restrictPublicBuckets: boolean;
}

const PAB_FLAGS = [
  ["blockPublicAcls", "BlockPublicAcls"],
  ["ignorePublicAcls", "IgnorePublicAcls"],
  ["blockPublicPolicy", "BlockPublicPolicy"],
  ["restrictPublicBuckets", "RestrictPublicBuckets"],
] as const;

/** True when all four PAB flags are set. */
export function isFullPab(pab: Pab): boolean {
  return pab.blockPublicAcls && pab.ignorePublicAcls && pab.blockPublicPolicy &&
    pab.restrictPublicBuckets;
}

/** All four flags set. */
export const FULL_PAB: Pab = {
  blockPublicAcls: true,
  ignorePublicAcls: true,
  blockPublicPolicy: true,
  restrictPublicBuckets: true,
};

function parseFlag(value: string): boolean {
  if (value === "true") return true;
  if (value === "false" || value === "") return false;
  throw new Error(`not a boolean: ${value}`);
}

/** Parses a `PublicAccessBlockConfiguration` document. */
export function parsePab(xml: string, phase = "read"): Pab {
  let root: XmlElement;
  try {
    root = parseS3Xml(xml);
  } catch {
    fail(phase, "the Public Access Block document could not be parsed", {});
  }
  if (root.local !== "PublicAccessBlockConfiguration") {
    fail(phase, "the Public Access Block document has the wrong root", {});
  }
  try {
    return {
      blockPublicAcls: parseFlag(childText(root, "BlockPublicAcls")),
      ignorePublicAcls: parseFlag(childText(root, "IgnorePublicAcls")),
      blockPublicPolicy: parseFlag(childText(root, "BlockPublicPolicy")),
      restrictPublicBuckets: parseFlag(
        childText(root, "RestrictPublicBuckets"),
      ),
    };
  } catch {
    fail(phase, "a Public Access Block flag is not a boolean", {});
  }
}

/** Reads PAB: null when none is configured. */
export async function readPab(ctx: S3Context): Promise<Pab | null> {
  const res = await send(ctx, {
    method: "GET",
    path: `/${ctx.bucket}`,
    query: { publicAccessBlock: "" },
    signed: true,
  });
  if (res.kind !== "answered") {
    fail("read", "the Public Access Block could not be read", {});
  }
  if (res.status === 404) {
    const code = s3ErrorCode(res.body);
    if (code === "NoSuchPublicAccessBlockConfiguration") return null;
    fail("read", "the Public Access Block read failed", { code });
  }
  if (res.status !== 200) {
    fail("read", "the Public Access Block read failed", { status: res.status });
  }
  return parsePab(res.body);
}

function renderPab(pab: Pab): Uint8Array {
  const body = PAB_FLAGS.map(([key, tag]) =>
    `<${tag}>${pab[key] ? "true" : "false"}</${tag}>`
  ).join("");
  return encoder.encode(
    `<PublicAccessBlockConfiguration xmlns="${S3_NS}">${body}</PublicAccessBlockConfiguration>`,
  );
}

/** Writes all four PAB flags and verifies the re-read matches exactly. */
export async function writePab(
  ctx: S3Context,
  pab: Pab,
  phase = "pab-set",
): Promise<void> {
  const body = renderPab(pab);
  const res = await send(ctx, {
    method: "PUT",
    path: `/${ctx.bucket}`,
    query: { publicAccessBlock: "" },
    headers: {
      "content-type": "application/xml",
      "content-md5": md5Base64(body),
    },
    body,
    signed: true,
  });
  if (res.kind !== "answered" || res.status !== 200) {
    fail(phase, "the Public Access Block write was not accepted", {
      status: statusOf(res),
    });
  }
  const after = await readPab(ctx);
  if (
    after === null ||
    PAB_FLAGS.some(([key]) => after[key] !== pab[key])
  ) {
    fail(phase, "the Public Access Block did not converge");
  }
}

// ---------------------------------------------------------------------------
// Versioning
// ---------------------------------------------------------------------------

/** The three versioning states. */
export type Versioning = "Enabled" | "Suspended" | "never-configured";

/** Parses a `VersioningConfiguration` document into one of the three states. */
export function parseVersioning(xml: string, phase = "parse"): Versioning {
  let root: XmlElement;
  try {
    root = parseS3Xml(xml);
  } catch {
    fail(phase, "the versioning document could not be parsed", {});
  }
  if (root.local !== "VersioningConfiguration") {
    fail(phase, "the versioning document has the wrong root", {});
  }
  const status = childText(root, "Status");
  if (status === "") return "never-configured";
  if (status === "Enabled" || status === "Suspended") return status;
  fail(phase, "the versioning status is not recognised", {});
}

/** Reads versioning (the read must answer 200). */
export async function readVersioning(ctx: S3Context): Promise<Versioning> {
  const res = await send(ctx, {
    method: "GET",
    path: `/${ctx.bucket}`,
    query: { versioning: "" },
    signed: true,
  });
  if (res.kind !== "answered" || res.status !== 200) {
    fail("read", "the versioning state could not be read", {
      status: statusOf(res),
    });
  }
  return parseVersioning(res.body);
}

// ---------------------------------------------------------------------------
// Policy: structural validation, canonical form, owner-lockout
// ---------------------------------------------------------------------------

type JsonValue =
  | null
  | boolean
  | number
  | string
  | JsonValue[]
  | { [key: string]: JsonValue };

/** A policy statement normalised for canonical comparison. */
export interface NormalisedStatement {
  /** Sorted statement object with normalised list/principal fields. */
  statement: Record<string, JsonValue>;
  /** Raw statement, for the owner-lockout walk. */
  raw: Record<string, JsonValue>;
}

/** The structural analysis of a policy document. */
export interface PolicyAnalysis {
  /** Canonical JSON string used for equality. */
  canonical: string;
  /** Number of statements. */
  statementCount: number;
  /** Some Deny gates on `aws:SecureTransport` false. */
  declaresSecureTransport: boolean;
  /** Normalised statements. */
  statements: NormalisedStatement[];
}

function isObject(v: JsonValue | undefined): v is { [k: string]: JsonValue } {
  return v !== null && typeof v === "object" && !Array.isArray(v);
}

function stringList(v: JsonValue | undefined): string[] | null {
  if (typeof v === "string") return [v];
  if (Array.isArray(v) && v.every((x) => typeof x === "string")) {
    return v as string[];
  }
  return null;
}

function principalNames(v: JsonValue | undefined): string[] | null {
  if (typeof v === "string") return [v];
  if (Array.isArray(v)) {
    const out: string[] = [];
    for (const item of v) {
      if (typeof item !== "string") return null;
      out.push(item);
    }
    return out;
  }
  if (isObject(v)) {
    if (v.AWS === undefined) return null;
    return stringList(v.AWS);
  }
  return null;
}

function isStar(names: string[]): boolean {
  return names.includes("*");
}

function normalisePrincipal(
  v: JsonValue | undefined,
): Record<string, JsonValue> | null {
  if (typeof v === "string") return { AWS: [v] };
  if (isObject(v)) {
    const out: Record<string, JsonValue> = {};
    for (const [k, value] of Object.entries(v)) {
      const names = stringList(value);
      if (names === null) return null;
      out[k] = [...names].sort();
    }
    return out;
  }
  return null;
}

function conditionList(v: JsonValue): string[] | null {
  if (typeof v === "string") return [v];
  if (typeof v === "boolean" || typeof v === "number") return [String(v)];
  if (
    Array.isArray(v) &&
    v.every((x) =>
      typeof x === "string" || typeof x === "boolean" || typeof x === "number"
    )
  ) {
    return (v as (string | boolean | number)[]).map(String);
  }
  return null;
}

function canonicaliseCondition(
  v: JsonValue | undefined,
): Record<string, JsonValue> | null {
  if (!isObject(v)) return null;
  const out: Record<string, JsonValue> = {};
  for (const [op, operands] of Object.entries(v)) {
    if (!isObject(operands)) return null;
    const inner: Record<string, JsonValue> = {};
    for (const [key, value] of Object.entries(operands)) {
      const names = conditionList(value);
      if (names === null) return null;
      inner[key] = [...names].sort();
    }
    out[op] = inner;
  }
  return out;
}

/** Canonical JSON with every object key sorted recursively. */
function canonicalJson(value: JsonValue): string {
  if (Array.isArray(value)) {
    return `[${value.map(canonicalJson).join(",")}]`;
  }
  if (isObject(value)) {
    return `{${
      Object.keys(value).sort().map((k) =>
        `${JSON.stringify(k)}:${canonicalJson(value[k])}`
      )
        .join(",")
    }}`;
  }
  return JSON.stringify(value);
}

const MANAGEMENT_ACTIONS = [
  "s3:GetBucketPolicy",
  "s3:PutBucketPolicy",
  "s3:DeleteBucketPolicy",
] as const;

/** Analyses a policy document: validates it and returns its canonical form. */
export function analysePolicy(
  text: string,
  bucket: string,
  mode: "validate" | "canonical" = "validate",
): PolicyAnalysis {
  let parsed: JsonValue;
  try {
    parsed = JSON.parse(text) as JsonValue;
  } catch {
    fail("validate", "the policy document is not JSON", {});
  }
  if (!isObject(parsed)) {
    fail("validate", "the policy document is not an object");
  }
  const version = parsed.Version;
  if (typeof version !== "string" || version === "") {
    fail("validate", "the policy document has no Version", {});
  }
  const rawStatements = parsed.Statement;
  let statementList: JsonValue[];
  if (isObject(rawStatements)) statementList = [rawStatements];
  else if (Array.isArray(rawStatements)) statementList = rawStatements;
  else fail("validate", "the policy document has no Statement");
  if (statementList.length === 0) {
    fail("validate", "the policy document has an empty Statement");
  }
  const bucketArn = `arn:aws:s3:::${bucket}`;
  const statements: NormalisedStatement[] = [];
  let declaresSecureTransport = false;
  for (const rawStatement of statementList) {
    if (!isObject(rawStatement)) {
      fail("validate", "a policy statement is not an object", {});
    }
    const effect = rawStatement.Effect;
    if (effect !== "Allow" && effect !== "Deny") {
      fail("validate", "a policy statement has an invalid Effect", {});
    }
    const allow = effect === "Allow";
    if (mode === "validate" && allow) {
      if (rawStatement.NotPrincipal !== undefined) {
        fail("public-allow", "an Allow uses NotPrincipal", {});
      }
      if (rawStatement.Principal === undefined) {
        fail("public-allow", "an Allow has no Principal");
      }
      const names = principalNames(rawStatement.Principal);
      if (names === null || names.length === 0 || isStar(names)) {
        fail("public-allow", "an Allow has a public or malformed Principal");
      }
      if (rawStatement.NotResource !== undefined) {
        fail("public-allow", "an Allow uses NotResource", {});
      }
      if (rawStatement.Resource === undefined) {
        fail("public-allow", "an Allow has no Resource");
      }
    }
    if (mode === "validate") {
      for (const key of ["Resource", "NotResource"] as const) {
        if (rawStatement[key] === undefined) continue;
        const resources = stringList(rawStatement[key]);
        if (resources === null) {
          fail("validate", `a policy statement has a malformed ${key}`);
        }
        for (const arn of resources) {
          if (arn !== bucketArn && !arn.startsWith(`${bucketArn}/`)) {
            fail("validate", "a policy Resource points at another bucket", {});
          }
        }
      }
    }
    // Normalise for canonical comparison.
    const normalised: Record<string, JsonValue> = {};
    for (const [key, value] of Object.entries(rawStatement)) {
      if (
        key === "Action" || key === "NotAction" || key === "Resource" ||
        key === "NotResource"
      ) {
        const list = stringList(value);
        if (list === null) {
          fail("validate", `a policy statement has a malformed ${key}`);
        }
        normalised[key] = [...list].sort();
      } else if (key === "Principal" || key === "NotPrincipal") {
        const principal = normalisePrincipal(value);
        if (principal === null) {
          fail("validate", `a policy statement has a malformed ${key}`);
        }
        normalised[key] = principal;
      } else if (key === "Condition") {
        const condition = canonicaliseCondition(value);
        if (condition === null) {
          fail("validate", "a policy statement has a malformed Condition");
        }
        normalised[key] = condition;
      } else {
        normalised[key] = value;
      }
    }
    if (effect === "Deny") {
      const condition = rawStatement.Condition;
      if (isObject(condition) && isObject(condition.Bool)) {
        const secure = condition.Bool["aws:SecureTransport"];
        const names = stringList(secure);
        if (names !== null && names.some((v) => v === "false")) {
          declaresSecureTransport = true;
        }
      }
    }
    statements.push({ statement: normalised, raw: rawStatement });
  }
  statements.sort((a, b) =>
    canonicalJson(a.statement) < canonicalJson(b.statement) ? -1 : 1
  );
  return {
    canonical: `[${
      statements.map((s) => canonicalJson(s.statement)).join(",")
    }]`,
    statementCount: statements.length,
    declaresSecureTransport,
    statements,
  };
}

function globMatches(glob: string, value: string): boolean {
  const pattern = glob.replace(/[.+^${}()|[\]\\]/g, "\\$&")
    .replace(/\*/g, ".*")
    .replace(/\?/g, ".");
  return new RegExp(`^${pattern}$`, "i").test(value);
}

function statementCoversBucket(
  raw: Record<string, JsonValue>,
  bucketArn: string,
): boolean {
  const resources = stringList(raw.Resource);
  if (resources !== null) {
    return resources.some((r) => globMatches(r, bucketArn));
  }
  const notResources = stringList(raw.NotResource);
  if (notResources !== null) {
    return !notResources.some((r) => globMatches(r, bucketArn));
  }
  return false;
}

function statementTargetsOwner(
  raw: Record<string, JsonValue>,
  ownerId: string,
  tenant: string,
  uid: string,
): boolean {
  const principal = principalNames(raw.Principal);
  if (principal !== null) {
    if (isStar(principal)) return true;
    if (principal.includes(ownerId)) return true;
    return principal.includes(`arn:aws:iam::${tenant}:user/${uid}`);
  }
  const notPrincipal = principalNames(raw.NotPrincipal);
  if (notPrincipal !== null) {
    if (isStar(notPrincipal)) return false;
    if (notPrincipal.includes(ownerId)) return false;
    return !notPrincipal.includes(`arn:aws:iam::${tenant}:user/${uid}`);
  }
  return false;
}

/**
 * True when a Deny's Condition can never change the outcome: no Condition at
 * all, or a Bool `aws:SecureTransport` that matches both true and false (so it
 * applies on every request and equally locks the owner out).
 */
function conditionAlwaysApplies(condition: JsonValue | undefined): boolean {
  if (condition === undefined) return true;
  if (!isObject(condition)) return false;
  const operators = Object.keys(condition);
  if (operators.length !== 1 || operators[0] !== "Bool") return false;
  const bool = condition.Bool;
  if (!isObject(bool)) return false;
  const keys = Object.keys(bool);
  if (keys.length !== 1 || keys[0] !== "aws:SecureTransport") return false;
  const values = conditionList(bool["aws:SecureTransport"]);
  if (values === null) return false;
  const lowered = new Set(values.map((v) => v.toLowerCase()));
  return lowered.has("true") && lowered.has("false");
}

/**
 * Returns the management actions an unconditional Deny would take from the
 * owner. A non-empty result means the policy locks its own owner out.
 */
export function ownerLockout(
  statements: NormalisedStatement[],
  ownerId: string,
  bucket: string,
): string[] {
  const at = ownerId.indexOf("$");
  const tenant = at >= 0 ? ownerId.slice(0, at) : "";
  const uid = at >= 0 ? ownerId.slice(at + 1) : ownerId;
  const bucketArn = `arn:aws:s3:::${bucket}`;
  const denied = new Set<string>();
  for (const { raw } of statements) {
    if (raw.Effect !== "Deny") continue;
    if (!conditionAlwaysApplies(raw.Condition)) continue;
    if (!statementCoversBucket(raw, bucketArn)) continue;
    if (!statementTargetsOwner(raw, ownerId, tenant, uid)) continue;
    const actions = stringList(raw.Action);
    const notActions = stringList(raw.NotAction);
    for (const action of MANAGEMENT_ACTIONS) {
      const matchesAction = actions !== null &&
        actions.some((g) => globMatches(g, action));
      const excludedByNotAction = notActions === null ||
        !notActions.some((g) => globMatches(g, action));
      if (matchesAction || excludedByNotAction) denied.add(action);
    }
  }
  return [...denied];
}

// ---------------------------------------------------------------------------
// Shared probes (anonymous list, object-leak)
// ---------------------------------------------------------------------------

/** The fixed, non-configurable probe prefix. */
export const PROBE_PREFIX = ".cephadm-pab-probe/";

const PROBE_BODY = encoder.encode(
  "cephadm public-access-block probe object; safe to delete at any time.\n",
);

/** Runs the signed-control / unsigned anonymous list probe. */
async function listProbe(
  ctx: S3Context,
): Promise<{ controlStatus: number; anonymousStatus: number }> {
  const query = { "list-type": "2", "max-keys": "0" };
  const control = await send(ctx, {
    method: "GET",
    path: `/${ctx.bucket}`,
    query,
    signed: true,
  });
  if (control.kind !== "answered" || control.status !== 200) {
    fail("control", "the owner's signed list was not answered 200", {
      status: statusOf(control),
    });
  }
  const anon = await send(ctx, {
    method: "GET",
    path: `/${ctx.bucket}`,
    query,
    signed: false,
  });
  if (anon.kind === "answered" && anon.status >= 200 && anon.status < 300) {
    fail("anonymous-allowed", "an unsigned list served the bucket");
  }
  if (anon.kind === "answered" && anon.status === 403) {
    return { controlStatus: control.status, anonymousStatus: anon.status };
  }
  fail("anonymous-inconclusive", "the unsigned list proved nothing", {
    status: statusOf(anon),
  });
}

/** Object-leak probe evidence. */
export interface LeakProbe {
  /** Canned PutObject status. */
  objectAclStatus: number;
  /** Anonymous canned GET status. */
  anonymousObjectStatus: number;
  /** Grant-header PutObject status. */
  grantHeaderPutStatus: number;
  /** Anonymous grant GET status, 0 when not attempted. */
  grantHeaderAnonymousStatus: number;
  /** Canned probe key. */
  cannedKey: string;
  /** Writer (owner id). */
  writer: string;
}

function probeStem(now: number): string {
  return `${PROBE_PREFIX}${now}`;
}

async function putProbeObject(
  ctx: S3Context,
  key: string,
  extraHeaders: Record<string, string>,
): Promise<Outcome> {
  return await send(ctx, {
    method: "PUT",
    path: `/${ctx.bucket}/${key}`,
    headers: { "content-type": "text/plain", ...extraHeaders },
    body: PROBE_BODY,
    signed: true,
  });
}

/** Sets `public-read` on an object with PutObjectAcl (`PUT ?acl`), no body. */
async function putProbeAcl(
  ctx: S3Context,
  key: string,
): Promise<Outcome> {
  return await send(ctx, {
    method: "PUT",
    path: `/${ctx.bucket}/${key}`,
    query: { acl: "" },
    headers: { "x-amz-acl": "public-read" },
    signed: true,
  });
}

/** Lists every object version stored under `key`, or null when unreadable. */
async function listObjectVersions(
  ctx: S3Context,
  key: string,
): Promise<string[] | null> {
  const res = await send(ctx, {
    method: "GET",
    path: `/${ctx.bucket}`,
    query: { versions: "", prefix: key },
    signed: true,
  });
  if (res.kind !== "answered" || res.status !== 200) return null;
  try {
    const root = parseS3Xml(res.body);
    const entries = [
      ...childrenOf(root, "Version"),
      ...childrenOf(root, "DeleteMarker"),
    ];
    return entries
      .filter((entry) => childText(entry, "Key") === key)
      .map((entry) => childText(entry, "VersionId"))
      .filter((version) => version !== "");
  } catch {
    return null;
  }
}

async function deleteProbeObject(
  ctx: S3Context,
  key: string,
  versionId: string,
): Promise<boolean> {
  const query: Record<string, string> = {};
  if (versionId !== "") query["versionId"] = versionId;
  const res = await send(ctx, {
    method: "DELETE",
    path: `/${ctx.bucket}/${key}`,
    query,
    signed: true,
  });
  return res.kind === "answered" && res.status >= 200 && res.status < 300;
}

/**
 * Deletes every version of a probe object, so a retried or versioned PutObject
 * cannot leave a public version behind. Falls back to the PutObject version id
 * (or the key itself) when the version listing is unreadable.
 */
async function cleanupProbeObject(
  ctx: S3Context,
  key: string,
  putVersionId: string,
): Promise<boolean> {
  const versions = await listObjectVersions(ctx, key);
  if (versions !== null && versions.length > 0) {
    let ok = true;
    for (const version of versions) {
      const id = version === "null" ? "" : version;
      if (!await deleteProbeObject(ctx, key, id)) ok = false;
    }
    return ok;
  }
  return await deleteProbeObject(ctx, key, putVersionId);
}

async function anonymousGet(ctx: S3Context, key: string): Promise<number> {
  const res = await send(ctx, {
    method: "GET",
    path: `/${ctx.bucket}/${key}`,
    signed: false,
  });
  return statusOf(res);
}

/**
 * Runs the object-leak probe under the fixed prefix. Throws
 * `object-leak-probe` when the probe could not run, `object-leak-cleanup` when
 * a probe object could not be removed, `object-leak` when a leak is detected,
 * and `object-leak-inconclusive` when the anonymous answers prove nothing.
 */
async function objectLeakProbe(
  ctx: S3Context,
  writer: string,
): Promise<LeakProbe> {
  const stem = probeStem(ctx.deps.now());
  const cannedKey = `${stem}-canned`;
  const grantKey = `${stem}-grant`;
  const canned = await putProbeObject(ctx, cannedKey, {});
  if (canned.kind !== "answered" || canned.status !== 200) {
    fail(
      "object-leak-probe",
      "the object-leak probe could not run; no leak is claimed",
      { status: statusOf(canned) },
    );
  }
  const cannedVersion = canned.headers["x-amz-version-id"] ?? "";
  // The public-read step is PutObjectAcl (?acl), never a second PutObject: a
  // second PutObject on a versioned bucket would leave an undeleted version.
  const acl = await putProbeAcl(ctx, cannedKey);
  const objectAclStatus = statusOf(acl);
  const anonymousObjectStatus = await anonymousGet(ctx, cannedKey);
  let storedGrant = false;
  let grantVersion = "";
  let grantHeaderPutStatus = 0;
  let grantHeaderAnonymousStatus = 0;
  const grant = await putProbeObject(ctx, grantKey, {
    "x-amz-grant-read": 'uri="http://acs.amazonaws.com/groups/global/AllUsers"',
  });
  grantHeaderPutStatus = statusOf(grant);
  if (
    grant.kind === "answered" && grant.status >= 200 && grant.status < 300
  ) {
    storedGrant = true;
    grantVersion = grant.headers["x-amz-version-id"] ?? "";
    grantHeaderAnonymousStatus = await anonymousGet(ctx, grantKey);
  }
  // Cleanup always runs, by version id when one was returned.
  const leftBehind: string[] = [];
  if (!await cleanupProbeObject(ctx, cannedKey, cannedVersion)) {
    leftBehind.push(cannedKey);
  }
  if (storedGrant && !await cleanupProbeObject(ctx, grantKey, grantVersion)) {
    leftBehind.push(grantKey);
  }
  if (leftBehind.length > 0) {
    fail(
      "object-leak-cleanup",
      "probe objects could not be deleted; remove them by hand",
      { keys: leftBehind.join(",") },
    );
  }
  if (anonymousObjectStatus >= 200 && anonymousObjectStatus < 300) {
    fail("object-leak", "the canned probe object leaked (public-read ACL)", {
      status: anonymousObjectStatus,
    });
  }
  if (
    grantHeaderAnonymousStatus >= 200 && grantHeaderAnonymousStatus < 300
  ) {
    fail(
      "object-leak",
      "the probe object leaked through x-amz-grant-read; IgnorePublicAcls did not hold",
      { status: grantHeaderAnonymousStatus },
    );
  }
  if (anonymousObjectStatus !== 403) {
    fail("object-leak-inconclusive", "the canned probe GET proved nothing", {
      status: anonymousObjectStatus,
    });
  }
  if (
    grantHeaderAnonymousStatus !== 403 && grantHeaderAnonymousStatus !== 0
  ) {
    fail("object-leak-inconclusive", "the grant probe GET proved nothing", {
      status: grantHeaderAnonymousStatus,
    });
  }
  return {
    objectAclStatus,
    anonymousObjectStatus,
    grantHeaderPutStatus,
    grantHeaderAnonymousStatus,
    cannedKey,
    writer,
  };
}

// ---------------------------------------------------------------------------
// The four RGW S3-plane methods
// ---------------------------------------------------------------------------

/** The common S3-plane arguments. */
export interface S3Args {
  /** RGW S3 endpoint, https origin only. */
  endpoint: string;
  /** Zonegroup api name. */
  region: string;
  /** Bucket name. */
  bucket: string;
  /** Owner's access key id (sensitive). */
  accessKey: string;
  /** Owner's secret; used only to sign (sensitive). */
  secretKey: string;
  /** Timeout per request in milliseconds. */
  requestTimeoutMs: number;
}

/** Validates the common arguments into a request context. */
function prepare(
  deps: { fetch: FetchFn; now: () => number },
  args: S3Args,
): S3Context {
  const origin = validateCommon(args);
  return {
    deps,
    origin,
    region: args.region,
    bucket: args.bucket,
    accessKey: args.accessKey,
    secretKey: args.secretKey,
    timeoutMs: args.requestTimeoutMs,
  };
}

function xmlEscape(value: string): string {
  return value.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(
    />/g,
    "&gt;",
  ).replace(/"/g, "&quot;").replace(/'/g, "&apos;");
}

/** Reads a bucket policy as raw text, "" when none. */
async function readPolicyRaw(ctx: S3Context): Promise<string> {
  const res = await send(ctx, {
    method: "GET",
    path: `/${ctx.bucket}`,
    query: { policy: "" },
    signed: true,
  });
  if (res.kind !== "answered") {
    fail("read", "the bucket policy could not be read", {});
  }
  if (res.status === 404) {
    const code = s3ErrorCode(res.body);
    if (code === "NoSuchBucketPolicy") return "";
    fail("read", "the policy read failed", { code });
  }
  if (res.status !== 200) {
    fail("read", "the policy read failed", { status: res.status });
  }
  return res.body;
}

/** Canonicalises a stored policy; a malformed one is a parse failure. */
function canonicaliseStoredPolicy(text: string, bucket: string): string {
  if (text === "") return "";
  try {
    return analysePolicy(text, bucket, "canonical").canonical;
  } catch {
    fail("parse", "the stored policy could not be canonicalised", {});
  }
}

// --- cephRgwBucketInspect --------------------------------------------------

/** One ACL grant as recorded. */
export interface AclGrantRecord {
  /** Grantee type. */
  granteeType: string;
  /** Grantee identity. */
  grantee: string;
  /** Permission. */
  permission: string;
}

/** The `cephRgwBucketInspect` record. */
export interface InspectRecord {
  /** Method name. */
  method: string;
  /** Normalised origin. */
  endpoint: string;
  /** Region. */
  region: string;
  /** Bucket. */
  bucket: string;
  /** Presence class. */
  presence: Presence;
  /** Owner id, "" unless owned. */
  ownerId: string;
  /** Grants, empty unless owned. */
  aclGrants: AclGrantRecord[];
  /** True when the ACL is exactly the owner's FULL_CONTROL. */
  aclPrivate: boolean;
  /** Whether a policy is present. */
  hasPolicy: boolean;
  /** Policy text verbatim, "" when none. */
  policy: string;
  /** Canonical policy, "" when none. */
  policyCanonical: string;
  /** Versioning state, "" when not owned. */
  versioning: string;
  /** Public Access Block, or null. */
  publicAccessBlock: Pab | null;
  /** True only when all four flags are set. */
  publicAccessBlockFull: boolean;
}

/** Records what one bucket is, as seen by the supplied credentials. */
export async function bucketInspect(
  deps: { fetch: FetchFn; now: () => number },
  args: S3Args,
): Promise<InspectRecord> {
  const ctx = prepare(deps, args);
  const { presence, code } = await classifyPresence(ctx);
  if (presence === "unreadable") {
    fail("read", "the bucket presence could not be read", {});
  }
  const record: InspectRecord = {
    method: "cephRgwBucketInspect",
    endpoint: ctx.origin,
    region: ctx.region,
    bucket: ctx.bucket,
    presence,
    ownerId: "",
    aclGrants: [],
    aclPrivate: false,
    hasPolicy: false,
    policy: "",
    policyCanonical: "",
    versioning: "",
    publicAccessBlock: null,
    publicAccessBlockFull: false,
  };
  if (presence !== "owned") {
    void code;
    return record;
  }
  record.publicAccessBlock = await readPab(ctx);
  record.publicAccessBlockFull = record.publicAccessBlock !== null &&
    isFullPab(record.publicAccessBlock);
  const acl = await readAcl(ctx);
  record.ownerId = acl.ownerId;
  record.aclGrants = acl.grants;
  record.aclPrivate = isPrivateAcl(acl);
  const policy = await readPolicyRaw(ctx);
  record.hasPolicy = policy !== "";
  record.policy = policy;
  record.policyCanonical = canonicaliseStoredPolicy(policy, ctx.bucket);
  record.versioning = await readVersioning(ctx);
  return record;
}

// --- cephRgwBucketEnsure ---------------------------------------------------

/** Arguments for `cephRgwBucketEnsure`. */
export interface EnsureArgs extends S3Args {
  /** Placement id in the zonegroup. */
  placementTarget: string;
  /** True skips the object-leak probe. */
  skipObjectLeakProbe?: boolean | null;
}

/** The `cephRgwBucketEnsure` record. */
export interface EnsureRecord {
  /** Method name. */
  method: string;
  /** Normalised origin. */
  endpoint: string;
  /** Region. */
  region: string;
  /** Bucket. */
  bucket: string;
  /** Requested `<region>:<placementTarget>`; not proven. */
  placementRequested: string;
  /** Whether the bucket existed before this run. */
  existedBefore: boolean;
  /** True only on a 200 create. */
  created: boolean;
  /** Owner id from the final ACL. */
  ownerId: string;
  /** Grants before the ACL convergence. */
  aclGrantsBefore: AclGrantRecord[];
  /** Grants after the ACL convergence. */
  aclGrantsAfter: AclGrantRecord[];
  /** Whether the ACL changed. */
  aclChanged: boolean;
  /** True when the final ACL is private. */
  aclPrivate: boolean;
  /** PAB before, or null. */
  pabBefore: Pab | null;
  /** PAB after, always all four true. */
  pabAfter: Pab;
  /** Whether the PAB changed. */
  pabChanged: boolean;
  /** `refused` or `skipped`. */
  objectLeakProbe: string;
  /** Probe writer owner id, "" when skipped. */
  objectLeakProbeWriter: string;
  /** Canned probe key, "" when skipped. */
  objectLeakProbeKey: string;
  /** Canned PutObjectAcl status. */
  objectAclStatus: number;
  /** Anonymous canned GET status. */
  anonymousObjectStatus: number;
  /** Grant-header PutObject status. */
  grantHeaderPutStatus: number;
  /** Anonymous grant GET status. */
  grantHeaderAnonymousStatus: number;
  /** Signed list status (200). */
  controlStatus: number;
  /** Unsigned list status (403). */
  anonymousStatus: number;
}

/** Ensures the bucket exists, is private and fully blocked, and proves it. */
export async function bucketEnsure(
  deps: { fetch: FetchFn; now: () => number },
  args: EnsureArgs,
  log?: S3Logger,
): Promise<EnsureRecord> {
  const ctx = prepare(deps, args);
  if (!isRegion(args.placementTarget)) {
    fail("validate", "the placement target is not valid", {});
  }
  const skip = args.skipObjectLeakProbe === true;
  const placementRequested = `${ctx.region}:${args.placementTarget}`;
  const { presence, code } = await classifyPresence(ctx);
  if (presence !== "owned" && presence !== "absent") {
    refusePresence(presence, code);
  }
  const existedBefore = presence === "owned";
  let created = false;
  if (presence === "absent") {
    const body = encoder.encode(
      `<CreateBucketConfiguration xmlns="${S3_NS}"><LocationConstraint>${
        xmlEscape(placementRequested)
      }</LocationConstraint></CreateBucketConfiguration>`,
    );
    const res = await send(ctx, {
      method: "PUT",
      path: `/${ctx.bucket}`,
      headers: { "content-type": "application/xml", "x-amz-acl": "private" },
      body,
      signed: true,
    });
    if (res.kind !== "answered") {
      fail("create", "the bucket create was not answered", {});
    }
    const code2 = s3ErrorCode(res.body);
    if (res.status === 200) created = true;
    else if (res.status === 409 && code2 === "BucketAlreadyOwnedByYou") {
      created = false;
    } else if (code2 === "InvalidLocationConstraint") {
      fail(
        "placement",
        "the placement target is not available in this zonegroup",
        {},
      );
    } else {
      fail("create", "the bucket could not be created", {
        status: res.status,
        code: code2 || undefined,
      });
    }
    const re = await classifyPresence(ctx);
    if (re.presence !== "owned") {
      fail("create-verify", "the bucket was not owned after create", {
        presence: re.presence,
      });
    }
  }
  const aclBefore = await readAcl(ctx);
  let aclAfter = aclBefore;
  let aclChanged = false;
  if (!isPrivateAcl(aclBefore)) {
    const put = await send(ctx, {
      method: "PUT",
      path: `/${ctx.bucket}`,
      query: { acl: "" },
      headers: { "x-amz-acl": "private" },
      signed: true,
    });
    if (put.kind !== "answered" || put.status !== 200) {
      fail("acl-set", "the private ACL write was not accepted", {
        status: statusOf(put),
      });
    }
    aclAfter = await readAcl(ctx);
    if (!isPrivateAcl(aclAfter)) {
      fail("acl-verify", "the ACL is not private after the write", {});
    }
    aclChanged = true;
  }
  const pabBefore = await readPab(ctx);
  let pabAfter: Pab = pabBefore ?? FULL_PAB;
  let pabChanged = false;
  if (pabBefore === null || !isFullPab(pabBefore)) {
    await writePab(ctx, FULL_PAB, "pab-set");
    pabAfter = FULL_PAB;
    pabChanged = true;
  }
  const { controlStatus, anonymousStatus } = await listProbe(ctx);
  let probeOutcome = "skipped";
  let leak = {
    objectAclStatus: 0,
    anonymousObjectStatus: 0,
    grantHeaderPutStatus: 0,
    grantHeaderAnonymousStatus: 0,
    cannedKey: "",
    writer: "",
  };
  if (!skip) {
    leak = await objectLeakProbe(ctx, aclAfter.ownerId);
    probeOutcome = "refused";
  }
  log?.info("RGW bucket {bucket} ensured ({action})", {
    bucket: ctx.bucket,
    action: created ? "created" : "converged",
  });
  return {
    method: "cephRgwBucketEnsure",
    endpoint: ctx.origin,
    region: ctx.region,
    bucket: ctx.bucket,
    placementRequested,
    existedBefore,
    created,
    ownerId: aclAfter.ownerId,
    aclGrantsBefore: aclBefore.grants,
    aclGrantsAfter: aclAfter.grants,
    aclChanged,
    aclPrivate: isPrivateAcl(aclAfter),
    pabBefore,
    pabAfter,
    pabChanged,
    objectLeakProbe: probeOutcome,
    objectLeakProbeWriter: leak.writer,
    objectLeakProbeKey: leak.cannedKey,
    objectAclStatus: leak.objectAclStatus,
    anonymousObjectStatus: leak.anonymousObjectStatus,
    grantHeaderPutStatus: leak.grantHeaderPutStatus,
    grantHeaderAnonymousStatus: leak.grantHeaderAnonymousStatus,
    controlStatus,
    anonymousStatus,
  };
}

// --- cephRgwBucketPolicyEnsure ---------------------------------------------

/** Arguments for `cephRgwBucketPolicyEnsure`. */
export interface PolicyArgs extends S3Args {
  /** Bucket policy JSON text, sent verbatim. */
  policyDocument: string;
  /** Plain-HTTP origin to probe, or null/absent for not-tested. */
  plainHttpEndpoint?: string | null;
}

/** The `cephRgwBucketPolicyEnsure` record. */
export interface PolicyRecord {
  /** Method name. */
  method: string;
  /** Normalised origin. */
  endpoint: string;
  /** Region. */
  region: string;
  /** Bucket. */
  bucket: string;
  /** Whether a policy existed before. */
  hadPolicyBefore: boolean;
  /** Whether the stored policy differs from the desired one. */
  changed: boolean;
  /** Statement count. */
  statementCount: number;
  /** Some Deny gates on `aws:SecureTransport` false. */
  declaresSecureTransport: boolean;
  /** Desired canonical JSON. */
  canonicalPolicy: string;
  /** Signed list status. */
  controlStatus: number;
  /** Unsigned list status. */
  anonymousStatus: number;
  /** Whether the PAB was lifted for the write. */
  pabLiftedForWrite: boolean;
  /** `not-tested`, `denied`, `no-listener` or `served`. */
  plainHttp: string;
  /** Plain-HTTP status, 0 unless answered. */
  plainHttpStatus: number;
}

/** Writes one policy state: DELETE when removing, otherwise PUT the text. */
async function applyPolicyState(
  ctx: S3Context,
  text: string,
): Promise<boolean> {
  if (text === "") {
    const res = await send(ctx, {
      method: "DELETE",
      path: `/${ctx.bucket}`,
      query: { policy: "" },
      signed: true,
    });
    return res.kind === "answered" &&
      (res.status === 200 || res.status === 204);
  }
  const res = await send(ctx, {
    method: "PUT",
    path: `/${ctx.bucket}`,
    query: { policy: "" },
    headers: { "content-type": "application/json" },
    body: encoder.encode(text),
    signed: true,
  });
  return res.kind === "answered" &&
    (res.status === 200 || res.status === 204);
}

/** Applies a bucket policy and proves its effect, with rollback. */
export async function bucketPolicyEnsure(
  deps: { fetch: FetchFn; now: () => number },
  args: PolicyArgs,
  log?: S3Logger,
): Promise<PolicyRecord> {
  const ctx = prepare(deps, args);
  if (args.policyDocument.length < 2) {
    fail("validate", "the policy document is too short", {});
  }
  if (encoder.encode(args.policyDocument).length > 20480) {
    fail("validate", "the policy document is too large", {});
  }
  const analysis = analysePolicy(args.policyDocument, ctx.bucket);
  let plainHttpOrigin = "";
  if (args.plainHttpEndpoint !== undefined && args.plainHttpEndpoint !== null) {
    plainHttpOrigin = normaliseEndpoint(args.plainHttpEndpoint, "http");
  }
  await requireOwned(ctx);
  const acl = await readAcl(ctx);
  const lockout = ownerLockout(analysis.statements, acl.ownerId, ctx.bucket);
  if (lockout.length > 0) {
    fail(
      "self-lockout",
      "the policy would deny the owner its own policy management",
      { actions: lockout.join(",") },
    );
  }
  const previous = await readPolicyRaw(ctx);
  const hadPolicyBefore = previous !== "";
  const beforeCanonical = canonicaliseStoredPolicy(previous, ctx.bucket);
  const changed = beforeCanonical !== analysis.canonical;
  let pabLiftedForWrite = false;
  let originalPab: Pab | null = null;
  if (changed) {
    const pab = await readPab(ctx);
    if (pab !== null && pab.blockPublicPolicy) {
      originalPab = pab;
      try {
        await writePab(ctx, { ...pab, blockPublicPolicy: false }, "pab-lift");
        pabLiftedForWrite = true;
      } catch {
        // The lift PUT may have landed even though its read-back failed, so
        // put the original block back and report whether that succeeded.
        let restored = false;
        try {
          await writePab(ctx, originalPab, "pab-restore");
          restored = true;
        } catch {
          restored = false;
        }
        fail(
          "pab-lift",
          restored
            ? "the Public Access Block lift failed but the original block was restored"
            : "the Public Access Block lift failed and the original block could NOT be restored",
        );
      }
    }
  }
  let wrote = false;
  let controlStatus = 0;
  let anonymousStatus = 0;
  let blockFailure: unknown = null;
  try {
    if (changed) {
      const put = await send(ctx, {
        method: "PUT",
        path: `/${ctx.bucket}`,
        query: { policy: "" },
        headers: { "content-type": "application/json" },
        body: encoder.encode(args.policyDocument),
        signed: true,
      });
      if (put.kind === "answered") {
        if (put.status !== 200 && put.status !== 204) {
          fail("policy-write", "the policy write was not accepted", {
            status: put.status,
          });
        }
        wrote = true;
      } else {
        // Indeterminate: assume it landed until a re-read says otherwise, so
        // the rollback runs if the re-read itself fails.
        wrote = true;
        const after = await readPolicyRaw(ctx);
        if (canonicaliseStoredPolicy(after, ctx.bucket) === beforeCanonical) {
          wrote = false;
          fail("policy-write", "the policy write was not accepted", {
            status: 0,
          });
        }
      }
      const readBack = await readPolicyRaw(ctx);
      if (
        canonicaliseStoredPolicy(readBack, ctx.bucket) !== analysis.canonical
      ) {
        fail(
          "verify",
          "the stored policy does not match the requested one",
          {},
        );
      }
    }
    const probe = await listProbe(ctx);
    controlStatus = probe.controlStatus;
    anonymousStatus = probe.anonymousStatus;
  } catch (e) {
    blockFailure = e;
  }
  let policyOutcome = "";
  if (blockFailure !== null && wrote) {
    const applied = await applyPolicyState(ctx, previous);
    let confirmed = false;
    if (applied) {
      try {
        const back = await readPolicyRaw(ctx);
        confirmed = canonicaliseStoredPolicy(back, ctx.bucket) ===
          beforeCanonical;
      } catch {
        confirmed = false;
      }
    }
    policyOutcome = confirmed
      ? (hadPolicyBefore
        ? "RESTORED; previous policy was put back"
        : "RESTORED")
      : "RESTORE FAILED";
  }
  let pabRestoreFailed = false;
  if (pabLiftedForWrite && originalPab !== null) {
    try {
      await writePab(ctx, originalPab, "pab-restore");
    } catch {
      pabRestoreFailed = true;
    }
  }
  if (blockFailure !== null) {
    const original = blockFailure as { phase?: string; message?: string };
    const suffix = `policy ${policyOutcome || "not written"}; pab ${
      pabRestoreFailed
        ? "PUBLIC ACCESS BLOCK NOT RESTORED"
        : (pabLiftedForWrite ? "RESTORED" : "not lifted")
    }`;
    log?.warn("RGW bucket policy ensure failed; {suffix}", {
      suffix: suffix,
    });
    fail(
      original.phase ?? "policy-write",
      `${original.message ?? "the policy could not be applied"}; ${suffix}`,
    );
  }
  if (pabRestoreFailed) {
    fail("pab-restore", "the Public Access Block was not restored", {});
  }
  let plainHttp = "not-tested";
  let plainHttpStatus = 0;
  if (plainHttpOrigin !== "") {
    const res = await send(ctx, {
      method: "GET",
      origin: plainHttpOrigin,
      path: `/${ctx.bucket}`,
      query: { "list-type": "2", "max-keys": "0" },
      signed: true,
    });
    if (res.kind === "refused") {
      plainHttp = "no-listener";
    } else if (res.kind === "unreachable") {
      fail(
        "plain-http-inconclusive",
        "the plain-HTTP probe proved nothing",
        {},
      );
    } else if (res.status >= 200 && res.status < 300) {
      plainHttp = "served";
      plainHttpStatus = res.status;
      if (analysis.declaresSecureTransport) {
        fail(
          "secure-transport-ignored",
          "the gateway served plain HTTP despite a SecureTransport deny",
          {},
        );
      }
    } else if (res.status === 403) {
      plainHttp = "denied";
      plainHttpStatus = res.status;
    } else {
      fail("plain-http-inconclusive", "the plain-HTTP probe proved nothing", {
        status: res.status,
      });
    }
  }
  log?.info("RGW bucket policy for {bucket}: changed={changed}", {
    bucket: ctx.bucket,
    changed: changed,
  });
  return {
    method: "cephRgwBucketPolicyEnsure",
    endpoint: ctx.origin,
    region: ctx.region,
    bucket: ctx.bucket,
    hadPolicyBefore,
    changed,
    statementCount: analysis.statementCount,
    declaresSecureTransport: analysis.declaresSecureTransport,
    canonicalPolicy: analysis.canonical,
    controlStatus,
    anonymousStatus,
    pabLiftedForWrite,
    plainHttp,
    plainHttpStatus,
  };
}

// --- cephRgwBucketVersioningEnsure -----------------------------------------

/** Arguments for `cephRgwBucketVersioningEnsure`. */
export interface VersioningArgs extends S3Args {
  /** Target state. */
  desired: "Enabled" | "Suspended";
}

/** The `cephRgwBucketVersioningEnsure` record. */
export interface VersioningRecord {
  /** Method name. */
  method: string;
  /** Normalised origin. */
  endpoint: string;
  /** Region. */
  region: string;
  /** Bucket. */
  bucket: string;
  /** State before. */
  before: Versioning;
  /** State after. */
  after: Versioning;
  /** Whether a write was made. */
  changed: boolean;
  /** True when the final state is Enabled. */
  conditionalWritesUnsafe: boolean;
}

/** Converges a bucket's versioning to Enabled or Suspended. */
export async function bucketVersioningEnsure(
  deps: { fetch: FetchFn; now: () => number },
  args: VersioningArgs,
  log?: S3Logger,
): Promise<VersioningRecord> {
  const ctx = prepare(deps, args);
  if (args.desired !== "Enabled" && args.desired !== "Suspended") {
    fail("validate", "the desired versioning state is not valid", {});
  }
  await requireOwned(ctx);
  const before = await readVersioning(ctx);
  let after = before;
  let changed = false;
  if (before !== args.desired) {
    const body = encoder.encode(
      `<VersioningConfiguration xmlns="${S3_NS}"><Status>${args.desired}</Status></VersioningConfiguration>`,
    );
    const res = await send(ctx, {
      method: "PUT",
      path: `/${ctx.bucket}`,
      query: { versioning: "" },
      headers: { "content-type": "application/xml" },
      body,
      signed: true,
    });
    if (res.kind !== "answered" || res.status !== 200) {
      fail("versioning-write", "the versioning write was not accepted", {
        status: statusOf(res),
      });
    }
    after = await readVersioning(ctx);
    if (after !== args.desired) {
      fail("verify", "the versioning state did not converge", {});
    }
    changed = true;
  }
  const conditionalWritesUnsafe = after === "Enabled";
  if (conditionalWritesUnsafe) {
    log?.warn(
      "versioning Enabled on {bucket}: this RGW ignores If-None-Match and rejects If-Match, so conditional writes are unsafe; do not use it as a swamp datastore",
      { bucket: ctx.bucket },
    );
  }
  return {
    method: "cephRgwBucketVersioningEnsure",
    endpoint: ctx.origin,
    region: ctx.region,
    bucket: ctx.bucket,
    before,
    after,
    changed,
    conditionalWritesUnsafe,
  };
}
