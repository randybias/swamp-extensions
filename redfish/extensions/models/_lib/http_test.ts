import { assert, assertEquals, assertRejects } from "jsr:@std/assert@1.0.19";
import {
  b64Utf8,
  classifyFetch,
  defaultDeps,
  drain,
  MAX_BODY_BYTES,
  readBounded,
  RedfishError,
  sha256Hex,
  statusError,
} from "./http.ts";

Deno.test("readBounded returns a body under the cap", async () => {
  const text = await readBounded(new Response('{"a":1}'));
  assertEquals(text, '{"a":1}');
});

Deno.test("readBounded refuses a body over the cap", async () => {
  const big = "x".repeat(MAX_BODY_BYTES + 1);
  const e = await assertRejects(() =>
    readBounded(new Response(big))
  ) as RedfishError;
  assertEquals(e.code, "response_too_large");
});

Deno.test("readBounded on an empty body is an empty string", async () => {
  assertEquals(await readBounded(new Response(null, { status: 204 })), "");
});

Deno.test("classifyFetch maps certificate failures to tls and the rest to unreachable", () => {
  assertEquals(
    classifyFetch(new Error("certificate verify failed")).code,
    "tls",
  );
  assertEquals(
    classifyFetch(new Error("x509: certificate signed by unknown authority"))
      .code,
    "tls",
  );
  const unreachable = classifyFetch(new TypeError("connection refused"));
  assertEquals(unreachable.code, "unreachable");
  assert(!unreachable.message.includes("connection refused"));
});

Deno.test("statusError maps status classes to fixed messages", () => {
  assertEquals(statusError(401).code, "unauthorized");
  assertEquals(statusError(403).code, "unauthorized");
  assertEquals(statusError(404).code, "not_found");
  const failed = statusError(500);
  assertEquals(failed.code, "redfish_failed");
  assertEquals(failed.message, "Redfish request failed (HTTP 500)");
});

Deno.test("b64Utf8 and sha256Hex", async () => {
  assertEquals(b64Utf8("user:pass"), "dXNlcjpwYXNz");
  assertEquals(
    await sha256Hex("abc"),
    "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
  );
});

Deno.test("drain discards a body without throwing", async () => {
  await drain(new Response("ignored"));
  await drain(new Response(null, { status: 204 }));
});

Deno.test("readBounded fails as a timeout when the signal is already aborted", async () => {
  const controller = new AbortController();
  controller.abort();
  const stream = new ReadableStream<Uint8Array>({ start() {} });
  const e = await assertRejects(() =>
    readBounded(new Response(stream), undefined, controller.signal)
  ) as RedfishError;
  assertEquals(e.code, "timeout");
});

Deno.test("classifyFetch maps an abort to a typed timeout", () => {
  assertEquals(
    classifyFetch(new DOMException("x", "TimeoutError")).code,
    "timeout",
  );
  assertEquals(
    classifyFetch(new DOMException("x", "AbortError")).code,
    "timeout",
  );
});

Deno.test("defaultDeps exposes the injectable seams", () => {
  const d = defaultDeps();
  assertEquals(typeof d.fetch, "function");
  assertEquals(typeof d.makeClient, "function");
  assertEquals(typeof d.now, "function");
  assertEquals(typeof d.sleep, "function");
  assertEquals(typeof d.requestTimeoutMs, "number");
});

Deno.test("classifyFetch reads the cause chain: Deno puts the certificate error in cause", () => {
  const wrap = (cause: string) =>
    new TypeError("fetch failed", { cause: new Error(cause) });
  const cases: [string, RegExp][] = [
    ["invalid peer certificate: UnknownIssuer", /not issued by a trusted CA/],
    ["invalid peer certificate: CaUsedAsEndEntity", /CA:FALSE/],
    ["invalid peer certificate: Expired", /expired/],
    ["invalid peer certificate: NotValidForName", /host name or address/],
    ["invalid peer certificate: BadSignature", /could not be verified/],
  ];
  for (const [cause, hint] of cases) {
    const e = classifyFetch(wrap(cause));
    assertEquals(e.code, "tls", cause);
    assertEquals(hint.test(e.message), true, `${cause}: ${e.message}`);
    // Only fixed text: the cause string itself is never echoed.
    assertEquals(e.message.includes("peer certificate"), false);
  }
  // A refused connection (no TLS word anywhere) stays unreachable.
  const refused = classifyFetch(
    new TypeError("fetch failed", {
      cause: new Error("Connection refused (os error 111)"),
    }),
  );
  assertEquals(refused.code, "unreachable");
});
