import {
  assertEquals,
  assertRejects,
  assertStringIncludes,
} from "jsr:@std/assert@1.0.19";
import {
  CherryApiError,
  instanceName,
  listAll,
  request,
  requestExisting,
  resolveToken,
  safeMessage,
  setFetch,
  setSleep,
  summarize,
  TOKEN_ENV,
} from "./cherry.ts";

type Call = { url: string; init?: RequestInit };

/** Installs a scripted fetch; returns the recorded calls and a restore fn. */
function scriptFetch(responses: Response[]) {
  const calls: Call[] = [];
  const previous = setFetch((url, init) => {
    calls.push({ url, init });
    const next = responses.shift();
    if (!next) throw new Error(`unexpected request to ${url}`);
    return Promise.resolve(next);
  });
  const previousSleep = setSleep(() => Promise.resolve());
  return {
    calls,
    restore: () => {
      setFetch(previous);
      setSleep(previousSleep);
    },
  };
}

function json(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

Deno.test("request sends the token only in the Authorization header", async () => {
  const f = scriptFetch([json(200, { id: 1 })]);
  try {
    const result = await request("GET", "/servers/1", { token: "tok-abc" });
    assertEquals(result, { id: 1 });
    const headers = f.calls[0].init?.headers as Record<string, string>;
    assertEquals(headers["Authorization"], "Bearer tok-abc");
    assertEquals(f.calls[0].url.includes("tok-abc"), false);
  } finally {
    f.restore();
  }
});

Deno.test("request returns null on 404", async () => {
  const f = scriptFetch([new Response("gone", { status: 404 })]);
  try {
    assertEquals(await request("GET", "/servers/9", { token: "t" }), null);
  } finally {
    f.restore();
  }
});

Deno.test("requestExisting throws CherryApiError on 404", async () => {
  const f = scriptFetch([new Response("gone", { status: 404 })]);
  try {
    const err = await assertRejects(
      () => requestExisting("GET", "/servers/9", { token: "t" }),
      CherryApiError,
    );
    assertEquals(err.status, 404);
  } finally {
    f.restore();
  }
});

Deno.test("request retries on 429 then succeeds", async () => {
  const f = scriptFetch([
    new Response("slow down", { status: 429 }),
    json(200, { ok: true }),
  ]);
  try {
    assertEquals(await request("GET", "/plans", { token: "t" }), { ok: true });
    assertEquals(f.calls.length, 2);
  } finally {
    f.restore();
  }
});

Deno.test("request raises a trimmed error on 500", async () => {
  const f = scriptFetch([new Response("x".repeat(1000), { status: 500 })]);
  try {
    const err = await assertRejects(
      () => request("POST", "/projects/1/servers", { token: "t", body: {} }),
      CherryApiError,
    );
    assertEquals(err.status, 500);
    assertEquals(err.message.length < 450, true);
  } finally {
    f.restore();
  }
});

Deno.test("anonymous requests carry no Authorization header", async () => {
  const f = scriptFetch([json(200, [])]);
  try {
    await request("GET", "/plans", { anonymous: true });
    const headers = f.calls[0].init?.headers as Record<string, string>;
    assertEquals("Authorization" in headers, false);
  } finally {
    f.restore();
  }
});

Deno.test("resolveToken falls back to the environment, then fails", () => {
  const saved = Deno.env.get(TOKEN_ENV);
  try {
    Deno.env.set(TOKEN_ENV, "env-token");
    assertEquals(resolveToken(), "env-token");
    assertEquals(resolveToken("explicit"), "explicit");
    Deno.env.delete(TOKEN_ENV);
    let message = "";
    try {
      resolveToken();
    } catch (e) {
      message = (e as Error).message;
    }
    assertStringIncludes(message, TOKEN_ENV);
  } finally {
    if (saved === undefined) Deno.env.delete(TOKEN_ENV);
    else Deno.env.set(TOKEN_ENV, saved);
  }
});

Deno.test("listAll pages until a short page", async () => {
  const full = Array.from({ length: 100 }, (_, i) => ({ id: i }));
  const f = scriptFetch([json(200, full), json(200, [{ id: 100 }])]);
  try {
    const items = await listAll("/projects/1/servers", { token: "t" });
    assertEquals(items.length, 101);
    assertStringIncludes(f.calls[1].url, "offset=100");
  } finally {
    f.restore();
  }
});

Deno.test("listAll rejects a non-array body", async () => {
  const f = scriptFetch([json(200, { not: "an array" })]);
  try {
    await assertRejects(
      () => listAll("/projects/1/servers", { token: "t" }),
      CherryApiError,
    );
  } finally {
    f.restore();
  }
});

Deno.test("instanceName strips path separators and traversal", () => {
  assertEquals(instanceName("a/b\\c..d"), "a_b_c_d");
});

Deno.test("listAll fails closed when an endpoint ignores limit/offset", async () => {
  const page = Array.from({ length: 100 }, (_, i) => ({ id: i }));
  const f = scriptFetch([json(200, page), json(200, page)]);
  try {
    await assertRejects(
      () => listAll("/teams/1/projects", { token: "t" }),
      Error,
      "repeated full page",
    );
    assertEquals(f.calls.length, 2);
  } finally {
    f.restore();
  }
});

Deno.test("error messages never echo the response body", async () => {
  const body = JSON.stringify({
    code: 500,
    message: "Internal error",
    request: { user_data: "c2VjcmV0", password: "pw-placeholder" },
  });
  const f = scriptFetch([new Response(body, { status: 500 })]);
  try {
    const err = await assertRejects(
      () =>
        request("POST", "/projects/1/servers", { token: "tok-xyz", body: {} }),
      CherryApiError,
    );
    assertStringIncludes(err.message, "Internal error");
    for (const leak of ["c2VjcmV0", "pw-placeholder", "tok-xyz", "user_data"]) {
      assertEquals(err.message.includes(leak), false);
    }
  } finally {
    f.restore();
  }
});

Deno.test("summarize handles non-JSON bodies without echoing them", () => {
  assertEquals(summarize("<html>secret</html>"), "non-JSON error body");
});

Deno.test("a non-JSON 2xx body raises CherryApiError", async () => {
  const f = scriptFetch([new Response("<html>ok</html>", { status: 200 })]);
  try {
    await assertRejects(
      () => request("GET", "/plans", { token: "t" }),
      CherryApiError,
      "invalid JSON",
    );
  } finally {
    f.restore();
  }
});

Deno.test("every request carries an abort signal", async () => {
  const f = scriptFetch([json(200, {})]);
  try {
    await request("GET", "/plans", { token: "t" });
    assertEquals(f.calls[0].init?.signal instanceof AbortSignal, true);
  } finally {
    f.restore();
  }
});

Deno.test("a timed-out write says it may have been applied", async () => {
  const previous = setFetch(() =>
    Promise.reject(new DOMException("timed out", "TimeoutError"))
  );
  try {
    const err = await assertRejects(
      () => request("POST", "/projects/1/servers", { token: "t", body: {} }),
      CherryApiError,
    );
    assertStringIncludes(err.message, "may still have been applied");
  } finally {
    setFetch(previous);
  }
});

Deno.test("summarize withholds provider messages that could carry secrets", () => {
  const cases: [string, string[]][] = [
    ["Invalid password=synthetic-secret supplied", ["synthetic-secret"]],
    ["bad password: hunter2 for root", ["hunter2"]],
    ['Invalid password: "correct horse battery staple"', ["horse"]],
    ["api-key: hunter2", ["hunter2"]],
    ["Authorization: Bearer abc123", ["abc123"]],
    ["user_data: #cloud-config\nruncmd: [echo secret42]", ["secret42"]],
    ["token ghp_abcdefghijklmnopqrstuvwxyz0123 rejected", ["ghp_"]],
    ["Key AAAAC3NzaC1lZDI1NTE5 is malformed", ["AAAAC3"]],
  ];
  for (const [message, leaks] of cases) {
    const out = summarize(JSON.stringify({ code: 422, message }));
    assertEquals(out, "code 422: message withheld", `for: ${message}`);
    for (const leak of leaks) assertEquals(out.includes(leak), false);
  }
});

Deno.test("summarize keeps short plain-prose provider messages", () => {
  assertEquals(safeMessage("Plan is out of stock"), "Plan is out of stock");
  assertEquals(
    summarize(JSON.stringify({ code: 422, message: "Region not available." })),
    "code 422: Region not available.",
  );
  assertEquals(safeMessage("x".repeat(121)), undefined);
});

Deno.test("summarize drops a code with unsafe characters", () => {
  assertEquals(
    summarize(JSON.stringify({ code: "x\nsecret=1", message: "Not allowed" })),
    "Not allowed",
  );
});

Deno.test("a stalled response body raises CherryApiError", async () => {
  const body = new ReadableStream({
    pull(controller) {
      controller.error(new DOMException("timed out", "TimeoutError"));
    },
  });
  const f = scriptFetch([new Response(body, { status: 200 })]);
  try {
    await assertRejects(
      () => request("GET", "/plans", { token: "t" }),
      CherryApiError,
      "not received",
    );
  } finally {
    f.restore();
  }
});

Deno.test("GET and DELETE retry transient gateway errors; POST does not", async () => {
  for (const method of ["GET", "DELETE"]) {
    const f = scriptFetch([
      new Response("origin down", { status: 521 }),
      new Response("bad gateway", { status: 502 }),
      json(200, { ok: true }),
    ]);
    try {
      assertEquals(await request(method, "/servers/1", { token: "t" }), {
        ok: true,
      });
      assertEquals(f.calls.length, 3);
    } finally {
      f.restore();
    }
  }
  const f = scriptFetch([new Response("origin down", { status: 521 })]);
  try {
    await assertRejects(
      () => request("POST", "/projects/1/servers", { token: "t", body: {} }),
      CherryApiError,
      "521",
    );
    assertEquals(f.calls.length, 1);
  } finally {
    f.restore();
  }
});

Deno.test("a GET with no response is retried, then reported", async () => {
  let n = 0;
  const previous = setFetch(() => {
    n++;
    return Promise.reject(new DOMException("timed out", "TimeoutError"));
  });
  const previousSleep = setSleep(() => Promise.resolve());
  try {
    const err = await assertRejects(
      () => request("GET", "/servers/1", { token: "t" }),
      CherryApiError,
    );
    assertStringIncludes(err.message, "no response within");
    assertEquals(n, 5);
  } finally {
    setFetch(previous);
    setSleep(previousSleep);
  }
});

Deno.test("an order is never resent after a 429", async () => {
  const f = scriptFetch([new Response("slow down", { status: 429 })]);
  try {
    await assertRejects(
      () => request("POST", "/projects/1/servers", { token: "t", body: {} }),
      CherryApiError,
      "429",
    );
    assertEquals(f.calls.length, 1);
  } finally {
    f.restore();
  }
});

Deno.test("summarize drops a provider code that could be a reflected token", () => {
  for (
    const code of [
      "AbC123xyzTOKEN",
      "a1b2c3",
      "Bearer",
      "abcdefghijklmnopqrstuvwx",
    ]
  ) {
    assertEquals(
      summarize(JSON.stringify({ code, message: "Bad request." })),
      "Bad request.",
      code,
    );
  }
  assertEquals(
    summarize(JSON.stringify({ code: 422, message: "Bad request." })),
    "code 422: Bad request.",
  );
});

Deno.test("safeMessage withholds single words and token-length words", () => {
  assertEquals(safeMessage("abcdefghijklmnopqrstuvwx"), undefined);
  assertEquals(safeMessage("Forbidden"), undefined);
  assertEquals(safeMessage("Invalid abcdefghijklmnopqrstuvwx"), undefined);
  assertEquals(safeMessage("Region not available."), "Region not available.");
});
