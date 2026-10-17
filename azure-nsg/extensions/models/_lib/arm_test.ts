import { assert, assertEquals, assertRejects } from "jsr:@std/assert@1.0.19";
import {
  type ArmDeps,
  ArmError,
  createArmClient,
  type FetchFn,
  isNotFound,
  pollUntil,
  redact,
} from "./arm.ts";

const TENANT = "11111111-1111-1111-1111-111111111111";
const CLIENT = "22222222-2222-2222-2222-222222222222";
const SECRET = "PLACEHOLDER-CLIENT-SECRET-MATERIAL";

interface Call {
  url: string;
  method: string;
  body?: string;
  headers: Record<string, string>;
}

/** A scripted fetch that records every call. */
function fakeFetch(
  calls: Call[],
  handler: (call: Call) => Response,
): FetchFn {
  return (input, init) => {
    const call: Call = {
      url: String(input),
      method: init?.method ?? "GET",
      body: typeof init?.body === "string" ? init.body : undefined,
      headers: (init?.headers ?? {}) as Record<string, string>,
    };
    calls.push(call);
    return Promise.resolve(handler(call));
  };
}

/** Deps with an advancing clock. */
function deps(
  fetchFn: FetchFn,
  start = 0,
): { deps: ArmDeps; advance: (ms: number) => void } {
  let t = start;
  return {
    deps: {
      fetch: fetchFn,
      now: () => t,
      sleep: (ms: number) => {
        t += ms;
        return Promise.resolve();
      },
    },
    advance: (ms: number) => {
      t += ms;
    },
  };
}

/** A JSON response. */
function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

function clientFor(
  fetchFn: FetchFn,
  start = 0,
): {
  client: ReturnType<typeof createArmClient>;
  advance: (ms: number) => void;
} {
  const clock = deps(fetchFn, start);
  return {
    client: createArmClient(clock.deps, {
      tenantId: TENANT,
      clientId: CLIENT,
      clientSecret: SECRET,
    }),
    advance: clock.advance,
  };
}

Deno.test("the client secret travels only in the token POST body", async () => {
  const calls: Call[] = [];
  const fetchFn = fakeFetch(
    calls,
    (call) =>
      call.url.includes("/oauth2/v2.0/token")
        ? json({ access_token: "token-value" })
        : json({ id: "/subscriptions/x" }),
  );
  const { client } = clientFor(fetchFn);
  await client.get("/subscriptions/x?api-version=1");

  assertEquals(calls.length, 2);
  const tokenCall = calls[0];
  assertEquals(tokenCall.method, "POST");
  assert(tokenCall.url.includes(TENANT), "token URL carries the tenant");
  assertEquals(tokenCall.url.includes(SECRET), false, "secret in token URL");
  assertEquals(
    JSON.stringify(tokenCall.headers).includes(SECRET),
    false,
    "secret in a header",
  );
  assert(tokenCall.body?.includes(SECRET), "secret must be in the POST body");
  assert(
    tokenCall.body?.includes("grant_type=client_credentials"),
    "client-credentials grant",
  );
  assertEquals(calls[1].method, "GET");
  assertEquals(calls[1].headers.authorization, "Bearer token-value");
});

Deno.test("the access token is fetched once per client", async () => {
  const calls: Call[] = [];
  const fetchFn = fakeFetch(
    calls,
    (call) =>
      call.url.includes("/oauth2/v2.0/token")
        ? json({ access_token: "token-value" })
        : json({ id: "/x" }),
  );
  const { client } = clientFor(fetchFn);
  await client.get("/a");
  await client.get("/b");
  await client.post("/c", { a: 1 });
  assertEquals(
    calls.filter((c) => c.url.includes("/oauth2/v2.0/token")).length,
    1,
  );
});

Deno.test("a 404 is a typed not-found and never leaks the secret", async () => {
  const calls: Call[] = [];
  const fetchFn = fakeFetch(
    calls,
    (call) =>
      call.url.includes("/oauth2/v2.0/token")
        ? json({ access_token: "token-value" })
        : json({ code: "ResourceNotFound", message: `missing ${SECRET}` }, 404),
  );
  const { client } = clientFor(fetchFn);
  const error = await assertRejects(() => client.get("/missing"), ArmError);
  assertEquals(isNotFound(error), true);
  assertEquals(error.status, 404);
  assertEquals(error.message.includes(SECRET), false, "secret leaked");
  assert(error.message.includes("***"), "secret should be redacted");
});

Deno.test("a failed token request is typed and redacts the secret", async () => {
  const calls: Call[] = [];
  const fetchFn = fakeFetch(
    calls,
    () =>
      json(
        { error: "invalid_client", error_description: `bad ${SECRET}` },
        401,
      ),
  );
  const { client } = clientFor(fetchFn);
  const error = await assertRejects(() => client.get("/x"), ArmError);
  assertEquals(error.status, 401);
  assertEquals(error.message.includes(SECRET), false);
});

Deno.test("a token response without access_token is an error", async () => {
  const calls: Call[] = [];
  const fetchFn = fakeFetch(calls, () => json({ token_type: "Bearer" }));
  const { client } = clientFor(fetchFn);
  await assertRejects(() => client.get("/x"), ArmError, "access_token");
});

Deno.test("pollUntil returns a settled value and times out otherwise", async () => {
  const clock = deps(fakeFetch([], () => json({})));
  let attempts = 0;
  const settled = await pollUntil(clock.deps, {
    deadlineMs: 10_000,
    intervalMs: 100,
    label: "test",
  }, () => {
    attempts += 1;
    return Promise.resolve(attempts >= 3 ? "done" : null);
  });
  assertEquals(settled, "done");
  assertEquals(attempts, 3);

  const failing = deps(fakeFetch([], () => json({})));
  await assertRejects(
    () =>
      pollUntil(failing.deps, {
        deadlineMs: 500,
        intervalMs: 100,
        label: "never",
      }, () => Promise.resolve(null)),
    ArmError,
    "did not settle",
  );
});

Deno.test("redact removes every secret occurrence", () => {
  assertEquals(redact(`a ${SECRET} b ${SECRET}`, [SECRET]), "a *** b ***");
  assertEquals(redact("nothing", ["x"]), "nothing");
});
