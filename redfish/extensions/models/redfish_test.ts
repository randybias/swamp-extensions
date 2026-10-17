import { assert, assertEquals, assertRejects } from "jsr:@std/assert@1.0.19";
import { createModelTestContext } from "jsr:@swamp-club/swamp-testing@0.20261014.55";
import type { FetchFn, TlsPolicy } from "./_lib/http.ts";
import { RedfishError } from "./_lib/http.ts";
import { model, setDeps } from "./redfish.ts";

const SYSTEM = JSON.parse(
  await Deno.readTextFile(
    new URL("./_lib/fixtures/system.json", import.meta.url),
  ),
) as Record<string, unknown>;
const SYSTEMS = JSON.parse(
  await Deno.readTextFile(
    new URL("./_lib/fixtures/systems.json", import.meta.url),
  ),
) as Record<string, unknown>;

const ORIGIN = "https://bmc.example.com";
const ID = "437XR1138R2";
const SYSTEM_PATH = `/redfish/v1/Systems/${ID}`;
const SESSION_LOCATION = "/redfish/v1/SessionService/Sessions/1";
const TOKEN = "session-token-placeholder";
const USER = "operator";
const PASS = "placeholder-password-value";

interface Call {
  method: string;
  url: string;
  headers: Record<string, string>;
  body?: string;
}

function headersOf(init?: RequestInit): Record<string, string> {
  const h = init?.headers as Record<string, string> | undefined;
  return { ...(h ?? {}) };
}

const json = (obj: unknown, etag?: string) =>
  new Response(JSON.stringify(obj), {
    status: 200,
    headers: { "content-type": "application/json", ...(etag ? { etag } : {}) },
  });

function makeBmc() {
  const system = structuredClone(SYSTEM) as Record<string, unknown>;
  const systems = structuredClone(SYSTEMS) as Record<string, unknown>;
  const calls: Call[] = [];
  let sessionStatus = 201;
  let systemStatus = 200;
  let ignoreReset = false;
  const fetchImpl: FetchFn = (url, init) => {
    const method = init?.method ?? "GET";
    const headers = headersOf(init);
    const body = init?.body !== undefined ? String(init.body) : undefined;
    calls.push({ method, url, headers, body });
    const path = new URL(url).pathname;
    if (method === "POST" && path === "/redfish/v1/SessionService/Sessions") {
      if (sessionStatus !== 201) {
        return Promise.resolve(new Response("x", { status: sessionStatus }));
      }
      return Promise.resolve(
        new Response("{}", {
          status: 201,
          headers: { "x-auth-token": TOKEN, location: SESSION_LOCATION },
        }),
      );
    }
    if (method === "DELETE" && path === SESSION_LOCATION) {
      return Promise.resolve(new Response(null, { status: 204 }));
    }
    if (method === "GET" && path === "/redfish/v1/Systems") {
      return Promise.resolve(json(systems));
    }
    if (method === "GET" && path === SYSTEM_PATH) {
      if (systemStatus !== 200) {
        return Promise.resolve(new Response("x", { status: systemStatus }));
      }
      return Promise.resolve(json(system, 'W/"e1"'));
    }
    if (
      method === "POST" &&
      path === `${SYSTEM_PATH}/Actions/ComputerSystem.Reset`
    ) {
      if (!ignoreReset) {
        const resetType = (JSON.parse(body ?? "{}") as { ResetType?: string })
          .ResetType;
        if (resetType === "On") system.PowerState = "On";
        if (resetType === "ForceOff" || resetType === "GracefulShutdown") {
          system.PowerState = "Off";
        }
        if (
          resetType === "ForceRestart" || resetType === "GracefulRestart"
        ) {
          system.PowerState = "On";
        }
      }
      return Promise.resolve(new Response(null, { status: 204 }));
    }
    if (method === "PATCH" && path === SYSTEM_PATH) {
      const b = JSON.parse(body ?? "{}") as {
        Boot?: Record<string, string>;
      };
      const boot = system.Boot as Record<string, unknown>;
      if (b.Boot?.BootSourceOverrideTarget) {
        boot.BootSourceOverrideTarget = b.Boot.BootSourceOverrideTarget;
      }
      if (b.Boot?.BootSourceOverrideEnabled) {
        boot.BootSourceOverrideEnabled = b.Boot.BootSourceOverrideEnabled;
      }
      return Promise.resolve(new Response(null, { status: 204 }));
    }
    return Promise.resolve(new Response("not found", { status: 404 }));
  };
  return {
    system,
    systems,
    calls,
    fetch: fetchImpl,
    setSessionStatus: (s: number) => {
      sessionStatus = s;
    },
    setSystemStatus: (s: number) => {
      systemStatus = s;
    },
    setIgnoreReset: (v: boolean) => {
      ignoreReset = v;
    },
  };
}

type Bmc = ReturnType<typeof makeBmc>;

let lastTls: TlsPolicy | undefined;

/** Installs the fake BMC as the model's deps. */
function useBmc(bmc: Bmc) {
  let clock = 1_700_000_000_000;
  const prev = setDeps({
    fetch: bmc.fetch,
    makeClient: (tls) => {
      lastTls = tls;
      return { client: undefined, close: () => {} };
    },
    now: () => new Date(clock += 1000),
    sleep: () => Promise.resolve(),
  });
  return { restore: () => setDeps(prev) };
}

const DEF = "test-redfish";
const ctxOptions = { globalArgs: {}, definition: { name: DEF } };

const BASE = {
  endpoint: ORIGIN,
  username: USER,
  password: PASS,
  tls_verify: "strict" as const,
};

/** No output, state or URL may carry the password or username. */
function assertNoSecret(blob: unknown, bmc: Bmc) {
  const dump = JSON.stringify(blob);
  assert(!dump.includes(PASS));
  assertEquals(dump.includes(USER), false);
  for (const c of bmc.calls) {
    assert(!c.url.includes(PASS) && !c.url.includes(USER), c.url);
  }
  // The session POST body is the credential exchange; nothing else may carry it.
  for (const c of bmc.calls) {
    if (c.method === "POST" && c.url.endsWith("/Sessions")) continue;
    assert(!(c.body ?? "").includes(PASS), c.method + " " + c.url);
  }
}

Deno.test("schema: username and password are sensitive and tls_verify is required", () => {
  const shape = (model.methods.get.arguments as unknown as {
    shape: Record<string, { meta(): { sensitive?: boolean } }>;
  }).shape;
  assertEquals(shape.username.meta().sensitive, true);
  assertEquals(shape.password.meta().sensitive, true);
  assertEquals(shape.tls_verify.meta().sensitive, undefined);
  const parsed = model.methods.get.arguments.safeParse({
    endpoint: ORIGIN,
    username: USER,
    password: PASS,
  });
  assertEquals(parsed.success, false);
});

Deno.test("get reads state, sends credentials in headers only, and deletes the session", async () => {
  const bmc = makeBmc();
  const u = useBmc(bmc);
  try {
    const { context, getWrittenResources } = createModelTestContext(ctxOptions);
    const out = await model.methods.get.execute(BASE, context) as {
      result: Record<string, unknown>;
    };
    assertEquals(out.result.system_id, ID);
    assertEquals(out.result.power_state, "On");
    assertEquals(out.result.boot_target, "Pxe");
    const session = bmc.calls.find((c) => c.url.endsWith("/Sessions"))!;
    assertEquals(JSON.parse(session.body!).UserName, USER);
    const read = bmc.calls.find((c) =>
      c.method === "GET" && c.url.endsWith(SYSTEM_PATH)
    )!;
    assertEquals(read.headers["X-Auth-Token"], TOKEN);
    assertEquals(read.headers["Authorization"], undefined);
    assert(
      bmc.calls.some((c) =>
        c.method === "DELETE" && c.url.endsWith(SESSION_LOCATION)
      ),
    );
    assertNoSecret([out, getWrittenResources()], bmc);
  } finally {
    u.restore();
  }
});

Deno.test("auth_mode basic sends an Authorization header and opens no session", async () => {
  const bmc = makeBmc();
  const u = useBmc(bmc);
  try {
    const { context } = createModelTestContext(ctxOptions);
    await model.methods.get.execute({ ...BASE, auth_mode: "basic" }, context);
    assert(!bmc.calls.some((c) => c.url.endsWith("/Sessions")));
    const read = bmc.calls.find((c) => c.method === "GET")!;
    assert(read.headers["Authorization"]?.startsWith("Basic "));
    assertEquals(read.headers["X-Auth-Token"], undefined);
  } finally {
    u.restore();
  }
});

Deno.test("session auth falls back to Basic when the BMC has no SessionService", async () => {
  const bmc = makeBmc();
  bmc.setSessionStatus(404);
  const u = useBmc(bmc);
  try {
    const { context } = createModelTestContext(ctxOptions);
    await model.methods.get.execute(BASE, context);
    const read = bmc.calls.find((c) => c.method === "GET")!;
    assert(read.headers["Authorization"]?.startsWith("Basic "));
  } finally {
    u.restore();
  }
});

Deno.test("tls policy is passed to the client factory, with no default", async () => {
  const bmc = makeBmc();
  const u = useBmc(bmc);
  try {
    const { context } = createModelTestContext(ctxOptions);
    await model.methods.get.execute(BASE, context);
    assertEquals(lastTls, { mode: "strict" });
    await model.methods.get.execute(
      { ...BASE, tls_verify: "insecure_skip_verify" },
      context,
    );
    assertEquals(lastTls, { mode: "insecure_skip_verify" });
    await model.methods.get.execute(
      { ...BASE, ca_pem: "placeholder-ca-pem" },
      context,
    );
    assertEquals(lastTls, {
      mode: "strict",
      caPem: "placeholder-ca-pem",
    });
  } finally {
    u.restore();
  }
});

Deno.test("sync records not_found when the system is gone", async () => {
  const bmc = makeBmc();
  bmc.setSystemStatus(404);
  const u = useBmc(bmc);
  try {
    const { context, getWrittenResources } = createModelTestContext(ctxOptions);
    await model.methods.sync.execute({ ...BASE, system_id: ID }, context);
    assertEquals(
      (getWrittenResources()[0].data as { status: string }).status,
      "not_found",
    );
  } finally {
    u.restore();
  }
});

Deno.test("get of a missing system is a typed not_found", async () => {
  const bmc = makeBmc();
  bmc.setSystemStatus(404);
  const u = useBmc(bmc);
  try {
    const { context } = createModelTestContext(ctxOptions);
    const e = await assertRejects(() =>
      model.methods.get.execute({ ...BASE, system_id: ID }, context)
    ) as RedfishError;
    assertEquals(e.code, "not_found");
    assert(bmc.calls.some((c) => c.method === "DELETE"));
  } finally {
    u.restore();
  }
});

Deno.test("discovery uses the only ComputerSystem when no id is given", async () => {
  const bmc = makeBmc();
  const u = useBmc(bmc);
  try {
    const { context } = createModelTestContext(ctxOptions);
    const out = await model.methods.get.execute(BASE, context) as {
      result: Record<string, unknown>;
    };
    assertEquals(out.result.system_id, ID);
    assert(bmc.calls.some((c) => c.url.endsWith("/redfish/v1/Systems")));
  } finally {
    u.restore();
  }
});

Deno.test("power is a no-op when the system is already On", async () => {
  const bmc = makeBmc();
  const u = useBmc(bmc);
  try {
    const { context } = createModelTestContext(ctxOptions);
    const out = await model.methods.power.execute(
      { ...BASE, action: "On" },
      context,
    ) as { result: Record<string, unknown> };
    assert(
      !bmc.calls.some((c) => c.method === "POST" && c.url.includes("Reset")),
    );
    assertEquals(out.result.power_state, "On");
  } finally {
    u.restore();
  }
});

Deno.test("power ForceOff posts the reset and polls until Off", async () => {
  const bmc = makeBmc();
  const u = useBmc(bmc);
  try {
    const { context, getWrittenResources } = createModelTestContext(ctxOptions);
    const out = await model.methods.power.execute(
      { ...BASE, action: "ForceOff" },
      context,
    ) as { result: Record<string, unknown> };
    const reset = bmc.calls.find((c) =>
      c.method === "POST" && c.url.includes("Reset")
    )!;
    assertEquals(JSON.parse(reset.body!), { ResetType: "ForceOff" });
    assertEquals(out.result.power_state, "Off");
    assertNoSecret([out, getWrittenResources()], bmc);
  } finally {
    u.restore();
  }
});

Deno.test("power times out with a typed error when the state never changes", async () => {
  const bmc = makeBmc();
  bmc.setIgnoreReset(true);
  const u = useBmc(bmc);
  try {
    const { context } = createModelTestContext(ctxOptions);
    const e = await assertRejects(() =>
      model.methods.power.execute(
        { ...BASE, action: "ForceOff", timeout_seconds: 5 },
        context,
      )
    ) as RedfishError;
    assertEquals(e.code, "timeout");
  } finally {
    u.restore();
  }
});

Deno.test("power refuses a reset type the BMC does not allow", async () => {
  const bmc = makeBmc();
  const actions = bmc.system.Actions as Record<string, Record<string, unknown>>;
  actions["#ComputerSystem.Reset"][
    ["ResetType", "@", "Redfish.AllowableValues"].join("")
  ] = [
    "On",
    "ForceOff",
  ];
  const u = useBmc(bmc);
  try {
    const { context } = createModelTestContext(ctxOptions);
    const e = await assertRejects(() =>
      model.methods.power.execute(
        { ...BASE, action: "GracefulRestart" },
        context,
      )
    ) as RedfishError;
    assertEquals(e.code, "invalid_input");
    assert(e.message.includes("GracefulRestart"));
    assert(
      !bmc.calls.some((c) => c.method === "POST" && c.url.includes("Reset")),
    );
  } finally {
    u.restore();
  }
});

Deno.test("set_boot is a no-op when the override already matches", async () => {
  const bmc = makeBmc();
  const u = useBmc(bmc);
  try {
    const { context } = createModelTestContext(ctxOptions);
    await model.methods.set_boot.execute(
      { ...BASE, target: "Pxe", enabled: "Once" },
      context,
    );
    assert(!bmc.calls.some((c) => c.method === "PATCH"));
  } finally {
    u.restore();
  }
});

Deno.test("set_boot patches, sends If-Match, and reads the override back", async () => {
  const bmc = makeBmc();
  const u = useBmc(bmc);
  try {
    const { context, getWrittenResources } = createModelTestContext(ctxOptions);
    const out = await model.methods.set_boot.execute(
      { ...BASE, target: "Hdd", enabled: "Continuous" },
      context,
    ) as { result: Record<string, unknown> };
    const patch = bmc.calls.find((c) => c.method === "PATCH")!;
    assertEquals(JSON.parse(patch.body!), {
      Boot: {
        BootSourceOverrideTarget: "Hdd",
        BootSourceOverrideEnabled: "Continuous",
      },
    });
    assertEquals(patch.headers["If-Match"], 'W/"e1"');
    assertEquals(out.result.boot_target, "Hdd");
    assertEquals(out.result.boot_enabled, "Continuous");
    assertEquals(
      (getWrittenResources()[0].data as { boot_target: string }).boot_target,
      "Hdd",
    );
  } finally {
    u.restore();
  }
});

Deno.test("set_boot Disabled clears the override to None", async () => {
  const bmc = makeBmc();
  const u = useBmc(bmc);
  try {
    const { context } = createModelTestContext(ctxOptions);
    await model.methods.set_boot.execute(
      { ...BASE, target: "Pxe", enabled: "Disabled" },
      context,
    );
    const patch = bmc.calls.find((c) => c.method === "PATCH")!;
    assertEquals(JSON.parse(patch.body!), {
      Boot: {
        BootSourceOverrideTarget: "None",
        BootSourceOverrideEnabled: "Disabled",
      },
    });
  } finally {
    u.restore();
  }
});

Deno.test("set_boot refuses a target the BMC does not allow", async () => {
  const bmc = makeBmc();
  const boot = bmc.system.Boot as Record<string, unknown>;
  boot[["BootSourceOverrideTarget", "@", "Redfish.AllowableValues"].join("")] =
    [
      "None",
      "Pxe",
    ];
  const u = useBmc(bmc);
  try {
    const { context } = createModelTestContext(ctxOptions);
    const e = await assertRejects(() =>
      model.methods.set_boot.execute(
        { ...BASE, target: "Usb", enabled: "Once" },
        context,
      )
    ) as RedfishError;
    assertEquals(e.code, "invalid_input");
    assert(!bmc.calls.some((c) => c.method === "PATCH"));
  } finally {
    u.restore();
  }
});

Deno.test("an unreachable BMC is a typed error", async () => {
  const bmc = makeBmc();
  const failing: Bmc = {
    ...bmc,
    fetch: () => Promise.reject(new TypeError("connection refused")),
  };
  const u = useBmc(failing);
  try {
    const { context } = createModelTestContext(ctxOptions);
    const e = await assertRejects(() =>
      model.methods.get.execute(BASE, context)
    ) as RedfishError;
    assertEquals(e.code, "unreachable");
  } finally {
    u.restore();
  }
});

Deno.test("a TLS failure is a typed error", async () => {
  const bmc = makeBmc();
  const failing: Bmc = {
    ...bmc,
    fetch: () => Promise.reject(new Error("certificate verify failed")),
  };
  const u = useBmc(failing);
  try {
    const { context } = createModelTestContext(ctxOptions);
    const e = await assertRejects(() =>
      model.methods.get.execute(BASE, context)
    ) as RedfishError;
    assertEquals(e.code, "tls");
  } finally {
    u.restore();
  }
});

Deno.test("a session the BMC refuses is a typed unauthorized error", async () => {
  const bmc = makeBmc();
  bmc.setSessionStatus(401);
  const u = useBmc(bmc);
  try {
    const { context } = createModelTestContext(ctxOptions);
    const e = await assertRejects(() =>
      model.methods.get.execute(BASE, context)
    ) as RedfishError;
    assertEquals(e.code, "unauthorized");
  } finally {
    u.restore();
  }
});

Deno.test("an oversized BMC response is refused", async () => {
  const bmc = makeBmc();
  const baseFetch = bmc.fetch;
  const oversized: Bmc = {
    ...bmc,
    fetch: (url, init) =>
      new URL(url).pathname === "/redfish/v1/SessionService/Sessions"
        ? baseFetch(url, init)
        : Promise.resolve(new Response("x".repeat(1024 * 1024 + 1))),
  };
  const u = useBmc(oversized);
  try {
    const { context } = createModelTestContext(ctxOptions);
    const e = await assertRejects(() =>
      model.methods.get.execute(BASE, context)
    ) as RedfishError;
    assertEquals(e.code, "response_too_large");
  } finally {
    u.restore();
  }
});

Deno.test("a cross-origin reset target is refused", async () => {
  const bmc = makeBmc();
  const actions = bmc.system.Actions as Record<string, Record<string, unknown>>;
  actions["#ComputerSystem.Reset"].target =
    "https://evil.example.com/redfish/v1/Systems/1/Actions/ComputerSystem.Reset";
  const u = useBmc(bmc);
  try {
    const { context } = createModelTestContext(ctxOptions);
    const e = await assertRejects(() =>
      model.methods.power.execute({ ...BASE, action: "ForceOff" }, context)
    ) as RedfishError;
    assertEquals(e.code, "redfish_failed");
    assert(!bmc.calls.some((c) => c.url.includes("evil.example.com")));
  } finally {
    u.restore();
  }
});

Deno.test("injection in endpoint and system_id is rejected before any request", async () => {
  const bmc = makeBmc();
  const u = useBmc(bmc);
  try {
    const { context } = createModelTestContext(ctxOptions);
    for (
      const bad of [
        { ...BASE, endpoint: "http://bmc.example.com" },
        { ...BASE, endpoint: "https://bmc.example.com/redfish" },
        { ...BASE, system_id: "../1" },
        { ...BASE, system_id: "a;b" },
        {
          ...BASE,
          endpoint: ["https://user:", "pass", "@bmc.example.com"].join(""),
        },
      ]
    ) {
      await assertRejects(() =>
        model.methods.get.execute(bad as never, context)
      );
    }
    assertEquals(bmc.calls.length, 0);
  } finally {
    u.restore();
  }
});

Deno.test("no fixture, source or doc carries real-looking secret material", async () => {
  const patterns: [string, RegExp][] = [
    ["PEM private key", /-----BEGIN [A-Z ]*PRIVATE KEY-----/],
    [
      "JWT",
      /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/,
    ],
    ["AWS access key", /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/],
  ];
  const files: URL[] = [];
  async function walk(dir: URL): Promise<void> {
    for await (const e of Deno.readDir(dir)) {
      if (e.name === ".swamp" || e.name === ".gates") continue;
      const child = new URL(e.name + (e.isDirectory ? "/" : ""), dir);
      if (e.isDirectory) await walk(child);
      else if (/\.(ts|md|ya?ml|json|txt)$/.test(e.name)) files.push(child);
    }
  }
  await walk(new URL("../../", import.meta.url));
  assert(files.length > 0);
  for (const file of files) {
    const text = await Deno.readTextFile(file);
    for (const [name, re] of patterns) {
      assertEquals(re.test(text), false, `${name} found in ${file.pathname}`);
    }
  }
});
