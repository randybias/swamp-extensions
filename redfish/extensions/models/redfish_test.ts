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
  let sessionBodyLocation = false;
  let sessionLocationOverride: string | undefined;
  let taskOnReset = false;
  let taskState = "Completed";
  let taskStatusText: string | undefined;
  let taskHttpStatus: number | undefined;
  let taskEmpty = false;
  let taskLocationOverride: string | undefined;
  let restartTransition = true;
  let restartStuck = false;
  let restartCounter = 0;
  let systemBodyOverride: unknown = undefined;
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
      const sessionLocation = sessionLocationOverride ?? SESSION_LOCATION;
      const sessionBody = sessionBodyLocation
        ? JSON.stringify({ "@odata.id": sessionLocation })
        : "{}";
      return Promise.resolve(
        new Response(sessionBody, {
          status: 201,
          headers: sessionBodyLocation
            ? { "x-auth-token": TOKEN }
            : { "x-auth-token": TOKEN, location: sessionLocation },
        }),
      );
    }
    if (method === "DELETE" && path === SESSION_LOCATION) {
      return Promise.resolve(new Response(null, { status: 204 }));
    }
    if (method === "GET" && path === "/redfish/v1/TaskService/Tasks/1") {
      if (taskHttpStatus !== undefined) {
        return Promise.resolve(new Response("", { status: taskHttpStatus }));
      }
      if (taskEmpty) {
        return Promise.resolve(new Response(null, { status: 204 }));
      }
      return Promise.resolve(json({
        TaskState: taskState,
        ...(taskStatusText ? { TaskStatus: taskStatusText } : {}),
      }));
    }
    if (method === "GET" && path === "/redfish/v1/Systems") {
      return Promise.resolve(json(systems));
    }
    if (method === "GET" && path === SYSTEM_PATH) {
      if (systemStatus !== 200) {
        return Promise.resolve(new Response("x", { status: systemStatus }));
      }
      if (systemBodyOverride !== undefined) {
        return Promise.resolve(
          new Response(JSON.stringify(systemBodyOverride), {
            status: 200,
            headers: { "content-type": "application/json" },
          }),
        );
      }
      if (restartCounter === 1) {
        restartCounter = 2;
        system.PowerState = "Off";
      } else if (restartCounter === 2) {
        restartCounter = 0;
        system.PowerState = "On";
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
          resetType === "ForceRestart" || resetType === "GracefulRestart" ||
          resetType === "PowerCycle" || resetType === "Nmi"
        ) {
          if (restartStuck) {
            system.PowerState = "Off";
          } else if (restartTransition) {
            restartCounter = 1;
            system.PowerState = "Off";
          } else {
            system.PowerState = "On";
          }
        }
      }
      if (taskOnReset) {
        return Promise.resolve(
          new Response(null, {
            status: 202,
            headers: {
              location: taskLocationOverride ??
                "/redfish/v1/TaskService/Tasks/1",
            },
          }),
        );
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
    setSessionBodyLocation: (v: boolean) => {
      sessionBodyLocation = v;
    },
    setTaskOnReset: (v: boolean) => {
      taskOnReset = v;
    },
    setTaskState: (v: string) => {
      taskState = v;
    },
    setTaskStatusText: (v: string) => {
      taskStatusText = v;
    },
    setTaskHttpStatus: (v: number) => {
      taskHttpStatus = v;
    },
    setRestartTransition: (v: boolean) => {
      restartTransition = v;
    },
    setRestartStuck: (v: boolean) => {
      restartStuck = v;
    },
    setSessionLocation: (v: string) => {
      sessionLocationOverride = v;
    },
    setTaskLocation: (v: string) => {
      taskLocationOverride = v;
    },
    setTaskEmpty: (v: boolean) => {
      taskEmpty = v;
    },
    setSystemBody: (v: unknown) => {
      systemBodyOverride = v;
    },
  };
}

type Bmc = ReturnType<typeof makeBmc>;

let lastTls: TlsPolicy | undefined;

/** Installs the fake BMC as the model's deps. */
function useBmc(bmc: Bmc, requestTimeoutMs = 30_000) {
  let clock = 1_700_000_000_000;
  const prev = setDeps({
    fetch: bmc.fetch,
    makeClient: (tls) => {
      lastTls = tls;
      return { client: undefined, close: () => {} };
    },
    now: () => new Date(clock += 1000),
    sleep: () => Promise.resolve(),
    requestTimeoutMs,
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
  const withTls = model.methods.get.arguments.safeParse({
    endpoint: ORIGIN,
    username: USER,
    password: PASS,
    tls_verify: "strict",
  });
  assertEquals(withTls.success, true);
  if (withTls.success) {
    assertEquals(
      (withTls.data as { allow_insecure_credentials: boolean })
        .allow_insecure_credentials,
      false,
    );
  }
  const caDesc =
    (shape.ca_pem as unknown as { description?: string }).description ?? "";
  assert(caDesc.includes("additionally"));
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
      {
        ...BASE,
        tls_verify: "insecure_skip_verify",
        allow_insecure_credentials: true,
      },
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
    "VendorMagic",
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
    assert(!e.message.includes("VendorMagic"));
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

Deno.test("credentials over insecure TLS are refused unless explicitly allowed", async () => {
  const bmc = makeBmc();
  const u = useBmc(bmc);
  try {
    const { context } = createModelTestContext(ctxOptions);
    for (const auth_mode of ["session", "basic"] as const) {
      const e = await assertRejects(() =>
        model.methods.get.execute({
          ...BASE,
          auth_mode,
          tls_verify: "insecure_skip_verify",
        }, context)
      ) as RedfishError;
      assertEquals(e.code, "invalid_input", auth_mode);
    }
    assertEquals(bmc.calls.length, 0);
    await model.methods.get.execute({
      ...BASE,
      auth_mode: "session",
      tls_verify: "insecure_skip_verify",
      allow_insecure_credentials: true,
    }, context);
    assert(bmc.calls.some((c) => c.method === "GET"));
  } finally {
    u.restore();
  }
});

Deno.test("the SessionService fallback is refused over insecure TLS unless allowed", async () => {
  const bmc = makeBmc();
  bmc.setSessionStatus(404);
  const u = useBmc(bmc);
  try {
    const { context } = createModelTestContext(ctxOptions);
    const e = await assertRejects(() =>
      model.methods.get.execute(
        { ...BASE, tls_verify: "insecure_skip_verify" },
        context,
      )
    ) as RedfishError;
    assertEquals(e.code, "invalid_input");
    assert(!bmc.calls.some((c) => c.method === "GET"));
    // Strict TLS allows the fallback.
    await model.methods.get.execute(BASE, context);
    const read = bmc.calls.find((c) => c.method === "GET")!;
    assert(read.headers["Authorization"]?.startsWith("Basic "));
  } finally {
    u.restore();
  }
});

Deno.test("a stalled request times out and the session is still deleted", async () => {
  const bmc = makeBmc();
  const baseFetch = bmc.fetch;
  const stalled: Bmc = {
    ...bmc,
    fetch: (url, init) => {
      const method = init?.method ?? "GET";
      if (method === "POST" && url.endsWith("/Sessions")) {
        return baseFetch(url, init);
      }
      if (method === "DELETE") return baseFetch(url, init);
      return new Promise<Response>((_resolve, reject) => {
        const signal = (init as { signal?: AbortSignal } | undefined)?.signal;
        if (!signal) return;
        if (signal.aborted) return reject(signal.reason);
        signal.addEventListener("abort", () => reject(signal.reason), {
          once: true,
        });
      });
    },
  };
  const u = useBmc(stalled, 20);
  try {
    const { context } = createModelTestContext(ctxOptions);
    const e = await assertRejects(() =>
      model.methods.get.execute(BASE, context)
    ) as RedfishError;
    assertEquals(e.code, "timeout");
    assert(stalled.calls.some((c) => c.method === "DELETE"));
  } finally {
    u.restore();
  }
});

Deno.test("a session with no Location header is deleted via its body @odata.id", async () => {
  const bmc = makeBmc();
  bmc.setSessionBodyLocation(true);
  const u = useBmc(bmc);
  try {
    const { context } = createModelTestContext(ctxOptions);
    await model.methods.get.execute(BASE, context);
    assert(
      bmc.calls.some((c) =>
        c.method === "DELETE" && c.url.endsWith(SESSION_LOCATION)
      ),
    );
  } finally {
    u.restore();
  }
});

Deno.test("power restart waits for an observed transition before accepting On", async () => {
  const bmc = makeBmc();
  bmc.setRestartTransition(true);
  const u = useBmc(bmc);
  try {
    const { context } = createModelTestContext(ctxOptions);
    const out = await model.methods.power.execute(
      { ...BASE, action: "ForceRestart", timeout_seconds: 30 },
      context,
    ) as { result: Record<string, unknown> };
    assertEquals(out.result.power_state, "On");
  } finally {
    u.restore();
  }
});

Deno.test("power restart times out when the system never returns to desired", async () => {
  const bmc = makeBmc();
  bmc.setRestartStuck(true);
  const u = useBmc(bmc);
  try {
    const { context } = createModelTestContext(ctxOptions);
    const e = await assertRejects(() =>
      model.methods.power.execute(
        { ...BASE, action: "ForceRestart", timeout_seconds: 5 },
        context,
      )
    ) as RedfishError;
    assertEquals(e.code, "timeout");
  } finally {
    u.restore();
  }
});

Deno.test("power follows a returned Redfish task monitor", async () => {
  const bmc = makeBmc();
  bmc.setTaskOnReset(true);
  bmc.setTaskState("Completed");
  bmc.setRestartTransition(true);
  const u = useBmc(bmc);
  try {
    const { context } = createModelTestContext(ctxOptions);
    await model.methods.power.execute(
      { ...BASE, action: "ForceRestart", timeout_seconds: 30 },
      context,
    );
    assert(
      bmc.calls.some((c) => c.url.endsWith("/redfish/v1/TaskService/Tasks/1")),
    );
  } finally {
    u.restore();
  }
});

Deno.test("a null or Id-less ComputerSystem body is refused", async () => {
  for (const body of [null, { PowerState: "On" }]) {
    const bmc = makeBmc();
    bmc.setSystemBody(body);
    const u = useBmc(bmc);
    try {
      const { context } = createModelTestContext(ctxOptions);
      const e = await assertRejects(() =>
        model.methods.get.execute({ ...BASE, system_id: ID }, context)
      ) as RedfishError;
      assertEquals(e.code, "redfish_failed", JSON.stringify(body));
    } finally {
      u.restore();
    }
  }
});

Deno.test("set_boot is described as destructive", () => {
  assert(
    String(model.methods.set_boot.description).startsWith("DESTRUCTIVE."),
  );
});

Deno.test("a restart already at desired on the immediate poll is accepted", async () => {
  const bmc = makeBmc();
  bmc.setRestartTransition(false);
  const u = useBmc(bmc);
  try {
    const { context } = createModelTestContext(ctxOptions);
    const out = await model.methods.power.execute(
      { ...BASE, action: "ForceRestart", timeout_seconds: 5 },
      context,
    ) as { result: Record<string, unknown> };
    assertEquals(out.result.power_state, "On");
  } finally {
    u.restore();
  }
});

Deno.test("Nmi is fire-and-forget: a 2xx is the result", async () => {
  const bmc = makeBmc();
  const u = useBmc(bmc);
  try {
    const { context } = createModelTestContext(ctxOptions);
    await model.methods.power.execute(
      { ...BASE, action: "Nmi", timeout_seconds: 5 },
      context,
    );
    assert(
      bmc.calls.some((c) =>
        c.method === "POST" && c.url.includes("ComputerSystem.Reset")
      ),
    );
  } finally {
    u.restore();
  }
});

Deno.test("a completed task monitor is success without a transition", async () => {
  const bmc = makeBmc();
  bmc.setTaskOnReset(true);
  bmc.setTaskState("Completed");
  bmc.setRestartTransition(false);
  const u = useBmc(bmc);
  try {
    const { context } = createModelTestContext(ctxOptions);
    const out = await model.methods.power.execute(
      { ...BASE, action: "ForceRestart", timeout_seconds: 30 },
      context,
    ) as { result: Record<string, unknown> };
    assertEquals(out.result.power_state, "On");
  } finally {
    u.restore();
  }
});

Deno.test("a 204 task monitor is unconfirmed and falls through to the state poll", async () => {
  const bmc = makeBmc();
  bmc.setTaskOnReset(true);
  bmc.setTaskEmpty(true);
  bmc.setRestartTransition(false);
  const u = useBmc(bmc);
  try {
    const { context } = createModelTestContext(ctxOptions);
    const out = await model.methods.power.execute(
      { ...BASE, action: "ForceRestart", timeout_seconds: 5 },
      context,
    ) as { result: Record<string, unknown> };
    assertEquals(out.result.power_state, "On");
  } finally {
    u.restore();
  }
});

Deno.test("a 404 task with the host still On times out (ForceOff)", async () => {
  const bmc = makeBmc();
  bmc.setTaskOnReset(true);
  bmc.setTaskHttpStatus(404);
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

Deno.test("an empty 500 task read throws", async () => {
  const bmc = makeBmc();
  bmc.setTaskOnReset(true);
  bmc.setTaskHttpStatus(500);
  const u = useBmc(bmc);
  try {
    const { context } = createModelTestContext(ctxOptions);
    const e = await assertRejects(() =>
      model.methods.power.execute(
        { ...BASE, action: "ForceRestart", timeout_seconds: 5 },
        context,
      )
    ) as RedfishError;
    assertEquals(e.code, "redfish_failed");
  } finally {
    u.restore();
  }
});

Deno.test("a completed task with a non-OK status throws", async () => {
  const bmc = makeBmc();
  bmc.setTaskOnReset(true);
  bmc.setTaskState("Completed");
  bmc.setTaskStatusText("Critical");
  const u = useBmc(bmc);
  try {
    const { context } = createModelTestContext(ctxOptions);
    const e = await assertRejects(() =>
      model.methods.power.execute(
        { ...BASE, action: "ForceRestart", timeout_seconds: 5 },
        context,
      )
    ) as RedfishError;
    assertEquals(e.code, "redfish_failed");
  } finally {
    u.restore();
  }
});

Deno.test("a completed task does not confirm a non-restart action that stays On", async () => {
  const bmc = makeBmc();
  bmc.setTaskOnReset(true);
  bmc.setTaskState("Completed");
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

Deno.test("a stalled session DELETE does not hang the method", async () => {
  const bmc = makeBmc();
  const baseFetch = bmc.fetch;
  const stalled: Bmc = {
    ...bmc,
    fetch: (url, init) => {
      if ((init?.method ?? "GET") === "DELETE") {
        return new Promise<Response>((_resolve, reject) => {
          const signal = (init as { signal?: AbortSignal } | undefined)?.signal;
          if (!signal) return;
          if (signal.aborted) return reject(signal.reason);
          signal.addEventListener("abort", () => reject(signal.reason), {
            once: true,
          });
        });
      }
      return baseFetch(url, init);
    },
  };
  const u = useBmc(stalled, 20);
  try {
    const { context } = createModelTestContext(ctxOptions);
    const out = await model.methods.get.execute(BASE, context) as {
      result: Record<string, unknown>;
    };
    assertEquals(out.result.system_id, ID);
  } finally {
    u.restore();
  }
});

Deno.test("a cross-origin session URI skips logout without throwing", async () => {
  const bmc = makeBmc();
  bmc.setSessionLocation(["https://evil.example.com", "/session"].join(""));
  bmc.setSessionBodyLocation(true);
  const u = useBmc(bmc);
  try {
    const { context } = createModelTestContext(ctxOptions);
    const out = await model.methods.get.execute(BASE, context) as {
      result: Record<string, unknown>;
    };
    assertEquals(out.result.system_id, ID);
    assert(!bmc.calls.some((c) => c.url.includes("evil.example.com")));
  } finally {
    u.restore();
  }
});

Deno.test("a cross-origin task monitor is not followed", async () => {
  const bmc = makeBmc();
  bmc.setTaskOnReset(true);
  bmc.setTaskLocation(["https://evil.example.com", "/task"].join(""));
  bmc.setRestartTransition(false);
  const u = useBmc(bmc);
  try {
    const { context } = createModelTestContext(ctxOptions);
    const out = await model.methods.power.execute(
      { ...BASE, action: "ForceRestart", timeout_seconds: 5 },
      context,
    ) as { result: Record<string, unknown> };
    assertEquals(out.result.power_state, "On");
    assert(!bmc.calls.some((c) => c.url.includes("evil.example.com")));
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
