import {
  assertEquals,
  assertExists,
  assertRejects,
  assertStringIncludes,
} from "jsr:@std/assert@1.0.19";
import { createModelTestContext } from "jsr:@swamp-club/swamp-testing@0.20261014.55";
import { setFetch, setSleep } from "./_lib/cherry.ts";
import type { CommandRunner } from "./_lib/ssh_probe.ts";
import {
  createBody,
  cycleOf,
  model,
  setProbeDeps,
  toState,
} from "./servers.ts";

const KEY_LINE =
  "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeHostKeyForTestsOnly000000000";

const GLOBALS = {
  project_id: 1001,
  hostname: "node-1",
  plan: "test-plan",
  region: "test-region",
  image: "test-image",
  cycle: "hourly" as const,
  ssh_keys: [7],
  token: "test-token",
};

/** A raw API server object, including fields that must never be stored. */
function rawServer(overrides: Record<string, unknown> = {}) {
  return {
    id: 501,
    hostname: "node-1",
    status: "deployed",
    state: "active",
    password: "root-password-placeholder",
    bmc: { user: "admin", password: "bmc-password-placeholder" },
    plan: { slug: "test-plan" },
    region: { slug: "test-region" },
    project: { id: 1001, name: "example" },
    pricing: { unit: "Hourly" },
    ip_addresses: [
      { address: "192.0.2.10", type: "primary-ip", cidr: "192.0.2.10/32" },
      { address: "198.51.100.5", type: "private-ip" },
    ],
    ...overrides,
  };
}

type Route = (method: string, url: URL, body?: unknown) => Response | null;

/** Routes fetch calls through `route`; records them for assertions. */
function api(route: Route) {
  const calls: { method: string; url: URL; body?: unknown }[] = [];
  const prevFetch = setFetch((input, init) => {
    const url = new URL(input);
    const method = init?.method ?? "GET";
    const body = init?.body ? JSON.parse(String(init.body)) : undefined;
    calls.push({ method, url, body });
    const resp = route(method, url, body);
    if (!resp) throw new Error(`unrouted ${method} ${url.pathname}`);
    return Promise.resolve(resp);
  });
  const prevSleep = setSleep(() => Promise.resolve());
  return {
    calls,
    restore: () => {
      setFetch(prevFetch);
      setSleep(prevSleep);
    },
  };
}

const ok = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status });
const gone = () => new Response("not found", { status: 404 });

Deno.test("toState keeps the allowlist and drops passwords", () => {
  const state = toState(rawServer());
  assertEquals(state.public_ipv4, "192.0.2.10");
  assertEquals(state.private_ipv4, "198.51.100.5");
  assertEquals(state.project_id, 1001);
  assertEquals(state.cycle, "hourly");
  const text = JSON.stringify(state);
  assertEquals(text.includes("password"), false);
  assertEquals(text.includes("bmc"), false);
});

Deno.test("createBody base64-encodes user data and passes the cycle", () => {
  const body = createBody({
    ...GLOBALS,
    cycle: "monthly",
    user_data: "#cloud-config\n",
    os_partition_size: 40,
  });
  assertEquals(body.cycle, "monthly");
  assertEquals(atob(body.user_data as string), "#cloud-config\n");
  assertEquals(body.os_partition_size, 40);
});

Deno.test("create orders a new server and never stores user data", async () => {
  const a = api((method, url) => {
    if (method === "GET" && url.pathname.endsWith("/projects/1001/servers")) {
      return ok([]);
    }
    if (method === "POST") return ok(rawServer({ status: "pending" }), 201);
    return null;
  });
  try {
    const { context, getWrittenResources } = createModelTestContext({
      globalArgs: { ...GLOBALS, user_data: "#cloud-config\nsecret: x\n" },
    });
    await model.methods.create.execute({}, context);
    const post = a.calls.find((c) => c.method === "POST");
    assertExists(post);
    assertEquals((post.body as Record<string, unknown>).cycle, "hourly");
    const written = getWrittenResources();
    assertEquals(written.length, 1);
    const data = written[0].data as Record<string, unknown>;
    assertEquals(data.status, "pending");
    assertEquals(typeof data.user_data_sha256, "string");
    assertEquals(JSON.stringify(data).includes("secret"), false);
    assertEquals(JSON.stringify(data).includes("password"), false);
  } finally {
    a.restore();
  }
});

Deno.test("create adopts a server already recorded in state (idempotent re-run)", async () => {
  const a = api((method, url) => {
    if (method === "GET" && url.pathname.endsWith("/servers/501")) {
      return ok(rawServer());
    }
    return null;
  });
  try {
    const { context, getWrittenResources } = createModelTestContext({
      globalArgs: GLOBALS,
      storedResources: {
        "node-1": { id: 501, hostname: "node-1", status: "deployed" },
      },
    });
    await model.methods.create.execute({}, context);
    assertEquals(a.calls.some((c) => c.method === "POST"), false);
    assertEquals((getWrittenResources()[0].data as { id: number }).id, 501);
  } finally {
    a.restore();
  }
});

Deno.test("create adopts a same-hostname server found in the project", async () => {
  const a = api((method, url) => {
    if (method === "GET" && url.pathname.endsWith("/projects/1001/servers")) {
      return ok([rawServer(), rawServer({ id: 502, hostname: "node-10" })]);
    }
    return null;
  });
  try {
    const { context, getWrittenResources } = createModelTestContext({
      globalArgs: GLOBALS,
    });
    await model.methods.create.execute({}, context);
    assertEquals(a.calls.some((c) => c.method === "POST"), false);
    assertEquals((getWrittenResources()[0].data as { id: number }).id, 501);
  } finally {
    a.restore();
  }
});

Deno.test("create refuses when several servers share the hostname", async () => {
  const a = api((method) =>
    method === "GET" ? ok([rawServer(), rawServer({ id: 502 })]) : null
  );
  try {
    const { context } = createModelTestContext({ globalArgs: GLOBALS });
    await assertRejects(
      () => model.methods.create.execute({}, context),
      Error,
      "refusing to guess",
    );
    assertEquals(a.calls.some((c) => c.method === "POST"), false);
  } finally {
    a.restore();
  }
});

Deno.test("global arguments reject hostile hostnames and slugs", () => {
  const schema = model.globalArguments;
  for (const hostname of ["node;id", "-node", "Node", "a".repeat(64), "n/1"]) {
    assertEquals(schema.safeParse({ ...GLOBALS, hostname }).success, false);
  }
  assertEquals(
    schema.safeParse({ ...GLOBALS, plan: "plan$(id)" }).success,
    false,
  );
  assertEquals(
    schema.safeParse({ ...GLOBALS, cycle: "weekly" }).success,
    false,
  );
  assertEquals(schema.safeParse(GLOBALS).success, true);
});

Deno.test("get fails when the server does not exist", async () => {
  const a = api(() => gone());
  try {
    const { context } = createModelTestContext({ globalArgs: GLOBALS });
    await assertRejects(() => model.methods.get.execute({ id: 9 }, context));
  } finally {
    a.restore();
  }
});

Deno.test("sync records not_found when the server is gone", async () => {
  const a = api(() => gone());
  try {
    const { context, getWrittenResources } = createModelTestContext({
      globalArgs: GLOBALS,
      storedResources: {
        "node-1": { id: 501, hostname: "node-1", status: "deployed" },
      },
    });
    await model.methods.sync.execute({}, context);
    assertEquals(
      (getWrittenResources()[0].data as { status: string }).status,
      "not_found",
    );
  } finally {
    a.restore();
  }
});

Deno.test("list stores one state per server", async () => {
  const a = api(() =>
    ok([rawServer(), rawServer({ id: 502, hostname: "node-2" })])
  );
  try {
    const { context, getWrittenResources } = createModelTestContext({
      globalArgs: GLOBALS,
    });
    await model.methods.list.execute({}, context);
    assertEquals(getWrittenResources().map((r) => r.name).sort(), [
      "node-1",
      "node-2",
    ]);
  } finally {
    a.restore();
  }
});

Deno.test("delete refuses a confirm_hostname that differs from the model", async () => {
  const a = api(() => null);
  try {
    const { context } = createModelTestContext({ globalArgs: GLOBALS });
    await assertRejects(
      () =>
        model.methods.delete.execute(
          { id: 501, confirm_hostname: "node-2" },
          context,
        ),
      Error,
      "does not match",
    );
    assertEquals(a.calls.length, 0);
  } finally {
    a.restore();
  }
});

Deno.test("delete refuses a live server in another project", async () => {
  const a = api((method) =>
    method === "GET" ? ok(rawServer({ project: { id: 2002 } })) : null
  );
  try {
    const { context } = createModelTestContext({
      globalArgs: GLOBALS,
      storedResources: STORED,
    });
    await assertRejects(
      () =>
        model.methods.delete.execute(
          { id: 501, confirm_hostname: "node-1" },
          context,
        ),
      Error,
      "project 2002",
    );
    assertEquals(a.calls.some((c) => c.method === "DELETE"), false);
  } finally {
    a.restore();
  }
});

Deno.test("delete refuses a live server with another hostname", async () => {
  const a = api((method) =>
    method === "GET" ? ok(rawServer({ hostname: "other" })) : null
  );
  try {
    const { context } = createModelTestContext({
      globalArgs: GLOBALS,
      storedResources: STORED,
    });
    await assertRejects(
      () =>
        model.methods.delete.execute(
          { id: 501, confirm_hostname: "node-1" },
          context,
        ),
      Error,
      "refusing to delete",
    );
    assertEquals(a.calls.some((c) => c.method === "DELETE"), false);
  } finally {
    a.restore();
  }
});

Deno.test("delete deletes, then verifies the API returns 404", async () => {
  let deleted = false;
  const a = api((method) => {
    if (method === "DELETE") {
      deleted = true;
      return new Response(null, { status: 204 });
    }
    return deleted ? gone() : ok(rawServer());
  });
  try {
    const { context, getWrittenResources } = createModelTestContext({
      globalArgs: GLOBALS,
      storedResources: STORED,
    });
    await model.methods.delete.execute(
      { id: 501, confirm_hostname: "node-1" },
      context,
    );
    assertEquals(
      (getWrittenResources()[0].data as { status: string }).status,
      "deleted",
    );
  } finally {
    a.restore();
  }
});

Deno.test("delete of an already-gone server records not_found (idempotent)", async () => {
  const a = api(() => gone());
  try {
    const { context, getWrittenResources } = createModelTestContext({
      globalArgs: GLOBALS,
      storedResources: STORED,
    });
    await model.methods.delete.execute(
      { confirm_hostname: "node-1" },
      context,
    );
    assertEquals(
      (getWrittenResources()[0].data as { status: string }).status,
      "not_found",
    );
    assertEquals(a.calls.some((c) => c.method === "DELETE"), false);
  } finally {
    a.restore();
  }
});

/** Probe dependencies with a controllable clock and scripted SSH. */
function probe(
  opts: { bannerAfter?: number; keyLine?: string; markerCode?: number },
) {
  let t = 0;
  let polls = 0;
  const run: CommandRunner = (cmd, args) => {
    if (cmd === "ssh-keyscan") {
      return Promise.resolve({
        code: 0,
        stdout: `192.0.2.10 ${opts.keyLine ?? KEY_LINE}\n`,
        stderr: "",
      });
    }
    if (cmd === "ssh-keygen") {
      return Promise.resolve({
        code: 0,
        stdout: "256 SHA256:testFingerprint no comment (ED25519)\n",
        stderr: "",
      });
    }
    if (cmd === "ssh-agent" && args[0] === "-s") {
      return Promise.resolve({
        code: 0,
        stdout:
          "SSH_AUTH_SOCK=/tmp/a.sock; export;\nSSH_AGENT_PID=1; export;\n",
        stderr: "",
      });
    }
    if (cmd === "ssh") {
      return Promise.resolve({
        code: opts.markerCode ?? 0,
        stdout: "",
        stderr: "",
      });
    }
    return Promise.resolve({ code: 0, stdout: "", stderr: "" });
  };
  const prev = setProbeDeps({
    run,
    banner: () => {
      polls++;
      return polls > (opts.bannerAfter ?? 0)
        ? Promise.resolve("SSH-2.0-OpenSSH_9.6\r\n")
        : Promise.reject(new Error("connection refused"));
    },
    now: () => (t += 15000),
  });
  const deps = setProbeDeps(prev);
  setProbeDeps(deps);
  return { deps, restore: () => setProbeDeps(prev) };
}

const STORED = { "node-1": { id: 501, hostname: "node-1", status: "pending" } };

Deno.test("wait_ready requires known_hosts for strict", async () => {
  const { context } = createModelTestContext({
    globalArgs: GLOBALS,
    storedResources: STORED,
  });
  await assertRejects(
    () =>
      model.methods.wait_ready.execute(
        {
          host_key_policy: "strict",
          port: 22,
          ssh_user: "root",
          timeout_seconds: 60,
          poll_interval_seconds: 1,
        },
        context,
      ),
    Error,
    "known_hosts",
  );
});

Deno.test("wait_ready requires a private key for a marker check", async () => {
  const { context } = createModelTestContext({
    globalArgs: GLOBALS,
    storedResources: STORED,
  });
  await assertRejects(
    () =>
      model.methods.wait_ready.execute(
        {
          host_key_policy: "accept-new",
          port: 22,
          ssh_user: "root",
          marker_path: "/var/lib/cloud/instance/boot-finished",
          timeout_seconds: 60,
          poll_interval_seconds: 1,
        },
        context,
      ),
    Error,
    "ssh_private_key",
  );
});

Deno.test("wait_ready polls until SSH answers, then records evidence", async () => {
  let n = 0;
  const a = api(() =>
    ok(
      ++n <= 3
        ? rawServer({ status: "deploying", state: "provisioning" })
        : rawServer(),
    )
  );
  const p = probe({ bannerAfter: 2 });
  try {
    const { context, getWrittenResources } = createModelTestContext({
      globalArgs: GLOBALS,
      storedResources: STORED,
    });
    await model.methods.wait_ready.execute(
      {
        host_key_policy: "accept-new",
        port: 22,
        ssh_user: "root",
        marker_path: "/var/lib/cloud/instance/boot-finished",
        ssh_private_key: "PRIVATE-KEY-PLACEHOLDER",
        timeout_seconds: 600,
        poll_interval_seconds: 15,
      },
      context,
    );
    const readiness = getWrittenResources().find((r) =>
      r.specName === "readiness"
    );
    assertExists(readiness);
    const data = readiness.data as Record<string, unknown>;
    assertEquals(data.address, "192.0.2.10");
    assertEquals(data.api_status, "deployed");
    assertEquals(data.api_state, "active");
    assertEquals((data.host_keys as unknown[]).length, 1);
    assertEquals(JSON.stringify(data).includes("PRIVATE-KEY"), false);
  } finally {
    p.restore();
    a.restore();
  }
});

Deno.test("wait_ready fails hard on a host-key mismatch under strict", async () => {
  const a = api(() => ok(rawServer()));
  const p = probe({
    keyLine:
      "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDifferentKey0000000000000000",
  });
  try {
    const { context } = createModelTestContext({
      globalArgs: GLOBALS,
      storedResources: STORED,
    });
    await assertRejects(
      () =>
        model.methods.wait_ready.execute(
          {
            host_key_policy: "strict",
            known_hosts: `192.0.2.10 ${KEY_LINE}`,
            port: 22,
            ssh_user: "root",
            timeout_seconds: 600,
            poll_interval_seconds: 15,
          },
          context,
        ),
      Error,
      "mismatch",
    );
  } finally {
    p.restore();
    a.restore();
  }
});

Deno.test("wait_ready times out with the last reason", async () => {
  const a = api(() => ok(rawServer()));
  const p = probe({ markerCode: 1 });
  try {
    const { context } = createModelTestContext({
      globalArgs: GLOBALS,
      storedResources: STORED,
    });
    const err = await assertRejects(
      () =>
        model.methods.wait_ready.execute(
          {
            host_key_policy: "insecure",
            port: 22,
            ssh_user: "root",
            marker_path: "/var/lib/cloud/instance/boot-finished",
            ssh_private_key: "PRIVATE-KEY-PLACEHOLDER",
            timeout_seconds: 60,
            poll_interval_seconds: 15,
          },
          context,
        ),
      Error,
    );
    assertStringIncludes(err.message, "marker file not present");
  } finally {
    p.restore();
    a.restore();
  }
});

Deno.test("strict checking ignores keys listed for another host", async () => {
  const a = api(() => ok(rawServer()));
  const p = probe({});
  try {
    const { context } = createModelTestContext({
      globalArgs: GLOBALS,
      storedResources: STORED,
    });
    await assertRejects(
      () =>
        model.methods.wait_ready.execute(
          {
            host_key_policy: "strict",
            known_hosts: `198.51.100.99 ${KEY_LINE}`,
            port: 22,
            ssh_user: "root",
            timeout_seconds: 600,
            poll_interval_seconds: 15,
          },
          context,
        ),
      Error,
      "no entry for 192.0.2.10",
    );
  } finally {
    p.restore();
    a.restore();
  }
});

Deno.test("global arguments reject unknown fields", () => {
  // Method arguments stay non-strict: swamp merges global arguments into them.
  assertEquals(
    model.globalArguments.safeParse({ ...GLOBALS, extra: true }).success,
    false,
  );
});

Deno.test("accept-new enforces keys recorded by an earlier readiness run", async () => {
  const a = api(() => ok(rawServer()));
  const p = probe({
    keyLine:
      "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDifferentKey0000000000000000",
  });
  try {
    const { context } = createModelTestContext({
      globalArgs: GLOBALS,
      storedResources: {
        ...STORED,
        "node-1-readiness": {
          server_id: 501,
          hostname: "node-1",
          address: "192.0.2.10",
          port: 22,
          ssh_banner: "SSH-2.0-OpenSSH_9.6",
          host_key_policy: "accept-new",
          host_keys: [],
          known_hosts: [`192.0.2.10 ${KEY_LINE}`],
          api_status: "deployed",
          started_at: "2026-01-01T00:00:00Z",
          ready_at: "2026-01-01T00:01:00Z",
          waited_seconds: 60,
        },
      },
    });
    await assertRejects(
      () =>
        model.methods.wait_ready.execute(
          {
            host_key_policy: "accept-new",
            port: 22,
            ssh_user: "root",
            timeout_seconds: 600,
            poll_interval_seconds: 15,
          },
          context,
        ),
      Error,
      "mismatch",
    );
  } finally {
    p.restore();
    a.restore();
  }
});

Deno.test("delete refuses an id other than the recorded server", async () => {
  const a = api(() => gone());
  try {
    const { context, getWrittenResources } = createModelTestContext({
      globalArgs: GLOBALS,
      storedResources: STORED,
    });
    await assertRejects(
      () =>
        model.methods.delete.execute(
          { id: 999, confirm_hostname: "node-1" },
          context,
        ),
      Error,
      "not this model's recorded server 501",
    );
    assertEquals(a.calls.length, 0);
    assertEquals(getWrittenResources().length, 0);
  } finally {
    a.restore();
  }
});

Deno.test("delete defaults to the recorded server id", async () => {
  let deleted = false;
  const a = api((method) => {
    if (method === "DELETE") {
      deleted = true;
      return new Response(null, { status: 204 });
    }
    return deleted ? gone() : ok(rawServer());
  });
  try {
    const { context } = createModelTestContext({
      globalArgs: GLOBALS,
      storedResources: STORED,
    });
    await model.methods.delete.execute({ confirm_hostname: "node-1" }, context);
    const del = a.calls.find((c) => c.method === "DELETE");
    assertEquals(del?.url.pathname.endsWith("/servers/501"), true);
  } finally {
    a.restore();
  }
});

Deno.test("delete with no recorded server refuses before any API call", async () => {
  const a = api(() => gone());
  try {
    const { context, getWrittenResources } = createModelTestContext({
      globalArgs: GLOBALS,
    });
    await assertRejects(
      () =>
        model.methods.delete.execute(
          { id: 777, confirm_hostname: "node-1" },
          context,
        ),
      Error,
      "no record",
    );
    assertEquals(a.calls.length, 0);
    assertEquals(getWrittenResources().length, 0);
  } finally {
    a.restore();
  }
});

Deno.test("delete fails when the server is still returned after 60s", async () => {
  const a = api((method) =>
    method === "DELETE" ? new Response(null, { status: 204 }) : ok(rawServer())
  );
  try {
    const { context } = createModelTestContext({
      globalArgs: GLOBALS,
      storedResources: STORED,
    });
    await assertRejects(
      () =>
        model.methods.delete.execute({ confirm_hostname: "node-1" }, context),
      Error,
      "still returned",
    );
  } finally {
    a.restore();
  }
});

Deno.test("create does not adopt a recorded id now in another project", async () => {
  const a = api((method, url) => {
    if (method === "GET" && url.pathname.endsWith("/servers/501")) {
      return ok(rawServer({ project: { id: 2002 } }));
    }
    if (method === "GET" && url.pathname.endsWith("/projects/1001/servers")) {
      return ok([rawServer({ id: 503 })]);
    }
    return null;
  });
  try {
    const { context, getWrittenResources } = createModelTestContext({
      globalArgs: GLOBALS,
      storedResources: STORED,
    });
    await model.methods.create.execute({}, context);
    assertEquals(a.calls.some((c) => c.method === "POST"), false);
    assertEquals((getWrittenResources()[0].data as { id: number }).id, 503);
  } finally {
    a.restore();
  }
});

Deno.test("create does not adopt a recorded id renamed to another hostname", async () => {
  const a = api((method, url) => {
    if (method === "GET" && url.pathname.endsWith("/servers/501")) {
      return ok(rawServer({ hostname: "renamed" }));
    }
    if (method === "GET" && url.pathname.endsWith("/projects/1001/servers")) {
      return ok([]);
    }
    if (method === "POST") return ok(rawServer({ id: 504 }), 201);
    return null;
  });
  try {
    const { context, getWrittenResources } = createModelTestContext({
      globalArgs: GLOBALS,
      storedResources: STORED,
    });
    await model.methods.create.execute({}, context);
    assertEquals((getWrittenResources()[0].data as { id: number }).id, 504);
  } finally {
    a.restore();
  }
});

Deno.test("create surfaces a failed order and stores nothing", async () => {
  const a = api((method) => {
    if (method === "GET") return ok([]);
    return new Response(JSON.stringify({ message: "out of stock" }), {
      status: 422,
    });
  });
  try {
    const { context, getWrittenResources } = createModelTestContext({
      globalArgs: GLOBALS,
    });
    await assertRejects(
      () => model.methods.create.execute({}, context),
      Error,
      "out of stock",
    );
    assertEquals(getWrittenResources().length, 0);
  } finally {
    a.restore();
  }
});

Deno.test("get stores the live server under its hostname", async () => {
  const a = api(() => ok(rawServer()));
  try {
    const { context, getWrittenResources } = createModelTestContext({
      globalArgs: GLOBALS,
    });
    await model.methods.get.execute({ id: 501 }, context);
    const written = getWrittenResources();
    assertEquals(written[0].name, "node-1");
    assertEquals((written[0].data as { id: number }).id, 501);
  } finally {
    a.restore();
  }
});

Deno.test("sync without stored state fails without calling the API", async () => {
  const a = api(() => null);
  try {
    const { context } = createModelTestContext({ globalArgs: GLOBALS });
    await assertRejects(
      () => model.methods.sync.execute({}, context),
      Error,
      "No stored state",
    );
    assertEquals(a.calls.length, 0);
  } finally {
    a.restore();
  }
});

Deno.test("wait_ready arguments reject injection in ssh_user and marker_path", () => {
  const schema = model.methods.wait_ready.arguments;
  const base = { host_key_policy: "insecure" };
  for (const ssh_user of ["root;id", "-oProxyCommand=x", "Root", "a b"]) {
    assertEquals(schema.safeParse({ ...base, ssh_user }).success, false);
  }
  for (
    const marker_path of [
      "relative/path",
      "/tmp/$(id)",
      "/tmp/a';id;'",
      "/var/../etc/passwd",
    ]
  ) {
    assertEquals(schema.safeParse({ ...base, marker_path }).success, false);
  }
  assertEquals(
    schema.safeParse({
      ...base,
      marker_path: "/var/lib/cloud/instance/boot-finished",
    }).success,
    true,
  );
});

Deno.test("wait_ready stops at once when ssh-add rejects the key", async () => {
  const a = api(() => ok(rawServer()));
  const p = probe({});
  const prev = setProbeDeps({
    ...p.deps,
    run: (cmd, args, options) =>
      cmd === "ssh-add"
        ? Promise.resolve({ code: 1, stdout: "", stderr: "bad" })
        : p.deps.run(cmd, args, options),
  });
  try {
    const { context } = createModelTestContext({
      globalArgs: GLOBALS,
      storedResources: STORED,
    });
    await assertRejects(
      () =>
        model.methods.wait_ready.execute(
          {
            host_key_policy: "accept-new",
            port: 22,
            ssh_user: "root",
            marker_path: "/var/lib/cloud/instance/boot-finished",
            ssh_private_key: "PRIVATE-KEY-PLACEHOLDER",
            timeout_seconds: 600,
            poll_interval_seconds: 15,
          },
          context,
        ),
      Error,
      "rejected the private key",
    );
    // One poll only: a rejected key is not retried until the deadline.
    assertEquals(a.calls.length, 1);
  } finally {
    setProbeDeps(prev);
    p.restore();
    a.restore();
  }
});

Deno.test("cycleOf maps the API's pricing units", () => {
  assertEquals(cycleOf("Hourly"), "hourly");
  assertEquals(cycleOf("1 month"), "monthly");
  assertEquals(cycleOf("Monthly"), "monthly");
  assertEquals(cycleOf("1 year"), "annually");
  assertEquals(cycleOf(undefined), undefined);
  const state = toState(
    rawServer({ pricing: { unit: "1 month" }, termination_date: "None" }),
  );
  assertEquals(state.cycle, "monthly");
  assertEquals(state.termination_date, undefined);
});

Deno.test("a repeat delete of a deleted server keeps it recorded as deleted", async () => {
  const a = api(() => gone());
  try {
    const { context, getWrittenResources } = createModelTestContext({
      globalArgs: GLOBALS,
      storedResources: {
        "node-1": { id: 501, hostname: "node-1", status: "deleted" },
      },
    });
    await model.methods.delete.execute({ confirm_hostname: "node-1" }, context);
    assertEquals(
      (getWrittenResources()[0].data as { status: string }).status,
      "deleted",
    );
  } finally {
    a.restore();
  }
});

Deno.test("adopt by hostname keeps the user data hash only for the same id", async () => {
  const route = (id: number) =>
    api((method, url) => {
      if (method === "GET" && url.pathname.endsWith("/servers/501")) {
        return gone();
      }
      if (method === "GET" && url.pathname.endsWith("/projects/1001/servers")) {
        return ok([rawServer({ id })]);
      }
      return null;
    });
  const stored = {
    "node-1": {
      id: 501,
      hostname: "node-1",
      status: "pending",
      user_data_sha256: "abc123",
    },
  };
  for (const [id, want] of [[501, "abc123"], [777, undefined]] as const) {
    const a = route(id);
    try {
      const { context, getWrittenResources } = createModelTestContext({
        globalArgs: GLOBALS,
        storedResources: stored,
      });
      await model.methods.create.execute({}, context);
      const data = getWrittenResources()[0].data as Record<string, unknown>;
      assertEquals(data.user_data_sha256, want);
    } finally {
      a.restore();
    }
  }
});

/**
 * Global arguments as swamp hands them over when some definition inputs were
 * not given: reading an unresolved field throws, so a method must not touch it.
 */
function partialGlobals(given: Record<string, unknown>) {
  const target: Record<string, unknown> = { ...given };
  for (const field of ["project_id", "plan", "region", "image", "cycle"]) {
    if (field in given) continue;
    Object.defineProperty(target, field, {
      enumerable: true,
      get() {
        throw new Error(`Unresolved expression in globalArguments.${field}`);
      },
    });
  }
  return target;
}

Deno.test("delete needs only the hostname and guards on the recorded project", async () => {
  let deleted = false;
  const a = api((method) => {
    if (method === "DELETE") {
      deleted = true;
      return new Response(null, { status: 204 });
    }
    return deleted ? gone() : ok(rawServer());
  });
  try {
    const { context, getWrittenResources } = createModelTestContext({
      globalArgs: partialGlobals({ hostname: "node-1", token: "test-token" }),
      storedResources: {
        "node-1": { ...STORED["node-1"], project_id: 1001 },
      },
    });
    await model.methods.delete.execute({ confirm_hostname: "node-1" }, context);
    assertEquals(
      (getWrittenResources()[0].data as { status: string }).status,
      "deleted",
    );
  } finally {
    a.restore();
  }
});

Deno.test("delete refuses when the live project differs from the recorded one", async () => {
  const a = api((method) => method === "GET" ? ok(rawServer()) : null);
  try {
    const { context } = createModelTestContext({
      // The global project matches the live server; the record does not.
      globalArgs: GLOBALS,
      storedResources: {
        "node-1": { ...STORED["node-1"], project_id: 2002 },
      },
    });
    await assertRejects(
      () =>
        model.methods.delete.execute({ confirm_hostname: "node-1" }, context),
      Error,
      "not 2002",
    );
    assertEquals(a.calls.some((c) => c.method === "DELETE"), false);
  } finally {
    a.restore();
  }
});

Deno.test("sync, get and wait_ready read only the global arguments they need", async () => {
  const a = api(() => ok(rawServer()));
  try {
    const { context } = createModelTestContext({
      globalArgs: partialGlobals({ hostname: "node-1", token: "test-token" }),
      storedResources: STORED,
    });
    await model.methods.sync.execute({}, context);
    await model.methods.get.execute({ id: 501 }, context);
  } finally {
    a.restore();
  }
});

Deno.test("null optional arguments are treated as not given", async () => {
  const a = api((method) =>
    method === "GET" ? ok([]) : ok(rawServer({ status: "pending" }), 201)
  );
  try {
    const { context } = createModelTestContext({
      globalArgs: {
        ...GLOBALS,
        image: null,
        ssh_keys: null,
        user_data: null,
        os_partition_size: null,
        spot_market: null,
        tags: null,
      },
    });
    await model.methods.create.execute({}, context);
    const post = a.calls.find((c) => c.method === "POST");
    assertEquals(post?.body, {
      plan: "test-plan",
      region: "test-region",
      hostname: "node-1",
      cycle: "hourly",
    });
  } finally {
    a.restore();
  }
  assertEquals(
    model.globalArguments.safeParse({ ...GLOBALS, os_partition_size: null })
      .success,
    true,
  );
});

Deno.test("get and list keep the stored user data hash for the same server", async () => {
  const stored = {
    "node-1": { ...STORED["node-1"], user_data_sha256: "abc123" },
  };
  for (const [id, want] of [[501, "abc123"], [777, undefined]] as const) {
    const a = api((_m, url) =>
      url.pathname.endsWith("/servers")
        ? ok([rawServer({ id })])
        : ok(rawServer({ id }))
    );
    try {
      for (const run of ["get", "list"] as const) {
        const { context, getWrittenResources } = createModelTestContext({
          globalArgs: GLOBALS,
          storedResources: stored,
        });
        if (run === "get") {
          await model.methods.get.execute({ id }, context);
        } else {
          await model.methods.list.execute({}, context);
        }
        const data = getWrittenResources()[0].data as Record<string, unknown>;
        assertEquals(data.user_data_sha256, want, `${run} id ${id}`);
      }
    } finally {
      a.restore();
    }
  }
});

Deno.test("sync keeps a deleted server recorded as deleted", async () => {
  const a = api(() => gone());
  try {
    const { context, getWrittenResources } = createModelTestContext({
      globalArgs: GLOBALS,
      storedResources: {
        "node-1": { id: 501, hostname: "node-1", status: "deleted" },
      },
    });
    await model.methods.sync.execute({}, context);
    assertEquals(
      (getWrittenResources()[0].data as { status: string }).status,
      "deleted",
    );
  } finally {
    a.restore();
  }
});

Deno.test("wait_ready keeps polling through API server errors", async () => {
  let n = 0;
  const a = api(() => {
    n++;
    // A network failure on one poll is retried too.
    if (n === 1) throw new TypeError("fetch failed");
    // Five 500s exhaust one request's retries; the next poll succeeds.
    return n <= 10
      ? new Response('{"code":500,"message":"Something went wrong"}', {
        status: 500,
      })
      : ok(rawServer());
  });
  const run: CommandRunner = (cmd) =>
    Promise.resolve(
      cmd === "ssh-keyscan"
        ? { code: 0, stdout: `192.0.2.10 ${KEY_LINE}\n`, stderr: "" }
        : { code: 0, stdout: "256 SHA256:fake x (ED25519)\n", stderr: "" },
    );
  let t = 0;
  const prev = setProbeDeps({
    run,
    banner: () => Promise.resolve("SSH-2.0-OpenSSH_9.6\r\n"),
    now: () => (t += 1000),
  });
  try {
    const { context, getWrittenResources } = createModelTestContext({
      globalArgs: GLOBALS,
      storedResources: STORED,
    });
    await model.methods.wait_ready.execute(
      {
        host_key_policy: "accept-new",
        port: 22,
        ssh_user: "root",
        timeout_seconds: 600,
        poll_interval_seconds: 1,
      },
      context,
    );
    assertEquals(getWrittenResources().length, 2);
  } finally {
    setProbeDeps(prev);
    a.restore();
  }
});

Deno.test("readiness records only the host keys strict checking verified", async () => {
  const a = api(() => ok(rawServer()));
  const RSA = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABFakeUnpinnedRsaKey0000";
  const p = probe({ keyLine: `${KEY_LINE}\n192.0.2.10 ${RSA}` });
  try {
    const { context, getWrittenResources } = createModelTestContext({
      globalArgs: GLOBALS,
      storedResources: STORED,
    });
    await model.methods.wait_ready.execute(
      {
        host_key_policy: "strict",
        known_hosts: `192.0.2.10 ${KEY_LINE}`,
        port: 22,
        ssh_user: "root",
        timeout_seconds: 600,
        poll_interval_seconds: 15,
      },
      context,
    );
    const data = getWrittenResources().find((r) => r.specName === "readiness")
      ?.data as { known_hosts: string[] };
    assertEquals(data.known_hosts, [`192.0.2.10 ${KEY_LINE}`]);
  } finally {
    p.restore();
    a.restore();
  }
});

Deno.test("sync and wait_ready refuse to rebind a server that moved project", async () => {
  const stored = { "node-1": { ...STORED["node-1"], project_id: 1001 } };
  for (const run of ["sync", "wait_ready"] as const) {
    const a = api(() => ok(rawServer({ project: { id: 2002 } })));
    const p = probe({});
    try {
      const { context, getWrittenResources } = createModelTestContext({
        globalArgs: GLOBALS,
        storedResources: stored,
      });
      await assertRejects(
        () =>
          run === "sync"
            ? model.methods.sync.execute({}, context)
            : model.methods.wait_ready.execute(
              {
                host_key_policy: "accept-new",
                port: 22,
                ssh_user: "root",
                timeout_seconds: 600,
                poll_interval_seconds: 15,
              },
              context,
            ),
        Error,
        "not recording it",
      );
      assertEquals(getWrittenResources().length, 0, run);
    } finally {
      p.restore();
      a.restore();
    }
  }
});

Deno.test("a record without a project never gains one from a refresh", async () => {
  const a = api(() => ok(rawServer({ project: { id: 2002 } })));
  try {
    const { context, getWrittenResources } = createModelTestContext({
      globalArgs: GLOBALS,
      storedResources: STORED,
    });
    await model.methods.sync.execute({}, context);
    const data = getWrittenResources()[0].data as Record<string, unknown>;
    assertEquals(data.project_id, undefined);
  } finally {
    a.restore();
  }
});

Deno.test("without a marker, SSH during deploy is not readiness", async () => {
  let n = 0;
  const a = api(() => {
    n++;
    return ok(
      n <= 2
        ? rawServer({ status: "deploying", state: "provisioning" })
        : rawServer(),
    );
  });
  const p = probe({});
  try {
    const { context, getWrittenResources } = createModelTestContext({
      globalArgs: GLOBALS,
      storedResources: STORED,
    });
    await model.methods.wait_ready.execute(
      {
        host_key_policy: "accept-new",
        port: 22,
        ssh_user: "root",
        timeout_seconds: 600,
        poll_interval_seconds: 15,
      },
      context,
    );
    const data = getWrittenResources().find((r) => r.specName === "readiness")
      ?.data as { api_status: string };
    assertEquals(data.api_status, "deployed");
    assertEquals(n, 3);
  } finally {
    p.restore();
    a.restore();
  }
});

Deno.test("readiness records the address of the final API state, not a deploy address", async () => {
  let n = 0;
  const deployIp = [{ address: "203.0.113.7", type: "primary-ip" }];
  const a = api(() =>
    ok(
      ++n <= 2
        ? rawServer({
          status: "deploying",
          state: "provisioning",
          ip_addresses: deployIp,
        })
        : rawServer(),
    )
  );
  const p = probe({});
  try {
    const { context, getWrittenResources } = createModelTestContext({
      globalArgs: GLOBALS,
      storedResources: STORED,
    });
    await model.methods.wait_ready.execute(
      {
        host_key_policy: "accept-new",
        port: 22,
        ssh_user: "root",
        marker_path: "/var/lib/cloud/instance/boot-finished",
        ssh_private_key: "PRIVATE-KEY-PLACEHOLDER",
        timeout_seconds: 600,
        poll_interval_seconds: 15,
      },
      context,
    );
    const written = getWrittenResources();
    const ready = written.find((r) => r.specName === "readiness")?.data as {
      address: string;
    };
    const state = written.find((r) => r.specName === "state")?.data as {
      public_ipv4: string;
    };
    assertEquals(ready.address, "192.0.2.10");
    assertEquals(state.public_ipv4, "192.0.2.10");
  } finally {
    p.restore();
    a.restore();
  }
});
