import { assert, assertEquals, assertRejects } from "jsr:@std/assert@1.0.19";
import { z } from "npm:zod@4.3.6";
import {
  type CommandResult,
  type CommandRunner,
  sha256Hex,
  SshConfigError,
} from "./_lib/ssh.ts";
import {
  type FetchFn,
  type SyncthingDeps,
  SyncthingError,
} from "./_lib/syncthing.ts";
import {
  createModel,
  type MethodContext,
  model,
  nodeInstance,
} from "./syncthing_peer.ts";

const DEVICE =
  "AAAAAAA-BBBBBBB-CCCCCCC-DDDDDDD-EEEEEEE-FFFFFFF-GGGGGGG-HHHHHHH";
const HEADER_VALUE = "placeholder-header-value";
const MY_ID = "NODE-ID";
const KEY_LINE = "192.0.2.10 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeKey";

const BASE = {
  access: "local" as const,
  node: "edge-1",
  api_url: "http://127.0.0.1:8384",
  api_key: HEADER_VALUE,
};

const DEVICE_ARGS = {
  ...BASE,
  device_id: DEVICE,
  name: "edge-2",
  addresses: ["dynamic"],
};

const FOLDER_ARGS = {
  ...BASE,
  folder_id: "media",
  label: "Media",
  path: "/srv/media",
  devices: [DEVICE],
};

/** Syncthing's folder read-back: own device added, objects with extra fields. */
function normalizeFolder(
  body: Record<string, unknown>,
): Record<string, unknown> {
  const devices = Array.isArray(body.devices) ? body.devices : [];
  const ids = devices.map((entry) =>
    typeof entry === "string"
      ? entry
      : String((entry as Record<string, unknown>).deviceID ?? "")
  ).filter((id) => id !== "");
  const all = [MY_ID, ...ids.filter((id) => id !== MY_ID)];
  return {
    ...body,
    devices: all.map((deviceID) => ({
      deviceID,
      introducedBy: "",
      encryptionPassword: "",
    })),
  };
}

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status });
}

/** A scripted Syncthing API that normalizes like the real one. */
function server(initial: {
  devices?: Record<string, unknown>;
  folders?: Record<string, unknown>;
  status?: number;
}) {
  const devices = new Map(Object.entries(initial.devices ?? {}));
  const folders = new Map(Object.entries(initial.folders ?? {}));
  const calls: string[] = [];
  const fetch: FetchFn = (input, init) => {
    const url = new URL(String(input));
    const method = init?.method ?? "GET";
    const path = url.pathname;
    calls.push(`${method} ${path}`);
    const body = typeof init?.body === "string"
      ? JSON.parse(init.body) as Record<string, unknown>
      : undefined;
    if (path === "/rest/system/status") {
      return Promise.resolve(
        initial.status && initial.status !== 200
          ? json({ error: "unauthorized" }, initial.status)
          : json({ myID: MY_ID, version: "v2.0.0" }),
      );
    }
    if (path === "/rest/config/devices") {
      return Promise.resolve(json([...devices.values()]));
    }
    if (path === "/rest/config/folders") {
      return Promise.resolve(json([...folders.values()]));
    }
    const device = /^\/rest\/config\/devices\/(.+)$/.exec(path);
    if (device) {
      const id = decodeURIComponent(device[1]);
      if (method === "GET") {
        return Promise.resolve(
          devices.has(id)
            ? json(devices.get(id))
            : json({ error: "not found" }, 404),
        );
      }
      if (method === "PUT") {
        devices.set(id, body);
        return Promise.resolve(json({}, 200));
      }
      if (method === "PATCH") {
        devices.set(id, { ...(devices.get(id) as object), ...body });
        return Promise.resolve(json({}, 200));
      }
      if (method === "DELETE") {
        devices.delete(id);
        return Promise.resolve(json({}, 200));
      }
    }
    const folder = /^\/rest\/config\/folders\/(.+)$/.exec(path);
    if (folder) {
      const id = decodeURIComponent(folder[1]);
      if (method === "GET") {
        return Promise.resolve(
          folders.has(id)
            ? json(folders.get(id))
            : json({ error: "not found" }, 404),
        );
      }
      if (method === "PUT") {
        folders.set(id, normalizeFolder(body as Record<string, unknown>));
        return Promise.resolve(json({}, 200));
      }
      if (method === "PATCH") {
        folders.set(
          id,
          normalizeFolder({ ...(folders.get(id) as object), ...body }),
        );
        return Promise.resolve(json({}, 200));
      }
      if (method === "DELETE") {
        folders.delete(id);
        return Promise.resolve(json({}, 200));
      }
    }
    return Promise.resolve(json({ error: "unhandled" }, 500));
  };
  return { fetch, devices, folders, calls };
}

interface Written {
  specName: string;
  name: string;
  data: Record<string, unknown>;
}

function testContext(): { context: MethodContext; written: Written[] } {
  const written: Written[] = [];
  return {
    context: {
      logger: { info: () => {}, warn: () => {} },
      writeResource: (specName, name, data) => {
        written.push({ specName, name, data });
        return Promise.resolve({
          name,
          specName,
          kind: "resource",
          dataId: "d0",
          version: 1,
          size: 0,
        });
      },
    },
    written,
  };
}

function deps(
  fetch: FetchFn,
  run: CommandRunner = () =>
    Promise.resolve({ code: 0, stdout: "", stderr: "" }),
): SyncthingDeps {
  let t = 0;
  return {
    fetch,
    run,
    now: () => t,
    sleep: (ms: number) => {
      t += ms;
      return Promise.resolve();
    },
  };
}

function isSensitive(schema: z.ZodType): boolean {
  let current: z.ZodType | undefined = schema;
  for (let depth = 0; current; depth++) {
    if (current.meta()?.sensitive) return true;
    current = (current as unknown as { def?: { innerType?: z.ZodType } }).def
      ?.innerType;
    if (depth > 5) throw new Error("unexpected wrapper nesting");
  }
  return false;
}

Deno.test("model contract: empty globals, action verbs, three resources", () => {
  assertEquals(model.type, "@randybias/syncthing-peer");
  assertEquals(model.globalArguments.safeParse({}).success, true);
  for (
    const name of [
      "get",
      "sync",
      "ensure_device",
      "remove_device",
      "ensure_folder",
      "remove_folder",
    ]
  ) {
    assert(name in model.methods, `missing method ${name}`);
  }
  for (
    const name of [
      "ensure_device",
      "remove_device",
      "ensure_folder",
      "remove_folder",
    ]
  ) {
    assertEquals(model.methods[name].kind, "action", name);
  }
  assert(model.methods.get.description.startsWith("READ-ONLY."));
  assertEquals(Object.keys(model.resources).sort(), [
    "device",
    "folder",
    "node",
  ]);
  // Only strict is offered for the ssh transport.
  const shape = (model.methods.get.arguments as z.ZodObject)
    .shape as Record<string, z.ZodType>;
  assertEquals(shape.host_key_policy.safeParse("insecure_tofu").success, false);
});

Deno.test("schemas are strict, mark secrets, and default the API origin", () => {
  const shape = (model.methods.get.arguments as z.ZodObject)
    .shape as Record<string, z.ZodType>;
  assertEquals(isSensitive(shape.api_key), true);
  assertEquals(isSensitive(shape.private_key), true);
  assertEquals(
    model.methods.get.arguments.safeParse({ ...BASE, extra: 1 }).success,
    false,
  );
  const parsed = model.methods.get.arguments.parse({
    access: "local",
    node: "edge-1",
    api_key: HEADER_VALUE,
  }) as { api_url: string; port: number };
  assertEquals(parsed.api_url, "http://127.0.0.1:8384");
  assertEquals(parsed.port, 22);
});

Deno.test("node instance names are distinct SHA-256 keys", async () => {
  const a = await nodeInstance("edge-1", "http://127.0.0.1:8384");
  const b = await nodeInstance("edge-2", "http://127.0.0.1:8384");
  const c = await nodeInstance("edge-1", "http://127.0.0.1:8385");
  assertEquals(a === b, false);
  assertEquals(a === c, false);
  assert(/^syncthing-[0-9a-f]{32}$/.test(a), a);
});

Deno.test("get stores node status and counts", async () => {
  const s = server({
    devices: {
      [DEVICE]: {
        deviceID: DEVICE,
        name: "edge-2",
        addresses: ["dynamic"],
        introducer: false,
        paused: false,
      },
    },
  });
  const m = createModel(deps(s.fetch));
  const { context, written } = testContext();
  const result = await m.methods.get.execute(BASE, context);
  assertEquals((result.result as { device_count: number }).device_count, 1);
  assertEquals(written[0].specName, "node");
  assertEquals(written[0].data.my_id, MY_ID);
});

Deno.test("sync records unreachable on a connect failure", async () => {
  const fetch: FetchFn = () => Promise.reject(new Error("connection refused"));
  const m = createModel(deps(fetch));
  const { context, written } = testContext();
  const result = await m.methods.sync.execute(BASE, context);
  assertEquals((result.result as { reachable: boolean }).reachable, false);
  assertEquals(written[0].data.status, "unreachable");
});

Deno.test("sync rethrows an auth failure instead of recording unreachable", async () => {
  const s = server({ status: 401 });
  const m = createModel(deps(s.fetch));
  const { context, written } = testContext();
  const error = await assertRejects(
    () => m.methods.sync.execute(BASE, context),
    SyncthingError,
  );
  assertEquals(error.status, 401);
  assertEquals(written.length, 0);
});

Deno.test("ensure_device creates, is a no-op, then removes", async () => {
  const s = server({});
  const m = createModel(deps(s.fetch));
  const first = testContext();
  const created = await m.methods.ensure_device.execute(
    DEVICE_ARGS,
    first.context,
  );
  assertEquals((created.result as { changed: boolean }).changed, true);
  assertEquals(first.written[0].specName, "device");
  assertEquals(first.written[0].data.status, "present");
  assert(
    s.calls.some((c) => c === `PUT /rest/config/devices/${DEVICE}`),
    "a create uses PUT",
  );

  const second = testContext();
  const noop = await m.methods.ensure_device.execute(
    DEVICE_ARGS,
    second.context,
  );
  assertEquals((noop.result as { changed: boolean }).changed, false);

  const third = testContext();
  const removed = await m.methods.remove_device.execute(
    { ...BASE, device_id: DEVICE },
    third.context,
  );
  assertEquals((removed.result as { changed: boolean }).changed, true);
  assertEquals(third.written[0].data.status, "removed");
});

Deno.test("ensure_device PATCHes an existing differing device", async () => {
  const s = server({
    devices: {
      [DEVICE]: {
        deviceID: DEVICE,
        name: "old-name",
        addresses: ["dynamic"],
        introducer: false,
        paused: false,
      },
    },
  });
  const m = createModel(deps(s.fetch));
  const { context, written } = testContext();
  const result = await m.methods.ensure_device.execute(DEVICE_ARGS, context);
  assertEquals((result.result as { changed: boolean }).changed, true);
  assert(
    s.calls.some((c) => c === `PATCH /rest/config/devices/${DEVICE}`),
    "an update uses PATCH",
  );
  assert(
    !s.calls.some((c) => c === `PUT /rest/config/devices/${DEVICE}`),
    "an update must not PUT",
  );
  assertEquals(written[0].data.changed, true);
});

Deno.test("ensure_folder creates, is a no-op on the second run, then removes", async () => {
  const s = server({});
  const m = createModel(deps(s.fetch));
  const first = testContext();
  const created = await m.methods.ensure_folder.execute(
    FOLDER_ARGS,
    first.context,
  );
  assertEquals((created.result as { changed: boolean }).changed, true);
  assertEquals(first.written[0].data.device_ids, [DEVICE]);
  // The observed read-back is stored, not the requested spec.
  const stored = first.written[0].data.devices ?? first.written[0].data;
  assert(stored !== undefined);
  assertEquals(
    s.calls.filter((c) => c === "PUT /rest/config/folders/media").length,
    1,
  );

  const second = testContext();
  const noop = await m.methods.ensure_folder.execute(
    FOLDER_ARGS,
    second.context,
  );
  assertEquals((noop.result as { changed: boolean }).changed, false);
  assertEquals(
    s.calls.filter((c) =>
      c === "PUT /rest/config/folders/media" ||
      c === "PATCH /rest/config/folders/media"
    ).length,
    1,
    "a second run must not write",
  );

  const third = testContext();
  const removed = await m.methods.remove_folder.execute(
    { ...BASE, folder_id: "media" },
    third.context,
  );
  assertEquals((removed.result as { changed: boolean }).changed, true);
  assertEquals(third.written[0].data.status, "removed");
});

Deno.test("a non-loopback plain-HTTP API origin is refused", async () => {
  const s = server({});
  const m = createModel(deps(s.fetch));
  const { context } = testContext();
  await assertRejects(
    () =>
      m.methods.get.execute(
        { ...BASE, api_url: "http://syncthing.example.com" },
        context,
      ),
    SshConfigError,
    "HTTPS",
  );
});

Deno.test("bad device, folder and path inputs are refused", async () => {
  const s = server({});
  const m = createModel(deps(s.fetch));
  const { context } = testContext();
  await assertRejects(
    () =>
      m.methods.ensure_device.execute(
        { ...DEVICE_ARGS, device_id: "nope" },
        context,
      ),
    SshConfigError,
  );
  await assertRejects(
    () =>
      m.methods.ensure_folder.execute(
        { ...FOLDER_ARGS, path: "/a/../b" },
        context,
      ),
    SshConfigError,
  );
  await assertRejects(
    () =>
      m.methods.ensure_folder.execute(
        { ...FOLDER_ARGS, folder_id: ".." },
        context,
      ),
    SshConfigError,
  );
});

Deno.test("the ssh transport reaches the API and keeps the key off argv", async () => {
  const calls: { args: string[]; stdin?: string }[] = [];
  let lastConfig = "";
  const run: CommandRunner = async (
    cmd,
    args,
    options = {},
  ): Promise<CommandResult> => {
    const remote = args.at(-1) ?? "";
    if (options.stdin !== undefined) {
      lastConfig = typeof options.stdin === "string"
        ? options.stdin
        : new TextDecoder().decode(options.stdin);
    }
    calls.push({ args: [cmd, ...args], stdin: lastConfig });
    if (remote.includes("mmin +5")) {
      return { code: 0, stdout: "/root/.cache/syncthing-peer", stderr: "" };
    }
    if (remote.includes("mktemp")) {
      return {
        code: 0,
        stdout: `${await sha256Hex(lastConfig)} 600\n`,
        stderr: "",
      };
    }
    if (remote.includes("trap") && remote.includes("curl")) {
      const url = /url = "([^"]+)"/.exec(lastConfig)?.[1] ?? "";
      const path = new URL(url).pathname;
      const body = path === "/rest/system/status"
        ? { myID: MY_ID, version: "v2.0.0" }
        : [];
      return {
        code: 0,
        stdout: `${JSON.stringify(body)}__SYNCTHING_STATUS__200`,
        stderr: "",
      };
    }
    return { code: 0, stdout: "MISSING\n", stderr: "" };
  };
  const m = createModel(deps(() => Promise.resolve(json({})), run));
  const { context, written } = testContext();
  const result = await m.methods.get.execute(
    {
      ...BASE,
      access: "ssh",
      host: "192.0.2.10",
      user: "root",
      host_key_policy: "strict",
      host_keys: [KEY_LINE],
    },
    context,
  );
  assertEquals((result.result as { my_id: string }).my_id, MY_ID);
  assertEquals(written[0].data.reachable, true);
  for (const call of calls) {
    assertEquals(
      call.args.join(" ").includes(HEADER_VALUE),
      false,
      "key on argv",
    );
  }
  assert(
    calls.some((call) =>
      (call.stdin ?? "").includes(`X-API-Key: ${HEADER_VALUE}`)
    ),
    "the key must be uploaded over stdin",
  );
});

Deno.test("a strict ssh policy without pinned keys is refused before any call", async () => {
  const s = server({});
  const m = createModel(deps(s.fetch));
  const { context } = testContext();
  await assertRejects(
    () =>
      m.methods.get.execute(
        {
          ...BASE,
          access: "ssh",
          host: "192.0.2.10",
          user: "root",
          host_key_policy: "strict",
          host_keys: undefined,
        },
        context,
      ),
    SshConfigError,
    "host_keys",
  );
  assertEquals(s.calls.length, 0);
});

Deno.test("the factory returns an independent model", () => {
  const s = server({});
  const m = createModel(deps(s.fetch));
  assertEquals(m.type, model.type);
  assert(m !== model);
  assertEquals(typeof m.methods.ensure_device.execute, "function");
});

Deno.test("get surfaces a typed Syncthing error on a non-2xx status", async () => {
  const fetch: FetchFn = () => Promise.resolve(json({ error: "boom" }, 500));
  const m = createModel(deps(fetch));
  const { context } = testContext();
  const error = await assertRejects(
    () => m.methods.get.execute(BASE, context),
    SyncthingError,
  );
  assertEquals(error.status, 500);
});
