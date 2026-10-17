import {
  assert,
  assertEquals,
  assertRejects,
  assertThrows,
} from "jsr:@std/assert@1.0.19";
import { z } from "npm:zod@4.3.6";
import {
  type ArmDeps,
  ArmError,
  type FetchFn,
  isNotFound,
} from "./_lib/arm.ts";
import { GrammarError, resourceInstanceName } from "./_lib/validate.ts";
import {
  buildVmBody,
  createModel,
  type MethodContext,
  model,
  vmUrl,
} from "./azure_vm.ts";

const SUB = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";
const TENANT = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb";
const CLIENT = "cccccccc-cccc-cccc-cccc-cccccccccccc";
const SECRET = "PLACEHOLDER-CLIENT-SECRET";
const RG = "rg-example";
const NAME = "web-1";
const NIC =
  `/subscriptions/${SUB}/resourceGroups/${RG}/providers/Microsoft.Network/networkInterfaces/nic-1`;

const BASE = {
  tenantId: TENANT,
  clientId: CLIENT,
  clientSecret: SECRET,
  subscriptionId: SUB,
  resourceGroup: RG,
  name: NAME,
};

const CREATE = {
  ...BASE,
  location: "eastus2",
  vmSize: "Standard_B2s",
  image: {
    publisher: "Canonical",
    offer: "ubuntu-24_04-lts",
    sku: "server",
    version: "latest",
  },
  adminUsername: "azureuser",
  sshPublicKey: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeKey user@example",
  networkInterfaceId: NIC,
};

interface Reply {
  status: number;
  body: unknown;
}

/** A fetch that answers token requests and delegates ARM requests. */
function armFetch(
  handler: (method: string, url: string, body?: unknown) => Reply,
): { fetch: FetchFn; calls: { method: string; url: string }[] } {
  const calls: { method: string; url: string }[] = [];
  const fetchFn: FetchFn = (input, init) => {
    const url = String(input);
    const method = init?.method ?? "GET";
    calls.push({ method, url });
    if (url.includes("/oauth2/v2.0/token")) {
      return Promise.resolve(
        new Response(JSON.stringify({ access_token: "token-value" }), {
          status: 200,
        }),
      );
    }
    const parsed = typeof init?.body === "string"
      ? JSON.parse(init.body)
      : undefined;
    const reply = handler(method, url, parsed);
    return Promise.resolve(
      new Response(reply.body === null ? "" : JSON.stringify(reply.body), {
        status: reply.status,
      }),
    );
  };
  return { fetch: fetchFn, calls };
}

/** Deps with an advancing clock. */
function deps(fetchFn: FetchFn): ArmDeps {
  let t = 0;
  return {
    fetch: fetchFn,
    now: () => t,
    sleep: (ms: number) => {
      t += ms;
      return Promise.resolve();
    },
  };
}

interface Written {
  specName: string;
  name: string;
  data: Record<string, unknown>;
}

/** Minimal method context recording writes. */
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

/** Reads `sensitive` through optional wrappers. */
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

Deno.test("model contract: empty globals, action delete, resources", () => {
  assertEquals(model.type, "@randybias/azure-vm");
  assert(/^\d{4}\.\d{2}\.\d{2}\.\d+$/.test(model.version));
  assertEquals(model.globalArguments.safeParse({}).success, true);
  assertEquals(
    model.globalArguments.safeParse({ subscriptionId: SUB }).success,
    false,
  );
  for (
    const name of [
      "get",
      "sync",
      "create",
      "start",
      "deallocate",
      "stop",
      "delete",
    ]
  ) {
    assert(name in model.methods, `missing method ${name}`);
  }
  assertEquals(model.methods.delete.kind, "action");
  assertEquals(Object.keys(model.resources).sort(), ["vm"]);
});

Deno.test("schemas are strict and mark the client secret sensitive", () => {
  const shape = (model.methods.delete.arguments as z.ZodObject)
    .shape as Record<string, z.ZodType>;
  assertEquals(isSensitive(shape.clientSecret), true);
  assertEquals(
    model.methods.create.arguments.safeParse({ ...CREATE, extra: 1 }).success,
    false,
  );
  assertEquals(
    model.methods.delete.arguments.safeParse({ ...BASE, extra: 1 }).success,
    false,
  );
});

Deno.test("schemas reject injection in every name", () => {
  for (
    const bad of ["a/b", "a b", "a;b", "$(id)", "a`b`", "a".repeat(65)]
  ) {
    assertEquals(
      model.methods.delete.arguments.safeParse({ ...BASE, name: bad }).success,
      false,
      bad,
    );
  }
  assertEquals(
    model.methods.create.arguments.safeParse({
      ...CREATE,
      networkInterfaceId: "/subscriptions/a/resourceGroups/../x",
    }).success,
    false,
  );
  assertEquals(
    model.methods.create.arguments.safeParse({
      ...CREATE,
      sshPublicKey: 'command="x" ssh-ed25519 AAAA',
    }).success,
    false,
  );
});

Deno.test("buildVmBody never carries a password and pins the NIC", () => {
  const body = buildVmBody(CREATE) as {
    properties: Record<string, Record<string, unknown>>;
  };
  const props = body.properties;
  assertEquals(
    (props.osProfile.linuxConfiguration as Record<string, unknown>)
      .disablePasswordAuthentication,
    true,
  );
  assertEquals("adminPassword" in props.osProfile, false);
  const ssh = (props.osProfile.linuxConfiguration as Record<string, unknown>)
    .ssh as { publicKeys: { path: string; keyData: string }[] };
  assertEquals(ssh.publicKeys[0].path, "/home/azureuser/.ssh/authorized_keys");
  assertEquals(
    (props.networkProfile.networkInterfaces as { id: string }[])[0].id,
    NIC,
  );
  const full = buildVmBody({ ...CREATE, osDiskSizeGb: 64 }) as {
    properties: Record<string, unknown>;
  };
  assertEquals(
    ((full.properties.storageProfile as Record<string, unknown>)
      .osDisk as Record<string, unknown>).diskSizeGB,
    64,
  );
  assertEquals(JSON.stringify(body).includes("password"), false);
});

Deno.test("buildVmBody rejects a bad name, location or key", () => {
  assertThrows(
    () => buildVmBody({ ...CREATE, location: "East US" }),
    GrammarError,
  );
  assertThrows(
    () => buildVmBody({ ...CREATE, sshPublicKey: "not-a-key" }),
    GrammarError,
  );
});

Deno.test("vmUrl pins the API version and target", () => {
  const url = vmUrl(BASE, "&$expand=instanceView");
  assert(url.includes(`/subscriptions/${SUB}/resourceGroups/${RG}`));
  assert(url.includes("/virtualMachines/web-1"));
  assert(url.includes("api-version=2024-07-01"));
  assert(url.endsWith("$expand=instanceView"));
});

Deno.test("create adopts an existing VM and never issues a PUT", async () => {
  const { fetch, calls } = armFetch((method) => {
    if (method === "GET") {
      return {
        status: 200,
        body: {
          id: "vm-1",
          location: "eastus2",
          properties: {
            provisioningState: "Succeeded",
            hardwareProfile: { vmSize: "Standard_B2s" },
          },
        },
      };
    }
    return { status: 500, body: { message: "unexpected" } };
  });
  const m = createModel(deps(fetch));
  const { context, written } = testContext();
  const result = await m.methods.create.execute(CREATE, context);
  assertEquals(calls.some((c) => c.method === "PUT"), false);
  assertEquals(written[0].name, resourceInstanceName(SUB, RG, NAME));
  assertEquals((result.result as { status: string }).status, "present");
});

Deno.test("create builds a new VM and polls to provisioned", async () => {
  let created = false;
  const { fetch, calls } = armFetch((method) => {
    if (method === "PUT") {
      created = true;
      return {
        status: 201,
        body: { id: "vm-1", properties: { provisioningState: "Creating" } },
      };
    }
    if (method === "GET") {
      return created
        ? {
          status: 200,
          body: {
            id: "vm-1",
            properties: {
              provisioningState: "Succeeded",
              hardwareProfile: { vmSize: "Standard_B2s" },
            },
          },
        }
        : { status: 404, body: { code: "ResourceNotFound" } };
    }
    return { status: 200, body: {} };
  });
  const m = createModel(deps(fetch));
  const { context, written } = testContext();
  const result = await m.methods.create.execute(CREATE, context);
  assertEquals(calls.filter((c) => c.method === "PUT").length, 1);
  assertEquals(
    (result.result as { provisioningState: string }).provisioningState,
    "Succeeded",
  );
  assertEquals(written[0].data.status, "present");
});

Deno.test("get fails typed on a missing VM and sync records not_found", async () => {
  const { fetch } = armFetch(() => ({
    status: 404,
    body: { code: "ResourceNotFound", message: "missing" },
  }));
  const m = createModel(deps(fetch));
  const { context, written } = testContext();
  const error = await assertRejects(
    () => m.methods.get.execute(BASE, context),
    ArmError,
  );
  assertEquals(isNotFound(error), true);
  const sync = await m.methods.sync.execute(BASE, context);
  assertEquals((sync.result as { status: string }).status, "not_found");
  assertEquals(written[0].data.status, "not_found");
});

Deno.test("delete is a clean no-op when the VM is already gone", async () => {
  const { fetch, calls } = armFetch(() => ({
    status: 404,
    body: { code: "ResourceNotFound" },
  }));
  const m = createModel(deps(fetch));
  const { context, written } = testContext();
  const result = await m.methods.delete.execute({
    ...BASE,
    timeoutMs: 5000,
    pollIntervalMs: 250,
  }, context);
  assertEquals(calls.some((c) => c.method === "DELETE"), false);
  assertEquals(written[0].data.status, "deleted");
  assertEquals((result.result as { status: string }).status, "deleted");
});

Deno.test("delete deletes and polls until the VM is gone", async () => {
  let deleted = false;
  const { fetch, calls } = armFetch((method) => {
    if (method === "DELETE") {
      deleted = true;
      return { status: 202, body: null };
    }
    return deleted ? { status: 404, body: { code: "ResourceNotFound" } } : {
      status: 200,
      body: { id: "vm-1", properties: { provisioningState: "Succeeded" } },
    };
  });
  const m = createModel(deps(fetch));
  const { context, written } = testContext();
  const result = await m.methods.delete.execute({
    ...BASE,
    timeoutMs: 5000,
    pollIntervalMs: 250,
  }, context);
  assertEquals(calls.some((c) => c.method === "DELETE"), true);
  assertEquals(written[0].data.status, "deleted");
  assertEquals((result.result as { status: string }).status, "deleted");
});

Deno.test("deallocate posts the deallocate action and waits", async () => {
  let deallocated = false;
  const { fetch, calls } = armFetch((method, url) => {
    if (method === "POST") {
      assert(url.includes("/deallocate"), url);
      deallocated = true;
      return { status: 202, body: null };
    }
    return {
      status: 200,
      body: {
        id: "vm-1",
        properties: {
          provisioningState: "Succeeded",
          instanceView: {
            statuses: [{
              code: deallocated
                ? "PowerState/deallocated"
                : "PowerState/running",
            }],
          },
        },
      },
    };
  });
  const m = createModel(deps(fetch));
  const { context } = testContext();
  const result = await m.methods.deallocate.execute(
    { ...BASE, hibernate: false, timeoutMs: 5000, pollIntervalMs: 250 },
    context,
  );
  assertEquals(calls.some((c) => c.method === "POST"), true);
  assertEquals(
    (result.result as { powerState: string }).powerState,
    "deallocated",
  );
});

Deno.test("start is a no-op when the VM is already running", async () => {
  const { fetch, calls } = armFetch(() => ({
    status: 200,
    body: {
      id: "vm-1",
      properties: {
        provisioningState: "Succeeded",
        instanceView: { statuses: [{ code: "PowerState/running" }] },
      },
    },
  }));
  const m = createModel(deps(fetch));
  const { context } = testContext();
  const result = await m.methods.start.execute({
    ...BASE,
    timeoutMs: 5000,
    pollIntervalMs: 250,
  }, context);
  assertEquals(
    calls.some((c) =>
      c.method === "POST" && !c.url.includes("/oauth2/v2.0/token")
    ),
    false,
  );
  assertEquals((result.result as { powerState: string }).powerState, "running");
});

Deno.test("the factory returns an independent model", () => {
  const { fetch } = armFetch(() => ({ status: 200, body: {} }));
  const m = createModel(deps(fetch));
  assertEquals(m.type, model.type);
  assert(m !== model);
  assertEquals(typeof m.methods.create.execute, "function");
});
