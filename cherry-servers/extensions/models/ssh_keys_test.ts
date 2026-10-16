import { assertEquals, assertRejects } from "jsr:@std/assert@1.0.19";
import { createModelTestContext } from "jsr:@swamp-club/swamp-testing@0.20261014.55";
import { setFetch, setSleep } from "./_lib/cherry.ts";
import { keyMaterial, model } from "./ssh_keys.ts";

const PUB =
  "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakePublicKeyForTests0000 user@example.com";
const GLOBALS = { label: "deploy-key", public_key: PUB, token: "test-token" };

function api(route: (method: string, path: string) => Response | null) {
  const calls: { method: string; path: string; body?: unknown }[] = [];
  const prev = setFetch((input, init) => {
    const url = new URL(input);
    const method = init?.method ?? "GET";
    calls.push({
      method,
      path: url.pathname,
      body: init?.body ? JSON.parse(String(init.body)) : undefined,
    });
    const resp = route(method, url.pathname);
    if (!resp) throw new Error(`unrouted ${method} ${url.pathname}`);
    return Promise.resolve(resp);
  });
  const prevSleep = setSleep(() => Promise.resolve());
  return {
    calls,
    restore: () => {
      setFetch(prev);
      setSleep(prevSleep);
    },
  };
}

const ok = (b: unknown, status = 200) =>
  new Response(JSON.stringify(b), { status });
const gone = () => new Response("gone", { status: 404 });

Deno.test("keyMaterial ignores the comment", () => {
  assertEquals(
    keyMaterial(PUB),
    keyMaterial(PUB.replace("user@example.com", "other")),
  );
});

Deno.test("create adopts a key with matching material (idempotent)", async () => {
  const a = api((
    m,
  ) => (m === "GET"
    ? ok([{ id: 9, label: "old-label", key: PUB.replace("user@", "x@") }])
    : null)
  );
  try {
    const { context, getWrittenResources } = createModelTestContext({
      globalArgs: GLOBALS,
    });
    await model.methods.create.execute({}, context);
    assertEquals(a.calls.some((c) => c.method === "POST"), false);
    assertEquals((getWrittenResources()[0].data as { id: number }).id, 9);
  } finally {
    a.restore();
  }
});

Deno.test("create uploads a new key", async () => {
  const a = api((
    m,
  ) => (m === "GET"
    ? ok([])
    : ok({ id: 10, label: "deploy-key", fingerprint: "aa:bb" }, 201))
  );
  try {
    const { context, getWrittenResources } = createModelTestContext({
      globalArgs: GLOBALS,
    });
    await model.methods.create.execute({}, context);
    assertEquals(a.calls.find((c) => c.method === "POST")?.body, {
      label: "deploy-key",
      key: PUB,
    });
    assertEquals(
      (getWrittenResources()[0].data as { fingerprint: string }).fingerprint,
      "aa:bb",
    );
  } finally {
    a.restore();
  }
});

Deno.test("create refuses a label held by a different key", async () => {
  const a = api(() =>
    ok([{ id: 9, label: "deploy-key", key: "ssh-ed25519 AAAAOther" }])
  );
  try {
    const { context } = createModelTestContext({ globalArgs: GLOBALS });
    await assertRejects(
      () => model.methods.create.execute({}, context),
      Error,
      "different key",
    );
  } finally {
    a.restore();
  }
});

Deno.test("delete checks the label, deletes and verifies", async () => {
  let deleted = false;
  const a = api((m) => {
    if (m === "DELETE") {
      deleted = true;
      return new Response(null, { status: 204 });
    }
    return deleted ? gone() : ok({ id: 9, label: "deploy-key" });
  });
  try {
    const { context, getWrittenResources } = createModelTestContext({
      globalArgs: GLOBALS,
      storedResources: STORED_KEY,
    });
    await model.methods.delete.execute(
      { id: 9, confirm_label: "deploy-key" },
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

Deno.test("delete refuses a key whose live label differs", async () => {
  const a = api((
    m,
  ) => (m === "GET" ? ok({ id: 9, label: "someone-else" }) : null));
  try {
    const { context } = createModelTestContext({
      globalArgs: GLOBALS,
      storedResources: STORED_KEY,
    });
    await assertRejects(
      () =>
        model.methods.delete.execute(
          { id: 9, confirm_label: "deploy-key" },
          context,
        ),
      Error,
      "refusing",
    );
    assertEquals(a.calls.some((c) => c.method === "DELETE"), false);
  } finally {
    a.restore();
  }
});

Deno.test("public_key must be an OpenSSH public key line", () => {
  for (
    const public_key of [
      "-----BEGIN OPENSSH PRIVATE KEY-----",
      "ssh-ed25519",
      "rm -rf /",
    ]
  ) {
    assertEquals(
      model.globalArguments.safeParse({ ...GLOBALS, public_key }).success,
      false,
    );
  }
});

const STORED_KEY = {
  "deploy-key": {
    id: 9,
    label: "deploy-key",
    status: "present",
    observed_at: "2026-01-01T00:00:00Z",
  },
};

Deno.test("sync refreshes a present key", async () => {
  const a = api(() => ok({ id: 9, label: "deploy-key", fingerprint: "fp" }));
  try {
    const { context, getWrittenResources } = createModelTestContext({
      globalArgs: GLOBALS,
      storedResources: STORED_KEY,
    });
    await model.methods.sync.execute({}, context);
    const data = getWrittenResources()[0].data as Record<string, unknown>;
    assertEquals(data.status, "present");
    assertEquals(data.fingerprint, "fp");
    assertEquals(a.calls[0].path, "/v1/ssh-keys/9");
  } finally {
    a.restore();
  }
});

Deno.test("sync records not_found when the key is gone", async () => {
  const a = api(() => gone());
  try {
    const { context, getWrittenResources } = createModelTestContext({
      globalArgs: GLOBALS,
      storedResources: STORED_KEY,
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

Deno.test("list stores one record per key and never the key material", async () => {
  const a = api(() =>
    ok([{ id: 9, label: "deploy-key", key: PUB }, { id: 10, label: "ops" }])
  );
  try {
    const { context, getWrittenResources } = createModelTestContext({
      globalArgs: GLOBALS,
    });
    await model.methods.list.execute({}, context);
    const written = getWrittenResources();
    assertEquals(written.map((r) => r.name), ["deploy-key", "ops"]);
    assertEquals(JSON.stringify(written).includes("AAAAC3"), false);
  } finally {
    a.restore();
  }
});

Deno.test("delete of an already-gone recorded key records not_found", async () => {
  const a = api(() => gone());
  try {
    const { context, getWrittenResources } = createModelTestContext({
      globalArgs: GLOBALS,
      storedResources: STORED_KEY,
    });
    await model.methods.delete.execute(
      { confirm_label: "deploy-key" },
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

Deno.test("delete refuses an id other than the recorded key", async () => {
  const a = api(() => gone());
  try {
    const { context, getWrittenResources } = createModelTestContext({
      globalArgs: GLOBALS,
      storedResources: STORED_KEY,
    });
    await assertRejects(
      () =>
        model.methods.delete.execute(
          { id: 99, confirm_label: "deploy-key" },
          context,
        ),
      Error,
      "not this model's recorded key 9",
    );
    assertEquals(a.calls.length, 0);
    assertEquals(getWrittenResources().length, 0);
  } finally {
    a.restore();
  }
});

Deno.test("delete with no recorded key refuses before any API call", async () => {
  const a = api(() => gone());
  try {
    const { context, getWrittenResources } = createModelTestContext({
      globalArgs: GLOBALS,
    });
    await assertRejects(
      () =>
        model.methods.delete.execute(
          { id: 99, confirm_label: "deploy-key" },
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

Deno.test("delete fails when the key is still returned after delete", async () => {
  const a = api((m) =>
    m === "DELETE"
      ? new Response(null, { status: 204 })
      : ok({ id: 9, label: "deploy-key" })
  );
  try {
    const { context } = createModelTestContext({
      globalArgs: GLOBALS,
      storedResources: STORED_KEY,
    });
    await assertRejects(
      () =>
        model.methods.delete.execute({ confirm_label: "deploy-key" }, context),
      Error,
      "still returned",
    );
  } finally {
    a.restore();
  }
});

Deno.test("sync keeps a deleted record recorded as deleted", async () => {
  const a = api(() => new Response("{}", { status: 404 }));
  try {
    const { context, getWrittenResources } = createModelTestContext({
      globalArgs: GLOBALS,
      storedResources: {
        "deploy-key": { ...STORED_KEY["deploy-key"], status: "deleted" },
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
