import { assertEquals, assertRejects } from "jsr:@std/assert@1.0.19";
import { createModelTestContext } from "jsr:@swamp-club/swamp-testing@0.20261014.55";
import { setFetch } from "./_lib/cherry.ts";
import { model } from "./projects.ts";

const GLOBALS = { team_id: 300, name: "example-project", token: "test-token" };

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
  return { calls, restore: () => setFetch(prev) };
}

const ok = (b: unknown, status = 200) =>
  new Response(JSON.stringify(b), { status });

Deno.test("create posts a new project when none matches", async () => {
  const a = api((m) =>
    m === "GET"
      ? ok([{ id: 1, name: "other" }])
      : ok({ id: 2, name: "example-project" }, 201)
  );
  try {
    const { context, getWrittenResources } = createModelTestContext({
      globalArgs: GLOBALS,
    });
    await model.methods.create.execute({}, context);
    const post = a.calls.find((c) => c.method === "POST");
    assertEquals(post?.body, { name: "example-project" });
    assertEquals((getWrittenResources()[0].data as { id: number }).id, 2);
  } finally {
    a.restore();
  }
});

Deno.test("create adopts an existing project with the same name (idempotent)", async () => {
  const a = api((
    m,
  ) => (m === "GET" ? ok([{ id: 5, name: "example-project" }]) : null));
  try {
    const { context, getWrittenResources } = createModelTestContext({
      globalArgs: GLOBALS,
    });
    await model.methods.create.execute({}, context);
    assertEquals(a.calls.some((c) => c.method === "POST"), false);
    assertEquals((getWrittenResources()[0].data as { id: number }).id, 5);
  } finally {
    a.restore();
  }
});

Deno.test("create refuses duplicate project names", async () => {
  const a = api(() =>
    ok([{ id: 5, name: "example-project" }, { id: 6, name: "example-project" }])
  );
  try {
    const { context } = createModelTestContext({ globalArgs: GLOBALS });
    await assertRejects(
      () => model.methods.create.execute({}, context),
      Error,
      "refusing",
    );
  } finally {
    a.restore();
  }
});

Deno.test("sync records not_found when the project is gone", async () => {
  const a = api(() => new Response("gone", { status: 404 }));
  try {
    const { context, getWrittenResources } = createModelTestContext({
      globalArgs: GLOBALS,
      storedResources: {
        "example-project": {
          id: 5,
          name: "example-project",
          status: "present",
          observed_at: "2026-01-01T00:00:00Z",
        },
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

Deno.test("names with shell or path metacharacters are rejected", () => {
  for (const name of ["a;b", "a/b", "$(x)", ""]) {
    assertEquals(
      model.globalArguments.safeParse({ ...GLOBALS, name }).success,
      false,
    );
  }
});

Deno.test("get stores a project under its name", async () => {
  const a = api(() => ok({ id: 2, name: "example-project" }));
  try {
    const { context, getWrittenResources } = createModelTestContext({
      globalArgs: GLOBALS,
    });
    await model.methods.get.execute({ id: 2 }, context);
    const written = getWrittenResources();
    assertEquals(written[0].name, "example-project");
    assertEquals((written[0].data as { id: number }).id, 2);
    assertEquals(a.calls[0].path, "/v1/projects/2");
  } finally {
    a.restore();
  }
});

Deno.test("get fails when the project does not exist", async () => {
  const a = api(() => new Response("gone", { status: 404 }));
  try {
    const { context } = createModelTestContext({ globalArgs: GLOBALS });
    await assertRejects(() => model.methods.get.execute({ id: 2 }, context));
  } finally {
    a.restore();
  }
});

Deno.test("list stores one record per project in the team", async () => {
  const a = api(() =>
    ok([{ id: 1, name: "example-project" }, { id: 2, name: "other" }])
  );
  try {
    const { context, getWrittenResources } = createModelTestContext({
      globalArgs: GLOBALS,
    });
    const result = await model.methods.list.execute({}, context);
    assertEquals(getWrittenResources().map((r) => r.name), [
      "example-project",
      "other",
    ]);
    assertEquals(result.result.count, 2);
    assertEquals(a.calls[0].path, "/v1/teams/300/projects");
  } finally {
    a.restore();
  }
});

const STORED_PROJECT = {
  "example-project": {
    id: 5,
    name: "example-project",
    team_id: 300,
    status: "present",
    observed_at: "2026-01-01T00:00:00Z",
  },
};

const gone = () => new Response("{}", { status: 404 });

Deno.test("delete checks the name and emptiness, deletes and verifies", async () => {
  let deleted = false;
  const a = api((m, path) => {
    if (m === "DELETE") {
      deleted = true;
      return new Response(null, { status: 204 });
    }
    if (path === "/v1/projects/5/servers") return ok([]);
    return deleted ? gone() : ok({ id: 5, name: "example-project" });
  });
  try {
    const { context, getWrittenResources } = createModelTestContext({
      globalArgs: GLOBALS,
      storedResources: STORED_PROJECT,
    });
    await model.methods.delete.execute(
      { confirm_name: "example-project" },
      context,
    );
    assertEquals(
      a.calls.filter((c) => c.method === "DELETE").map((c) => c.path),
      ["/v1/projects/5"],
    );
    assertEquals(
      (getWrittenResources()[0].data as { status: string }).status,
      "deleted",
    );
  } finally {
    a.restore();
  }
});

Deno.test("delete refuses a project that still holds servers", async () => {
  const a = api((m, path) => {
    if (m !== "GET") return null;
    if (path === "/v1/projects/5/servers") return ok([{ id: 77 }]);
    return ok({ id: 5, name: "example-project" });
  });
  try {
    const { context } = createModelTestContext({
      globalArgs: GLOBALS,
      storedResources: STORED_PROJECT,
    });
    await assertRejects(
      () =>
        model.methods.delete.execute(
          { confirm_name: "example-project" },
          context,
        ),
      Error,
      "still holds 1 servers",
    );
    assertEquals(a.calls.some((c) => c.method === "DELETE"), false);
  } finally {
    a.restore();
  }
});

Deno.test("delete refuses with no record, before any API call", async () => {
  const a = api(() => null);
  try {
    const { context } = createModelTestContext({ globalArgs: GLOBALS });
    await assertRejects(
      () =>
        model.methods.delete.execute(
          { id: 5, confirm_name: "example-project" },
          context,
        ),
      Error,
      "no recorded project",
    );
    assertEquals(a.calls.length, 0);
  } finally {
    a.restore();
  }
});

Deno.test("delete refuses an id other than the recorded project", async () => {
  const a = api(() => null);
  try {
    const { context } = createModelTestContext({
      globalArgs: GLOBALS,
      storedResources: STORED_PROJECT,
    });
    await assertRejects(
      () =>
        model.methods.delete.execute(
          { id: 6, confirm_name: "example-project" },
          context,
        ),
      Error,
      "not this model's recorded project",
    );
    assertEquals(a.calls.length, 0);
  } finally {
    a.restore();
  }
});

Deno.test("delete refuses a live project whose name differs", async () => {
  const a = api((m) => (m === "GET" ? ok({ id: 5, name: "renamed" }) : null));
  try {
    const { context } = createModelTestContext({
      globalArgs: GLOBALS,
      storedResources: STORED_PROJECT,
    });
    await assertRejects(
      () =>
        model.methods.delete.execute(
          { confirm_name: "example-project" },
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

Deno.test("delete of an already-gone recorded project records not_found", async () => {
  const a = api(() => gone());
  try {
    const { context, getWrittenResources } = createModelTestContext({
      globalArgs: GLOBALS,
      storedResources: STORED_PROJECT,
    });
    await model.methods.delete.execute(
      { confirm_name: "example-project" },
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
