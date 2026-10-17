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
  buildRuleBody,
  createModel,
  type MethodContext,
  model,
  ruleMatches,
} from "./azure_nsg.ts";

const SUB = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";
const TENANT = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb";
const CLIENT = "cccccccc-cccc-cccc-cccc-cccccccccccc";
const SECRET = "PLACEHOLDER-CLIENT-SECRET";
const RG = "rg-example";
const NSG = "nsg-1";

const BASE = {
  tenantId: TENANT,
  clientId: CLIENT,
  clientSecret: SECRET,
  subscriptionId: SUB,
  resourceGroup: RG,
  nsgName: NSG,
};

const RULE = {
  ...BASE,
  ruleName: "allow-ssh",
  priority: 100,
  direction: "Inbound" as const,
  access: "Allow" as const,
  protocol: "Tcp" as const,
  sourceAddressPrefixes: ["192.0.2.0/24", "198.51.100.0/24"],
  destinationAddressPrefixes: ["*"],
  sourcePortRanges: ["*"],
  destinationPortRanges: ["22"],
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

Deno.test("model contract: empty globals, action delete, three resources", () => {
  assertEquals(model.type, "@randybias/azure-nsg");
  assertEquals(model.globalArguments.safeParse({}).success, true);
  for (
    const name of [
      "get",
      "sync",
      "ensure_rule",
      "remove_rule",
      "apply_rule_set",
      "delete",
    ]
  ) {
    assert(name in model.methods, `missing method ${name}`);
  }
  assertEquals(model.methods.delete.kind, "action");
  assertEquals(model.methods.ensure_rule.kind, "action");
  assertEquals(model.methods.apply_rule_set.kind, "action");
  assertEquals(Object.keys(model.resources).sort(), ["nsg", "rule", "ruleSet"]);
});

Deno.test("schemas are strict and mark the client secret sensitive", () => {
  const shape = (model.methods.delete.arguments as z.ZodObject)
    .shape as Record<string, z.ZodType>;
  assertEquals(isSensitive(shape.clientSecret), true);
  assertEquals(
    model.methods.ensure_rule.arguments.safeParse({ ...RULE, extra: 1 })
      .success,
    false,
  );
  assertEquals(
    model.methods.delete.arguments.safeParse({ ...BASE, extra: 1 }).success,
    false,
  );
});

Deno.test("schemas reject injection in names, prefixes and ports", () => {
  assertEquals(
    model.methods.delete.arguments.safeParse({ ...BASE, nsgName: "a/b" })
      .success,
    false,
  );
  assertEquals(
    model.methods.ensure_rule.arguments.safeParse({
      ...RULE,
      sourceAddressPrefixes: ["$(id)"],
    }).success,
    false,
  );
  assertEquals(
    model.methods.ensure_rule.arguments.safeParse({
      ...RULE,
      destinationPortRanges: ["70000"],
    }).success,
    false,
  );
  assertEquals(
    model.methods.ensure_rule.arguments.safeParse({ ...RULE, priority: 50 })
      .success,
    false,
  );
});

Deno.test("buildRuleBody and ruleMatches normalize arrays", () => {
  const body = buildRuleBody(RULE) as {
    name: string;
    properties: Record<string, unknown>;
  };
  assertEquals(body.name, "allow-ssh");
  assertEquals(body.properties.priority, 100);
  assertEquals(
    ruleMatches(
      {
        name: "allow-ssh",
        properties: {
          priority: 100,
          direction: "Inbound",
          access: "Allow",
          protocol: "Tcp",
          sourceAddressPrefixes: ["198.51.100.0/24", "192.0.2.0/24"],
          destinationAddressPrefixes: ["*"],
          sourcePortRanges: ["*"],
          destinationPortRanges: ["22"],
        },
      },
      RULE,
    ),
    true,
  );
  assert(
    !ruleMatches({ properties: { priority: 101 } }, RULE),
    "a different priority must not match",
  );
  assertThrows(() => buildRuleBody({ ...RULE, ruleName: "a/b" }), GrammarError);
});

Deno.test("ensure_rule is a no-op when the rule already matches", async () => {
  const { fetch, calls } = armFetch((method) =>
    method === "GET"
      ? { status: 200, body: buildRuleBody(RULE) }
      : { status: 500, body: { message: "unexpected" } }
  );
  const m = createModel(deps(fetch));
  const { context, written } = testContext();
  const result = await m.methods.ensure_rule.execute(RULE, context);
  assertEquals(calls.some((c) => c.method === "PUT"), false);
  assertEquals((result.result as { changed: boolean }).changed, false);
  assertEquals(written[0].specName, "rule");
  assertEquals(written[0].name, `s36-${SUB}-g10-${RG}-n5-${NSG}-c9-allow-ssh`);
});

Deno.test("ensure_rule PUTs when the rule differs", async () => {
  const { fetch, calls } = armFetch((method) =>
    method === "GET"
      ? { status: 200, body: buildRuleBody({ ...RULE, priority: 101 }) }
      : { status: 200, body: buildRuleBody(RULE) }
  );
  const m = createModel(deps(fetch));
  const { context, written } = testContext();
  const result = await m.methods.ensure_rule.execute(RULE, context);
  assertEquals(calls.some((c) => c.method === "PUT"), true);
  assertEquals((result.result as { changed: boolean }).changed, true);
  assertEquals(written[0].data.changed, true);
});

Deno.test("remove_rule is a clean no-op when the rule is gone", async () => {
  const { fetch, calls } = armFetch(() => ({
    status: 404,
    body: { code: "NotFound" },
  }));
  const m = createModel(deps(fetch));
  const { context, written } = testContext();
  const result = await m.methods.remove_rule.execute(
    { ...BASE, ruleName: "allow-ssh" },
    context,
  );
  assertEquals(calls.some((c) => c.method === "DELETE"), false);
  assertEquals((result.result as { changed: boolean }).changed, false);
  assertEquals(written[0].data.status, "not_found");
});

Deno.test("remove_rule deletes when the rule exists", async () => {
  const { fetch, calls } = armFetch((method) =>
    method === "DELETE"
      ? { status: 202, body: null }
      : { status: 200, body: buildRuleBody(RULE) }
  );
  const m = createModel(deps(fetch));
  const { context, written } = testContext();
  const result = await m.methods.remove_rule.execute(
    { ...BASE, ruleName: "allow-ssh" },
    context,
  );
  assertEquals(calls.some((c) => c.method === "DELETE"), true);
  assertEquals((result.result as { changed: boolean }).changed, true);
  assertEquals(written[0].data.status, "deleted");
});

Deno.test("apply_rule_set plans first and only writes when apply is true", async () => {
  const builds = [RULE, { ...RULE, ruleName: "allow-http", priority: 200 }];
  const existing = [
    buildRuleBody(RULE),
    buildRuleBody({ ...RULE, ruleName: "allow-http", priority: 999 }),
    buildRuleBody({ ...RULE, ruleName: "leftover", priority: 400 }),
  ];
  const { fetch, calls } = armFetch((method, url) => {
    if (method === "GET" && url.includes("/securityRules?")) {
      return { status: 200, body: { value: existing } };
    }
    if (method === "PUT") return { status: 200, body: {} };
    return { status: 404, body: {} };
  });
  const m = createModel(deps(fetch));
  const dryRun = testContext();
  const declared = [builds[0], builds[1]];
  const plan = await m.methods.apply_rule_set.execute(
    { ...BASE, rules: declared, apply: false },
    dryRun.context,
  );
  assertEquals((plan.result as { applied: string[] }).applied, []);
  assertEquals(
    calls.some((c) => c.method === "PUT"),
    false,
    "dry run must not write",
  );
  assertEquals(dryRun.written[0].specName, "ruleSet");
  const planned = dryRun.written[0].data as {
    create: string[];
    update: string[];
    unchanged: string[];
    undeclared: string[];
  };
  assertEquals(planned.create, []);
  assertEquals(planned.update, ["allow-http"]);
  assertEquals(planned.unchanged, ["allow-ssh"]);
  assertEquals(planned.undeclared, ["leftover"]);

  const appliedRun = testContext();
  await m.methods.apply_rule_set.execute(
    { ...BASE, rules: [{ ...RULE, priority: 101 }, builds[1]], apply: true },
    appliedRun.context,
  );
  assertEquals(
    calls.filter((c) => c.method === "PUT" && !c.url.includes("/oauth2"))
      .length,
    2,
  );
  assertEquals(
    (appliedRun.written[0].data as { applied: string[] }).applied,
    ["allow-ssh", "allow-http"],
  );
});

Deno.test("get fails typed on a missing NSG and sync records not_found", async () => {
  const { fetch } = armFetch(() => ({
    status: 404,
    body: { code: "NotFound" },
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

Deno.test("delete is a clean no-op when the NSG is already gone", async () => {
  const { fetch, calls } = armFetch(() => ({
    status: 404,
    body: { code: "NotFound" },
  }));
  const m = createModel(deps(fetch));
  const { context, written } = testContext();
  const result = await m.methods.delete.execute(
    { ...BASE, timeoutMs: 5000, pollIntervalMs: 250 },
    context,
  );
  assertEquals(calls.some((c) => c.method === "DELETE"), false);
  assertEquals(written[0].data.status, "deleted");
  assertEquals((result.result as { deleted: boolean }).deleted, false);
});

Deno.test("delete deletes and polls until the NSG is gone", async () => {
  let deleted = false;
  const { fetch, calls } = armFetch((method) => {
    if (method === "DELETE") {
      deleted = true;
      return { status: 202, body: null };
    }
    return deleted ? { status: 404, body: { code: "NotFound" } } : {
      status: 200,
      body: { id: "nsg-1", properties: { provisioningState: "Succeeded" } },
    };
  });
  const m = createModel(deps(fetch));
  const { context, written } = testContext();
  const result = await m.methods.delete.execute(
    { ...BASE, timeoutMs: 5000, pollIntervalMs: 250 },
    context,
  );
  assertEquals(calls.some((c) => c.method === "DELETE"), true);
  assertEquals(written[0].data.status, "deleted");
  assertEquals((result.result as { deleted: boolean }).deleted, true);
});

Deno.test("the factory returns an independent model", () => {
  const { fetch } = armFetch(() => ({ status: 200, body: {} }));
  const m = createModel(deps(fetch));
  assertEquals(m.type, model.type);
  assert(m !== model);
  assertEquals(typeof m.methods.apply_rule_set.execute, "function");
});

Deno.test("instance keys include the NSG and the rule", () => {
  assertEquals(
    resourceInstanceName(SUB, RG, NSG),
    `s36-${SUB}-g10-${RG}-n5-${NSG}`,
  );
});
