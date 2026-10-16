import { assertEquals, assertRejects } from "jsr:@std/assert@1.0.19";
import { createModelTestContext } from "jsr:@swamp-club/swamp-testing@0.20261014.55";
import { setFetch } from "./_lib/cherry.ts";
import { filterPlans, model, toPlan } from "./plans.ts";

function rawPlan(
  slug: string,
  hourly: number,
  ram: number,
  stock: Record<string, number>,
  type = "baremetal",
) {
  return {
    slug,
    name: slug,
    type,
    specs: {
      cpus: { name: "Example CPU", cores: 8 },
      memory: { total: ram },
      storage: [{ count: 2, size: 500, unit: "GB", type: "SSD" }],
    },
    pricing: [
      { unit: "Hourly", price: hourly, currency: "EUR", taxed: false },
      { unit: "Monthly", price: hourly * 600, currency: "EUR", taxed: false },
      {
        unit: "Spot hourly",
        price: hourly * 0.8,
        currency: "EUR",
        taxed: false,
      },
    ],
    available_regions: Object.entries(stock).map(([slug, stock_qty]) => ({
      slug,
      stock_qty,
      spot_qty: 0,
    })),
  };
}

Deno.test("toPlan normalises prices, stock and specs", () => {
  const p = toPlan(rawPlan("plan-a", 0.3, 64, { "region-a": 3 }));
  assertEquals(p.prices.hourly, 0.3);
  assertEquals(p.prices.spot_hourly, 0.24);
  assertEquals(p.stock["region-a"], 3);
  assertEquals(p.ram_gb, 64);
  assertEquals(p.storage, ["2x500GB SSD"]);
  assertEquals(p.taxed, false);
});

Deno.test("filterPlans drops out-of-stock and sorts cheapest first", () => {
  const plans = [
    toPlan(rawPlan("dear", 1.0, 128, { "region-a": 1 })),
    toPlan(rawPlan("cheap", 0.2, 64, { "region-a": 2 })),
    toPlan(rawPlan("empty", 0.1, 64, { "region-a": 0 })),
    toPlan(rawPlan("elsewhere", 0.15, 64, { "region-b": 5 })),
  ];
  assertEquals(
    filterPlans(plans, { in_stock_only: true, region: "region-a" }).map((p) =>
      p.slug
    ),
    ["cheap", "dear"],
  );
  assertEquals(
    filterPlans(plans, { in_stock_only: true, min_ram_gb: 100 }).map((p) =>
      p.slug
    ),
    ["dear"],
  );
  assertEquals(
    filterPlans(plans, { in_stock_only: false, max_hourly_price: 0.16 }).map((
      p,
    ) => p.slug),
    ["empty", "elsewhere"],
  );
});

Deno.test("list without team_id uses the public endpoint and no token", async () => {
  let auth: string | undefined;
  let path = "";
  const prev = setFetch((input, init) => {
    path = new URL(input).pathname;
    auth = (init?.headers as Record<string, string>)["Authorization"];
    return Promise.resolve(
      new Response(
        JSON.stringify([rawPlan("vps-a", 0.05, 6, { "region-a": 4 }, "vps")]),
      ),
    );
  });
  try {
    const { context, getWrittenResources } = createModelTestContext({
      globalArgs: {},
    });
    await model.methods.list.execute(
      { in_stock_only: true, type: "vps" },
      context,
    );
    assertEquals(path, "/v1/plans");
    assertEquals(auth, undefined);
    assertEquals(getWrittenResources().map((r) => r.name), ["vps-a"]);
  } finally {
    setFetch(prev);
  }
});

Deno.test("list with team_id uses the team endpoint and the token", async () => {
  let auth: string | undefined;
  let path = "";
  const prev = setFetch((input, init) => {
    path = new URL(input).pathname;
    auth = (init?.headers as Record<string, string>)["Authorization"];
    return Promise.resolve(
      new Response(JSON.stringify([rawPlan("bm-a", 0.2, 64, { "r-a": 1 })])),
    );
  });
  try {
    const { context, getWrittenResources } = createModelTestContext({
      globalArgs: { team_id: 300, token: "test-token" },
    });
    await model.methods.list.execute({ in_stock_only: true }, context);
    assertEquals(path, "/v1/teams/300/plans");
    assertEquals(auth, "Bearer test-token");
    assertEquals(getWrittenResources().map((r) => r.name), ["bm-a"]);
  } finally {
    setFetch(prev);
  }
});

Deno.test("list fails on a non-array response", async () => {
  const prev = setFetch(() =>
    Promise.resolve(new Response(JSON.stringify({ plans: [] })))
  );
  try {
    const { context, getWrittenResources } = createModelTestContext({
      globalArgs: {},
    });
    await assertRejects(
      () => model.methods.list.execute({ in_stock_only: true }, context),
      Error,
      "did not return a list",
    );
    assertEquals(getWrittenResources().length, 0);
  } finally {
    setFetch(prev);
  }
});
