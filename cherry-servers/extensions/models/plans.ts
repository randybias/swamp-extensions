/**
 * Swamp extension model for Cherry Servers plans and their live stock.
 *
 * Stock changes within minutes, so plan choice should be made from a fresh
 * `list` run rather than a fixed slug. Prices come from the API as listed;
 * `taxed` says whether VAT is included.
 *
 * @module
 */

import { z } from "npm:zod@4.3.6";
import { instanceName, request } from "./_lib/cherry.ts";

const GlobalArgsSchema = z.strictObject({
  team_id: z.number().int().positive().describe(
    "Team ID; when set, prices are the team's (with its VAT treatment). Requires a token.",
  ).optional(),
  token: z.string().meta({ sensitive: true }).describe(
    "Cherry Servers API token; overrides CHERRY_AUTH_TOKEN. Only needed with team_id.",
  ).optional(),
});

type GlobalArgs = z.infer<typeof GlobalArgsSchema>;

const PlanSchema = z.strictObject({
  slug: z.string(),
  name: z.string().optional(),
  type: z.string().optional(),
  cpu: z.string().optional(),
  cores: z.number().optional(),
  ram_gb: z.number().optional(),
  storage: z.array(z.string()),
  prices: z.record(z.string(), z.number()),
  currency: z.string().optional(),
  taxed: z.boolean().optional(),
  stock: z.record(z.string(), z.number()),
  spot_stock: z.record(z.string(), z.number()),
  observed_at: z.string(),
});

/** One plan with prices per billing unit and stock per region. */
export type Plan = z.infer<typeof PlanSchema>;

type Raw = Record<string, unknown>;

/** Maps a raw API plan onto the stored allowlist. */
export function toPlan(raw: Raw): Plan {
  const specs = (raw.specs ?? {}) as Raw;
  const cpus = (specs.cpus ?? {}) as Raw;
  const memory = (specs.memory ?? {}) as Raw;
  const pricing = Array.isArray(raw.pricing) ? raw.pricing as Raw[] : [];
  const regions = Array.isArray(raw.available_regions)
    ? raw.available_regions as Raw[]
    : [];
  const prices: Record<string, number> = {};
  for (const p of pricing) {
    if (typeof p.unit === "string" && typeof p.price === "number") {
      prices[p.unit.toLowerCase().replace(/\s+/g, "_")] = p.price;
    }
  }
  const stock: Record<string, number> = {};
  const spot: Record<string, number> = {};
  for (const r of regions) {
    if (typeof r.slug !== "string") continue;
    stock[r.slug] = typeof r.stock_qty === "number" ? r.stock_qty : 0;
    spot[r.slug] = typeof r.spot_qty === "number" ? r.spot_qty : 0;
  }
  const storage = Array.isArray(specs.storage)
    ? (specs.storage as Raw[]).map((s) =>
      `${s.count ?? 1}x${s.size ?? "?"}${s.unit ?? ""}${
        s.type ? ` ${s.type}` : ""
      }`
    )
    : [];
  return PlanSchema.parse({
    slug: String(raw.slug),
    ...(typeof raw.name === "string" ? { name: raw.name } : {}),
    ...(typeof raw.type === "string" ? { type: raw.type } : {}),
    ...(typeof cpus.name === "string" ? { cpu: cpus.name } : {}),
    ...(typeof cpus.cores === "number" ? { cores: cpus.cores } : {}),
    ...(typeof memory.total === "number" ? { ram_gb: memory.total } : {}),
    storage,
    prices,
    ...(typeof pricing[0]?.currency === "string"
      ? { currency: pricing[0].currency }
      : {}),
    ...(typeof pricing[0]?.taxed === "boolean"
      ? { taxed: pricing[0].taxed }
      : {}),
    stock,
    spot_stock: spot,
    observed_at: new Date().toISOString(),
  });
}

const ListArgs = z.object({
  type: z.enum(["baremetal", "vps"]).describe("Only plans of this type.")
    .optional(),
  region: z.string().regex(/^[A-Za-z0-9._-]{1,64}$/).describe(
    "Only consider stock in this region.",
  ).optional(),
  min_ram_gb: z.number().min(0).describe("Minimum RAM in GB.").optional(),
  max_hourly_price: z.number().min(0).describe(
    "Maximum hourly price, in the listed currency.",
  ).optional(),
  in_stock_only: z.boolean().default(true).describe(
    "Drop plans with no stock (in the region, if given).",
  ),
});

/** Applies list filters and sorts by hourly price, cheapest first. */
export function filterPlans(
  plans: Plan[],
  f: z.infer<typeof ListArgs>,
): Plan[] {
  return plans.filter((p) => {
    if (f.type && p.type !== f.type) return false;
    if (f.min_ram_gb !== undefined && (p.ram_gb ?? 0) < f.min_ram_gb) {
      return false;
    }
    if (
      f.max_hourly_price !== undefined &&
      (p.prices.hourly ?? Infinity) > f.max_hourly_price
    ) {
      return false;
    }
    if (f.in_stock_only) {
      const qty = f.region
        ? (p.stock[f.region] ?? 0)
        : Object.values(p.stock).reduce((a, b) => a + b, 0);
      if (qty <= 0) return false;
    }
    return true;
  }).sort((a, b) =>
    (a.prices.hourly ?? Infinity) - (b.prices.hourly ?? Infinity)
  );
}

// deno-lint-ignore no-explicit-any
type Ctx = any;

/** Model definition for `@randybias/cherry-servers/plans`. */
export const model = {
  type: "@randybias/cherry-servers/plans",
  version: "2026.10.16.3",
  upgrades: [
    {
      toVersion: "2026.10.16.2",
      description: "Version bump for the public release; no schema changes",
      upgradeAttributes: (old: Record<string, unknown>) => old,
    },
    {
      toVersion: "2026.10.16.3",
      description: "Version bump with the package; no schema changes",
      upgradeAttributes: (old: Record<string, unknown>) => old,
    },
  ],
  globalArguments: GlobalArgsSchema,
  resources: {
    plan: {
      description:
        "A plan's specs, prices per billing unit and stock per region",
      schema: PlanSchema,
      lifetime: "1d" as const,
      garbageCollection: 5,
    },
  },
  methods: {
    list: {
      description:
        "READ-ONLY. Fetch plans with live stock, filter them, and store one record per matching plan, cheapest hourly first. Stock is a snapshot.",
      arguments: ListArgs,
      execute: async (args: z.infer<typeof ListArgs>, context: Ctx) => {
        const g = context.globalArgs as GlobalArgs;
        const raw = g.team_id === undefined
          ? await request("GET", "/plans", { anonymous: true })
          : await request("GET", `/teams/${g.team_id}/plans`, {
            token: g.token,
          });
        if (!Array.isArray(raw)) {
          throw new Error("Plans endpoint did not return a list");
        }
        const plans = filterPlans((raw as Raw[]).map(toPlan), args);
        context.logger.info("{count} of {total} plans match", {
          count: plans.length,
          total: raw.length,
        });
        const dataHandles = [];
        for (const p of plans) {
          dataHandles.push(
            await context.writeResource("plan", instanceName(p.slug), p),
          );
        }
        return {
          dataHandles,
          result: { count: plans.length, slugs: plans.map((p) => p.slug) },
        };
      },
    },
  },
};
