/**
 * Swamp extension model for a multi-node k0s cluster.
 *
 * Cluster-scope work that no single node owns — topology planning, join tokens,
 * membership, drain/detach and upgrade ordering — runs through a controller
 * over SSH. Per-node work is delegated to `@randybias/k0s-cluster`; this model
 * holds no kubeconfig.
 *
 * @module
 */

import { z } from "npm:zod@4.3.6";
import {
  plan,
  type PlanInput,
  PlanInputSchema,
  planRemove,
  PlanStep,
} from "./_lib/plan.ts";

const GlobalArgsSchema = z.strictObject({});

const StepSchema = z.strictObject({
  kind: z.string(),
  node: z.string().optional(),
  role: z.string().optional(),
  reason: z.string(),
});

const PlanStateSchema = z.strictObject({
  cluster_name: z.string(),
  operation: z.enum(["create", "add", "remove", "upgrade"]),
  steps: z.array(StepSchema),
  observed_at: z.string(),
});

/** Stored plan of one cluster. */
export type PlanState = z.infer<typeof PlanStateSchema>;

// deno-lint-ignore no-explicit-any
type Ctx = any;

/** Overridable dependencies (SSH, vault, clock) for the action methods. */
export interface Deps {
  /** Current time. */
  now: () => Date;
}

/** The model type, as a top-level literal so swamp can index it statically. */
export const type = "@randybias/k0s-multinode";

/** Builds the model with overridable dependencies. */
export function createModel(deps: Partial<Deps> = {}) {
  const d: Deps = { now: deps.now ?? (() => new Date()) };
  const store = async (
    context: Ctx,
    input: PlanInput,
    operation: PlanState["operation"],
    steps: PlanStep[],
  ) => {
    const handle = await context.writeResource("plan", input.cluster_name, {
      cluster_name: input.cluster_name,
      operation,
      steps,
      observed_at: d.now().toISOString(),
    });
    return { dataHandles: [handle] };
  };

  return {
    type,
    version: "2026.10.17.1",
    description:
      "Plan and operate a multi-node k0s cluster over SSH in the k0sctl style: a short-lived join token per node, ordered controller and worker joins, drain/detach before reset, and safe rolling upgrades. Per-node install, reset and upgrade are delegated to @randybias/k0s-cluster; no join token ever appears in state or output.",
    upgrades: [],
    globalArguments: GlobalArgsSchema,
    resources: {
      plan: {
        description: "Ordered step list for one cluster operation",
        schema: PlanStateSchema,
        lifetime: "infinite" as const,
        garbageCollection: 10,
      },
    },
    methods: {
      plan: {
        description:
          "READ-ONLY. Return the ordered step list for creating, adding to, or upgrading the cluster, enforcing the ordering invariants; the same inputs give the same list. Tokens are never minted here.",
        arguments: PlanInputSchema,
        execute: async (
          args: z.input<typeof PlanInputSchema>,
          context: Ctx,
        ) => {
          const input = PlanInputSchema.parse(args);
          const operation = input.target_version
            ? "upgrade" as const
            : input.observed.length > 0
            ? "add" as const
            : "create" as const;
          return await store(context, input, operation, plan(input));
        },
      },
      plan_remove: {
        description:
          "READ-ONLY. Return the drain -> detach -> reset step list for removing one node, refusing a detach that would lose etcd quorum without confirm.",
        arguments: PlanInputSchema.extend({
          node: z.string().describe("Name of the node to remove."),
        }),
        execute: async (
          args: z.input<typeof PlanInputSchema> & { node: string },
          context: Ctx,
        ) => {
          const input = PlanInputSchema.parse(args);
          return await store(
            context,
            input,
            "remove",
            planRemove(input, args.node),
          );
        },
      },
    },
  };
}

/** Model definition for `@randybias/k0s-multinode`. */
export const model = createModel();
