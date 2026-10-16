/**
 * Swamp extension model for a Cherry Servers project.
 *
 * Projects group servers, keys and addresses inside a team. `create` adopts an
 * existing project with the same name, so it is safe to run repeatedly.
 *
 * @module
 */

import { z } from "npm:zod@4.3.6";
import {
  instanceName,
  listAll,
  request,
  requestExisting,
} from "./_lib/cherry.ts";

const GlobalArgsSchema = z.strictObject({
  team_id: z.number().int().positive().describe(
    "ID of the team that owns the project.",
  ),
  name: z.string().min(1).max(64).regex(/^[A-Za-z0-9 ._-]+$/).describe(
    "Project name; also the identity used to find an existing project.",
  ),
  token: z.string().meta({ sensitive: true }).describe(
    "Cherry Servers API token; overrides CHERRY_AUTH_TOKEN. Wire with a vault.get(...) expression.",
  ).optional(),
});

type GlobalArgs = z.infer<typeof GlobalArgsSchema>;

const StateSchema = z.strictObject({
  id: z.number().int(),
  name: z.string(),
  team_id: z.number().int().optional(),
  status: z.enum(["present", "not_found"]),
  observed_at: z.string(),
});

/** Stored state of one project. */
export type ProjectState = z.infer<typeof StateSchema>;

/** Maps a raw API project onto the stored-state allowlist. */
export function toState(
  raw: Record<string, unknown>,
  teamId?: number,
): ProjectState {
  return StateSchema.parse({
    id: Number(raw.id),
    name: String(raw.name ?? raw.id),
    ...(teamId === undefined ? {} : { team_id: teamId }),
    status: "present",
    observed_at: new Date().toISOString(),
  });
}

// deno-lint-ignore no-explicit-any
type Ctx = any;

/** Model definition for `@randybias/cherry-servers/projects`. */
export const model = {
  type: "@randybias/cherry-servers/projects",
  version: "2026.10.16.2",
  upgrades: [
    {
      toVersion: "2026.10.16.2",
      description: "Version bump for the public release; no schema changes",
      upgradeAttributes: (old: Record<string, unknown>) => old,
    },
  ],
  globalArguments: GlobalArgsSchema,
  resources: {
    state: {
      description: "Project id and name",
      schema: StateSchema,
      lifetime: "infinite" as const,
      garbageCollection: 10,
    },
  },
  methods: {
    create: {
      description:
        "Create the project, or adopt an existing one in the team with the same name. Idempotent. Fails if several projects share the name.",
      arguments: z.object({}),
      execute: async (_args: Record<string, never>, context: Ctx) => {
        const g = context.globalArgs as GlobalArgs;
        const existing = (await listAll(`/teams/${g.team_id}/projects`, {
          token: g.token,
        })).filter((p) => p.name === g.name);
        if (existing.length > 1) {
          throw new Error(
            `${existing.length} projects named ${g.name} exist in team ${g.team_id}; refusing to guess`,
          );
        }
        const raw = existing[0] ?? await requestExisting(
          "POST",
          `/teams/${g.team_id}/projects`,
          { token: g.token, body: { name: g.name } },
        ) as Record<string, unknown>;
        context.logger.info(
          existing[0] ? "Adopted project {id}" : "Created project {id}",
          { id: raw.id },
        );
        const handle = await context.writeResource(
          "state",
          instanceName(g.name),
          toState(raw, g.team_id),
        );
        return { dataHandles: [handle] };
      },
    },

    get: {
      description: "READ-ONLY. Fetch a project by ID and store its state.",
      arguments: z.object({
        id: z.number().int().positive().describe("Project ID."),
      }),
      execute: async (args: { id: number }, context: Ctx) => {
        const g = context.globalArgs as GlobalArgs;
        const raw = await requestExisting("GET", `/projects/${args.id}`, {
          token: g.token,
        }) as Record<string, unknown>;
        const state = toState(raw, g.team_id);
        context.logger.info("Project {id} is {name}", {
          id: state.id,
          name: state.name,
        });
        const handle = await context.writeResource(
          "state",
          instanceName(state.name),
          state,
        );
        return { dataHandles: [handle] };
      },
    },

    sync: {
      description:
        "READ-ONLY. Refresh stored state; records not_found instead of failing when the project is gone.",
      arguments: z.object({}),
      execute: async (_args: Record<string, never>, context: Ctx) => {
        const g = context.globalArgs as GlobalArgs;
        const name = instanceName(g.name);
        const stored = await context.readResource(name) as ProjectState | null;
        if (!stored) {
          throw new Error("No stored state; run create or get first");
        }
        const raw = await request("GET", `/projects/${stored.id}`, {
          token: g.token,
        }) as Record<string, unknown> | null;
        const state = raw ? toState(raw, g.team_id) : StateSchema.parse({
          ...stored,
          status: "not_found",
          observed_at: new Date().toISOString(),
        });
        context.logger.info("Project {id} status {status}", {
          id: stored.id,
          status: state.status,
        });
        const handle = await context.writeResource("state", name, state);
        return { dataHandles: [handle] };
      },
    },

    list: {
      description:
        "READ-ONLY. List every project in the team and store one state record per name.",
      arguments: z.object({}),
      execute: async (_args: Record<string, never>, context: Ctx) => {
        const g = context.globalArgs as GlobalArgs;
        const items = await listAll(`/teams/${g.team_id}/projects`, {
          token: g.token,
        });
        context.logger.info("Team {team} has {count} projects", {
          team: g.team_id,
          count: items.length,
        });
        const dataHandles = [];
        for (const item of items) {
          const state = toState(item, g.team_id);
          dataHandles.push(
            await context.writeResource(
              "state",
              instanceName(state.name),
              state,
            ),
          );
        }
        return { dataHandles, result: { count: items.length } };
      },
    },
  },
};
