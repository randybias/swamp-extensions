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
  sleep,
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
  status: z.enum(["present", "not_found", "deleted"]),
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
  version: "2026.10.16.3",
  upgrades: [
    {
      toVersion: "2026.10.16.2",
      description: "Version bump for the public release; no schema changes",
      upgradeAttributes: (old: Record<string, unknown>) => old,
    },
    {
      toVersion: "2026.10.16.3",
      description:
        "Adds delete and the deleted status; existing attributes are unchanged",
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

    delete: {
      description:
        "DESTRUCTIVE. Delete this model's recorded project and confirm the API no longer returns it. Refuses unless the live project's name matches and it holds no servers, and refuses an id other than the recorded one; an already-deleted recorded project is stored as not_found.",
      arguments: z.object({
        id: z.number().int().positive().describe(
          "Project ID; defaults to the recorded project and must match it when both exist.",
        ).optional(),
        confirm_name: z.string().describe("Must equal the project's name."),
      }),
      execute: async (
        args: { id?: number; confirm_name: string },
        context: Ctx,
      ) => {
        const g = context.globalArgs as GlobalArgs;
        const name = instanceName(g.name);
        if (args.confirm_name !== g.name) {
          throw new Error(
            `confirm_name ${args.confirm_name} does not match this model's name ${g.name}`,
          );
        }
        // Only a project this model recorded can be deleted.
        const stored = await context.readResource(name) as ProjectState | null;
        if (!stored) {
          throw new Error(
            "No stored state; this model has no recorded project to delete",
          );
        }
        if (args.id !== undefined && args.id !== stored.id) {
          throw new Error(
            `id ${args.id} is not this model's recorded project ${stored.id}; refusing to delete`,
          );
        }
        const id = stored.id;
        const raw = await request("GET", `/projects/${id}`, {
          token: g.token,
        }) as Record<string, unknown> | null;
        if (!raw) {
          context.logger.info("Project {id} already gone", { id });
          const handle = await context.writeResource(
            "state",
            name,
            StateSchema.parse({
              ...stored,
              status: stored.status === "deleted" ? "deleted" : "not_found",
              observed_at: new Date().toISOString(),
            }),
          );
          return { dataHandles: [handle] };
        }
        if (raw.name !== args.confirm_name) {
          throw new Error(
            `Project ${id} is named ${raw.name}, not ${args.confirm_name}; refusing to delete`,
          );
        }
        const servers = await listAll(`/projects/${id}/servers`, {
          token: g.token,
        });
        if (servers.length > 0) {
          throw new Error(
            `Project ${id} still holds ${servers.length} servers; refusing to delete`,
          );
        }
        context.logger.info("Deleting project {id}", { id });
        await request("DELETE", `/projects/${id}`, { token: g.token });
        for (let i = 0; i < 6; i++) {
          if (
            await request("GET", `/projects/${id}`, { token: g.token }) ===
              null
          ) {
            context.logger.info("Project {id} deleted", { id });
            const handle = await context.writeResource(
              "state",
              name,
              StateSchema.parse({
                ...toState(raw, g.team_id),
                status: "deleted",
              }),
            );
            return { dataHandles: [handle] };
          }
          await sleep(2000);
        }
        throw new Error(`Project ${id} still returned by the API after delete`);
      },
    },
  },
};
