/**
 * Swamp extension model for a Cherry Servers SSH public key.
 *
 * Keys are account-wide and referenced by ID when ordering servers. `create`
 * adopts a key whose material already matches, so it is safe to re-run; it
 * refuses when the label is taken by a different key.
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

const KEY_RE =
  /^(ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp(256|384|521)) [A-Za-z0-9+\/=]+( .*)?$/;

const GlobalArgsSchema = z.strictObject({
  label: z.string().min(1).max(64).regex(/^[A-Za-z0-9 ._@-]+$/).describe(
    "Key label; also the identity used to find an existing key.",
  ),
  public_key: z.string().max(16384).regex(KEY_RE).describe(
    "OpenSSH public key line.",
  ),
  token: z.string().meta({ sensitive: true }).describe(
    "Cherry Servers API token; overrides CHERRY_AUTH_TOKEN. Wire with a vault.get(...) expression.",
  ).optional(),
});

type GlobalArgs = z.infer<typeof GlobalArgsSchema>;

const StateSchema = z.strictObject({
  id: z.number().int(),
  label: z.string(),
  fingerprint: z.string().optional(),
  status: z.enum(["present", "not_found", "deleted"]),
  observed_at: z.string(),
});

/** Stored state of one SSH key. */
export type SshKeyState = z.infer<typeof StateSchema>;

/** Returns "type base64" so keys compare equal regardless of comment. */
export function keyMaterial(line: string): string {
  return line.trim().split(/\s+/).slice(0, 2).join(" ");
}

function toState(
  raw: Record<string, unknown>,
  status: SshKeyState["status"] = "present",
): SshKeyState {
  return StateSchema.parse({
    id: Number(raw.id),
    label: String(raw.label ?? raw.id),
    ...(typeof raw.fingerprint === "string"
      ? { fingerprint: raw.fingerprint }
      : {}),
    status,
    observed_at: new Date().toISOString(),
  });
}

// deno-lint-ignore no-explicit-any
type Ctx = any;

/** Model definition for `@randybias/cherry-servers/ssh-keys`. */
export const model = {
  type: "@randybias/cherry-servers/ssh-keys",
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
      description: "SSH key id, label and fingerprint",
      schema: StateSchema,
      lifetime: "infinite" as const,
      garbageCollection: 10,
    },
  },
  methods: {
    create: {
      description:
        "Upload the key, or adopt an existing key with the same material. Idempotent. Fails if the label is used by a different key.",
      arguments: z.object({}),
      execute: async (_args: Record<string, never>, context: Ctx) => {
        const g = context.globalArgs as GlobalArgs;
        const want = keyMaterial(g.public_key);
        const keys = await listAll("/ssh-keys", { token: g.token });
        const same = keys.find((k) =>
          typeof k.key === "string" && keyMaterial(k.key) === want
        );
        if (!same && keys.some((k) => k.label === g.label)) {
          throw new Error(
            `Label ${g.label} is already used by a different key; refusing to overwrite`,
          );
        }
        const raw = same ?? await requestExisting("POST", "/ssh-keys", {
          token: g.token,
          body: { label: g.label, key: g.public_key.trim() },
        }) as Record<string, unknown>;
        context.logger.info(
          same ? "Adopted SSH key {id}" : "Uploaded SSH key {id}",
          { id: raw.id },
        );
        const handle = await context.writeResource(
          "state",
          instanceName(g.label),
          toState(raw),
        );
        return { dataHandles: [handle] };
      },
    },

    sync: {
      description:
        "READ-ONLY. Refresh stored state; records not_found instead of failing when the key is gone.",
      arguments: z.object({}),
      execute: async (_args: Record<string, never>, context: Ctx) => {
        const g = context.globalArgs as GlobalArgs;
        const name = instanceName(g.label);
        const stored = await context.readResource(name) as SshKeyState | null;
        if (!stored) throw new Error("No stored state; run create first");
        const raw = await request("GET", `/ssh-keys/${stored.id}`, {
          token: g.token,
        }) as
          | Record<string, unknown>
          | null;
        const state = raw ? toState(raw) : StateSchema.parse({
          ...stored,
          status: "not_found",
          observed_at: new Date().toISOString(),
        });
        context.logger.info("SSH key {id} status {status}", {
          id: stored.id,
          status: state.status,
        });
        const handle = await context.writeResource("state", name, state);
        return { dataHandles: [handle] };
      },
    },

    list: {
      description:
        "READ-ONLY. List every SSH key on the account and store one record per label.",
      arguments: z.object({}),
      execute: async (_args: Record<string, never>, context: Ctx) => {
        const g = context.globalArgs as GlobalArgs;
        const keys = await listAll("/ssh-keys", { token: g.token });
        context.logger.info("Account has {count} SSH keys", {
          count: keys.length,
        });
        const dataHandles = [];
        for (const k of keys) {
          const state = toState(k);
          dataHandles.push(
            await context.writeResource(
              "state",
              instanceName(state.label),
              state,
            ),
          );
        }
        return { dataHandles, result: { count: keys.length } };
      },
    },

    delete: {
      description:
        "DESTRUCTIVE. Delete this model's recorded key after checking its label matches, and refuse an id other than the recorded one; an already-deleted recorded key is stored as not_found.",
      arguments: z.object({
        id: z.number().int().positive().describe(
          "SSH key ID; defaults to the recorded key and must match it when both exist.",
        ).optional(),
        confirm_label: z.string().describe("Must equal the key's label."),
      }),
      execute: async (
        args: { id?: number; confirm_label: string },
        context: Ctx,
      ) => {
        const g = context.globalArgs as GlobalArgs;
        const name = instanceName(g.label);
        if (args.confirm_label !== g.label) {
          throw new Error(
            `confirm_label ${args.confirm_label} does not match this model's label ${g.label}`,
          );
        }
        // Only a key this model recorded can be deleted.
        const stored = await context.readResource(name) as SshKeyState | null;
        if (!stored) {
          throw new Error(
            "No stored state; this model has no recorded key to delete",
          );
        }
        if (args.id !== undefined && args.id !== stored.id) {
          throw new Error(
            `id ${args.id} is not this model's recorded key ${stored.id}; refusing to delete`,
          );
        }
        const id = stored.id;
        const raw = await request("GET", `/ssh-keys/${id}`, {
          token: g.token,
        }) as
          | Record<string, unknown>
          | null;
        if (!raw) {
          context.logger.info("SSH key {id} already gone", { id });
          const handle = await context.writeResource(
            "state",
            name,
            StateSchema.parse({
              id,
              label: g.label,
              status: stored.status === "deleted" ? "deleted" : "not_found",
              observed_at: new Date().toISOString(),
            }),
          );
          return { dataHandles: [handle] };
        }
        if (raw.label !== args.confirm_label) {
          throw new Error(
            `Key ${id} is labelled ${raw.label}, not ${args.confirm_label}; refusing to delete`,
          );
        }
        context.logger.info("Deleting SSH key {id}", { id });
        await request("DELETE", `/ssh-keys/${id}`, { token: g.token });
        for (let i = 0; i < 6; i++) {
          if (
            await request("GET", `/ssh-keys/${id}`, { token: g.token }) ===
              null
          ) {
            context.logger.info("SSH key {id} deleted", { id });
            const handle = await context.writeResource(
              "state",
              name,
              toState(raw, "deleted"),
            );
            return { dataHandles: [handle] };
          }
          await sleep(2000);
        }
        throw new Error(
          `SSH key ${id} still returned by the API after delete`,
        );
      },
    },
  },
};
