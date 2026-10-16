/**
 * Swamp extension model for a Cherry Servers server (bare metal or VPS).
 *
 * The model's global arguments describe one server; methods order it,
 * read it back, wait until it actually answers SSH, and delete it. Stored
 * state is an explicit allowlist of fields: provider responses also carry
 * root and BMC passwords, which are never written to swamp data.
 *
 * @module
 */

import { z } from "npm:zod@4.3.6";
import {
  CherryApiError,
  instanceName,
  listAll,
  request,
  requestExisting,
  sleep,
} from "./_lib/cherry.ts";
import {
  type BannerReader,
  checkHostKeys,
  checkMarker,
  type CommandRunner,
  denoBannerReader,
  denoRunner,
  fingerprints,
  type HostKey,
  keysForHost,
  MARKER_RE,
  parseBanner,
  parseHostKeys,
  ProbeConfigError,
  scanHostKeys,
  USER_RE,
} from "./_lib/ssh_probe.ts";

const HOSTNAME_RE = /^(?=.{1,63}$)[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/;
const SLUG_RE = /^[A-Za-z0-9._-]{1,64}$/;

const GlobalArgsSchema = z.strictObject({
  project_id: z.number().int().positive().describe(
    "ID of the Cherry Servers project that owns the server.",
  ),
  hostname: z.string().regex(HOSTNAME_RE).describe(
    "Server hostname; also the identity used to find an existing server in the project.",
  ),
  plan: z.string().regex(SLUG_RE).describe(
    "Plan slug, e.g. a bare-metal or VPS plan from the plans model.",
  ),
  region: z.string().regex(SLUG_RE).describe("Region slug."),
  image: z.string().regex(SLUG_RE).describe("Operating system image slug.")
    .nullish(),
  cycle: z.enum(["hourly", "monthly", "annually"]).describe(
    "Billing cycle. Non-hourly cycles are charged upfront from the account balance.",
  ),
  ssh_keys: z.array(z.number().int().positive()).describe(
    "IDs of SSH keys to install for the root user.",
  ).nullish(),
  user_data: z.string().max(65536).meta({ sensitive: true }).describe(
    "Cloud-init user data or a shell script, as plain text. Never stored; only its SHA-256 is recorded.",
  ).nullish(),
  os_partition_size: z.number().int().positive().describe(
    "Size of the OS partition in GB, leaving the rest of the disk unallocated.",
  ).nullish(),
  spot_market: z.boolean().describe("Order as an interruptible spot server.")
    .nullish(),
  tags: z.record(
    z.string().regex(/^[A-Za-z0-9._-]{1,64}$/),
    z.string().max(255),
  ).describe("Key/value tags attached to the server.").nullish(),
  token: z.string().meta({ sensitive: true }).describe(
    "Cherry Servers API token; overrides CHERRY_AUTH_TOKEN. Wire with a vault.get(...) expression.",
  ).nullish(),
});

/** `T` with null removed from every field; see `withoutNulls`. */
type NoNull<T> = { [K in keyof T]: Exclude<T[K], null> };

type GlobalArgs = NoNull<z.infer<typeof GlobalArgsSchema>>;

const IpSchema = z.strictObject({
  address: z.string(),
  type: z.string(),
  cidr: z.string().optional(),
});

const StateSchema = z.strictObject({
  id: z.number().int(),
  hostname: z.string(),
  project_id: z.number().int().optional(),
  plan: z.string().optional(),
  region: z.string().optional(),
  image: z.string().optional(),
  status: z.string(),
  state: z.string().optional(),
  cycle: z.string().optional(),
  spot_instance: z.boolean().optional(),
  public_ipv4: z.string().optional(),
  private_ipv4: z.string().optional(),
  ip_addresses: z.array(IpSchema).optional(),
  tags: z.record(z.string(), z.string()).optional(),
  created_at: z.string().optional(),
  termination_date: z.string().optional(),
  user_data_sha256: z.string().optional(),
  observed_at: z.string(),
});

/** Stored state of one server. */
export type ServerState = z.infer<typeof StateSchema>;

const ReadinessSchema = z.strictObject({
  server_id: z.number().int(),
  hostname: z.string(),
  address: z.string(),
  port: z.number().int(),
  ssh_banner: z.string(),
  host_key_policy: z.enum(["strict", "accept-new", "insecure"]),
  host_keys: z.array(z.strictObject({ type: z.string(), sha256: z.string() })),
  known_hosts: z.array(z.string()),
  marker_path: z.string().optional(),
  api_status: z.string(),
  api_state: z.string().optional(),
  started_at: z.string(),
  ready_at: z.string(),
  waited_seconds: z.number(),
});

/** Stored readiness evidence for one server. */
export type Readiness = z.infer<typeof ReadinessSchema>;

type Raw = Record<string, unknown>;

function str(v: unknown): string | undefined {
  return typeof v === "string" && v !== "" ? v : undefined;
}

function slugOf(v: unknown): string | undefined {
  if (typeof v === "string") return str(v);
  if (v && typeof v === "object") return str((v as Raw).slug);
  return undefined;
}

/** Maps the API's pricing unit (e.g. `Hourly`, `1 month`) onto a cycle. */
export function cycleOf(unit: string | undefined): string | undefined {
  if (unit === undefined) return undefined;
  const u = unit.toLowerCase();
  if (u.includes("hour")) return "hourly";
  if (u.includes("month")) return "monthly";
  if (u.includes("year") || u.includes("annual")) return "annually";
  return u;
}

/**
 * Maps a raw API server object onto the stored-state allowlist. Fields not
 * named here — including passwords and BMC credentials — are dropped.
 */
export function toState(
  raw: Raw,
  extra: Partial<ServerState> = {},
): ServerState {
  const ips = Array.isArray(raw.ip_addresses)
    ? (raw.ip_addresses as Raw[]).flatMap((ip) => {
      const address = str(ip.address);
      const type = str(ip.type);
      return address && type
        ? [{ address, type, ...(str(ip.cidr) ? { cidr: str(ip.cidr) } : {}) }]
        : [];
    })
    : [];
  const isV4 = (a: string) => /^\d{1,3}(\.\d{1,3}){3}$/.test(a);
  const pub = ips.find((ip) => ip.type === "primary-ip" && isV4(ip.address)) ??
    ips.find((ip) => ip.type === "floating-ip" && isV4(ip.address));
  const priv = ips.find((ip) => ip.type === "private-ip" && isV4(ip.address));
  const project = raw.project as Raw | undefined;
  const pricing = raw.pricing as Raw | undefined;
  const tags = raw.tags && typeof raw.tags === "object" &&
      !Array.isArray(raw.tags)
    ? Object.fromEntries(
      Object.entries(raw.tags as Raw).filter(([, v]) => typeof v === "string"),
    ) as Record<string, string>
    : undefined;
  const state: ServerState = {
    id: Number(raw.id),
    hostname: str(raw.hostname) ?? str(raw.name) ?? String(raw.id),
    project_id: typeof project?.id === "number" ? project.id : undefined,
    plan: slugOf(raw.plan),
    region: slugOf(raw.region),
    image: slugOf(raw.deployed_image) ?? str(raw.image),
    status: str(raw.status) ?? "unknown",
    state: str(raw.state),
    cycle: cycleOf(str(pricing?.unit)),
    spot_instance: typeof raw.spot_instance === "boolean"
      ? raw.spot_instance
      : undefined,
    public_ipv4: pub?.address,
    private_ipv4: priv?.address,
    ip_addresses: ips,
    tags: tags && Object.keys(tags).length > 0 ? tags : undefined,
    created_at: str(raw.created_at),
    termination_date: str(raw.termination_date) === "None"
      ? undefined
      : str(raw.termination_date),
    observed_at: new Date().toISOString(),
    ...extra,
  };
  return StateSchema.parse(
    Object.fromEntries(
      Object.entries(state).filter(([, v]) => v !== undefined),
    ),
  );
}

/**
 * The stored user-data hash to carry onto a fresh read of server `id`: the API
 * never returns user data, so only a record of the same server can supply it.
 */
function keepUserDataSha(
  recorded: ServerState | null,
  id: number,
): Partial<ServerState> {
  return recorded?.id === id && recorded.user_data_sha256
    ? { user_data_sha256: recorded.user_data_sha256 }
    : {};
}

/**
 * Refuses to overwrite a record whose server has since moved to another
 * project or hostname: the recorded project and hostname are what delete
 * guards on, so a refresh must not rebind them. `get` re-adopts deliberately.
 */
function assertSameBinding(stored: ServerState, live: ServerState): void {
  // A record without a project never gains one from a refresh, so delete
  // keeps falling back to the explicit project_id for it.
  if (stored.project_id === undefined) delete live.project_id;
  if (
    live.hostname !== stored.hostname ||
    (stored.project_id !== undefined && live.project_id !== stored.project_id)
  ) {
    throw new Error(
      `Server ${stored.id} is now ${live.hostname} in project ${live.project_id}, not the recorded ${stored.hostname} in project ${stored.project_id}; not recording it. Run get to adopt it deliberately.`,
    );
  }
}

async function sha256Hex(text: string): Promise<string> {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(text),
  );
  return Array.from(new Uint8Array(digest)).map((b) =>
    b.toString(16).padStart(2, "0")
  ).join("");
}

function toBase64(text: string): string {
  const bytes = new TextEncoder().encode(text);
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin);
}

/** Finds servers in the project whose hostname matches exactly. */
async function findByHostname(g: GlobalArgs): Promise<Raw[]> {
  const items = await listAll(`/projects/${g.project_id}/servers`, {
    token: g.token,
    query: { search: g.hostname },
  });
  return items.filter((s) => s.hostname === g.hostname);
}

/** Builds the POST body for a new server from the global arguments. */
export function createBody(g: GlobalArgs): Raw {
  const body: Raw = {
    plan: g.plan,
    region: g.region,
    hostname: g.hostname,
    cycle: g.cycle,
  };
  if (g.image !== undefined) body.image = g.image;
  if (g.ssh_keys !== undefined) body.ssh_keys = g.ssh_keys;
  if (g.user_data !== undefined) body.user_data = toBase64(g.user_data);
  if (g.os_partition_size !== undefined) {
    body.os_partition_size = g.os_partition_size;
  }
  if (g.spot_market !== undefined) body.spot_market = g.spot_market;
  if (g.tags !== undefined) body.tags = g.tags;
  return body;
}

/** Dependencies of wait_ready; replaceable in tests. */
export interface ProbeDeps {
  /** Runs external commands (ssh-keyscan, ssh-keygen, ssh, ssh-agent). */
  run: CommandRunner;
  /** Reads the first line a TCP peer sends. */
  banner: BannerReader;
  /** Current time in milliseconds. */
  now: () => number;
}

let probeDeps: ProbeDeps = {
  run: denoRunner,
  banner: denoBannerReader,
  now: () => Date.now(),
};

/** Replaces wait_ready's dependencies (tests only). Returns the previous set. */
export function setProbeDeps(deps: ProbeDeps): ProbeDeps {
  const previous = probeDeps;
  probeDeps = deps;
  return previous;
}

// deno-lint-ignore no-explicit-any
type Ctx = any;

/**
 * Reads null as undefined, so an optional argument a workflow passes as null
 * (it cannot leave a key out) is treated the same as one never given. Fields
 * are read lazily: swamp fails a method only when it reads a global argument
 * whose expression did not resolve, so the arguments are never enumerated.
 */
export function withoutNulls<T extends object>(o: T): NoNull<T> {
  return new Proxy(o, {
    get(target, key, receiver) {
      const v = Reflect.get(target, key, receiver);
      return v === null ? undefined : v;
    },
  }) as NoNull<T>;
}

const WaitReadyArgs = z.object({
  host_key_policy: z.enum(["strict", "accept-new", "insecure"]).describe(
    "strict: keys must match known_hosts; accept-new: trust on first use, then enforce the recorded keys; insecure: record without enforcing.",
  ),
  known_hosts: z.string().max(16384).describe(
    "Expected host keys in known_hosts or ssh-keyscan format; required for strict.",
  ).nullish(),
  port: z.number().int().min(1).max(65535).default(22).describe(
    "SSH port.",
  ),
  marker_path: z.string().regex(MARKER_RE).refine(
    (p) => !p.split("/").includes(".."),
    "marker_path must not contain ..",
  ).describe(
    "Absolute path of a file whose existence marks first-boot setup as finished.",
  ).nullish(),
  ssh_user: z.string().regex(USER_RE).default("root").describe(
    "User for the marker check.",
  ),
  ssh_private_key: z.string().meta({ sensitive: true }).describe(
    "Private key for the marker check, loaded into a temporary ssh-agent over stdin.",
  ).nullish(),
  timeout_seconds: z.number().int().min(10).max(7200).default(2700).describe(
    "Give up after this many seconds.",
  ),
  poll_interval_seconds: z.number().int().min(1).max(300).default(15)
    .describe("Seconds between polls."),
});

/** Model definition for `@randybias/cherry-servers/servers`. */
export const model = {
  type: "@randybias/cherry-servers/servers",
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
        "Optional global and wait_ready arguments accept null as not given; delete guards on the recorded project; existing attributes are unchanged",
      upgradeAttributes: (old: Record<string, unknown>) => old,
    },
  ],
  globalArguments: GlobalArgsSchema,
  resources: {
    state: {
      description:
        "Server state: id, addresses, status, plan and billing cycle",
      schema: StateSchema,
      lifetime: "infinite" as const,
      garbageCollection: 10,
    },
    readiness: {
      description: "Evidence that the server answers SSH, with its host keys",
      schema: ReadinessSchema,
      lifetime: "infinite" as const,
      garbageCollection: 10,
    },
  },
  methods: {
    create: {
      description:
        "Order the server, or adopt an existing one with the same hostname in the project. Idempotent: a re-run never places a second order. Returns as soon as the order is accepted; use wait_ready to wait for SSH.",
      arguments: z.object({}),
      execute: async (_args: Record<string, never>, context: Ctx) => {
        const g = withoutNulls(context.globalArgs) as GlobalArgs;
        const name = instanceName(g.hostname);
        context.logger.info("Ensuring server {hostname} in project {project}", {
          hostname: g.hostname,
          project: g.project_id,
        });
        const userDataSha = g.user_data === undefined
          ? undefined
          : await sha256Hex(g.user_data);

        // The no-second-order guard is per model: it reads this model's state
        // and the project's server list. Two different models ordering the
        // same hostname at the same moment can still both place an order.
        const stored = await context.readResource(name) as ServerState | null;
        if (stored?.id && stored.status !== "deleted") {
          const live = await request("GET", `/servers/${stored.id}`, {
            token: g.token,
          }) as Raw | null;
          const current = live ? toState(live) : null;
          // Only adopt the recorded id if it is still this hostname in this
          // project; otherwise fall through to the hostname search.
          if (
            live && current?.hostname === g.hostname &&
            current.project_id === g.project_id
          ) {
            context.logger.info("Server {id} already exists; adopting", {
              id: stored.id,
            });
            const handle = await context.writeResource(
              "state",
              name,
              toState(live, { user_data_sha256: stored.user_data_sha256 }),
            );
            return { dataHandles: [handle] };
          }
          if (live) {
            context.logger.warn(
              "Recorded server {id} is {hostname} in project {project}; not adopting it",
              {
                id: stored.id,
                hostname: current?.hostname,
                project: current?.project_id,
              },
            );
          }
        }

        const matches = await findByHostname(g);
        if (matches.length > 1) {
          throw new Error(
            `${matches.length} servers named ${g.hostname} exist in project ${g.project_id}; refusing to guess`,
          );
        }
        if (matches.length === 1) {
          context.logger.info("Adopting existing server {id}", {
            id: matches[0].id,
          });
          const sameAsStored = stored?.id === Number(matches[0].id);
          const handle = await context.writeResource(
            "state",
            name,
            toState(
              matches[0],
              sameAsStored && stored?.user_data_sha256
                ? { user_data_sha256: stored.user_data_sha256 }
                : {},
            ),
          );
          return { dataHandles: [handle] };
        }

        const created = await requestExisting(
          "POST",
          `/projects/${g.project_id}/servers`,
          { token: g.token, body: createBody(g) },
        ) as Raw;
        context.logger.info("Ordered server {id} ({plan}, {cycle})", {
          id: created.id,
          plan: g.plan,
          cycle: g.cycle,
        });
        const handle = await context.writeResource(
          "state",
          name,
          toState(created, {
            project_id: g.project_id,
            ...(userDataSha ? { user_data_sha256: userDataSha } : {}),
          }),
        );
        return { dataHandles: [handle] };
      },
    },

    get: {
      description:
        "READ-ONLY. Fetch a server by ID and store its state. Fails if the server does not exist.",
      arguments: z.object({
        id: z.number().int().positive().describe("Server ID."),
      }),
      execute: async (args: { id: number }, context: Ctx) => {
        const g = withoutNulls(context.globalArgs) as GlobalArgs;
        const live = await requestExisting("GET", `/servers/${args.id}`, {
          token: g.token,
        }) as Raw;
        const recorded = await context.readResource(
          instanceName(str(live.hostname) ?? String(live.id)),
        ) as ServerState | null;
        const state = toState(live, keepUserDataSha(recorded, Number(live.id)));
        context.logger.info("Server {id} is {hostname}, status {status}", {
          id: state.id,
          hostname: state.hostname,
          status: state.status,
        });
        const handle = await context.writeResource(
          "state",
          instanceName(state.hostname),
          state,
        );
        return { dataHandles: [handle] };
      },
    },

    sync: {
      description:
        "READ-ONLY. Refresh stored state from the API; records status not_found instead of failing when the server is gone.",
      arguments: z.object({}),
      execute: async (_args: Record<string, never>, context: Ctx) => {
        const g = withoutNulls(context.globalArgs) as GlobalArgs;
        const name = instanceName(g.hostname);
        const stored = await context.readResource(name) as ServerState | null;
        if (!stored) {
          throw new Error("No stored state; run create or get first");
        }
        const live = await request("GET", `/servers/${stored.id}`, {
          token: g.token,
        }) as Raw | null;
        const state = live
          ? toState(live, { user_data_sha256: stored.user_data_sha256 })
          : StateSchema.parse({
            id: stored.id,
            hostname: stored.hostname,
            project_id: stored.project_id,
            // A server this model deleted stays recorded as deleted.
            status: stored.status === "deleted" ? "deleted" : "not_found",
            observed_at: new Date().toISOString(),
          });
        if (live) assertSameBinding(stored, state);
        context.logger.info("Server {id} status {status}", {
          id: stored.id,
          status: state.status,
        });
        const handle = await context.writeResource("state", name, state);
        return { dataHandles: [handle] };
      },
    },

    list: {
      description:
        "READ-ONLY. List every server in the project and store one state record per hostname.",
      arguments: z.object({}),
      execute: async (_args: Record<string, never>, context: Ctx) => {
        const g = withoutNulls(context.globalArgs) as GlobalArgs;
        const items = await listAll(`/projects/${g.project_id}/servers`, {
          token: g.token,
        });
        context.logger.info("Project {project} has {count} servers", {
          project: g.project_id,
          count: items.length,
        });
        const dataHandles = [];
        for (const item of items) {
          const recorded = await context.readResource(
            instanceName(str(item.hostname) ?? String(item.id)),
          ) as ServerState | null;
          const state = toState(
            item,
            keepUserDataSha(recorded, Number(item.id)),
          );
          dataHandles.push(
            await context.writeResource(
              "state",
              instanceName(state.hostname),
              state,
            ),
          );
        }
        return { dataHandles, result: { count: items.length } };
      },
    },

    wait_ready: {
      description:
        "Wait until the server answers SSH with acceptable host keys and, if marker_path is set, the marker file exists. Does not trust the API's active state, which can lag real boot by several minutes. Stores readiness evidence.",
      arguments: WaitReadyArgs,
      execute: async (
        rawArgs: z.infer<typeof WaitReadyArgs>,
        context: Ctx,
      ) => {
        const args = withoutNulls(rawArgs);
        const g = withoutNulls(context.globalArgs) as GlobalArgs;
        const name = instanceName(g.hostname);
        if (args.host_key_policy === "strict" && !args.known_hosts) {
          throw new Error("host_key_policy strict requires known_hosts");
        }
        if (args.marker_path !== undefined && !args.ssh_private_key) {
          throw new Error("marker_path requires ssh_private_key");
        }
        const expectedAll: HostKey[] = parseHostKeys(args.known_hosts ?? "");
        const stored = await context.readResource(name) as ServerState | null;
        if (!stored?.id) throw new Error("No stored state; run create first");
        // accept-new is trust-on-first-use: keys recorded by an earlier
        // readiness run for this server are enforced as if strict.
        const previous = args.host_key_policy === "accept-new"
          ? await context.readResource(`${name}-readiness`) as Readiness | null
          : null;

        const deps = probeDeps;
        const started = deps.now();
        const deadline = started + args.timeout_seconds * 1000;
        let lastReason = "not polled yet";
        while (deps.now() < deadline) {
          let live: Raw | null;
          try {
            live = await request("GET", `/servers/${stored.id}`, {
              token: g.token,
            }) as Raw | null;
          } catch (e) {
            // One bad poll must not end a wait of up to two hours: no
            // response, a 5xx or a network failure is retried; a 4xx is not.
            const transient = e instanceof CherryApiError
              ? e.status === 0 || e.status >= 500
              : e instanceof TypeError;
            if (!transient) throw e;
            lastReason = e instanceof CherryApiError
              ? `API unavailable (${e.status || "no response"})`
              : "API unreachable";
            context.logger.info("Server {id} not ready: {reason}", {
              id: stored.id,
              reason: lastReason,
            });
            await sleep(args.poll_interval_seconds * 1000);
            continue;
          }
          if (!live) throw new Error(`Server ${stored.id} no longer exists`);
          const state = toState(live, {
            user_data_sha256: stored.user_data_sha256,
          });
          assertSameBinding(stored, state);
          const address = state.public_ipv4;
          if (!address) {
            lastReason = "no public IPv4 assigned yet";
          } else {
            let banner: string | null = null;
            try {
              banner = parseBanner(
                await deps.banner(address, args.port, 5000),
              );
            } catch (e) {
              lastReason = `ssh not answering: ${(e as Error).message}`;
            }
            // Bare metal is installed from a provisioning environment that
            // runs its own sshd. Without a marker check, SSH counts only once
            // the API has finished deploying.
            const deploying = state.status === "deploying" ||
              state.state === "provisioning";
            if (banner && args.marker_path === undefined && deploying) {
              lastReason =
                "SSH answers but the API still reports deploying; without marker_path this may be the provisioning environment";
            } else if (banner) {
              const observed = await scanHostKeys(deps.run, address, args.port);
              if (observed.length === 0) {
                lastReason = "ssh answered but keyscan returned no host keys";
                await sleep(args.poll_interval_seconds * 1000);
                continue;
              }
              // A host-key mismatch is a hard failure, not a reason to retry.
              const pinned = previous?.server_id === stored.id &&
                  previous.address === address && previous.port === args.port
                ? parseHostKeys(previous.known_hosts.join("\n"))
                : [];
              const expected = pinned.length > 0
                ? pinned
                : keysForHost(expectedAll, address, args.port);
              if (args.host_key_policy === "strict" && expected.length === 0) {
                throw new Error(
                  `known_hosts has no entry for ${
                    args.port === 22 ? address : `[${address}]:${args.port}`
                  }`,
                );
              }
              const trusted = checkHostKeys(
                observed,
                pinned.length > 0 ? "strict" : args.host_key_policy,
                expected,
              );
              let markerOk = true;
              if (args.marker_path !== undefined) {
                try {
                  markerOk = await checkMarker(deps.run, {
                    host: address,
                    port: args.port,
                    user: args.ssh_user,
                    privateKey: args.ssh_private_key!,
                    hostKeys: trusted,
                    markerPath: args.marker_path,
                  });
                  if (!markerOk) lastReason = "marker file not present yet";
                } catch (e) {
                  // Bad input or a rejected key will not fix itself.
                  if (e instanceof ProbeConfigError) throw e;
                  // First boot can restart sshd or reboot; retry until the deadline.
                  markerOk = false;
                  lastReason = `marker check failed: ${(e as Error).message}`;
                }
              }
              if (markerOk && deps.now() >= deadline) {
                lastReason = "became ready only after the deadline";
                break;
              }
              if (markerOk) {
                const now = deps.now();
                const readiness = ReadinessSchema.parse({
                  server_id: stored.id,
                  hostname: g.hostname,
                  address,
                  port: args.port,
                  ssh_banner: banner,
                  host_key_policy: args.host_key_policy,
                  // Only verified keys are recorded: a key of a type strict
                  // checking ignored must never become trusted later.
                  host_keys: await fingerprints(deps.run, trusted),
                  known_hosts: trusted.map((k) =>
                    `${address} ${k.type} ${k.key}`
                  ),
                  ...(args.marker_path
                    ? { marker_path: args.marker_path }
                    : {}),
                  api_status: state.status,
                  ...(state.state ? { api_state: state.state } : {}),
                  started_at: new Date(started).toISOString(),
                  ready_at: new Date(now).toISOString(),
                  waited_seconds: Math.round((now - started) / 1000),
                });
                const stateHandle = await context.writeResource(
                  "state",
                  name,
                  state,
                );
                const readyHandle = await context.writeResource(
                  "readiness",
                  `${name}-readiness`,
                  readiness,
                );
                return { dataHandles: [stateHandle, readyHandle] };
              }
            } else if (!lastReason.startsWith("ssh not answering")) {
              lastReason = "port open but no SSH banner";
            }
          }
          context.logger.info("Server {id} not ready: {reason}", {
            id: stored.id,
            reason: lastReason,
          });
          await sleep(args.poll_interval_seconds * 1000);
        }
        throw new Error(
          `Server ${stored.id} not ready after ${args.timeout_seconds}s: ${lastReason}`,
        );
      },
    },

    delete: {
      // One definition holds many servers, projects or keys (one record per
      // name). Swamp treats a "delete" kind as deleting the whole model and
      // tombstones every record it holds, so this is declared an action: it
      // marks only the record it deleted.
      kind: "action" as const,
      description:
        "DESTRUCTIVE. Delete this model's recorded server and confirm the API no longer returns it. Refuses unless the live server's hostname and its recorded project both match, and refuses an id other than the recorded one; an already-deleted recorded server is stored as not_found.",
      arguments: z.object({
        id: z.number().int().positive().describe(
          "Server ID; defaults to the recorded server and must match it when both exist.",
        ).optional(),
        confirm_hostname: z.string().describe(
          "Must equal the server's hostname; guards against deleting the wrong server.",
        ),
      }),
      execute: async (
        args: { id?: number; confirm_hostname: string },
        context: Ctx,
      ) => {
        const g = withoutNulls(context.globalArgs) as GlobalArgs;
        const name = instanceName(g.hostname);
        if (args.confirm_hostname !== g.hostname) {
          throw new Error(
            `confirm_hostname ${args.confirm_hostname} does not match this model's hostname ${g.hostname}`,
          );
        }
        // Only a server this model recorded can be deleted; run create, get
        // or list first to record one.
        const stored = await context.readResource(name) as ServerState | null;
        if (!stored) {
          throw new Error(
            "No stored state; this model has no recorded server to delete",
          );
        }
        if (args.id !== undefined && args.id !== stored.id) {
          throw new Error(
            `id ${args.id} is not this model's recorded server ${stored.id}; refusing to delete`,
          );
        }
        const id = stored.id;
        // The guard is the project the server was recorded in, so delete
        // needs only the hostname; project_id is read only for an old record
        // without one.
        const project = stored.project_id ?? g.project_id;
        if (project === undefined) {
          throw new Error(
            "The recorded server has no project; pass project_id to delete it",
          );
        }
        const live = await request("GET", `/servers/${id}`, {
          token: g.token,
        }) as Raw | null;
        if (!live) {
          context.logger.info("Server {id} already gone", { id });
          const handle = await context.writeResource(
            "state",
            name,
            StateSchema.parse({
              id,
              hostname: g.hostname,
              project_id: project,
              // A server this model already deleted stays recorded as deleted.
              status: stored.status === "deleted" ? "deleted" : "not_found",
              observed_at: new Date().toISOString(),
            }),
          );
          return { dataHandles: [handle] };
        }
        const current = toState(live);
        if (current.hostname !== args.confirm_hostname) {
          throw new Error(
            `Server ${id} is named ${current.hostname}, not ${args.confirm_hostname}; refusing to delete`,
          );
        }
        if (current.project_id !== project) {
          throw new Error(
            `Server ${id} is in project ${current.project_id}, not ${project}; refusing to delete`,
          );
        }
        context.logger.info("Deleting server {id} ({hostname})", {
          id,
          hostname: current.hostname,
        });
        await request("DELETE", `/servers/${id}`, { token: g.token });
        for (let i = 0; i < 12; i++) {
          const after = await request("GET", `/servers/${id}`, {
            token: g.token,
          });
          if (after === null) {
            context.logger.info("Server {id} deleted", { id });
            const handle = await context.writeResource(
              "state",
              name,
              StateSchema.parse({
                ...current,
                status: "deleted",
                observed_at: new Date().toISOString(),
              }),
            );
            return { dataHandles: [handle] };
          }
          await sleep(5000);
        }
        throw new Error(
          `Server ${id} still returned by the API 60s after delete`,
        );
      },
    },
  },
};
