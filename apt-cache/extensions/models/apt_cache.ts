/**
 * Model entry point for `@randybias/apt-cache`.
 *
 * One definition serves any server or client: every method takes its SSH
 * target and operands, and state is keyed by the canonical `{user, host,
 * port}`. The HTTPS policy is a required input with no default and there is no
 * silent trust-on-first-use: `host_key_policy` is strict-only and the private
 * key is resolved from a vault reference inside the method.
 *
 * The implementation lives in `_lib/`: `schemas.ts` (argument and state
 * shapes), `remote.ts` (host operations and parsers), `server_install.ts`,
 * `server_methods.ts` and `client_methods.ts` (the method bodies).
 *
 * @module
 */

import { type AptCacheDeps, setDeps } from "./_lib/remote.ts";
import {
  ApplyServerArgsSchema,
  ClientGetArgsSchema,
  ClientStateSchema,
  ConfigureClientArgsSchema,
  GetArgsSchema,
  GlobalArgsSchema,
  InstallServerArgsSchema,
  ObservationSchema,
  RemoveServerArgsSchema,
  RenderSchema,
  RenderServerArgsSchema,
  ServerStateSchema,
  StatsArgsSchema,
  SyncArgsSchema,
  UnconfigureClientArgsSchema,
} from "./_lib/schemas.ts";
import {
  applyServer,
  getServer,
  removeServer,
  renderServer,
  statsServer,
  syncServer,
} from "./_lib/server_methods.ts";
import { installServer } from "./_lib/server_install.ts";
import {
  clientGet,
  configureClient,
  unconfigureClient,
} from "./_lib/client_methods.ts";

export { setDeps };

/** Production model definition. */
export const model = {
  type: "@randybias/apt-cache",
  version: "2026.10.17.1",
  description:
    "Install and configure an Apt-Cacher NG caching proxy on one host and point clients' apt at it over SSH, with a required HTTPS policy and one managed config fragment per side. State is keyed by the target's {host, port, user} and no credential is ever placed on argv.",
  globalArguments: GlobalArgsSchema,
  resources: {
    server: {
      description: "Recorded Apt-Cacher NG server state for one host",
      schema: ServerStateSchema,
      lifetime: "infinite" as const,
      garbageCollection: 10,
    },
    client: {
      description: "Recorded apt proxy client state for one host",
      schema: ClientStateSchema,
      lifetime: "infinite" as const,
      garbageCollection: 10,
    },
    observation: {
      description: "Last read-only observation for one host",
      schema: ObservationSchema,
      lifetime: "7d" as const,
      garbageCollection: 20,
    },
    render: {
      description: "Last rendered server configuration for one input set",
      schema: RenderSchema,
      lifetime: "7d" as const,
      garbageCollection: 20,
    },
  },
  methods: {
    install_server: {
      kind: "action" as const,
      description:
        "Install apt-cacher-ng non-interactively with the HTTP-tunnel debconf prompt answered no. Idempotent: an already-installed package is adopted and its version read. Returns the host and version.",
      arguments: InstallServerArgsSchema,
      execute: installServer,
    },
    render_server: {
      description:
        "READ-ONLY. Render the managed server fragment and backend files with their SHA-256 and persist the render. Deterministic; no host is contacted.",
      arguments: RenderServerArgsSchema,
      execute: renderServer,
    },
    apply_server: {
      kind: "action" as const,
      description:
        "Write the managed fragment and backend files, restart apt-cacher-ng only when they changed, and verify the service, the listen socket and an HTTP fetch. Idempotent: identical bytes mean no write and no restart.",
      arguments: ApplyServerArgsSchema,
      execute: applyServer,
    },
    remove_server: {
      kind: "action" as const,
      description:
        "DESTRUCTIVE. Stop and disable apt-cacher-ng, remove the managed fragment and backend files, and remove the package (purge only with purge_cache_ack, which also deletes the cache directory). Re-running on a host with nothing installed is a clean no-op.",
      arguments: RemoveServerArgsSchema,
      execute: removeServer,
    },
    get: {
      description:
        "READ-ONLY. Report service state, listen sockets, a config digest, cache size and filesystem free space, and persist the observation.",
      arguments: GetArgsSchema,
      execute: getServer,
    },
    sync: {
      description:
        "READ-ONLY. Re-render the managed fragment, compare it with the live file, flag a PassThroughPattern the model did not render, and persist the observation.",
      arguments: SyncArgsSchema,
      execute: syncServer,
    },
    stats: {
      description:
        "READ-ONLY. Read the apt-cacher request log over SSH for hit/miss counts and bytes over a window, plus cache size and free space, and persist the observation. Matches the maintenance page's log analysis without invoking Count Data; fails closed on an unrecognised log.",
      arguments: StatsArgsSchema,
      execute: statsServer,
    },
    configure_client: {
      kind: "action" as const,
      description:
        "Write the managed apt snippet on a client, verify it with apt-config dump and optionally apt-get update, and persist the client state. Refuses a conflicting proxy file without override_existing_ack and a policy that disagrees with a recorded server for the proxy host.",
      arguments: ConfigureClientArgsSchema,
      execute: configureClient,
    },
    client_get: {
      description:
        "READ-ONLY. Report the effective Acquire::*::Proxy values on a client, whether the managed snippet is the one in force, and any conflicting file, and persist the observation.",
      arguments: ClientGetArgsSchema,
      execute: clientGet,
    },
    unconfigure_client: {
      kind: "action" as const,
      description:
        "Remove the managed apt snippet and auto-detect script and verify apt no longer uses the managed proxy. Re-running when nothing is present is a clean no-op.",
      arguments: UnconfigureClientArgsSchema,
      execute: unconfigureClient,
    },
  },
};

/** Test factory: install dependencies and return the model. */
export function createModel(overrides: Partial<AptCacheDeps> = {}) {
  setDeps(overrides);
  return model;
}
