/**
 * Shared fixtures and a stateful test context for the apt-cache model tests.
 * The two method-test files import these instead of repeating them.
 *
 * @module
 */

import { createModelTestContext } from "jsr:@swamp-club/swamp-testing@0.20261014.55";
import { TEST_NOW } from "./test_support.ts";

/** The fixed clock every model test uses. */
export const NOW = TEST_NOW;

/** A valid strict host-key block. */
export const SSH = {
  host: "192.0.2.20",
  port: 22,
  user: "root",
  host_key_policy: "strict" as const,
  host_keys: ["192.0.2.20 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeKey"],
  ssh_key_ref: { vault: "default", key: "APT_SSH" },
  connect_timeout_s: 15,
};

/** Server inputs shared by the server tests. */
export const SERVER = {
  listen: ["192.0.2.20"],
  https_policy: "direct" as const,
  passthrough_hosts: [] as string[],
  backends: { debian: ["http://deb.example.test/debian/"] },
  expire_days: 4,
  cache_dir: "/var/cache/apt-cacher-ng",
};

/** Client inputs shared by the client tests. */
export const CLIENT = {
  proxy_url: "http://192.0.2.20:3142",
  https_policy: "direct" as const,
  bypass_hosts: [] as string[],
  fallback_direct: false,
  verify_update: false,
};

/** SERVER with overrides; avoids duplicate-key literals under strict TS. */
export function serverArgs(overrides: Record<string, unknown> = {}) {
  return Object.assign({}, SERVER, overrides);
}

/**
 * A test context whose written resources are readable later in the same test.
 * The stock context answers `readResource` only from `storedResources`, but a
 * sequence like apply/apply/remove needs the earlier writes.
 */
export function ctx(
  options: Record<string, unknown> = {},
  extraContext: Record<string, unknown> = {},
) {
  const base = createModelTestContext({ globalArgs: {}, ...options });
  const written = new Map<string, Record<string, unknown>>();
  return {
    ...base,
    context: {
      // A default query API so configure_client's policy check runs; tests that
      // exercise the failure path override it.
      queryData: () => Promise.resolve([]),
      ...base.context,
      writeResource: (
        spec: string,
        name: string,
        data: Record<string, unknown>,
      ) => {
        written.set(name, data);
        return base.context.writeResource(spec, name, data);
      },
      readResource: async (name: string, version?: number) => {
        return written.get(name) ??
          await base.context.readResource(name, version);
      },
      ...extraContext,
    },
  };
}
