/**
 * Shared setup for the model's test files: the canonical arguments, the fake
 * transport bound to the model, and a seeded layout.
 *
 * @module
 */

import { createModelTestContext } from "jsr:@swamp-club/swamp-testing@0.20261014.55";
import { createModel } from "../artifact_server.ts";
import { makeFakeRemote } from "./fake_remote.ts";
import { sha256Hex } from "./ssh.ts";
import { SHA256SUMS_FILE } from "./layout.ts";

/** The pinned SSH block used by every test. */
export const SSH = {
  host: "node-1.example.test",
  user: "deploy",
  host_key_policy: "strict" as const,
  host_keys: [
    "node-1.example.test ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestOnly",
  ],
};

/** The served root used by every test. */
export const ROOT = "/srv/artifacts";

/** A fixed 64-hex hash for schema-only tests. */
export const HOST = "a".repeat(64);

/** Listen and server-name inputs shared by config and install calls. */
export const SITE_ARGS = {
  listen: { address: "*", port: 8080 },
  server_name: "cdn.example.test",
};

/** The shared argument block with defaults filled in. */
export function base(overrides: Record<string, unknown> = {}) {
  return { ssh: SSH, root: ROOT, ...overrides };
}

/** Binds the model to a fake transport and returns a fresh test context. */
export function modelFor(host: ReturnType<typeof makeFakeRemote>) {
  return { host, m: createModel(host.deps), ...createModelTestContext({}) };
}

/** Seeds a layout with one blob and one ref; returns the blob hash. */
export async function seed(host: ReturnType<typeof makeFakeRemote>) {
  const body = "stored\n";
  const hash = await sha256Hex(body);
  host.setFile(`${ROOT}/.layout-version`, "1\n", "644", "user", "user");
  host.setFile(`${ROOT}/sha256/${hash}/x.txt`, body, "644", "user", "user");
  host.setFile(
    `${ROOT}/${SHA256SUMS_FILE}`,
    `${hash}  sha256/${hash}/x.txt\n`,
    "644",
    "user",
    "user",
  );
  host.setFile(`${ROOT}/refs/stable`, `blob  ${hash}\n`, "644", "user", "user");
  return hash;
}
