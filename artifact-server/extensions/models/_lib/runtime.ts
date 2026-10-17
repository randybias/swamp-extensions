/**
 * The active transport dependencies.
 *
 * This is deliberately a single module-level binding rather than a parameter,
 * so `model` can be a plain object literal that the cataloguer can read. The
 * cost is that it is shared mutable state: production sets it once (via the
 * default), and tests bind it once per test through one shared helper, which
 * must not run concurrently in the same worker. `setDeps` is the only writer.
 *
 * @module
 */

import { denoDeps, type SshDeps } from "./ssh.ts";

/** The active transport dependencies. */
export let activeDeps: SshDeps = denoDeps;

/** Swaps the transport dependencies. Tests use this; production never does. */
export function setDeps(next: SshDeps): void {
  activeDeps = next;
}
