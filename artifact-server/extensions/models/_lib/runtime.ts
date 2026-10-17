/**
 * The active transport dependencies. Production uses the real runner; tests
 * swap it once, and every module reads the same live binding.
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
