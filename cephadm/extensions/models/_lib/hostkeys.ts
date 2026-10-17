/**
 * Host-key pin persistence and resolution for the cephadm model.
 *
 * The canonical transport pins `host_keys` per host and port: `strict` requires
 * them; `insecure_tofu` learns them on first contact and verifies them on every
 * later contact. This module owns the pure decisions — which pins apply, which
 * are used, and whether a first contact must learn — so the model can persist
 * them in the `hostkeys` resource without any transport in the loop.
 *
 * @module
 */

import { z } from "npm:zod@4.3.6";
import { LocalRefusalError } from "./errors.ts";
import { isHostKeyLine } from "./validate.ts";

/** One pinned set of host keys for a host and port. */
export const HostKeysSchema = z.strictObject({
  host: z.string().max(253),
  port: z.number().int().min(1).max(65535),
  host_keys: z.array(
    z.string().max(8192).refine(isHostKeyLine, "an ssh-keyscan line"),
  ).min(1).max(64),
  learned_at: z.string().max(64),
});

/** A persisted host-key pin. */
export type HostKeys = z.infer<typeof HostKeysSchema>;

/** The resource instance name for one host and port. */
export function hostKeysName(host: string, port: number): string {
  return `hostkeys-${host}-${port}`;
}

/**
 * Requires every pinned line to name a host. A bare `type blob` line is refused
 * outright: in a multi-host model it would pin a key for every host, so host A's
 * key could pass for host B. A line naming some OTHER host is valid — the
 * transport selects the lines that apply to the host being dialled and refuses
 * when none do.
 */
export function assertPinsNamed(hostKeys: string[]): void {
  for (const line of hostKeys) {
    if (line.split(" ").length === 2) {
      throw new LocalRefusalError(
        `a pinned host key must name its host ([host]:port or host), not be a bare key line: "${line}"`,
      );
    }
    if (!isHostKeyLine(line)) {
      throw new LocalRefusalError(`not an ssh-keyscan line: ${line}`);
    }
  }
}

/** What a call should present to the transport, and whether it must learn. */
export interface PinDecision {
  /** Pins to present; empty only when a first `insecure_tofu` contact learns. */
  hostKeys: string[];
  /** True only for a first `insecure_tofu` contact with no pins. */
  learn: boolean;
}

/**
 * Decides the pins for one call. Explicit `supplied` pins win over a stored
 * pin; otherwise the stored pin is used. `strict` with no pins is refused.
 * `insecure_tofu` with no pins returns `learn` so the model learns and persists
 * them per host:port.
 */
export function resolvePins(opts: {
  host: string;
  port: number;
  host_key_policy: "strict" | "insecure_tofu";
  supplied?: string[] | null;
  stored?: HostKeys | null;
}): PinDecision {
  const supplied = (opts.supplied ?? []).filter((k) => k !== "");
  const hostKeys = supplied.length > 0
    ? supplied
    : (opts.stored?.host_keys ?? []);
  assertPinsNamed(hostKeys);
  if (opts.host_key_policy === "strict") {
    if (hostKeys.length === 0) {
      throw new LocalRefusalError(
        `host_key_policy strict requires host_keys for ${opts.host}:${opts.port}`,
      );
    }
    return { hostKeys, learn: false };
  }
  return { hostKeys, learn: hostKeys.length === 0 };
}
