/**
 * Shared runtime of the Knot DNS model: the injectable transport, the SSH
 * target built from a vault reference, resource instance names and the
 * action-outcome record.
 *
 * @module
 */

import { z } from "npm:zod@4.3.6";
import {
  denoDeps,
  exec as sshExec,
  sha256Hex,
  type SshDeps,
  type SshTarget,
} from "./ssh.ts";
import { KnotError, resolveSecret } from "./vault.ts";
import { discoverZonesScript, portCheckScript } from "./scripts.ts";
import { mapScriptError } from "./errors.ts";
import { type Outcome, type SshOnlyArgs } from "./schemas.ts";

/** Cap on captured remote output. */
const MAX_OUTPUT_BYTES = 16 * 1024 * 1024;

// deno-lint-ignore no-explicit-any
export type Ctx = any;

/** The injected transport; one shared object so every module sees a swap. */
export const deps: SshDeps = { ...denoDeps };

/** Replaces the injected transport dependencies (tests only). */
export function setDeps(d: Partial<SshDeps>): SshDeps {
  const prev = { ...deps };
  Object.assign(deps, d);
  return prev;
}

export type SshInput = z.infer<typeof SshOnlyArgs>["ssh"];

/** The SSH target for a method's `ssh` argument, key read from the vault. */
export async function sshTarget(
  context: Ctx,
  ssh: SshInput,
): Promise<SshTarget> {
  const key = await resolveSecret(context.vaultService, ssh.ssh_key_ref);
  return {
    host: ssh.host,
    port: ssh.port,
    user: ssh.user,
    host_key_policy: "strict",
    host_keys: ssh.host_keys,
    private_key: key,
    connect_timeout_s: ssh.connect_timeout_s,
    max_output_bytes: MAX_OUTPUT_BYTES,
  };
}

/** Instance name for a set of identity parts; kind keeps resources distinct. */
export async function instanceName(parts: string[]): Promise<string> {
  const digest = (await sha256Hex(parts.join("\0"))).slice(0, 16);
  return `knot_${digest}`;
}

/**
 * Persists what an action did. The key is the action plus the host (and zone),
 * so the latest outcome per target replaces the previous one.
 */
export async function recordOutcome(context: Ctx, outcome: Outcome) {
  const zone = "zone" in outcome ? outcome.zone : "";
  const name = await instanceName([
    "outcome",
    outcome.action,
    outcome.host,
    zone,
  ]);
  return await context.writeResource("outcome", name, outcome);
}

/**
 * Precheck that each requested listen address/port is free or held by the
 * named server process. A foreign holder is a typed `port_busy` error that
 * names it, before anything is staged or swapped.
 */
export async function assertPortsFree(
  target: SshTarget,
  listens: string[],
  allow: string[] = ["knotd"],
): Promise<void> {
  const res = await sshExec(deps, target, [
    "sh",
    "-c",
    portCheckScript(listens, allow),
  ]);
  if (res.exit_code !== 0) {
    const detail = res.stderr.split("\n").find((l) => l.includes("PORT_BUSY"));
    throw new KnotError(
      "port_busy",
      detail ?? "a requested listen port is busy",
    );
  }
}

/** The apexes of the zones this model serves on the host. */
export async function servedApexes(target: SshTarget): Promise<string[]> {
  const res = await sshExec(deps, target, ["sh", "-c", discoverZonesScript()]);
  if (res.exit_code !== 0) throw mapScriptError(res.stderr, res.exit_code);
  return res.stdout.split("\n").map((l) => l.trim()).filter((l) =>
    l.endsWith(".")
  );
}
