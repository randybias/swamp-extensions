/**
 * Authoritative listen-address rules. The host's `server.listen` fragment is
 * one file shared by every zone, so it is always the union of what each
 * applied zone asked for.
 *
 * @module
 */

import { KnotError } from "./vault.ts";

/** Normalizes `addr` or `addr@port` to host and port for comparison. */
function listenPort(addr: string): { host: string; port: string } {
  const at = addr.indexOf("@");
  return at === -1
    ? { host: addr, port: "53" }
    : { host: addr.slice(0, at), port: addr.slice(at + 1) };
}

const isWildcard = (host: string) => host === "0.0.0.0" || host === "::";

/** Returns the overlapping pair when the two listen sets can share a socket. */
function listenOverlap(
  a: string[],
  b: string[] | undefined,
): string | undefined {
  for (const x of a) {
    for (const y of b ?? []) {
      const lx = listenPort(x);
      const ly = listenPort(y);
      if (lx.port !== ly.port) continue;
      if (
        lx.host === ly.host || isWildcard(lx.host) || isWildcard(ly.host)
      ) {
        return `${x} and ${y}`;
      }
    }
  }
  return undefined;
}

/** Enforces wildcard and authoritative/resolver disjointness preconditions. */
export function assertListenAcceptable(
  a: { listen: string[]; listen_any_ack: boolean },
  resolverListen: string[] | undefined,
): void {
  for (const addr of a.listen) {
    if (isWildcard(listenPort(addr).host) && !a.listen_any_ack) {
      throw new KnotError(
        "invalid_input",
        "a wildcard listen address needs listen_any_ack",
      );
    }
  }
  const overlap = listenOverlap(a.listen, resolverListen);
  if (overlap !== undefined) {
    throw new KnotError(
      "invalid_input",
      `the authoritative and resolver listen sets overlap at ${overlap}`,
    );
  }
}

/** The subset of a recorded zone that the listen union depends on. */
interface RecordedZone {
  attributes?: {
    host?: string;
    apex?: string;
    status?: string;
    requested_listen?: string[];
  };
}

/** The slice of the method context this module reads recorded zones through. */
interface ZoneStore {
  definition?: { name?: string };
  readModelData?: (model: string | undefined, spec: string) => Promise<unknown>;
}

/**
 * The listens other applied zones on `host` still need. The zone being
 * changed is excluded so its previous request cannot keep a listen alive.
 * A store that exists but cannot be read fails the call: guessing here would
 * rewrite the shared fragment and drop other zones' listeners.
 */
export async function otherZoneListens(
  context: ZoneStore,
  host: string,
  exceptApex: string,
): Promise<string[]> {
  if (typeof context.readModelData !== "function") return [];
  let recorded: unknown;
  try {
    recorded = await context.readModelData(context.definition?.name, "zone");
  } catch (err) {
    throw new KnotError(
      "tool_failed",
      `could not read the recorded zones to compute the host listen set: ${
        err instanceof Error ? err.message : String(err)
      }`,
    );
  }
  const listens = new Set<string>();
  for (const r of (Array.isArray(recorded) ? recorded : []) as RecordedZone[]) {
    const attrs = r.attributes;
    if (attrs?.host !== host || attrs.apex === exceptApex) continue;
    if (attrs.status !== "applied") continue;
    for (const x of attrs.requested_listen ?? []) listens.add(x);
  }
  return [...listens];
}

/** The host-wide listen set: this zone's request plus every other zone's. */
export function hostListens(own: string[], others: string[]): string[] {
  return [...new Set([...own, ...others])].sort();
}

/** The `server.listen` fragment for a listen set; empty when none. */
export function listenFragment(listens: string[]): string {
  return listens.length === 0
    ? ""
    : `server:\n  listen: [${
      listens.map((x) => JSON.stringify(x)).join(", ")
    }]\n`;
}
