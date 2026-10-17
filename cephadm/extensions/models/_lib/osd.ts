/**
 * OSD service application, in two modes.
 *
 * All-available mode claims every empty device fleet-wide, so the caller must
 * state an exclude list and every excluded disk is checked against the
 * orchestrator's device inventory before anything is applied; "available"
 * means empty, not safe to claim. Selector mode resolves each serial to a
 * stable by-id path on the disk-owning host first, then converges exactly one
 * managed service per host, removing leftover services whose placement is that
 * one host.
 *
 * @module
 */

import { fail } from "./errors.ts";
import type { SshSession } from "./ssh.ts";
import { CEPH_ID_CREATE_RE, quote } from "./validate.ts";
import {
  matchesSerial,
  type ResolvedDevice,
  resolveSerial,
} from "./resolve.ts";
import type { PrepDeps } from "./hostprep.ts";
import { runCeph, runCephScript } from "./shell.ts";
import type { DataDevice, ExcludedDevice } from "./wipe.ts";

/** The raw OSD method arguments, before mode validation. */
export interface OsdArgs {
  /** Fleet-wide claim of empty devices. */
  allAvailableDevices?: boolean | null;
  /** Name cephadm registered for the disk owner. */
  targetHost?: string | null;
  /** How the control host reaches the disk owner. */
  targetAddr?: string | null;
  /** SSH port for the disk owner. */
  targetPort?: number | null;
  /** Disks to make OSDs. */
  dataDevices?: DataDevice[] | null;
  /** Disks that must never be claimed. */
  excludeDevices?: ExcludedDevice[] | null;
}

/** The validated mode of an OSD application. */
export interface OsdMode {
  /** Chosen mode. */
  mode: "all" | "selector";
  /** Selector target, or null. */
  targetHost: string | null;
  /** Requested data devices. */
  dataDevices: DataDevice[];
  /** Requested excluded devices. */
  excludeDevices: ExcludedDevice[];
}

/**
 * Re-checks the mode rules at run time, because a direct call can bypass the
 * schema. An empty string and an empty list count as absent.
 */
export function validateOsdMode(args: OsdArgs): OsdMode {
  const all = args.allAvailableDevices === true;
  const dataDevices = (args.dataDevices ?? []).filter((d) => d.serial !== "");
  const excludeDevices = (args.excludeDevices ?? []).filter((d) =>
    d.serial !== ""
  );
  const targetHost =
    args.targetHost !== undefined && args.targetHost !== null &&
      args.targetHost !== ""
      ? args.targetHost
      : null;
  if (all && dataDevices.length > 0) {
    fail(
      "cephApplyOsd",
      "choose one mode: allAvailableDevices or a non-empty dataDevices",
      {},
    );
  }
  if (!all && dataDevices.length === 0) {
    fail(
      "cephApplyOsd",
      "choose one mode: allAvailableDevices or a non-empty dataDevices",
      {},
    );
  }
  if (all && targetHost !== null) {
    fail("cephApplyOsd", "all-available mode must not name a targetHost", {
      targetHost,
    });
  }
  if (!all && targetHost === null) {
    fail("cephApplyOsd", "selector mode requires a non-empty targetHost", {});
  }
  if (all && excludeDevices.length === 0) {
    fail(
      "cephApplyOsd",
      "all-available mode requires a non-empty excludeDevices",
      {},
    );
  }
  return {
    mode: all ? "all" : "selector",
    targetHost,
    dataDevices,
    excludeDevices,
  };
}

/** One orchestrator device-inventory entry. */
export interface DeviceEntry {
  /** Enrolled host. */
  hostname: string;
  /** Device path as cephadm sees it. */
  path: string;
  /** Device id (often the serial). */
  deviceId: string;
  /** Whether cephadm considers the device empty. */
  available: boolean;
}

/** Parses `ceph orch device ls -f json` into inventory entries. */
export function parseDeviceInventory(json: unknown): DeviceEntry[] {
  if (!Array.isArray(json)) return [];
  return json.flatMap((raw) => {
    if (raw === null || typeof raw !== "object") return [];
    const e = raw as Record<string, unknown>;
    return [{
      hostname: typeof e.hostname === "string" ? e.hostname : "",
      path: typeof e.path === "string" ? e.path : "",
      deviceId: typeof e.device_id === "string"
        ? e.device_id
        : (typeof e.deviceId === "string" ? e.deviceId : ""),
      available: e.available === true,
    }];
  });
}

/** True when an inventory entry names `serial`. */
export function entryMatchesSerial(
  entry: DeviceEntry,
  serial: string,
): boolean {
  if (entry.deviceId === serial) return true;
  const basename = entry.path.split("/").at(-1) ?? entry.path;
  return matchesSerial(basename, serial);
}

/**
 * Checks every excluded serial against the device inventory. Refuses when a
 * serial is found on no enrolled host, or when a matching device is available.
 */
export async function checkExclusions(
  deps: PrepDeps,
  session: SshSession,
  excludeDevices: ExcludedDevice[],
  log?: { warn: (message: string, props?: Record<string, unknown>) => void },
): Promise<void> {
  const r = await runCeph(deps, session, "orch device ls", {
    json: true,
    phase: "cephApplyOsd.exclusions",
  }, log);
  const entries = parseDeviceInventory(r.json);
  for (const ex of excludeDevices) {
    const matches = entries.filter((e) => entryMatchesSerial(e, ex.serial));
    if (matches.length === 0) {
      fail("cephApplyOsd", "an excluded serial was found on no enrolled host", {
        serial: ex.serial,
      });
    }
    const available = matches.find((e) => e.available);
    if (available) {
      fail(
        "cephApplyOsd",
        "an excluded device is available and would be claimed",
        {
          host: available.hostname,
          serial: ex.serial,
          path: available.path,
        },
      );
    }
  }
}

/** A managed OSD service as returned by `ceph orch ls --service_type osd`. */
export interface OsdService {
  /** Service name, e.g. `osd.by-serial-node1-b`. */
  name: string;
  /** Normalised placement hosts. */
  hosts: string[];
}

/** Parses the OSD service list. */
export function parseOsdServices(json: unknown): OsdService[] {
  if (!Array.isArray(json)) return [];
  return json.flatMap((raw) => {
    if (raw === null || typeof raw !== "object") return [];
    const e = raw as Record<string, unknown>;
    const name = typeof e.service_name === "string"
      ? e.service_name
      : (typeof e.service_id === "string" ? `osd.${e.service_id}` : "");
    const placement = e.placement as { hosts?: unknown } | undefined;
    const hosts = Array.isArray(placement?.hosts)
      ? placement!.hosts!.filter((h): h is string => typeof h === "string").map(
        (h) => h.split("=")[0].split(":")[0],
      )
      : [];
    return [{ name, hosts }];
  });
}

/** Leftover services for `targetHost`: name prefix matches and placement is exactly that host. */
export function findLeftovers(
  services: OsdService[],
  targetHost: string,
): string[] {
  const prefix = `osd.by-serial-${targetHost}-`;
  return services
    .filter((s) =>
      s.name.startsWith(prefix) && s.hosts.length === 1 &&
      s.hosts[0] === targetHost
    )
    .map((s) => s.name);
}

/** Extracts the device paths from an exported OSD spec. */
export function extractSpecPaths(exportText: string): string[] {
  const out: string[] = [];
  let inPaths = false;
  for (const line of exportText.split("\n")) {
    if (/^\s*paths:\s*$/.test(line)) {
      inPaths = true;
      continue;
    }
    if (inPaths) {
      const m = line.match(/^\s*-\s*(\S+)\s*$/);
      if (m) {
        out.push(m[1]);
        continue;
      }
      if (line.trim() !== "" && !/^\s/.test(line)) inPaths = false;
    }
  }
  return out;
}

/** True when two path lists are equal as sets. */
export function samePathSet(a: string[], b: string[]): boolean {
  const x = [...new Set(a)].sort();
  const y = [...new Set(b)].sort();
  return x.length === y.length && x.every((p, i) => p === y[i]);
}

/** The YAML for one by-serial OSD service. */
export function osdSpecYaml(
  serviceId: string,
  targetHost: string,
  paths: string[],
): string {
  return [
    "service_type: osd",
    `service_id: ${serviceId}`,
    "placement:",
    "  hosts:",
    `    - ${targetHost}`,
    "spec:",
    "  data_devices:",
    "    paths:",
    ...paths.map((p) => `      - ${p}`),
    "",
  ].join("\n");
}

/** The script body that writes the spec inside the container and applies it. */
export function osdApplyBody(specYaml: string): string {
  return [
    'spec="$(mktemp /tmp/cephadm-osd-XXXXXX.yaml)"',
    "trap 'rm -f \"$spec\"' EXIT",
    "cat > \"$spec\" <<'CEPHADM_OSD_SPEC'",
    specYaml.trimEnd(),
    "CEPHADM_OSD_SPEC",
    'ceph orch apply -i "$spec"',
  ].join("\n");
}

/** The record an OSD application writes. */
export interface OsdRecord {
  /** Service id applied or matched. */
  serviceId: string;
  /** Mode flag. */
  allAvailableDevices: boolean;
  /** Selector target, or null. */
  targetHost: string | null;
  /** Requested data devices. */
  dataDevices: { serial: string }[];
  /** By-id paths applied or matched (selector), or empty. */
  resolvedPaths: string[];
  /** Requested excluded devices, or empty. */
  excludeDevices: { serial: string }[];
  /** Whether an apply was issued. */
  applied: boolean;
  /** Leftover services removed. */
  staleServicesRemoved: string[];
}

/**
 * Applies an OSD service. `session` is the admin host; `targetSession` is the
 * disk owner in selector mode (ignored otherwise).
 */
export async function applyOsd(
  deps: PrepDeps,
  session: SshSession,
  targetSession: SshSession | null,
  args: OsdArgs,
  log?: { warn: (message: string, props?: Record<string, unknown>) => void },
): Promise<OsdRecord> {
  const mode = validateOsdMode(args);

  if (mode.mode === "all") {
    const serviceId = "all-available-devices";
    await checkExclusions(deps, session, mode.excludeDevices, log);
    const ls = await runCeph(
      deps,
      session,
      `orch ls --service_name osd.${serviceId}`,
      { json: true, phase: "cephApplyOsd.read" },
      log,
    );
    const exists = Array.isArray(ls.json) && ls.json.length > 0;
    if (!exists) {
      await runCeph(
        deps,
        session,
        "orch apply osd --all-available-devices",
        { phase: "cephApplyOsd.apply" },
        log,
      );
    }
    return {
      serviceId,
      allAvailableDevices: true,
      targetHost: null,
      dataDevices: [],
      resolvedPaths: [],
      excludeDevices: mode.excludeDevices.map((e) => ({ serial: e.serial })),
      applied: !exists,
      staleServicesRemoved: [],
    };
  }

  const targetHost = mode.targetHost!;
  const serviceId = `by-serial-${targetHost}`;
  if (!CEPH_ID_CREATE_RE.test(serviceId)) {
    fail("cephApplyOsd", "targetHost does not yield a valid service id", {
      serviceId,
      targetHost,
    });
  }
  if (targetSession === null) {
    fail(
      "cephApplyOsd",
      "selector mode needs a connection to the disk-owning host",
      { targetHost },
    );
  }

  // Resolve every serial before removing anything, so a failure leaves the cluster untouched.
  const resolved: ResolvedDevice[] = [];
  for (const d of mode.dataDevices) {
    resolved.push(
      await resolveSerial(targetSession, d.serial, "cephApplyOsd:gate-resolve"),
    );
  }
  const paths = resolved.map((r) => r.path);

  const services = await runCeph(
    deps,
    session,
    "orch ls --service_type osd",
    { json: true, phase: "cephApplyOsd.services" },
    log,
  );
  const leftovers = findLeftovers(parseOsdServices(services.json), targetHost);

  const exported = await runCeph(
    deps,
    session,
    `orch ls --service_name osd.${serviceId} --export`,
    { phase: "cephApplyOsd.export", allowNonZero: true },
    log,
  );
  const livePaths = exported.result.code === 0
    ? extractSpecPaths(exported.result.stdout)
    : null;
  const converged = livePaths !== null && livePaths.length > 0 &&
    samePathSet(livePaths, paths);

  const staleServicesRemoved: string[] = [];
  try {
    // Apply the desired service first, so a failure cannot leave the host
    // with no managed OSD service; only then remove the stale specs.
    if (!converged) {
      await runCephScript(
        deps,
        session,
        {
          body: osdApplyBody(osdSpecYaml(serviceId, targetHost, paths)),
          phase: "cephApplyOsd.apply",
        },
        log,
      );
    }
    for (const name of leftovers) {
      await runCeph(deps, session, `orch rm ${quote(name)} --force`, {
        phase: "cephApplyOsd.rm",
      }, log);
      staleServicesRemoved.push(name);
    }
  } catch (e) {
    fail(
      "cephApplyOsd",
      "the OSD apply failed after removing leftover services",
      {
        removedServices: staleServicesRemoved,
        cause: (e as Error).message,
      },
    );
  }

  return {
    serviceId,
    allAvailableDevices: false,
    targetHost,
    dataDevices: mode.dataDevices.map((d) => ({ serial: d.serial })),
    resolvedPaths: paths,
    excludeDevices: [],
    applied: !converged,
    staleServicesRemoved,
  };
}
