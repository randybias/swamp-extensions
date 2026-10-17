/**
 * Maintenance and teardown: the shared privileged host observation, the
 * poll-until-verified contract, host-subtree maintenance, and the purge chain.
 *
 * The host observation is one privileged script per host, so reads are
 * consistent with each other and a missing tool is never read as a clean host.
 * A mutating command's exit code is acceptance, never effect: every one is
 * followed by a poll that re-reads state until the effect is observed.
 *
 * @module
 */

import { fail, TransportError } from "./errors.ts";
import type { SshSession } from "./ssh.ts";
import type { PrepDeps } from "./hostprep.ts";
import { runCeph } from "./shell.ts";
import { quote } from "./validate.ts";
import { nooutPredicate } from "./verify.ts";
import { settle } from "./verify.ts";

type Logger = {
  info: (m: string, p?: Record<string, unknown>) => void;
  warn: (m: string, p?: Record<string, unknown>) => void;
};

/** The poll-budget floor for maintenance methods. */
export const MAINTENANCE_POLL_FLOOR_MS = 300_000;

/** Raises a caller budget to the maintenance floor, with a warning. */
export function floorPollBudget(
  requested: number,
  log?: Logger,
): number {
  if (requested < MAINTENANCE_POLL_FLOOR_MS) {
    log?.warn("Raised the poll budget to the maintenance floor", {
      requestedMs: requested,
      floorMs: MAINTENANCE_POLL_FLOOR_MS,
    });
    return MAINTENANCE_POLL_FLOOR_MS;
  }
  return requested;
}

/** A poll that has to observe an effect rather than accept an exit code. */
export async function pollEffect<T>(
  deps: PrepDeps,
  opts: {
    budgetMs: number;
    ceilingMs: number;
    label: string;
    phase: string;
    read: () => Promise<T>;
    pass: (value: T) => boolean;
  },
  _log?: Logger,
): Promise<{ value: T; attempts: number }> {
  const result = await settle(deps, {
    budgetMs: opts.budgetMs,
    ceilingMs: opts.ceilingMs,
    read: opts.read,
    pass: opts.pass,
  });
  if (result.value === null) {
    fail(opts.phase, `${opts.label} condition not satisfied`, {
      budgetMs: opts.budgetMs,
      attempts: result.attempts,
    });
  }
  if (!opts.pass(result.value)) {
    fail(opts.phase, `${opts.label} condition not satisfied within timeout`, {
      budgetMs: opts.budgetMs,
      attempts: result.attempts,
    });
  }
  return { value: result.value, attempts: result.attempts };
}

// ---------------------------------------------------------------------------
// Host observation
// ---------------------------------------------------------------------------

/** Marker constants for the host-observation script. */
export const HOST_MARKERS = {
  systemctl: "#__cephadm_present_systemctl__",
  lvm: "#__cephadm_present_lvm__",
  fsid: "#__cephadm_section_fsid__",
  units: "#__cephadm_section_units__",
  unitFiles: "#__cephadm_section_unitfiles__",
  vgs: "#__cephadm_section_vgs__",
  lvs: "#__cephadm_section_lvs__",
  mdstat: "#__cephadm_section_mdstat__",
} as const;

/** The six sections that must all be present. */
export const HOST_SECTIONS: (keyof typeof HOST_MARKERS)[] = [
  "fsid",
  "units",
  "unitFiles",
  "vgs",
  "lvs",
  "mdstat",
];

/** The privileged host-observation script, sent over one connection. */
export function hostObservationScript(): string {
  const m = HOST_MARKERS;
  return [
    `if command -v systemctl >/dev/null 2>&1; then echo '${m.systemctl}'; fi`,
    `if command -v vgs >/dev/null 2>&1 && command -v lvs >/dev/null 2>&1; then echo '${m.lvm}'; fi`,
    `echo '${m.fsid}'`,
    "ls -1 /var/lib/ceph 2>/dev/null || true",
    `echo '${m.units}'`,
    "systemctl list-units --all --plain --no-legend --no-pager 'ceph*' 2>/dev/null || true",
    `echo '${m.unitFiles}'`,
    "systemctl list-unit-files --no-legend --no-pager 'ceph*' 2>/dev/null || true",
    `echo '${m.vgs}'`,
    "vgs --noheadings -o vg_name 2>/dev/null || true",
    `echo '${m.lvs}'`,
    "lvs --noheadings -o vg_name,lv_name --separator / 2>/dev/null || true",
    `echo '${m.mdstat}'`,
    "cat /proc/mdstat 2>/dev/null || true",
    "exit 0",
  ].join("\n");
}

/** The derived state of one host's OS disk. */
export interface HostState {
  /** Target host. */
  host: string;
  /** fsid directory entries matching the UUID grammar, sorted. */
  fsids: string[];
  /** Union of loaded units and unit files, sorted. */
  cephUnits: string[];
  /** Units whose name contains a UUID. */
  clusterUnits: string[];
  /** Volume groups starting with `ceph-`. */
  cephVolumeGroups: string[];
  /** `vg/lv` entries starting with `ceph-`. */
  cephLogicalVolumes: string[];
  /** md array names seen in mdstat. */
  mdArrays: string[];
  /** Which tools were observed. */
  toolsSeen: { systemctl: boolean; lvm: boolean; mdstat: boolean };
}

const UUID_RE =
  /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/;

/** Splits host-observation stdout into sections, discarding unknown markers. */
export function splitHostSections(stdout: string): Record<string, string[]> {
  const markerToSection: Record<string, string> = {
    [HOST_MARKERS.fsid]: "fsid",
    [HOST_MARKERS.units]: "units",
    [HOST_MARKERS.unitFiles]: "unitFiles",
    [HOST_MARKERS.vgs]: "vgs",
    [HOST_MARKERS.lvs]: "lvs",
    [HOST_MARKERS.mdstat]: "mdstat",
  };
  const sections: Record<string, string[]> = {
    fsid: [],
    units: [],
    unitFiles: [],
    vgs: [],
    lvs: [],
    mdstat: [],
  };
  let current: string | null = null;
  for (const raw of stdout.split("\n")) {
    const line = raw.trim();
    const section = markerToSection[line];
    if (section !== undefined) {
      current = section;
      continue;
    }
    // A presence marker, or any other marker-shaped line, files nothing.
    if (line.startsWith("#__cephadm_")) {
      current = null;
      continue;
    }
    if (current !== null && line !== "") sections[current].push(line);
  }
  return sections;
}

/** Parses host-observation stdout into derived state, failing closed. */
export function parseHostState(host: string, stdout: string): HostState {
  const sections = splitHostSections(stdout);
  const missing = HOST_SECTIONS.filter((s) =>
    !stdout.split("\n").some((l) => l.trim() === HOST_MARKERS[s])
  );
  if (missing.length > 0) {
    fail("host-cluster-state", "host state not observed", {
      host,
      missing: missing.map((s) => HOST_MARKERS[s]),
    });
  }
  const firstColumn = (lines: string[]): string[] =>
    lines.map((l) => l.split(/\s+/)[0]).filter((s) => s !== "");
  const units = [
    ...new Set([
      ...firstColumn(sections.units),
      ...firstColumn(sections.unitFiles),
    ]),
  ]
    .sort();
  return {
    host,
    fsids: sections.fsid.filter((f) => UUID_RE.test(f)).sort(),
    cephUnits: units,
    clusterUnits: units.filter((u) =>
      /[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}/
        .test(u)
    ).sort(),
    cephVolumeGroups: sections.vgs.filter((v) => v.startsWith("ceph-")).sort(),
    cephLogicalVolumes: sections.lvs.filter((v) => v.startsWith("ceph-"))
      .sort(),
    mdArrays: sections.mdstat.flatMap((l) => {
      const name = l.match(/^(md\d+)\s*:/)?.[1];
      return name ? [name] : [];
    }),
    toolsSeen: {
      systemctl: stdout.split("\n").some((l) =>
        l.trim() === HOST_MARKERS.systemctl
      ),
      lvm: stdout.split("\n").some((l) => l.trim() === HOST_MARKERS.lvm),
      mdstat: sections.mdstat.length > 0,
    },
  };
}

/** Runs the privileged host observation over one connection. */
export async function observeHost(
  _deps: PrepDeps,
  session: SshSession,
  host: string,
): Promise<HostState> {
  const r = await session.run({
    command: "bash -s --",
    stdin: hostObservationScript(),
    sudo: true,
    allowNonZero: true,
  });
  if (r.code !== 0) {
    fail("host-cluster-state", "the host observation script failed", {
      host,
      code: r.code,
      stderr: r.stderr.slice(0, 300),
    });
  }
  return parseHostState(host, r.stdout);
}

/** One residue finding. */
export interface Residue {
  /** `fsid`, `unit`, `vg` or `lv`. */
  kind: string;
  /** The offending item. */
  item: string;
}

/** The cephadm-plane residue, or throws when systemctl was not observed. */
export function cephadmResidue(
  state: HostState,
  phase = "verify-host-torn-down",
): Residue[] {
  if (!state.toolsSeen.systemctl) {
    fail(phase, "host state not observed (systemctl absent)", {
      host: state.host,
    });
  }
  return [
    ...state.fsids.map((item) => ({ kind: "fsid", item })),
    ...state.clusterUnits.map((item) => ({ kind: "unit", item })),
  ];
}

/** The LVM-plane residue, or throws when the LVM tools were not observed. */
export function lvmResidue(
  state: HostState,
  phase = "verify-host-torn-down",
): Residue[] {
  if (!state.toolsSeen.lvm) {
    fail(phase, "host state not observed (LVM tools absent)", {
      host: state.host,
    });
  }
  return [
    ...state.cephVolumeGroups.map((item) => ({ kind: "vg", item })),
    ...state.cephLogicalVolumes.map((item) => ({ kind: "lv", item })),
  ];
}

/** The whole-host residue (both planes). */
export function wholeHostResidue(
  state: HostState,
  phase = "verify-host-torn-down",
): Residue[] {
  return [...cephadmResidue(state, phase), ...lvmResidue(state, phase)];
}

/** The fsid classification shared by the gate and the purge. */
export type FsidVerdict = "refuse" | "no-op" | "stranded" | "purge";

/** Classifies a host against the named fsid. */
export function classifyFsid(state: HostState, fsid: string): FsidVerdict {
  const other = state.fsids.filter((f) =>
    f.toLowerCase() !== fsid.toLowerCase()
  );
  if (other.length > 0) return "refuse";
  const cephadm = cephadmResidue(state, "verify-cluster-fsid");
  const lvm = lvmResidue(state, "verify-cluster-fsid");
  if (cephadm.length === 0 && lvm.length === 0) return "no-op";
  if (cephadm.length === 0 && lvm.length > 0) return "stranded";
  return "purge";
}

// ---------------------------------------------------------------------------
// Maintenance methods
// ---------------------------------------------------------------------------

interface HostRow {
  hostname: string;
  status: string;
}

/** Reads `ceph orch host ls` into host/status rows. */
async function readHostRows(
  deps: PrepDeps,
  session: SshSession,
  phase: string,
  log?: Logger,
): Promise<HostRow[]> {
  const r = await runCeph(
    deps,
    session,
    "orch host ls",
    { json: true, phase },
    log,
  );
  if (!Array.isArray(r.json)) return [];
  return r.json.flatMap((raw) => {
    if (raw === null || typeof raw !== "object") return [];
    const e = raw as Record<string, unknown>;
    return typeof e.hostname === "string"
      ? [{
        hostname: e.hostname,
        status: typeof e.status === "string" ? e.status : "",
      }]
      : [];
  });
}

/** Reads `osd stat` counts. */
async function readOsdStat(
  deps: PrepDeps,
  session: SshSession,
  phase: string,
  log?: Logger,
): Promise<{ up: number; in: number; numOsds: number }> {
  const r = await runCeph(
    deps,
    session,
    "osd stat",
    { json: true, phase },
    log,
  ) as {
    num_up_osds?: unknown;
    num_in_osds?: unknown;
    num_osds?: unknown;
  };
  const n = (v: unknown) => typeof v === "number" ? v : 0;
  return { up: n(r.num_up_osds), in: n(r.num_in_osds), numOsds: n(r.num_osds) };
}

/** Reads `health detail` for the noout predicate. */
async function readHealthDetail(
  deps: PrepDeps,
  session: SshSession,
  phase: string,
  log?: Logger,
): Promise<unknown> {
  const r = await runCeph(
    deps,
    session,
    "health detail",
    { json: true, phase },
    log,
  );
  return r.json;
}

/** The result of entering or exiting maintenance. */
export interface MaintenanceRecord {
  /** Method name. */
  method: string;
  /** Admin host. */
  host: string;
  /** Ceph host. */
  hostName: string;
  /** `enter` or `exit`. */
  action: "enter" | "exit";
  /** Whether a command was issued. */
  didIssueCommand: boolean;
  /** Reads performed, including the final read. */
  pollAttempts: number;
  /** Verification-poll duration. */
  pollDurationMs: number;
  /** Whether the host is in maintenance. */
  hostInMaintenance?: boolean;
  /** Whether the subtree noout flag was found. */
  nooutFlagFound?: boolean;
  /** Whether the host's OSDs are down. */
  hostOsdsDown?: boolean;
  /** Whether every OSD stayed in. */
  hostOsdsStayIn?: boolean;
  /** Whether the host left maintenance. */
  hostExitedMaintenance?: boolean;
  /** Whether every OSD is up and in. */
  osdsRestored?: boolean;
  /** Up count. */
  numUpOsds: number;
  /** In count. */
  numInOsds: number;
}

/** Ensures one host is in maintenance, proving status, noout and OSD state. */
export async function enterMaintenance(
  deps: PrepDeps,
  session: SshSession,
  args: {
    host: string;
    hostName: string;
    osdCount: number;
    pollIntervalMs?: number | null;
    pollTimeoutMs?: number | null;
  },
  log?: Logger,
): Promise<MaintenanceRecord> {
  const before = await readHostRows(deps, session, "maintenance-enter", log);
  const entry = before.find((h) => h.hostname === args.hostName);
  let didIssueCommand = false;
  if ((entry?.status ?? "").toLowerCase() !== "maintenance") {
    await runCeph(
      deps,
      session,
      `orch host maintenance enter ${quote(args.hostName)}`,
      {
        phase: "maintenance-enter",
      },
      log,
    );
    didIssueCommand = true;
  } else {
    log?.info("Host already in maintenance", { hostName: args.hostName });
  }
  const budget = floorPollBudget(args.pollTimeoutMs ?? 600_000, log);
  const ceiling = args.pollIntervalMs ?? 15_000;
  const started = deps.now();
  const result = await pollEffect(deps, {
    budgetMs: budget,
    ceilingMs: ceiling,
    label: "maintenance-enter",
    phase: "maintenance-enter",
    read: async () => {
      const rows = await readHostRows(deps, session, "maintenance-enter", log);
      const health = await readHealthDetail(
        deps,
        session,
        "maintenance-enter",
        log,
      );
      const osd = await readOsdStat(deps, session, "maintenance-enter", log);
      const status = rows.find((h) => h.hostname === args.hostName)?.status ??
        "not_found";
      const noout = nooutPredicate(health, args.hostName).set;
      return { status, noout, osd };
    },
    pass: (v) => {
      const down = v.osd.up <= v.osd.in - args.osdCount;
      const stayIn = v.osd.in >= v.osd.numOsds;
      return v.status.toLowerCase() === "maintenance" && v.noout && down &&
        stayIn;
    },
  }, log);
  const v = result.value;
  return {
    method: "cephHostMaintenanceEnter",
    host: args.host,
    hostName: args.hostName,
    action: "enter",
    didIssueCommand,
    pollAttempts: result.attempts,
    pollDurationMs: deps.now() - started,
    hostInMaintenance: v.status.toLowerCase() === "maintenance",
    nooutFlagFound: v.noout,
    hostOsdsDown: v.osd.up <= v.osd.in - args.osdCount,
    hostOsdsStayIn: v.osd.in >= v.osd.numOsds,
    numUpOsds: v.osd.up,
    numInOsds: v.osd.in,
  };
}

/** Classifies `ceph cephadm check-host` output. */
export function classifyCheckHost(
  text: string,
): { ok: boolean; detail: string } {
  const trimmed = text.trim();
  if (/host looks ok/i.test(trimmed)) {
    return { ok: true, detail: "Host looks OK" };
  }
  return { ok: false, detail: trimmed };
}

/** Runs `ceph cephadm check-host` and classifies it. */
export async function checkHost(
  deps: PrepDeps,
  session: SshSession,
  hostName: string,
  log?: Logger,
): Promise<{ ok: boolean; detail: string }> {
  const r = await runCeph(
    deps,
    session,
    `cephadm check-host ${quote(hostName)}`,
    {
      phase: "check-host",
      allowNonZero: true,
    },
    log,
  );
  return classifyCheckHost(`${r.result.stdout}\n${r.result.stderr}`);
}

/** Takes one host out of maintenance, proving its OSDs are restored. */
export async function exitMaintenance(
  deps: PrepDeps,
  session: SshSession,
  args: {
    host: string;
    hostName: string;
    pollIntervalMs?: number | null;
    pollTimeoutMs?: number | null;
  },
  log?: Logger,
): Promise<MaintenanceRecord> {
  const before = await readHostRows(deps, session, "maintenance-exit", log);
  const entry = before.find((h) => h.hostname === args.hostName);
  let didIssueCommand = false;
  if ((entry?.status ?? "").toLowerCase() === "maintenance") {
    didIssueCommand = true;
    const issue = () =>
      runCeph(
        deps,
        session,
        `orch host maintenance exit ${quote(args.hostName)}`,
        {
          phase: "maintenance-exit",
          allowNonZero: true,
        },
        log,
      );
    let first: Awaited<ReturnType<typeof issue>> | null = null;
    let firstError: unknown = null;
    try {
      first = await issue();
    } catch (e) {
      firstError = e;
    }
    if (first !== null && first.result.code !== 0) {
      const check = await checkHost(deps, session, args.hostName, log);
      if (check.ok) {
        await issue(); // exactly one retry
      } else {
        fail("maintenance-exit", "check-host failed before retrying", {
          kind: "check-host-failed",
          hostName: args.hostName,
          checkHost: check.detail,
        });
      }
    } else if (firstError !== null) {
      if (
        firstError instanceof TransportError &&
        firstError.kind !== "dropped-before-auth"
      ) {
        fail("maintenance-exit", "outcome unknown", {
          kind: "outcome-unknown",
          hostName: args.hostName,
          transport: firstError.kind,
          error: firstError.message,
        });
      }
      // A delivered failure or a pre-session drop: check-host discriminates.
      const check = await checkHost(deps, session, args.hostName, log);
      if (check.ok) {
        await issue(); // exactly one retry
      } else {
        fail("maintenance-exit", "check-host failed before retrying", {
          kind: "check-host-failed",
          hostName: args.hostName,
          checkHost: check.detail,
        });
      }
    }
  } else {
    log?.info("Host not in maintenance; verifying restoration", {
      hostName: args.hostName,
    });
  }
  const budget = floorPollBudget(args.pollTimeoutMs ?? 600_000, log);
  const ceiling = args.pollIntervalMs ?? 15_000;
  const started = deps.now();
  const result = await pollEffect(deps, {
    budgetMs: budget,
    ceilingMs: ceiling,
    label: "maintenance-exit",
    phase: "maintenance-exit",
    read: async () => {
      const rows = await readHostRows(deps, session, "maintenance-exit", log);
      const osd = await readOsdStat(deps, session, "maintenance-exit", log);
      return {
        status: rows.find((h) => h.hostname === args.hostName)?.status ??
          "not_found",
        osd,
      };
    },
    pass: (v) =>
      v.status !== "not_found" && v.status.toLowerCase() !== "maintenance" &&
      v.osd.up >= v.osd.numOsds && v.osd.in >= v.osd.numOsds,
  }, log);
  const v = result.value;
  return {
    method: "cephHostMaintenanceExit",
    host: args.host,
    hostName: args.hostName,
    action: "exit",
    didIssueCommand,
    pollAttempts: result.attempts,
    pollDurationMs: deps.now() - started,
    hostExitedMaintenance: v.status !== "not_found" &&
      v.status.toLowerCase() !== "maintenance",
    osdsRestored: v.osd.up >= v.osd.numOsds && v.osd.in >= v.osd.numOsds,
    numUpOsds: v.osd.up,
    numInOsds: v.osd.in,
  };
}

/** Reports which hosts are out by maintenance status or subtree noout. */
export async function maintenanceState(
  deps: PrepDeps,
  session: SshSession,
  host: string,
  log?: Logger,
): Promise<{
  method: string;
  host: string;
  hosts: {
    hostname: string;
    status: string;
    nooutFlag: boolean;
    out: boolean;
  }[];
  hostsOut: string[];
  numHosts: number;
  numHostsOut: number;
}> {
  const rows = await readHostRows(deps, session, "maintenance-state", log);
  const health = await readHealthDetail(
    deps,
    session,
    "maintenance-state",
    log,
  );
  if (rows.length === 0) {
    fail("maintenance-state", "the host list is empty or invalid", {});
  }
  const hosts = rows.map((r) => {
    const nooutFlag = nooutPredicate(health, r.hostname).set;
    return {
      hostname: r.hostname,
      status: r.status,
      nooutFlag,
      out: r.status.toLowerCase() === "maintenance" || nooutFlag,
    };
  });
  return {
    method: "cephHostMaintenanceState",
    host,
    hosts,
    hostsOut: hosts.filter((h) => h.out).map((h) => h.hostname),
    numHosts: hosts.length,
    numHostsOut: hosts.filter((h) => h.out).length,
  };
}

/** Strips known cephadm-shell banners from the front of a message. */
export function stripCephadmBanner(text: string): string {
  const keep: string[] = [];
  let inBanner = true;
  for (const line of text.split("\n")) {
    if (
      inBanner &&
      /^(Inferring fsid|Inferring config|Using ceph image with id|Using ceph image)/i
        .test(line.trim())
    ) {
      continue;
    }
    inBanner = false;
    keep.push(line);
  }
  return keep.join("\n").trim();
}

/** Parses the daemons named in a safe ok-to-stop answer. */
export function parseOkToStopDaemons(text: string): string[] {
  const out: string[] = [];
  const push = (name: string) => {
    const clean = name.trim().replace(/^['"]|['"]$/g, "").replace(/\.$/, "");
    if (clean !== "" && !out.includes(clean)) out.push(clean);
  };
  for (const raw of text.split("\n")) {
    const line = raw.trim();
    if (/^It is presumed safe to stop host /i.test(line)) continue;
    let m = line.match(/^It appears safe to stop (.+)$/i);
    if (m) {
      push(m[1]);
      continue;
    }
    m = line.match(/^(.+?) are safe to restart$/i);
    if (m) {
      for (const n of m[1].split(",")) push(n);
      continue;
    }
    m = line.match(/^It is presumed safe to stop \[(.+)\]$/i);
    if (m) {
      for (const n of m[1].split(",")) push(n);
      continue;
    }
    m = line.match(/^- (.+)$/);
    if (m) push(m[1]);
  }
  return out;
}

/** Asks the orchestrator whether a host can be stopped safely. */
export async function okToStop(
  deps: PrepDeps,
  session: SshSession,
  host: string,
  hostName: string,
  log?: Logger,
): Promise<
  {
    method: string;
    host: string;
    hostName: string;
    safe: boolean;
    reason: string;
    daemons: string[];
  }
> {
  const r = await runCeph(
    deps,
    session,
    `orch host ok-to-stop ${quote(hostName)}`,
    {
      phase: "ok-to-stop",
      allowNonZero: true,
    },
    log,
  );
  const text = `${r.result.stdout}\n${r.result.stderr}`;
  if (/presumed safe/i.test(text)) {
    return {
      method: "cephOsdOkToStop",
      host,
      hostName,
      safe: true,
      reason: "presumed safe",
      daemons: parseOkToStopDaemons(text),
    };
  }
  return {
    method: "cephOsdOkToStop",
    host,
    hostName,
    safe: false,
    reason: stripCephadmBanner(text),
    daemons: [],
  };
}

/** Finds the OSD ids under a host in the OSD tree. */
export function hostOsdIds(tree: unknown, hostName: string): number[] {
  const nodes = (tree as {
    nodes?: {
      id?: unknown;
      name?: unknown;
      type?: unknown;
      children?: unknown;
    }[];
  }).nodes;
  if (!Array.isArray(nodes)) return [];
  const byId = new Map<
    number,
    { id: number; name: string; type: string; children: number[] }
  >();
  for (const n of nodes) {
    if (typeof n.id !== "number") continue;
    byId.set(n.id, {
      id: n.id,
      name: typeof n.name === "string" ? n.name : "",
      type: typeof n.type === "string" ? n.type : "",
      children: Array.isArray(n.children)
        ? n.children.filter((c): c is number => typeof c === "number")
        : [],
    });
  }
  const host = nodes.find((n) => n.type === "host" && n.name === hostName);
  if (!host || typeof host.id !== "number") return [];
  const out: number[] = [];
  const visited = new Set<number>();
  const walk = (id: number) => {
    if (visited.has(id)) return;
    visited.add(id);
    const node = byId.get(id);
    if (!node) return;
    if (node.type === "osd") out.push(node.id);
    for (const c of node.children) walk(c);
  };
  walk(host.id);
  return out.sort((a, b) => a - b);
}

/** Clears an orphaned host-subtree noout flag, refusing unsafe states. */
export async function nooutClear(
  deps: PrepDeps,
  session: SshSession,
  args: {
    host: string;
    hostName: string;
    pollIntervalMs?: number | null;
    pollTimeoutMs?: number | null;
  },
  log?: Logger,
): Promise<{
  method: string;
  host: string;
  hostName: string;
  wasSet: boolean;
  didIssueCommand: boolean;
  nooutClearedObserved: boolean;
  hostInMaintenance: boolean;
  hostOsdIds: number[];
  downOsdIds: number[];
  elapsedMs: number;
}> {
  const started = deps.now();
  const rows = await readHostRows(deps, session, "noout-clear", log);
  const health = await readHealthDetail(deps, session, "noout-clear", log);
  const tree = await runCeph(deps, session, "osd tree", {
    json: true,
    phase: "noout-clear",
  }, log);
  const entry = rows.find((h) => h.hostname === args.hostName);
  if (!entry) {
    fail(
      "noout-clear",
      "host not known to the cluster (likely a typo; no action taken)",
      { host: args.hostName },
    );
  }
  const inMaintenance = entry!.status.toLowerCase() === "maintenance";
  if (inMaintenance) {
    fail(
      "noout-clear",
      "the host is in maintenance; use cephHostMaintenanceExit to clear the flag as part of a proven restore",
      { host: args.hostName },
    );
  }
  const osdTree = tree.json as {
    nodes?: { id?: number; status?: unknown; type?: unknown }[];
  };
  const ids = hostOsdIds(tree.json, args.hostName);
  const down = (osdTree.nodes ?? [])
    .filter((n) =>
      n.type === "osd" && typeof n.id === "number" && ids.includes(n.id) &&
      String(n.status ?? "").toLowerCase() !== "up"
    )
    .map((n) => n.id as number)
    .sort((a, b) => a - b);
  if (down.length > 0) {
    fail(
      "noout-clear",
      "the host has down OSDs; clearing noout would start a rebalance",
      {
        hostOsdIds: ids,
        downOsdIds: down,
      },
    );
  }
  const wasSet = nooutPredicate(health, args.hostName).set;
  if (!wasSet) {
    return {
      method: "cephHostNooutClear",
      host: args.host,
      hostName: args.hostName,
      wasSet: false,
      didIssueCommand: false,
      nooutClearedObserved: true,
      hostInMaintenance: inMaintenance,
      hostOsdIds: ids,
      downOsdIds: down,
      elapsedMs: deps.now() - started,
    };
  }
  await runCeph(
    deps,
    session,
    `osd unset-group noout ${quote(args.hostName)}`,
    {
      phase: "noout-clear",
    },
    log,
  );
  const budget = floorPollBudget(args.pollTimeoutMs ?? 600_000, log);
  await pollEffect(deps, {
    budgetMs: budget,
    ceilingMs: args.pollIntervalMs ?? 15_000,
    label: "noout-clear",
    phase: "noout-clear",
    read: () => readHealthDetail(deps, session, "noout-clear", log),
    pass: (h) => !nooutPredicate(h, args.hostName).set,
  }, log);
  return {
    method: "cephHostNooutClear",
    host: args.host,
    hostName: args.hostName,
    wasSet: true,
    didIssueCommand: true,
    nooutClearedObserved: true,
    hostInMaintenance: inMaintenance,
    hostOsdIds: ids,
    downOsdIds: down,
    elapsedMs: deps.now() - started,
  };
}

/** Parses `ceph cephadm osd activate` output. */
export function parseOsdActivate(
  text: string,
): { activated: number[]; alreadyPresent: boolean } {
  const created = text.match(/Created osd\(s\)\s+([0-9,\s]+)/i);
  if (created) {
    const ids = created[1].split(",").map((s) => s.trim()).filter((s) =>
      /^\d+$/.test(s)
    ).map(Number);
    if (ids.length > 0) return { activated: ids, alreadyPresent: false };
  }
  if (/Created no osd\(s\)/i.test(text) && /already created/i.test(text)) {
    return { activated: [], alreadyPresent: true };
  }
  fail("osd-activate", "unexpected output", { output: text.slice(0, 2000) });
}

/** Runs `ceph cephadm osd activate` and parses the result. */
export async function osdActivate(
  deps: PrepDeps,
  session: SshSession,
  host: string,
  hostName: string,
  log?: Logger,
): Promise<
  {
    method: string;
    host: string;
    hostName: string;
    activated: number[];
    alreadyPresent: boolean;
  }
> {
  const r = await runCeph(
    deps,
    session,
    `cephadm osd activate ${quote(hostName)}`,
    {
      phase: "osd-activate",
    },
    log,
  );
  const parsed = parseOsdActivate(`${r.result.stdout}\n${r.result.stderr}`);
  return { method: "cephOsdActivate", host, hostName, ...parsed };
}

/** Disables the cephadm mgr module, recording an unreachable cluster. */
export async function disableOrchestration(
  deps: PrepDeps,
  adminHost: string,
  session: SshSession,
  log?: Logger,
): Promise<{
  method: string;
  adminHost: string;
  outcome: "disabled" | "alreadyDisabled" | "clusterUnreachable";
  enabledBefore?: boolean;
  unreachableReason?: string;
}> {
  const enabledIn = (json: unknown): boolean | null => {
    if (json === null || typeof json !== "object") return null;
    const e = json as {
      enabled_modules?: unknown;
      always_on_modules?: unknown;
      disabled_modules?: unknown;
    };
    const names = (v: unknown) =>
      Array.isArray(v)
        ? v.map((x) =>
          typeof x === "string" ? x : (x as { name?: unknown })?.name
        ).filter((x): x is string => typeof x === "string")
        : [];
    if (
      names(e.enabled_modules).includes("cephadm") ||
      names(e.always_on_modules).includes("cephadm")
    ) return true;
    return false;
  };
  let enabledBefore: boolean | undefined;
  try {
    const first = await runCeph(deps, session, "mgr module ls", {
      json: true,
      phase: "disable-orchestration",
    }, log);
    const enabled = enabledIn(first.json);
    enabledBefore = enabled === true;
    if (!enabled) {
      return {
        method: "cephDisableOrchestration",
        adminHost,
        outcome: "alreadyDisabled",
        enabledBefore: false,
      };
    }
    await runCeph(deps, session, "mgr module disable cephadm", {
      phase: "disable-orchestration",
    }, log);
    await pollEffect(deps, {
      budgetMs: 120_000,
      ceilingMs: 5_000,
      label: "disable-orchestration",
      phase: "disable-orchestration",
      read: async () =>
        (await runCeph(deps, session, "mgr module ls", {
          json: true,
          phase: "disable-orchestration",
        }, log)).json,
      pass: (json) => enabledIn(json) === false,
    }, log);
    return {
      method: "cephDisableOrchestration",
      adminHost,
      outcome: "disabled",
      enabledBefore: true,
    };
  } catch (e) {
    log?.warn("Orchestration was NOT stopped", {
      adminHost,
      error: (e as Error).message,
    });
    return {
      method: "cephDisableOrchestration",
      adminHost,
      outcome: "clusterUnreachable",
      ...(enabledBefore !== undefined ? { enabledBefore } : {}),
      unreachableReason: (e as Error).message,
    };
  }
}

/** Purges a named cluster from one host. */
export async function rmCluster(
  deps: PrepDeps,
  session: SshSession,
  args: {
    host: string;
    fsid: string;
    zapOsds: boolean;
    verifyTimeoutMs?: number | null;
    verifyPollIntervalMs?: number | null;
  },
  log?: Logger,
): Promise<Record<string, unknown>> {
  const before = await observeHost(deps, session, args.host);
  const verdict = classifyFsid(before, args.fsid);
  if (verdict === "refuse") {
    fail("rm-cluster", "host carries an unnamed cluster", {
      host: args.host,
      named: args.fsid,
      found: before.fsids,
      unnamed: before.fsids.filter((f) =>
        f.toLowerCase() !== args.fsid.toLowerCase()
      ),
    });
  }
  const budget = args.verifyTimeoutMs ?? 120_000;
  const ceiling = args.verifyPollIntervalMs ?? 5_000;
  if (verdict === "stranded") {
    log?.warn(
      "LVM items still hold the disks; the data-disk wipe must free them",
      {
        host: args.host,
        lvmResidue: lvmResidue(before),
      },
    );
    return {
      host: args.host,
      fsid: args.fsid,
      zapOsds: args.zapOsds,
      purged: false,
      alreadyAbsent: false,
      cephadmStateAbsent: true,
      lvmResidue: lvmResidue(before).map((r) => r.item),
      fsidsBefore: before.fsids,
      mdArraysAfter: before.mdArrays,
      capturedAt: new Date(deps.now()).toISOString(),
    };
  }
  let command: string | undefined;
  if (verdict === "purge") {
    command = `cephadm rm-cluster --force${
      args.zapOsds ? " --zap-osds" : ""
    } --fsid ${quote(args.fsid)}`;
    const purge = await session.run({
      command,
      sudo: true,
      budgetMs: 600_000,
      allowNonZero: true,
    });
    if (purge.code !== 0) {
      fail("rm-cluster", "rm-cluster failed", {
        host: args.host,
        code: purge.code,
        stderr: purge.stderr.slice(0, 300),
      });
    }
  }
  const poll = await pollEffect(deps, {
    budgetMs: budget,
    ceilingMs: ceiling,
    label: "rm-cluster",
    phase: "rm-cluster",
    read: () => observeHost(deps, session, args.host),
    pass: (s) => cephadmResidue(s, "rm-cluster").length === 0,
  }, log);
  const after = poll.value;
  const lvm = lvmResidue(after, "rm-cluster").map((r) => r.item);
  return {
    host: args.host,
    fsid: args.fsid,
    zapOsds: args.zapOsds,
    purged: verdict === "purge",
    alreadyAbsent: verdict === "no-op",
    ...(command !== undefined ? { command } : {}),
    fsidsBefore: before.fsids,
    fsidsAfter: after.fsids,
    clusterUnitsBefore: before.clusterUnits,
    cephVolumeGroupsBefore: before.cephVolumeGroups,
    lvmResidue: lvm,
    mdArraysAfter: after.mdArrays,
    capturedAt: new Date(deps.now()).toISOString(),
  };
}

/** Refuses unless every fsid on the host is the named one. */
export async function verifyClusterFsid(
  deps: PrepDeps,
  session: SshSession,
  host: string,
  fsid: string,
  _log?: Logger,
): Promise<
  {
    host: string;
    fsid: string;
    pass: boolean;
    fsidsFound: string[];
    carriesNamedFsid: boolean;
  }
> {
  const state = await observeHost(deps, session, host);
  const verdict = classifyFsid(state, fsid);
  if (verdict === "refuse") {
    fail(
      "verify-cluster-fsid",
      "host carries an unnamed cluster; nothing has been changed on any host",
      {
        host,
        named: fsid,
        found: state.fsids,
        unnamed: state.fsids.filter((f) =>
          f.toLowerCase() !== fsid.toLowerCase()
        ),
        remedy:
          "check the host's state, then re-run naming the correct fsid or target the correct host",
      },
    );
  }
  return {
    host,
    fsid,
    pass: true,
    fsidsFound: state.fsids,
    carriesNamedFsid: state.fsids.some((f) =>
      f.toLowerCase() === fsid.toLowerCase()
    ),
  };
}

/** The full derived state plus an fsid/pass/findings verdict. */
export async function hostTornDown(
  deps: PrepDeps,
  session: SshSession,
  host: string,
  fsid: string,
): Promise<
  HostState & {
    fsid: string;
    pass: boolean;
    namedFsidGone: boolean;
    findings: Residue[];
  }
> {
  const state = await observeHost(deps, session, host);
  const findings = wholeHostResidue(state, "verify-host-torn-down");
  return {
    ...state,
    fsid,
    pass: findings.length === 0,
    namedFsidGone: !state.fsids.some((f) =>
      f.toLowerCase() === fsid.toLowerCase()
    ),
    findings,
  };
}
