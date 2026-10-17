/**
 * Cluster lifecycle: bootstrap, admin-key distribution, host enrolment and
 * daemon placement.
 *
 * Cluster-side `ceph ...` commands run through `cephadm shell`; host-level
 * `cephadm` commands and `authorized_keys` work run directly. Bootstrap proves
 * "no cluster" positively before creating one, and treats a lost session as an
 * unknown outcome rather than as failure. Placement converges to an explicit
 * host list and never to a count.
 *
 * @module
 */

import { fail, TransportError } from "./errors.ts";
import type { CommandResult, SshSession } from "./ssh.ts";
import { runStep } from "./ssh.ts";
import {
  assertSshPublicKey,
  CEPH_ID_CREATE_RE,
  isIpv4,
  quote,
} from "./validate.ts";
import type { PrepDeps } from "./hostprep.ts";
import { runCeph } from "./shell.ts";

/** A public key read from a host must be a single valid SSH public key line. */
export function validateCephPubKey(text: string): string {
  const key = text.trim();
  assertSshPublicKey("cephPubKey", key);
  return key;
}

/** One of the three outcomes of the `cephadm ls` probe. */
export type ProbeOutcome =
  | { outcome: "found"; fsid: string }
  | { outcome: "none" }
  | { outcome: "unknown"; reason: string; code: number; stderr: string };

/** Probes a host for an existing cluster via `sudo -n cephadm ls` (no `-f`). */
export async function probeCephadmLs(
  session: SshSession,
): Promise<ProbeOutcome> {
  const r = await runStep(
    { sleep: () => Promise.resolve() },
    session,
    {
      command: "cephadm ls",
      sudo: true,
      allowNonZero: true,
      phase: "cephBootstrap.probe",
      resend: "any",
    },
  );
  if (r.code !== 0) {
    return {
      outcome: "unknown",
      reason: `exit ${r.code}`,
      code: r.code,
      stderr: r.stderr.slice(0, 300),
    };
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(r.stdout);
  } catch {
    return {
      outcome: "unknown",
      reason: "output is not JSON",
      code: r.code,
      stderr: "",
    };
  }
  if (!Array.isArray(parsed)) {
    return {
      outcome: "unknown",
      reason: "output is not a JSON array",
      code: r.code,
      stderr: "",
    };
  }
  for (const entry of parsed) {
    const fsid = (entry as { fsid?: unknown }).fsid;
    if (typeof fsid === "string" && fsid !== "") {
      return { outcome: "found", fsid };
    }
  }
  return { outcome: "none" };
}

/** Reads and validates `/etc/ceph/ceph.pub` under sudo. */
export async function readCephPubKey(session: SshSession): Promise<string> {
  const r = await runStep(
    { sleep: () => Promise.resolve() },
    session,
    {
      command: "cat /etc/ceph/ceph.pub",
      sudo: true,
      allowNonZero: true,
      phase: "cephBootstrap.ceph-pub",
      resend: "any",
    },
  );
  if (r.code !== 0) {
    fail("cephBootstrap.ceph-pub", "could not read the cluster public key", {
      code: r.code,
      stderr: r.stderr.slice(0, 300),
    });
  }
  return validateCephPubKey(r.stdout);
}

/** A unique config-file name for one bootstrap run. */
export function bootstrapConfPath(random: () => number): string {
  let hex = "";
  while (hex.length < 12) {
    hex += (Math.floor(random() * 256) & 0xff).toString(16).padStart(2, "0");
  }
  return `/tmp/cephadm-bootstrap-${hex.slice(0, 12)}.conf`;
}

/** The `sh -c` compound one bootstrap run executes under sudo. */
export function bootstrapCompound(opts: {
  conf: string;
  publicNet: string;
  clusterNet: string;
  cephImage: string;
  monIp: string;
  sshUser: string;
}): string {
  return [
    `printf '[global]\\npublic_network = %s\\n' ${quote(opts.publicNet)} > ${
      quote(opts.conf)
    }`,
    `cephadm --image ${quote(opts.cephImage)} bootstrap -c ${
      quote(opts.conf)
    } --mon-ip ${quote(opts.monIp)} --cluster-network ${
      quote(opts.clusterNet)
    } --ssh-user ${quote(opts.sshUser)} --skip-monitoring-stack`,
    "rc=$?",
    `rm -f ${quote(opts.conf)}`,
    "exit $rc",
  ].join("\n");
}

/** True when `monIp` lies inside the CIDR `publicNet`. */
export function ipInCidr(monIp: string, publicNet: string): boolean {
  const slash = publicNet.indexOf("/");
  if (slash < 0) return false;
  const base = publicNet.slice(0, slash);
  const prefix = Number(publicNet.slice(slash + 1));
  if (!isIpv4(base) || !isIpv4(monIp)) return false;
  const toInt = (ip: string) => {
    const o = ip.split(".").map(Number);
    return ((o[0] << 24) | (o[1] << 16) | (o[2] << 8) | o[3]) >>> 0;
  };
  const mask = prefix === 0 ? 0 : (~0 << (32 - prefix)) >>> 0;
  return ((toInt(monIp) & mask) >>> 0) === ((toInt(base) & mask) >>> 0);
}

/** Result of a bootstrap run. */
export interface BootstrapResult {
  /** Cluster fsid. */
  fsid: string;
  /** Validated cluster public key. */
  cephPubKey: string;
  /** True only if this run created the cluster. */
  bootstrapped: boolean;
  /** True only if recovery after a transport failure proved the cluster. */
  recoveredAfterTransportError: boolean;
}

/**
 * Bootstraps a cluster, or adopts the one already on the host. `session` is the
 * bootstrap host; `cephadm` runs at host level.
 */
export async function bootstrapCluster(
  deps: PrepDeps,
  session: SshSession,
  opts: {
    host: string;
    monIp: string;
    publicNet: string;
    clusterNet: string;
    cephImage: string;
    sshUser: string;
    timeoutMs: number;
  },
  log?: { warn: (message: string, props?: Record<string, unknown>) => void },
): Promise<BootstrapResult> {
  const first = await probeCephadmLs(session);
  if (first.outcome === "unknown") {
    fail("cephBootstrap", "could not tell whether a cluster exists", {
      host: opts.host,
      reason: first.reason,
      code: first.code,
    });
  }
  if (first.outcome === "found") {
    const cephPubKey = await readCephPubKey(session);
    return {
      fsid: first.fsid,
      cephPubKey,
      bootstrapped: false,
      recoveredAfterTransportError: false,
    };
  }

  const conf = bootstrapConfPath(deps.random);
  const compound = bootstrapCompound({ ...opts, conf });
  let transportError: TransportError | null = null;
  let commandResult: CommandResult | null = null;
  try {
    // A lost session here may still leave a running bootstrap, so it is
    // handled specially rather than by the shared re-send helper.
    commandResult = await session.run({
      command: `sh -c ${quote(compound)}`,
      sudo: true,
      budgetMs: opts.timeoutMs,
      allowNonZero: true,
    });
  } catch (e) {
    if (e instanceof TransportError) transportError = e;
    else throw e;
  }

  if (transportError !== null) {
    const again = await probeCephadmLs(session);
    if (again.outcome === "found") {
      log?.warn("Bootstrap session was lost but the cluster is now visible", {
        host: opts.host,
      });
      const cephPubKey = await readCephPubKey(session);
      return {
        fsid: again.fsid,
        cephPubKey,
        bootstrapped: true,
        recoveredAfterTransportError: true,
      };
    }
    throw transportError;
  }

  if (commandResult !== null && commandResult.code !== 0) {
    fail("cephBootstrap", "bootstrap failed", {
      host: opts.host,
      code: commandResult.code,
      stderr: commandResult.stderr.slice(0, 300),
    });
  }

  const reprobe = await probeCephadmLs(session);
  if (reprobe.outcome !== "found") {
    fail("cephBootstrap", "bootstrap succeeded but no cluster is visible", {
      host: opts.host,
    });
  }
  const cephPubKey = await readCephPubKey(session);
  return {
    fsid: reprobe.fsid,
    cephPubKey,
    bootstrapped: true,
    recoveredAfterTransportError: false,
  };
}

/** One host's key-distribution outcome. */
export interface DistributeOutcome {
  /** Target host. */
  host: string;
  /** Target port. */
  port: number;
  /** Whether the key was already present before this run. */
  alreadyPresent: boolean;
  /** Whether a backup of authorized_keys was taken. */
  backedUp: boolean;
  /** Whether the key verified after the run. */
  verified: boolean;
  /** Reason on failure. */
  reason?: string;
}

/** The 40-character tail needle used to verify a distributed key. */
export function keyNeedle(cephPubKey: string): string {
  const blob = cephPubKey.split(" ")[1] ?? "";
  if (blob.length < 40) {
    fail("cephDistributeKey", "the public key body is too short to verify", {
      length: blob.length,
    });
  }
  return blob.slice(-40);
}

/** Distributes the cluster key to one host over an already-open session. */
export async function distributeKeyToHost(
  deps: PrepDeps,
  session: SshSession,
  cephPubKey: string,
  host: string,
  port: number,
): Promise<DistributeOutcome> {
  assertSshPublicKey("cephPubKey", cephPubKey);
  const needle = keyNeedle(cephPubKey);
  const setup = await runStep(deps, session, {
    command:
      'mkdir -p "$HOME/.ssh" && chmod 700 "$HOME/.ssh" && touch "$HOME/.ssh/authorized_keys" && chmod 600 "$HOME/.ssh/authorized_keys" && cp -a "$HOME/.ssh/authorized_keys" "$HOME/.ssh/authorized_keys.bak"',
    phase: "cephDistributeKey.setup",
    resend: "dropped",
  });
  if (setup.code !== 0) {
    return {
      host,
      port,
      alreadyPresent: false,
      backedUp: false,
      verified: false,
      reason: "setup failed",
    };
  }
  const present = await runStep(deps, session, {
    command: `grep -Fqx -- ${quote(cephPubKey)} "$HOME/.ssh/authorized_keys"`,
    allowNonZero: true,
    phase: "cephDistributeKey.check",
    resend: "any",
  });
  const alreadyPresent = present.code === 0;
  if (!alreadyPresent) {
    const appended = await runStep(deps, session, {
      command: 'cat >> "$HOME/.ssh/authorized_keys"',
      stdin: `${cephPubKey}\n`,
      phase: "cephDistributeKey.append",
      resend: "dropped",
    });
    if (appended.code !== 0) {
      return {
        host,
        port,
        alreadyPresent,
        backedUp: true,
        verified: false,
        reason: "append failed",
      };
    }
  }
  const verify = await runStep(deps, session, {
    command: `grep -Fq -- ${quote(needle)} "$HOME/.ssh/authorized_keys"`,
    allowNonZero: true,
    phase: "cephDistributeKey.verify",
    resend: "any",
  });
  const verified = verify.code === 0;
  return verified
    ? { host, port, alreadyPresent, backedUp: true, verified: true }
    : {
      host,
      port,
      alreadyPresent,
      backedUp: true,
      verified: false,
      reason: "key not found after distribution",
    };
}

/** The sorted `host:port` record key for a set of targets. */
export function distributeRecordKey(
  hosts: { host: string; port: number }[],
): string {
  return `cephDistributeKey-${
    hosts.map((h) => `${h.host}:${h.port}`).sort().join(",")
  }`;
}

/** Result of enrolling a host. */
export interface HostAddResult {
  /** Whether this run issued the add. */
  added: boolean;
}

/** Enrols `host` at `addr`, gating on `fsid`. */
export async function hostAdd(
  deps: PrepDeps,
  session: SshSession,
  opts: { fsid: string; host: string; addr: string },
  log?: { warn: (message: string, props?: Record<string, unknown>) => void },
): Promise<HostAddResult> {
  const fsid = await runCeph(deps, session, "fsid", {
    phase: "cephHostAdd.fsid",
  }, log);
  const actual = fsid.result.stdout.trim().toLowerCase();
  if (actual !== opts.fsid.toLowerCase()) {
    fail("cephHostAdd", "refusing to mutate a possibly-wrong cluster", {
      expected: opts.fsid.toLowerCase(),
      actual,
    });
  }
  const before = await readHostList(deps, session, log);
  const existing = before.find((h) => h.hostname === opts.host);
  if (existing) {
    if (existing.addr !== opts.addr) {
      fail("cephHostAdd", "the host is registered at a different address", {
        host: opts.host,
        expected: opts.addr,
        actual: existing.addr,
      });
    }
    return { added: false };
  }
  await runCeph(
    deps,
    session,
    `orch host add ${quoteHost(opts.host)} ${quoteHost(opts.addr)}`,
    {
      phase: "cephHostAdd.add",
    },
    log,
  );
  const after = await readHostList(deps, session, log);
  if (!after.some((h) => h.hostname === opts.host && h.addr === opts.addr)) {
    fail(
      "cephHostAdd",
      "the host list does not show the host at the requested address",
      {
        host: opts.host,
        addr: opts.addr,
      },
    );
  }
  return { added: true };
}

/** Quotes a hostname or address for a ceph command (they are grammar-validated). */
function quoteHost(value: string): string {
  return quote(value);
}

interface HostListEntry {
  hostname: string;
  addr: string;
}

/** Reads `ceph orch host ls -f json` into host/addr pairs. */
export async function readHostList(
  deps: PrepDeps,
  session: SshSession,
  log?: { warn: (message: string, props?: Record<string, unknown>) => void },
): Promise<HostListEntry[]> {
  const r = await runCeph(deps, session, "orch host ls", {
    json: true,
    phase: "cephHostAdd.host-ls",
  }, log);
  const parsed = r.json;
  if (!Array.isArray(parsed)) return [];
  return parsed.flatMap((e) => {
    const hostname = (e as { hostname?: unknown }).hostname;
    const addr = (e as { addr?: unknown }).addr;
    return typeof hostname === "string"
      ? [{ hostname, addr: typeof addr === "string" ? addr : "" }]
      : [];
  });
}

// ---------------------------------------------------------------------------
// Placement convergence
// ---------------------------------------------------------------------------

/** An existing service's placement. */
export interface ExistingPlacement {
  /** Normalised host names. */
  hosts: string[];
  /** A count, when the spec used one. */
  count: number | null;
}

/** Strips a network and a daemon name from a reported placement host. */
export function normalisePlacementHost(value: string): string {
  return value.split("=")[0].split(":")[0];
}

/** Reads the first entry's placement from `ceph orch ls --service_name <svc>` output. */
export function parsePlacement(json: unknown): ExistingPlacement | null {
  if (!Array.isArray(json) || json.length === 0) return null;
  const placement = (json[0] as { placement?: unknown }).placement;
  if (placement === null || typeof placement !== "object") return null;
  const p = placement as { hosts?: unknown; count?: unknown };
  const hosts = Array.isArray(p.hosts)
    ? p.hosts.filter((h): h is string => typeof h === "string").map(
      normalisePlacementHost,
    )
    : [];
  const count = typeof p.count === "number" ? p.count : null;
  return { hosts, count };
}

/** True when the existing placement equals the requested host set with no count. */
export function placementConverged(
  existing: ExistingPlacement | null,
  requested: string[],
): boolean {
  if (existing === null) return false;
  if (existing.count !== null) return false;
  if (existing.hosts.length === 0) return false;
  const a = [...new Set(existing.hosts)].sort();
  const b = [...new Set(requested)].sort();
  return a.length === b.length && a.every((h, i) => h === b[i]);
}

/** Outcome of converging one service's placement. */
export interface ApplyPlacementResult {
  /** Whether an apply was issued. */
  applied: boolean;
  /** Whether a count spec was replaced. */
  replacedCountSpec: boolean;
  /** The previous count, or null. */
  previousCount: number | null;
}

/** Converges a placement service to an explicit host list. */
export async function applyPlacement(
  deps: PrepDeps,
  session: SshSession,
  opts: {
    serviceName: string;
    applyArgs: string;
    requested: string[];
    phase: string;
  },
  log?: { warn: (message: string, props?: Record<string, unknown>) => void },
): Promise<ApplyPlacementResult> {
  const ls = await runCeph(
    deps,
    session,
    `orch ls --service_name ${quote(opts.serviceName)}`,
    { json: true, phase: `${opts.phase}.read` },
    log,
  );
  const existing = parsePlacement(ls.json);
  if (placementConverged(existing, opts.requested)) {
    return { applied: false, replacedCountSpec: false, previousCount: null };
  }
  await runCeph(
    deps,
    session,
    `orch apply ${opts.applyArgs} --placement=${
      quote(opts.requested.join(","))
    }`,
    { phase: `${opts.phase}.apply` },
    log,
  );
  return {
    applied: true,
    replacedCountSpec: existing?.count !== null &&
      existing?.count !== undefined,
    previousCount: existing?.count ?? null,
  };
}

// ---------------------------------------------------------------------------
// Mon quorum safety
// ---------------------------------------------------------------------------

/** The mon-quorum judgement for a proposed placement. */
export interface QuorumCheck {
  /** Whether the check ran. */
  evaluated: boolean;
  /** Pass/fail, or null when the reads failed. */
  pass: boolean | null;
  /** In-quorum mons whose hosts remain in the placement. */
  kept: number;
  /** Current in-quorum mon count. */
  current: number;
}

/** Evaluates whether `placement` keeps a strict majority of in-quorum mons. */
export function evaluateMonQuorum(
  monDump: unknown,
  quorumStatus: unknown,
  placement: string[],
): QuorumCheck {
  const mons = (monDump as { mons?: unknown }).mons;
  const inQuorum = (quorumStatus as { quorum_names?: unknown }).quorum_names;
  if (!Array.isArray(mons) || !Array.isArray(inQuorum)) {
    return { evaluated: true, pass: null, kept: 0, current: 0 };
  }
  const requested = new Set(placement.map(normalisePlacementHost));
  const hosts = mons.map((m) => String((m as { name?: unknown }).name ?? ""));
  const quorum = inQuorum.filter((n): n is string => typeof n === "string");
  const kept =
    quorum.filter((name) =>
      hosts.includes(name) && requested.has(normalisePlacementHost(name))
    ).length;
  const current = quorum.length;
  return { evaluated: true, pass: kept * 2 > current, kept, current };
}

/** Reads the monmap and quorum and evaluates a proposed placement. */
export async function checkMonQuorum(
  deps: PrepDeps,
  session: SshSession,
  placement: string[],
  log?: { warn: (message: string, props?: Record<string, unknown>) => void },
): Promise<QuorumCheck> {
  const dump = await runCeph(deps, session, "mon dump", {
    json: true,
    phase: "cephApplyMon.quorum",
  }, log);
  const status = await runCeph(deps, session, "quorum_status", {
    json: true,
    phase: "cephApplyMon.quorum",
  }, log);
  return evaluateMonQuorum(dump.json, status.json, placement);
}

/** A Ceph service identifier is creatable and may not be empty. */
export function cephIdentifier(value: string): boolean {
  return CEPH_ID_CREATE_RE.test(value);
}

/** Mon placement result, including the quorum judgement. */
export interface MonApplyResult extends ApplyPlacementResult {
  /** The quorum judgement recorded with the result. */
  quorumCheck: {
    /** Whether the check ran (false when already converged). */
    evaluated: boolean;
    /** Pass/fail, or null when it could not run. */
    pass: boolean | null;
    /** Whether the operator overrode a non-passing check. */
    overridden: boolean;
    /** In-quorum mons whose hosts remain. */
    kept: number;
    /** Current in-quorum mon count. */
    current: number;
  };
}

/** Converges mon placement, with a quorum-safety gate before any change. */
export async function applyMon(
  deps: PrepDeps,
  session: SshSession,
  opts: { placement: string[]; allowQuorumRisk: boolean },
  log?: { warn: (message: string, props?: Record<string, unknown>) => void },
): Promise<MonApplyResult> {
  const ls = await runCeph(
    deps,
    session,
    "orch ls --service_name 'mon'",
    { json: true, phase: "cephApplyMon.read" },
    log,
  );
  const existing = parsePlacement(ls.json);
  const emptyQuorum = {
    evaluated: false,
    pass: null,
    overridden: false,
    kept: 0,
    current: 0,
  };
  if (placementConverged(existing, opts.placement)) {
    return {
      applied: false,
      replacedCountSpec: false,
      previousCount: null,
      quorumCheck: emptyQuorum,
    };
  }
  let quorum: QuorumCheck;
  try {
    quorum = await checkMonQuorum(deps, session, opts.placement, log);
  } catch {
    // The check could not run; treat it as a non-passing check, not a refusal.
    quorum = { evaluated: true, pass: null, kept: 0, current: 0 };
  }
  if (quorum.pass !== true && !opts.allowQuorumRisk) {
    fail(
      "cephApplyMon",
      "refusing to change mon placement: the quorum check did not pass",
      {
        kept: quorum.kept,
        current: quorum.current,
        placement: opts.placement,
      },
    );
  }
  if (quorum.pass !== true) {
    log?.warn("Changing mon placement despite a quorum risk", {
      kept: quorum.kept,
      current: quorum.current,
    });
  }
  await runCeph(
    deps,
    session,
    `orch apply mon --placement=${quote(opts.placement.join(","))}`,
    { phase: "cephApplyMon.apply" },
    log,
  );
  return {
    applied: true,
    replacedCountSpec: existing?.count !== null &&
      existing?.count !== undefined,
    previousCount: existing?.count ?? null,
    quorumCheck: {
      evaluated: true,
      pass: quorum.pass,
      overridden: quorum.pass !== true,
      kept: quorum.kept,
      current: quorum.current,
    },
  };
}
