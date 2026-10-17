/**
 * Verification checks: the shared verify-result contract, settle polling, and
 * the cluster-membership checks.
 *
 * Every check produces exactly one verdict, persists it before throwing, and
 * throws only when the caller asked for it. A read that never produced an
 * answer rethrows its transport error instead of inventing a verdict, and a
 * malformed answer stops a poll at once.
 *
 * @module
 */

import { cappedBackoff, type WaitDeps } from "./backoff.ts";
import { fail, TransportError } from "./errors.ts";
import type { SshSession } from "./ssh_session.ts";
import {
  CEPHADM_PATH,
  parseDpkgVersion,
  type PrepDeps,
  probeCephadmVersion,
} from "./hostprep.ts";
import { runCeph, runCephScript } from "./shell.ts";
import { parseAuthEntities } from "./dataplane.ts";
import { assertSshPublicKey, quote } from "./validate.ts";
import { findNode, lsblkCommand, parseLsblk, subtreeMounts } from "./wipe.ts";
import { resolveSerial } from "./resolve.ts";

type Logger = {
  info: (m: string, p?: Record<string, unknown>) => void;
  warn: (m: string, p?: Record<string, unknown>) => void;
};

/** One check's verdict. */
export interface VerifyOutcome {
  /** Whether the check passed. */
  pass: boolean;
  /** What the caller asserted. */
  expected: unknown;
  /** What was observed, or null when nothing was observed. */
  actual: unknown;
  /** Extra evidence. */
  detail: Record<string, unknown>;
  /** The subject the check is about, when it has one. */
  subject?: string;
}

/** Settle poll options. */
export interface SettleOptions<T> {
  /** Poll budget; 0 means one read. */
  budgetMs: number;
  /** Backoff ceiling. */
  ceilingMs: number;
  /** Reads once. */
  read: () => Promise<T>;
  /** Decides whether a read is the passing state. */
  pass: (value: T) => boolean;
  /** Iteration bound, so a frozen clock cannot spin. */
  maxIterations?: number;
}

/**
 * Re-reads until `pass` accepts, the budget runs out, or the iteration bound
 * is hit. Transport errors are retried; any other error propagates. When no
 * read ever produced an answer, the last transport error is rethrown.
 */
export async function settle<T>(
  deps: WaitDeps,
  opts: SettleOptions<T>,
): Promise<{ value: T | null; attempts: number }> {
  const max = opts.maxIterations ?? 10_000;
  const started = deps.now();
  const deadline = started + Math.max(0, opts.budgetMs);
  let last: T | null = null;
  let lastError: TransportError | null = null;
  let attempts = 0;
  for (let i = 0; i < max; i++) {
    attempts++;
    try {
      const value = await opts.read();
      last = value;
      lastError = null;
      if (opts.pass(value)) return { value, attempts };
    } catch (e) {
      if (e instanceof TransportError) {
        lastError = e;
      } else {
        throw e;
      }
    }
    if (opts.budgetMs <= 0) break;
    const remaining = deadline - deps.now();
    if (remaining <= 0) break;
    await deps.sleep(
      Math.min(remaining, cappedBackoff(i, opts.ceilingMs, deps.random())),
    );
  }
  if (last === null && lastError !== null) throw lastError;
  return { value: last, attempts };
}

/** Options for persisting a verdict. */
export interface PersistVerdictOptions {
  /** Method name, recorded. */
  method: string;
  /** Admin host, recorded and used in the key. */
  host: string;
  /** Error phase tag. */
  phase: string;
  /** Record key. */
  key: string;
  /** The verdict. */
  outcome: VerifyOutcome;
  /** Throw after recording when the verdict fails. */
  throwOnFail: boolean;
}

/** The parts of the method context persistence needs. */
interface WriteContext {
  /** Writes a resource and returns its handle. */
  writeResource: (
    specName: string,
    name: string,
    data: Record<string, unknown>,
  ) => Promise<{ name: string }>;
}

/** Writes the verify record, then throws when the verdict failed and asked to. */
export async function persistVerdict(
  context: WriteContext,
  deps: PrepDeps,
  opts: PersistVerdictOptions,
): Promise<{ name: string }> {
  const record: Record<string, unknown> = {
    method: opts.method,
    host: opts.host,
    pass: opts.outcome.pass,
    expected: opts.outcome.expected,
    actual: opts.outcome.actual,
    detail: opts.outcome.detail,
    capturedAt: new Date(deps.now()).toISOString(),
  };
  if (opts.outcome.subject !== undefined) record.subject = opts.outcome.subject;
  const handle = await context.writeResource(
    "cephVerifyResult",
    opts.key,
    record,
  );
  if (!opts.outcome.pass && opts.throwOnFail) {
    const detail: Record<string, unknown> = {
      expected: JSON.stringify(opts.outcome.expected),
      actual: JSON.stringify(opts.outcome.actual),
    };
    for (const [k, v] of Object.entries(opts.outcome.detail)) {
      detail[k] = typeof v === "string" ? v : JSON.stringify(v);
    }
    detail.recordKey = opts.key;
    fail(opts.phase, "verification failed", detail);
  }
  return handle;
}

/** Reads `ceph <args>` JSON, throwing a phase error on failure. */
async function read(
  deps: PrepDeps,
  session: SshSession,
  args: string,
  phase: string,
  log?: Logger,
  redact = false,
): Promise<unknown> {
  const r = await runCeph(
    deps,
    session,
    args,
    { json: true, phase, redactStdout: redact },
    log,
  );
  if (r.result.code !== 0) {
    fail(phase, `command failed: ceph ${args}`, {
      code: r.result.code,
      stderr: r.result.stderr.slice(0, 300),
    });
  }
  return r.json;
}

/** Times a settle block for the record's detail. */
function settleDetail(
  attempts: number,
  elapsedMs: number,
): Record<string, unknown> {
  return { settle: { attempts, elapsedMs } };
}

// ---------------------------------------------------------------------------
// cephVerifyMonQuorum
// ---------------------------------------------------------------------------

/** Arguments for the mon-quorum check. */
export interface MonQuorumArgs {
  /** Expected number of mons in the monmap. */
  expectedMonCount: number;
  /** Settle budget in ms. */
  quorumSettleMs?: number | null;
  /** Backoff ceiling in ms. */
  quorumPollIntervalMs?: number | null;
}

/** Asserts the monmap count and that every defined mon is in quorum. */
export async function verifyMonQuorum(
  deps: PrepDeps,
  session: SshSession,
  args: MonQuorumArgs,
  log?: Logger,
): Promise<VerifyOutcome> {
  const budget = args.quorumSettleMs ?? 0;
  const ceiling = args.quorumPollIntervalMs ?? 10_000;
  const started = deps.now();
  const outcome = (value: {
    monNames: string[];
    quorumNames: string[];
  }): VerifyOutcome => {
    const outOfQuorum = value.monNames.filter((n) =>
      !value.quorumNames.includes(n)
    );
    const pass = value.monNames.length === args.expectedMonCount &&
      outOfQuorum.length === 0;
    return {
      pass,
      expected: { monCount: args.expectedMonCount, allInQuorum: true },
      actual: {
        monCount: value.monNames.length,
        quorumCount: value.quorumNames.length,
        outOfQuorum,
      },
      detail: { monNames: value.monNames, quorumNames: value.quorumNames },
    };
  };
  const result = await settle(deps, {
    budgetMs: budget,
    ceilingMs: ceiling,
    read: async () => {
      const json = await read(
        deps,
        session,
        "quorum_status",
        "mon-quorum",
        log,
      ) as {
        monmap?: { mons?: { name?: string }[] };
        quorum_names?: string[];
      };
      return {
        monNames: (json.monmap?.mons ?? []).flatMap((m) =>
          typeof m.name === "string" ? [m.name] : []
        ),
        quorumNames: (json.quorum_names ?? []).filter((n): n is string =>
          typeof n === "string"
        ),
      };
    },
    pass: (v) => outcome(v).pass,
  });
  const value = result.value ?? { monNames: [], quorumNames: [] };
  const verdict = outcome(value);
  verdict.detail = {
    ...verdict.detail,
    ...settleDetail(result.attempts, deps.now() - started),
  };
  return verdict;
}

// ---------------------------------------------------------------------------
// cephVerifyMgr
// ---------------------------------------------------------------------------

/** Arguments for the mgr check. */
export interface MgrArgs {
  /** Expected total mgr count. */
  expectedCount: number;
}

/** Asserts the mgr count and that one mgr is genuinely active. */
export async function verifyMgr(
  deps: PrepDeps,
  session: SshSession,
  args: MgrArgs,
  log?: Logger,
): Promise<VerifyOutcome> {
  const json = await read(deps, session, "mgr dump", "mgr", log) as {
    active_name?: unknown;
    standbys?: unknown;
  };
  const activeName =
    typeof json.active_name === "string" && json.active_name !== ""
      ? json.active_name
      : null;
  const standbys = Array.isArray(json.standbys) ? json.standbys : [];
  const active = activeName !== null;
  const total = (active ? 1 : 0) + standbys.length;
  const pass = active && total === args.expectedCount;
  return {
    pass,
    expected: { total: args.expectedCount, active: true },
    actual: {
      total,
      active,
      activeName,
      standbyCount: standbys.length,
    },
    detail: {
      standbyNames: standbys.filter((s): s is string => typeof s === "string"),
    },
  };
}

// ---------------------------------------------------------------------------
// cephVerifyOsd
// ---------------------------------------------------------------------------

/** Arguments for the OSD check. */
export interface OsdArgs {
  /** Expected up count. */
  expectedUp: number;
  /** Expected in count. */
  expectedIn: number;
  /** Expected CRUSH failure domain. */
  expectedFailureDomain: string;
  /** Rule name; default is the rule with rule_id 0. */
  crushRuleName?: string | null;
  /** Settle budget in ms. */
  osdSettleMs?: number | null;
  /** Backoff ceiling in ms. */
  osdPollIntervalMs?: number | null;
}

/** Selects the CRUSH rule by name, or by rule_id 0 when no name is given. */
export function selectCrushRule(
  json: unknown,
  name: string | null,
): Record<string, unknown> | null {
  const rules = Array.isArray(json)
    ? json as Record<string, unknown>[]
    : json !== null && typeof json === "object"
    ? [json as Record<string, unknown>]
    : [];
  if (name === null) return rules.find((r) => r.rule_id === 0) ?? null;
  return rules.find((r) => r.rule_name === name) ?? null;
}

/** The failure domain of a CRUSH rule: the type of the first choosing step. */
export function crushFailureDomain(
  rule: Record<string, unknown>,
): string | null {
  const steps = rule.steps;
  if (!Array.isArray(steps)) return null;
  for (const step of steps) {
    const s = step as { op?: unknown; type?: unknown };
    if (
      typeof s.op === "string" && s.op.startsWith("choose") &&
      typeof s.type === "string"
    ) {
      return s.type;
    }
  }
  return null;
}

/** Asserts OSD up/in counts and a CRUSH rule's failure domain. */
export async function verifyOsd(
  deps: PrepDeps,
  session: SshSession,
  args: OsdArgs,
  log?: Logger,
): Promise<VerifyOutcome> {
  const budget = args.osdSettleMs ?? 0;
  const ceiling = args.osdPollIntervalMs ?? 10_000;
  const started = deps.now();
  const evaluate = (value: {
    up: number;
    in: number;
    numOsds: number;
    rule: Record<string, unknown> | null;
    ruleNames: string[];
  }): VerifyOutcome => {
    const osdPass = value.up === args.expectedUp &&
      value.in === args.expectedIn;
    const domain = value.rule === null ? null : crushFailureDomain(value.rule);
    const crushPass = value.rule !== null &&
      domain === args.expectedFailureDomain;
    return {
      pass: osdPass && crushPass,
      expected: {
        osd: { up: args.expectedUp, in: args.expectedIn },
        crush: { failureDomain: args.expectedFailureDomain },
      },
      actual: {
        osd: { up: value.up, in: value.in, numOsds: value.numOsds },
        crush: value.rule === null ? null : {
          ruleName: value.rule.rule_name,
          ruleId: value.rule.rule_id,
          failureDomain: domain,
        },
      },
      detail: {
        osd: { numOsds: value.numOsds },
        crush: value.rule === null
          ? { reason: "rule not found", availableRules: value.ruleNames }
          : {
            ruleName: value.rule.rule_name,
            ruleId: value.rule.rule_id,
            failureDomain: domain,
          },
      },
    };
  };
  const result = await settle(deps, {
    budgetMs: budget,
    ceilingMs: ceiling,
    read: async () => {
      const stat = await read(deps, session, "osd stat", "osd", log) as {
        num_up_osds?: number;
        num_in_osds?: number;
        num_osds?: number;
      };
      const rulesJson = await read(
        deps,
        session,
        "osd crush rule dump",
        "osd",
        log,
      );
      const rules = Array.isArray(rulesJson)
        ? rulesJson as Record<string, unknown>[]
        : [];
      const rule = selectCrushRule(rulesJson, args.crushRuleName ?? null);
      return {
        up: stat.num_up_osds ?? 0,
        in: stat.num_in_osds ?? 0,
        numOsds: stat.num_osds ?? 0,
        rule,
        ruleNames: rules.flatMap((r) =>
          typeof r.rule_name === "string" ? [r.rule_name] : []
        ),
      };
    },
    pass: (v) => evaluate(v).pass,
  });
  const value = result.value ??
    { up: 0, in: 0, numOsds: 0, rule: null, ruleNames: [] };
  const verdict = evaluate(value);
  verdict.detail = {
    ...verdict.detail,
    ...settleDetail(result.attempts, deps.now() - started),
  };
  return verdict;
}

// ---------------------------------------------------------------------------
// cephVerifyCsiUsers
// ---------------------------------------------------------------------------

/** Asserts that every expected client entity exists. */
export async function verifyCsiUsers(
  deps: PrepDeps,
  session: SshSession,
  expectedUserNames: string[],
  log?: Logger,
): Promise<VerifyOutcome> {
  // auth ls output carries keys; never let a parse error echo it.
  const json = await read(deps, session, "auth ls", "csi-users", log, true);
  const entities = parseAuthEntities(json);
  const found = new Map(entities.map((e) => [e.entity, e.caps]));
  const expected = expectedUserNames.map((n) => `client.${n}`);
  const missing = expected.filter((e) => !found.has(e));
  const users = expected.flatMap((e) =>
    found.has(e) ? [{ entity: e, caps: found.get(e)! }] : []
  );
  return {
    pass: missing.length === 0,
    expected,
    actual: expected.filter((e) => found.has(e)),
    detail: { missing, users },
  };
}

/** The host-subtree `noout` predicate result. */
export interface NooutPredicate {
  /** Whether the flag is set for the host. */
  set: boolean;
  /** The statement that asserted it, when one did. */
  matched: string | null;
  /** `OSD_FLAGS` summary messages. */
  summaries: string[];
  /** `OSD_FLAGS` detail messages. */
  details: string[];
}

/**
 * The shared host-subtree noout predicate. It reads only `checks.OSD_FLAGS`
 * from `ceph health detail`; the cluster-wide flags in `osd dump` are never
 * consulted.
 */
export function nooutPredicate(
  healthDetail: unknown,
  hostName: string,
): NooutPredicate {
  const checks = (healthDetail as { checks?: Record<string, unknown> }).checks;
  const osdFlags = checks?.OSD_FLAGS as
    | { summary?: { message?: unknown }; detail?: { message?: unknown }[] }
    | undefined;
  if (osdFlags === undefined) {
    return { set: false, matched: null, summaries: [], details: [] };
  }
  const summaries: string[] = [];
  if (typeof osdFlags.summary?.message === "string") {
    summaries.push(osdFlags.summary.message);
  }
  const details: string[] = [];
  for (const d of osdFlags.detail ?? []) {
    if (typeof d.message === "string") details.push(d.message);
  }
  for (const statement of [...summaries, ...details]) {
    const m = statement.match(/^host\s+(\S+)\s+has flags\s+(.+)$/i);
    if (!m) continue;
    if (m[1] !== hostName) continue;
    const flags = m[2].split(",").map((f) => f.trim().toLowerCase());
    if (flags.includes("noout")) {
      return { set: true, matched: statement, summaries, details };
    }
  }
  return { set: false, matched: null, summaries, details };
}

/** Arguments for the host-noout check. */
export interface HostNooutArgs {
  /** Ceph host whose subtree flag is checked. */
  hostName: string;
  /** Expected state of the flag. */
  expectSet: boolean;
}

/** Checks a host-subtree noout against the caller's expectation. */
export async function verifyHostNoout(
  deps: PrepDeps,
  session: SshSession,
  args: HostNooutArgs,
  log?: Logger,
): Promise<VerifyOutcome> {
  const detail = await read(deps, session, "health detail", "host-noout", log);
  const predicate = nooutPredicate(detail, args.hostName);
  return {
    pass: predicate.set === args.expectSet,
    expected: { hostName: args.hostName, nooutSet: args.expectSet },
    actual: { hostName: args.hostName, nooutSet: predicate.set },
    subject: args.hostName,
    detail: {
      osdFlagsSummary: predicate.summaries,
      osdFlagsDetail: predicate.details,
      matchedStatement: predicate.matched,
      readFrom: "checks.OSD_FLAGS",
      osdDumpConsulted: false,
    },
  };
}

/** Arguments for the health check. */
export interface HealthArgs {
  /** Direction: true asserts healthy, false asserts not healthy. */
  wantOk: boolean;
  /** Health check names treated as tolerated when wantOk is true. */
  allowedWarnings?: string[] | null;
}

/** A trivial verdict for the health refusals. */
function healthRefusal(
  wantOk: boolean,
  reason: string,
  detail: Record<string, unknown>,
): VerifyOutcome {
  return {
    pass: false,
    expected: wantOk,
    actual: null,
    detail: { reason, ...detail },
  };
}

/** Asserts cluster health in a stated direction with a warning allowlist. */
export async function verifyHealth(
  deps: PrepDeps,
  session: SshSession,
  args: HealthArgs,
  log?: Logger,
): Promise<VerifyOutcome> {
  const allowed = (args.allowedWarnings ?? []).map((w) => w.toUpperCase());
  const json = await read(deps, session, "health detail", "health", log) as {
    status?: unknown;
    checks?: Record<string, { summary?: { message?: unknown } }>;
  };
  const status = json.status;
  if (typeof status !== "string" || status === "") {
    return healthRefusal(args.wantOk, "status is missing or empty", {});
  }
  const upper = status.toUpperCase();
  if (!["HEALTH_OK", "HEALTH_WARN", "HEALTH_ERR"].includes(upper)) {
    return healthRefusal(args.wantOk, "unknown health status", { status });
  }
  const checks = json.checks ?? {};
  const checkNames = Object.keys(checks);
  if (upper === "HEALTH_WARN" && checkNames.length === 0) {
    return healthRefusal(args.wantOk, "HEALTH_WARN with no named check", {
      status: upper,
    });
  }
  if (!args.wantOk && allowed.length > 0) {
    return healthRefusal(
      args.wantOk,
      "wantOk false cannot be combined with an allowlist",
      {
        status: upper,
        allowedWarnings: args.allowedWarnings ?? [],
      },
    );
  }
  const unallowedChecks = checkNames.filter((n) =>
    !allowed.includes(n.toUpperCase())
  );
  const healthy = upper === "HEALTH_OK" ||
    (upper === "HEALTH_WARN" && unallowedChecks.length === 0);
  const messages: Record<string, unknown> = {};
  for (const name of checkNames) {
    messages[name] = checks[name]?.summary?.message ?? null;
  }
  return {
    pass: healthy === args.wantOk,
    expected: args.wantOk,
    actual: healthy,
    detail: {
      status: upper,
      activeChecks: checkNames,
      unallowedChecks,
      messages,
    },
  };
}

// ---------------------------------------------------------------------------
// cephVerifyHostPrep
// ---------------------------------------------------------------------------

/** Arguments for the host-prep check. */
export interface HostPrepVerifyArgs {
  /** Packages that must be installed. */
  expectedPackages: string[];
  /** Exact cephadm version token expected. */
  expectedCephadmVersion: string;
  /** Time-sync service that must be active. */
  expectedTimeSyncService: string;
}

/** Assert the facts cephHostPrep establishes, without changing anything. */
export async function verifyHostPrep(
  _deps: PrepDeps,
  session: SshSession,
  args: HostPrepVerifyArgs,
  _log?: Logger,
): Promise<VerifyOutcome> {
  const packages: { name: string; present: boolean; version?: string }[] = [];
  const missingPackages: string[] = [];
  for (const name of args.expectedPackages) {
    const r = await session.run({
      command: `dpkg -s ${quote(name)}`,
      allowNonZero: true,
    });
    const present = r.code === 0;
    const version = present ? parseDpkgVersion(r.stdout) : undefined;
    packages.push({
      name,
      present,
      ...(version !== undefined ? { version } : {}),
    });
    if (!present) missingPackages.push(name);
  }
  const presentResult = await session.run({
    command: `test -x ${CEPHADM_PATH}`,
    allowNonZero: true,
  });
  const cephadmPresent = presentResult.code === 0;
  let token: string | null = null;
  let rawOutput = "";
  if (cephadmPresent) {
    const probe = await probeCephadmVersion(
      session,
      args.expectedCephadmVersion,
    );
    token = probe.token;
    rawOutput = probe.stdout;
  }
  const sync = await session.run({
    command: `systemctl is-active ${quote(args.expectedTimeSyncService)}`,
    allowNonZero: true,
  });
  const timeSyncActive = sync.stdout.trim() === "active";
  const pass = missingPackages.length === 0 && cephadmPresent &&
    token === args.expectedCephadmVersion && timeSyncActive;
  return {
    pass,
    expected: {
      packages: args.expectedPackages,
      cephadmPresent: true,
      cephadmVersion: args.expectedCephadmVersion,
      timeSyncActive: true,
    },
    actual: {
      missingPackages,
      cephadmPresent,
      cephadmVersion: token,
      cephadmVersionOutput: rawOutput,
      timeSyncActive,
    },
    detail: { packages },
  };
}

// ---------------------------------------------------------------------------
// cephVerifyDisksRaw
// ---------------------------------------------------------------------------

/** Assert that each serial-resolved device is genuinely raw. */
export async function verifyDisksRaw(
  _deps: PrepDeps,
  session: SshSession,
  dataDevices: { serial: string }[],
  _log?: Logger,
): Promise<VerifyOutcome> {
  const read = await session.run({
    command: lsblkCommand(),
    allowNonZero: true,
  });
  const tree = parseLsblk(read.stdout);
  const expected: Record<string, unknown> = {};
  const actual: Record<string, unknown> = {};
  const perDevice: unknown[] = [];
  const mounted: string[] = [];
  const unobserved: string[] = [];
  for (const d of dataDevices) {
    const resolved = await resolveSerial(session, d.serial, "disks-raw");
    expected[d.serial] = { raw: true };
    const node = findNode(tree, resolved.device);
    if (!node) {
      actual[d.serial] = "not found";
      unobserved.push(d.serial);
      perDevice.push({
        serial: d.serial,
        path: resolved.path,
        device: resolved.device,
        found: false,
      });
      continue;
    }
    const mounts = subtreeMounts(node);
    const children = (node.children ?? []).map((c) => ({
      name: c.name ?? "",
      type: c.type ?? "",
    }));
    const raw = !node.fstype && (node.children ?? []).length === 0 &&
      mounts.length === 0;
    actual[d.serial] = raw
      ? "raw"
      : { fstype: node.fstype ?? null, children, mountpoints: mounts };
    if (mounts.length > 0) mounted.push(d.serial);
    perDevice.push({
      serial: d.serial,
      path: resolved.path,
      device: resolved.device,
      fstype: node.fstype ?? null,
      children,
      mountpoints: mounts,
    });
  }
  const pass = Object.values(actual).every((v) => v === "raw");
  return {
    pass,
    expected,
    actual,
    detail: { perDevice, mounted, unobserved },
  };
}

// ---------------------------------------------------------------------------
// cephVerifyKeyDistributed
// ---------------------------------------------------------------------------

/** One host's key read-back. */
export interface KeyReadBack {
  /** Target host. */
  host: string;
  /** `present`, `absent`, `unreadable` or `unreachable`. */
  outcome: "present" | "absent" | "unreadable" | "unreachable";
  /** Whether the key was found. */
  present: boolean;
  /** Whether `authorized_keys` was readable. */
  readable: boolean;
  /** Extra evidence. */
  detail?: string;
}

/** Options for the key-distribution check. */
export interface KeyDistributedOptions {
  /** Hosts the key was distributed to. */
  hosts: string[];
  /** SSH port for every host. */
  port: number;
  /** The public key to look for. */
  cephPubKey: string;
  /** Opens a fresh, non-multiplexed session to one host. */
  makeSession: (host: string) => Promise<SshSession>;
}

/** Reads each host's authorized_keys on a fresh connection. */
export async function verifyKeyDistributed(
  _deps: PrepDeps,
  opts: KeyDistributedOptions,
  _log?: Logger,
): Promise<{ outcome: VerifyOutcome; unreachable: TransportError[] }> {
  assertSshPublicKey("cephPubKey", opts.cephPubKey);
  const readBacks: KeyReadBack[] = [];
  const unreachable: TransportError[] = [];
  for (const host of opts.hosts) {
    let session: SshSession;
    try {
      session = await opts.makeSession(host);
    } catch (e) {
      if (e instanceof TransportError) {
        unreachable.push(e);
        readBacks.push({
          host,
          outcome: "unreachable",
          present: false,
          readable: false,
          detail: e.message,
        });
        continue;
      }
      throw e;
    }
    try {
      const r = await session.run({
        command: `grep -qF -- ${
          quote(opts.cephPubKey)
        } "$HOME/.ssh/authorized_keys"`,
        allowNonZero: true,
      });
      if (r.code === 0) {
        readBacks.push({
          host,
          outcome: "present",
          present: true,
          readable: true,
        });
      } else if (r.code === 1) {
        readBacks.push({
          host,
          outcome: "absent",
          present: false,
          readable: true,
        });
      } else {
        readBacks.push({
          host,
          outcome: "unreadable",
          present: false,
          readable: false,
          detail: (r.stderr || r.stdout || `grep exited ${r.code}`).slice(
            0,
            200,
          ),
        });
      }
    } catch (e) {
      if (e instanceof TransportError) {
        unreachable.push(e);
        readBacks.push({
          host,
          outcome: "unreachable",
          present: false,
          readable: false,
          detail: e.message,
        });
      } else {
        throw e;
      }
    } finally {
      await session.close();
    }
  }
  const absentOn = readBacks.filter((r) => r.outcome === "absent").map((r) =>
    r.host
  );
  const unreadableOn = readBacks.filter((r) => r.outcome === "unreadable").map((
    r,
  ) => r.host);
  const unreachableOn = readBacks.filter((r) => r.outcome === "unreachable")
    .map((r) => r.host);
  const missingHosts = opts.hosts.filter((h) =>
    !readBacks.some((r) => r.host === h)
  );
  const pass = missingHosts.length === 0 && absentOn.length === 0 &&
    unreadableOn.length === 0 &&
    unreachableOn.length === 0;
  return {
    outcome: {
      pass,
      expected: {
        hosts: opts.hosts,
        condition: "key present in authorized_keys on every host",
      },
      actual: readBacks,
      detail: {
        missingHosts,
        absentOn,
        unreadableOn,
        unreachableOn,
        cannotSee:
          "this check cannot prove that sshd will accept the key (file location, ownership, mode or a non-default AuthorizedKeysFile), nor that cephadm can log in, which needs the private half",
      },
    },
    unreachable,
  };
}

// ---------------------------------------------------------------------------
// cephCapacityReport
// ---------------------------------------------------------------------------

/** One pool's capacity and durability margin. */
export interface CapacityPool {
  /** Pool name. */
  name: string;
  /** Pool id. */
  id: number | null;
  /** `replicated`, `erasure` or `unknown`. */
  poolType: string;
  /** Replica count or k+m. */
  size: number | null;
  /** Durability floor. */
  minSize: number | null;
  /** size - minSize, or null. */
  minSizeMargin: number | null;
  /** Placement groups. */
  pgNum: number | null;
  /** EC profile name, or null. */
  ecProfile: string | null;
  /** Bytes stored. */
  storedBytes: number | null;
  /** Bytes used. */
  usedBytes: number | null;
  /** Percent used. */
  percentUsed: number | null;
  /** Maximum available bytes. */
  maxAvailBytes: number | null;
  /** Object count. */
  objects: number | null;
  /** True unless the pool appeared in both reads. */
  partial: boolean;
}

/** The capacity report's data. */
export interface CapacityReport {
  /** Cluster totals. */
  cluster: {
    /** Total bytes. */
    totalBytes: number | null;
    /** Available bytes. */
    availBytes: number | null;
    /** Used bytes. */
    usedBytes: number | null;
    /** Raw used ratio. */
    rawUsedRatio: number | null;
    /** OSD count. */
    numOsds: number | null;
  };
  /** Per-pool rows, sorted by name. */
  pools: CapacityPool[];
  /** Number of pools. */
  poolCount: number;
  /** Pools seen in only one read. */
  partialCount: number;
  /** EC pools whose min_size margin is <= 1. */
  atRiskPools: string[];
  /** EC pools whose margin could not be judged. */
  unjudgedPools: string[];
}

/** A finite number, or null. */
function num(v: unknown): number | null {
  return typeof v === "number" && Number.isFinite(v) ? v : null;
}

/** Maps a Ceph pool type number to a name. */
export function poolTypeOf(v: unknown): string {
  if (v === 1) return "replicated";
  if (v === 3) return "erasure";
  return "unknown";
}

/** Builds the capacity report from the two reads. */
export async function capacityReport(
  deps: PrepDeps,
  session: SshSession,
  log?: Logger,
): Promise<CapacityReport> {
  const df = await read(deps, session, "df", "capacity", log) as {
    stats?: Record<string, unknown>;
    pools?: { name?: unknown; id?: unknown; stats?: Record<string, unknown> }[];
  };
  let detail = await read(deps, session, "osd pool ls detail", "capacity", log);
  if (!Array.isArray(detail)) detail = [];
  const detailPools = (detail as Record<string, unknown>[]).filter((p) =>
    typeof p.pool_name === "string" && p.pool_name !== ""
  );
  const dfPools = (Array.isArray(df.pools) ? df.pools : []).filter((p) =>
    typeof p.name === "string" && p.name !== ""
  );
  const names = new Set<string>();
  for (const p of detailPools) names.add(p.pool_name as string);
  for (const p of dfPools) names.add(p.name as string);
  const sorted = [...names].sort();

  const pools: CapacityPool[] = sorted.map((name) => {
    const d = detailPools.find((p) => p.pool_name === name);
    const f = dfPools.find((p) => p.name === name);
    const size = d ? num(d.size) : null;
    const minSize = d ? num(d.min_size) : null;
    const ecProfile = d && typeof d.erasure_code_profile === "string" &&
        d.erasure_code_profile !== ""
      ? d.erasure_code_profile
      : null;
    const stats = f?.stats ?? {};
    return {
      name,
      id: d ? num(d.pool) : (f ? num(f.id) : null),
      poolType: d ? poolTypeOf(d.type) : "unknown",
      size,
      minSize,
      minSizeMargin: size !== null && minSize !== null ? size - minSize : null,
      pgNum: d ? num(d.pg_num) : null,
      ecProfile,
      storedBytes: num(stats.stored),
      usedBytes: num(stats.bytes_used),
      percentUsed: num(stats.percent_used),
      maxAvailBytes: num(stats.max_avail),
      objects: num(stats.objects),
      partial: !(d !== undefined && f !== undefined),
    };
  });

  if (pools.length === 0) {
    fail("capacity", "the cluster reports no pools", { poolCount: 0 });
  }

  const atRiskPools = pools
    .filter((p) =>
      p.poolType === "erasure" && p.minSizeMargin !== null &&
      p.minSizeMargin <= 1
    )
    .map((p) => p.name);
  const unjudgedPools = pools
    .filter((p) => p.poolType === "erasure" && p.minSizeMargin === null)
    .map((p) => p.name);
  const stats = df.stats ?? {};
  const report: CapacityReport = {
    cluster: {
      totalBytes: num(stats.total_bytes),
      availBytes: num(stats.total_avail_bytes),
      usedBytes: num(stats.total_used_bytes),
      rawUsedRatio: num(stats.total_used_raw_ratio),
      numOsds: num(stats.num_osds),
    },
    pools,
    poolCount: pools.length,
    partialCount: pools.filter((p) => p.partial).length,
    atRiskPools,
    unjudgedPools,
  };
  log?.info("Capacity report: {pools} pools, {osds} OSDs, {atRisk} at risk", {
    pools: report.poolCount,
    osds: report.cluster.numOsds ?? "unknown",
    atRisk: report.atRiskPools.length + report.unjudgedPools.length,
  });
  return report;
}

// ---------------------------------------------------------------------------
// Placement pre-checks
// ---------------------------------------------------------------------------

interface OrchPsRow {
  daemonType: string;
  daemonId: string;
  hostname: string;
}

/** Parses `ceph orch ps` rows. */
export function parseOrchPs(json: unknown): OrchPsRow[] {
  if (!Array.isArray(json)) return [];
  return json.flatMap((raw) => {
    if (raw === null || typeof raw !== "object") return [];
    const e = raw as Record<string, unknown>;
    const daemonType = typeof e.daemon_type === "string" ? e.daemon_type : "";
    const daemonId = typeof e.daemon_id === "string" ? e.daemon_id : "";
    const hostname = typeof e.hostname === "string" ? e.hostname : "";
    return daemonType === "" || daemonId === ""
      ? []
      : [{ daemonType, daemonId, hostname }];
  });
}

/** Parses `ceph orch host ls` into hostname -> status. */
export function parseHostStatus(json: unknown): Map<string, string> {
  const out = new Map<string, string>();
  if (!Array.isArray(json)) return out;
  for (const raw of json) {
    if (raw === null || typeof raw !== "object") continue;
    const e = raw as Record<string, unknown>;
    if (typeof e.hostname === "string") {
      out.set(e.hostname, typeof e.status === "string" ? e.status : "");
    }
  }
  return out;
}

/** Judges a proposed mon placement against live quorum. */
export async function verifyMonPlacement(
  deps: PrepDeps,
  session: SshSession,
  placement: string[],
  log?: Logger,
): Promise<VerifyOutcome> {
  const quorum = await read(
    deps,
    session,
    "quorum_status",
    "mon-placement",
    log,
  ) as {
    monmap?: { mons?: { name?: string }[] };
    quorum_names?: string[];
  };
  const ps = parseOrchPs(
    await read(deps, session, "orch ps", "mon-placement", log),
  );
  const hostStatus = parseHostStatus(
    await read(deps, session, "orch host ls", "mon-placement", log),
  );
  const monNames = (quorum.monmap?.mons ?? []).flatMap((m) =>
    typeof m.name === "string" ? [m.name] : []
  );
  const quorumNames = (quorum.quorum_names ?? []).filter((n): n is string =>
    typeof n === "string"
  );
  const requestSet = new Set(placement);
  const monRows = ps.filter((r) => r.daemonType === "mon");
  const hostByName = new Map(monRows.map((r) => [r.daemonId, r.hostname]));
  const orchOnlyMons = monRows.filter((r) => !monNames.includes(r.daemonId))
    .map((r) => r.daemonId);
  const outOfQuorum = monNames.filter((n) => !quorumNames.includes(n));
  const monHosts = monNames.map((name) => ({
    name,
    host: hostByName.get(name) ?? null,
  }));
  const unmappedMons = monHosts.filter((m) => m.host === null).map((m) =>
    m.name
  );
  const currentHosts = [
    ...new Set(monHosts.flatMap((m) => m.host === null ? [] : [m.host])),
  ];
  const retainedHosts = placement.filter((h) => currentHosts.includes(h));
  const removedHosts = currentHosts.filter((h) => !requestSet.has(h));
  const addedHosts = placement.filter((h) => !currentHosts.includes(h));
  const retainedMons = monHosts.filter((m) =>
    m.host !== null && quorumNames.includes(m.name) && requestSet.has(m.host)
  );
  const majorityKept = monNames.length > 0 &&
    2 * retainedMons.length > monNames.length;
  const unknownPlacementHosts = placement.filter((h) => !hostStatus.has(h));
  const unavailableAddedHosts = addedHosts.filter((h) =>
    (hostStatus.get(h) ?? "") !== ""
  );
  const reasons: string[] = [];
  if (monNames.length === 0) reasons.push("the monmap lists no mons");
  if (outOfQuorum.length > 0) {
    reasons.push(`mons out of quorum: ${outOfQuorum.join(", ")}`);
  }
  if (unmappedMons.length > 0) {
    reasons.push(`mons with no orch ps row: ${unmappedMons.join(", ")}`);
  }
  if (unknownPlacementHosts.length > 0) {
    reasons.push(
      `placement hosts unknown to orch host ls: ${
        unknownPlacementHosts.join(", ")
      }`,
    );
  }
  if (unavailableAddedHosts.length > 0) {
    reasons.push(
      `added hosts not deployable: ${unavailableAddedHosts.join(", ")}`,
    );
  }
  if (!majorityKept && monNames.length > 0) {
    reasons.push(
      `the placement keeps ${retainedMons.length} of ${monNames.length} mons, not a strict majority`,
    );
  }
  return {
    pass: reasons.length === 0,
    expected: {
      monmapNonEmpty: true,
      allInQuorum: true,
      allMonsMapped: true,
      hostsKnown: true,
      addedHostsDeployable: true,
      majorityKept: true,
    },
    actual: {
      monmapNonEmpty: monNames.length > 0,
      allInQuorum: outOfQuorum.length === 0,
      allMonsMapped: unmappedMons.length === 0,
      hostsKnown: unknownPlacementHosts.length === 0,
      addedHostsDeployable: unavailableAddedHosts.length === 0,
      majorityKept,
      retainedHosts,
      removedHosts,
      addedHosts,
    },
    detail: {
      monNames,
      quorumNames,
      outOfQuorum,
      monHosts,
      unmappedMons,
      orchOnlyMons,
      placement,
      retainedHosts,
      removedHosts,
      addedHosts,
      retainedMons: retainedMons.map((m) => m.name),
      unknownPlacementHosts,
      unavailableAddedHosts,
      majorityKept,
      monmapEmpty: monNames.length === 0,
      reasons,
    },
  };
}

/** Judges a proposed mgr placement, reporting a collision with an active MDS. */
export async function verifyMgrPlacement(
  deps: PrepDeps,
  session: SshSession,
  placement: string[],
  log?: Logger,
): Promise<VerifyOutcome> {
  const mgr = await read(deps, session, "mgr dump", "mgr-placement", log) as {
    active_name?: unknown;
  };
  const fsDump = await read(deps, session, "fs dump", "mgr-placement", log) as {
    filesystems?: {
      mdsmap?: { info?: Record<string, { name?: unknown; state?: unknown }> };
    }[];
  };
  const ps = parseOrchPs(
    await read(deps, session, "orch ps", "mgr-placement", log),
  );
  const hostStatus = parseHostStatus(
    await read(deps, session, "orch host ls", "mgr-placement", log),
  );
  const activeName =
    typeof mgr.active_name === "string" && mgr.active_name !== ""
      ? mgr.active_name
      : null;
  const activeMgrHost = activeName === null
    ? null
    : ps.find((r) => r.daemonType === "mgr" && r.daemonId === activeName)
      ?.hostname ?? null;
  const mdsHostById = new Map(
    ps.filter((r) => r.daemonType === "mds").map((
      r,
    ) => [r.daemonId, r.hostname]),
  );
  const activeMds: { fsName: string; name: string; host: string | null }[] = [];
  const unmappedMds: string[] = [];
  const fsWithoutActiveMds: string[] = [];
  for (const fs of fsDump.filesystems ?? []) {
    const info = fs.mdsmap?.info ?? {};
    let found = false;
    for (const entry of Object.values(info)) {
      const state = typeof entry.state === "string"
        ? entry.state.toLowerCase()
        : "";
      const name = typeof entry.name === "string" ? entry.name : "";
      if (state === "up:active") {
        found = true;
        const host = mdsHostById.get(name) ?? null;
        if (host === null) unmappedMds.push(name);
        activeMds.push({
          fsName: fsDump.filesystems?.indexOf(fs) === undefined ? "" : "",
          name,
          host,
        });
      }
    }
    if (!found) fsWithoutActiveMds.push("");
  }
  const unknownPlacementHosts = placement.filter((h) => !hostStatus.has(h));
  const besideActiveMds = placement.filter((h) =>
    activeMds.some((m) => m.host === h)
  );
  const reasons: string[] = [];
  if (activeName === null) reasons.push("no active mgr");
  if (unknownPlacementHosts.length > 0) {
    reasons.push(
      `placement hosts unknown: ${unknownPlacementHosts.join(", ")}`,
    );
  }
  if (unmappedMds.length > 0) {
    reasons.push(`active MDS with no host: ${unmappedMds.join(", ")}`);
  }
  if (besideActiveMds.length > 0) {
    reasons.push(
      `placement hosts run an active MDS: ${besideActiveMds.join(", ")}`,
    );
  }
  if (fsWithoutActiveMds.length > 0) {
    reasons.push(
      `${fsWithoutActiveMds.length} filesystem(s) with no up:active MDS`,
    );
  }
  return {
    pass: reasons.length === 0,
    expected: {
      activeMgrPresent: true,
      hostsKnown: true,
      activeMdsMapped: true,
      placementClearOfActiveMds: true,
      everyFsHasActiveMds: true,
    },
    actual: {
      activeMgr: activeName === null
        ? null
        : { name: activeName, host: activeMgrHost },
      unknownPlacementHosts,
      unmappedMds,
      besideActiveMds,
      fsWithoutActiveMds,
      activeMds,
    },
    detail: {
      activeMgr: activeName === null
        ? null
        : { name: activeName, host: activeMgrHost },
      activeMds,
      unknownPlacementHosts,
      unmappedMds,
      besideActiveMds,
      fsWithoutActiveMds,
      reasons,
    },
  };
}

// ---------------------------------------------------------------------------
// cephVerifyPool
// ---------------------------------------------------------------------------

/** Arguments for the pool check. */
export interface PoolVerifyArgs {
  /** Pool name. */
  poolName: string;
  /** Expected size (replicas, or k+m). */
  expectedSize: number;
  /** Expected min_size, when asserted. */
  expectedMinSize?: number | null;
  /** Expected EC shape, when asserted. */
  expectedErasureProfile?:
    | { k: number; m: number; failureDomain: string }
    | null;
  /** Optional MDS assertion. */
  mds?:
    | { fsName: string; expectedActive: number; expectedStandby: number }
    | null;
  /** Settle budget in ms. */
  settleMs?: number | null;
  /** Backoff ceiling in ms. */
  settlePollIntervalMs?: number | null;
}

/** The raw observation one poll makes. */
interface PoolObservation {
  pool: Record<string, unknown> | null;
  availablePools: string[];
  pgReadable: boolean;
  pgStats: { pgid: string; state: string }[];
  ecProfileRaw: unknown;
  ecReadable: boolean;
  mds: { active: number; standby: number } | null;
}

/** Asserts a pool's size, PGs, EC shape and optional MDS state. */
export async function verifyPool(
  deps: PrepDeps,
  session: SshSession,
  args: PoolVerifyArgs,
  log?: Logger,
): Promise<VerifyOutcome> {
  const budget = args.settleMs ?? 0;
  const ceiling = args.settlePollIntervalMs ?? 10_000;
  const started = deps.now();

  const evaluate = (o: PoolObservation): VerifyOutcome => {
    const expected: Record<string, unknown> = {
      pool: {
        size: args.expectedSize,
        ...(args.expectedMinSize !== undefined && args.expectedMinSize !== null
          ? { minSize: args.expectedMinSize }
          : {}),
      },
    };
    const actual: Record<string, unknown> = {};
    const detail: Record<string, unknown> = {};
    const skipped: { check: string; reason: string }[] = [];

    if (o.pool === null) {
      actual.pool = null;
      detail.pool = { reason: "pool absent", availablePools: o.availablePools };
      for (const check of ["pgs", "ec", "mds"]) {
        skipped.push({ check, reason: "pool absent" });
      }
      return {
        pass: false,
        expected,
        actual,
        detail: { ...detail, skipped },
        subject: args.poolName,
      };
    }

    const size = typeof o.pool.size === "number" ? o.pool.size : null;
    const minSize = typeof o.pool.min_size === "number"
      ? o.pool.min_size
      : null;
    const sizeOk = size === args.expectedSize;
    const minAsserted = args.expectedMinSize !== undefined &&
      args.expectedMinSize !== null;
    const minOk = !minAsserted || minSize === args.expectedMinSize;
    actual.pool = { size, minSize };
    detail.pool = { size, minSize, minSizeAsserted: minAsserted };
    if (!minAsserted) {
      detail.pool = {
        ...detail.pool as object,
        minSizeNote: "observed but not certified",
      };
    }
    const skipReason = o.pool === null
      ? "pool absent"
      : !sizeOk
      ? "size mismatch"
      : !minOk
      ? "min_size mismatch"
      : null;
    if (skipReason !== null) {
      for (const check of ["pgs", "ec", "mds"]) {
        skipped.push({ check, reason: skipReason });
      }
      return {
        pass: false,
        expected,
        actual,
        detail: { ...detail, skipped },
        subject: args.poolName,
      };
    }

    // pgs
    const total = o.pgStats.length;
    const clean = o.pgStats.filter((p) => {
      const tokens = p.state.split("+");
      return tokens.includes("active") && tokens.includes("clean");
    });
    const pgsOk = total > 0 && clean.length === total;
    actual.pgs = `${clean.length}/${total} active+clean`;
    detail.pgs = { dirty: o.pgStats.filter((p) => !clean.includes(p)) };
    if (total === 0) detail.pgs = { reason: "no PGs" };

    // ec
    const profile = typeof o.pool.erasure_code_profile === "string" &&
        o.pool.erasure_code_profile !== ""
      ? o.pool.erasure_code_profile
      : null;
    let ecOk = true;
    if (args.expectedErasureProfile) {
      expected.ec = args.expectedErasureProfile;
      if (profile === null) {
        ecOk = false;
        actual.ec = null;
        detail.ec = { reason: "not erasure-coded" };
      } else if (!o.ecReadable) {
        ecOk = false;
        actual.ec = { profile };
        detail.ec = {
          reason: "EC profile could not be read; absence is not a pass",
          profile,
        };
      } else {
        const p = o.ecProfileRaw as Record<string, unknown>;
        const kRaw = p?.k;
        const mRaw = p?.m;
        const k = Number(kRaw);
        const m = Number(mRaw);
        const fd = p?.["crush-failure-domain"];
        const ecPass = Number.isInteger(k) && Number.isInteger(m) &&
          k === args.expectedErasureProfile.k &&
          m === args.expectedErasureProfile.m &&
          fd === args.expectedErasureProfile.failureDomain;
        ecOk = ecPass;
        actual.ec = {
          k: Number.isInteger(k) ? k : kRaw,
          m: Number.isInteger(m) ? m : mRaw,
          failureDomain: fd,
        };
        detail.ec = { profile, content: p };
      }
    } else {
      actual.ec = { profile, asserted: false };
      detail.ec = { profile, asserted: false, note: "not asserted" };
    }

    // mds
    let mdsOk = true;
    if (args.mds) {
      expected.mds = {
        active: args.mds.expectedActive,
        standbyAtLeast: args.mds.expectedStandby,
      };
      const observed = o.mds ?? { active: 0, standby: 0 };
      mdsOk = observed.active === args.mds.expectedActive &&
        observed.standby >= args.mds.expectedStandby;
      actual.mds = observed;
      detail.mds = observed;
    }

    return {
      pass: sizeOk && minOk && pgsOk && ecOk && mdsOk,
      expected,
      actual,
      detail: { ...detail, skipped },
      subject: args.poolName,
    };
  };

  const result = await settle(deps, {
    budgetMs: budget,
    ceilingMs: ceiling,
    read: async (): Promise<PoolObservation> => {
      let detailJson = await read(
        deps,
        session,
        "osd pool ls detail",
        "pool",
        log,
      );
      if (!Array.isArray(detailJson)) detailJson = [];
      const pools = detailJson as Record<string, unknown>[];
      const pool = pools.find((p) => p.pool_name === args.poolName) ?? null;
      const availablePools = pools.flatMap((p) =>
        typeof p.pool_name === "string" ? [p.pool_name] : []
      );
      let pgStats: { pgid: string; state: string }[] = [];
      let pgReadable = false;
      let ecProfileRaw: unknown = null;
      let ecReadable = false;
      let mds: { active: number; standby: number } | null = null;
      const size = pool && typeof pool.size === "number" ? pool.size : null;
      const minSize = pool && typeof pool.min_size === "number"
        ? pool.min_size
        : null;
      const gateOk = pool !== null && size === args.expectedSize &&
        (args.expectedMinSize === undefined || args.expectedMinSize === null ||
          minSize === args.expectedMinSize);
      if (gateOk && pool) {
        const pgs = await read(
          deps,
          session,
          `pg ls-by-pool ${quote(args.poolName)}`,
          "pool",
          log,
        ) as {
          pg_stats?: { pgid?: unknown; state?: unknown }[];
        };
        pgReadable = true;
        pgStats = (pgs.pg_stats ?? []).flatMap((p) =>
          typeof p.pgid === "string" && typeof p.state === "string"
            ? [{ pgid: p.pgid, state: p.state }]
            : []
        );
        const profile = typeof pool.erasure_code_profile === "string" &&
            pool.erasure_code_profile !== ""
          ? pool.erasure_code_profile
          : null;
        if (args.expectedErasureProfile && profile !== null) {
          ecProfileRaw = await read(
            deps,
            session,
            `osd erasure-code-profile get ${quote(profile)}`,
            "pool",
            log,
          );
          ecReadable = true;
        }
        if (args.mds) {
          const status = await read(
            deps,
            session,
            `fs status ${quote(args.mds.fsName)}`,
            "pool",
            log,
          ) as {
            mdsmap?: { state?: unknown }[];
          };
          const states = (status.mdsmap ?? []).map((m) =>
            typeof m.state === "string" ? m.state.toLowerCase() : ""
          );
          mds = {
            active: states.filter((s) => s === "active").length,
            standby: states.filter((s) => s === "standby").length,
          };
        }
      }
      return {
        pool,
        availablePools,
        pgReadable,
        pgStats,
        ecProfileRaw,
        ecReadable,
        mds,
      };
    },
    pass: (o) => evaluate(o).pass,
  });

  const observation: PoolObservation = result.value ?? {
    pool: null,
    availablePools: [],
    pgReadable: false,
    pgStats: [],
    ecProfileRaw: null,
    ecReadable: false,
    mds: null,
  };
  const verdict = evaluate(observation);
  const firstReadPassed = result.attempts === 1 && verdict.pass;
  verdict.detail = {
    ...verdict.detail,
    settle: {
      settleMs: budget,
      attempts: result.attempts,
      elapsedMs: deps.now() - started,
      firstReadPassed,
      observedTransition: result.attempts > 1 && verdict.pass,
    },
  };
  return verdict;
}

// ---------------------------------------------------------------------------
// cephVerifyRbdSmoke
// ---------------------------------------------------------------------------

/** A random UUID v4 from the injected randomness source. */
export function randomUuid(random: () => number): string {
  const bytes = Array.from(
    { length: 16 },
    () => Math.floor(random() * 256) & 0xff,
  );
  bytes[6] = (bytes[6] & 0x0f) | 0x40;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const hex = bytes.map((b) => b.toString(16).padStart(2, "0")).join("");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${
    hex.slice(16, 20)
  }-${hex.slice(20)}`;
}

/**
 * Creates, reads back and removes one tiny throwaway RBD image. This is the
 * only verify method that writes anything; it never touches a pre-existing
 * image.
 */
export async function verifyRbdSmoke(
  deps: PrepDeps,
  session: SshSession,
  pool: string,
  log?: Logger,
): Promise<VerifyOutcome> {
  const imageName = `cephadm-smoke-${randomUuid(deps.random)}`;
  const target = `${pool}/${imageName}`;
  const probe = await runCephScript(
    deps,
    session,
    {
      body: `rbd info ${quote(target)} --format json`,
      phase: "rbd-smoke.probe",
      allowNonZero: true,
    },
    log,
  );
  if (probe.result.code === 0) {
    fail("rbd-smoke", "the throwaway image name already exists", { imageName });
  }
  let createAttempted = false;
  let createError: Error | null = null;
  let infoMatches = false;
  let infoDetail: unknown = null;
  try {
    createAttempted = true;
    const created = await runCephScript(
      deps,
      session,
      {
        body: `rbd create --size 1M ${quote(target)}`,
        phase: "rbd-smoke.create",
      },
      log,
    );
    if (created.result.code !== 0) {
      createError = new Error(
        `cephadm[rbd-smoke]: rbd create exited ${created.result.code}`,
      );
    }
  } catch (e) {
    createError = e as Error;
  }
  if (createAttempted && createError === null) {
    try {
      const info = await runCephScript(
        deps,
        session,
        {
          body: `rbd info ${quote(target)} --format json`,
          phase: "rbd-smoke.info",
          allowNonZero: true,
        },
        log,
      );
      if (info.result.code !== 0) {
        infoDetail = {
          code: info.result.code,
          stderr: info.result.stderr.slice(0, 200),
        };
      } else {
        const parsed = parseCephJsonSafe(info.result.stdout);
        infoDetail = parsed;
        infoMatches = parsed !== null && parsed.name === imageName &&
          parsed.size === 1048576;
      }
    } catch (e) {
      createError = e as Error;
    }
  }
  let cleanedUp = false;
  let cleanupStderr = "";
  if (createAttempted) {
    try {
      const rm = await runCephScript(
        deps,
        session,
        {
          body: `rbd rm ${quote(target)}`,
          phase: "rbd-smoke.rm",
          allowNonZero: true,
        },
        log,
      );
      cleanedUp = rm.result.code === 0;
      cleanupStderr = rm.result.stderr.slice(0, 200);
    } catch {
      cleanedUp = false;
    }
  }
  if (createError !== null) throw createError;
  const created = createAttempted;
  return {
    pass: created && infoMatches && cleanedUp,
    expected: { created: true, infoMatches: true, cleanedUp: true },
    actual: { created, infoMatches, cleanedUp },
    detail: { pool, imageName, info: infoDetail, cleanupStderr },
  };
}

/** Parses JSON or returns null, never quoting the input. */
function parseCephJsonSafe(
  text: string,
): { name?: unknown; size?: unknown } | null {
  try {
    const parsed = JSON.parse(text.trim());
    return parsed !== null && typeof parsed === "object" ? parsed : null;
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// cephVerifyOsdClaimable
// ---------------------------------------------------------------------------

interface DeviceHost {
  hostname: string;
  devices: { deviceId: string; path: string; available: boolean }[] | null;
}

/** Parses `ceph orch device ls` host rows. */
export function parseDeviceHosts(json: unknown): DeviceHost[] {
  if (!Array.isArray(json)) return [];
  return json.flatMap((raw) => {
    if (raw === null || typeof raw !== "object") return [];
    const e = raw as Record<string, unknown>;
    const hostname = typeof e.hostname === "string" ? e.hostname : "";
    let devices: DeviceHost["devices"] = null;
    if (Array.isArray(e.devices)) {
      devices = e.devices.flatMap((d) => {
        if (d === null || typeof d !== "object") return [];
        const dev = d as Record<string, unknown>;
        return [{
          deviceId: typeof dev.device_id === "string"
            ? dev.device_id
            : (typeof dev.deviceId === "string" ? dev.deviceId : ""),
          path: typeof dev.path === "string" ? dev.path : "",
          available: dev.available === true,
        }];
      });
    }
    return [{ hostname, devices }];
  });
}

/** True when a device id names `serial` exactly or as a `_<serial>` suffix. */
export function deviceIdMatches(deviceId: string, serial: string): boolean {
  return deviceId === serial || deviceId.endsWith(`_${serial}`);
}

/** Arguments for the OSD-claimable pre-check. */
export interface OsdClaimableArgs {
  /** Fleet-wide mode. */
  allAvailableDevices?: boolean | null;
  /** Serials that must never be claimed. */
  excludeDevices?: { serial: string }[] | null;
  /** Selector target host. */
  targetHost?: string | null;
  /** Selector data devices. */
  dataDevices?: { serial: string }[] | null;
}

/** Judges which disks cephadm would claim, before an OSD apply. */
export async function verifyOsdClaimable(
  deps: PrepDeps,
  session: SshSession,
  args: OsdClaimableArgs,
  log?: Logger,
): Promise<VerifyOutcome> {
  const all = args.allAvailableDevices === true;
  const dataDevices = (args.dataDevices ?? []).filter((d) => d.serial !== "");
  const excludes = (args.excludeDevices ?? []).filter((d) => d.serial !== "");
  const targetHost =
    args.targetHost !== undefined && args.targetHost !== null &&
      args.targetHost !== ""
      ? args.targetHost
      : null;
  if (all && dataDevices.length > 0) {
    fail("osd-claimable", "choose one mode", {});
  }
  if (!all && dataDevices.length === 0) {
    fail("osd-claimable", "choose one mode", {});
  }
  if (all && targetHost !== null) {
    fail("osd-claimable", "all-available must not name a targetHost", {});
  }
  if (!all && targetHost === null) {
    fail("osd-claimable", "selector mode requires a targetHost", {});
  }
  if (all && excludes.length === 0) {
    fail("osd-claimable", "all-available requires excludes", {});
  }

  const json = await read(
    deps,
    session,
    "orch device ls",
    "osd-claimable",
    log,
  );
  const hosts = parseDeviceHosts(json);

  if (all) {
    const reasons: string[] = [];
    const claimableExcluded: { host: string; serial: string; path: string }[] =
      [];
    const unidentified: { host: string; path: string }[] = [];
    const malformedHosts: string[] = [];
    const hostsWithoutDevices: string[] = [];
    if (hosts.length === 0) reasons.push("the device listing has no hosts");
    for (const h of hosts) {
      if (h.devices === null) {
        malformedHosts.push(h.hostname);
        reasons.push(`${h.hostname} has no devices array`);
        continue;
      }
      if (h.devices.length === 0) {
        hostsWithoutDevices.push(h.hostname);
        reasons.push(`${h.hostname} has not been inventoried`);
        continue;
      }
      for (const d of h.devices) {
        if (!d.available) continue;
        if (d.deviceId === "") {
          unidentified.push({ host: h.hostname, path: d.path });
          reasons.push(`${h.hostname}:${d.path} has no device_id`);
          continue;
        }
        for (const ex of excludes) {
          if (deviceIdMatches(d.deviceId, ex.serial)) {
            claimableExcluded.push({
              host: h.hostname,
              serial: ex.serial,
              path: d.path,
            });
            reasons.push(
              `${h.hostname} would claim ${d.path} (serial ${ex.serial})`,
            );
          }
        }
      }
    }
    return {
      pass: reasons.length === 0,
      expected: { claimableDevicesExclude: excludes.map((e) => e.serial) },
      actual: {
        claimableExcluded,
        unidentified,
        malformedHosts,
        hostsWithoutDevices,
      },
      detail: {
        mode: "all",
        claimableExcluded,
        unidentified,
        malformedHosts,
        hostsWithoutDevices,
        reasons,
      },
    };
  }

  const host = hosts.find((h) => h.hostname === targetHost);
  const reasons: string[] = [];
  const matched: Record<string, number> = {};
  if (!host) {
    reasons.push(`target host ${targetHost} is not in the device listing`);
    for (const d of dataDevices) matched[d.serial] = 0;
  } else {
    const devices = host.devices ?? [];
    for (const d of dataDevices) {
      matched[d.serial] = devices.filter((dev) =>
        deviceIdMatches(dev.deviceId, d.serial)
      ).length;
      if (matched[d.serial] === 0) {
        reasons.push(`serial ${d.serial} matched no device on ${targetHost}`);
      }
      if (matched[d.serial] > 1) {
        reasons.push(
          `serial ${d.serial} matched ${
            matched[d.serial]
          } devices on ${targetHost}`,
        );
      }
    }
  }
  return {
    pass: reasons.length === 0,
    expected: { targetHost, eachSerialMatchedExactlyOnce: true },
    actual: { targetKnown: host !== undefined, matched },
    detail: { mode: "selector", targetHost, matched, reasons },
  };
}
