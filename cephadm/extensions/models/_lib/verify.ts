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
import type { SshSession } from "./ssh.ts";
import type { PrepDeps } from "./hostprep.ts";
import { runCeph } from "./shell.ts";
import { parseAuthEntities } from "./dataplane.ts";

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
): Promise<unknown> {
  const r = await runCeph(deps, session, args, { json: true, phase }, log);
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
  const json = await read(deps, session, "auth ls", "csi-users", log);
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
