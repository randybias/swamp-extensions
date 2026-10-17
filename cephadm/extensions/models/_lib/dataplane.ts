/**
 * Data plane: pools, CephFS, client entities, the connection bundle and the
 * two destructive verbs.
 *
 * Every Ceph command runs through `cephadm shell`. Key material appears in the
 * output of several auth commands; it is parsed and discarded at once, never
 * recorded, logged or quoted in an error, except by the one sensitive method
 * that exists to store it in a vault-backed field.
 *
 * @module
 */

import { fail } from "./errors.ts";
import type { SshSession } from "./ssh.ts";
import { quote, truncate } from "./validate.ts";
import type { PrepDeps } from "./hostprep.ts";
import { runCeph } from "./shell.ts";
import { applyPlacement } from "./lifecycle.ts";

type Logger = {
  warn: (message: string, props?: Record<string, unknown>) => void;
};

/** The 10-minute default budget for pool and filesystem creation. */
export const CREATE_BUDGET_MS = 10 * 60 * 1000;

/** Reads `ceph <args> -f json`; `allowMissing` returns null on a non-zero exit. */
async function readJson(
  deps: PrepDeps,
  session: SshSession,
  args: string,
  opts: {
    phase: string;
    redact?: boolean;
    allowMissing?: boolean;
    budgetMs?: number;
  },
  log?: Logger,
): Promise<unknown> {
  const r = await runCeph(
    deps,
    session,
    args,
    {
      json: true,
      phase: opts.phase,
      redactStdout: opts.redact,
      budgetMs: opts.budgetMs,
    },
    log,
  );
  if (r.result.code !== 0) {
    if (opts.allowMissing) return null;
    fail(opts.phase, `command failed: ceph ${args}`, {
      code: r.result.code,
      stderr: r.result.stderr.slice(0, 300),
    });
  }
  return r.json;
}

/** Runs `ceph <args>`, returning the result; a non-zero exit throws unless tolerated. */
async function runMut(
  deps: PrepDeps,
  session: SshSession,
  args: string,
  opts: {
    phase: string;
    allowNonZero?: boolean;
    budgetMs?: number;
    redact?: boolean;
  },
  log?: Logger,
) {
  const r = await runCeph(
    deps,
    session,
    args,
    {
      phase: opts.phase,
      budgetMs: opts.budgetMs,
      redactStdout: opts.redact,
      allowNonZero: true,
    },
    log,
  );
  if (r.result.code !== 0 && !opts.allowNonZero) {
    fail(opts.phase, `command failed: ceph ${args}`, {
      code: r.result.code,
      stderr: r.result.stderr.slice(0, 300),
    });
  }
  return r.result;
}

// ---------------------------------------------------------------------------
// cephCreatePool
// ---------------------------------------------------------------------------

/** Arguments for pool creation. */
export interface PoolArgs {
  /** Pool name. */
  name: string;
  /** `replicated` or `erasure`. */
  scheme: "replicated" | "erasure";
  /** Replica count (replicated only). */
  size?: number | null;
  /** EC data and coding chunks (erasure only). */
  erasureProfile?: { k: number; m: number } | null;
  /** Application tag. */
  application: string;
  /** CRUSH failure domain. */
  failureDomain: string;
}

/** The record a pool creation writes. */
export interface PoolRecord {
  /** Pool name. */
  name: string;
  /** Scheme. */
  scheme: string;
  /** Application. */
  application: string;
  /** Failure domain. */
  failureDomain: string;
  /** Replica count (replicated only). */
  size?: number;
  /** Derived CRUSH rule (replicated only). */
  crushRule?: string;
  /** Derived EC profile (erasure only). */
  erasureCodeProfile?: string;
  /** Whether the pool already existed. */
  existed: boolean;
  /** Ordered change tokens. */
  changed: string[];
}

interface PoolDetail {
  pool_name?: string;
  type?: number;
  size?: number;
  crush_rule?: number;
  erasure_code_profile?: string;
  application_metadata?: Record<string, unknown>;
}

/** Verifies a replicated rule takes `default` and chooses leaves of `failureDomain`. */
export function ruleMatches(dump: unknown, failureDomain: string): boolean {
  const steps = (dump as { steps?: unknown }).steps;
  if (!Array.isArray(steps)) return false;
  const takesDefault = steps.some((s) =>
    (s as { item_name?: unknown }).item_name === "default"
  );
  const choosesDomain = steps.some((s) =>
    (s as { type?: unknown }).type === failureDomain
  );
  return takesDefault && choosesDomain;
}

/** Verifies an existing EC profile matches the request. */
export function profileMatches(
  get: unknown,
  k: number,
  m: number,
  failureDomain: string,
): boolean {
  const p = get as Record<string, unknown>;
  const equal = (v: unknown, want: number) => String(v ?? "") === String(want);
  const root = p["crush-root"];
  return equal(p.k, k) && equal(p.m, m) &&
    p["crush-failure-domain"] === failureDomain &&
    (root === undefined || root === "default");
}

/** Ensures a pool exists with the requested redundancy and application. */
export async function createPool(
  deps: PrepDeps,
  session: SshSession,
  args: PoolArgs,
  log?: Logger,
): Promise<PoolRecord> {
  const pools = (await readJson(deps, session, "osd pool ls detail", {
    phase: "cephCreatePool.read",
  }, log)) as PoolDetail[];
  const existing = Array.isArray(pools)
    ? pools.find((p) => p.pool_name === args.name)
    : undefined;

  // Conditional requirements are re-checked at run time; null means missing.
  if (
    args.scheme === "replicated" &&
    (args.size === undefined || args.size === null)
  ) {
    fail("cephCreatePool", "size is required", {
      scheme: "replicated",
      name: args.name,
    });
  }
  if (
    args.scheme === "erasure" &&
    (args.erasureProfile === undefined || args.erasureProfile === null)
  ) {
    fail("cephCreatePool", "erasureProfile is required", {
      scheme: "erasure",
      name: args.name,
    });
  }

  const rule = `${args.failureDomain}_rule`;
  const profile = args.scheme === "erasure"
    ? `ec_k${args.erasureProfile!.k}_m${
      args.erasureProfile!.m
    }_${args.failureDomain}`
    : undefined;

  if (existing) {
    const expectedType = args.scheme === "replicated" ? 1 : 3;
    if (existing.type !== expectedType) {
      fail("cephCreatePool", "the existing pool has a different scheme", {
        name: args.name,
        expected: args.scheme,
        actual: existing.type === 1
          ? "replicated"
          : existing.type === 3
          ? "erasure"
          : String(existing.type),
      });
    }
    if (args.scheme === "replicated") {
      const dump = await readJson(
        deps,
        session,
        `osd crush rule dump ${rule}`,
        {
          phase: "cephCreatePool.rule",
          allowMissing: true,
        },
        log,
      );
      if (
        dump === null ||
        (dump as { rule_id?: number }).rule_id !== existing.crush_rule ||
        !ruleMatches(dump, args.failureDomain)
      ) {
        fail(
          "cephCreatePool",
          "the existing pool uses a different CRUSH rule",
          {
            name: args.name,
            expected: `${rule} choosing ${args.failureDomain}`,
            actual: String(existing.crush_rule),
          },
        );
      }
    } else {
      if (existing.erasure_code_profile !== profile) {
        fail(
          "cephCreatePool",
          "the existing pool uses a different EC profile",
          {
            name: args.name,
            expected: profile,
            actual: existing.erasure_code_profile ?? "",
          },
        );
      }
      // A profile with the right name can hold anything; check its content.
      const get = await readJson(
        deps,
        session,
        `osd erasure-code-profile get ${quote(profile!)}`,
        { phase: "cephCreatePool.profile" },
        log,
      );
      if (
        !profileMatches(
          get,
          args.erasureProfile!.k,
          args.erasureProfile!.m,
          args.failureDomain,
        )
      ) {
        fail(
          "cephCreatePool",
          "the existing EC profile does not match the request",
          {
            name: args.name,
            expected: `k=${args.erasureProfile!.k} m=${
              args.erasureProfile!.m
            } crush-failure-domain=${args.failureDomain}`,
          },
        );
      }
    }
  }

  const changed: string[] = [];
  let existed = false;

  if (existing) {
    existed = true;
  } else if (args.scheme === "replicated") {
    const rules = (await readJson(deps, session, "osd crush rule ls", {
      phase: "cephCreatePool.rules",
    }, log)) as string[];
    if (!Array.isArray(rules) || !rules.includes(rule)) {
      await runMut(
        deps,
        session,
        `osd crush rule create-replicated ${quote(rule)} default ${
          quote(args.failureDomain)
        }`,
        { phase: "cephCreatePool.rule-create" },
        log,
      );
      changed.push(`crushRule:${rule}`);
    } else {
      const dump = await readJson(
        deps,
        session,
        `osd crush rule dump ${rule}`,
        { phase: "cephCreatePool.rule" },
        log,
      );
      if (!ruleMatches(dump, args.failureDomain)) {
        fail(
          "cephCreatePool",
          "the existing CRUSH rule does not match its derived name",
          {
            rule,
            failureDomain: args.failureDomain,
          },
        );
      }
    }
    await runMut(
      deps,
      session,
      `osd pool create ${quote(args.name)} replicated ${quote(rule)}`,
      {
        phase: "cephCreatePool.create",
        budgetMs: CREATE_BUDGET_MS,
      },
      log,
    );
    changed.push("created");
  } else {
    const profiles =
      (await readJson(deps, session, "osd erasure-code-profile ls", {
        phase: "cephCreatePool.profiles",
      }, log)) as string[];
    if (!Array.isArray(profiles) || !profiles.includes(profile!)) {
      await runMut(
        deps,
        session,
        `osd erasure-code-profile set ${quote(profile!)} k=${
          args.erasureProfile!.k
        } m=${args.erasureProfile!.m} crush-failure-domain=${
          quote(args.failureDomain)
        }`,
        { phase: "cephCreatePool.profile-set" },
        log,
      );
      changed.push(`erasureCodeProfile:${profile}`);
    } else {
      const get = await readJson(
        deps,
        session,
        `osd erasure-code-profile get ${quote(profile!)}`,
        {
          phase: "cephCreatePool.profile",
        },
        log,
      );
      if (
        !profileMatches(
          get,
          args.erasureProfile!.k,
          args.erasureProfile!.m,
          args.failureDomain,
        )
      ) {
        fail(
          "cephCreatePool",
          "the existing EC profile does not match its derived name",
          { profile },
        );
      }
    }
    await runMut(
      deps,
      session,
      `osd pool create ${quote(args.name)} erasure ${quote(profile!)}`,
      {
        phase: "cephCreatePool.create",
        budgetMs: CREATE_BUDGET_MS,
      },
      log,
    );
    changed.push("created");
  }

  if (args.scheme === "replicated") {
    if (!existed || existing!.size !== args.size) {
      await runMut(
        deps,
        session,
        `osd pool set ${quote(args.name)} size ${args.size}`,
        {
          phase: "cephCreatePool.size",
        },
        log,
      );
      changed.push(`size:${args.size}`);
    }
  }

  const appMeta = existing?.application_metadata ?? {};
  if (!(args.application in appMeta)) {
    await runMut(
      deps,
      session,
      `osd pool application enable ${quote(args.name)} ${
        quote(args.application)
      }`,
      {
        phase: "cephCreatePool.application",
      },
      log,
    );
    changed.push(`application:${args.application}`);
  }

  if (args.application === "rbd") {
    await runMut(deps, session, `rbd pool init ${quote(args.name)}`, {
      phase: "cephCreatePool.rbd-init",
      budgetMs: CREATE_BUDGET_MS,
    }, log);
  }

  return {
    name: args.name,
    scheme: args.scheme,
    application: args.application,
    failureDomain: args.failureDomain,
    ...(args.scheme === "replicated" ? { size: args.size! } : {}),
    ...(args.scheme === "replicated" ? { crushRule: rule } : {}),
    ...(profile !== undefined ? { erasureCodeProfile: profile } : {}),
    existed,
    changed,
  };
}

// ---------------------------------------------------------------------------
// cephCreateFs
// ---------------------------------------------------------------------------

/** Arguments for filesystem creation. */
export interface FsArgs {
  /** Volume name. */
  name: string;
  /** MDS placement hosts. */
  placement: string[];
  /** Budget for the create and apply commands. */
  timeoutMs?: number | null;
}

/** The record a filesystem creation writes. */
export interface FsRecord {
  /** Volume name. */
  name: string;
  /** Sorted placement hosts. */
  mdsHosts: string[];
  /** Which creation path was taken. */
  creationPath: string;
  /** Whether the volume already existed. */
  existed: boolean;
}

/** Ensures a CephFS volume exists and MDS placement is explicit. */
export async function createFs(
  deps: PrepDeps,
  session: SshSession,
  args: FsArgs,
  log?: Logger,
): Promise<FsRecord> {
  if (
    args.placement.length === 0 ||
    new Set(args.placement).size !== args.placement.length
  ) {
    fail("cephCreateFs", "placement must be non-empty and duplicate-free", {
      placement: args.placement,
    });
  }
  const budgetMs = Math.max(300_000, args.timeoutMs ?? 600_000);
  if (budgetMs > (args.timeoutMs ?? 600_000)) {
    log?.warn("Raised the CephFS command budget to the floor", { budgetMs });
  }
  const fsList = (await readJson(
    deps,
    session,
    "fs ls",
    { phase: "cephCreateFs.fs-ls" },
    log,
  )) as { name?: string }[];
  const existingFs = Array.isArray(fsList)
    ? fsList.find((f) => f.name === args.name)
    : undefined;
  const pools = (await readJson(deps, session, "osd pool ls", {
    phase: "cephCreateFs.pools",
  }, log)) as string[];
  const meta = `cephfs.${args.name}.meta`;
  const data = `cephfs.${args.name}.data`;

  let creationPath: string;
  let existed = false;
  if (existingFs) {
    existed = true;
    creationPath = "already existed";
  } else if (
    Array.isArray(pools) && pools.includes(meta) && pools.includes(data)
  ) {
    const detail = (await readJson(deps, session, "osd pool ls detail", {
      phase: "cephCreateFs.detail",
    }, log)) as PoolDetail[];
    const dataPool = Array.isArray(detail)
      ? detail.find((p) => p.pool_name === data)
      : undefined;
    const ec = dataPool?.erasure_code_profile !== undefined &&
      dataPool.erasure_code_profile !== "";
    if (ec) {
      const flags = String(
        (dataPool as { flags_names?: unknown }).flags_names ?? "",
      );
      if (!flags.includes("ec_overwrites")) {
        fail(
          "cephCreateFs",
          "the data pool is erasure-coded but allow_ec_overwrites is not set",
          {
            fix: `ceph osd pool set ${data} allow_ec_overwrites true`,
          },
        );
      }
      await runMut(
        deps,
        session,
        `fs new ${quote(args.name)} ${quote(meta)} ${quote(data)} --force`,
        {
          phase: "cephCreateFs.new",
          budgetMs,
        },
        log,
      );
    } else {
      await runMut(
        deps,
        session,
        `fs new ${quote(args.name)} ${quote(meta)} ${quote(data)}`,
        {
          phase: "cephCreateFs.new",
          budgetMs,
        },
        log,
      );
    }
    creationPath = "fs new (adopted pools)";
  } else if (
    Array.isArray(pools) && (pools.includes(meta) || pools.includes(data))
  ) {
    fail(
      "cephCreateFs",
      "exactly one backing pool exists; create both or neither",
      {
        meta: pools.includes(meta),
        data: pools.includes(data),
      },
    );
  } else {
    await runMut(deps, session, `fs volume create ${quote(args.name)}`, {
      phase: "cephCreateFs.create",
      budgetMs,
    }, log);
    creationPath = "fs volume create";
  }

  // MDS placement always runs, on the already-existed path too.
  await applyPlacement(
    deps,
    session,
    {
      serviceName: `mds.${args.name}`,
      applyArgs: `mds ${args.name}`,
      requested: args.placement,
      phase: "cephCreateFs.mds",
    },
    log,
  );

  return {
    name: args.name,
    mdsHosts: [...args.placement].sort(),
    creationPath,
    existed,
  };
}

// ---------------------------------------------------------------------------
// Auth parsing, cephCreateCsiUser, cephGetConnBundle, cephFetchCsiKey
// ---------------------------------------------------------------------------

/** One auth entity: name, caps and (discarded) key. */
export interface AuthEntity {
  /** Entity name, e.g. `client.csi-rbd`. */
  entity: string;
  /** Caps map. */
  caps: Record<string, string>;
  /** Key material; callers must discard it. */
  key?: string;
}

/** Parses the bare-array and `auth_dump`-wrapped auth shapes. */
export function parseAuthEntities(json: unknown): AuthEntity[] {
  let dump: unknown = json;
  if (json !== null && typeof json === "object" && !Array.isArray(json)) {
    const wrapped = (json as { auth_dump?: unknown }).auth_dump;
    if (wrapped !== undefined) dump = wrapped;
  }
  if (!Array.isArray(dump)) return [];
  return dump.flatMap((raw) => {
    if (raw === null || typeof raw !== "object") return [];
    const e = raw as Record<string, unknown>;
    const entity = typeof e.entity === "string" ? e.entity : "";
    if (entity === "") return [];
    const caps: Record<string, string> = {};
    if (e.caps !== null && typeof e.caps === "object") {
      for (const [k, v] of Object.entries(e.caps as Record<string, unknown>)) {
        if (typeof v === "string") caps[k] = v;
      }
    }
    return [{
      entity,
      caps,
      ...(typeof e.key === "string" ? { key: e.key } : {}),
    }];
  });
}

/** Arguments for CSI user creation. */
export interface CsiUserArgs {
  /** Bare entity name, without `client.`. */
  name: string;
  /** Caps by subsystem. */
  caps: { mon: string; mgr: string; osd: string; mds?: string | null };
}

/** The record a CSI user creation writes. */
export interface CsiUserRecord {
  /** Bare entity name. */
  name: string;
  /** Caps as read back. */
  caps: Record<string, string>;
}

/** The ordered `subsystem caps` pairs for an auth command. */
export function capPairs(caps: CsiUserArgs["caps"]): [string, string][] {
  const pairs: [string, string][] = [["mon", caps.mon], ["mgr", caps.mgr], [
    "osd",
    caps.osd,
  ]];
  if (caps.mds !== undefined && caps.mds !== null && caps.mds !== "") {
    pairs.push(["mds", caps.mds]);
  }
  return pairs;
}

/** Creates or converges a client entity's caps; never returns a key. */
export async function createCsiUser(
  deps: PrepDeps,
  session: SshSession,
  args: CsiUserArgs,
  log?: Logger,
): Promise<CsiUserRecord> {
  if (args.name === "admin" || args.name.startsWith("bootstrap-")) {
    fail("cephCreateCsiUser", "refusing to rewrite a reserved entity", {
      name: args.name,
    });
  }
  const entity = `client.${args.name}`;
  const capArgs = capPairs(args.caps).map(([sub, value]) =>
    `${sub} ${quote(value)}`
  ).join(" ");
  await runMut(deps, session, `auth get-or-create ${entity} ${capArgs}`, {
    phase: "cephCreateCsiUser.get-or-create",
    allowNonZero: false,
    redact: true,
  }, log);
  await runMut(deps, session, `auth caps ${entity} ${capArgs}`, {
    phase: "cephCreateCsiUser.caps",
    allowNonZero: false,
    redact: true,
  }, log);
  const got = await readJson(deps, session, `auth get ${entity}`, {
    phase: "cephCreateCsiUser.get",
    redact: true,
  }, log);
  const entry = parseAuthEntities(got).find((e) => e.entity === entity);
  if (!entry) {
    fail("cephCreateCsiUser", "auth get returned no entry for the entity", {
      entity,
    });
  }
  return { name: args.name, caps: entry.caps };
}

/** The connection bundle: non-secret facts only. */
export interface ConnBundleRecord {
  /** Cluster fsid. */
  fsid: string;
  /** v2 mon endpoints, in order. */
  monEndpoints: string[];
  /** Pool names. */
  pools: string[];
  /** Filesystem names. */
  filesystems: string[];
  /** Client entity names without the `client.` prefix. */
  csiUserNames: string[];
}

/** Reads the non-secret connection facts. */
export async function getConnBundle(
  deps: PrepDeps,
  session: SshSession,
  log?: Logger,
): Promise<ConnBundleRecord> {
  const monDump = await readJson(deps, session, "mon dump", {
    phase: "cephGetConnBundle.mon",
  }, log) as {
    fsid?: string;
    mons?: {
      public_addrs?: { addrvec?: { type?: string; addr?: string }[] };
      public_addr?: string;
    }[];
  };
  const monEndpoints: string[] = [];
  for (const mon of monDump.mons ?? []) {
    for (const addr of mon.public_addrs?.addrvec ?? []) {
      if (addr.type === "v2" && typeof addr.addr === "string") {
        monEndpoints.push(addr.addr);
      }
    }
  }
  const pools = await readJson(deps, session, "osd pool ls", {
    phase: "cephGetConnBundle.pools",
  }, log);
  const fsList = await readJson(deps, session, "fs ls", {
    phase: "cephGetConnBundle.fs",
  }, log);
  const auth = await readJson(deps, session, "auth ls", {
    phase: "cephGetConnBundle.auth",
    redact: true,
  }, log);
  const filesystems = (Array.isArray(fsList) ? fsList : []).flatMap((f) =>
    typeof (f as { name?: unknown }).name === "string"
      ? [(f as { name: string }).name]
      : []
  );
  const csiUserNames = parseAuthEntities(auth)
    .map((e) => e.entity)
    .filter((e) =>
      e.startsWith("client.") && e !== "client.admin" &&
      !e.startsWith("client.bootstrap-")
    )
    .map((e) => e.slice("client.".length))
    .sort();
  return {
    fsid: monDump.fsid ?? "",
    monEndpoints,
    pools: Array.isArray(pools)
      ? pools.filter((p): p is string => typeof p === "string")
      : [],
    filesystems,
    csiUserNames,
  };
}

/** Reads one client entity's key into a sensitive field. */
export async function fetchCsiKey(
  deps: PrepDeps,
  session: SshSession,
  userName: string,
  log?: Logger,
): Promise<{ userName: string; key: string }> {
  const r = await runCeph(
    deps,
    session,
    `auth get-key client.${userName}`,
    { phase: "cephFetchCsiKey.get", allowNonZero: true, redactStdout: true },
    log,
  );
  if (r.result.code !== 0) {
    fail("cephFetchCsiKey", "could not read the key (stdout withheld)", {
      userName,
      code: r.result.code,
      stderr: r.result.stderr.slice(0, 200),
    });
  }
  const key = r.result.stdout.trim();
  if (key === "" || !/^[A-Za-z0-9+/]+={0,2}$/.test(key) || key.includes("\n")) {
    fail("cephFetchCsiKey", "the key output is not a single base64 line", {
      userName,
    });
  }
  return { userName, key };
}

// ---------------------------------------------------------------------------
// cephRemoveOsds
// ---------------------------------------------------------------------------

/** Arguments for OSD removal. */
export interface OsdRemoveArgs {
  /** OSD ids to remove. */
  osdIds: number[];
  /** Add `--zap` to the orchestrator removal. */
  zap?: boolean | null;
  /** Poll budget. */
  maxPolls?: number | null;
  /** Time between polls, in milliseconds. */
  pollIntervalMs?: number | null;
}

/** The record an OSD removal writes. */
export interface OsdRemoveRecord {
  /** Deduplicated, ascending requested ids. */
  requested: number[];
  /** Ids removed by this run. */
  removed: number[];
  /** Ids already absent. */
  skippedAbsent: number[];
  /** Whether zap was requested. */
  zap: boolean;
}

/** Removes OSDs through the orchestrator and proves they are gone. */
export async function removeOsds(
  deps: PrepDeps,
  session: SshSession,
  args: OsdRemoveArgs,
  log?: Logger,
): Promise<OsdRemoveRecord> {
  const requested = [...new Set(args.osdIds)].sort((a, b) => a - b);
  if (requested.length > 256) {
    fail("cephRemoveOsds", "too many OSD ids requested", {
      count: requested.length,
      max: 256,
    });
  }
  const zap = args.zap ?? true;
  const maxPolls = args.maxPolls ?? 60;
  const pollIntervalMs = args.pollIntervalMs ?? 15_000;
  if (maxPolls > 10_000 || pollIntervalMs > 3_600_000) {
    fail("cephRemoveOsds", "poll budget out of range", {
      maxPolls,
      pollIntervalMs,
    });
  }
  const present = await presentOsdIds(deps, session, log);
  const presentIds = requested.filter((id) => present.has(id));
  const skippedAbsent = requested.filter((id) => !present.has(id));
  if (presentIds.length === 0) {
    return { requested, removed: [], skippedAbsent, zap };
  }
  // In-method safety. The workflow gate is not the only protection: a plain
  // resume with overridden inputs can run this method on a new target with the
  // gate skipped, so the method must refuse an unsafe cluster itself.
  const health = await readJson(deps, session, "health detail", {
    phase: "cephRemoveOsds.health",
  }, log) as { status?: unknown } | null;
  const healthStatus = typeof health?.status === "string"
    ? health.status.toUpperCase()
    : "";
  if (healthStatus !== "HEALTH_OK" && healthStatus !== "HEALTH_WARN") {
    fail(
      "cephRemoveOsds",
      "refusing to remove OSDs: cluster health was not HEALTH_OK or HEALTH_WARN",
      { status: healthStatus === "" ? "missing" : healthStatus },
    );
  }
  // One joint ok-to-stop for the whole set. `osd safe-to-destroy` would reject
  // any OSD with PGs still mapped (EBUSY), which is every in-service OSD, so it
  // cannot gate a normal removal; `orch osd rm` performs the drain itself.
  const okToStop = await runMut(
    deps,
    session,
    `osd ok-to-stop ${presentIds.join(" ")}`,
    { phase: "cephRemoveOsds.ok-to-stop", allowNonZero: true },
    log,
  );
  if (okToStop.code !== 0) {
    fail(
      "cephRemoveOsds",
      "the orchestrator refuses to stop these OSDs together",
      { osdIds: presentIds, stderr: okToStop.stderr.slice(0, 300) },
    );
  }
  await runMut(deps, session, `osd out ${presentIds.join(" ")}`, {
    phase: "cephRemoveOsds.out",
  }, log);
  for (const id of presentIds) {
    await runMut(deps, session, `orch osd rm ${id}${zap ? " --zap" : ""}`, {
      phase: "cephRemoveOsds.rm",
    }, log);
  }
  for (let poll = 0; poll < maxPolls; poll++) {
    if (poll > 0) await deps.sleep(pollIntervalMs);
    const now = await presentOsdIds(deps, session, log);
    if (presentIds.every((id) => !now.has(id))) {
      return { requested, removed: presentIds, skippedAbsent, zap };
    }
  }
  fail("cephRemoveOsds", "OSDs are still present after the poll budget", {
    requested,
    present: presentIds,
  });
}

/** The set of OSD ids currently in `osd tree`. */
async function presentOsdIds(
  deps: PrepDeps,
  session: SshSession,
  log?: Logger,
): Promise<Set<number>> {
  const tree = await readJson(deps, session, "osd tree", {
    phase: "cephRemoveOsds.tree",
  }, log) as {
    nodes?: { id?: number; type?: string }[];
  };
  const ids = new Set<number>();
  for (const node of tree.nodes ?? []) {
    if (node.type === "osd" && typeof node.id === "number") ids.add(node.id);
  }
  return ids;
}

// ---------------------------------------------------------------------------
// cephDeleteFs
// ---------------------------------------------------------------------------

/** Arguments for filesystem deletion. */
export interface FsDeleteArgs {
  /** Volume to delete. */
  fsName: string;
  /** The target named a second time. */
  confirmFsName: string;
  /** MDS-removal poll budget. */
  maxPolls?: number | null;
  /** Time between polls. */
  pollIntervalMs?: number | null;
}

/** The record a filesystem deletion writes. */
export interface FsDeleteRecord {
  /** Target volume. */
  fsName: string;
  /** Whether the volume was removed by this run. */
  deleted: boolean;
  /** Volume absent at the start. */
  alreadyAbsent: boolean;
  /** MDS service proven gone. */
  mdsServiceRemoved: boolean;
  /** Sorted backing pools now gone. */
  poolsDeleted: string[];
  /** Sorted backing pools still present. */
  poolsRemaining: string[];
  /** Whether the pool-delete gate was closed again. */
  gateRestored: boolean;
}

/** Deletes a CephFS volume and its pools, with a double confirmation and a restored gate. */
export async function deleteFs(
  deps: PrepDeps,
  session: SshSession,
  args: FsDeleteArgs,
  log?: Logger,
): Promise<FsDeleteRecord> {
  if (args.confirmFsName !== args.fsName) {
    fail("cephDeleteFs", "confirmFsName does not match fsName", {
      fsName: args.fsName,
      confirmFsName: args.confirmFsName,
    });
  }
  const maxPolls = args.maxPolls ?? 30;
  const pollIntervalMs = args.pollIntervalMs ?? 10_000;
  if (maxPolls > 10_000 || pollIntervalMs > 3_600_000) {
    fail("cephDeleteFs", "poll budget out of range", {
      maxPolls,
      pollIntervalMs,
    });
  }
  const fsList = (await readJson(
    deps,
    session,
    "fs ls",
    { phase: "cephDeleteFs.fs-ls" },
    log,
  )) as {
    name?: string;
    metadata_pool?: string;
    data_pools?: string[];
  }[];
  const entry = Array.isArray(fsList)
    ? fsList.find((f) => f.name === args.fsName)
    : undefined;
  if (!entry) {
    return {
      fsName: args.fsName,
      deleted: false,
      alreadyAbsent: true,
      mdsServiceRemoved: false,
      poolsDeleted: [],
      poolsRemaining: [],
      gateRestored: true,
    };
  }
  const backing = [entry.metadata_pool ?? "", ...(entry.data_pools ?? [])]
    .filter((p) => p !== "");
  // In-method safety. The workflow confirmation gate can be skipped by a
  // resume with overridden inputs, so the method refuses a filesystem still in
  // use by clients on its own.
  const fsStatus = await readJson(
    deps,
    session,
    `fs status ${quote(args.fsName)}`,
    { phase: "cephDeleteFs.in-use" },
    log,
  ) as { clients?: unknown } | null;
  // `ceph fs status -f json` reports {"clients":[{"fs":"<name>","clients":N}]}.
  // The array is never empty, so count the matching entry and fail closed when
  // it or its count is missing or non-numeric.
  const entries = Array.isArray(fsStatus?.clients)
    ? fsStatus.clients as Record<string, unknown>[]
    : null;
  const match = entries?.find((e) =>
    e !== null && typeof e === "object" &&
    (e as Record<string, unknown>).fs === args.fsName
  ) as
    | Record<string, unknown>
    | undefined;
  const clientCount = match && typeof match.clients === "number"
    ? match.clients
    : null;
  if (entries === null || clientCount === null) {
    fail(
      "cephDeleteFs",
      "could not read the filesystem client count; refusing to delete",
      { fsName: args.fsName },
    );
  }
  if (clientCount > 0) {
    fail(
      "cephDeleteFs",
      "refusing to delete a filesystem still in use by clients",
      { fsName: args.fsName, clients: clientCount },
    );
  }
  const before = new Set(
    ((await readJson(deps, session, "osd pool ls", {
      phase: "cephDeleteFs.pools-before",
    }, log)) as string[]) ?? [],
  );

  await runMut(deps, session, `orch rm mds.${args.fsName}`, {
    phase: "cephDeleteFs.orch-rm",
    allowNonZero: true,
  }, log);
  let serviceGone = false;
  for (let poll = 0; poll < maxPolls; poll++) {
    if (poll > 0) await deps.sleep(pollIntervalMs);
    const ls = await readJson(
      deps,
      session,
      `orch ls --service_name mds.${args.fsName}`,
      {
        phase: "cephDeleteFs.poll",
        redact: true,
      },
      log,
    );
    if (!Array.isArray(ls) || ls.length === 0) {
      serviceGone = true;
      break;
    }
  }
  if (!serviceGone) {
    fail("cephDeleteFs", "the MDS service is still present", {
      fsName: args.fsName,
    });
  }

  let removalError: Error | null = null;
  try {
    // Inside the try so the gate is reset even when this call's outcome is
    // unknown (a lost session after the command ran).
    await runMut(deps, session, "config set mon mon_allow_pool_delete true", {
      phase: "cephDeleteFs.gate-on",
    }, log);
    const removal = await runCeph(
      deps,
      session,
      `fs volume rm ${quote(args.fsName)} --yes-i-really-mean-it`,
      { phase: "cephDeleteFs.rm", allowNonZero: true },
      log,
    );
    if (removal.result.code !== 0) {
      removalError = new Error(
        `cephadm[cephDeleteFs]: fs volume rm exited ${removal.result.code} (${
          truncate(removal.result.stderr, 200)
        })`,
      );
    }
  } catch (e) {
    removalError = e as Error;
  }

  let gateRestored = true;
  try {
    const off = await runMut(
      deps,
      session,
      "config set mon mon_allow_pool_delete false",
      {
        phase: "cephDeleteFs.gate-off",
        allowNonZero: true,
      },
      log,
    );
    gateRestored = off.code === 0;
  } catch {
    gateRestored = false;
  }

  const after = new Set(
    ((await readJson(deps, session, "osd pool ls", {
      phase: "cephDeleteFs.pools-after",
    }, log)) as string[]) ?? [],
  );
  const poolsDeleted = backing.filter((p) => before.has(p) && !after.has(p))
    .sort();
  const poolsRemaining = backing.filter((p) => after.has(p)).sort();
  const stillThere = (
    (await readJson(
      deps,
      session,
      "fs ls",
      { phase: "cephDeleteFs.fs-after" },
      log,
    )) as { name?: string }[]
  ).some((f) => f.name === args.fsName);

  if (removalError !== null) {
    throw new Error(
      `${removalError.message}${gateRestored ? "" : " (gateRestored=false)"}`,
    );
  }
  if (stillThere) {
    fail("cephDeleteFs", "the volume is still listed after removal", {
      fsName: args.fsName,
    });
  }
  if (poolsRemaining.length > 0 || !gateRestored) {
    fail("cephDeleteFs", "the volume was removed but cleanup is incomplete", {
      poolsRemaining,
      gateRestored,
    });
  }
  return {
    fsName: args.fsName,
    deleted: true,
    alreadyAbsent: false,
    mdsServiceRemoved: true,
    poolsDeleted,
    poolsRemaining,
    gateRestored,
  };
}
