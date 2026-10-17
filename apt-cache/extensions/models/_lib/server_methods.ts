/**
 * Server-side method implementations: install, render, apply, remove, and the
 * read-only get/sync/stats probes. Each function has the swamp `execute`
 * signature `(args, context)` and is registered by `apt_cache.ts`.
 *
 * @module
 */

import { exec, sha256Hex, type SshTarget } from "./ssh.ts";
import {
  APT_CACHER_LOG_PATH,
  AptConfigError,
  assertCacheDir,
  assertPassthroughHost,
  FRAGMENT_PATH,
  type HttpsPolicy,
  isBackendUrl,
  isWildcardAddress,
  parseAptCacherLog,
  parseCacheBytes,
  parseFsFree,
  renderBackendFiles,
  renderLogReadScript,
  renderSecurityConf,
  renderServerFragment,
  SECURITY_CONF_PATH,
  type ServerRenderInput,
  windowToSeconds,
} from "./apt.ts";
import {
  AptCacheError,
  type Ctx,
  deps,
  iso,
  managedPaths,
  observationName,
  parseSsListen,
  passThroughPatternOf,
  readRemoteFile,
  remoteSha,
  removeCacheDir,
  removeOrRestoreManaged,
  requireOk,
  resolveKey,
  serverName,
  serverState,
  targetKey,
  targetOf,
  writeManagedFile,
} from "./remote.ts";
import {
  type ApplyServerArgs,
  type GetArgs,
  ObservationSchema,
  type RemoveServerArgs,
  RenderSchema,
  type RenderServerArgs,
  type ServerState,
  ServerStateSchema,
  type StatsArgs,
  type SyncArgs,
} from "./schemas.ts";

/** The server render inputs from method arguments. */
function serverInput(args: {
  listen: string[];
  port: number;
  https_policy: HttpsPolicy;
  passthrough_hosts: string[];
  backends: Record<string, string[]>;
  expire_days: number;
  cache_dir: string;
}): ServerRenderInput {
  return {
    listen: args.listen,
    port: args.port,
    https_policy: args.https_policy,
    passthrough_hosts: args.passthrough_hosts,
    backends: args.backends,
    expire_days: args.expire_days,
    cache_dir: args.cache_dir,
  };
}

/** The mirror scheme a policy requires. */
function schemeOf(policy: HttpsPolicy): "http" | "https" {
  return policy === "https_backends" ? "https" : "http";
}

/**
 * Checks every cross-field server precondition in-method, because a workflow
 * gate can be bypassed. Throws a typed error naming the offending input.
 */
function assertServerArgs(args: {
  listen: string[];
  listen_any_ack: boolean;
  https_policy: HttpsPolicy;
  passthrough_hosts: string[];
  backends: Record<string, string[]>;
  cache_dir: string;
}): void {
  for (const address of args.listen) {
    if (isWildcardAddress(address) && !args.listen_any_ack) {
      throw new AptCacheError(
        "wildcard_listen",
        `listen ${address} binds every interface; set listen_any_ack=true to accept that`,
      );
    }
  }
  assertCacheDir(args.cache_dir);
  if (args.https_policy === "passthrough") {
    if (args.passthrough_hosts.length === 0) {
      throw new AptCacheError(
        "config",
        "https_policy passthrough requires a non-empty passthrough_hosts list",
      );
    }
    for (const host of args.passthrough_hosts) assertPassthroughHost(host);
  }
  // The package's built-in Remap-secdeb claims every debian-security prefix
  // (both path-style and proxy-style) and uses inline http backends; acng.conf
  // cannot be edited and a second Remap- only appends, so a managed
  // debian-security mirror would be silently ignored. Refuse it instead.
  if ("debian-security" in args.backends) {
    throw new AptCacheError(
      "config",
      "the debian-security key cannot be managed: the package's built-in Remap-secdeb owns those routes and uses inline http backends that cannot be overridden; omit it and configure it in the package's acng.conf",
    );
  }
  const scheme = schemeOf(args.https_policy);
  for (const [key, urls] of Object.entries(args.backends)) {
    if (urls.length === 0) {
      throw new AptCacheError("config", `backend ${key} names no mirror`);
    }
    for (const url of urls) {
      if (!isBackendUrl(url, scheme)) {
        throw new AptCacheError(
          "config",
          `backend ${key} URL must be a plain ${scheme} mirror: ${url}`,
        );
      }
    }
  }
}

/** Render the managed fragment and backend files with their digests. */
export async function renderServer(
  args: RenderServerArgs,
  context: Ctx,
) {
  assertServerArgs(args);
  const fragment = renderServerFragment(serverInput(args));
  const backends = renderBackendFiles(
    args.backends,
    schemeOf(args.https_policy),
  );
  const fragmentSha = await sha256Hex(new TextEncoder().encode(fragment));
  const backendOut = await Promise.all(
    backends.map(async (b) => ({
      key: b.key,
      path: b.path,
      sha256: await sha256Hex(new TextEncoder().encode(b.text)),
    })),
  );
  const handle = await context.writeResource(
    "render",
    `render-${fragmentSha.slice(0, 16)}`,
    RenderSchema.parse({
      listen: args.listen,
      port: args.port,
      https_policy: args.https_policy,
      fragment_path: FRAGMENT_PATH,
      fragment_sha256: fragmentSha,
      backends: backendOut,
      observed_at: iso(deps.now()),
    }),
  );
  return {
    dataHandles: [handle],
    result: {
      fragment: { path: FRAGMENT_PATH, text: fragment, sha256: fragmentSha },
      backends: backends.map((b, i) => ({
        key: b.key,
        path: b.path,
        text: b.text,
        sha256: backendOut[i].sha256,
      })),
    },
  };
}

/** Write the fragment and backends, restart when changed, and verify. */
export async function applyServer(
  args: ApplyServerArgs,
  context: Ctx,
) {
  assertServerArgs(args);
  const key = await resolveKey(context, args.ssh.ssh_key_ref);
  const t = targetOf(args.ssh, key);
  const fragment = renderServerFragment(serverInput(args));
  const backendFiles = renderBackendFiles(
    args.backends,
    schemeOf(args.https_policy),
  );
  const prior = await context.readResource(serverName(t)) as
    | ServerState
    | null;
  const priorManaged = prior?.managed_files ?? {};
  const written = await writeServerFiles(
    t,
    fragment,
    backendFiles,
    args,
    context,
    priorManaged,
  );
  const dropped = await cleanupDroppedFiles(t, priorManaged, written.managed);
  const managed = written.managed;
  const changed = written.changed || dropped.changed;
  // Anything apt-cacher-ng reads that changed (written or dropped) needs a
  // restart: the daemon holds its configuration, and a restored security.conf
  // would otherwise keep enforcing the old credential.
  if (changed) {
    requireOk(
      await exec(deps, t, ["systemctl", "restart", "apt-cacher-ng"]),
      "systemctl restart apt-cacher-ng",
    );
  }
  await verifyApplied(t, args, adminExpectation(args, dropped.adminCredential));
  const now = deps.now();
  const handle = await context.writeResource(
    "server",
    serverName(t),
    ServerStateSchema.parse({
      target: targetKey(t),
      host: t.host,
      installed: true,
      listen: args.listen,
      port: args.port,
      https_policy: args.https_policy,
      cache_dir: args.cache_dir,
      managed_files: managed,
      config_sha256: managed[FRAGMENT_PATH],
      applied_at: iso(now),
      observed_at: iso(now),
    }),
  );
  return {
    dataHandles: [handle],
    result: {
      host: t.host,
      changed,
      listen: args.listen,
      port: args.port,
      https_policy: args.https_policy,
    },
  };
}

/** Write the fragment, backends and optional admin credential. */
async function writeServerFiles(
  t: SshTarget,
  fragment: string,
  backendFiles: { path: string; text: string }[],
  args: ApplyServerArgs,
  context: Ctx,
  priorManaged: Record<string, string>,
): Promise<{ managed: Record<string, string>; changed: boolean }> {
  const managed: Record<string, string> = {};
  let changed = false;
  const write = async (path: string, content: string, mode: string) => {
    const result = await writeManagedFile(
      deps,
      t,
      path,
      content,
      mode,
      priorManaged[path],
    );
    managed[path] = result.sha256;
    changed = result.changed || changed;
  };
  await write(FRAGMENT_PATH, fragment, "0644");
  for (const file of backendFiles) await write(file.path, file.text, "0644");
  if (args.admin_auth_ref) {
    await write(
      SECURITY_CONF_PATH,
      renderSecurityConf(await resolveKey(context, args.admin_auth_ref)),
      "0600",
    );
    requireOk(
      await exec(deps, t, [
        "chown",
        "apt-cacher-ng:apt-cacher-ng",
        SECURITY_CONF_PATH,
      ]),
      "chown security.conf",
    );
  }
  return { managed, changed };
}

/** What happened to the admin credential file this apply stopped writing. */
type AdminCredential = "kept" | "restored" | "removed" | "untouched";

/**
 * Restores or removes every managed path an earlier apply wrote that this one
 * does not (a dropped backend key, or a dropped admin_auth_ref), so its
 * ownership digest does not linger in the record. Only the fixed managed set is
 * touched. `changed` is true when a file on disk changed, so the caller
 * restarts the daemon.
 */
async function cleanupDroppedFiles(
  t: SshTarget,
  priorManaged: Record<string, string>,
  managed: Record<string, string>,
): Promise<{ changed: boolean; adminCredential: AdminCredential }> {
  const allowed = managedPaths();
  let changed = false;
  let adminCredential: AdminCredential = "untouched";
  for (const [path, sha] of Object.entries(priorManaged)) {
    if (path in managed || !allowed.has(path)) continue;
    const result = await removeOrRestoreManaged(deps, t, path, sha);
    changed = changed || result !== "kept";
    if (path === SECURITY_CONF_PATH) adminCredential = result;
  }
  return { changed, adminCredential };
}

/**
 * Whether the live daemon must refuse or accept an unauthenticated
 * administrative request after this apply. An apply that sets admin_auth_ref
 * must enforce it; one that dropped it and deleted the file must not enforce
 * the old credential any more. A restored file is the admin's own, so nothing
 * is assumed about it.
 */
function adminExpectation(
  args: ApplyServerArgs,
  dropped: AdminCredential,
): "enforced" | "open" | "unchecked" {
  if (args.admin_auth_ref) return "enforced";
  return dropped === "removed" ? "open" : "unchecked";
}

/** Verify the service is active, listening on every address, and answering. */
async function verifyApplied(
  t: SshTarget,
  args: ApplyServerArgs,
  admin: "enforced" | "open" | "unchecked",
): Promise<void> {
  const active = requireOk(
    await exec(deps, t, ["systemctl", "is-active", "apt-cacher-ng"]),
    "systemctl is-active apt-cacher-ng",
  ).stdout.trim();
  if (active !== "active") {
    throw new AptCacheError(
      "verify_failed",
      `apt-cacher-ng is ${active} after apply`,
    );
  }
  const listening = parseSsListen(
    requireOk(await exec(deps, t, ["ss", "-ltn"]), "ss -ltn").stdout,
  );
  for (const address of args.listen) {
    // Exact parsed address:port pair; a port-only match would accept any
    // listener on the port.
    if (
      !listening.pairs.some((p) =>
        p.address === address && p.port === args.port
      )
    ) {
      throw new AptCacheError(
        "verify_failed",
        `apt-cacher-ng is not listening on ${address}:${args.port}`,
      );
    }
  }
  const fetch = await exec(deps, t, [
    "curl",
    "-fsS",
    "--noproxy",
    "*",
    "--max-time",
    "15",
    "-o",
    "/dev/null",
    `http://127.0.0.1:${args.port}/acng-report.html`,
  ]);
  if (fetch.exit_code !== 0) {
    throw new AptCacheError(
      "verify_failed",
      `the proxy did not answer on 127.0.0.1:${args.port}`,
    );
  }
  if (admin !== "unchecked") await verifyAdminAuth(t, args.port, admin);
}

/**
 * Asks the live daemon for a read-only administrative action without a
 * credential: 401 proves AdminAuth is enforced and 200 proves it is not (the
 * report page itself is not gated, an action URL is). Any other status fails.
 */
async function verifyAdminAuth(
  t: SshTarget,
  port: number,
  expected: "enforced" | "open",
): Promise<void> {
  const probe = requireOk(
    await exec(deps, t, [
      "curl",
      "-s",
      "--noproxy",
      "*",
      "-o",
      "/dev/null",
      "-w",
      "%{http_code}",
      "--max-time",
      "15",
      `http://127.0.0.1:${port}/acng-report.html?doCount=Count+Data`,
    ]),
    "curl admin probe",
  ).stdout.trim();
  if (expected === "enforced" && probe !== "401") {
    throw new AptCacheError(
      "verify_failed",
      `the admin credential is not enforced by the running daemon (HTTP ${probe})`,
    );
  }
  if (expected === "open" && probe !== "200") {
    throw new AptCacheError(
      "verify_failed",
      probe === "401"
        ? "the running daemon still enforces the dropped admin credential"
        : `the admin page did not answer after dropping the credential (HTTP ${probe})`,
    );
  }
}

/** Stop, remove the managed files and package, and optionally the cache. */
export async function removeServer(
  args: RemoveServerArgs,
  context: Ctx,
) {
  if (args.confirm_host !== args.ssh.host) {
    throw new AptCacheError(
      "confirm",
      `confirm_host ${args.confirm_host} does not match the SSH host ${args.ssh.host}`,
    );
  }
  assertCacheDir(args.cache_dir);
  const key = await resolveKey(context, args.ssh.ssh_key_ref);
  const t = targetOf(args.ssh, key);
  const status = await exec(deps, t, [
    "dpkg-query",
    "-W",
    "-f=${Status}",
    "apt-cacher-ng",
  ]);
  const installed = /install ok installed/.test(status.stdout);
  // A prior plain remove leaves the package in `deinstall ok config-files`;
  // only a purging apt-get can finish it, so treat those as present for the
  // ack path.
  const configFiles = /deinstall ok config-files/.test(status.stdout);
  if (!installed && !configFiles) {
    context.logger.info(
      "apt-cacher-ng is not installed on {host}; remove is a no-op",
      { host: t.host },
    );
    const handle = await context.writeResource(
      "server",
      serverName(t),
      ServerStateSchema.parse({
        target: targetKey(t),
        host: t.host,
        installed: false,
        observed_at: iso(deps.now()),
      }),
    );
    return {
      dataHandles: [handle],
      result: { host: t.host, removed: false, cache_purged: false },
    };
  }
  if (args.purge_cache_ack) {
    await assertRecordedCacheDir(context, t, args.cache_dir);
  }
  await uninstallPackage(t, installed, args.purge_cache_ack);
  await removeManagedFiles(context, t);
  let cachePurged = false;
  if (args.purge_cache_ack) {
    await removeCacheDir(deps, t, args.cache_dir);
    cachePurged = true;
  }
  context.logger.info("Removed apt-cacher-ng from {host}", { host: t.host });
  const handle = await context.writeResource(
    "server",
    serverName(t),
    ServerStateSchema.parse({
      target: targetKey(t),
      host: t.host,
      installed: false,
      observed_at: iso(deps.now()),
    }),
  );
  return {
    dataHandles: [handle],
    result: { host: t.host, removed: true, cache_purged: cachePurged },
  };
}

/** Stop and disable the service, then remove or purge the package. */
async function uninstallPackage(
  t: SshTarget,
  installed: boolean,
  purgeAck: boolean,
): Promise<void> {
  if (installed) {
    requireOk(
      await exec(deps, t, ["systemctl", "stop", "apt-cacher-ng"]),
      "systemctl stop apt-cacher-ng",
    );
    requireOk(
      await exec(deps, t, ["systemctl", "disable", "apt-cacher-ng"]),
      "systemctl disable apt-cacher-ng",
    );
  }
  // `purge` deletes the cache directory and the package config files; `remove`
  // keeps them. Without the ack the cache is data we must not touch.
  const subcommand = purgeAck ? "purge" : (installed ? "remove" : undefined);
  if (subcommand) {
    requireOk(
      await exec(deps, t, [
        "sh",
        "-c",
        `DEBIAN_FRONTEND=noninteractive apt-get ${subcommand} -y apt-cacher-ng`,
      ]),
      `apt-get ${subcommand} apt-cacher-ng`,
    );
  }
}

/**
 * Removes or restores every file the model could have written. A file whose
 * bytes are not the recorded ones (an admin edit) is left untouched.
 */
async function removeManagedFiles(context: Ctx, t: SshTarget): Promise<void> {
  const record = await context.readResource(serverName(t)) as
    | ServerState
    | null;
  const recorded = record?.managed_files ?? {};
  const paths = managedPaths();
  for (const path of paths) {
    const result = await removeOrRestoreManaged(deps, t, path, recorded[path]);
    if (result === "kept") {
      context.logger.warning(
        "Kept {path}: its bytes are not the ones this model wrote",
        { path },
      );
    }
  }
}

/**
 * Refuses to delete a cache directory that is not the one the server actually
 * used: the live fragment's `CacheDir` first, then the recorded server state.
 */
async function assertRecordedCacheDir(
  context: Ctx,
  t: SshTarget,
  cacheDir: string,
): Promise<void> {
  const fragment = await readRemoteFile(deps, t, FRAGMENT_PATH);
  let known = fragment === null
    ? undefined
    : /^CacheDir:\s*(.*)$/m.exec(fragment)?.[1].trim();
  if (known === undefined) {
    const record = await context.readResource(serverName(t)) as
      | ServerState
      | null;
    known = record?.cache_dir;
  }
  if (known === undefined) {
    throw new AptCacheError(
      "cache_dir_unknown",
      "cannot determine the server's cache directory (no managed fragment and no recorded state); refusing to delete the cache",
    );
  }
  if (known !== cacheDir) {
    throw new AptCacheError(
      "cache_dir_mismatch",
      `cache_dir ${cacheDir} does not match the server's ${known}`,
    );
  }
}

/** Read the server state, fragment digest, cache and free space. */
export async function getServer(args: GetArgs, context: Ctx) {
  const key = await resolveKey(context, args.ssh.ssh_key_ref);
  const t = targetOf(args.ssh, key);
  const now = deps.now();
  const observation = ObservationSchema.parse({
    target: targetKey(t),
    kind: "get",
    host: t.host,
    ...await serverState(deps, t, args.cache_dir),
    config_sha256: (await remoteSha(deps, t, FRAGMENT_PATH)) ?? undefined,
    observed_at: iso(now),
  });
  const handle = await context.writeResource(
    "observation",
    observationName("get", t),
    observation,
  );
  return { dataHandles: [handle], result: observation };
}

/** Re-render the fragment and report drift against the live file. */
export async function syncServer(args: SyncArgs, context: Ctx) {
  assertServerArgs(args);
  const key = await resolveKey(context, args.ssh.ssh_key_ref);
  const t = targetOf(args.ssh, key);
  const now = deps.now();
  const expected = renderServerFragment(serverInput(args));
  const expectedSha = await sha256Hex(new TextEncoder().encode(expected));
  const liveSha = await remoteSha(deps, t, FRAGMENT_PATH);
  const liveText = await readRemoteFile(deps, t, FRAGMENT_PATH);
  const livePattern = liveText === null
    ? undefined
    : passThroughPatternOf(liveText);
  const expectedPattern = passThroughPatternOf(expected);
  const drift: string[] = [];
  if (liveSha === null) drift.push("fragment:missing");
  else if (liveSha !== expectedSha) drift.push("fragment:edited");
  if (livePattern !== undefined && livePattern !== expectedPattern) {
    drift.push(`passthrough:${livePattern}`);
  }
  const observation = ObservationSchema.parse({
    target: targetKey(t),
    kind: "sync",
    host: t.host,
    ...await serverState(deps, t, args.cache_dir),
    config_sha256: liveSha ?? undefined,
    expected_config_sha256: expectedSha,
    config_matches: liveSha === expectedSha,
    passthrough_pattern: livePattern,
    drift,
    observed_at: iso(now),
  });
  const handle = await context.writeResource(
    "observation",
    observationName("sync", t),
    observation,
  );
  return {
    dataHandles: [handle],
    result: { in_sync: drift.length === 0, drift },
  };
}

/** Read the request log and cache size for the requested window. */
export async function statsServer(args: StatsArgs, context: Ctx) {
  const key = await resolveKey(context, args.ssh.ssh_key_ref);
  const t = targetOf(args.ssh, key);
  const now = deps.now();
  const until = Math.floor(now / 1000);
  const since = until - windowToSeconds(args.window);
  const log = await exec(deps, t, [
    "sh",
    "-c",
    renderLogReadScript(APT_CACHER_LOG_PATH),
  ]);
  if (log.exit_code !== 0) {
    throw new AptCacheError(
      log.exit_code === 4 ? "log_corrupt" : "log_missing",
      log.exit_code === 4
        ? `a rotated log under ${APT_CACHER_LOG_PATH} is corrupt; refusing to report a partial window`
        : `could not read ${APT_CACHER_LOG_PATH} (exit ${log.exit_code})`,
    );
  }
  let totals;
  try {
    totals = parseAptCacherLog(log.stdout, since, until);
  } catch (error) {
    throw new AptCacheError(
      "parse_failed",
      error instanceof AptConfigError
        ? error.message
        : "could not parse the apt-cacher log",
    );
  }
  const cacheBytes = await dirBytes(t, args.cache_dir);
  const observation = ObservationSchema.parse({
    target: targetKey(t),
    kind: "stats",
    host: t.host,
    window: args.window,
    requests: totals.requests,
    hits: totals.hits,
    misses: totals.misses,
    bytes_from_cache: totals.bytes_from_cache,
    bytes_upstream: totals.bytes_upstream,
    hit_ratio: totals.requests > 0 ? totals.hits / totals.requests : 0,
    cache_bytes: cacheBytes,
    fs_free_bytes: await freeBytes(t, args.cache_dir),
    observed_at: iso(now),
  });
  const handle = await context.writeResource(
    "observation",
    observationName("stats", t),
    observation,
  );
  return { dataHandles: [handle], result: observation };
}

/** `du -sb` for a directory, or 0 when unreadable. */
async function dirBytes(t: SshTarget, dir: string): Promise<number> {
  const res = await exec(deps, t, ["du", "-sb", "--", dir]);
  if (res.exit_code !== 0) return 0;
  try {
    return parseCacheBytes(res.stdout);
  } catch {
    return 0;
  }
}

/** `df -B1 --output=avail` for a directory, or 0 when unreadable. */
async function freeBytes(t: SshTarget, dir: string): Promise<number> {
  const res = await exec(deps, t, ["df", "-B1", "--output=avail", "--", dir]);
  if (res.exit_code !== 0) return 0;
  try {
    return parseFsFree(res.stdout);
  } catch {
    return 0;
  }
}
