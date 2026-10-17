/**
 * The mutating methods: install, apply, commit and remove, plus the shared
 * probing and verify logic.
 *
 * Apply and remove share one claim/arm/install path so a revert is armed the
 * same way either time. Every remote mutation is validated by Kea, installed
 * atomically with the service group, and reversible unless committed.
 *
 * @module
 */

import {
  exec as sshExec,
  posixQuote,
  SshError,
  type SshTarget,
  upload as sshUpload,
} from "./ssh.ts";
import { deps, type MethodContext, type MethodOutcome } from "./deps.ts";
import {
  actionName,
  ActionStateSchema,
  type ApplyArgs,
  configName,
  type ConfigState,
  ConfigStateSchema,
  instanceKey,
  type Observation,
  pendingName,
  type PendingState,
  PendingStateSchema,
  revertName,
  type RevertState,
  RevertStateSchema,
  type SshArgs,
  type VerifyResult,
} from "./schemas.ts";
import {
  claimScript,
  commitScript,
  CONFIG_PATH,
  installFileScript,
  ORIGINAL_CONFIG,
  restoreScript,
  REVERT_ROOT,
  SERVICE,
  timerName,
} from "./host_scripts.ts";
import {
  assertHookLibrary,
  assertManagementInterface,
  configSetRequest,
  keaControl,
  parseFiredMarker,
  readMarker,
  readRemoteText,
  remoteFileSha,
  renderAndHash,
  resolveServiceGroup,
  runScript,
  serviceActive,
  serviceEnabled,
  toTarget,
  waitForHash,
} from "./transport.ts";
import { probe, verifyOf } from "./probe.ts";
import {
  APPLY_PLAN,
  type ApplyStep,
  DEFAULT_CONTROL_SOCKET,
  type RenderResult,
} from "./render.ts";
import { KeaInputError } from "./grammar.ts";

/** The last non-empty line of a command's stderr, for error messages. */
function lastLine(text: string): string {
  return text.trim().split("\n").at(-1) ?? "";
}

/** Uploads a staged config and validates it with Kea itself. */
async function stageConfig(
  target: SshTarget,
  content: string,
  token: string,
): Promise<string> {
  const staged = `/etc/kea/kea-dhcp4.conf.staged-${token}`;
  await sshUpload(deps, target, { path: staged, content, mode: "0600" });
  const rest = await runScript(target, `kea-dhcp4 -t ${posixQuote(staged)}`);
  if (rest.exit_code !== 0) {
    await sshExec(deps, target, ["rm", "-f", staged]).catch(() => undefined);
    throw new KeaInputError(
      `kea-dhcp4 -t rejected the config: ${lastLine(rest.stderr)}`,
    );
  }
  return staged;
}

/** Reads and parses the snapshotted previous config, or null. */
async function readPreviousRender(
  target: SshTarget,
  dir: string,
): Promise<RenderResult | null> {
  const text = await readRemoteText(target, `${dir}/previous.conf`);
  if (text === null) return null;
  try {
    return { config: JSON.parse(text), json: text, warnings: [] };
  } catch {
    return null;
  }
}

/** Claims the revert or throws, naming the armed token on a collision. */
async function claimRevert(
  target: SshTarget,
  dir: string,
  activeJson: string,
): Promise<void> {
  const claim = await runScript(target, claimScript(dir, activeJson));
  if (claim.exit_code === 9) {
    const active = await readMarker(target);
    throw new SshError(
      `a revert is already armed (token ${
        active?.token ?? "unknown"
      }, expires ${active?.expiresAt ?? "unknown"})`,
    );
  }
  if (claim.exit_code !== 0) {
    throw new SshError(
      `could not claim the revert: ${lastLine(claim.stderr)}`,
    );
  }
}

/** Records a revert as cancelled. */
async function recordCancelled(
  context: MethodContext,
  key: string,
  token: string,
  revert: RevertState,
): Promise<void> {
  await context.writeResource(
    "revert",
    revertName(key, token),
    RevertStateSchema.parse({
      ...revert,
      cancelled_at: new Date(deps.now()).toISOString(),
    }),
  );
}

/** Removes the claim's marker and records the revert as cancelled. */
async function abortClaim(
  context: MethodContext,
  target: SshTarget,
  args: { host: string; port: number; user: string },
  dir: string,
  token: string,
  revert: RevertState,
): Promise<void> {
  await sshExec(deps, target, ["rm", "-rf", dir]).catch(() => undefined);
  await sshExec(deps, target, ["rm", "-f", `${REVERT_ROOT}/active.json`])
    .catch(() => undefined);
  await recordCancelled(context, instanceKey(args), token, revert);
}

/** Uploads the restore assets and arms the host-side revert timer. */
async function armRevert(
  context: MethodContext,
  target: SshTarget,
  args: { host: string; port: number; user: string },
  opts: {
    token: string;
    dir: string;
    socket: string;
    priorActive: boolean;
    priorEnabled: boolean;
    revertAfterS: number;
    revert: RevertState;
  },
): Promise<void> {
  const { token, dir, socket, priorActive, priorEnabled, revert } = opts;
  const scriptPath = `${dir}/restore.sh`;
  try {
    const prev = await readPreviousRender(target, dir);
    await sshUpload(deps, target, {
      path: scriptPath,
      content: restoreScript(token, socket, priorActive, priorEnabled),
      mode: "0700",
    });
    if (prev !== null) {
      await sshUpload(deps, target, {
        path: `${dir}/restore-request.json`,
        content: JSON.stringify(configSetRequest(prev)),
        mode: "0600",
      });
    }
    await sshUpload(deps, target, {
      path: `${dir}/hash-request.json`,
      content: JSON.stringify({
        command: "config-hash-get",
        service: ["dhcp4"],
      }),
      mode: "0600",
    });
  } catch (error) {
    await abortClaim(context, target, args, dir, token, revert);
    throw error;
  }
  const armed = await runScript(
    target,
    `systemd-run --on-active=${opts.revertAfterS} --unit=${timerName(token)} ${
      posixQuote(scriptPath)
    }`,
  );
  if (armed.exit_code !== 0) {
    await abortClaim(context, target, args, dir, token, revert);
    throw new SshError(
      `could not arm the revert timer: ${lastLine(armed.stderr)}`,
    );
  }
}

/** Claims, records and arms one revert. Shared by apply and remove. */
async function claimAndArm(
  context: MethodContext,
  target: SshTarget,
  args: { host: string; port: number; user: string },
  opts: {
    token: string;
    dir: string;
    socket: string;
    activeSha: string;
    intent: "apply" | "remove";
    canaries?: string[];
    priorActive: boolean;
    priorEnabled: boolean;
    revertAfterS: number;
  },
): Promise<RevertState> {
  const expiresAt = new Date(deps.now() + opts.revertAfterS * 1000)
    .toISOString();
  await claimRevert(
    target,
    opts.dir,
    JSON.stringify({ token: opts.token, expires_at: expiresAt }),
  );
  const revert: RevertState = {
    host: args.host,
    token: opts.token,
    armed_at: new Date(deps.now()).toISOString(),
    expires_at: expiresAt,
    armed_sha256: opts.activeSha,
    canaries: opts.canaries,
    intent: opts.intent,
    prior_enabled: opts.priorEnabled,
  };
  await context.writeResource(
    "revert",
    revertName(instanceKey(args), opts.token),
    RevertStateSchema.parse(revert),
  );
  await armRevert(context, target, args, { ...opts, revert });
  return revert;
}

/** Sets the service group and atomically installs the staged file. */
async function installStaged(
  target: SshTarget,
  staged: string,
  group: string,
): Promise<void> {
  const install = await runScript(target, installFileScript(staged, group));
  if (install.exit_code !== 0) {
    throw new SshError(
      `could not install the config file: ${lastLine(install.stderr)}`,
    );
  }
}

/** Pushes the config: config-set when running, start when not, then hash. */
async function pushConfig(
  target: SshTarget,
  rendered: RenderResult,
  isActive: boolean,
  socket: string,
): Promise<string | undefined> {
  if (isActive) {
    await keaControl(target, configSetRequest(rendered), socket);
  } else {
    const start = await runScript(target, `systemctl start ${SERVICE}`);
    if (start.exit_code !== 0) {
      throw new SshError(
        `could not start ${SERVICE}: ${lastLine(start.stderr)}`,
      );
    }
  }
  return await waitForHash(target, socket);
}

/** Writes the pending apply record for a target. */
async function persistPending(
  context: MethodContext,
  args: { host: string; port: number; user: string },
  state: Omit<PendingState, "host" | "status">,
): Promise<void> {
  await context.writeResource(
    "pending",
    pendingName(instanceKey(args)),
    PendingStateSchema.parse({
      host: args.host,
      status: "pending",
      ...state,
    }),
  );
}

/** Writes the committed config record for a target. */
async function persistCommitted(
  context: MethodContext,
  args: { host: string; port: number; user: string },
  state: Omit<ConfigState, "host">,
): Promise<void> {
  await context.writeResource(
    "config",
    configName(instanceKey(args)),
    ConfigStateSchema.parse({ host: args.host, ...state }),
  );
}

/** Discards the pending record after a commit or a fired revert. */
export async function discardPending(
  context: MethodContext,
  key: string,
): Promise<void> {
  const pending = await context.readResource(pendingName(key)) as
    | PendingState
    | null;
  if (pending === null || pending.status === "discarded") return;
  await context.writeResource(
    "pending",
    pendingName(key),
    PendingStateSchema.parse({ ...pending, status: "discarded" }),
  );
}

/** Writes the outcome record for an action method. */
export async function persistAction(
  context: MethodContext,
  method: "install" | "apply" | "commit" | "remove",
  args: { host: string; port: number; user: string },
  result: unknown,
): Promise<void> {
  await context.writeResource(
    "action",
    actionName(method, instanceKey(args)),
    ActionStateSchema.parse({
      method,
      host: args.host,
      at: new Date(deps.now()).toISOString(),
      result,
    }),
  );
}

/**
 * Undoes an uncommitted apply/remove after a failure, using the same
 * restore.sh the timer would run. It only disarms when the restore judged the
 * post-state a pass; otherwise the timer stays armed and the recovery note is
 * surfaced.
 */
async function disarmAndRestore(
  context: MethodContext,
  target: SshTarget,
  args: { host: string; port: number; user: string },
  dir: string,
  token: string,
  revert: RevertState,
): Promise<void> {
  await runScript(target, `sh ${posixQuote(`${dir}/restore.sh`)}`);
  const fired = await readRemoteText(target, `${dir}/fired.json`);
  const result = fired !== null ? parseFiredMarker(fired)?.result : null;
  if (result !== "pass") {
    const recovery = await readRemoteText(target, `${dir}/recovery.txt`);
    throw new SshError(
      `the revert restore did not pass (${
        result ?? "no marker"
      }); the timer is left armed; recovery: ${
        recovery?.trim() ?? `${dir}/recovery.txt`
      }`,
    );
  }
  await sshExec(deps, target, [
    "systemctl",
    "stop",
    `${timerName(token)}.timer`,
  ])
    .catch(() => undefined);
  await sshExec(deps, target, ["rm", "-f", `${REVERT_ROOT}/active.json`])
    .catch(() => undefined);
  await recordCancelled(context, instanceKey(args), token, revert);
}

/** Runs every apply step in order and returns the revert and observation. */
async function doApply(
  context: MethodContext,
  target: SshTarget,
  args: ApplyArgs,
  rendered: RenderResult & { sha256: string },
  socket: string,
): Promise<{ revert: RevertState; observation: Observation }> {
  await assertManagementInterface(
    target,
    args.interfaces,
    args.serve_on_management_ack,
  );
  if (args.lease_api && args.lease_cmds_path) {
    await assertHookLibrary(target, args.lease_cmds_path);
  }
  const staged = await stageConfig(target, rendered.json, deps.token());
  let stagedMoved = false;
  try {
    const isActive = await serviceActive(target);
    if (
      await remoteFileSha(target, CONFIG_PATH) === rendered.sha256 && isActive
    ) {
      return {
        revert: {
          host: args.host,
          token: "",
          armed_at: "",
          expires_at: "",
          armed_sha256: rendered.sha256,
        },
        observation: await probe(target, args, socket),
      };
    }

    const token = deps.token();
    const dir = `${REVERT_ROOT}/${token}`;
    const priorEnabled = await serviceEnabled(target);
    const revert = await claimAndArm(context, target, args, {
      token,
      dir,
      socket,
      activeSha: rendered.sha256,
      intent: "apply",
      canaries: args.canary_hosts.length > 0 ? args.canary_hosts : undefined,
      priorActive: isActive,
      priorEnabled,
      revertAfterS: args.revert_after_s,
    });

    try {
      await installStaged(target, staged, await resolveServiceGroup(target));
      stagedMoved = true;
      const keaHash = await pushConfig(target, rendered, isActive, socket);
      await persistPending(context, args, {
        config_sha256: rendered.sha256,
        kea_hash: keaHash,
        applied_at: new Date(deps.now()).toISOString(),
        subnets: args.subnets.length,
      });
    } catch (error) {
      await disarmAndRestore(context, target, args, dir, token, revert);
      throw error;
    }
    return {
      revert: { ...revert },
      observation: await probe(target, args, socket),
    };
  } finally {
    if (!stagedMoved) {
      await sshExec(deps, target, ["rm", "-f", staged]).catch(() => undefined);
    }
  }
}

/** `apply`: validate, arm, install and push a new config. */
export async function runApply(
  rawArgs: unknown,
  context: MethodContext,
): Promise<MethodOutcome> {
  const args = rawArgs as ApplyArgs;
  const target = await toTarget(context, args);
  const rendered = await renderAndHash(args);
  const { revert, observation } = await doApply(
    context,
    target,
    args,
    rendered,
    DEFAULT_CONTROL_SOCKET,
  );
  context.logger.info("Applied Kea config on {host} (token {token})", {
    host: args.host,
    token: revert.token,
  });
  const result = {
    host: args.host,
    revert_token: revert.token,
    expires_at: revert.expires_at,
    config_sha256: rendered.sha256,
    plan: [...APPLY_PLAN] as ApplyStep[],
    observation,
  };
  await persistAction(context, "apply", args, result);
  return { dataHandles: [], result };
}

/** Writes a fired marker onto its revert record. */
async function adoptFired(
  context: MethodContext,
  key: string,
  token: string,
  revert: RevertState,
  firedAt: string,
): Promise<void> {
  await context.writeResource(
    "revert",
    revertName(key, token),
    RevertStateSchema.parse({ ...revert, fired_at: firedAt }),
  );
}

/** The pre-commit checks that must pass before the timer is touched. */
async function commitPreflight(
  target: SshTarget,
  removal: boolean,
  storedConfig: PendingState | null,
): Promise<string | undefined> {
  if (removal) return undefined;
  if (!(await serviceActive(target))) {
    throw new SshError("the service is not active; refusing to commit");
  }
  const recorded = storedConfig?.kea_hash;
  if (!recorded) {
    throw new SshError(
      "no applied config hash is recorded; refusing to commit",
    );
  }
  const runningHash = await waitForHash(target, DEFAULT_CONTROL_SOCKET);
  if (runningHash === undefined) {
    throw new SshError(
      "the control socket did not answer a config hash; refusing to commit",
    );
  }
  if (runningHash !== recorded) {
    throw new SshError(
      "the running config differs from the applied one; refusing to commit",
    );
  }
  const enabled = await sshExec(deps, target, ["systemctl", "enable", SERVICE]);
  if (enabled.exit_code !== 0) {
    throw new SshError("could not enable the service; refusing to commit");
  }
  return runningHash;
}

/** Refuses to commit while a configured canary is unreachable. */
async function assertCanaries(
  target: SshTarget,
  canaries: string[],
): Promise<void> {
  for (const canary of canaries) {
    const ping = await runScript(
      target,
      `ping -c 1 -W 3 ${
        posixQuote(canary)
      } >/dev/null 2>&1 && echo ok || echo no`,
    );
    if (ping.stdout.trim() !== "ok") {
      throw new SshError(
        `canary ${canary} is unreachable; refusing to commit and leaving the revert armed`,
      );
    }
  }
}

/** Reads and validates the armed revert, adopting a fired marker. */
async function loadArmedRevert(
  context: MethodContext,
  target: SshTarget,
  key: string,
): Promise<{ token: string; dir: string; revert: RevertState }> {
  const marker = await readMarker(target);
  if (marker === null) {
    throw new SshError("no revert is armed for this host");
  }
  const { token } = marker;
  const dir = `${REVERT_ROOT}/${token}`;
  const revert = await context.readResource(revertName(key, token)) as
    | RevertState
    | null;
  if (revert === null) {
    throw new SshError("the revert record is missing; refusing to commit");
  }
  if (revert.cancelled_at) {
    throw new SshError("this revert was already cancelled or committed");
  }
  const firedNow = await readRemoteText(target, `${dir}/fired.json`);
  if (firedNow !== null) {
    const firedAt = parseFiredMarker(firedNow)?.firedAt ??
      new Date(deps.now()).toISOString();
    await adoptFired(context, key, token, revert, firedAt);
    throw new SshError(`the revert already fired at ${firedAt}`);
  }
  return { token, dir, revert };
}

/** Runs the verify checks as a gate; refuses on any failed field. */
async function verifyCommit(
  target: SshTarget,
  args: { host: string; port: number; user: string },
  revert: RevertState,
  runningHash: string | undefined,
  removal: boolean,
): Promise<{ observation: Observation; verify: VerifyResult }> {
  const observation = await probe(target, args, DEFAULT_CONTROL_SOCKET);
  const fresh = await sshExec(deps, target, ["true"]);
  const verify = verifyOf(
    observation,
    revert,
    runningHash,
    !removal,
    fresh.exit_code === 0,
  );
  const failures = (Object.keys(verify) as (keyof VerifyResult)[])
    .filter((name) => verify[name] === "fail");
  if (failures.length > 0) {
    throw new SshError(
      `verify failed (${
        failures.join(", ")
      }); refusing to commit and leaving the revert armed`,
    );
  }
  return { observation, verify };
}

/** Runs the locked commit section and adopts a race-fired revert. */
async function commitUnderLock(
  context: MethodContext,
  target: SshTarget,
  key: string,
  token: string,
  dir: string,
  revert: RevertState,
): Promise<void> {
  const status = await runScript(
    target,
    commitScript(dir, token, revert.armed_sha256),
  );
  const outcome = status.stdout.trim();
  if (outcome === "fired") {
    const firedAt = new Date(deps.now()).toISOString();
    await adoptFired(context, key, token, revert, firedAt);
    throw new SshError(`the revert already fired at ${firedAt}`);
  }
  if (outcome !== "committed") {
    throw new SshError(
      `could not commit the revert (${outcome}); it is still armed`,
    );
  }
}

/** Persists the committed revert and config records. */
async function recordCommitted(
  context: MethodContext,
  args: { host: string; port: number; user: string },
  key: string,
  token: string,
  revert: RevertState,
  observation: Observation,
  storedConfig: PendingState | null,
  removal: boolean,
): Promise<void> {
  await recordCancelled(context, key, token, revert);
  await persistCommitted(context, args, {
    config_sha256: observation.file_sha256 ?? "",
    kea_hash: observation.kea_hash,
    committed_at: new Date(deps.now()).toISOString(),
    applied_at: new Date(deps.now()).toISOString(),
    subnets: removal ? 0 : (storedConfig?.subnets ?? 0),
  });
  await discardPending(context, key);
}

/** `commit`: gate on verify, then take the lock and cancel the revert. */
export async function runCommit(
  rawArgs: unknown,
  context: MethodContext,
): Promise<MethodOutcome> {
  const args = rawArgs as SshArgs;
  const target = await toTarget(context, args);
  const key = instanceKey(args);
  const { token, dir, revert } = await loadArmedRevert(context, target, key);
  if (await remoteFileSha(target, CONFIG_PATH) !== revert.armed_sha256) {
    throw new SshError(
      "the live config differs from the armed one; refusing to commit",
    );
  }
  const removal = revert.intent === "remove";
  const storedConfig = await context.readResource(pendingName(key)) as
    | PendingState
    | null;
  const runningHash = await commitPreflight(target, removal, storedConfig);
  await assertCanaries(target, revert.canaries ?? []);
  const { observation, verify } = await verifyCommit(
    target,
    args,
    revert,
    runningHash,
    removal,
  );
  await commitUnderLock(context, target, key, token, dir, revert);
  await recordCommitted(
    context,
    args,
    key,
    token,
    revert,
    observation,
    storedConfig,
    removal,
  );
  const result = { host: args.host, committed: true, verify };
  await persistAction(context, "commit", args, result);
  return { dataHandles: [], result };
}

/** Stops and disables the service; used when converging a removal. */
async function convergeDisabled(target: SshTarget): Promise<void> {
  const stop = await runScript(target, `systemctl stop ${SERVICE}`);
  const disable = await runScript(target, `systemctl disable ${SERVICE}`);
  if (stop.exit_code !== 0 || disable.exit_code !== 0) {
    throw new SshError(
      "could not stop and disable the Kea service; removal aborted",
    );
  }
}

/** `remove`: converge disabled and the original config under the revert. */
export async function runRemove(
  rawArgs: unknown,
  context: MethodContext,
): Promise<MethodOutcome> {
  const args = rawArgs as SshArgs;
  const target = await toTarget(context, args);
  const socket = DEFAULT_CONTROL_SOCKET;
  const originalSha = await remoteFileSha(target, ORIGINAL_CONFIG);
  const original = await readRemoteText(target, ORIGINAL_CONFIG);
  if (originalSha === null || original === null) {
    throw new SshError(
      "no captured original config; run install before remove",
    );
  }
  const isActive = await serviceActive(target);
  const marker = await readMarker(target);
  if (
    !isActive && marker === null &&
    await remoteFileSha(target, CONFIG_PATH) === originalSha
  ) {
    return { dataHandles: [], result: { host: args.host, removed: false } };
  }

  const staged = await stageConfig(target, original, deps.token());
  let stagedMoved = false;
  try {
    const token = deps.token();
    const dir = `${REVERT_ROOT}/${token}`;
    const priorEnabled = await serviceEnabled(target);
    const revert = await claimAndArm(context, target, args, {
      token,
      dir,
      socket,
      activeSha: originalSha,
      intent: "remove",
      priorActive: isActive,
      priorEnabled,
      revertAfterS: 600,
    });

    try {
      await installStaged(target, staged, await resolveServiceGroup(target));
      stagedMoved = true;
      await convergeDisabled(target);
      const observation = await probe(target, args, socket);
      await persistPending(context, args, {
        config_sha256: originalSha,
        kea_hash: observation.kea_hash,
        applied_at: new Date(deps.now()).toISOString(),
        subnets: 0,
      });
      const result = {
        host: args.host,
        removed: true,
        revert_token: token,
        expires_at: revert.expires_at,
        observation,
      };
      await persistAction(context, "remove", args, result);
      return { dataHandles: [], result };
    } catch (error) {
      await disarmAndRestore(context, target, args, dir, token, revert);
      throw error;
    }
  } finally {
    if (!stagedMoved) {
      await sshExec(deps, target, ["rm", "-f", staged]).catch(() => undefined);
    }
  }
}
