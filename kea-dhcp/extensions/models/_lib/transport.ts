/**
 * SSH and Kea control-socket transport, plus the typed revert markers.
 *
 * Everything here talks to the host through the vendored `_lib/ssh.ts`; the
 * secrets travel over stdin and the config-set request carries the whole
 * `{"Dhcp4": {...}}` object Kea expects.
 *
 * @module
 */

import {
  assertRemotePath,
  exec as sshExec,
  type ExecResult,
  posixQuote,
  sha256Hex,
  SshConfigError,
  SshError,
  type SshTarget,
  upload as sshUpload,
} from "./ssh.ts";
import { deps, type MethodContext } from "./deps.ts";
import type { ConfigArgs, SshArgs } from "./schemas.ts";
import { toRenderInput } from "./schemas.ts";
import {
  groupScript,
  hookLibraryScript,
  managementScript,
  REVERT_ROOT,
  SERVICE,
} from "./host_scripts.ts";
import { renderConfig, type RenderResult } from "./render.ts";
import { KeaInputError, parseInterface } from "./grammar.ts";

/** The armed-revert marker written to active.json. */
export interface ActiveMarker {
  token: string;
  expiresAt: string;
}

/** One fired revert marker. */
export interface FiredMarker {
  token: string;
  firedAt: string;
  result: string;
}

/** Resolves the private key for a target, over stdin only. */
async function resolveKey(
  context: MethodContext,
  reference: string,
): Promise<string> {
  if (deps.resolveSecret) return await deps.resolveSecret(reference);
  const slash = reference.indexOf("/");
  if (slash <= 0 || slash === reference.length - 1) {
    throw new KeaInputError("ssh_key_ref must be '<vault>/<key>'");
  }
  const vault = reference.slice(0, slash);
  const key = reference.slice(slash + 1);
  const service = context.vaultService;
  if (!service || typeof service.get !== "function") {
    throw new Error("no vault service is available to resolve ssh_key_ref");
  }
  const value = await service.get(vault, key);
  if (typeof value !== "string" || value === "") {
    throw new Error(`vault ${vault} key ${key} is empty`);
  }
  return value;
}

/** Builds the transport target, resolving the key over stdin. */
export async function toTarget(
  context: MethodContext,
  args: SshArgs,
): Promise<SshTarget> {
  const privateKey = await resolveKey(context, args.ssh_key_ref);
  return {
    host: args.host,
    port: args.port,
    user: args.user,
    host_key_policy: "strict",
    host_keys: args.host_keys,
    private_key: privateKey,
    connect_timeout_s: args.connect_timeout_s,
  };
}

/** Renders the configuration and its hash. */
export async function renderAndHash(
  args: ConfigArgs,
): Promise<RenderResult & { sha256: string }> {
  const rendered = renderConfig(toRenderInput(args));
  return { ...rendered, sha256: await sha256Hex(rendered.json) };
}

/** Runs `kea-dhcp4 -V` and returns the version token (2.4 prints a bare version). */
export function keaVersion(text: string): string | undefined {
  const match = /(\d+\.\d+\.\d+)/.exec(text);
  return match?.[1];
}

/** Runs a fixed script on the host through `sh -c`. */
export async function runScript(
  target: SshTarget,
  script: string,
): Promise<ExecResult> {
  return await sshExec(deps, target, ["sh", "-c", script]);
}

/** The config file's SHA-256, or null when the file is absent. */
export async function remoteFileSha(
  target: SshTarget,
  path: string,
): Promise<string | null> {
  assertRemotePath(path);
  const result = await sshExec(deps, target, [
    "sh",
    "-c",
    `[ -f ${posixQuote(path)} ] && { sha256sum ${
      posixQuote(path)
    } || shasum -a 256 ${posixQuote(path)}; } | awk '{print $1}'`,
  ]);
  if (result.exit_code !== 0) return null;
  const sha = result.stdout.trim();
  return /^[0-9a-f]{64}$/.test(sha) ? sha : null;
}

/** Reads a remote text file, or null when absent. */
export async function readRemoteText(
  target: SshTarget,
  path: string,
): Promise<string | null> {
  assertRemotePath(path);
  const result = await sshExec(deps, target, ["cat", path]);
  return result.exit_code === 0 ? result.stdout : null;
}

/** Uploads a JSON payload to a mode-0600 temp file and returns its path. */
async function stageJson(
  target: SshTarget,
  payload: unknown,
): Promise<string> {
  const path = `/tmp/kea-dhcp-${deps.token()}.json`;
  await sshUpload(deps, target, {
    path,
    content: JSON.stringify(payload),
    mode: "0600",
  });
  return path;
}

/** Sends one command to the Kea control socket and parses the answer. */
export async function keaControl(
  target: SshTarget,
  request: Record<string, unknown>,
  socket: string,
): Promise<Record<string, unknown>> {
  const reqPath = await stageJson(target, request);
  try {
    const result = await runScript(
      target,
      `socat -t 10 - UNIX-CONNECT:${posixQuote(socket)} < ${
        posixQuote(reqPath)
      }`,
    );
    if (result.exit_code !== 0) {
      throw new SshError(`control socket failed (exit ${result.exit_code})`);
    }
    const parsed = JSON.parse(result.stdout) as Record<string, unknown>;
    if (parsed.result !== 0) {
      throw new SshError(
        `Kea refused the command: ${String(parsed.text ?? "unknown")}`,
      );
    }
    return parsed;
  } finally {
    await sshExec(deps, target, ["rm", "-f", reqPath]).catch(() => undefined);
  }
}

/** Reads the running config hash over the control socket. */
export async function configHash(
  target: SshTarget,
  socket: string,
): Promise<string | undefined> {
  const answer = await keaControl(target, {
    command: "config-hash-get",
    service: ["dhcp4"],
  }, socket);
  const args = answer.arguments as Record<string, unknown> | undefined;
  const hash = args?.hash;
  return typeof hash === "string" ? hash : undefined;
}

/** Polls the control socket until it answers a config hash. */
export async function waitForHash(
  target: SshTarget,
  socket: string,
): Promise<string | undefined> {
  for (let i = 0; i < 10; i++) {
    const hash = await configHash(target, socket).catch(() => undefined);
    if (hash !== undefined) return hash;
    await deps.sleep(500);
  }
  return undefined;
}

/** Refuses serving DHCP on the interface that carries the SSH session. */
export async function assertManagementInterface(
  target: SshTarget,
  interfaces: string[],
  acknowledge: boolean,
): Promise<void> {
  if (acknowledge) return;
  const result = await runScript(target, managementScript());
  const iface = result.stdout.trim();
  if (iface === "" || iface === "UNKNOWN") {
    throw new SshConfigError(
      "could not determine the interface that carries this SSH session; refusing to apply unless serve_on_management_ack is set",
    );
  }
  const configured = interfaces.map((value) =>
    parseInterface(value)?.name ?? value
  );
  if (configured.includes(iface)) {
    throw new SshConfigError(
      `refusing to serve DHCP on ${iface}, the interface that carries this SSH session; set serve_on_management_ack to override`,
    );
  }
}

/** True when the Kea service is active. */
export async function serviceActive(target: SshTarget): Promise<boolean> {
  const result = await runScript(
    target,
    `systemctl is-active ${SERVICE} 2>/dev/null || true`,
  );
  return result.stdout.trim() === "active";
}

/** True when the Kea service is enabled at boot. */
export async function serviceEnabled(target: SshTarget): Promise<boolean> {
  const result = await runScript(
    target,
    `systemctl is-enabled ${SERVICE} 2>/dev/null || true`,
  );
  return result.stdout.trim() === "enabled";
}

/** The group the Kea service runs as; the unit's `User=` is authoritative. */
export async function resolveServiceGroup(target: SshTarget): Promise<string> {
  const result = await runScript(target, groupScript());
  const group = result.stdout.trim();
  if (!/^[A-Za-z0-9_.-]+$/.test(group)) {
    throw new SshError(
      "could not resolve the Kea service group; check `systemctl show -p User kea-dhcp4-server`",
    );
  }
  return group;
}

/** Refuses a lease_cmds hook that is not the packaged, root-owned library. */
export async function assertHookLibrary(
  target: SshTarget,
  path: string,
): Promise<void> {
  assertRemotePath(path);
  const result = await runScript(target, hookLibraryScript(path));
  if (result.stdout.trim() !== "ok") {
    throw new KeaInputError(
      `lease_cmds_path rejected (${result.stdout.trim()}); it must be the packaged library in the host hooks directory`,
    );
  }
}

/** Parses a fired.json body, or null when it is absent or malformed. */
export function parseFiredMarker(text: string): FiredMarker | null {
  try {
    const body = JSON.parse(text) as {
      token?: unknown;
      fired_at?: unknown;
      result?: unknown;
    };
    if (typeof body.fired_at !== "string") return null;
    return {
      token: typeof body.token === "string" ? body.token : "",
      firedAt: body.fired_at,
      result: typeof body.result === "string" ? body.result : "unknown",
    };
  } catch {
    return null;
  }
}

/** The fired markers under the revert root. */
export async function readFiredMarkers(
  target: SshTarget,
): Promise<FiredMarker[]> {
  const result = await runScript(
    target,
    `for p in ${REVERT_ROOT}/*/fired.json; do [ -f "$p" ] && cat "$p"; done 2>/dev/null || true`,
  );
  const markers: FiredMarker[] = [];
  for (const line of result.stdout.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (trimmed === "") continue;
    const marker = parseFiredMarker(trimmed);
    if (marker !== null && marker.token !== "") markers.push(marker);
  }
  return markers;
}

/** Reads the armed-revert marker, or null when it is absent or malformed. */
export async function readMarker(
  target: SshTarget,
): Promise<ActiveMarker | null> {
  const text = await readRemoteText(target, `${REVERT_ROOT}/active.json`);
  if (text === null || text.trim() === "") return null;
  try {
    const body = JSON.parse(text) as { token?: unknown; expires_at?: unknown };
    if (typeof body.token !== "string" || typeof body.expires_at !== "string") {
      return null;
    }
    return { token: body.token, expiresAt: body.expires_at };
  } catch {
    return null;
  }
}

/**
 * Builds the config-set request from a rendered config. Kea expects the whole
 * top-level object (`{"Dhcp4": {...}}`), not the inner `Dhcp4` body; sending
 * the body answers `Missing mandatory 'Dhcp4' parameter.`
 */
export function configSetRequest(
  rendered: RenderResult,
): Record<string, unknown> {
  return {
    command: "config-set",
    service: ["dhcp4"],
    arguments: rendered.config,
  };
}
