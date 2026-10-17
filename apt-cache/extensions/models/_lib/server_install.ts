/**
 * `install_server`: refresh the package lists, write a loopback-only bootstrap
 * fragment, install apt-cacher-ng, and prove nothing listens on a wildcard.
 *
 * @module
 */

import { exec, sha256Hex, type SshTarget } from "./ssh.ts";
import {
  ACNG_CONF_DIR,
  DEFAULT_ACNG_PORT,
  FRAGMENT_PATH,
  isWildcardAddress,
  renderBootstrapFragment,
} from "./apt.ts";
import {
  AptCacheError,
  type Ctx,
  deps,
  iso,
  parseSsListen,
  requireOk,
  resolveKey,
  serverName,
  targetKey,
  targetOf,
  writeManagedFile,
} from "./remote.ts";
import {
  type InstallServerArgs,
  type ServerState,
  ServerStateSchema,
} from "./schemas.ts";

/** Install apt-cacher-ng non-interactively, or adopt it when present. */
export async function installServer(
  args: InstallServerArgs,
  context: Ctx,
) {
  const key = await resolveKey(context, args.ssh.ssh_key_ref);
  const t = targetOf(args.ssh, key);
  // Preserve the ownership map from a prior apply: install only adds the
  // package, and dropping the map would leave remove_server unable to clean up.
  const prior = await context.readResource(serverName(t)) as
    | ServerState
    | null;
  const status = await exec(deps, t, [
    "dpkg-query",
    "-W",
    "-f=${Status}",
    "apt-cacher-ng",
  ]);
  const managed = { ...prior?.managed_files };
  if (!/install ok installed/.test(status.stdout)) {
    context.logger.info("Installing apt-cacher-ng on {host}", { host: t.host });
    managed[FRAGMENT_PATH] = await installPackage(t, managed[FRAGMENT_PATH]);
  }
  const version = requireOk(
    await exec(deps, t, [
      "dpkg-query",
      "-W",
      "-f=${Version}",
      "apt-cacher-ng",
    ]),
    "dpkg-query apt-cacher-ng",
  ).stdout.trim();
  const handle = await context.writeResource(
    "server",
    serverName(t),
    ServerStateSchema.parse({
      target: targetKey(t),
      host: t.host,
      installed: true,
      version,
      managed_files: Object.keys(managed).length > 0 ? managed : undefined,
      observed_at: iso(deps.now()),
    }),
  );
  return { dataHandles: [handle], result: { host: t.host, version } };
}

/**
 * Installs the package without ever exposing the default listener: refresh the
 * package lists (a stock cloud image has none), write the loopback-only
 * bootstrap fragment, then install. Returns the digest of the fragment so the
 * record owns it; apply_server later treats it as the model's own bytes.
 */
async function installPackage(
  t: SshTarget,
  recordedFragmentSha: string | undefined,
): Promise<string> {
  requireOk(
    await exec(deps, t, [
      "timeout",
      String(APT_UPDATE_TIMEOUT_S),
      "apt-get",
      "-o",
      "Acquire::http::Timeout=30",
      "-o",
      "Acquire::https::Timeout=30",
      "update",
    ]),
    "apt-get update",
  );
  requireOk(
    await exec(deps, t, ["mkdir", "-p", "--", ACNG_CONF_DIR]),
    "mkdir /etc/apt-cacher-ng",
  );
  const bootstrap = await writeManagedFile(
    deps,
    t,
    FRAGMENT_PATH,
    renderBootstrapFragment(),
    "0644",
    recordedFragmentSha ??
      await sha256Hex(new TextEncoder().encode(renderBootstrapFragment())),
  );
  requireOk(
    await exec(deps, t, [
      "sh",
      "-c",
      "set -e; " +
      "printf '%s\\n' 'apt-cacher-ng apt-cacher-ng/tunnelenable boolean false' | debconf-set-selections; " +
      "DEBIAN_FRONTEND=noninteractive apt-get install -y apt-cacher-ng",
    ]),
    "apt-get install apt-cacher-ng",
  );
  await assertNoWildcardListener(t);
  return bootstrap.sha256;
}

/** Upper bound on `apt-get update`, in seconds. */
const APT_UPDATE_TIMEOUT_S = 300;

/**
 * Fails closed, stopping the daemon, when anything listens on a wildcard
 * address on the package's default port after install: the proxy would be open
 * on every interface.
 */
async function assertNoWildcardListener(t: SshTarget): Promise<void> {
  const listening = parseSsListen(
    requireOk(await exec(deps, t, ["ss", "-ltn"]), "ss -ltn").stdout,
  );
  const open = listening.pairs.filter((p) =>
    p.port === DEFAULT_ACNG_PORT && isWildcardAddress(p.address)
  );
  if (open.length === 0) return;
  await exec(deps, t, ["systemctl", "stop", "apt-cacher-ng"]);
  throw new AptCacheError(
    "open_listener",
    `apt-cacher-ng listens on ${
      open.map((p) => p.address).join(", ")
    }:${DEFAULT_ACNG_PORT} after install; stopped it`,
  );
}
