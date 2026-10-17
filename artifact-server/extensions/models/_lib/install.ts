/**
 * The steps of an install, each small enough to read: snapshot the host,
 * install nginx, create the layout, write the site and credentials, prove the
 * config, and roll the whole thing back on failure.
 *
 * @module
 */

import {
  BLOB_DIR,
  BUNDLE_DIR,
  LAYOUT_VERSION,
  LAYOUT_VERSION_FILE,
  LOCK_FILE,
  REFS_DIR,
} from "./layout.ts";
import {
  HTPASSWD_PATH,
  NGINX_DEFAULT_SITE,
  NGINX_ENABLED_PATH,
  NGINX_SITE_PATH,
  TLS_CERT_PATH,
  TLS_KEY_PATH,
} from "./nginx.ts";
import { execSudo, putRootFile, putUserFile } from "./remote.ts";
import type { InstallArgsType } from "./schema.ts";
import type { SshDeps, SshTarget } from "./ssh.ts";
import { SshError } from "./ssh.ts";
import {
  type FileSnap,
  type LinkSnap,
  restoreFile,
  restoreLink,
  snapFile,
  snapLink,
} from "./snapshots.ts";

/** Everything an install may change, captured before it changes anything. */
export interface InstallSnaps {
  /** The site config file. */
  site: FileSnap;
  /** The TLS certificate, or null when TLS is not provided. */
  cert: FileSnap | null;
  /** The TLS key, or null when TLS is not provided. */
  key: FileSnap | null;
  /** The htpasswd file, or null when basic auth is not used. */
  htpasswd: FileSnap | null;
  /** The sites-enabled link. */
  enabled: LinkSnap;
  /** The default site link or file, or null when it is not touched. */
  default: LinkSnap | null;
}

/** Captures the files and links an install may touch. */
export async function captureInstallSnaps(
  deps: SshDeps,
  target: SshTarget,
  args: InstallArgsType,
): Promise<InstallSnaps> {
  const tls = args.tls.mode === "provided";
  return {
    site: await snapFile(deps, target, NGINX_SITE_PATH),
    cert: tls ? await snapFile(deps, target, TLS_CERT_PATH) : null,
    key: tls ? await snapFile(deps, target, TLS_KEY_PATH) : null,
    htpasswd: args.basic_auth
      ? await snapFile(deps, target, HTPASSWD_PATH)
      : null,
    enabled: await snapLink(deps, target, NGINX_ENABLED_PATH),
    default: args.disable_default_site
      ? await snapLink(deps, target, NGINX_DEFAULT_SITE)
      : null,
  };
}

/** Installs the nginx package, failing closed. */
/** Debian's service-start gate; returning 101 refuses a start. */
const POLICY_RC_D = "/usr/sbin/policy-rc.d";

/**
 * Installs nginx without ever letting the package default site come up. The
 * postinst would otherwise start nginx serving /var/www/html on 0.0.0.0:80; a
 * blocking policy-rc.d and a best-effort systemd mask keep it down until the
 * managed config and the enabled link are in place.
 */
export async function installNginx(
  deps: SshDeps,
  target: SshTarget,
): Promise<void> {
  const policy = await snapFile(deps, target, POLICY_RC_D);
  await putRootFile(deps, target, {
    path: POLICY_RC_D,
    content: "#!/bin/sh\nexit 101\n",
    mode: "0755",
    owner: "root",
    group: "root",
  });
  await execSudo(deps, target, ["systemctl", "mask", "nginx.service"]).catch(
    () => undefined,
  );
  let failure: unknown = null;
  try {
    const result = await execSudo(deps, target, [
      "env",
      "DEBIAN_FRONTEND=noninteractive",
      "apt-get",
      "install",
      "-y",
      "nginx",
    ]);
    if (result.exit_code !== 0) throw new SshError("could not install nginx");
  } catch (err) {
    failure = err;
  }
  await execSudo(deps, target, ["systemctl", "unmask", "nginx.service"]).catch(
    () => undefined,
  );
  try {
    await restoreFile(deps, target, policy);
  } catch (err) {
    if (failure === null) failure = err;
  }
  if (failure !== null) throw failure;
}

/**
 * The TCP ports nginx listens on for a wildcard address, as seen by `ss`. Used
 * to prove the package default site is not left listening after an install.
 */
export async function nginxWildcardPorts(
  deps: SshDeps,
  target: SshTarget,
): Promise<Set<number>> {
  const ports = new Set<number>();
  const result = await execSudo(deps, target, ["ss", "-ltnp"]);
  if (result.exit_code !== 0) return ports;
  for (const line of result.stdout.split("\n")) {
    const f = line.trim().split(/\s+/);
    if (f[0] !== "LISTEN" || f.length < 4) continue;
    if (!f.slice(5).join(" ").includes("nginx")) continue;
    const local = f[3];
    const idx = local.lastIndexOf(":");
    if (idx < 0) continue;
    const host = local.slice(0, idx);
    const port = Number(local.slice(idx + 1));
    if (!Number.isInteger(port)) continue;
    if (
      host === "0.0.0.0" || host === "*" || host === "[::]" || host === "::"
    ) {
      ports.add(port);
    }
  }
  return ports;
}

/** Creates the served layout and its sentinel files. */
export async function ensureLayout(
  deps: SshDeps,
  target: SshTarget,
  args: InstallArgsType,
): Promise<void> {
  const result = await execSudo(deps, target, [
    "install",
    "-d",
    "-o",
    args.ssh.user,
    "-g",
    args.ssh.user,
    "-m",
    "0755",
    args.root,
    `${args.root}/${BLOB_DIR}`,
    `${args.root}/${BUNDLE_DIR}`,
    `${args.root}/${REFS_DIR}`,
  ]);
  if (result.exit_code !== 0) throw new SshError("could not create the layout");
  await putUserFile(
    deps,
    target,
    `${args.root}/${LOCK_FILE}`,
    "",
    "0644",
  );
  await putUserFile(
    deps,
    target,
    `${args.root}/${LAYOUT_VERSION_FILE}`,
    `${LAYOUT_VERSION}\n`,
    "0644",
  );
}

/** Writes the site config, enables it and removes the default site if asked. */
export async function writeSite(
  deps: SshDeps,
  target: SshTarget,
  args: InstallArgsType,
  text: string,
  snaps: InstallSnaps,
): Promise<boolean> {
  const site = await putRootFile(deps, target, {
    path: NGINX_SITE_PATH,
    content: text,
    mode: "0644",
    owner: "root",
    group: "root",
  });
  const link = await execSudo(deps, target, [
    "ln",
    "-sfn",
    NGINX_SITE_PATH,
    NGINX_ENABLED_PATH,
  ]);
  if (link.exit_code !== 0) throw new SshError("could not enable the site");
  const enabledChanged = snaps.enabled.state !== "symlink" ||
    snaps.enabled.target !== NGINX_SITE_PATH;
  let changed = site.changed || enabledChanged;
  if (args.disable_default_site) {
    const rm = await execSudo(deps, target, ["rm", "-f", NGINX_DEFAULT_SITE]);
    if (rm.exit_code !== 0) {
      throw new SshError("could not remove the default nginx site");
    }
    changed = changed ||
      (snaps.default !== null && snaps.default.state !== "missing");
  }
  return changed;
}

/** Writes the TLS files and htpasswd the rendered config points at. */
export async function writeCredentials(
  deps: SshDeps,
  target: SshTarget,
  args: InstallArgsType,
): Promise<boolean> {
  let changed = false;
  if (args.tls.mode === "provided") {
    const sslDir = TLS_CERT_PATH.slice(0, TLS_CERT_PATH.lastIndexOf("/"));
    const madeSsl = await execSudo(deps, target, [
      "install",
      "-d",
      "-m",
      "0755",
      sslDir,
    ]);
    if (madeSsl.exit_code !== 0) {
      throw new SshError(`could not create ${sslDir}`);
    }
    const cert = await putRootFile(deps, target, {
      path: TLS_CERT_PATH,
      content: args.tls.cert_pem,
      mode: "0644",
      owner: "root",
      group: "root",
    });
    const key = await putRootFile(deps, target, {
      path: TLS_KEY_PATH,
      content: args.tls.key_pem,
      mode: "0600",
      owner: "root",
      group: "root",
    });
    changed = changed || cert.changed || key.changed;
  }
  if (args.basic_auth) {
    const htpasswd = args.basic_auth.users.map((u) => `${u.name}:${u.hash}`)
      .join("\n") + "\n";
    const file = await putRootFile(deps, target, {
      path: HTPASSWD_PATH,
      content: htpasswd,
      mode: "0640",
      owner: "root",
      group: "www-data",
    });
    changed = changed || file.changed;
  }
  return changed;
}

/**
 * Puts every file and link back the way {@link captureInstallSnaps} found it,
 * then re-runs `nginx -t`. Returns the list of rollback failures; an empty
 * list means the host is back to the captured state and the config passes.
 */
export async function rollbackInstall(
  deps: SshDeps,
  target: SshTarget,
  snaps: InstallSnaps,
): Promise<string[]> {
  const failures: string[] = [];
  const attempt = async (label: string, work: () => Promise<void>) => {
    try {
      await work();
    } catch (err) {
      failures.push(`${label}: ${err instanceof Error ? err.message : err}`);
    }
  };
  await attempt("site", () => restoreFile(deps, target, snaps.site));
  await attempt("enabled link", () => restoreLink(deps, target, snaps.enabled));
  const def = snaps.default;
  if (def !== null) {
    await attempt("default site", () => restoreLink(deps, target, def));
  }
  const cert = snaps.cert;
  if (cert !== null) {
    await attempt("certificate", () => restoreFile(deps, target, cert));
  }
  const key = snaps.key;
  if (key !== null) {
    await attempt("key", () => restoreFile(deps, target, key));
  }
  const htpasswd = snaps.htpasswd;
  if (htpasswd !== null) {
    await attempt("htpasswd", () => restoreFile(deps, target, htpasswd));
  }
  const retest = await execSudo(deps, target, ["nginx", "-t"]);
  if (retest.exit_code !== 0) {
    failures.push("nginx -t still fails after rollback");
  }
  return failures;
}

/**
 * Proves the rendered config with `nginx -t`, enables nginx at boot, starts or
 * reloads it, asserts it is enabled, then fails if a wildcard nginx listener
 * appeared on a port this install did not configure. The mask installNginx used
 * to keep the default site down also blocks the package from enabling nginx, so
 * enabling here is what makes the service survive a reboot.
 */
export async function verifyAndReload(
  deps: SshDeps,
  target: SshTarget,
  before: Set<number>,
  allowed: number[],
): Promise<void> {
  const test = await execSudo(deps, target, ["nginx", "-t"]);
  if (test.exit_code !== 0) {
    throw new SshError(
      `nginx -t failed on the rendered config: ${test.stderr.slice(0, 300)}`,
    );
  }
  const enable = await execSudo(deps, target, ["systemctl", "enable", "nginx"]);
  if (enable.exit_code !== 0) {
    throw new SshError("could not enable nginx at boot");
  }
  const active = await execSudo(deps, target, [
    "systemctl",
    "is-active",
    "--quiet",
    "nginx",
  ]);
  const action = active.exit_code === 0 ? "reload" : "start";
  const started = await execSudo(deps, target, ["systemctl", action, "nginx"]);
  if (started.exit_code !== 0) throw new SshError(`nginx ${action} failed`);
  const enabled = await execSudo(deps, target, [
    "systemctl",
    "is-enabled",
    "nginx",
  ]);
  if (
    enabled.exit_code !== 0 ||
    /^(disabled|masked)/m.test(enabled.stdout.trim())
  ) {
    throw new SshError(
      `nginx is not enabled at boot: ${
        enabled.stdout.trim() || enabled.stderr.trim()
      }`,
    );
  }
  const after = await nginxWildcardPorts(deps, target);
  const offenders = [...after].filter((p) =>
    !before.has(p) && !allowed.includes(p)
  );
  if (offenders.length > 0) {
    throw new SshError(
      `nginx listens on unexpected wildcard ports: ${offenders.join(", ")}`,
    );
  }
}
