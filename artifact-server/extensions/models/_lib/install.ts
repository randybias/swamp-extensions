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
export async function installNginx(
  deps: SshDeps,
  target: SshTarget,
): Promise<void> {
  const result = await execSudo(deps, target, [
    "apt-get",
    "install",
    "-y",
    "nginx",
  ]);
  if (result.exit_code !== 0) throw new SshError("could not install nginx");
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
 * then re-runs `nginx -t`. Returns whether the restored config passes.
 */
export async function rollbackInstall(
  deps: SshDeps,
  target: SshTarget,
  snaps: InstallSnaps,
): Promise<boolean> {
  await restoreFile(deps, target, snaps.site);
  await restoreLink(deps, target, snaps.enabled);
  if (snaps.default !== null) await restoreLink(deps, target, snaps.default);
  if (snaps.cert !== null) await restoreFile(deps, target, snaps.cert);
  if (snaps.key !== null) await restoreFile(deps, target, snaps.key);
  if (snaps.htpasswd !== null) {
    await restoreFile(deps, target, snaps.htpasswd);
  }
  const retest = await execSudo(deps, target, ["nginx", "-t"]);
  return retest.exit_code === 0;
}

/**
 * Proves the rendered config with `nginx -t` and reloads. The reload is
 * idempotent and always runs, so a retry after a prior reload failure picks up
 * the config even when this run changed nothing.
 */
export async function verifyAndReload(
  deps: SshDeps,
  target: SshTarget,
): Promise<void> {
  const test = await execSudo(deps, target, ["nginx", "-t"]);
  if (test.exit_code !== 0) {
    throw new SshError(
      `nginx -t failed on the rendered config: ${test.stderr.slice(0, 300)}`,
    );
  }
  const reload = await execSudo(deps, target, [
    "systemctl",
    "reload",
    "nginx",
  ]);
  if (reload.exit_code !== 0) throw new SshError("nginx reload failed");
}
