/**
 * Server lifecycle methods: render a config, install or uninstall the site,
 * and observe its state.
 *
 * @module
 */

import type { ArtifactServerMethod, MethodContext } from "./types.ts";
import { observeServer } from "./artifacts.ts";
import { LAYOUT_VERSION_FILE, urlBase } from "./layout.ts";
import {
  HTPASSWD_PATH,
  NGINX_DEFAULT_SITE,
  NGINX_ENABLED_PATH,
  NGINX_SITE_PATH,
  TLS_CERT_PATH,
  TLS_KEY_PATH,
} from "./nginx.ts";
import { removeRoot } from "./ops.ts";
import { execSudo, probeFile } from "./remote.ts";
import { renderFor } from "./render.ts";
import { activeDeps } from "./runtime.ts";
import {
  ConfigSchema,
  GetArgs,
  InstallArgs,
  RenderConfigArgs,
  UninstallArgs,
} from "./schema.ts";
import {
  captureInstallSnaps,
  ensureLayout,
  installNginx,
  nginxWildcardPorts,
  rollbackInstall,
  verifyAndReload,
  writeCredentials,
  writeSite,
} from "./install.ts";
import { type LinkSnap, restoreLink, rootState } from "./snapshots.ts";
import { sha256Hex, SshError } from "./ssh.ts";
import { instanceKey, toTarget, validateCommon } from "./target.ts";
import { validateTls } from "./tls.ts";

/** The methods in this group. */
export const lifecycleMethods: Record<string, ArtifactServerMethod> = {
  render_config: {
    description:
      "READ-ONLY. Render the nginx site config for the given inputs and persist it; deterministic, and contains no secret, only paths to secret files.",
    arguments: RenderConfigArgs,
    execute: async (rawArgs: unknown, context: MethodContext) => {
      const args = RenderConfigArgs.parse(rawArgs);
      validateCommon(args);
      if (args.tls.mode === "provided") {
        await validateTls(activeDeps, args.tls.cert_pem, args.tls.key_pem);
      }
      const text = renderFor(args);
      const configSha = await sha256Hex(text);
      const base = urlBase(
        args.server_name,
        args.listen.port,
        args.tls.mode === "provided" ? "https" : "http",
      );
      // Carry forward any default-site removal recorded by install, so a later
      // render does not erase the snapshot uninstall needs.
      const prior = await context.readResource?.(
        `config-${instanceKey(args)}`,
      ) as {
        removed_default_site?: boolean;
        default_site_target?: string | null;
        default_site_content?: string | null;
      } | null;
      const handle = await context.writeResource(
        "config",
        `config-${instanceKey(args)}`,
        ConfigSchema.parse({
          config_sha256: configSha,
          text,
          url_base: base,
          removed_default_site: prior?.removed_default_site ?? false,
          default_site_target: prior?.default_site_target ?? null,
          default_site_content: prior?.default_site_content ?? null,
          rendered_at: new Date(activeDeps.now()).toISOString(),
        }),
      );
      return {
        dataHandles: [handle],
        result: { config_sha256: configSha, url_base: base, text },
      };
    },
  },
  install: {
    kind: "action",
    description:
      "DESTRUCTIVE. Install nginx without starting the package default site, create the served layout, write the site config, htpasswd and TLS files, prove the config with nginx -t and reload. The reload is idempotent and always runs; any failure after the host is snapshotted rolls every change back and re-tests the restored config.",
    arguments: InstallArgs,
    execute: async (rawArgs: unknown, context: MethodContext) => {
      const args = InstallArgs.parse(rawArgs);
      validateCommon(args);
      if (args.tls.mode === "provided") {
        await validateTls(activeDeps, args.tls.cert_pem, args.tls.key_pem);
      }
      const target = toTarget(args.ssh);
      const rootKind = await rootState(activeDeps, target, args.root);
      if (rootKind === "foreign") {
        throw new SshError(
          `refusing to install into ${args.root}: it exists but holds no regular ${LAYOUT_VERSION_FILE} sentinel`,
        );
      }
      const createdRoot = rootKind === "missing";
      const listenersBefore = await nginxWildcardPorts(activeDeps, target);
      await installNginx(activeDeps, target);
      const snaps = await captureInstallSnaps(activeDeps, target, args);
      let text = "";
      let configSha = "";
      let changed = false;
      try {
        await ensureLayout(activeDeps, target, args);
        text = renderFor(args);
        configSha = await sha256Hex(text);
        // Credentials first: the site is enabled last, so a failure writing the
        // cert can never leave an enabled link pointing at a missing file.
        changed = await writeCredentials(activeDeps, target, args);
        changed = (await writeSite(activeDeps, target, args, text, snaps)) ||
          changed;
        await verifyAndReload(activeDeps, target, listenersBefore, [
          args.listen.port,
        ]);
      } catch (err) {
        // Any throw after the snapshots — nginx -t, a failed credential write,
        // a failed remove, a lost connection — rolls the host back.
        const failures = await rollbackInstall(activeDeps, target, snaps);
        if (createdRoot) {
          try {
            await removeRoot(activeDeps, target, args.root);
          } catch (rootErr) {
            failures.push(
              `root: ${rootErr instanceof Error ? rootErr.message : rootErr}`,
            );
          }
        }
        const reason = err instanceof Error ? err.message : String(err);
        const rolled = failures.length
          ? ` with rollback errors (${failures.join("; ")})`
          : "";
        throw new SshError(
          `install failed; rolled back and not reloaded${rolled}: ${reason}`,
        );
      }
      // Persist and log only after the host is known good, so a failure here
      // cannot restore the files while nginx keeps running the new config.
      const scheme = args.tls.mode === "provided" ? "https" : "http";
      const base = urlBase(args.server_name, args.listen.port, scheme);
      const handle = await context.writeResource(
        "config",
        `config-${instanceKey(args)}`,
        ConfigSchema.parse({
          config_sha256: configSha,
          text,
          url_base: base,
          removed_default_site: args.disable_default_site &&
            snaps.default !== null && snaps.default.state !== "missing",
          default_site_target: snaps.default?.target ?? null,
          default_site_content: snaps.default?.content ?? null,
          rendered_at: new Date(activeDeps.now()).toISOString(),
        }),
      );
      context.logger.info("Installed artifact server on {host}:{port}", {
        host: args.ssh.host,
        port: args.listen.port,
      });
      return {
        dataHandles: [handle],
        result: { config_sha256: configSha, url_base: base, changed },
      };
    },
  },
  get: {
    description:
      "READ-ONLY. Observe nginx state (active, site config hash, TLS and basic-auth mode) and the layout summary, and persist the observation; it fails when no artifact-server site is installed.",
    arguments: GetArgs,
    execute: async (rawArgs: unknown, context: MethodContext) => {
      const args = GetArgs.parse(rawArgs);
      const target = toTarget(args.ssh);
      return await observeServer(activeDeps, target, args, context, {
        requireSite: true,
      });
    },
  },
  sync: {
    description:
      "READ-ONLY. Observe nginx state and the layout summary and persist it, succeeding even when no site is installed yet.",
    arguments: GetArgs,
    execute: async (rawArgs: unknown, context: MethodContext) => {
      const args = GetArgs.parse(rawArgs);
      const target = toTarget(args.ssh);
      return await observeServer(activeDeps, target, args, context);
    },
  },
  uninstall: {
    kind: "action",
    description:
      "DESTRUCTIVE. Remove the site config, its TLS files and htpasswd, restore the package default site if install removed it, and reload nginx; with remove_data also remove the served root, but only when it is a real directory holding a .layout-version sentinel. A clean no-op when absent, and it never removes the nginx package.",
    arguments: UninstallArgs,
    execute: async (rawArgs: unknown, context: MethodContext) => {
      const args = UninstallArgs.parse(rawArgs);
      const target = toTarget(args.ssh);
      const enabled = await probeFile(
        activeDeps,
        target,
        NGINX_ENABLED_PATH,
        true,
      );
      const site = await probeFile(activeDeps, target, NGINX_SITE_PATH, true);
      const present = enabled.state !== "missing" ||
        site.state !== "missing";
      const credentialPaths = [TLS_CERT_PATH, TLS_KEY_PATH, HTPASSWD_PATH];
      const credProbes = await Promise.all(
        credentialPaths.map((p) => probeFile(activeDeps, target, p, true)),
      );
      const credentialsPresent =
        credProbes.filter((p) => p.state !== "missing").length;

      // Restore the default site install removed, if it recorded doing so.
      const stored = await context.readResource?.(
        `config-${instanceKey(args)}`,
      ) as {
        removed_default_site?: boolean;
        default_site_target?: string | null;
        default_site_content?: string | null;
      } | null;
      let defaultRestored = false;
      if (stored?.removed_default_site) {
        const snap: LinkSnap = stored.default_site_target != null
          ? {
            path: NGINX_DEFAULT_SITE,
            state: "symlink",
            target: stored.default_site_target,
            content: null,
          }
          : stored.default_site_content != null
          ? {
            path: NGINX_DEFAULT_SITE,
            state: "file",
            target: null,
            content: stored.default_site_content,
          }
          : {
            path: NGINX_DEFAULT_SITE,
            state: "missing",
            target: null,
            content: null,
          };
        await restoreLink(activeDeps, target, snap);
        defaultRestored = true;
      }

      if (present || credentialsPresent > 0) {
        const rm = await execSudo(activeDeps, target, [
          "rm",
          "-f",
          NGINX_ENABLED_PATH,
          NGINX_SITE_PATH,
          ...credentialPaths,
        ]);
        if (rm.exit_code !== 0) {
          throw new SshError("could not remove the site files");
        }
      }
      if (present || credentialsPresent > 0 || defaultRestored) {
        const reload = await execSudo(activeDeps, target, [
          "systemctl",
          "reload",
          "nginx",
        ]);
        if (reload.exit_code !== 0) {
          throw new SshError("nginx reload failed");
        }
      }
      let dataRemoved = false;
      if (args.remove_data) {
        const kind = await rootState(activeDeps, target, args.root);
        if (kind === "foreign") {
          throw new SshError(
            `refusing to remove ${args.root}: it is not a directory holding a regular ${LAYOUT_VERSION_FILE} sentinel`,
          );
        }
        if (kind === "ours") {
          await removeRoot(activeDeps, target, args.root);
          dataRemoved = true;
        }
      }
      context.logger.info(
        "Uninstalled artifact server site (present={present})",
        { present },
      );
      return {
        result: {
          removed: present,
          credentials_removed: credentialsPresent,
          default_site_restored: defaultRestored,
          data_removed: dataRemoved,
        },
      };
    },
  },
};
