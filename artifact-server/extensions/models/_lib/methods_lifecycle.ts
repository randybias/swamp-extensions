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
  rollbackInstall,
  verifyAndReload,
  writeCredentials,
  writeSite,
} from "./install.ts";
import { rootState } from "./snapshots.ts";
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
      const handle = await context.writeResource(
        "config",
        `config-${instanceKey(args)}`,
        ConfigSchema.parse({
          config_sha256: configSha,
          text,
          url_base: base,
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
      "DESTRUCTIVE. Install nginx, create the served layout, write the site config, htpasswd and TLS files, prove the config with nginx -t and reload. Idempotent: the same rendered config is not reloaded. A failed nginx -t restores the previous config and never reloads.",
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
      await installNginx(activeDeps, target);
      const snaps = await captureInstallSnaps(activeDeps, target, args);
      try {
        await ensureLayout(activeDeps, target, args);
        const text = renderFor(args);
        const configSha = await sha256Hex(text);
        // Credentials first: the site is enabled last, so a failure writing the
        // cert can never leave an enabled link pointing at a missing file.
        let changed = await writeCredentials(activeDeps, target, args);
        changed = (await writeSite(activeDeps, target, args, text, snaps)) ||
          changed;
        await verifyAndReload(activeDeps, target);
        const scheme = args.tls.mode === "provided" ? "https" : "http";
        const base = urlBase(args.server_name, args.listen.port, scheme);
        const handle = await context.writeResource(
          "config",
          `config-${instanceKey(args)}`,
          ConfigSchema.parse({
            config_sha256: configSha,
            text,
            url_base: base,
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
      } catch (err) {
        // Any throw after the snapshots — nginx -t, a failed credential write,
        // a failed remove, a lost connection — rolls the host back.
        const clean = await rollbackInstall(activeDeps, target, snaps);
        const reason = err instanceof Error ? err.message : String(err);
        throw new SshError(
          `install failed; rolled back and not reloaded${
            clean ? "" : " (the restored config also fails nginx -t)"
          }: ${reason}`,
        );
      }
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
      "DESTRUCTIVE. Remove the site config, its TLS files and htpasswd, and reload nginx; with remove_data also remove the served root, but only when it is a real directory holding a .layout-version sentinel. A clean no-op when absent, and it never removes the nginx package.",
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
        if (present) {
          const reload = await execSudo(activeDeps, target, [
            "systemctl",
            "reload",
            "nginx",
          ]);
          if (reload.exit_code !== 0) {
            throw new SshError("nginx reload failed");
          }
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
          data_removed: dataRemoved,
        },
      };
    },
  },
};
