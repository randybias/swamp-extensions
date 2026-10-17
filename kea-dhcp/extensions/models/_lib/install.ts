/**
 * `install`: the package install and the one-time capture of the shipped
 * config, which `remove` restores.
 *
 * @module
 */

import { exec as sshExec, posixQuote, SshError } from "./ssh.ts";
import { deps, type MethodContext, type MethodOutcome } from "./deps.ts";
import type { SshArgs } from "./schemas.ts";
import {
  CONFIG_PATH,
  ORIGINAL_CONFIG,
  REVERT_ROOT,
  SERVICE,
} from "./host_scripts.ts";
import { keaVersion, runScript, toTarget } from "./transport.ts";

/** `install`: install the packages and capture the original config once. */
export async function runInstall(
  rawArgs: unknown,
  context: MethodContext,
): Promise<MethodOutcome> {
  const args = rawArgs as SshArgs;
  const target = await toTarget(context, args);
  const installed: string[] = [];
  for (const pkg of ["kea-dhcp4-server", "socat"]) {
    const check = await runScript(
      target,
      `dpkg-query -W -f='\${Status}' ${posixQuote(pkg)} 2>/dev/null || true`,
    );
    if (!check.stdout.includes("install ok installed")) {
      const add = await runScript(
        target,
        `DEBIAN_FRONTEND=noninteractive apt-get install -y ${posixQuote(pkg)}`,
      );
      if (add.exit_code !== 0) {
        throw new SshError(`could not install ${pkg}`);
      }
      installed.push(pkg);
    }
  }
  await runScript(
    target,
    `mkdir -p ${posixQuote(REVERT_ROOT)} && chmod 700 ${
      posixQuote(REVERT_ROOT)
    } && if [ -f ${posixQuote(CONFIG_PATH)} ] && [ ! -f ${
      posixQuote(ORIGINAL_CONFIG)
    } ]; then cp -a ${posixQuote(CONFIG_PATH)} ${
      posixQuote(ORIGINAL_CONFIG)
    }; fi`,
  );
  await sshExec(deps, target, ["systemctl", "stop", SERVICE]).catch(
    () => undefined,
  );
  await sshExec(deps, target, ["systemctl", "disable", SERVICE]).catch(
    () => undefined,
  );
  const versionText = await runScript(target, "kea-dhcp4 -V 2>&1 || true");
  return {
    dataHandles: [],
    result: {
      host: args.host,
      kea_version: keaVersion(versionText.stdout),
      installed,
    },
  };
}
