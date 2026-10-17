/**
 * Client-side method implementations: configure the apt snippet, read the
 * effective proxy values, and remove the managed files. Each function has the
 * swamp `execute` signature `(args, context)` and is registered by
 * `apt_cache.ts`.
 *
 * @module
 */

import { exec, sha256Hex, type SshTarget } from "./ssh.ts";
import {
  assertPassthroughHost,
  CLIENT_SNIPPET_PATH,
  type ClientRenderInput,
  DETECT_DIR,
  DETECT_PATH,
  expectedProxyKeys,
  parseProxyUrl,
  proxyValuesOf,
  renderClientSnippet,
  renderDetectScript,
} from "./apt.ts";
import {
  AptCacheError,
  clientName,
  type Ctx,
  deps,
  iso,
  observationName,
  parseAptConfigDump,
  proxyConflicts,
  readRemoteFile,
  remoteSha,
  requireOk,
  resolveKey,
  restoreClient,
  serverPolicyForHost,
  snapshotClient,
  targetKey,
  targetOf,
  uploadIfChanged,
  verifyClientProxy,
} from "./remote.ts";
import {
  type ClientGetArgs,
  type ClientState,
  ClientStateSchema,
  type ConfigureClientArgs,
  ObservationSchema,
  type UnconfigureClientArgs,
} from "./schemas.ts";

/** Write the managed snippet, and the auto-detect script when requested. */
async function writeClientFiles(
  t: SshTarget,
  proxyUrl: string,
  input: ClientRenderInput,
  snippet: string,
): Promise<boolean> {
  let changed = false;
  if (input.fallback_direct) {
    // The auto-detect script lives in a directory that may not exist on a
    // fresh host, and the snippet references it, so create the directory and
    // write the script before the snippet.
    requireOk(
      await exec(deps, t, ["mkdir", "-p", "--", DETECT_DIR]),
      "mkdir auto-detect dir",
    );
    requireOk(
      await exec(deps, t, ["chmod", "0755", "--", DETECT_DIR]),
      "chmod auto-detect dir",
    );
    changed = await uploadIfChanged(
      deps,
      t,
      DETECT_PATH,
      renderDetectScript(proxyUrl),
      "0755",
    ) || changed;
  }
  changed = await uploadIfChanged(
    deps,
    t,
    CLIENT_SNIPPET_PATH,
    snippet,
    "0644",
  ) || changed;
  return changed;
}

/** Verify every managed key is effective, then optionally run apt-get update. */
async function verifyClientWrote(
  t: SshTarget,
  input: ClientRenderInput,
  verifyUpdate: boolean,
): Promise<void> {
  const keysMatch = await verifyClientProxy(deps, t, expectedProxyKeys(input));
  // A key mismatch is a configuration error, never tolerated (even with
  // fallback_direct, which only makes apt resilient at run time).
  if (!keysMatch) {
    throw new AptCacheError(
      "verify_failed",
      "the managed snippet is not the proxy apt-config reports",
    );
  }
  if (verifyUpdate) {
    const update = await exec(deps, t, ["apt-get", "update"]);
    if (update.exit_code !== 0) {
      throw new AptCacheError(
        "verify_failed",
        `apt-get update failed after writing the snippet (exit ${update.exit_code})`,
      );
    }
  }
}

/** Write and verify the managed apt snippet on a client. */
export async function configureClient(
  args: ConfigureClientArgs,
  context: Ctx,
) {
  const proxy = parseProxyUrl(args.proxy_url);
  for (const host of args.bypass_hosts) assertPassthroughHost(host);
  const key = await resolveKey(context, args.ssh.ssh_key_ref);
  const t = targetOf(args.ssh, key);
  const recordedPolicy = await serverPolicyForHost(
    context,
    proxy.address,
    args.policy_check_ack,
  );
  if (recordedPolicy !== undefined && recordedPolicy !== args.https_policy) {
    throw new AptCacheError(
      "policy_mismatch",
      `https_policy ${args.https_policy} does not match the recorded server policy ${recordedPolicy} for ${proxy.address}`,
    );
  }
  const conflicts = await proxyConflicts(deps, t);
  if (conflicts.length > 0 && !args.override_existing_ack) {
    throw new AptCacheError(
      "conflict",
      `another apt configuration sets a proxy: ${
        conflicts.join(", ")
      }; pass override_existing_ack=true`,
    );
  }
  const input: ClientRenderInput = {
    proxy_url: proxy.url,
    https_policy: args.https_policy,
    bypass_hosts: args.bypass_hosts,
    fallback_direct: args.fallback_direct,
  };
  const snippet = renderClientSnippet(input);
  // Snapshot the prior managed files so a failed re-run restores them instead
  // of deleting a snippet that was working.
  const snapshot = await snapshotClient(deps, t);
  let changed = false;
  try {
    changed = await writeClientFiles(t, proxy.url, input, snippet);
    await verifyClientWrote(t, input, args.verify_update);
  } catch (error) {
    // Any failure restores the prior state: the snippet must never point at a
    // missing auto-detect script, an unverified proxy, or replace a working
    // configuration with a broken one.
    await restoreClient(deps, t, snapshot);
    throw error;
  }
  const handle = await context.writeResource(
    "client",
    clientName(t),
    ClientStateSchema.parse({
      target: targetKey(t),
      host: t.host,
      present: true,
      proxy_url: proxy.url,
      https_policy: args.https_policy,
      snippet_sha256: await sha256Hex(new TextEncoder().encode(snippet)),
      verified: true,
      observed_at: iso(deps.now()),
    }),
  );
  return {
    dataHandles: [handle],
    result: {
      client: t.host,
      changed,
      proxy_url: proxy.url,
      https_policy: args.https_policy,
      verified: true,
    },
  };
}

/** Report the effective proxy values and whether the managed snippet is in force. */
export async function clientGet(args: ClientGetArgs, context: Ctx) {
  const key = await resolveKey(context, args.ssh.ssh_key_ref);
  const t = targetOf(args.ssh, key);
  const dump = requireOk(
    await exec(deps, t, ["apt-config", "dump"]),
    "apt-config dump",
  ).stdout;
  // Keep only Acquire proxy keys and strip any userinfo: never persist a
  // credential that a pre-existing proxy file may carry.
  const proxyValues = proxyValuesOf(parseAptConfigDump(dump));
  const record = await context.readResource(clientName(t)) as
    | ClientState
    | null;
  const liveSha = await remoteSha(deps, t, CLIENT_SNIPPET_PATH);
  const observation = ObservationSchema.parse({
    target: targetKey(t),
    kind: "client_get",
    host: t.host,
    proxy_values: proxyValues,
    managed_snippet_in_force: record?.snippet_sha256 !== undefined &&
      liveSha === record.snippet_sha256,
    conflicts: await proxyConflicts(deps, t),
    observed_at: iso(deps.now()),
  });
  const handle = await context.writeResource(
    "observation",
    observationName("client_get", t),
    observation,
  );
  return { dataHandles: [handle], result: observation };
}

/** Remove the managed snippet and auto-detect script. */
export async function unconfigureClient(
  args: UnconfigureClientArgs,
  context: Ctx,
) {
  const key = await resolveKey(context, args.ssh.ssh_key_ref);
  const t = targetOf(args.ssh, key);
  const present = (await readRemoteFile(deps, t, CLIENT_SNIPPET_PATH)) !== null;
  if (present) {
    requireOk(
      await exec(deps, t, ["rm", "-f", "--", CLIENT_SNIPPET_PATH]),
      "rm client snippet",
    );
    requireOk(
      await exec(deps, t, ["rm", "-f", "--", DETECT_PATH]),
      "rm auto-detect script",
    );
    if ((await readRemoteFile(deps, t, CLIENT_SNIPPET_PATH)) !== null) {
      throw new AptCacheError(
        "verify_failed",
        "the managed snippet is still present after removal",
      );
    }
    const dump = requireOk(
      await exec(deps, t, ["apt-config", "dump"]),
      "apt-config dump",
    ).stdout;
    const stillManaged = /Acquire::http::Proxy-Auto-Detect/.test(dump) ||
      parseAptConfigDump(dump)["Acquire::http::Proxy"] !== undefined;
    if (stillManaged && (await proxyConflicts(deps, t)).length > 0) {
      throw new AptCacheError(
        "verify_failed",
        "another file still sets an apt proxy after removing the managed snippet",
      );
    }
  }
  const handle = await context.writeResource(
    "client",
    clientName(t),
    ClientStateSchema.parse({
      target: targetKey(t),
      host: t.host,
      present: false,
      observed_at: iso(deps.now()),
    }),
  );
  return {
    dataHandles: [handle],
    result: { client: t.host, removed: present },
  };
}
