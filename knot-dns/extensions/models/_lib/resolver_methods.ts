/**
 * The Knot Resolver 6 methods: render, apply and remove. The configuration is
 * staged, validated with `kresctl`, swapped, reloaded and proven with a test
 * query on the resolver's own listen address.
 *
 * @module
 */

import { z } from "npm:zod@4.3.6";
import { exec as sshExec, sha256Hex, upload as sshUpload } from "./ssh.ts";
import { KnotError } from "./vault.ts";
import {
  applyResolverScript,
  parseKeyValues,
  removeResolverScript,
} from "./scripts.ts";
import {
  ApplyResolverArgs,
  RemoveResolverArgs,
  StateResolverSchema,
} from "./schemas.ts";
import { mapScriptError } from "./errors.ts";
import {
  pickTestListen,
  pickTestQuery,
  renderResolverYaml,
} from "./resolver.ts";
import {
  assertPortsFree,
  type Ctx,
  deps,
  instanceName,
  recordOutcome,
  servedApexes,
  sshTarget,
} from "./runtime.ts";
import { assertListenAcceptable, otherZoneListens } from "./listen.ts";

/** Live resolver configuration path. */
const RESOLVER_YAML = "/etc/knot-resolver/config.yaml";
/** Staged resolver configuration path. */
const RESOLVER_YAML_STAGED = "/etc/knot-resolver/.config.yaml.staged";
/** Backup of the package's resolver configuration. */
const RESOLVER_PACKAGE_BACKUP = "/etc/knot-resolver/config.yaml.package";

/** Removes the staged file after a failed run that never reached the script. */
async function dropStaged(
  target: Awaited<ReturnType<typeof sshTarget>>,
): Promise<void> {
  try {
    await sshExec(deps, target, ["rm", "-f", "--", RESOLVER_YAML_STAGED]);
  } catch {
    // Best effort: the host script's own trap normally did it already.
  }
}

async function applyResolver(
  args: z.input<typeof ApplyResolverArgs>,
  context: Ctx,
) {
  const a = ApplyResolverArgs.parse(args);
  // A wildcard without an ack, or a listen the applied authoritative zones
  // already hold, is refused before any host work.
  assertListenAcceptable(
    { listen: a.resolver.listen, listen_any_ack: a.resolver.listen_any_ack },
    await otherZoneListens(context, a.ssh.host, ""),
  );
  const yaml = renderResolverYaml(a.resolver);
  const sha = await sha256Hex(yaml);
  const target = await sshTarget(context, a.ssh);
  // The resolver's own socket is allowed (a re-apply); a foreign holder, e.g.
  // the systemd-resolved stub, is a port_busy error instead of a failed bind.
  await assertPortsFree(target, a.resolver.listen, [
    "kresd",
    "knot-resolver",
  ]);
  const testListen = pickTestListen(a.resolver);
  if (testListen === null) {
    throw new KnotError(
      "invalid_input",
      "allow_query_from permits none of the resolver listen addresses, so the apply self-test would be refused; add a listen address (or loopback) to allow_query_from",
    );
  }
  const testName = pickTestQuery(a.resolver, await servedApexes(target));
  let res;
  try {
    await sshUpload(deps, target, {
      path: RESOLVER_YAML_STAGED,
      content: yaml,
      mode: "0644",
    });
    res = await sshExec(deps, target, [
      "sh",
      "-c",
      applyResolverScript({
        liveYaml: RESOLVER_YAML,
        packageBackup: RESOLVER_PACKAGE_BACKUP,
        stagedYaml: RESOLVER_YAML_STAGED,
        testListen,
        testName,
      }),
    ]);
  } catch (e) {
    await dropStaged(target);
    throw e;
  }
  if (res.exit_code !== 0) {
    await dropStaged(target);
    throw mapScriptError(res.stderr, res.exit_code);
  }
  const changed = parseKeyValues(res.stdout).changed === "yes";
  const forwards = a.resolver.forwards.map((f) => f.subtree);
  const state = await context.writeResource(
    "resolver",
    await instanceName(["resolver", a.ssh.host]),
    {
      host: a.ssh.host,
      status: "applied",
      rendered_sha256: sha,
      listen: a.resolver.listen,
      forwards,
      applied_at: new Date().toISOString(),
    },
  );
  const outcome = await recordOutcome(context, {
    action: "apply_resolver",
    host: a.ssh.host,
    changed,
    listen: a.resolver.listen,
    forwards,
    test_name: testName,
    observed_at: new Date().toISOString(),
  });
  return {
    dataHandles: [state, outcome],
    result: {
      host: a.ssh.host,
      changed,
      listen: a.resolver.listen,
      forwards,
    },
  };
}

async function removeResolver(
  args: z.input<typeof RemoveResolverArgs>,
  context: Ctx,
) {
  const a = RemoveResolverArgs.parse(args);
  const target = await sshTarget(context, a.ssh);
  const stored = await context.readResource(
    await instanceName(["resolver", a.ssh.host]),
  ) as z.infer<typeof StateResolverSchema> | null;
  if (stored?.status !== "applied" && !a.remove_ack) {
    throw new KnotError(
      "invalid_input",
      "this model did not apply a resolver on this host; pass remove_ack to proceed",
    );
  }
  const res = await sshExec(deps, target, [
    "sh",
    "-c",
    removeResolverScript({
      liveYaml: RESOLVER_YAML,
      packageBackup: RESOLVER_PACKAGE_BACKUP,
    }),
  ]);
  if (res.exit_code !== 0) throw mapScriptError(res.stderr, res.exit_code);
  const removed = parseKeyValues(res.stdout).removed === "yes";
  const state = await context.writeResource(
    "resolver",
    await instanceName(["resolver", a.ssh.host]),
    {
      host: a.ssh.host,
      status: "removed",
      rendered_sha256: "",
      listen: [],
      forwards: [],
    },
  );
  const outcome = await recordOutcome(context, {
    action: "remove_resolver",
    host: a.ssh.host,
    removed,
    observed_at: new Date().toISOString(),
  });
  return { dataHandles: [state, outcome], result: { removed } };
}

/** The resolver methods, spread into the model's `methods`. */
export const resolverMethods = {
  render_resolver: {
    description:
      "READ-ONLY. Render the Knot Resolver 6 config.yaml and its sha256 without touching any host.",
    arguments: ApplyResolverArgs,
    execute: (args: z.input<typeof ApplyResolverArgs>, _context: Ctx) => {
      const yaml = renderResolverYaml(ApplyResolverArgs.parse(args).resolver);
      return sha256Hex(yaml).then((sha256) => ({ result: { yaml, sha256 } }));
    },
  },
  apply_resolver: {
    kind: "action" as const,
    description:
      "DESTRUCTIVE. Validate with kresctl, back up the package config, atomically swap the resolver config.yaml, reload and verify a test query on a listen address allow_query_from permits, restoring the previous config on failure. Idempotent: an unchanged render is a no-op.",
    arguments: ApplyResolverArgs,
    execute: applyResolver,
  },
  remove_resolver: {
    kind: "action" as const,
    description:
      "DESTRUCTIVE. Stop and disable the recursive resolver, restore the package configuration, and fail if the service cannot be stopped. Refuses a host whose resolver this model did not apply unless remove_ack is set.",
    arguments: RemoveResolverArgs,
    execute: removeResolver,
  },
};
