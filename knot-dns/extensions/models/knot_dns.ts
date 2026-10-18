/**
 * Swamp extension model for Knot DNS (authoritative) and Knot Resolver 6
 * (recursive), managed over SSH.
 *
 * The model is generic: it holds no host, address or zone in its definition.
 * Every method takes its target and its declaration as arguments, so one
 * definition serves any host. Secret references are resolved in-model through
 * the runtime's vault service and reach the host over stdin, never on a
 * command line, in a log, in an output or in stored state.
 *
 * @module
 */

import { z } from "npm:zod@4.3.6";
import {
  exec as sshExec,
  sha256Hex,
  type SshTarget,
  upload as sshUpload,
} from "./_lib/ssh.ts";
import { KnotError, resolveSecret } from "./_lib/vault.ts";
import {
  type Ctx,
  deps,
  instanceName,
  recordOutcome,
  servedApexes,
  setDeps,
  sshTarget,
} from "./_lib/runtime.ts";
import { resolverMethods } from "./_lib/resolver_methods.ts";
import {
  applyZoneScript,
  between,
  finalizeZoneScript,
  getDsScript,
  kskSubmittedScript,
  observeScript,
  parseKeyValues,
  parseServed,
  portCheckScript,
  removeZoneScript,
  resolverObserveScript,
  restoreZoneScript,
  stagedListen,
  zonePaths,
} from "./_lib/scripts.ts";
import {
  assertListenAcceptable,
  hostListens,
  listenFragment,
  otherZoneListens,
} from "./_lib/listen.ts";
import {
  ApplyZoneArgs,
  DsSchema,
  InstallArgs,
  ObservationSchema,
  OutcomeSchema,
  RemoveZoneArgs,
  SshOnlyArgs,
  StateResolverSchema,
  StateZoneSchema,
  TsigKeySchema,
  ZoneArgs,
  ZoneOnlyArgs,
} from "./_lib/schemas.ts";
import { mapScriptError } from "./_lib/errors.ts";
import { installScript } from "./_lib/install.ts";
import { parseDsLines } from "./_lib/parse.ts";
import {
  canonicalRecords,
  declaredTuples,
  diffDeclared,
  type DiffEntry,
  DnssecSchema,
  normalizeApex,
  renderZoneConfig,
  renderZoneFile,
  type ZoneRecord,
} from "./_lib/zone.ts";

export { instanceName, setDeps };

/** Builds the declared records: explicit records plus apex NS from `ns[]`. */
export function zoneRecords(a: {
  ns: string[];
  records: unknown[];
}): ZoneRecord[] {
  return [
    ...(a.records as ZoneRecord[]),
    ...a.ns.map((ns) => ({
      name: "@",
      type: "NS" as const,
      data: ns,
    })),
  ];
}

function dnssecOf(a: { dnssec: "off" | z.infer<typeof DnssecSchema> }) {
  return a.dnssec === "off" ? undefined : a.dnssec;
}

function configFor(
  apex: string,
  a: {
    dnssec: "off" | z.infer<typeof DnssecSchema>;
    notify_secondaries: string[];
    allow_transfer: string[];
    tsig_keys: { name: string }[];
  },
) {
  return renderZoneConfig({
    apex,
    file: zonePaths(apex).zoneFile,
    signed: a.dnssec !== "off",
    dnssec: dnssecOf(a) ?? { algorithm: "ecdsap256sha256", nsec3: false },
    notifySecondaries: a.notify_secondaries,
    allowTransfer: a.allow_transfer,
    tsigKeyNames: a.tsig_keys.map((k) => k.name),
  });
}

async function renderTsigFragment(
  context: Ctx,
  keys: z.infer<typeof TsigKeySchema>[],
): Promise<string> {
  const lines = ["key:"];
  for (const k of keys) {
    const secret = await resolveSecret(context.vaultService, k.secret_ref);
    lines.push(`  - id: ${k.name}`);
    lines.push(`    algorithm: ${k.algorithm}`);
    lines.push(`    secret: ${JSON.stringify(secret)}`);
  }
  return `${lines.join("\n")}\n`;
}

async function persistZone(
  context: Ctx,
  host: string,
  zone: string,
  data: z.infer<typeof StateZoneSchema>,
) {
  const name = await instanceName(["zone", host, zone]);
  return await context.writeResource("zone", name, data);
}

/** Precheck that each requested listen address/port is free or held by Knot. */
async function assertPortsFree(
  target: SshTarget,
  listens: string[],
): Promise<void> {
  const res = await sshExec(deps, target, [
    "sh",
    "-c",
    portCheckScript(listens),
  ]);
  if (res.exit_code !== 0) {
    const detail = res.stderr.split("\n").find((l) => l.includes("PORT_BUSY"));
    throw new KnotError(
      "port_busy",
      detail ?? "a requested listen port is busy",
    );
  }
}

/** A fresh id that keeps one run's staged files apart from any other's. */
function newRun(): string {
  return crypto.randomUUID().replaceAll("-", "").slice(0, 16);
}

/** Uploads files to the host; the locked script that consumes them runs next. */
async function stageFiles(
  target: SshTarget,
  files: { path: string; content: string; mode: string }[],
): Promise<void> {
  for (const f of files) await sshUpload(deps, target, f);
}

/**
 * Compares what knotd serves with the declaration. A difference restores the
 * previous zone from `backup` and fails; a restore that itself fails says
 * where the backup is.
 */
async function verifyServed(
  target: SshTarget,
  zone: string,
  diff: { added: unknown[]; removed: unknown[] },
  backup: string,
): Promise<void> {
  if (diff.added.length === 0 && diff.removed.length === 0) return;
  if (!backup) {
    throw new KnotError(
      "verify_failed",
      "served records differ from the declaration and no backup was kept; repair by hand",
    );
  }
  const restored = await sshExec(deps, target, [
    "sh",
    "-c",
    restoreZoneScript({ apex: zone, backup }),
  ]);
  if (restored.exit_code !== 0) {
    throw new KnotError(
      "rollback_failed",
      `served records differ and the rollback failed; the backup is kept at ${backup}`,
    );
  }
  throw new KnotError(
    "verify_failed",
    `served records differ from the declaration (${diff.added.length} missing, ${diff.removed.length} extra); the previous zone was restored`,
  );
}

async function observe(
  context: Ctx,
  a: z.infer<typeof SshOnlyArgs>,
  verbose: boolean,
) {
  const target = await sshTarget(context, a.ssh);
  const apexes = await servedApexes(target);
  const zones: z.infer<typeof ObservationSchema>["zones"] = [];
  if (apexes.length > 0) {
    const res = await sshExec(deps, target, [
      "sh",
      "-c",
      observeScript(apexes),
    ]);
    if (res.exit_code !== 0) throw mapScriptError(res.stderr, res.exit_code);
    for (const apex of apexes) {
      const block = res.stdout.split(`ZONE ${apex}`)[1] ?? "";
      const kv = parseKeyValues(block);
      const served = parseServed(block, apex);
      const stored = await context.readResource(
        await instanceName(["zone", a.ssh.host, apex]),
      ) as z.infer<typeof StateZoneSchema> | null;
      const declared: DiffEntry[] = (stored?.declared ?? []).flatMap((s) => {
        try {
          return [JSON.parse(s) as DiffEntry];
        } catch {
          return [];
        }
      });
      const diff = diffDeclared(declared, served);
      const fileDrift = stored !== null && stored.rendered_sha256 !== "" &&
        kv.file_sha !== undefined && kv.file_sha !== stored.rendered_sha256;
      const keyStates = between(block, "KEY_BEGIN", "KEY_END").split("\n")
        .map((l) => l.trim()).filter((l) => l !== "");
      zones.push({
        apex,
        ...(kv.serial ? { served_serial: kv.serial } : {}),
        ...(kv.file_sha ? { file_sha256: kv.file_sha } : {}),
        drift: fileDrift || diff.added.length > 0 || diff.removed.length > 0,
        added: diff.added.map((t) => `${t.name} ${t.type} ${t.data}`),
        removed: diff.removed.map((t) => `${t.name} ${t.type} ${t.data}`),
        key_states: keyStates,
      });
    }
  }
  const rObs = await sshExec(deps, target, [
    "sh",
    "-c",
    resolverObserveScript(),
  ]);
  if (rObs.exit_code !== 0) throw mapScriptError(rObs.stderr, rObs.exit_code);
  const resolverActive = parseKeyValues(rObs.stdout).active;
  const handle = await context.writeResource(
    "observation",
    await instanceName(["observation", a.ssh.host]),
    {
      host: a.ssh.host,
      zones,
      ...(resolverActive ? { resolver_active: resolverActive } : {}),
      observed_at: new Date().toISOString(),
    },
  );
  return {
    dataHandles: [handle],
    result: {
      host: a.ssh.host,
      zones: verbose ? zones : zones.filter((z) => z.drift),
      resolver_active: resolverActive ?? "",
    },
  };
}

/** Model definition for `@randybias/knot-dns`. */
export const model = {
  type: "@randybias/knot-dns",
  version: "2026.10.17.2",
  description:
    "Manage authoritative Knot DNS zones and a Knot Resolver 6 recursive resolver over SSH, validating every candidate with the vendor tools before it reaches the service.",
  upgrades: [
    {
      toVersion: "2026.10.17.2",
      description:
        "Re-vendor the canonical SSH transport; drop the unrendered parent_ds_check input; purge a removed zone's KASP keys when acknowledged; test the resolver on a listen address the access list permits.",
      upgradeAttributes: (old: Record<string, unknown>) => old,
    },
  ],
  globalArguments: z.strictObject({}),
  resources: {
    zone: {
      description: "Zone declaration and its last applied render",
      schema: StateZoneSchema,
      lifetime: "infinite" as const,
      garbageCollection: 10,
    },
    resolver: {
      description: "Resolver configuration and its last applied render",
      schema: StateResolverSchema,
      lifetime: "infinite" as const,
      garbageCollection: 10,
    },
    observation: {
      description: "Last live observation of managed zones and the resolver",
      schema: ObservationSchema,
      lifetime: "infinite" as const,
      garbageCollection: 10,
    },
    outcome: {
      description:
        "What the last install, apply or remove did (changed, removed, versions)",
      schema: OutcomeSchema,
      lifetime: "infinite" as const,
      garbageCollection: 10,
    },
    ds: {
      description: "Last DS records read for a signed zone",
      schema: DsSchema,
      lifetime: "infinite" as const,
      garbageCollection: 10,
    },
  },
  methods: {
    install: {
      kind: "action" as const,
      description:
        "Install Knot (and Knot Resolver 6 when resolver is true) and add the model's include line to knot.conf. Idempotent: an already-installed host is unchanged.",
      arguments: InstallArgs,
      execute: async (args: z.input<typeof InstallArgs>, context: Ctx) => {
        const a = InstallArgs.parse(args);
        const target = await sshTarget(context, a.ssh);
        const res = await sshExec(deps, target, [
          "sh",
          "-c",
          installScript({ resolver: a.resolver }),
        ]);
        if (res.exit_code !== 0) {
          throw mapScriptError(res.stderr, res.exit_code);
        }
        const kv = parseKeyValues(res.stdout);
        const handle = await recordOutcome(context, {
          action: "install",
          host: a.ssh.host,
          knot_version: kv.knot_version ?? "",
          ...(kv.kresd_version ? { kresd_version: kv.kresd_version } : {}),
          observed_at: new Date().toISOString(),
        });
        return {
          dataHandles: [handle],
          result: {
            host: a.ssh.host,
            knot_version: kv.knot_version ?? "",
            ...(kv.kresd_version ? { kresd_version: kv.kresd_version } : {}),
          },
        };
      },
    },

    render_zone: {
      description:
        "READ-ONLY. Render the canonical zone file, its config fragment and their sha256 without touching any host. Persists the render under its own resource name, never overwriting applied state.",
      arguments: ZoneArgs,
      execute: async (args: z.input<typeof ZoneArgs>, context: Ctx) => {
        const a = ZoneArgs.parse(args);
        const zone = normalizeApex(a.zone);
        const all = zoneRecords(a);
        const records = canonicalRecords(zone, a.soa, all);
        const file = renderZoneFile(zone, a.soa, all);
        const fragment = configFor(zone, a);
        const sha = await sha256Hex(file);
        const handle = await context.writeResource(
          "zone",
          await instanceName(["render", a.ssh.host, zone]),
          {
            host: a.ssh.host,
            apex: zone,
            status: "rendered",
            rendered_sha256: sha,
            record_count: records.length,
            dnssec: a.dnssec !== "off",
          },
        );
        return {
          dataHandles: [handle],
          result: {
            zone,
            file,
            fragment,
            sha256: sha,
            record_count: records.length,
          },
        };
      },
    },

    apply_zone: {
      kind: "action" as const,
      description:
        "DESTRUCTIVE. Render, validate with kzonecheck and knotc conf-check, atomically swap, reload and verify one whole zone, restoring the previous zone if verification fails. A managed zone owns all of its records, so records not declared are removed. Idempotent: an unchanged render is a no-op.",
      arguments: ApplyZoneArgs,
      execute: async (args: z.input<typeof ApplyZoneArgs>, context: Ctx) => {
        const a = ApplyZoneArgs.parse(args);
        const zone = normalizeApex(a.zone);
        const all = zoneRecords(a);
        const records = canonicalRecords(zone, a.soa, all);
        const file = renderZoneFile(zone, a.soa, all);
        const fragment = configFor(zone, a);
        const sha = await sha256Hex(file);
        const target = await sshTarget(context, a.ssh);
        const name = await instanceName(["zone", a.ssh.host, zone]);
        const stored = await context.readResource(name) as
          | z.infer<typeof StateZoneSchema>
          | null;
        if (stored?.dnssec && a.dnssec === "off" && !a.dnssec_unsign_ack) {
          throw new KnotError(
            "invalid_input",
            "the zone is recorded as signed; turning signing off needs dnssec_unsign_ack (and the delete-algorithm path, not implemented yet)",
          );
        }
        const resolverState = await context.readResource(
          await instanceName(["resolver", a.ssh.host]),
        ) as z.infer<typeof StateResolverSchema> | null;
        assertListenAcceptable(a, resolverState?.listen);
        // The listen fragment is host-global: the union of every other zone's
        // request and this one's.
        const listens = hostListens(
          a.listen,
          await otherZoneListens(context, a.ssh.host, zone),
        );
        await assertPortsFree(target, listens);
        const run = newRun();
        const staged = zonePaths(zone, run);
        // Staged names are unique per run; the TSIG fragment is staged every
        // time, empty without keys, so a removed key is actually removed.
        await stageFiles(target, [
          {
            path: stagedListen(run),
            content: listenFragment(listens),
            mode: "0644",
          },
          {
            path: staged.stagedTsig,
            content: a.tsig_keys.length > 0
              ? await renderTsigFragment(context, a.tsig_keys)
              : "",
            mode: "0640",
          },
          { path: staged.stagedZone, content: file, mode: "0640" },
          { path: staged.stagedFragment, content: fragment, mode: "0644" },
        ]);
        const res = await sshExec(deps, target, [
          "sh",
          "-c",
          applyZoneScript({ apex: zone, run, listens }),
        ]);
        if (res.exit_code !== 0) {
          throw mapScriptError(res.stderr, res.exit_code);
        }
        const kv = parseKeyValues(res.stdout);
        const backup = kv.backup ?? "";
        const served = parseServed(res.stdout, zone);
        const expected = declaredTuples(zone, a.soa, all);
        const diff = diffDeclared(expected, served);
        await verifyServed(target, zone, diff, backup);
        if (backup) {
          await sshExec(deps, target, ["sh", "-c", finalizeZoneScript(backup)]);
        }
        const handle = await persistZone(context, a.ssh.host, zone, {
          host: a.ssh.host,
          apex: zone,
          status: "applied",
          rendered_sha256: sha,
          record_count: records.length,
          dnssec: a.dnssec !== "off",
          ...(kv.serial ? { served_serial: kv.serial } : {}),
          applied_at: new Date().toISOString(),
          declared: expected.map((t) => JSON.stringify(t)),
          requested_listen: a.listen,
          listen: listens,
        });
        const outcome = await recordOutcome(context, {
          action: "apply_zone",
          host: a.ssh.host,
          zone,
          changed: kv.changed === "yes",
          added: diff.added.length,
          removed: diff.removed.length,
          serial: kv.serial ?? "",
          dnssec: a.dnssec !== "off" ? "on" : "off",
          observed_at: new Date().toISOString(),
        });
        return {
          dataHandles: [handle, outcome],
          result: {
            zone,
            changed: kv.changed === "yes",
            added: diff.added,
            removed: diff.removed,
            serial: kv.serial ?? "",
            dnssec: a.dnssec !== "off" ? "on" : "off",
          },
        };
      },
    },

    remove_zone: {
      kind: "action" as const,
      description:
        "DESTRUCTIVE. Stop serving one managed zone and remove its zone file, config fragment and TSIG fragment. A signed zone is refused unless dnssec_unsign_ack is set; with purge_keys_ack the journal, timers and KASP keys are purged. A second call is a no-op.",
      arguments: RemoveZoneArgs,
      execute: async (args: z.input<typeof RemoveZoneArgs>, context: Ctx) => {
        const a = RemoveZoneArgs.parse(args);
        const zone = normalizeApex(a.zone);
        const target = await sshTarget(context, a.ssh);
        const name = await instanceName(["zone", a.ssh.host, zone]);
        const stored = await context.readResource(name) as
          | z.infer<typeof StateZoneSchema>
          | null;
        if (stored?.dnssec && !a.dnssec_unsign_ack) {
          throw new KnotError(
            "invalid_input",
            "the zone is recorded as signed; pass dnssec_unsign_ack to remove it",
          );
        }
        // The shared listen fragment shrinks to what the other zones need.
        const listens = hostListens(
          [],
          await otherZoneListens(context, a.ssh.host, zone),
        );
        const run = newRun();
        await stageFiles(target, [
          {
            path: stagedListen(run),
            content: listenFragment(listens),
            mode: "0644",
          },
        ]);
        const res = await sshExec(deps, target, [
          "sh",
          "-c",
          removeZoneScript({
            apex: zone,
            run,
            purgeKeysAck: a.purge_keys_ack,
            unsigned: a.dnssec_unsign_ack,
          }),
        ]);
        if (res.exit_code !== 0) {
          throw mapScriptError(res.stderr, res.exit_code);
        }
        const kv = parseKeyValues(res.stdout);
        const handle = await persistZone(context, a.ssh.host, zone, {
          host: a.ssh.host,
          apex: zone,
          status: "removed",
          rendered_sha256: stored?.rendered_sha256 ?? "",
          record_count: 0,
          dnssec: false,
        });
        const outcome = await recordOutcome(context, {
          action: "remove_zone",
          host: a.ssh.host,
          zone,
          removed: kv.removed === "yes",
          observed_at: new Date().toISOString(),
        });
        return {
          dataHandles: [handle, outcome],
          result: { zone, removed: kv.removed === "yes" },
        };
      },
    },

    get_ds: {
      description:
        "READ-ONLY. Read the DS records for a signed zone's current KSK(s) and persist them for submission to the parent. Never returns private key material.",
      arguments: ZoneOnlyArgs,
      execute: async (args: z.input<typeof ZoneOnlyArgs>, context: Ctx) => {
        const a = ZoneOnlyArgs.parse(args);
        const zone = normalizeApex(a.zone);
        const target = await sshTarget(context, a.ssh);
        const res = await sshExec(deps, target, [
          "sh",
          "-c",
          getDsScript(zone),
        ]);
        if (res.exit_code !== 0) {
          throw mapScriptError(res.stderr, res.exit_code);
        }
        const ds = parseDsLines(res.stdout);
        const handle = await context.writeResource(
          "ds",
          await instanceName(["ds", a.ssh.host, zone]),
          {
            host: a.ssh.host,
            zone,
            ds,
            observed_at: new Date().toISOString(),
          },
        );
        return { dataHandles: [handle], result: { zone, ds } };
      },
    },

    ksk_submitted: {
      kind: "action" as const,
      description:
        "DESTRUCTIVE. Tell Knot the zone's KSK DS has been submitted to the parent (knotc zone-ksk-submitted). Idempotent. Refuses a zone that is not present.",
      arguments: ZoneOnlyArgs,
      execute: async (args: z.input<typeof ZoneOnlyArgs>, context: Ctx) => {
        const a = ZoneOnlyArgs.parse(args);
        const zone = normalizeApex(a.zone);
        const target = await sshTarget(context, a.ssh);
        const res = await sshExec(deps, target, [
          "sh",
          "-c",
          kskSubmittedScript(zone),
        ]);
        if (res.exit_code !== 0) {
          throw mapScriptError(res.stderr, res.exit_code);
        }
        return { result: { zone, submitted: true } };
      },
    },

    ...resolverMethods,

    get: {
      description:
        "READ-ONLY. Observe the host: each managed zone's served records diffed against its recorded declaration, its DNSSEC key states, and the resolver service. Persists the observation only after every probe succeeds.",
      arguments: SshOnlyArgs,
      execute: async (args: z.input<typeof SshOnlyArgs>, context: Ctx) => {
        const a = SshOnlyArgs.parse(args);
        return await observe(context, a, true);
      },
    },

    sync: {
      description:
        "READ-ONLY. Reconcile the recorded state with the host and report drift (a changed zone file, missing or extra served records, an inactive resolver). Persists the observation only after every probe succeeds.",
      arguments: SshOnlyArgs,
      execute: async (args: z.input<typeof SshOnlyArgs>, context: Ctx) => {
        const a = SshOnlyArgs.parse(args);
        return await observe(context, a, false);
      },
    },
  },
};
