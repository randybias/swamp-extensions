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
  denoDeps,
  exec as sshExec,
  HOST_RE,
  sha256Hex,
  type SshDeps,
  type SshTarget,
  upload as sshUpload,
  USER_RE,
} from "./_lib/ssh.ts";
import { KnotError, resolveSecret } from "./_lib/vault.ts";
import {
  applyResolverScript,
  applyZoneScript,
  between,
  discoverZonesScript,
  finalizeZoneScript,
  getDsScript,
  installScript,
  observeScript,
  parseKeyValues,
  parseServed,
  portCheckScript,
  removeResolverScript,
  removeZoneScript,
  resolverObserveScript,
  restoreZoneScript,
  STAGED_LISTEN,
  zonePaths,
} from "./_lib/scripts.ts";
import { parseDsLines } from "./_lib/parse.ts";
import { renderResolverYaml, ResolverSchema } from "./_lib/resolver.ts";
import {
  canonicalRecords,
  declaredTuples,
  diffDeclared,
  type DiffEntry,
  DnssecSchema,
  FqdnSchema,
  isApex,
  normalizeApex,
  noSignerOwned,
  RefusedRecordSchema,
  renderZoneConfig,
  renderZoneFile,
  SoaSchema,
  type ZoneRecord,
} from "./_lib/zone.ts";

/** Cap on captured remote output. */
const MAX_OUTPUT_BYTES = 16 * 1024 * 1024;
/** Live resolver configuration path. */
const RESOLVER_YAML = "/etc/knot-resolver/config.yaml";
/** Staged resolver configuration path. */
const RESOLVER_YAML_STAGED = "/etc/knot-resolver/.config.yaml.staged";
/** Backup of the package's resolver configuration. */
const RESOLVER_PACKAGE_BACKUP = "/etc/knot-resolver/config.yaml.package";

const SshShape = {
  ssh: z.strictObject({
    host: z.string().regex(HOST_RE).max(253).describe(
      "Hostname or IP literal of the target.",
    ),
    port: z.number().int().min(1).max(65535).default(22).describe("SSH port."),
    user: z.string().regex(USER_RE).describe("Remote user name."),
    host_key_policy: z.literal("strict").describe(
      "Required; only strict is supported, with host_keys pinned.",
    ),
    host_keys: z.array(z.string().max(8192)).min(1).max(64).describe(
      "ssh-keyscan-format host keys the server must present.",
    ),
    ssh_key_ref: z.strictObject({
      vault: z.string().min(1).max(128).describe("Vault instance name."),
      key: z.string().min(1).max(128).describe("Key inside the vault."),
    }).describe("Vault reference to the SSH private key; resolved in-model."),
    connect_timeout_s: z.number().int().min(1).max(120).default(15).describe(
      "Connection timeout in seconds.",
    ),
  }),
};

const TsigKeySchema = z.strictObject({
  name: z.string().min(1).max(128).refine(
    (s) => /^[A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?$/.test(s),
    "invalid TSIG key name",
  ),
  algorithm: z.enum(["hmac-sha256", "hmac-sha512"]),
  secret_ref: z.strictObject({
    vault: z.string().min(1).max(128),
    key: z.string().min(1).max(128),
  }),
});

const ListenSchema = z.string().min(1).max(64).refine(
  (s) =>
    /^(\d{1,3}\.){3}\d{1,3}(@\d{1,5})?$/.test(s) ||
    /^[0-9a-fA-F:]+(@\d{1,5})?$/.test(s),
  "listen must be ADDR or ADDR@port",
);

const ZoneShape = {
  ...SshShape,
  zone: z.string().min(1).max(253).refine(isApex, "invalid zone apex"),
  soa: SoaSchema,
  ns: z.array(FqdnSchema).min(1).max(8),
  records: z.array(RefusedRecordSchema).max(5000).default([]).refine(
    noSignerOwned,
    "the signer owns DNSKEY, RRSIG, NSEC, NSEC3, NSEC3PARAM, CDS, CDNSKEY and SOA records; they are not valid input",
  ),
  dnssec: z.union([z.literal("off"), DnssecSchema]).default("off"),
  listen: z.array(ListenSchema).min(1).max(16).default(["0.0.0.0"]),
  listen_any_ack: z.boolean().default(false).describe(
    "Acknowledge binding a wildcard address (0.0.0.0/::).",
  ),
  notify_secondaries: z.array(z.string().min(1).max(64)).max(64).default([]),
  allow_transfer: z.array(z.string().min(1).max(64)).max(64).default([]),
  tsig_keys: z.array(TsigKeySchema).max(16).default([]),
};

const InstallArgs = z.strictObject({
  ...SshShape,
  resolver: z.boolean().default(false),
});
const ZoneArgs = z.strictObject(ZoneShape);
const ApplyZoneArgs = z.strictObject({
  ...ZoneShape,
  dnssec_unsign_ack: z.boolean().default(false).describe(
    "Acknowledge turning a signed zone unsigned; refused otherwise.",
  ),
});
const ZoneOnlyArgs = z.strictObject({
  ...SshShape,
  zone: z.string().min(1).max(253).refine(isApex, "invalid zone apex"),
});
const RemoveZoneArgs = z.strictObject({
  ...SshShape,
  zone: z.string().min(1).max(253).refine(isApex, "invalid zone apex"),
  dnssec_unsign_ack: z.boolean().default(false),
  purge_keys_ack: z.boolean().default(false),
});
const SshOnlyArgs = z.strictObject(SshShape);
const RemoveResolverArgs = z.strictObject({
  ...SshShape,
  remove_ack: z.boolean().default(false).describe(
    "Acknowledge removing a resolver this model did not apply.",
  ),
});
const ApplyResolverArgs = z.strictObject({
  ...SshShape,
  resolver: ResolverSchema,
});

const StateZoneSchema = z.strictObject({
  host: z.string(),
  apex: z.string(),
  status: z.enum(["rendered", "applied", "removed"]),
  rendered_sha256: z.string(),
  record_count: z.number().int(),
  dnssec: z.boolean(),
  served_serial: z.string().optional(),
  applied_at: z.string().optional(),
  declared: z.array(z.string()).optional(),
  listen: z.array(z.string()).optional(),
});

const StateResolverSchema = z.strictObject({
  host: z.string(),
  status: z.enum(["applied", "removed"]),
  rendered_sha256: z.string(),
  listen: z.array(z.string()),
  forwards: z.array(z.string()),
  applied_at: z.string().optional(),
});

const ObservationSchema = z.strictObject({
  host: z.string(),
  zones: z.array(z.object({
    apex: z.string(),
    served_serial: z.string().optional(),
    file_sha256: z.string().optional(),
    drift: z.boolean(),
    added: z.array(z.string()),
    removed: z.array(z.string()),
    key_states: z.array(z.string()),
  })),
  resolver_active: z.string().optional(),
  observed_at: z.string(),
});

const DsSchema = z.strictObject({
  host: z.string(),
  zone: z.string(),
  ds: z.array(z.string()),
  observed_at: z.string(),
});

// deno-lint-ignore no-explicit-any
type Ctx = any;

let deps: SshDeps = denoDeps;

/** Replaces the injected transport dependencies (tests only). */
export function setDeps(d: Partial<SshDeps>): SshDeps {
  const prev = deps;
  deps = { ...deps, ...d };
  return prev;
}

type SshInput = z.infer<typeof SshOnlyArgs>["ssh"];

async function sshTarget(context: Ctx, ssh: SshInput): Promise<SshTarget> {
  const key = await resolveSecret(context.vaultService, ssh.ssh_key_ref);
  return {
    host: ssh.host,
    port: ssh.port,
    user: ssh.user,
    host_key_policy: "strict",
    host_keys: ssh.host_keys,
    private_key: key,
    connect_timeout_s: ssh.connect_timeout_s,
    max_output_bytes: MAX_OUTPUT_BYTES,
  };
}

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

/** Instance name for a set of identity parts; kind keeps resources distinct. */
export async function instanceName(parts: string[]): Promise<string> {
  const digest = (await sha256Hex(parts.join("\0"))).slice(0, 16);
  return `knot_${digest}`;
}

function mapScriptError(stderr: string, exit: number): KnotError {
  if (stderr.includes("INCLUDE_MISSING")) {
    return new KnotError(
      "invalid_input",
      "knot.conf does not include /etc/knot/knot.conf.d/*.conf; run install first",
    );
  }
  if (stderr.includes("STAGE_MISSING")) {
    return new KnotError("invalid_input", "staged files are missing");
  }
  if (stderr.includes("KZONECHECK_FAILED")) {
    return new KnotError("tool_failed", "kzonecheck rejected the zone");
  }
  if (stderr.includes("CONFCHECK_FAILED")) {
    return new KnotError("tool_failed", "knotc conf-check rejected the config");
  }
  if (stderr.includes("RELOAD_FAILED")) {
    return new KnotError(
      "reload_failed",
      "reload failed; the previous configuration was restored",
    );
  }
  if (stderr.includes("KRESCTL_FAILED")) {
    return new KnotError("tool_failed", "kresctl validate rejected the config");
  }
  if (stderr.includes("TEST_QUERY_FAILED")) {
    return new KnotError("verify_failed", "the resolver test query failed");
  }
  if (stderr.includes("DNSSEC_UNSIGN_ACK_REQUIRED")) {
    return new KnotError(
      "invalid_input",
      "the zone is signed; pass dnssec_unsign_ack to remove it",
    );
  }
  if (stderr.includes("STOP_FAILED")) {
    return new KnotError("reload_failed", "could not stop the resolver");
  }
  if (stderr.includes("CHOWN_FAILED")) {
    return new KnotError(
      "tool_failed",
      "could not set root:knot ownership on a managed file",
    );
  }
  if (stderr.includes("RESTORE_RELOAD_FAILED")) {
    return new KnotError(
      "reload_failed",
      "the rollback reload failed; the backup was not removed",
    );
  }
  if (stderr.includes("PROBE_FAILED")) {
    return new KnotError("tool_failed", "a live probe failed");
  }
  if (stderr.includes("NO_BACKUP")) {
    return new KnotError("reload_failed", "the backup directory is missing");
  }
  return new KnotError("tool_failed", `remote command failed (exit ${exit})`);
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

/** Normalizes `addr` or `addr@port` to host and port for comparison. */
function listenPort(addr: string): { host: string; port: string } {
  const at = addr.indexOf("@");
  return at === -1
    ? { host: addr, port: "53" }
    : { host: addr.slice(0, at), port: addr.slice(at + 1) };
}

/** Returns the overlapping pair when the two listen sets can share a socket. */
function listenOverlap(
  a: string[],
  b: string[] | undefined,
): string | undefined {
  for (const x of a) {
    for (const y of b ?? []) {
      const lx = listenPort(x);
      const ly = listenPort(y);
      if (lx.port !== ly.port) continue;
      const wild = (h: string) => h === "0.0.0.0" || h === "::";
      if (lx.host === ly.host || wild(lx.host) || wild(ly.host)) {
        return `${x} and ${y}`;
      }
    }
  }
  return undefined;
}

/** Enforces wildcard and authoritative/resolver disjointness preconditions. */
function assertListenAcceptable(
  a: { listen: string[]; listen_any_ack: boolean },
  resolverListen: string[] | undefined,
): void {
  for (const addr of a.listen) {
    const host = listenPort(addr).host;
    if ((host === "0.0.0.0" || host === "::") && !a.listen_any_ack) {
      throw new KnotError(
        "invalid_input",
        "a wildcard listen address needs listen_any_ack",
      );
    }
  }
  const overlap = listenOverlap(a.listen, resolverListen);
  if (overlap !== undefined) {
    throw new KnotError(
      "invalid_input",
      `the authoritative and resolver listen sets overlap at ${overlap}`,
    );
  }
}

/** Precheck that port 53 is not held by something other than Knot. */
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

async function observe(
  context: Ctx,
  a: z.infer<typeof SshOnlyArgs>,
  verbose: boolean,
) {
  const target = await sshTarget(context, a.ssh);
  const disc = await sshExec(deps, target, ["sh", "-c", discoverZonesScript()]);
  if (disc.exit_code !== 0) throw mapScriptError(disc.stderr, disc.exit_code);
  const apexes = disc.stdout.split("\n").map((l) => l.trim()).filter((l) =>
    l.endsWith(".")
  );
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
  version: "2026.10.17.1",
  description:
    "Manage authoritative Knot DNS zones and a Knot Resolver 6 recursive resolver over SSH, validating every candidate with the vendor tools before it reaches the service.",
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
          throw new KnotError("tool_failed", "install failed");
        }
        const kv = parseKeyValues(res.stdout);
        return {
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
        // The authoritative listen is host-global: use the union of every
        // recorded zone's listens on this host plus this zone's.
        const union = new Set<string>(a.listen);
        try {
          const records = await context.readModelData?.(
            context.definition?.name,
            "zone",
          ) ?? [];
          for (const r of records) {
            const attrs =
              (r as { attributes?: { host?: string; listen?: string[] } })
                .attributes;
            if (attrs?.host === a.ssh.host && Array.isArray(attrs.listen)) {
              attrs.listen.forEach((x) => union.add(x));
            }
          }
        } catch {
          // readModelData is unavailable (for example in a unit test); use
          // this zone's listens only.
        }
        const listens = [...union].sort();
        await assertPortsFree(target, listens);
        const listenContent = listens.length === 0
          ? ""
          : `server:\n  listen: [${
            listens.map((x) => JSON.stringify(x)).join(", ")
          }]\n`;
        await sshUpload(deps, target, {
          path: STAGED_LISTEN,
          content: listenContent,
          mode: "0644",
        });
        // Upload the staged TSIG fragment every time, empty when there are no
        // keys, so a removed key is actually removed and a stale staged file
        // from a failed run cannot be installed later.
        await sshUpload(deps, target, {
          path: zonePaths(zone).stagedTsig,
          content: a.tsig_keys.length > 0
            ? await renderTsigFragment(context, a.tsig_keys)
            : "",
          mode: "0640",
        });
        await sshUpload(deps, target, {
          path: zonePaths(zone).stagedZone,
          content: file,
          mode: "0640",
        });
        await sshUpload(deps, target, {
          path: zonePaths(zone).stagedFragment,
          content: fragment,
          mode: "0644",
        });
        const res = await sshExec(deps, target, [
          "sh",
          "-c",
          applyZoneScript({ apex: zone }),
        ]);
        if (res.exit_code !== 0) {
          throw mapScriptError(res.stderr, res.exit_code);
        }
        const kv = parseKeyValues(res.stdout);
        const backup = kv.backup ?? "";
        const served = parseServed(res.stdout, zone);
        const expected = declaredTuples(zone, a.soa, all);
        const diff = diffDeclared(expected, served);
        if (diff.added.length > 0 || diff.removed.length > 0) {
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
          listen: listens,
        });
        return {
          dataHandles: [handle],
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
        "DESTRUCTIVE. Stop serving one managed zone and remove its zone file, config fragment and TSIG fragment. A signed zone is refused unless dnssec_unsign_ack is set; with purge_keys_ack the journal is purged. A second call is a no-op.",
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
        const res = await sshExec(deps, target, [
          "sh",
          "-c",
          removeZoneScript({
            apex: zone,
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
        return {
          dataHandles: [handle],
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
          `[ -f ${
            JSON.stringify(zonePaths(zone).fragment)
          } ] || { echo ZONE_ABSENT >&2; exit 3; }\n` +
          `knotc -b zone-ksk-submitted ${JSON.stringify(zone)} >/dev/null\n` +
          "echo submitted=yes",
        ]);
        if (res.exit_code !== 0) {
          throw mapScriptError(res.stderr, res.exit_code);
        }
        return { result: { zone, submitted: true } };
      },
    },

    render_resolver: {
      description:
        "READ-ONLY. Render the Knot Resolver 6 config.yaml and its sha256 without touching any host.",
      arguments: ApplyResolverArgs,
      execute: async (
        args: z.input<typeof ApplyResolverArgs>,
        _context: Ctx,
      ) => {
        const a = ApplyResolverArgs.parse(args);
        const yaml = renderResolverYaml(a.resolver);
        return { result: { yaml, sha256: await sha256Hex(yaml) } };
      },
    },

    apply_resolver: {
      kind: "action" as const,
      description:
        "DESTRUCTIVE. Validate with kresctl, back up the package config, atomically swap the resolver config.yaml, reload and verify a test query, restoring the previous config on failure. Idempotent: an unchanged render is a no-op.",
      arguments: ApplyResolverArgs,
      execute: async (
        args: z.input<typeof ApplyResolverArgs>,
        context: Ctx,
      ) => {
        const a = ApplyResolverArgs.parse(args);
        const yaml = renderResolverYaml(a.resolver);
        const sha = await sha256Hex(yaml);
        const target = await sshTarget(context, a.ssh);
        await sshUpload(deps, target, {
          path: RESOLVER_YAML_STAGED,
          content: yaml,
          mode: "0644",
        });
        const res = await sshExec(deps, target, [
          "sh",
          "-c",
          applyResolverScript({
            liveYaml: RESOLVER_YAML,
            packageBackup: RESOLVER_PACKAGE_BACKUP,
            stagedYaml: RESOLVER_YAML_STAGED,
            testListen: a.resolver.listen[0].split("@")[0],
            testName: ".",
          }),
        ]);
        if (res.exit_code !== 0) {
          throw mapScriptError(res.stderr, res.exit_code);
        }
        const kv = parseKeyValues(res.stdout);
        const handle = await context.writeResource(
          "resolver",
          await instanceName(["resolver", a.ssh.host]),
          {
            host: a.ssh.host,
            status: "applied",
            rendered_sha256: sha,
            listen: a.resolver.listen,
            forwards: a.resolver.forwards.map((f) => f.subtree),
            applied_at: new Date().toISOString(),
          },
        );
        return {
          dataHandles: [handle],
          result: {
            host: a.ssh.host,
            changed: kv.changed === "yes",
            listen: a.resolver.listen,
            forwards: a.resolver.forwards.map((f) => f.subtree),
          },
        };
      },
    },

    remove_resolver: {
      kind: "action" as const,
      description:
        "DESTRUCTIVE. Stop and disable the recursive resolver, restore the package configuration, and fail if the service cannot be stopped. Refuses a host whose resolver this model did not apply unless remove_ack is set.",
      arguments: RemoveResolverArgs,
      execute: async (
        args: z.input<typeof RemoveResolverArgs>,
        context: Ctx,
      ) => {
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
        if (res.exit_code !== 0) {
          throw mapScriptError(res.stderr, res.exit_code);
        }
        const kv = parseKeyValues(res.stdout);
        const handle = await context.writeResource(
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
        return {
          dataHandles: [handle],
          result: { removed: kv.removed === "yes" },
        };
      },
    },

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
