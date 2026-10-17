/**
 * Swamp extension model for managing libvirt/KVM on a host over SSH: virtual
 * networks (define/undefine, including removing the `default` network),
 * storage volumes (including cloning a golden volume or zvol per node),
 * domains (define from a cloned volume, power, serial console), all through
 * `virsh -c <uri>`.
 *
 * One definition manages any hypervisor: the SSH target, the libvirt URI and
 * every operand are method arguments, so the type names no particular host.
 * State is keyed by the canonical `{host, port, user}` plus the resource name.
 * The SSH private key is a sensitive argument delivered to the remote only via
 * stdin/agent, never remote argv.
 *
 * @module
 */

import { z } from "npm:zod@4.3.6";
import {
  denoDeps,
  exec,
  type ExecResult,
  sha256Hex,
  type SshDeps,
  type SshTarget,
} from "./_lib/ssh.ts";
import {
  assertName,
  assertUri,
  DISK_FORMATS,
  IPV4_ADDRESS_RE,
  LibvirtConfigError,
  MAC_ADDRESS_RE,
  NAME_RE,
  NETWORK_MODES,
  URI_RE,
} from "./_lib/validate.ts";
import {
  domainState,
  isOffState,
  isPausedState,
  isRunningState,
  memoryMib,
  networkProjection,
  parseKeyValues,
  parseNameList,
  parseVolList,
  renderDomainXml,
  renderNetworkXml,
} from "./_lib/xml.ts";
import {
  consoleArgv,
  isBenign,
  LibvirtError,
  removeFile,
  uploadXml,
  virsh,
  virshTry,
} from "./_lib/virsh.ts";

/** The model's dependencies: the vendored SSH transport plus a token source. */
export interface LibvirtDeps extends SshDeps {
  /** Returns a fresh token for a remote temporary XML file. */
  token: () => string;
}

function randomToken(): string {
  const bytes = new Uint8Array(8);
  crypto.getRandomValues(bytes);
  return [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
}

/** Production dependencies: the SSH transport, clock and token source. */
export const denoLibvirtDeps: LibvirtDeps = { ...denoDeps, token: randomToken };

const GlobalArgsSchema = z.strictObject({});

const HostKeyPolicy = z.enum(["strict", "insecure_tofu"]).describe(
  "strict trusts only host_keys; insecure_tofu trusts whatever key the host presents on first contact",
);

const SshFields = {
  host: z.string().min(1).max(255).describe("Hypervisor hostname or IP"),
  port: z.number().int().min(1).max(65535).default(22).describe("SSH port"),
  user: z.string().min(1).max(32).describe("SSH login name"),
  host_key_policy: HostKeyPolicy,
  host_keys: z.array(z.string().max(2048)).max(16).optional().describe(
    "Pinned host keys in ssh-keyscan format; required for strict",
  ),
  private_key: z.string().min(1).meta({ sensitive: true }).describe(
    "Private key in PEM or OpenSSH format; pass a vault reference",
  ),
  connect_timeout_s: z.number().int().min(1).max(120).default(15).describe(
    "Seconds to wait for the connection, 1-120",
  ),
  max_output_bytes: z.number().int().min(1).max(104857600).default(10485760)
    .describe(
      "Cap in bytes on captured stdout and stderr, 1-104857600",
    ),
};

const UriField = z.string().min(1).max(240).regex(URI_RE).describe(
  "libvirt connection URI, e.g. qemu:///system",
);
const NameField = z.string().min(1).max(63).regex(NAME_RE);

const NetworkFields = {
  name: NameField.describe("Network name"),
  xml: z.string().min(1).max(262144).optional().describe(
    "Full network XML; give this or the structured fields, not both",
  ),
  mode: z.enum(NETWORK_MODES).optional().describe(
    "Forward mode for a structured network",
  ),
  bridge: z.string().min(1).max(63).regex(NAME_RE).optional().describe(
    "Bridge device name",
  ),
  gateway: z.string().min(1).max(15).regex(IPV4_ADDRESS_RE).optional().describe(
    "Gateway address for the network IP block",
  ),
  prefix: z.number().int().min(1).max(32).optional().describe(
    "Prefix length for the gateway block",
  ),
  dhcp_start: z.string().min(1).max(15).regex(IPV4_ADDRESS_RE).optional()
    .describe("DHCP range start"),
  dhcp_end: z.string().min(1).max(15).regex(IPV4_ADDRESS_RE).optional()
    .describe("DHCP range end"),
  dns_domain: z.string().min(1).max(253).optional().describe(
    "DNS domain served by the DHCP block",
  ),
  start: z.boolean().default(true).describe(
    "Activate the network after define",
  ),
  autostart: z.boolean().default(true).describe(
    "Autostart the network on host boot",
  ),
  replace: z.boolean().default(false).describe(
    "Replace an existing network when the config differs (structured) or always (raw XML)",
  ),
};

const DefineNetworkArgs = z.strictObject({
  ...SshFields,
  uri: UriField,
  ...NetworkFields,
});

const UndefineNetworkArgs = z.strictObject({
  ...SshFields,
  uri: UriField,
  name: NameField.describe("Network to stop and undefine"),
});

const CloneVolumeArgs = z.strictObject({
  ...SshFields,
  uri: UriField,
  pool: NameField.describe("Storage pool holding the golden volume"),
  source_volume: NameField.describe("Golden volume or zvol to clone"),
  target_volume: NameField.describe("New volume name"),
  format: z.enum(DISK_FORMATS).optional().describe(
    "Expected target format; recorded with the state",
  ),
});

const DefineDomainArgs = z.strictObject({
  ...SshFields,
  uri: UriField,
  name: NameField.describe("Domain name"),
  pool: NameField.describe("Pool holding the backing volume"),
  volume: NameField.describe("Volume the domain boots from (usually a clone)"),
  vcpus: z.number().int().min(1).max(255).describe("Virtual CPU count"),
  memory_mib: z.number().int().min(128).max(1048576).describe(
    "Memory in MiB",
  ),
  format: z.enum(DISK_FORMATS).default("qcow2").describe("Disk driver format"),
  arch: z.string().min(1).max(32).default("x86_64").describe("Guest arch"),
  network: z.string().min(1).max(63).regex(NAME_RE).optional().describe(
    "libvirt network to attach",
  ),
  bridge: z.string().min(1).max(63).regex(NAME_RE).optional().describe(
    "Host bridge to attach instead of a network",
  ),
  mac: z.string().min(17).max(17).regex(MAC_ADDRESS_RE).optional().describe(
    "Fixed MAC address",
  ),
  start: z.boolean().default(false).describe("Start the domain after define"),
  replace: z.boolean().default(false).describe(
    "Destroy and redefine an existing domain",
  ),
});

const PowerAction = z.enum([
  "start",
  "shutdown",
  "destroy",
  "reboot",
  "suspend",
  "resume",
]).describe("Power action; destroy is immediate and loses guest state");

const PowerArgs = z.strictObject({
  ...SshFields,
  uri: UriField,
  name: NameField.describe("Domain name"),
  action: PowerAction,
});

const ConsoleArgs = z.strictObject({
  ...SshFields,
  uri: UriField,
  name: NameField.describe("Domain name"),
  timeout_s: z.number().int().min(1).max(300).default(15).describe(
    "Seconds to capture before disconnecting, 1-300",
  ),
  devname: z.string().min(1).max(63).optional().describe(
    "Console device name, when the domain has more than one",
  ),
});

const UndefineDomainArgs = z.strictObject({
  ...SshFields,
  uri: UriField,
  name: NameField.describe("Domain to destroy and undefine"),
  remove_volumes: z.boolean().default(false).describe(
    "Also remove the domain's managed volumes (virsh undefine --remove-all-storage)",
  ),
});

const GetArgs = z.strictObject({
  ...SshFields,
  uri: UriField,
  network: z.string().min(1).max(63).regex(NAME_RE).optional().describe(
    "Report only this network",
  ),
  domain: z.string().min(1).max(63).regex(NAME_RE).optional().describe(
    "Report only this domain",
  ),
  pool: z.string().min(1).max(63).regex(NAME_RE).optional().describe(
    "Also list the volumes in this pool",
  ),
});

const NetworkStateSchema = z.strictObject({
  target: z.string(),
  name: z.string(),
  present: z.boolean(),
  uuid: z.string().optional(),
  active: z.boolean().optional(),
  autostart: z.boolean().optional(),
  config_sha256: z.string().optional(),
  observed_at: z.string(),
});

const VolumeStateSchema = z.strictObject({
  target: z.string(),
  pool: z.string(),
  name: z.string(),
  present: z.boolean(),
  path: z.string().optional(),
  capacity: z.string().optional(),
  allocation: z.string().optional(),
  format: z.string().optional(),
  observed_at: z.string(),
});

const DomainStateSchema = z.strictObject({
  target: z.string(),
  name: z.string(),
  present: z.boolean(),
  uuid: z.string().optional(),
  state: z.string().optional(),
  vcpus: z.number().int().optional(),
  memory_mib: z.number().int().optional(),
  observed_at: z.string(),
});

const ConsoleStateSchema = z.strictObject({
  target: z.string(),
  domain: z.string(),
  text: z.string().meta({ sensitive: true }).describe(
    "Captured serial console text; may carry boot or login secrets",
  ),
  bytes: z.number().int(),
  observed_at: z.string(),
});

const NetSummary = z.strictObject({
  name: z.string(),
  active: z.boolean(),
  autostart: z.boolean(),
});

const DomainSummary = z.strictObject({
  name: z.string(),
  state: z.string(),
  uuid: z.string(),
});

const VolSummary = z.strictObject({
  pool: z.string(),
  name: z.string(),
  path: z.string(),
});

const HostStateSchema = z.strictObject({
  target: z.string(),
  networks: z.array(NetSummary),
  domains: z.array(DomainSummary),
  volumes: z.array(VolSummary),
  observed_at: z.string(),
});

/** Stored network state for one target. */
export type NetworkState = z.infer<typeof NetworkStateSchema>;
/** Stored domain state for one target. */
export type DomainState = z.infer<typeof DomainStateSchema>;
/** Stored host inventory for one target. */
export type HostState = z.infer<typeof HostStateSchema>;

type Ctx = {
  logger: {
    info(msg: string, ...args: unknown[]): void;
    warning(msg: string, ...args: unknown[]): void;
  };
  writeResource: (
    spec: string,
    name: string,
    data: Record<string, unknown>,
  ) => Promise<{ name: string }>;
  readResource: (
    name: string,
    version?: number,
  ) => Promise<Record<string, unknown> | null>;
};

const TARGET_KEY_RE = /[^A-Za-z0-9._-]/g;

/** The canonical `{host, port, user}` key for a target. */
export function targetKey(a: {
  host: string;
  port: number;
  user: string;
}): string {
  return `${a.user}@${a.host}:${a.port}`;
}

/** A swamp data instance name for one resource on one target. */
export function instanceName(
  kind: string,
  a: { host: string; port: number; user: string },
  ...parts: string[]
): string {
  const key = targetKey(a).replace(TARGET_KEY_RE, "_");
  const tail = parts.length > 0
    ? `-${parts.join("-").replace(TARGET_KEY_RE, "_")}`
    : "";
  return `${kind}-${key}${tail}`;
}

function targetOf(a: {
  host: string;
  port: number;
  user: string;
  host_key_policy: "strict" | "insecure_tofu";
  host_keys?: string[];
  private_key: string;
  connect_timeout_s: number;
  max_output_bytes: number;
}): SshTarget {
  return {
    host: a.host,
    port: a.port,
    user: a.user,
    host_key_policy: a.host_key_policy,
    host_keys: a.host_keys,
    private_key: a.private_key,
    connect_timeout_s: a.connect_timeout_s,
    max_output_bytes: a.max_output_bytes,
  };
}

function yesNo(value: string | undefined): boolean {
  return value !== undefined && /^yes$/i.test(value);
}

const BENIGN = {
  start: [/already (active|running)/i, /domain is already running/i],
  shutdown: [/already shut ?off/i, /domain is not running/i, /not running/i],
  destroy: [/domain is not running/i, /not running/i],
  suspend: [/already (suspended|paused)/i, /not running/i],
  resume: [/not paused/i, /already running/i],
  netStart: [/network is already active/i, /already active/i],
  netDestroy: [/network is not active/i, /not active/i],
  define: [/already exists/i],
  clone: [/already exists/i],
};

/** Defines an object from XML uploaded to a temporary remote file. */
async function defineFromXml(
  deps: LibvirtDeps,
  t: SshTarget,
  uri: string,
  kind: "net-define" | "define",
  xml: string,
): Promise<void> {
  const path = await uploadXml(deps, t, deps.token(), xml);
  try {
    const res = await virshTry(deps, t, uri, [kind, path]);
    if (res.exit_code !== 0 && !isBenign(res, BENIGN.define)) {
      throw new LibvirtError(
        `virsh ${kind} failed (exit ${res.exit_code}): ${
          `${res.stderr || res.stdout}`.trim().slice(0, 300)
        }`,
      );
    }
  } finally {
    await removeFile(deps, t, path);
  }
}

async function networkInfo(
  deps: LibvirtDeps,
  t: SshTarget,
  uri: string,
  name: string,
): Promise<
  { present: boolean; active: boolean; autostart: boolean; uuid: string }
> {
  const res = await virshTry(deps, t, uri, ["net-info", name]);
  if (res.exit_code !== 0) {
    return { present: false, active: false, autostart: false, uuid: "" };
  }
  const kv = parseKeyValues(res.stdout);
  return {
    present: true,
    active: yesNo(kv["active"]),
    autostart: yesNo(kv["autostart"]),
    uuid: kv["uuid"] ?? "",
  };
}

async function domainInfo(
  deps: LibvirtDeps,
  t: SshTarget,
  uri: string,
  name: string,
): Promise<Record<string, string>> {
  const res = await virshTry(deps, t, uri, ["dominfo", name]);
  if (res.exit_code !== 0) return {};
  return parseKeyValues(res.stdout);
}

async function volumePresent(
  deps: LibvirtDeps,
  t: SshTarget,
  uri: string,
  pool: string,
  name: string,
): Promise<boolean> {
  const res = await virshTry(deps, t, uri, [
    "vol-info",
    "--pool",
    pool,
    "--",
    name,
  ]);
  return res.exit_code === 0;
}

function buildNetworkSpec(args: {
  name: string;
  mode?: (typeof NETWORK_MODES)[number];
  bridge?: string;
  gateway?: string;
  prefix?: number;
  dhcp_start?: string;
  dhcp_end?: string;
  dns_domain?: string;
}): Parameters<typeof renderNetworkXml>[0] {
  if (args.mode === undefined) {
    throw new LibvirtConfigError(
      "give either raw xml or a structured network mode",
    );
  }
  if ((args.dhcp_start === undefined) !== (args.dhcp_end === undefined)) {
    throw new LibvirtConfigError("give dhcp_start and dhcp_end together");
  }
  return {
    name: args.name,
    mode: args.mode,
    bridge: args.bridge,
    gateway: args.gateway,
    prefix: args.prefix,
    dhcpStart: args.dhcp_start,
    dhcpEnd: args.dhcp_end,
    domain: args.dns_domain,
  };
}

/** Builds the model with overridable dependencies (spawner, clock, token). */
export function createModel(overrides: Partial<LibvirtDeps> = {}) {
  const deps: LibvirtDeps = { ...denoLibvirtDeps, ...overrides };
  return {
    type: "@randybias/libvirt",
    version: "2026.10.17.1",
    description:
      "Manage libvirt/KVM over SSH: define and undefine virtual networks including the default, clone a golden volume or zvol per node, define domains from a clone, control power, and capture the serial console. One generic model with no host in its definition.",
    upgrades: [],
    globalArguments: GlobalArgsSchema,
    resources: {
      network_state: {
        description: "Recorded state of one libvirt network",
        schema: NetworkStateSchema,
        lifetime: "infinite" as const,
        garbageCollection: 10,
      },
      volume_state: {
        description: "Recorded state of one libvirt storage volume",
        schema: VolumeStateSchema,
        lifetime: "infinite" as const,
        garbageCollection: 10,
      },
      domain_state: {
        description: "Recorded state of one libvirt domain",
        schema: DomainStateSchema,
        lifetime: "infinite" as const,
        garbageCollection: 10,
      },
      console_capture: {
        description: "Bounded serial console capture for one domain",
        schema: ConsoleStateSchema,
        lifetime: "1d" as const,
        garbageCollection: 5,
      },
      host_state: {
        description: "Inventory of networks, domains and pool volumes",
        schema: HostStateSchema,
        lifetime: "1d" as const,
        garbageCollection: 5,
      },
    },
    methods: {
      define_network: {
        description:
          "Idempotent. Define a network from raw XML or structured inputs, then start and autostart it as asked. A structured network whose projection already matches is a no-op; a differing one is replaced only when replace is true.",
        kind: "action" as const,
        arguments: DefineNetworkArgs,
        execute: async (
          args: z.infer<typeof DefineNetworkArgs>,
          context: Ctx,
        ) => {
          assertName(args.name, "network name");
          assertUri(args.uri);
          if (args.xml !== undefined && args.mode !== undefined) {
            throw new LibvirtConfigError(
              "give either xml or mode, not both",
            );
          }
          const xml = args.xml ?? renderNetworkXml(buildNetworkSpec(args));
          const t = targetOf(args);
          const before = await networkInfo(deps, t, args.uri, args.name);
          let changed = false;
          if (before.present) {
            let redefine = args.replace;
            if (!redefine && args.xml === undefined) {
              const dump = await virsh(deps, t, args.uri, [
                "net-dumpxml",
                args.name,
              ]);
              redefine = networkProjection(dump.stdout) !==
                networkProjection(xml);
            }
            if (redefine) {
              if (before.active) {
                const stop = await virshTry(deps, t, args.uri, [
                  "net-destroy",
                  args.name,
                ]);
                if (
                  stop.exit_code !== 0 && !isBenign(stop, BENIGN.netDestroy)
                ) {
                  throw new LibvirtError(
                    `could not stop network ${args.name} before redefining it`,
                  );
                }
              }
              await virsh(deps, t, args.uri, ["net-undefine", args.name]);
              await defineFromXml(deps, t, args.uri, "net-define", xml);
              changed = true;
            }
          } else {
            await defineFromXml(deps, t, args.uri, "net-define", xml);
            changed = true;
          }
          let after = await networkInfo(deps, t, args.uri, args.name);
          if (args.start && !after.active) {
            const start = await virshTry(deps, t, args.uri, [
              "net-start",
              args.name,
            ]);
            if (start.exit_code !== 0 && !isBenign(start, BENIGN.netStart)) {
              throw new LibvirtError(`could not start network ${args.name}`);
            }
            changed = true;
            after = await networkInfo(deps, t, args.uri, args.name);
          }
          if (args.autostart && !after.autostart) {
            await virsh(deps, t, args.uri, ["net-autostart", args.name]);
            changed = true;
            after = await networkInfo(deps, t, args.uri, args.name);
          }
          const handle = await context.writeResource(
            "network_state",
            instanceName("net", args, args.name),
            {
              target: targetKey(args),
              name: args.name,
              present: true,
              uuid: after.uuid,
              active: after.active,
              autostart: after.autostart,
              config_sha256: await sha256Hex(xml),
              observed_at: new Date(deps.now()).toISOString(),
            },
          );
          return {
            dataHandles: [handle],
            result: {
              target: targetKey(args),
              name: args.name,
              active: after.active,
              autostart: after.autostart,
              changed,
            },
          };
        },
      },
      undefine_network: {
        description:
          "DESTRUCTIVE. Stop a network if active, then undefine it; use this to remove the default network. Undefining an absent network is a clean no-op.",
        kind: "action" as const,
        arguments: UndefineNetworkArgs,
        execute: async (
          args: z.infer<typeof UndefineNetworkArgs>,
          context: Ctx,
        ) => {
          assertName(args.name, "network name");
          assertUri(args.uri);
          const t = targetOf(args);
          const before = await networkInfo(deps, t, args.uri, args.name);
          if (!before.present) {
            const handle = await context.writeResource(
              "network_state",
              instanceName("net", args, args.name),
              {
                target: targetKey(args),
                name: args.name,
                present: false,
                observed_at: new Date(deps.now()).toISOString(),
              },
            );
            return {
              dataHandles: [handle],
              result: {
                target: targetKey(args),
                name: args.name,
                changed: false,
              },
            };
          }
          if (before.active) {
            const stop = await virshTry(deps, t, args.uri, [
              "net-destroy",
              args.name,
            ]);
            if (stop.exit_code !== 0 && !isBenign(stop, BENIGN.netDestroy)) {
              throw new LibvirtError(`could not stop network ${args.name}`);
            }
          }
          await virsh(deps, t, args.uri, ["net-undefine", args.name]);
          const handle = await context.writeResource(
            "network_state",
            instanceName("net", args, args.name),
            {
              target: targetKey(args),
              name: args.name,
              present: false,
              observed_at: new Date(deps.now()).toISOString(),
            },
          );
          return {
            dataHandles: [handle],
            result: { target: targetKey(args), name: args.name, changed: true },
          };
        },
      },
      clone_volume: {
        description:
          "Idempotent. Clone a golden volume or zvol in a pool to a new volume with virsh vol-clone, which uses the pool driver and so supports zfs-backed pools. A target that already exists is a no-op, never a second clone.",
        kind: "action" as const,
        arguments: CloneVolumeArgs,
        execute: async (
          args: z.infer<typeof CloneVolumeArgs>,
          context: Ctx,
        ) => {
          assertName(args.pool, "pool name");
          assertName(args.source_volume, "source volume");
          assertName(args.target_volume, "target volume");
          assertUri(args.uri);
          const t = targetOf(args);
          if (
            !(await volumePresent(
              deps,
              t,
              args.uri,
              args.pool,
              args.source_volume,
            ))
          ) {
            throw new LibvirtError(
              `golden volume ${args.source_volume} not found in pool ${args.pool}`,
            );
          }
          let changed = false;
          if (
            await volumePresent(
              deps,
              t,
              args.uri,
              args.pool,
              args.target_volume,
            )
          ) {
            context.logger.info(
              "volume {volume} already exists in {pool}, no-op",
              { volume: args.target_volume, pool: args.pool },
            );
          } else {
            const res = await virshTry(deps, t, args.uri, [
              "vol-clone",
              args.source_volume,
              args.target_volume,
              "--pool",
              args.pool,
            ]);
            if (res.exit_code !== 0 && !isBenign(res, BENIGN.clone)) {
              throw new LibvirtError(
                `virsh vol-clone failed (exit ${res.exit_code}): ${
                  `${res.stderr || res.stdout}`.trim().slice(0, 300)
                }`,
              );
            }
            changed = true;
          }
          const info = await virsh(deps, t, args.uri, [
            "vol-info",
            "--pool",
            args.pool,
            "--",
            args.target_volume,
          ]);
          const kv = parseKeyValues(info.stdout);
          const handle = await context.writeResource(
            "volume_state",
            instanceName("vol", args, args.pool, args.target_volume),
            {
              target: targetKey(args),
              pool: args.pool,
              name: args.target_volume,
              present: true,
              path: kv["path"],
              capacity: kv["capacity"],
              allocation: kv["allocation"],
              format: args.format ?? kv["type"],
              observed_at: new Date(deps.now()).toISOString(),
            },
          );
          return {
            dataHandles: [handle],
            result: {
              target: targetKey(args),
              pool: args.pool,
              name: args.target_volume,
              changed,
            },
          };
        },
      },
      define_domain: {
        description:
          "Idempotent. Define a KVM domain that boots from a pool volume, usually a clone of the golden volume, from rendered XML. An existing domain of the same name is a no-op unless replace is true; start is optional. The rendered XML wires a pty serial console.",
        kind: "action" as const,
        arguments: DefineDomainArgs,
        execute: async (
          args: z.infer<typeof DefineDomainArgs>,
          context: Ctx,
        ) => {
          assertName(args.name, "domain name");
          assertName(args.pool, "pool name");
          assertName(args.volume, "volume name");
          assertUri(args.uri);
          if (args.network !== undefined && args.bridge !== undefined) {
            throw new LibvirtConfigError("give network or bridge, not both");
          }
          const t = targetOf(args);
          if (
            !(await volumePresent(deps, t, args.uri, args.pool, args.volume))
          ) {
            throw new LibvirtError(
              `volume ${args.volume} not found in pool ${args.pool}; clone it first`,
            );
          }
          const xml = renderDomainXml({
            name: args.name,
            pool: args.pool,
            volume: args.volume,
            vcpus: args.vcpus,
            memoryMib: args.memory_mib,
            format: args.format,
            arch: args.arch,
            network: args.network,
            bridge: args.bridge,
            mac: args.mac,
          });
          let before = await domainInfo(deps, t, args.uri, args.name);
          let changed = false;
          if (Object.keys(before).length > 0) {
            if (args.replace) {
              if (isRunningState(domainState(before))) {
                await virsh(deps, t, args.uri, ["destroy", args.name]);
              }
              await virsh(deps, t, args.uri, ["undefine", args.name]);
              await defineFromXml(deps, t, args.uri, "define", xml);
              changed = true;
            }
          } else {
            await defineFromXml(deps, t, args.uri, "define", xml);
            changed = true;
          }
          before = await domainInfo(deps, t, args.uri, args.name);
          if (args.start && !isRunningState(domainState(before))) {
            const start = await virshTry(deps, t, args.uri, [
              "start",
              args.name,
            ]);
            if (start.exit_code !== 0 && !isBenign(start, BENIGN.start)) {
              throw new LibvirtError(`could not start domain ${args.name}`);
            }
            changed = true;
            before = await domainInfo(deps, t, args.uri, args.name);
          }
          const handle = await context.writeResource(
            "domain_state",
            instanceName("dom", args, args.name),
            {
              target: targetKey(args),
              name: args.name,
              present: true,
              uuid: before["uuid"] ?? "",
              state: domainState(before),
              vcpus: Number(before["cpu(s)"] ?? "") || undefined,
              memory_mib: memoryMib(before),
              observed_at: new Date(deps.now()).toISOString(),
            },
          );
          return {
            dataHandles: [handle],
            result: {
              target: targetKey(args),
              name: args.name,
              state: domainState(before),
              changed,
            },
          };
        },
      },
      power: {
        description:
          "DESTRUCTIVE when action is destroy (immediate power-off, loses guest state). Start, shut down, destroy, reboot, suspend or resume a domain, idempotent toward the desired state: a domain already in the target state is a no-op.",
        kind: "action" as const,
        arguments: PowerArgs,
        execute: async (
          args: z.infer<typeof PowerArgs>,
          context: Ctx,
        ) => {
          assertName(args.name, "domain name");
          assertUri(args.uri);
          const t = targetOf(args);
          const info = await domainInfo(deps, t, args.uri, args.name);
          if (Object.keys(info).length === 0) {
            throw new LibvirtError(`domain ${args.name} not found`);
          }
          const state = domainState(info);
          const running = isRunningState(state);
          const paused = isPausedState(state);
          const off = isOffState(state);
          let noop = false;
          let argv: string[] | null = null;
          let benign: RegExp[] = [];
          switch (args.action) {
            case "start":
              noop = running;
              argv = ["start", args.name];
              benign = BENIGN.start;
              break;
            case "shutdown":
              noop = off;
              argv = ["shutdown", args.name];
              benign = BENIGN.shutdown;
              break;
            case "destroy":
              noop = off;
              argv = ["destroy", args.name];
              benign = BENIGN.destroy;
              break;
            case "reboot":
              if (off) {
                throw new LibvirtError(
                  `cannot reboot ${args.name}: it is not running`,
                );
              }
              argv = ["reboot", args.name];
              break;
            case "suspend":
              noop = paused;
              argv = ["suspend", args.name];
              benign = BENIGN.suspend;
              break;
            case "resume":
              if (off) {
                throw new LibvirtError(
                  `cannot resume ${args.name}: it is not paused`,
                );
              }
              noop = running && !paused;
              argv = ["resume", args.name];
              benign = BENIGN.resume;
              break;
          }
          let changed = false;
          if (!noop && argv !== null) {
            const res = await virshTry(deps, t, args.uri, argv);
            if (res.exit_code !== 0 && !isBenign(res, benign)) {
              throw new LibvirtError(
                `virsh ${args.action} ${args.name} failed (exit ${res.exit_code}): ${
                  `${res.stderr || res.stdout}`.trim().slice(0, 300)
                }`,
              );
            }
            changed = true;
          }
          const after = await domainInfo(deps, t, args.uri, args.name);
          const handle = await context.writeResource(
            "domain_state",
            instanceName("dom", args, args.name),
            {
              target: targetKey(args),
              name: args.name,
              present: true,
              uuid: after["uuid"] ?? "",
              state: domainState(after),
              vcpus: Number(after["cpu(s)"] ?? "") || undefined,
              memory_mib: memoryMib(after),
              observed_at: new Date(deps.now()).toISOString(),
            },
          );
          return {
            dataHandles: [handle],
            result: {
              target: targetKey(args),
              name: args.name,
              action: args.action,
              state: domainState(after),
              changed,
            },
          };
        },
      },
      console: {
        description:
          "READ-ONLY. Attach to a domain's serial console with a hard timeout and return the captured text. Never blocks past timeout_s; the capture is stored as a sensitive resource because it can carry boot or login secrets.",
        arguments: ConsoleArgs,
        execute: async (
          args: z.infer<typeof ConsoleArgs>,
          context: Ctx,
        ) => {
          assertName(args.name, "domain name");
          assertUri(args.uri);
          const t = targetOf(args);
          const info = await domainInfo(deps, t, args.uri, args.name);
          if (Object.keys(info).length === 0) {
            throw new LibvirtError(`domain ${args.name} not found`);
          }
          const res: ExecResult = await exec(
            deps,
            t,
            consoleArgv(args.uri, args.name, args.timeout_s, args.devname),
          );
          const text = res.stdout;
          if (res.exit_code !== 0 && text.trim() === "") {
            throw new LibvirtError(
              `could not attach to the console of ${args.name} (exit ${res.exit_code})`,
            );
          }
          const handle = await context.writeResource(
            "console_capture",
            instanceName("console", args, args.name),
            {
              target: targetKey(args),
              domain: args.name,
              text,
              bytes: text.length,
              observed_at: new Date(deps.now()).toISOString(),
            },
          );
          return {
            dataHandles: [handle],
            result: {
              target: targetKey(args),
              domain: args.name,
              text,
              bytes: text.length,
            },
          };
        },
      },
      undefine_domain: {
        description:
          "DESTRUCTIVE. Destroy the domain if running, then undefine it; remove_volumes also deletes its managed volumes. Undefining an absent domain is a clean no-op.",
        kind: "action" as const,
        arguments: UndefineDomainArgs,
        execute: async (
          args: z.infer<typeof UndefineDomainArgs>,
          context: Ctx,
        ) => {
          assertName(args.name, "domain name");
          assertUri(args.uri);
          const t = targetOf(args);
          const info = await domainInfo(deps, t, args.uri, args.name);
          if (Object.keys(info).length === 0) {
            const handle = await context.writeResource(
              "domain_state",
              instanceName("dom", args, args.name),
              {
                target: targetKey(args),
                name: args.name,
                present: false,
                observed_at: new Date(deps.now()).toISOString(),
              },
            );
            return {
              dataHandles: [handle],
              result: {
                target: targetKey(args),
                name: args.name,
                changed: false,
              },
            };
          }
          const state = domainState(info);
          if (isRunningState(state) || isPausedState(state)) {
            const destroy = await virshTry(deps, t, args.uri, [
              "destroy",
              args.name,
            ]);
            if (destroy.exit_code !== 0 && !isBenign(destroy, BENIGN.destroy)) {
              throw new LibvirtError(
                `could not destroy domain ${args.name} before undefining it`,
              );
            }
          }
          const undefine = ["undefine", args.name];
          if (args.remove_volumes) undefine.push("--remove-all-storage");
          await virsh(deps, t, args.uri, undefine);
          const handle = await context.writeResource(
            "domain_state",
            instanceName("dom", args, args.name),
            {
              target: targetKey(args),
              name: args.name,
              present: false,
              observed_at: new Date(deps.now()).toISOString(),
            },
          );
          return {
            dataHandles: [handle],
            result: { target: targetKey(args), name: args.name, changed: true },
          };
        },
      },
      get: {
        description:
          "READ-ONLY. Report network, domain and pool-volume state from virsh list/info. Writes the inventory as host_state and returns the same typed object.",
        arguments: GetArgs,
        execute: async (args: z.infer<typeof GetArgs>, context: Ctx) => {
          assertUri(args.uri);
          const state = await collectHost(deps, targetOf(args), args);
          const handle = await context.writeResource(
            "host_state",
            instanceName("host", args),
            state,
          );
          return { dataHandles: [handle], result: state };
        },
      },
      sync: {
        description:
          "READ-ONLY. Probe the host and report drift between the last recorded inventory and the live networks, domains and pool volumes.",
        arguments: GetArgs,
        execute: async (args: z.infer<typeof GetArgs>, context: Ctx) => {
          assertUri(args.uri);
          const prev = await context.readResource(
            instanceName("host", args),
          ) as HostState | null;
          const state = await collectHost(deps, targetOf(args), args);
          const drift = diffHost(prev, state);
          const handle = await context.writeResource(
            "host_state",
            instanceName("host", args),
            state,
          );
          return {
            dataHandles: [handle],
            result: { target: state.target, drift },
          };
        },
      },
    },
  };
}

async function collectHost(
  deps: LibvirtDeps,
  t: SshTarget,
  args: {
    host: string;
    port: number;
    user: string;
    uri: string;
    network?: string;
    domain?: string;
    pool?: string;
  },
): Promise<HostState> {
  const netOut = await virsh(deps, t, args.uri, [
    "net-list",
    "--all",
    "--name",
  ]);
  let netNames = parseNameList(netOut.stdout);
  if (args.network !== undefined) {
    netNames = netNames.filter((n) => n === args.network);
    if (!netNames.includes(args.network)) netNames = [args.network];
  }
  const networks: z.infer<typeof NetSummary>[] = [];
  for (const name of netNames) {
    const info = await networkInfo(deps, t, args.uri, name);
    networks.push({
      name,
      active: info.active,
      autostart: info.autostart,
    });
  }
  const domOut = await virsh(deps, t, args.uri, ["list", "--all", "--name"]);
  let domNames = parseNameList(domOut.stdout);
  if (args.domain !== undefined) {
    domNames = domNames.filter((n) => n === args.domain);
    if (!domNames.includes(args.domain)) domNames = [args.domain];
  }
  const domains: z.infer<typeof DomainSummary>[] = [];
  for (const name of domNames) {
    const info = await domainInfo(deps, t, args.uri, name);
    domains.push({
      name,
      state: domainState(info),
      uuid: info["uuid"] ?? "",
    });
  }
  const volumes: z.infer<typeof VolSummary>[] = [];
  if (args.pool !== undefined) {
    const list = await virsh(deps, t, args.uri, [
      "vol-list",
      "--pool",
      args.pool,
    ]);
    for (const v of parseVolList(list.stdout)) {
      volumes.push({ pool: args.pool, name: v.name, path: v.path });
    }
  }
  return {
    target: targetKey(args),
    networks,
    domains,
    volumes,
    observed_at: new Date(deps.now()).toISOString(),
  };
}

function diffHost(prev: HostState | null, next: HostState): string[] {
  if (prev === null) return ["unrecorded"];
  const drift: string[] = [];
  const prevNets = new Map(prev.networks.map((n) => [n.name, n]));
  const nextNets = new Map(next.networks.map((n) => [n.name, n]));
  for (const [name, live] of nextNets) {
    const was = prevNets.get(name);
    if (
      !was || was.active !== live.active || was.autostart !== live.autostart
    ) {
      drift.push(`network:${name}`);
    }
  }
  for (const name of prevNets.keys()) {
    if (!nextNets.has(name)) drift.push(`network:${name}`);
  }
  const prevDoms = new Map(prev.domains.map((d) => [d.name, d]));
  const nextDoms = new Map(next.domains.map((d) => [d.name, d]));
  for (const [name, live] of nextDoms) {
    const was = prevDoms.get(name);
    if (!was || was.state !== live.state) drift.push(`domain:${name}`);
  }
  for (const name of prevDoms.keys()) {
    if (!nextDoms.has(name)) drift.push(`domain:${name}`);
  }
  const prevVols = new Map(prev.volumes.map((v) => [`${v.pool}/${v.name}`, v]));
  const nextVols = new Map(next.volumes.map((v) => [`${v.pool}/${v.name}`, v]));
  for (const key of nextVols.keys()) {
    if (!prevVols.has(key)) drift.push(`volume:${key}`);
  }
  for (const key of prevVols.keys()) {
    if (!nextVols.has(key)) drift.push(`volume:${key}`);
  }
  return drift;
}

/** Production model: the factory with the registry-facing type and version. */
export const model = {
  ...createModel(),
  type: "@randybias/libvirt",
  version: "2026.10.17.1",
};
