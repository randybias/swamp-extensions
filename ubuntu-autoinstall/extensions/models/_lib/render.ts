/**
 * Builds the autoinstall object tree and the three NoCloud seed files.
 *
 * Everything is structured: an object tree is assembled and handed to one YAML
 * emitter, never a string concatenation of YAML fragments. The tree hash is the
 * SHA-256 of the bundle's sorted `SHA256SUMS` lines, so the `instance-id`
 * changes exactly when the seed content does.
 *
 * @module
 */

import { emitCloudConfig, emitYamlBody } from "./yaml.ts";
import { sha256Hex } from "./ssh.ts";

/** The three files of a NoCloud seed bundle, in served order. */
export const SEED_FILES = ["user-data", "meta-data", "vendor-data"] as const;

/** A seed file name. */
export type SeedFileName = typeof SEED_FILES[number];

/** One rendered seed file and its digest. */
export interface RenderedFile {
  /** Fixed file name. */
  name: SeedFileName;
  /** Hex SHA-256 of the UTF-8 bytes. */
  sha256: string;
  /** UTF-8 byte length. */
  bytes: number;
}

/** One `late-commands` entry. */
export interface LateCommand {
  /** argv words, run by the installer without a shell. */
  argv?: string[];
  /** A shell command; requires `shell: true` and the caller's acknowledgement. */
  shell?: string;
  /** Prepend `curtin in-target --` so the command runs in the installed system. */
  in_target?: boolean;
  /** Required when `shell` is used. */
  shell_ack?: boolean;
}

/** Guided storage layout. */
export interface LayoutStorage {
  layout: "lvm" | "direct";
  match?: Record<string, unknown>;
  sizing_policy?: "scaled" | "all";
  luks_password?: string;
}

/** Explicit curtin storage actions. */
export interface ConfigStorage {
  config: Record<string, unknown>[];
}

/** The `raid1-lvm` convenience preset. */
export interface PresetStorage {
  preset: "raid1-lvm";
  disks: string[];
  vg_name: string;
  lvs: { name: string; size: string; fs: string; mount: string }[];
}

/** Storage input, one of the three forms. */
export type StorageInput = LayoutStorage | ConfigStorage | PresetStorage;

/** Everything `render` needs; the model validates it before this is called. */
export interface AutoinstallInput {
  identity: {
    hostname: string;
    username: string;
    realname?: string;
    password_hash: string;
  };
  ssh: {
    install_server: boolean;
    authorized_keys: string[];
    allow_pw: boolean;
  };
  storage?: StorageInput;
  network?: Record<string, unknown>;
  packages?: string[];
  late_commands?: LateCommand[];
  late_commands_shell_ack?: boolean;
  first_boot_user_data?: Record<string, unknown>;
  shutdown?: "reboot" | "poweroff";
  updates?: "security" | "all";
  source_id?: string;
  locale?: string;
  keyboard?: { layout: string; variant?: string; toggle?: string };
  timezone?: string;
  seed_url?: string;
}

const BYTES_PER_MIB = 1024 * 1024;
const ESP_MIB = 512;

/** Renders one late command as an argv list, never a shell string. */
export function renderLateCommand(c: LateCommand): string[] {
  const inner = c.shell !== undefined ? ["sh", "-c", c.shell] : (c.argv ?? []);
  return c.in_target ? ["curtin", "in-target", "--", ...inner] : inner;
}

function diskAction(id: string, spec: string): Record<string, unknown> {
  const disk: Record<string, unknown> = {
    type: "disk",
    id,
    ptable: "gpt",
    grub_device: true,
    wipe: "superblock",
  };
  if (spec.startsWith("/dev/")) disk.path = spec;
  else disk.serial = spec;
  return disk;
}

/** Expands the `raid1-lvm` preset into explicit curtin storage actions. */
export function expandRaid1Lvm(
  preset: PresetStorage,
): Record<string, unknown>[] {
  const actions: Record<string, unknown>[] = [];
  const raidDevices: string[] = [];
  preset.disks.forEach((spec, i) => {
    const disk = `disk${i}`;
    actions.push(diskAction(disk, spec));
    actions.push({
      type: "partition",
      id: `${disk}-esp`,
      device: disk,
      size: ESP_MIB * BYTES_PER_MIB,
      flag: "boot",
      preserve: false,
    });
    actions.push({
      type: "partition",
      id: `${disk}-data`,
      device: disk,
      size: -1,
      preserve: false,
    });
    // One ESP per disk: the firmware cannot boot an ESP inside the md array.
    actions.push({
      type: "format",
      id: `${disk}-esp-fmt`,
      volume: `${disk}-esp`,
      fstype: "fat32",
      label: "ESP",
      preserve: false,
    });
    if (i === 0) {
      actions.push({
        type: "mount",
        id: `${disk}-esp-mnt`,
        device: `${disk}-esp-fmt`,
        path: "/boot/efi",
      });
    }
    raidDevices.push(`${disk}-data`);
  });
  actions.push({
    type: "raid",
    id: "md0",
    raidlevel: 1,
    devices: raidDevices,
    spare_devices: [],
    preserve: false,
  });
  actions.push({
    type: "lvm_volgroup",
    id: "vg0",
    name: preset.vg_name,
    devices: ["md0"],
    preserve: false,
  });
  for (const lv of preset.lvs) {
    const id = `lv-${lv.name}`;
    actions.push({
      type: "lvm_partition",
      id,
      name: lv.name,
      volgroup: "vg0",
      size: lv.size,
      preserve: false,
    });
    actions.push({
      type: "format",
      id: `${id}-fmt`,
      volume: id,
      fstype: lv.fs,
      preserve: false,
    });
    actions.push({
      type: "mount",
      id: `${id}-mnt`,
      device: `${id}-fmt`,
      path: lv.mount,
    });
  }
  return actions;
}

/** Renders a storage input to the autoinstall `storage:` object. */
export function renderStorage(
  storage: StorageInput,
): Record<string, unknown> {
  if ("preset" in storage) {
    return { config: expandRaid1Lvm(storage) };
  }
  if ("config" in storage) {
    return { config: storage.config };
  }
  const layout: Record<string, unknown> = { name: storage.layout };
  if (storage.match) layout.match = storage.match;
  if (storage.sizing_policy) layout["sizing-policy"] = storage.sizing_policy;
  if (storage.luks_password) layout.password = storage.luks_password;
  return { layout };
}

/** Builds the `autoinstall:` object from typed inputs. */
export function buildAutoinstall(
  i: AutoinstallInput,
): Record<string, unknown> {
  const ai: Record<string, unknown> = { version: 1 };
  const identity: Record<string, unknown> = {
    hostname: i.identity.hostname,
    username: i.identity.username,
    password: i.identity.password_hash,
  };
  if (i.identity.realname) identity.realname = i.identity.realname;
  ai.identity = identity;
  ai.ssh = {
    "install-server": i.ssh.install_server,
    "authorized-keys": i.ssh.authorized_keys,
    "allow-pw": i.ssh.allow_pw,
  };
  if (i.storage) ai.storage = renderStorage(i.storage);
  if (i.network) ai.network = i.network;
  if (i.packages && i.packages.length > 0) ai.packages = i.packages;
  if (i.late_commands && i.late_commands.length > 0) {
    ai["late-commands"] = i.late_commands.map(renderLateCommand);
  }
  if (i.first_boot_user_data) ai["user-data"] = i.first_boot_user_data;
  if (i.shutdown) ai.shutdown = i.shutdown;
  if (i.updates) ai.updates = i.updates;
  if (i.source_id) ai.source = { id: i.source_id };
  if (i.locale) ai.locale = i.locale;
  if (i.keyboard) ai.keyboard = i.keyboard;
  if (i.timezone) ai.timezone = i.timezone;
  return ai;
}

/** Builds the top-level cloud-config document for the seed. */
export function buildUserDataDocument(
  i: AutoinstallInput,
): Record<string, unknown> {
  return { autoinstall: buildAutoinstall(i) };
}

/**
 * The NotCloud `instance-id`. It is derived from the `user-data` content, so a
 * changed seed is a new instance, and never from the tree hash (which in turn
 * covers the meta-data that carries this id).
 */
function instanceId(userDataSha: string): string {
  return `iid-${userDataSha.slice(0, 12)}`;
}

/** Sorted `sha256sum`-format lines, `"<hash>  <name>"`. */
export function sha256sumsLines(files: RenderedFile[]): string[] {
  return [...files]
    .sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0))
    .map((f) => `${f.sha256}  ${f.name}`);
}

/** A complete rendered seed bundle. */
export interface RenderedSeed {
  /** `user-data` file text. */
  user_data: string;
  /** `meta-data` file text. */
  meta_data: string;
  /** `vendor-data` file text. */
  vendor_data: string;
  /** The object tree behind `meta-data`, for the round-trip guard. */
  meta_tree: Record<string, unknown>;
  /** SHA-256 of the sorted `SHA256SUMS` lines. */
  tree_sha256: string;
  /** Per-file digests, in `SEED_FILES` order. */
  files: RenderedFile[];
  /** Kernel and GRUB command lines for the HTTP seed, when a URL is given. */
  cmdline?: { kernel_args: string; grub_args: string };
}

/** The `meta-data` object: a content-derived instance id and the hostname. */
export function buildMetaDataDocument(
  i: AutoinstallInput,
  userDataSha: string,
): Record<string, unknown> {
  return {
    "instance-id": instanceId(userDataSha),
    "local-hostname": i.identity.hostname,
  };
}

/** Builds and hashes the seed bundle. Pure: no host, no clock, no network. */
export async function renderSeed(i: AutoinstallInput): Promise<RenderedSeed> {
  const userData = emitCloudConfig(buildUserDataDocument(i));
  const vendorData = emitCloudConfig({});
  const userSha = await sha256Hex(userData);
  const metaTree = buildMetaDataDocument(i, userSha);
  // Quoted like user-data: unquoted, YAML 1.1 reads a hostname `on` as a bool.
  const metaData = emitYamlBody(metaTree);
  const encoder = new TextEncoder();
  const files: RenderedFile[] = [];
  for (
    const [name, text] of [
      ["user-data", userData],
      ["meta-data", metaData],
      ["vendor-data", vendorData],
    ] as const
  ) {
    files.push({
      name,
      sha256: await sha256Hex(text),
      bytes: encoder.encode(text).length,
    });
  }
  const treeSha = await sha256Hex(
    sha256sumsLines(files).join("\n") + "\n",
  );
  const result: RenderedSeed = {
    user_data: userData,
    meta_data: metaData,
    vendor_data: vendorData,
    meta_tree: metaTree,
    tree_sha256: treeSha,
    files,
  };
  if (i.seed_url) result.cmdline = cmdlineFor(i.seed_url);
  return result;
}

/** The two command-line forms for a NoCloud-net seed URL. */
export function cmdlineFor(seedUrl: string): {
  kernel_args: string;
  grub_args: string;
} {
  if (!seedUrl.endsWith("/")) {
    throw new Error("a NoCloud seed URL must end in /");
  }
  return {
    kernel_args: `autoinstall ds=nocloud-net;s=${seedUrl}`,
    grub_args: `autoinstall ds=nocloud-net\\;s=${seedUrl}`,
  };
}

/** The CIDATA command line: cloud-init finds the labeled volume itself. */
export function cmdlineForCidata(): string {
  return "autoinstall";
}
