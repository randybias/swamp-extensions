/**
 * Argument and state schemas for the autoinstall model.
 *
 * Every method takes its operands per call, so one definition serves any host.
 * Grammars are applied here, at the boundary, before a value reaches a manifest
 * or a remote argv.
 *
 * @module
 */

import { z } from "npm:zod@4.3.6";
import {
  DEVICE_PATH_RE,
  HOSTNAME_RE,
  ID_RE,
  isCidr,
  isCryptHash,
  isIp,
  isOpenSshPublicKey,
  LVM_NAME_RE,
  MAC_RE,
  MOUNT_PATH_RE,
  PACKAGE_RE,
  PRINTABLE_RE,
  SERIAL_RE,
  USERNAME_RE,
} from "./grammars.ts";
import { isRootPath, isSeedUrl, isSeedUrlBase } from "./seed.ts";
import type { AutoinstallInput, StorageInput } from "./render.ts";
import type { SshTarget } from "./ssh.ts";

const IFACE_RE = /^[A-Za-z0-9][A-Za-z0-9:._-]{0,14}$/;
const SIZE_RE = /^\d{1,6}(M|G|T)$/;
/** Cap on the first-boot cloud-config block, in UTF-8 bytes. */
const FIRST_BOOT_MAX_BYTES = 65536;

/**
 * The SSH target. Only a strict host-key policy is offered: nothing persists a
 * first-seen key, so trust-on-first-use would be a silent MITM window.
 */
export const SshTargetSchema = z.strictObject({
  host: z.string().min(1).max(253).describe("Hostname or IP literal."),
  port: z.number().int().min(1).max(65535).default(22),
  user: z.string().regex(USERNAME_RE, "invalid remote user"),
  host_key_policy: z.literal("strict").describe(
    "Always strict; host_keys are required.",
  ),
  host_keys: z.array(z.string().max(8192).regex(PRINTABLE_RE)).min(1).max(64)
    .describe("Pinned ssh-keyscan-format lines."),
  private_key: z.string().max(65536).meta({ sensitive: true }).optional()
    .describe("SSH private key; pass a vault reference."),
  password: z.string().max(1024).meta({ sensitive: true }).optional(),
  connect_timeout_s: z.number().int().min(1).max(120).default(15),
});

const MatchSchema = z.strictObject({
  serial: z.string().regex(SERIAL_RE, "invalid serial").optional(),
  path: z.string().regex(DEVICE_PATH_RE, "invalid device path").optional(),
  model: z.string().max(64).regex(PRINTABLE_RE, "invalid model").optional(),
  size: z.enum(["largest", "smallest"]).optional(),
  ssd: z.boolean().optional(),
}).refine(
  (m) => m.serial || m.path || m.model || m.size || m.ssd !== undefined,
  "match needs at least one selector",
);

const LayoutStorage = z.strictObject({
  layout: z.enum(["lvm", "direct"]),
  match: MatchSchema.optional(),
  sizing_policy: z.enum(["scaled", "all"]).optional(),
  luks_password: z.string().min(8).max(4096).meta({ sensitive: true })
    .optional().describe("LUKS passphrase; refused by the pipeline."),
});

const StorageAction = z.discriminatedUnion("type", [
  z.strictObject({
    type: z.literal("disk"),
    id: z.string().regex(ID_RE, "invalid id"),
    ptable: z.literal("gpt").default("gpt"),
    serial: z.string().regex(SERIAL_RE, "invalid serial").optional(),
    path: z.string().regex(DEVICE_PATH_RE, "invalid device path").optional(),
    grub_device: z.boolean().optional(),
    wipe: z.string().max(32).optional(),
    preserve: z.boolean().optional(),
  }).refine(
    (d) => (d.serial === undefined) !== (d.path === undefined),
    "a disk needs exactly one of serial or path",
  ),
  z.strictObject({
    type: z.literal("partition"),
    id: z.string().regex(ID_RE, "invalid id"),
    device: z.string().regex(ID_RE, "invalid device"),
    size: z.union([z.number().int().positive(), z.literal(-1)]),
    flag: z.enum(["boot", "bios_grub", "raid", "lvm", "swap"]).optional(),
    preserve: z.boolean().optional(),
  }),
  z.strictObject({
    type: z.literal("raid"),
    id: z.string().regex(ID_RE, "invalid id"),
    raidlevel: z.union([
      z.literal(0),
      z.literal(1),
      z.literal(5),
      z.literal(6),
      z.literal(10),
    ]),
    devices: z.array(z.string().regex(ID_RE)).min(2).max(32),
    spare_devices: z.array(z.string().regex(ID_RE)).max(32).default([]),
    preserve: z.boolean().optional(),
  }),
  z.strictObject({
    type: z.literal("lvm_volgroup"),
    id: z.string().regex(ID_RE, "invalid id"),
    name: z.string().regex(LVM_NAME_RE, "invalid VG name"),
    devices: z.array(z.string().regex(ID_RE)).min(1).max(32),
    preserve: z.boolean().optional(),
  }),
  z.strictObject({
    type: z.literal("lvm_partition"),
    id: z.string().regex(ID_RE, "invalid id"),
    name: z.string().regex(LVM_NAME_RE, "invalid LV name"),
    volgroup: z.string().regex(ID_RE, "invalid volgroup"),
    size: z.string().regex(SIZE_RE, "invalid size").optional(),
    preserve: z.boolean().optional(),
  }),
  z.strictObject({
    type: z.literal("format"),
    id: z.string().regex(ID_RE, "invalid id"),
    volume: z.string().regex(ID_RE, "invalid volume"),
    fstype: z.enum(["ext4", "xfs", "vfat", "fat32", "swap"]),
    label: z.string().max(32).regex(PRINTABLE_RE, "invalid label").optional(),
    preserve: z.boolean().optional(),
  }),
  z.strictObject({
    type: z.literal("mount"),
    id: z.string().regex(ID_RE, "invalid id"),
    device: z.string().regex(ID_RE, "invalid device"),
    path: z.string().regex(MOUNT_PATH_RE, "invalid mount path"),
  }),
]);

const StorageSchema = z.union([
  LayoutStorage,
  z.strictObject({ config: z.array(StorageAction).min(1).max(256) }),
  z.strictObject({
    preset: z.literal("raid1-lvm"),
    disks: z.array(
      z.union([
        z.string().regex(SERIAL_RE, "invalid serial"),
        z.string().regex(DEVICE_PATH_RE, "invalid device path"),
      ]),
    ).min(2).max(8),
    vg_name: z.string().regex(LVM_NAME_RE, "invalid VG name"),
    lvs: z.array(z.strictObject({
      name: z.string().regex(LVM_NAME_RE, "invalid LV name"),
      size: z.string().regex(SIZE_RE, "invalid size"),
      fs: z.enum(["ext4", "xfs"]),
      mount: z.string().regex(MOUNT_PATH_RE, "invalid mount"),
    })).min(1).max(32),
  }),
]);

const ArgvLateCommand = z.strictObject({
  argv: z.array(
    z.string().max(4096).regex(PRINTABLE_RE, "not printable"),
  ).min(1).max(128),
  in_target: z.boolean().default(false),
});

const ShellLateCommand = z.strictObject({
  shell: z.string().max(4096).min(1).regex(PRINTABLE_RE, "not printable"),
  in_target: z.boolean().default(false),
  shell_ack: z.literal(true),
});

const LateCommandSchema = z.union([ArgvLateCommand, ShellLateCommand]);

const NetplanMatch = z.strictObject({
  name: z.string().max(64).regex(PRINTABLE_RE).optional(),
  macaddress: z.string().regex(MAC_RE, "not a MAC address").optional(),
  driver: z.string().max(64).regex(PRINTABLE_RE).optional(),
});

const NetplanRoute = z.strictObject({
  to: z.string().max(64).refine(
    (v) => v === "default" || isCidr(v),
    "not a CIDR",
  ).optional(),
  via: z.string().max(64).refine(isIp, "not an IP address").optional(),
  metric: z.number().int().min(0).max(4294967295).optional(),
  "on-link": z.boolean().optional(),
});

const NetplanInterface = z.strictObject({
  match: NetplanMatch.optional(),
  "set-name": z.string().regex(IFACE_RE, "invalid interface name").optional(),
  addresses: z.array(z.string().max(64).refine(isCidr, "not a CIDR")).max(64)
    .optional(),
  routes: z.array(NetplanRoute).max(64).optional(),
  nameservers: z.strictObject({
    addresses: z.array(z.string().max(64).refine(isIp, "not an IP")).max(8)
      .optional(),
    search: z.array(z.string().max(253).regex(PRINTABLE_RE)).max(8).optional(),
  }).optional(),
  dhcp4: z.boolean().optional(),
  dhcp6: z.boolean().optional(),
  optional: z.boolean().optional(),
  interfaces: z.array(z.string().regex(IFACE_RE)).min(1).max(16).optional(),
  parameters: z.record(
    z.string().max(32),
    z.union([z.string().max(64), z.number().int()]),
  ).optional(),
  id: z.number().int().min(0).max(4094).optional(),
  link: z.string().regex(IFACE_RE, "invalid interface name").optional(),
});

/** A bounded netplan v2 subset: ethernets, bonds, vlans and bridges. */
export const NetworkSchema = z.strictObject({
  version: z.literal(2),
  ethernets: z.record(z.string().regex(IFACE_RE), NetplanInterface).optional(),
  bonds: z.record(z.string().regex(IFACE_RE), NetplanInterface).optional(),
  vlans: z.record(z.string().regex(IFACE_RE), NetplanInterface).optional(),
  bridges: z.record(z.string().regex(IFACE_RE), NetplanInterface).optional(),
});

const KeyboardSchema = z.strictObject({
  layout: z.string().max(64).regex(PRINTABLE_RE),
  variant: z.string().max(64).regex(PRINTABLE_RE).optional(),
  toggle: z.string().max(64).regex(PRINTABLE_RE).optional(),
});

const IdentitySchema = z.strictObject({
  hostname: z.string().regex(HOSTNAME_RE, "not an RFC 1123 label").describe(
    "Installed hostname.",
  ),
  username: z.string().regex(USERNAME_RE, "invalid user name"),
  realname: z.string().max(64).regex(PRINTABLE_RE, "invalid real name")
    .optional(),
  password_hash: z.string().max(512).meta({ sensitive: true }).refine(
    isCryptHash,
    "not a crypt(3) hash; a plaintext password is refused",
  ).describe(
    "Crypt(3) hash from vault ($1$, $2b$, $5$, $6$ or $y$); never a plaintext.",
  ),
});

const SshBlockSchema = z.strictObject({
  install_server: z.boolean().default(true),
  authorized_keys: z.array(
    z.string().max(8192).refine(
      isOpenSshPublicKey,
      "not an OpenSSH public key (ed25519, ecdsa, or RSA 3072+)",
    ),
  ).min(1).max(32),
  allow_pw: z.boolean().default(false),
  allow_pw_ack: z.boolean().default(false),
});

const AutoinstallFields = {
  identity: IdentitySchema,
  ssh: SshBlockSchema,
  storage: StorageSchema.optional(),
  network: NetworkSchema.optional(),
  packages: z.array(z.string().max(192).regex(PACKAGE_RE, "invalid package"))
    .max(
      256,
    ).default([]),
  late_commands: z.array(LateCommandSchema).max(128).default([]),
  late_commands_shell_ack: z.boolean().default(false),
  first_boot_user_data: z.record(z.string(), z.unknown()).refine(
    (d) =>
      new TextEncoder().encode(JSON.stringify(d)).length <=
        FIRST_BOOT_MAX_BYTES,
    `first_boot_user_data must be at most ${FIRST_BOOT_MAX_BYTES} bytes`,
  ).optional().meta({ sensitive: true }),
  shutdown: z.enum(["reboot", "poweroff"]).default("reboot"),
  updates: z.enum(["security", "all"]).default("security"),
  source_id: z.string().regex(/^[a-z0-9.-]{1,64}$/, "invalid source id")
    .optional(),
  locale: z.string().regex(/^[A-Za-z0-9_.@-]{1,64}$/, "invalid locale")
    .optional(),
  keyboard: KeyboardSchema.optional(),
  timezone: z.string().regex(/^[A-Za-z0-9_+/-]{1,64}$/, "invalid timezone")
    .optional(),
};

/** The seed URL used on a kernel command line; it must end in `/`. */
const SeedUrlForCmdline = z.string().max(2048).refine(
  isSeedUrl,
  "must be an http(s) URL ending in / with no userinfo, query or shell character",
);

const ServerSchema = z.strictObject({
  ssh: SshTargetSchema,
  root: z.string().max(255).refine(isRootPath, "not an absolute safe path"),
  url_base: z.string().max(2048).refine(
    isSeedUrlBase,
    "must be an http(s) URL with no userinfo, query or shell character",
  ),
});

function needsAcknowledgement(
  a: {
    ssh: { allow_pw: boolean; allow_pw_ack: boolean };
    late_commands: unknown[];
    late_commands_shell_ack: boolean;
  },
  ctx: z.RefinementCtx,
): void {
  if (a.ssh.allow_pw && !a.ssh.allow_pw_ack) {
    ctx.addIssue({
      code: "custom",
      path: ["ssh", "allow_pw_ack"],
      message: "allow_pw requires allow_pw_ack",
    });
  }
  if (
    a.late_commands.some((c) =>
      typeof c === "object" && c !== null && "shell" in c
    ) && !a.late_commands_shell_ack
  ) {
    ctx.addIssue({
      code: "custom",
      path: ["late_commands_shell_ack"],
      message: "a shell late command requires late_commands_shell_ack",
    });
  }
}

export const RenderArgs = z.strictObject({
  ...AutoinstallFields,
  seed_url: SeedUrlForCmdline.optional(),
}).superRefine(needsAcknowledgement);

export const ValidateArgs = z.strictObject({
  user_data: z.string().min(1).max(1048576).meta({ sensitive: true }).describe(
    "A supplied autoinstall user-data document.",
  ),
});

export const CmdlineArgs = z.strictObject({ seed_url: SeedUrlForCmdline });

export const PublishArgs = z.strictObject({
  ...AutoinstallFields,
  server: ServerSchema,
}).superRefine(needsAcknowledgement);

export const UnpublishArgs = z.strictObject({
  ssh: SshTargetSchema,
  root: z.string().max(255).refine(isRootPath, "not an absolute safe path"),
  hostname: z.string().regex(HOSTNAME_RE, "not an RFC 1123 label"),
  tree_sha256: z.string().regex(/^[0-9a-f]{64}$/, "not a hex SHA-256")
    .optional().describe(
      "Only for a bundle with no ref; must match the bundle's hostname.",
    ),
});

const RenderedFileSchema = z.strictObject({
  name: z.string(),
  sha256: z.string(),
  bytes: z.number().int(),
});

export const RenderStateSchema = z.strictObject({
  hostname: z.string(),
  tree_sha256: z.string(),
  files: z.array(RenderedFileSchema),
  cmdline: z.strictObject({
    kernel_args: z.string(),
    grub_args: z.string(),
  }).optional(),
  seed_url: z.string().optional(),
  observed_at: z.string(),
});

/** The three seed files, sensitive: they carry the password hash. */
export const SeedFilesSchema = z.strictObject({
  "user-data": z.string().meta({ sensitive: true }),
  "meta-data": z.string().meta({ sensitive: true }),
  "vendor-data": z.string().meta({ sensitive: true }),
});

/** A published-seed observation, with a discriminated presence status. */
export const SeedStateSchema = z.strictObject({
  hostname: z.string(),
  tree_sha256: z.string().optional(),
  seed_url: z.string().optional(),
  files: z.array(RenderedFileSchema),
  status: z.enum(["present", "not_found", "mismatch"]),
  observed_at: z.string(),
});

export type RenderArgsT = z.infer<typeof RenderArgs>;
export type PublishArgsT = z.infer<typeof PublishArgs>;
export type SeedState = z.infer<typeof SeedStateSchema>;

/** Maps validated inputs to the pure renderer's input. */
export function toInput(a: RenderArgsT | PublishArgsT): AutoinstallInput {
  return {
    identity: a.identity,
    ssh: a.ssh,
    storage: a.storage as StorageInput | undefined,
    network: a.network,
    packages: a.packages,
    late_commands: a.late_commands,
    late_commands_shell_ack: a.late_commands_shell_ack,
    first_boot_user_data: a.first_boot_user_data,
    shutdown: a.shutdown,
    updates: a.updates,
    source_id: a.source_id,
    locale: a.locale,
    keyboard: a.keyboard,
    timezone: a.timezone,
    seed_url: "seed_url" in a ? a.seed_url : undefined,
  };
}

/** The vendored transport target. */
export function toTarget(s: z.infer<typeof SshTargetSchema>): SshTarget {
  return s as SshTarget;
}
