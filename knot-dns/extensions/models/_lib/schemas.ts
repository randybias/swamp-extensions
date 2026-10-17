/**
 * Zod schemas for the Knot DNS model's method arguments and stored state.
 *
 * @module
 */

import { z } from "npm:zod@4.3.6";
import { HOST_RE, USER_RE } from "./ssh.ts";
import { ResolverSchema } from "./resolver.ts";
import {
  DnssecSchema,
  FqdnSchema,
  isApex,
  noSignerOwned,
  RefusedRecordSchema,
  SoaSchema,
} from "./zone.ts";

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

export const TsigKeySchema = z.strictObject({
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

export const InstallArgs = z.strictObject({
  ...SshShape,
  resolver: z.boolean().default(false),
});
export const ZoneArgs = z.strictObject(ZoneShape);
export const ApplyZoneArgs = z.strictObject({
  ...ZoneShape,
  dnssec_unsign_ack: z.boolean().default(false).describe(
    "Acknowledge turning a signed zone unsigned; refused otherwise.",
  ),
});
export const ZoneOnlyArgs = z.strictObject({
  ...SshShape,
  zone: z.string().min(1).max(253).refine(isApex, "invalid zone apex"),
});
export const RemoveZoneArgs = z.strictObject({
  ...SshShape,
  zone: z.string().min(1).max(253).refine(isApex, "invalid zone apex"),
  dnssec_unsign_ack: z.boolean().default(false),
  purge_keys_ack: z.boolean().default(false),
});
export const SshOnlyArgs = z.strictObject(SshShape);
export const RemoveResolverArgs = z.strictObject({
  ...SshShape,
  remove_ack: z.boolean().default(false).describe(
    "Acknowledge removing a resolver this model did not apply.",
  ),
});
export const ApplyResolverArgs = z.strictObject({
  ...SshShape,
  resolver: ResolverSchema,
});

export const StateZoneSchema = z.strictObject({
  host: z.string(),
  apex: z.string(),
  status: z.enum(["rendered", "applied", "removed"]),
  rendered_sha256: z.string(),
  record_count: z.number().int(),
  dnssec: z.boolean(),
  served_serial: z.string().optional(),
  applied_at: z.string().optional(),
  declared: z.array(z.string()).optional(),
  /** Listens this zone asked for; the host's fragment is the union of these. */
  requested_listen: z.array(z.string()).optional(),
  /** The host-wide listen set in force after this zone was applied. */
  listen: z.array(z.string()).optional(),
});

export const StateResolverSchema = z.strictObject({
  host: z.string(),
  status: z.enum(["applied", "removed"]),
  rendered_sha256: z.string(),
  listen: z.array(z.string()),
  forwards: z.array(z.string()),
  applied_at: z.string().optional(),
});

export const ObservationSchema = z.strictObject({
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

export const DsSchema = z.strictObject({
  host: z.string(),
  zone: z.string(),
  ds: z.array(z.string()),
  observed_at: z.string(),
});
