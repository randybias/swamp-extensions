/**
 * Shared zod field declarations for the cephadm model.
 *
 * The connection fields are declared once here and spread into every
 * SSH-using method, so connection behaviour is uniform and a method cannot
 * narrow a shared field. Every optional field is nullish individually,
 * because a workflow passes the input if supplied and null otherwise.
 *
 * @module
 */

import { z } from "npm:zod@4.3.6";
import {
  CAPS_RE,
  CEPH_ID_CREATE_RE,
  CEPHADM_VERSION_RE,
  DEB_PACKAGE_RE,
  FSID_RE,
  HOSTNAME_RE,
  isContainerImage,
  isHostTarget,
  isHttpUrl,
  isIpv4,
  isIpv4Cidr,
  isKeyPath,
  isSshPublicKey,
  SERIAL_RE,
  SSH_USER_RE,
  UNIT_RE,
} from "./validate.ts";

/** Host target: a hostname or an IPv4 address. */
export const HOST_FIELD = z.string().min(1).max(253).refine(
  (v) => isHostTarget(v),
  "must be a hostname or IPv4 address (IPv6 is not supported)",
);

/** Device serial. */
export const SERIAL_SCHEMA = z.string().regex(
  SERIAL_RE,
  "a serial is 1-40 letters, digits or hyphens",
);

/** Debian package name. */
export const PACKAGE_SCHEMA = z.string().regex(
  DEB_PACKAGE_RE,
  "a Debian package name with no architecture qualifier or version pin",
);

/** HTTP(S) URL. */
export const HTTP_URL_SCHEMA = z.string().refine(
  (v) => isHttpUrl(v),
  "an absolute http or https URL with no shell metacharacters",
);

/** Dotted release number. */
export const CEPHADM_VERSION_SCHEMA = z.string().regex(
  CEPHADM_VERSION_RE,
  "a dotted release number such as 19.2.1",
);

/** systemd unit name. */
export const UNIT_SCHEMA = z.string().regex(UNIT_RE, "a systemd unit name");

/** Cluster fsid. */
export const FSID_SCHEMA = z.string().regex(FSID_RE, "an RFC 4122 UUID");

/** IPv4 CIDR with host bits zero. */
export const CIDR_SCHEMA = z.string().refine(
  (v) => isIpv4Cidr(v),
  "an IPv4 CIDR with a prefix length 0-32 and host bits zero",
);

/** IPv4 address. */
export const IPV4_SCHEMA = z.string().refine(
  (v) => isIpv4(v),
  "a dotted-quad IPv4 address",
);

/**
 * The shared SSH argument family, spread into every SSH-using method. The
 * private key is sensitive on both the string and its nullish wrapper.
 */
export const SSH_FIELDS = {
  sshUser: z.string().regex(SSH_USER_RE, "a POSIX portable username").describe(
    "Login user on the target; must have passwordless sudo for methods that escalate.",
  ),
  port: z.number().int().min(1).max(65535).nullish().describe(
    "SSH port; absent means 22. Workflows pass it explicitly.",
  ),
  keyPath: z.string().max(4096).refine(
    isKeyPath,
    "an absolute local path with no control characters",
  )
    .nullish().describe(
      "Path on the control host to a private key file; mutually exclusive with privateKey.",
    ),
  privateKey: z.string().max(16384).meta({ sensitive: true }).nullish().meta({
    sensitive: true,
  }).describe(
    "OpenSSH private key content, normally a vault reference; mutually exclusive with keyPath.",
  ),
  strictHostKeyChecking: z.enum(["yes", "no"]).describe(
    "Host-key policy: yes (strict) or no (explicitly insecure). Required; there is no silent default.",
  ),
  multiplex: z.boolean().nullish().describe(
    "Reuse one authenticated SSH master per host; absent means false.",
  ),
};

/** Field names every SSH-using method must declare. */
export const SSH_FIELD_NAMES = Object.keys(SSH_FIELDS);

/** The nullish-tolerant fields on any method, read from a parsed argument object. */
export interface SshFieldValues {
  /** Login user. */
  sshUser: string;
  /** SSH port or null. */
  port?: number | null;
  /** Key path or null. */
  keyPath?: string | null;
  /** Key content or null. */
  privateKey?: string | null;
  /** Host-key policy or null. */
  strictHostKeyChecking?: "yes" | "no" | null;
  /** Multiplex switch or null. */
  multiplex?: boolean | null;
}

/** Hostname used when a method needs a target-shaped host. */
export const HOSTNAME_SCHEMA = z.string().regex(
  HOSTNAME_RE,
  "an RFC 1122 hostname",
);

/** Hostname or IPv4, or an empty string meaning absent. */
export const OPTIONAL_HOST_SCHEMA = z.string().max(253).refine(
  (v) => v === "" || isHostTarget(v),
  "a hostname or IPv4 address, or empty",
).nullish();

/** A cephadm-registered hostname for a placement list. */
export const PLACEMENT_HOST_SCHEMA = HOSTNAME_SCHEMA;

/** A non-empty placement host list with no duplicates. */
export const PLACEMENT_SCHEMA = z.array(PLACEMENT_HOST_SCHEMA).min(1).max(64)
  .refine(
    (hosts) => new Set(hosts).size === hosts.length,
    "placement hosts must be unique",
  );

/** A Ceph caps expression. */
export const CAPS_SCHEMA = z.string().regex(
  CAPS_RE,
  "a Ceph caps expression (letters, digits, spaces, quotes and = * / , . _ - +)",
);

/** Ceph identifier in the create direction. */
export const CEPH_ID_SCHEMA = z.string().regex(
  CEPH_ID_CREATE_RE,
  "a Ceph identifier: letters, digits, dot, underscore or hyphen, starting with a letter or digit",
);

/** A single SSH public key line with no option prefix. */
export const SSH_PUBKEY_SCHEMA = z.string().refine(
  (v) => isSshPublicKey(v),
  "a single <keytype> <blob> [comment] line with no options",
);

/** An OCI image reference with an explicit tag or digest. */
export const CONTAINER_IMAGE_SCHEMA = z.string().refine(
  (v) => isContainerImage(v),
  "an OCI image reference with an explicit tag or digest",
);

/** A data device entry. */
export const DATA_DEVICE_SCHEMA = z.strictObject({
  serial: SERIAL_SCHEMA.describe("Disk serial."),
  sizeBytes: z.number().int().positive().optional().describe(
    "Informational size hint.",
  ),
  devHint: z.string().max(64).optional().describe(
    "Informational kernel name; never used.",
  ),
});

/** An excluded device entry. */
export const EXCLUDE_DEVICE_SCHEMA = z.strictObject({
  serial: SERIAL_SCHEMA.describe("Never-touch serial."),
  reason: z.string().max(256).optional().describe("Why it is excluded."),
});
