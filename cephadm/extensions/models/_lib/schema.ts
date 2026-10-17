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
  CEPHADM_VERSION_RE,
  DEB_PACKAGE_RE,
  FSID_RE,
  HOSTNAME_RE,
  isHostTarget,
  isHttpUrl,
  isIpv4,
  isIpv4Cidr,
  isKeyPath,
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
  keyPath: z.string().refine(
    isKeyPath,
    "an absolute local path with no control characters",
  )
    .nullish().describe(
      "Path on the control host to a private key file; mutually exclusive with privateKey.",
    ),
  privateKey: z.string().meta({ sensitive: true }).nullish().meta({
    sensitive: true,
  }).describe(
    "OpenSSH private key content, normally a vault reference; mutually exclusive with keyPath.",
  ),
  strictHostKeyChecking: z.enum(["yes", "no"]).nullish().describe(
    "Host-key policy; absent means yes (strict). no is explicit and loads no real known_hosts.",
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
