/**
 * Zod schemas and grammars for every method argument and stored resource.
 *
 * A format is described once, here; the model, the target helpers and the
 * layout reader all import from this module, so nothing is parsed two ways.
 *
 * @module
 */

import { z } from "npm:zod@4.3.6";
import { HOST_RE, USER_RE } from "./ssh.ts";
import {
  FILENAME_RE,
  REF_NAME_RE as REF_RE,
  SHA256SUMS_FILE,
} from "./layout.ts";

const HOSTNAME_JSON_RE =
  /^(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$/;
const ROOT_RE = /^\/[A-Za-z0-9._/-]{1,255}$/;
const SHA256_RE = /^[0-9a-f]{64}$/;
const CRYPT_RE = /^\$(6|5|y|2[aby])\$[./A-Za-z0-9$]{8,}$/;
const FETCH_URL_RE = /^https:\/\/[^\s;'"<>|`$()\\@]{1,2040}$/;
/** Bare top-level system directories that may never be a served root. */
const SYSTEM_ROOTS = new Set([
  "/etc",
  "/usr",
  "/bin",
  "/sbin",
  "/lib",
  "/lib64",
  "/boot",
  "/var",
  "/home",
  "/root",
  "/srv",
  "/opt",
  "/proc",
  "/sys",
  "/dev",
  "/run",
  "/tmp",
]);

const SshBlockSchema = z.strictObject({
  host: z.string().regex(HOST_RE).max(253).describe(
    "Hostname or IP literal of the server.",
  ),
  port: z.number().int().min(1).max(65535).default(22).describe("SSH port."),
  user: z.string().regex(USER_RE).describe("Remote login user."),
  host_key_policy: z.literal("strict").describe(
    "Required. strict verifies the host against host_keys; there is no trust-on-first-use.",
  ),
  host_keys: z.array(z.string().max(8192)).min(1).max(64).describe(
    "Pinned ssh-keyscan-format lines for the target.",
  ),
  private_key: z.string().max(65536).meta({ sensitive: true }).nullish()
    .describe(
      "Private key text, loaded into a temporary ssh-agent over stdin. Wire a vault reference; never a literal.",
    ),
  password: z.string().max(4096).meta({ sensitive: true }).nullish().describe(
    "Password, delivered through an askpass helper. Prefer private_key.",
  ),
  connect_timeout_s: z.number().int().min(1).max(120).default(15).describe(
    "Connection timeout in seconds.",
  ),
  max_output_bytes: z.number().int().min(1).max(104857600).default(10485760)
    .describe("Cap in bytes on captured output."),
});

const RootSchema = z.string().regex(ROOT_RE).refine(
  (p) => {
    if (
      p === "/" || p.split("/").some((part) => part === ".." || part === ".")
    ) {
      return false;
    }
    // At least two segments, so a bare system directory like /etc or /srv
    // can never be the served root, and a small deny list for defence in depth.
    const segments = p.split("/").filter(Boolean);
    if (segments.length < 2) return false;
    return !SYSTEM_ROOTS.has(p);
  },
  "root must be an absolute path of at least two segments, not / , with no . or .. segment and not a bare system directory",
).default("/srv/artifacts").describe(
  "Absolute served root directory with at least two segments; default /srv/artifacts.",
);

const ListenSchema = z.strictObject({
  address: z.string().max(64).refine(
    (a) =>
      a === "*" ||
      /^(\d{1,3}\.){3}\d{1,3}$/.test(a) ||
      /^[0-9A-Fa-f:]+$/.test(a),
    "listen.address must be *, an IPv4 literal or an IPv6 literal",
  ).describe("Listen address: *, an IPv4 literal or an IPv6 literal."),
  port: z.number().int().min(1).max(65535).describe("Listen port."),
});

const ServerNameSchema = z.string().max(253).refine(
  (v) => HOSTNAME_JSON_RE.test(v) || /^[0-9A-Fa-f:.]+$/.test(v),
  "server_name must be an RFC 1123 hostname or an IP literal",
);

const TlsSchema = z.discriminatedUnion("mode", [
  z.strictObject({
    mode: z.literal("none").describe("Serve plain HTTP."),
    plaintext_ack: z.literal(true).describe(
      "Required acknowledgement that HTTP carries no transport security.",
    ),
  }),
  z.strictObject({
    mode: z.literal("provided").describe("Serve the provided certificate."),
    cert_pem: z.string().min(64).max(65536).describe(
      "PEM certificate chain.",
    ),
    key_pem: z.string().min(64).max(65536).meta({ sensitive: true }).describe(
      "PEM private key. Wire a vault reference; never a literal.",
    ),
  }),
]);

const BasicAuthSchema = z.strictObject({
  realm: z.string().regex(/^[A-Za-z0-9 ._-]{1,64}$/).describe(
    "Auth realm shown to clients; letters, digits, space, dot, underscore and dash only.",
  ),
  users: z.array(
    z.strictObject({
      name: z.string().regex(/^[a-z_][a-z0-9_-]{0,31}$/).describe(
        "User name.",
      ),
      hash: z.string().regex(CRYPT_RE).meta({ sensitive: true }).describe(
        "crypt(3) password hash. Wire a vault reference; the model never sees a plaintext.",
      ),
    }),
  ).min(1).max(256).describe("Users and their crypt hashes."),
});

const CommonArgs = {
  ssh: SshBlockSchema,
  root: RootSchema,
};

export type SshBlock = z.infer<typeof SshBlockSchema>;
export type RootArgs = { ssh: SshBlock; root: string };

/** The provided-or-none TLS argument. */
export type TlsArgs = z.infer<typeof TlsSchema>;
/** The basic-auth argument. */
export type BasicAuthArgs = z.infer<typeof BasicAuthSchema>;
/** The install argument. */
export type InstallArgsType = z.infer<typeof InstallArgs>;
/** The fetch argument. */
export type FetchArgsType = z.infer<typeof FetchArgsSchema>;

export const ConfigSchema = z.strictObject({
  config_sha256: z.string(),
  text: z.string(),
  url_base: z.string(),
  rendered_at: z.string(),
});

export const ServerSchema = z.strictObject({
  host: z.string(),
  port: z.number().int(),
  user: z.string(),
  root: z.string(),
  nginx_active: z.string(),
  config_sha256: z.string().nullable(),
  tls: z.boolean(),
  basic_auth: z.boolean(),
  blobs: z.number().int(),
  bundles: z.number().int(),
  refs: z.number().int(),
  layout_version: z.number().int().nullable(),
  observed_at: z.string(),
});

export const ArtifactSchema = z.strictObject({
  sha256: z.string(),
  kind: z.enum(["blob", "bundle"]),
  path: z.string(),
  url: z.string(),
  bytes: z.number().int(),
  files: z.number().int(),
  ref: z.string().nullable(),
  changed: z.boolean(),
  written_at: z.string(),
});

export const ListingSchema = z.strictObject({
  host: z.string(),
  root: z.string(),
  refs: z.array(z.strictObject({
    name: z.string(),
    kind: z.enum(["blob", "bundle"]),
    hash: z.string(),
  })),
  blobs: z.array(z.strictObject({
    sha256: z.string(),
    filename: z.string(),
    bytes: z.number().int(),
    mtime_ms: z.number(),
  })),
  bundles: z.array(z.strictObject({
    tree_sha256: z.string(),
    bytes: z.number().int(),
    mtime_ms: z.number(),
    files: z.number().int(),
  })),
  observed_at: z.string(),
});

export const VerificationSchema = z.strictObject({
  host: z.string(),
  root: z.string(),
  ok: z.array(z.string()),
  corrupt: z.array(z.strictObject({
    path: z.string(),
    expected: z.string(),
    actual: z.string(),
  })),
  missing: z.array(z.string()),
  extra: z.array(z.string()),
  checked_at: z.string(),
});

export const PrunePlanSchema = z.strictObject({
  host: z.string(),
  root: z.string(),
  objects: z.array(z.strictObject({
    kind: z.enum(["blob", "bundle"]),
    hash: z.string(),
    path: z.string(),
    bytes: z.number().int(),
  })),
  total_bytes: z.number().int(),
  plan_sha256: z.string(),
  created_at: z.string(),
});

// ---------------------------------------------------------------------------
// Method argument schemas
// ---------------------------------------------------------------------------

export const RenderConfigArgs = z.strictObject({
  ...CommonArgs,
  listen: ListenSchema,
  server_name: ServerNameSchema,
  tls: TlsSchema,
  basic_auth: BasicAuthSchema.nullish(),
  basic_auth_plaintext_ack: z.boolean().nullish(),
});

export const InstallArgs = z.strictObject({
  ...CommonArgs,
  listen: ListenSchema,
  server_name: ServerNameSchema,
  tls: TlsSchema,
  basic_auth: BasicAuthSchema.nullish(),
  basic_auth_plaintext_ack: z.boolean().nullish(),
  disable_default_site: z.boolean().default(false).describe(
    "Remove /etc/nginx/sites-enabled/default so it cannot claim the port.",
  ),
});

export const UploadArgsSchema = z.strictObject({
  ...CommonArgs,
  filename: z.string().regex(FILENAME_RE).refine(
    (f) => f !== SHA256SUMS_FILE,
    "filename must not be SHA256SUMS",
  ).describe("Destination file name under sha256/<hex>/."),
  content: z.string().max(536870912).meta({ sensitive: true }).nullish()
    .describe("UTF-8 content. Wire a vault reference or data expression."),
  content_base64: z.string().max(715827883).meta({ sensitive: true }).nullish()
    .describe("Base64 content, for binary payloads."),
  sha256: z.string().regex(SHA256_RE).nullish().describe(
    "Expected content hash; the run refuses when the computed hash differs.",
  ),
  ref: z.string().regex(REF_RE).nullish().describe("Optional ref to set."),
  max_upload_bytes: z.number().int().min(1).max(536870912).default(67108864)
    .describe("Reject content larger than this many bytes."),
});

export const FetchArgsSchema = z.strictObject({
  ...CommonArgs,
  url: z.string().max(2048).regex(
    FETCH_URL_RE,
    "fetch.url must be an https URL with no userinfo, whitespace, quote or semicolon",
  ).describe("Upstream https URL to download on the host."),
  filename: z.string().regex(FILENAME_RE).refine(
    (f) => f !== SHA256SUMS_FILE,
    "filename must not be SHA256SUMS",
  ).describe("Destination file name under sha256/<hex>/."),
  sha256: z.string().regex(SHA256_RE).describe(
    "Required pinned hash; the object is kept only when the download matches.",
  ),
  ref: z.string().regex(REF_RE).nullish().describe("Optional ref to set."),
  max_bytes: z.number().int().min(1).max(1073741824).default(1073741824)
    .describe(
      "Refuse a download larger than this many bytes (default 1 GiB).",
    ),
});

export const PublishBundleArgs = z.strictObject({
  ...CommonArgs,
  files: z.array(
    z.strictObject({
      name: z.string().regex(FILENAME_RE).describe("Bundle file name."),
      content: z.string().max(67108864).meta({ sensitive: true }).nullish()
        .describe("UTF-8 content. Wire a vault reference."),
      content_base64: z.string().max(89478486).meta({ sensitive: true })
        .nullish().describe("Base64 content."),
    }),
  ).min(1).max(256).describe("Named files that make up the bundle."),
  ref: z.string().regex(REF_RE).nullish().describe("Optional ref to set."),
});

export const RefArgs = z.strictObject({
  ...CommonArgs,
  ref: z.string().regex(REF_RE).describe("Ref name."),
  kind: z.enum(["blob", "bundle"]).describe("Target kind."),
  hash: z.string().regex(SHA256_RE).describe("Blob hash or bundle tree hash."),
});

export const UnrefArgs = z.strictObject({
  ...CommonArgs,
  ref: z.string().regex(REF_RE).describe("Ref name."),
});

export const ListArgs = z.strictObject({ ...CommonArgs });

export const VerifyArgs = z.strictObject({ ...CommonArgs });

export const GetArgs = z.strictObject({ ...CommonArgs });

export const PlanPruneArgs = z.strictObject({
  ...CommonArgs,
  keep: z.array(z.string().regex(SHA256_RE)).max(10000).default([]).describe(
    "Hashes to keep even when unreferenced.",
  ),
});

export const PruneArgs = z.strictObject({
  ...CommonArgs,
  plan_sha256: z.string().regex(SHA256_RE).describe(
    "The plan hash from plan_prune; refuse when the recomputed plan differs.",
  ),
  keep: z.array(z.string().regex(SHA256_RE)).max(10000).default([]).describe(
    "The same keep list used to plan; hashes to keep even when unreferenced.",
  ),
});

export const UninstallArgs = z.strictObject({
  ...CommonArgs,
  remove_data: z.boolean().default(false).describe(
    "Also remove the served root directory.",
  ),
});
