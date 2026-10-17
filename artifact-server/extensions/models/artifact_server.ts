/**
 * Swamp extension model for a static artifact server: serve a directory of
 * pinned artifacts over HTTP(S) from one host and manage it over SSH.
 *
 * The model is generic: it holds no host, path or credential in its
 * definition. Every method takes its SSH target and `root` as arguments, and
 * stored data is keyed by the canonical target plus root, never the definition
 * name. Consumers fetch bytes by content hash; the server is a cache, not a
 * source of trust.
 *
 * @module
 */

import { z } from "npm:zod@4.3.6";
import {
  assertHost,
  assertUser,
  denoDeps,
  HOST_RE,
  type HostKeyPolicy,
  posixQuote,
  sha256Hex,
  SshConfigError,
  type SshDeps,
  SshError,
  type SshTarget,
  USER_RE,
} from "./_lib/ssh.ts";
import {
  BLOB_DIR,
  blobRelPath,
  blobUrl,
  BUNDLE_DIR,
  bundleUrl,
  LAYOUT_VERSION,
  LAYOUT_VERSION_FILE,
  LOCK_FILE,
  parseSha256Sums,
  planPrune,
  type PruneObject,
  REFS_DIR,
  SHA256SUMS_FILE,
  treeHash,
  urlBase,
} from "./_lib/layout.ts";
import {
  HTPASSWD_PATH,
  NGINX_DEFAULT_SITE,
  NGINX_ENABLED_PATH,
  NGINX_SITE_PATH,
  renderSite,
  TLS_CERT_PATH,
  TLS_KEY_PATH,
} from "./_lib/nginx.ts";
import { validateTls } from "./_lib/tls.ts";
import {
  execSudo,
  makeParentDir,
  probeFile,
  putRootFile,
  putUserFile,
  runScript,
} from "./_lib/remote.ts";
import {
  readFileText,
  readLayout,
  readLink,
  readNginxState,
} from "./_lib/observe.ts";
import {
  regenerateSha256Sums,
  removeObjects,
  removeRoot,
  setRef,
  unsetRef,
} from "./_lib/ops.ts";

/** A handle returned by `writeResource`. */
export interface DataHandle {
  /** Data artifact name. */
  name: string;
  /** Declared resource spec name. */
  specName: string;
  /** `"resource"` or `"file"`. */
  kind: string;
  /** Unique data id. */
  dataId: string;
  /** Version number of this write. */
  version: number;
  /** Size of the written content in bytes. */
  size: number;
}

/** What a method returns to swamp. */
export interface MethodResult {
  /** Resources written by the method. */
  dataHandles?: DataHandle[];
  /** Typed result for the caller / workflow. */
  result?: unknown;
}

/** The subset of the swamp method context this model uses. */
export interface MethodContext {
  /** Structured logger provided by swamp. */
  logger: {
    /** Logs at info level. */
    info: (message: string, fields?: Record<string, unknown>) => void;
    /** Logs at warn level. */
    warn: (message: string, fields?: Record<string, unknown>) => void;
  };
  /** Persists one resource and returns its handle. */
  writeResource: (
    specName: string,
    instanceName: string,
    data: Record<string, unknown>,
  ) => Promise<DataHandle>;
  /** Reads the latest version of one stored resource, or null. */
  readResource?: (
    instanceName: string,
  ) => Promise<Record<string, unknown> | null>;
}

/** A resource specification exposed by the model. */
export interface ResourceSpec {
  /** Human-readable description of the resource. */
  description: string;
  /** Zod schema the resource data is validated against. */
  schema: z.ZodType;
  /** Retention lifetime. */
  lifetime: string;
  /** Number of versions to keep. */
  garbageCollection: number;
}

/** A method exposed by the model. */
export interface ArtifactServerMethod {
  /** `action` for a mutating verb; never a bare `delete`. */
  kind?: "action";
  /** One to three sentences, with the READ-ONLY or DESTRUCTIVE lead. */
  description: string;
  /** Zod schema for the method arguments. */
  arguments: z.ZodType;
  /** Runs the method. */
  execute: (args: unknown, context: MethodContext) => Promise<MethodResult>;
}

/** The model definition returned by {@link createModel}. */
export interface ArtifactServerModel {
  /** Model type. */
  type: string;
  /** CalVer version, matching the manifest. */
  version: string;
  /** One-line summary for `swamp model type describe`. */
  description: string;
  /** Empty: every method takes its own target. */
  globalArguments: z.ZodType;
  /** Resource specifications. */
  resources: Record<string, ResourceSpec>;
  /** Method implementations. */
  methods: Record<string, ArtifactServerMethod>;
}

const HOSTNAME_JSON_RE =
  /^(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$/;
const ROOT_RE = /^\/[A-Za-z0-9._/-]{1,255}$/;
const SHA256_RE = /^[0-9a-f]{64}$/;
const FILENAME_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;
const REF_RE = /^[a-z0-9][a-z0-9._-]{0,63}$/;
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

type SshBlock = z.infer<typeof SshBlockSchema>;
type RootArgs = { ssh: SshBlock; root: string };

/** Maps the SSH block onto a transport target, refusing bad combinations. */
function toTarget(ssh: SshBlock): SshTarget {
  assertHost(ssh.host);
  assertUser(ssh.user);
  if (ssh.private_key && ssh.password) {
    throw new SshConfigError("pass private_key or password, not both");
  }
  return {
    host: ssh.host,
    port: ssh.port,
    user: ssh.user,
    host_key_policy: ssh.host_key_policy as HostKeyPolicy,
    host_keys: ssh.host_keys,
    private_key: ssh.private_key ?? undefined,
    password: ssh.password ?? undefined,
    connect_timeout_s: ssh.connect_timeout_s,
    max_output_bytes: ssh.max_output_bytes,
  };
}

/** The stable data key for one target and root. */
/** Replaces every character outside `[A-Za-z0-9._-]` with `_`. */
function sanitizeKey(value: string): string {
  return value.replace(/[^A-Za-z0-9._-]/g, "_");
}

/** A short, stable FNV-1a hash in hex, to keep encoded keys distinct. */
function shortKeyHash(value: string): string {
  let h = 2166136261 >>> 0;
  for (let i = 0; i < value.length; i++) {
    h ^= value.charCodeAt(i);
    h = Math.imul(h, 16777619) >>> 0;
  }
  return h.toString(16).padStart(8, "0");
}

/**
 * The stable data key for one target and root. The target and root are encoded
 * so no `/`, `:` or other unsafe character reaches a resource instance name,
 * and a short hash keeps distinct targets from colliding after encoding.
 */
function instanceKey(args: RootArgs): string {
  const raw = `${args.ssh.host}:${args.ssh.port}/${args.ssh.user}@${args.root}`;
  const host = sanitizeKey(args.ssh.host).slice(0, 40);
  const user = sanitizeKey(args.ssh.user).slice(0, 16);
  const root = sanitizeKey(args.root).slice(0, 32);
  return `${host}-${args.ssh.port}-${user}-${root}-${shortKeyHash(raw)}`;
}

/** Decodes `content`/`content_base64`, refusing both or neither. */
function contentBytes(args: {
  content?: string | null;
  content_base64?: string | null;
}): Uint8Array {
  if (args.content != null && args.content_base64 != null) {
    throw new SshConfigError("pass content or content_base64, not both");
  }
  if (args.content != null) return new TextEncoder().encode(args.content);
  if (args.content_base64 != null) return base64Decode(args.content_base64);
  throw new SshConfigError("content is required");
}

/** Decodes strict base64, refusing invalid input. */
function base64Decode(value: string): Uint8Array {
  const binary = atob(value);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
  return out;
}

/** Validates the shared preconditions that need no remote call. */
function validateCommon(
  args: RootArgs & {
    tls: z.infer<typeof TlsSchema>;
    basic_auth?: z.infer<typeof BasicAuthSchema> | null;
    basic_auth_plaintext_ack?: boolean | null;
  },
): void {
  if (
    args.basic_auth && args.tls.mode === "none" &&
    args.basic_auth_plaintext_ack !== true
  ) {
    throw new SshConfigError(
      "basic auth over plain HTTP requires basic_auth_plaintext_ack: true",
    );
  }
}

// ---------------------------------------------------------------------------
// Resources
// ---------------------------------------------------------------------------

const ConfigSchema = z.strictObject({
  config_sha256: z.string(),
  text: z.string(),
  url_base: z.string(),
  rendered_at: z.string(),
});

const ServerSchema = z.strictObject({
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

const ArtifactSchema = z.strictObject({
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

const ListingSchema = z.strictObject({
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

const VerificationSchema = z.strictObject({
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

const PrunePlanSchema = z.strictObject({
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

const RenderConfigArgs = z.strictObject({
  ...CommonArgs,
  listen: ListenSchema,
  server_name: ServerNameSchema,
  tls: TlsSchema,
  basic_auth: BasicAuthSchema.nullish(),
  basic_auth_plaintext_ack: z.boolean().nullish(),
});

const InstallArgs = z.strictObject({
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

const UploadArgsSchema = z.strictObject({
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

const FetchArgsSchema = z.strictObject({
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

const PublishBundleArgs = z.strictObject({
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

const RefArgs = z.strictObject({
  ...CommonArgs,
  ref: z.string().regex(REF_RE).describe("Ref name."),
  kind: z.enum(["blob", "bundle"]).describe("Target kind."),
  hash: z.string().regex(SHA256_RE).describe("Blob hash or bundle tree hash."),
});

const UnrefArgs = z.strictObject({
  ...CommonArgs,
  ref: z.string().regex(REF_RE).describe("Ref name."),
});

const ListArgs = z.strictObject({ ...CommonArgs });

const VerifyArgs = z.strictObject({ ...CommonArgs });

const GetArgs = z.strictObject({ ...CommonArgs });

const PlanPruneArgs = z.strictObject({
  ...CommonArgs,
  keep: z.array(z.string().regex(SHA256_RE)).max(10000).default([]).describe(
    "Hashes to keep even when unreferenced.",
  ),
});

const PruneArgs = z.strictObject({
  ...CommonArgs,
  plan_sha256: z.string().regex(SHA256_RE).describe(
    "The plan hash from plan_prune; refuse when the recomputed plan differs.",
  ),
  keep: z.array(z.string().regex(SHA256_RE)).max(10000).default([]).describe(
    "The same keep list used to plan; hashes to keep even when unreferenced.",
  ),
});

const UninstallArgs = z.strictObject({
  ...CommonArgs,
  remove_data: z.boolean().default(false).describe(
    "Also remove the served root directory.",
  ),
});

// ---------------------------------------------------------------------------
// Model factory
// ---------------------------------------------------------------------------

/** The active transport dependencies; production uses the real runner. */
let activeDeps: SshDeps = denoDeps;

/** Swaps the transport dependencies. Tests use this; production never does. */
export function setDeps(next: SshDeps): void {
  activeDeps = next;
}

/** Renders the site config for a method's inputs. */
const renderFor = (
  root: string,
  listen: { address: string; port: number },
  serverName: string,
  tls: z.infer<typeof TlsSchema>,
  basicAuth: z.infer<typeof BasicAuthSchema> | null | undefined,
): string =>
  renderSite({
    root,
    listen,
    serverName,
    tlsProvided: tls.mode === "provided",
    basicAuth: basicAuth != null,
    basicAuthRealm: basicAuth?.realm ?? "",
  });

const writeArtifact = async (
  context: MethodContext,
  args: RootArgs,
  data: {
    sha256: string;
    kind: "blob" | "bundle";
    path: string;
    url: string;
    bytes: number;
    files: number;
    ref?: string | null;
    changed: boolean;
  },
): Promise<DataHandle> =>
  await context.writeResource(
    "artifact",
    `artifact-${instanceKey(args)}-${data.sha256}`,
    ArtifactSchema.parse({
      ...data,
      ref: data.ref ?? null,
      written_at: new Date(activeDeps.now()).toISOString(),
    }),
  );

/** The artifact-server model: a plain object literal. */
export const model: ArtifactServerModel = {
  type: "@randybias/artifact-server",
  version: "2026.10.17.1",
  description:
    "Serve a directory of pinned artifacts over HTTP(S) from one host and manage it over SSH: nginx site config, upload, host-side fetch, bundles, refs, listing, verification and prune. One generic definition with no host, path or credential in it.",
  globalArguments: z.strictObject({}),
  resources: {
    config: {
      description: "Rendered nginx site config and its hash",
      schema: ConfigSchema,
      lifetime: "infinite",
      garbageCollection: 10,
    },
    server: {
      description: "Observed nginx state and layout summary",
      schema: ServerSchema,
      lifetime: "infinite",
      garbageCollection: 10,
    },
    artifact: {
      description: "One stored blob or bundle: hash, path, url, size",
      schema: ArtifactSchema,
      lifetime: "infinite",
      garbageCollection: 5,
    },
    listing: {
      description: "Refs, blobs and bundles with sizes and mtimes",
      schema: ListingSchema,
      lifetime: "infinite",
      garbageCollection: 10,
    },
    verification: {
      description: "Objects rehashed and compared against SHA256SUMS",
      schema: VerificationSchema,
      lifetime: "infinite",
      garbageCollection: 10,
    },
    prune_plan: {
      description: "Objects not reachable from a ref or keep list",
      schema: PrunePlanSchema,
      lifetime: "1d",
      garbageCollection: 10,
    },
  },
  methods: {
    render_config: {
      description:
        "READ-ONLY. Render the nginx site config for the given inputs and persist it; deterministic, and contains no secret, only paths to secret files.",
      arguments: RenderConfigArgs,
      execute: async (rawArgs: unknown, context: MethodContext) => {
        const args = RenderConfigArgs.parse(rawArgs);
        validateCommon(args);
        if (args.tls.mode === "provided") {
          await validateTls(activeDeps, args.tls.cert_pem, args.tls.key_pem);
        }
        const text = renderFor(
          args.root,
          args.listen,
          args.server_name,
          args.tls,
          args.basic_auth,
        );
        const configSha = await sha256Hex(text);
        const base = urlBase(
          args.server_name,
          args.listen.port,
          args.tls.mode === "provided" ? "https" : "http",
        );
        const handle = await context.writeResource(
          "config",
          `config-${instanceKey(args)}`,
          ConfigSchema.parse({
            config_sha256: configSha,
            text,
            url_base: base,
            rendered_at: new Date(activeDeps.now()).toISOString(),
          }),
        );
        return {
          dataHandles: [handle],
          result: { config_sha256: configSha, url_base: base, text },
        };
      },
    },

    install: {
      kind: "action",
      description:
        "DESTRUCTIVE. Install nginx, create the served layout, write the site config, htpasswd and TLS files, prove the config with nginx -t and reload. Idempotent: the same rendered config is not reloaded. A failed nginx -t restores the previous config and never reloads.",
      arguments: InstallArgs,
      execute: async (rawArgs: unknown, context: MethodContext) => {
        const args = InstallArgs.parse(rawArgs);
        validateCommon(args);
        if (args.tls.mode === "provided") {
          await validateTls(activeDeps, args.tls.cert_pem, args.tls.key_pem);
        }
        const target = toTarget(args.ssh);
        const rootKind = await rootState(activeDeps, target, args.root);
        if (rootKind === "foreign") {
          throw new SshError(
            `refusing to install into ${args.root}: it exists but holds no regular ${LAYOUT_VERSION_FILE} sentinel`,
          );
        }

        const nginx = await execSudo(activeDeps, target, [
          "apt-get",
          "install",
          "-y",
          "nginx",
        ]);
        if (nginx.exit_code !== 0) {
          throw new SshError("could not install nginx");
        }

        // Snapshot every file and link this run may touch, before touching any
        // of them, so a failed nginx -t can restore the whole host.
        const snapSite = await snapFile(activeDeps, target, NGINX_SITE_PATH);
        const snapCert = args.tls.mode === "provided"
          ? await snapFile(activeDeps, target, TLS_CERT_PATH)
          : null;
        const snapKey = args.tls.mode === "provided"
          ? await snapFile(activeDeps, target, TLS_KEY_PATH)
          : null;
        const snapHtpasswd = args.basic_auth
          ? await snapFile(activeDeps, target, HTPASSWD_PATH)
          : null;
        const snapEnabled = await snapLink(
          activeDeps,
          target,
          NGINX_ENABLED_PATH,
        );
        const snapDefault = args.disable_default_site
          ? await snapLink(activeDeps, target, NGINX_DEFAULT_SITE)
          : null;

        const mk = await execSudo(activeDeps, target, [
          "install",
          "-d",
          "-o",
          args.ssh.user,
          "-g",
          args.ssh.user,
          "-m",
          "0755",
          args.root,
          `${args.root}/${BLOB_DIR}`,
          `${args.root}/${BUNDLE_DIR}`,
          `${args.root}/${REFS_DIR}`,
        ]);
        if (mk.exit_code !== 0) {
          throw new SshError("could not create the layout");
        }
        await putUserFile(
          activeDeps,
          target,
          `${args.root}/${LOCK_FILE}`,
          "",
          "0644",
        );
        await putUserFile(
          activeDeps,
          target,
          `${args.root}/${LAYOUT_VERSION_FILE}`,
          `${LAYOUT_VERSION}\n`,
          "0644",
        );

        const text = renderFor(
          args.root,
          args.listen,
          args.server_name,
          args.tls,
          args.basic_auth,
        );
        const configSha = await sha256Hex(text);
        const site = await putRootFile(activeDeps, target, {
          path: NGINX_SITE_PATH,
          content: text,
          mode: "0644",
          owner: "root",
          group: "root",
        });
        const link = await execSudo(activeDeps, target, [
          "ln",
          "-sfn",
          NGINX_SITE_PATH,
          NGINX_ENABLED_PATH,
        ]);
        if (link.exit_code !== 0) {
          throw new SshError("could not enable the site");
        }
        const enabledChanged = snapEnabled.state !== "symlink" ||
          snapEnabled.target !== NGINX_SITE_PATH;
        let changed = site.changed || enabledChanged;
        if (args.disable_default_site) {
          const rm = await execSudo(activeDeps, target, [
            "rm",
            "-f",
            NGINX_DEFAULT_SITE,
          ]);
          changed = changed ||
            (rm.exit_code === 0 && snapDefault !== null &&
              snapDefault.state !== "missing");
        }
        if (args.tls.mode === "provided") {
          const sslDir = TLS_CERT_PATH.slice(
            0,
            TLS_CERT_PATH.lastIndexOf("/"),
          );
          const madeSsl = await execSudo(activeDeps, target, [
            "install",
            "-d",
            "-m",
            "0755",
            sslDir,
          ]);
          if (madeSsl.exit_code !== 0) {
            throw new SshError(`could not create ${sslDir}`);
          }
          const cert = await putRootFile(activeDeps, target, {
            path: TLS_CERT_PATH,
            content: args.tls.cert_pem,
            mode: "0644",
            owner: "root",
            group: "root",
          });
          const key = await putRootFile(activeDeps, target, {
            path: TLS_KEY_PATH,
            content: args.tls.key_pem,
            mode: "0600",
            owner: "root",
            group: "root",
          });
          changed = changed || cert.changed || key.changed;
        }
        if (args.basic_auth) {
          const htpasswd = args.basic_auth.users.map((u) =>
            `${u.name}:${u.hash}`
          ).join("\n") + "\n";
          const file = await putRootFile(activeDeps, target, {
            path: HTPASSWD_PATH,
            content: htpasswd,
            mode: "0640",
            owner: "root",
            group: "www-data",
          });
          changed = changed || file.changed;
        }

        const test = await execSudo(activeDeps, target, ["nginx", "-t"]);
        if (test.exit_code !== 0) {
          // Restore everything this run changed, then confirm the restored
          // config is one nginx accepts. A dangling enabled link from a first
          // install is removed, so the next host-wide nginx -t stays clean.
          await restoreFile(activeDeps, target, snapSite);
          await restoreLink(activeDeps, target, snapEnabled);
          if (snapDefault !== null) {
            await restoreLink(activeDeps, target, snapDefault);
          }
          if (snapCert !== null) {
            await restoreFile(activeDeps, target, snapCert);
          }
          if (snapKey !== null) await restoreFile(activeDeps, target, snapKey);
          if (snapHtpasswd !== null) {
            await restoreFile(activeDeps, target, snapHtpasswd);
          }
          const retest = await execSudo(activeDeps, target, ["nginx", "-t"]);
          throw new SshError(
            `nginx -t failed on the rendered config; rolled back and not reloaded${
              retest.exit_code !== 0
                ? " (the restored config also fails nginx -t)"
                : ""
            }: ${test.stderr.slice(0, 300)}`,
          );
        }
        if (changed) {
          const reload = await execSudo(activeDeps, target, [
            "systemctl",
            "reload",
            "nginx",
          ]);
          if (reload.exit_code !== 0) {
            throw new SshError("nginx reload failed");
          }
        }
        const scheme = args.tls.mode === "provided" ? "https" : "http";
        const base = urlBase(args.server_name, args.listen.port, scheme);
        const handle = await context.writeResource(
          "config",
          `config-${instanceKey(args)}`,
          ConfigSchema.parse({
            config_sha256: configSha,
            text,
            url_base: base,
            rendered_at: new Date(activeDeps.now()).toISOString(),
          }),
        );
        context.logger.info("Installed artifact server on {host}:{port}", {
          host: args.ssh.host,
          port: args.listen.port,
        });
        return {
          dataHandles: [handle],
          result: { config_sha256: configSha, url_base: base, changed },
        };
      },
    },

    upload: {
      kind: "action",
      description:
        "Idempotent. Push bytes to sha256/<hex>/<filename> over stdin and regenerate SHA256SUMS; refuses when the computed hash differs from a supplied sha256. Optionally sets a ref. Returns the hash, path, url and whether anything changed.",
      arguments: UploadArgsSchema,
      execute: async (rawArgs: unknown, context: MethodContext) => {
        const args = UploadArgsSchema.parse(rawArgs);
        const bytes = contentBytes(args);
        if (bytes.length > args.max_upload_bytes) {
          throw new SshConfigError(
            `content is ${bytes.length} bytes, over max_upload_bytes ${args.max_upload_bytes}`,
          );
        }
        const hash = await sha256Hex(bytes);
        if (args.sha256 != null && args.sha256 !== hash) {
          throw new SshConfigError(
            `computed sha256 ${hash} does not match the supplied ${args.sha256}`,
          );
        }
        const target = toTarget(args.ssh);
        const rel = blobRelPath({ sha256: hash, filename: args.filename });
        await makeParentDir(activeDeps, target, `${args.root}/${rel}`);
        const put = await putUserFile(
          activeDeps,
          target,
          `${args.root}/${rel}`,
          bytes,
          "0644",
        );
        await regenerateSha256Sums(activeDeps, target, args.root);
        if (args.ref != null) {
          await setRef(activeDeps, target, args.root, args.ref, "blob", hash);
        }
        const base = await resolveBase(context, args);
        const url = blobUrl(base, { sha256: hash, filename: args.filename });
        const handle = await writeArtifact(context, args, {
          sha256: hash,
          kind: "blob",
          path: rel,
          url,
          bytes: bytes.length,
          files: 1,
          ref: args.ref,
          changed: put.changed,
        });
        return {
          dataHandles: [handle],
          result: { sha256: hash, path: rel, url, changed: put.changed },
        };
      },
    },

    fetch: {
      kind: "action",
      description:
        "Idempotent. Download one https upstream on the host to a hidden temp file, compare the host's SHA-256 to the required pin, and only then rename it into sha256/<hex>/<filename>; a mismatch removes the temp and changes nothing. Optionally sets a ref.",
      arguments: FetchArgsSchema,
      execute: async (rawArgs: unknown, context: MethodContext) => {
        const args = FetchArgsSchema.parse(rawArgs);
        const target = toTarget(args.ssh);
        const token = (await sha256Hex(
          `${activeDeps.now()}-${
            crypto.getRandomValues(new Uint32Array(4)).join("")
          }`,
        )).slice(0, 16);
        const tempRel = `.fetch.${token}`;
        const temp = `${args.root}/${tempRel}`;
        const destRel = blobRelPath({
          sha256: args.sha256,
          filename: args.filename,
        });
        const dest = `${args.root}/${destRel}`;
        const before = await probeFile(activeDeps, target, dest);
        if (before.state === "file" && before.sha256 === args.sha256) {
          // Already stored with the pinned bytes: no download, no change.
          if (args.ref != null) {
            await setRef(
              activeDeps,
              target,
              args.root,
              args.ref,
              "blob",
              args.sha256,
            );
          }
          const base = await resolveBase(context, args);
          const url = blobUrl(base, {
            sha256: args.sha256,
            filename: args.filename,
          });
          const handle = await writeArtifact(context, args, {
            sha256: args.sha256,
            kind: "blob",
            path: destRel,
            url,
            bytes: before.size ?? 0,
            files: 1,
            ref: args.ref,
            changed: false,
          });
          return {
            dataHandles: [handle],
            result: {
              sha256: args.sha256,
              path: destRel,
              url,
              changed: false,
            },
          };
        }
        if (before.state === "symlink") {
          throw new SshError(
            `${dest} is a symlink; refusing to write through it`,
          );
        }
        const script = [
          `set -e`,
          `curl -fsS -L --max-redirs 5 --max-filesize ${args.max_bytes} --proto '=https' --proto-redir '=https' -o ${
            posixQuote(temp)
          } ${posixQuote(args.url)}`,
          `s=$(stat -c %s ${posixQuote(temp)} 2>/dev/null || echo 0)`,
          `[ "$s" -le ${args.max_bytes} ] || { echo "too large" >&2; exit 4; }`,
          `{ sha256sum ${posixQuote(temp)} 2>/dev/null || shasum -a 256 ${
            posixQuote(temp)
          } 2>/dev/null; } | awk '{print $1}'`,
        ].join("\n");
        const download = await runScript(activeDeps, target, script);
        if (download.exit_code !== 0) {
          await runScript(activeDeps, target, `rm -f ${posixQuote(temp)}`)
            .catch(
              () => undefined,
            );
          throw new SshError(
            "the upstream download failed; no object stored",
          );
        }
        const actual = download.stdout.trim().split(/\s+/)[0] ?? "";
        if (actual !== args.sha256) {
          await runScript(activeDeps, target, `rm -f ${posixQuote(temp)}`)
            .catch(
              () => undefined,
            );
          throw new SshError(
            `downloaded content hash ${actual} does not match the pinned ${args.sha256}; temp removed`,
          );
        }
        const move = await runScript(
          activeDeps,
          target,
          `mkdir -p ${
            posixQuote(dest.slice(0, dest.lastIndexOf("/")))
          } && mv -T ${posixQuote(temp)} ${posixQuote(dest)}`,
        );
        if (move.exit_code !== 0) {
          throw new SshError(
            "could not move the downloaded object into place",
          );
        }
        await regenerateSha256Sums(activeDeps, target, args.root);
        if (args.ref != null) {
          await setRef(
            activeDeps,
            target,
            args.root,
            args.ref,
            "blob",
            args.sha256,
          );
        }
        const after = await probeFile(activeDeps, target, dest);
        const base = await resolveBase(context, args);
        const url = blobUrl(base, {
          sha256: args.sha256,
          filename: args.filename,
        });
        const handle = await writeArtifact(context, args, {
          sha256: args.sha256,
          kind: "blob",
          path: destRel,
          url,
          bytes: after.size ?? 0,
          files: 1,
          ref: args.ref,
          changed: true,
        });
        return {
          dataHandles: [handle],
          result: { sha256: args.sha256, path: destRel, url, changed: true },
        };
      },
    },

    publish_bundle: {
      kind: "action",
      description:
        "Idempotent. Write a set of small named files under bundles/<tree-hash>/ where the tree hash is the SHA-256 of the bundle's sorted SHA256SUMS lines, for seed directories with fixed names. Optionally sets a ref; returns the tree hash and a URL ending in /.",
      arguments: PublishBundleArgs,
      execute: async (rawArgs: unknown, context: MethodContext) => {
        const args = PublishBundleArgs.parse(rawArgs);
        const target = toTarget(args.ssh);
        const decoded = args.files.map((f) => ({
          name: f.name,
          bytes: contentBytes(f),
        }));
        const names = decoded.map((f) => f.name);
        if (new Set(names).size !== names.length) {
          throw new SshConfigError("bundle file names must be unique");
        }
        const files = [];
        for (const f of decoded) {
          files.push({ name: f.name, sha256: await sha256Hex(f.bytes) });
        }
        const tree = await treeHash(files, (t) => sha256Hex(t));
        const token = (await sha256Hex(
          `${activeDeps.now()}-${
            crypto.getRandomValues(new Uint32Array(4)).join("")
          }`,
        )).slice(0, 16);
        const stage = `${args.root}/${BUNDLE_DIR}/.stage-${token}`;
        const final = `${args.root}/${BUNDLE_DIR}/${tree}`;
        // Stage into a hidden dot-directory, which the site config denies and
        // the layout reader ignores, then publish the directory in one rename.
        for (const f of decoded) {
          await makeParentDir(activeDeps, target, `${stage}/${f.name}`);
          await putUserFile(
            activeDeps,
            target,
            `${stage}/${f.name}`,
            f.bytes,
            "0644",
          );
        }
        const finalProbe = await probeFile(activeDeps, target, final);
        if (finalProbe.state === "symlink") {
          throw new SshError(
            `${final} is a symlink; refusing to write through it`,
          );
        }
        const commit = await runScript(
          activeDeps,
          target,
          `if [ -e ${posixQuote(final)} ]; then rm -rf ${
            posixQuote(stage)
          }; else mv -T ${posixQuote(stage)} ${posixQuote(final)}; fi`,
        );
        if (commit.exit_code !== 0) {
          throw new SshError("could not publish the bundle");
        }
        const changed = finalProbe.state === "missing";
        if (args.ref != null) {
          await setRef(activeDeps, target, args.root, args.ref, "bundle", tree);
        }
        const base = await resolveBase(context, args);
        const url = bundleUrl(base, tree);
        const total = decoded.reduce((sum, f) => sum + f.bytes.length, 0);
        const handle = await writeArtifact(context, args, {
          sha256: tree,
          kind: "bundle",
          path: `${BUNDLE_DIR}/${tree}`,
          url,
          bytes: total,
          files: files.length,
          ref: args.ref,
          changed,
        });
        return { dataHandles: [handle], result: { tree_sha256: tree, url } };
      },
    },

    ref: {
      kind: "action",
      description:
        "Idempotent. Point a named ref at a blob or bundle hash; refs make an object referenced and thus protected from prune.",
      arguments: RefArgs,
      execute: async (rawArgs: unknown, context: MethodContext) => {
        const args = RefArgs.parse(rawArgs);
        const target = toTarget(args.ssh);
        await setRef(
          activeDeps,
          target,
          args.root,
          args.ref,
          args.kind,
          args.hash,
        );
        context.logger.info("Set ref {ref} -> {hash}", {
          ref: args.ref,
          hash: args.hash,
        });
        return {
          result: { ref: args.ref, kind: args.kind, hash: args.hash },
        };
      },
    },

    unref: {
      kind: "action",
      description:
        "DESTRUCTIVE. Remove a named ref; an absent ref is a clean no-op. Removing a ref can make its object unreachable and eligible for prune.",
      arguments: UnrefArgs,
      execute: async (rawArgs: unknown, _context: MethodContext) => {
        const args = UnrefArgs.parse(rawArgs);
        const target = toTarget(args.ssh);
        const existed = await unsetRef(activeDeps, target, args.root, args.ref);
        return { result: { ref: args.ref, removed: existed } };
      },
    },

    list: {
      description:
        "READ-ONLY. Read refs, blobs and bundles with their sizes and mtimes from the host and persist the listing. Never returns a digest of secret content.",
      arguments: ListArgs,
      execute: async (rawArgs: unknown, context: MethodContext) => {
        const args = ListArgs.parse(rawArgs);
        const target = toTarget(args.ssh);
        const layout = await readLayout(activeDeps, target, args.root);
        const handle = await context.writeResource(
          "listing",
          `listing-${instanceKey(args)}`,
          ListingSchema.parse({
            host: args.ssh.host,
            root: args.root,
            refs: layout.refs,
            blobs: layout.blobs.map((b) => ({
              sha256: b.hash,
              filename: b.name,
              bytes: b.bytes,
              mtime_ms: b.mtimeMs,
            })),
            bundles: layout.bundles.map((b) => ({
              tree_sha256: b.hash,
              bytes: b.bytes,
              mtime_ms: b.mtimeMs,
              files: 0,
            })),
            observed_at: new Date(activeDeps.now()).toISOString(),
          }),
        );
        return {
          dataHandles: [handle],
          result: {
            refs: layout.refs.length,
            blobs: layout.blobs.length,
            bundles: layout.bundles.length,
          },
        };
      },
    },

    verify: {
      description:
        "READ-ONLY. Rehash every object on the host and compare each blob against its path hash and against SHA256SUMS; reports ok, corrupt, missing and extra and never repairs.",
      arguments: VerifyArgs,
      execute: async (rawArgs: unknown, context: MethodContext) => {
        const args = VerifyArgs.parse(rawArgs);
        const target = toTarget(args.ssh);
        const layout = await readLayout(activeDeps, target, args.root);
        const script = [
          `set -u`,
          `r=${posixQuote(args.root)}`,
          `if [ -d "$r/${BLOB_DIR}" ]; then`,
          `  find "$r/${BLOB_DIR}" -type f ! -name '.*' 2>/dev/null | LC_ALL=C sort | while IFS= read -r f; do`,
          `    rel="\${f#"$r/"}"`,
          `    h=$( { sha256sum "$f" 2>/dev/null || shasum -a 256 "$f" 2>/dev/null; } | awk '{print $1}' )`,
          `    printf 'BLOB\\t%s\\t%s\\n' "$rel" "$h"`,
          `  done`,
          `fi`,
          `if [ -d "$r/${BUNDLE_DIR}" ]; then`,
          `  for d in "$r/${BUNDLE_DIR}"/*/; do`,
          `    [ -d "$d" ] || continue`,
          `    tree="\${d%/}"; tree="\${tree##*/}"`,
          `    lines=$(mktemp)`,
          `    find "$d" -type f 2>/dev/null | LC_ALL=C sort | while IFS= read -r f; do`,
          `      sha256sum "$f" 2>/dev/null | awk -v n="\${f##*/}" '{print $1"  "n}'`,
          `    done > "$lines"`,
          `    h=$(sha256sum "$lines" 2>/dev/null | awk '{print $1}')`,
          `    rm -f "$lines"`,
          `    printf 'BUNDLE\\t%s\\t%s\\n' "$tree" "$h"`,
          `  done`,
          `fi`,
        ].join("\n");
        const raw = await runScript(activeDeps, target, script);
        if (raw.exit_code !== 0) {
          throw new SshError("verify could not read the objects");
        }
        const expected = new Map(
          parseSha256Sums(layout.sha256sums ?? "").map((
            e,
          ) => [e.path, e.sha256]),
        );
        const ok: string[] = [];
        const corrupt: { path: string; expected: string; actual: string }[] =
          [];
        const seen = new Set<string>();
        for (const line of raw.stdout.split("\n")) {
          const [kind, rel, actual] = line.split("\t");
          if (kind === "BLOB" && rel && actual) {
            seen.add(rel);
            const pathHash = rel.split("/")[1] ?? "";
            const sumsHash = expected.get(rel);
            const bad = actual !== pathHash ||
              (sumsHash !== undefined && sumsHash !== pathHash);
            if (bad) {
              corrupt.push({
                path: rel,
                expected: sumsHash ?? pathHash,
                actual,
              });
            } else {
              ok.push(rel);
            }
          } else if (kind === "BUNDLE" && rel && actual) {
            if (actual === rel) ok.push(`${BUNDLE_DIR}/${rel}`);
            else {corrupt.push({
                path: `${BUNDLE_DIR}/${rel}`,
                expected: rel,
                actual,
              });}
          }
        }
        const missing = [...expected.keys()].filter((p) => !seen.has(p));
        const extra = [...seen].filter((p) => !expected.has(p));
        const handle = await context.writeResource(
          "verification",
          `verification-${instanceKey(args)}`,
          VerificationSchema.parse({
            host: args.ssh.host,
            root: args.root,
            ok,
            corrupt,
            missing,
            extra,
            checked_at: new Date(activeDeps.now()).toISOString(),
          }),
        );
        return {
          dataHandles: [handle],
          result: {
            ok: ok.length,
            corrupt: corrupt.length,
            missing: missing.length,
            extra: extra.length,
          },
        };
      },
    },

    get: {
      description:
        "READ-ONLY. Observe nginx state (active, site config hash, TLS and basic-auth mode) and the layout summary, and persist the observation as the server resource.",
      arguments: GetArgs,
      execute: async (rawArgs: unknown, context: MethodContext) => {
        const args = GetArgs.parse(rawArgs);
        const target = toTarget(args.ssh);
        return await observeServer(activeDeps, target, args, context);
      },
    },

    sync: {
      description:
        "READ-ONLY. Refresh the observed nginx state and layout summary into the server resource, instead of failing when the site is absent.",
      arguments: GetArgs,
      execute: async (rawArgs: unknown, context: MethodContext) => {
        const args = GetArgs.parse(rawArgs);
        const target = toTarget(args.ssh);
        return await observeServer(activeDeps, target, args, context);
      },
    },

    plan_prune: {
      description:
        "READ-ONLY. List objects not reachable from any ref and not in keep[], with the total bytes and a plan hash over the sorted list, and persist the plan.",
      arguments: PlanPruneArgs,
      execute: async (rawArgs: unknown, context: MethodContext) => {
        const args = PlanPruneArgs.parse(rawArgs);
        const target = toTarget(args.ssh);
        const layout = await readLayout(activeDeps, target, args.root);
        const blobs: PruneObject[] = layout.blobs.map((b) => ({
          kind: "blob",
          hash: b.hash,
          bytes: b.bytes,
          path: b.path,
        }));
        const bundles: PruneObject[] = layout.bundles.map((b) => ({
          kind: "bundle",
          hash: b.hash,
          bytes: b.bytes,
          path: b.path,
        }));
        const plan = await planPrune(
          {
            refs: layout.refs.map((r) => ({
              name: r.name,
              target: { kind: r.kind, hash: r.hash },
            })),
            blobs,
            bundles,
            keep: args.keep,
          },
          (t) => sha256Hex(t),
        );
        const handle = await context.writeResource(
          "prune_plan",
          `prune_plan-${instanceKey(args)}`,
          PrunePlanSchema.parse({
            host: args.ssh.host,
            root: args.root,
            objects: plan.objects,
            total_bytes: plan.totalBytes,
            plan_sha256: plan.planSha256,
            created_at: new Date(activeDeps.now()).toISOString(),
          }),
        );
        return { dataHandles: [handle], result: plan };
      },
    },

    prune: {
      kind: "action",
      description:
        "DESTRUCTIVE. Delete exactly the objects of a plan whose hash matches plan_sha256; refuses when the recomputed plan differs, so a change since planning deletes nothing. Then regenerates SHA256SUMS.",
      arguments: PruneArgs,
      execute: async (rawArgs: unknown, context: MethodContext) => {
        const args = PruneArgs.parse(rawArgs);
        const target = toTarget(args.ssh);
        const layout = await readLayout(activeDeps, target, args.root);
        const blobs: PruneObject[] = layout.blobs.map((b) => ({
          kind: "blob",
          hash: b.hash,
          bytes: b.bytes,
          path: b.path,
        }));
        const bundles: PruneObject[] = layout.bundles.map((b) => ({
          kind: "bundle",
          hash: b.hash,
          bytes: b.bytes,
          path: b.path,
        }));
        const plan = await planPrune(
          {
            refs: layout.refs.map((r) => ({
              name: r.name,
              target: { kind: r.kind, hash: r.hash },
            })),
            blobs,
            bundles,
            keep: args.keep,
          },
          (t) => sha256Hex(t),
        );
        if (plan.planSha256 !== args.plan_sha256) {
          throw new SshError(
            "the prune plan changed since planning; nothing deleted",
          );
        }
        await removeObjects(
          activeDeps,
          target,
          args.root,
          plan.objects.map((o) => o.path),
        );
        await regenerateSha256Sums(activeDeps, target, args.root);
        context.logger.warn("Pruned {count} objects ({bytes} bytes)", {
          count: plan.objects.length,
          bytes: plan.totalBytes,
        });
        return {
          result: {
            removed: plan.objects.length,
            bytes: plan.totalBytes,
            plan_sha256: plan.planSha256,
          },
        };
      },
    },

    uninstall: {
      kind: "action",
      description:
        "DESTRUCTIVE. Remove the site config, its TLS files and htpasswd, and reload nginx; with remove_data also remove the served root, but only when it is a real directory holding a .layout-version sentinel. A clean no-op when absent, and it never removes the nginx package.",
      arguments: UninstallArgs,
      execute: async (rawArgs: unknown, context: MethodContext) => {
        const args = UninstallArgs.parse(rawArgs);
        const target = toTarget(args.ssh);
        const enabled = await probeFile(
          activeDeps,
          target,
          NGINX_ENABLED_PATH,
          true,
        );
        const site = await probeFile(activeDeps, target, NGINX_SITE_PATH, true);
        const present = enabled.state !== "missing" ||
          site.state !== "missing";
        const credentialPaths = [TLS_CERT_PATH, TLS_KEY_PATH, HTPASSWD_PATH];
        const credProbes = await Promise.all(
          credentialPaths.map((p) => probeFile(activeDeps, target, p, true)),
        );
        const credentialsPresent =
          credProbes.filter((p) => p.state !== "missing").length;
        if (present || credentialsPresent > 0) {
          await execSudo(activeDeps, target, [
            "rm",
            "-f",
            NGINX_ENABLED_PATH,
            NGINX_SITE_PATH,
            ...credentialPaths,
          ]);
          if (present) {
            const reload = await execSudo(activeDeps, target, [
              "systemctl",
              "reload",
              "nginx",
            ]);
            if (reload.exit_code !== 0) {
              throw new SshError("nginx reload failed");
            }
          }
        }
        let dataRemoved = false;
        if (args.remove_data) {
          const kind = await rootState(activeDeps, target, args.root);
          if (kind === "foreign") {
            throw new SshError(
              `refusing to remove ${args.root}: it is not a directory holding a regular ${LAYOUT_VERSION_FILE} sentinel`,
            );
          }
          if (kind === "ours") {
            await removeRoot(activeDeps, target, args.root);
            dataRemoved = true;
          }
        }
        context.logger.info(
          "Uninstalled artifact server site (present={present})",
          { present },
        );
        return {
          result: {
            removed: present,
            credentials_removed: credentialsPresent,
            data_removed: dataRemoved,
          },
        };
      },
    },
  },
};

/** Compatibility factory: sets the transport and returns the model. */
export function createModel(next: SshDeps = denoDeps): ArtifactServerModel {
  setDeps(next);
  return model;
}

/**
 * Classifies a served root: `missing`, `ours` when it is a real directory that
 * holds a regular `.layout-version` sentinel, or `foreign` otherwise.
 */
async function rootState(
  activeDeps: SshDeps,
  target: SshTarget,
  root: string,
): Promise<"missing" | "ours" | "foreign"> {
  const probe = await probeFile(activeDeps, target, root, true);
  if (probe.state === "missing") return "missing";
  if (probe.state !== "dir") return "foreign";
  const sentinel = await probeFile(
    activeDeps,
    target,
    `${root}/${LAYOUT_VERSION_FILE}`,
    true,
  );
  return sentinel.state === "file" ? "ours" : "foreign";
}

/** One root-owned file's state before a run. */
interface FileSnap {
  path: string;
  existed: boolean;
  content: string;
  mode: string;
  owner: string;
  group: string;
}

/** Captures a file's bytes, mode and owner so a rollback can restore it. */
async function snapFile(
  activeDeps: SshDeps,
  target: SshTarget,
  path: string,
): Promise<FileSnap> {
  const probe = await probeFile(activeDeps, target, path, true);
  if (probe.state !== "file") {
    return {
      path,
      existed: false,
      content: "",
      mode: "0644",
      owner: "root",
      group: "root",
    };
  }
  return {
    path,
    existed: true,
    content: (await readFileText(activeDeps, target, path, true)) ?? "",
    mode: probe.mode ?? "0644",
    owner: probe.owner ?? "root",
    group: probe.group ?? "root",
  };
}

/** Restores a file captured by {@link snapFile}, or removes it if it was absent. */
async function restoreFile(
  activeDeps: SshDeps,
  target: SshTarget,
  snap: FileSnap,
): Promise<void> {
  if (!snap.existed) {
    await execSudo(activeDeps, target, ["rm", "-f", snap.path]);
    return;
  }
  await putRootFile(activeDeps, target, {
    path: snap.path,
    content: snap.content,
    mode: snap.mode,
    owner: snap.owner,
    group: snap.group,
  });
}

/** A link or file at a fixed path, before a run. */
interface LinkSnap {
  path: string;
  state: "missing" | "symlink" | "file" | "dir";
  target: string | null;
  content: string | null;
}

/** Captures a link or file so a rollback can restore it. */
async function snapLink(
  activeDeps: SshDeps,
  target: SshTarget,
  path: string,
): Promise<LinkSnap> {
  const probe = await probeFile(activeDeps, target, path, true);
  if (probe.state === "symlink") {
    return {
      path,
      state: "symlink",
      target: await readLink(activeDeps, target, path, true),
      content: null,
    };
  }
  if (probe.state === "file") {
    return {
      path,
      state: "file",
      target: null,
      content: await readFileText(activeDeps, target, path, true),
    };
  }
  return { path, state: probe.state, target: null, content: null };
}

/** Restores a link or file captured by {@link snapLink}, or removes it. */
async function restoreLink(
  activeDeps: SshDeps,
  target: SshTarget,
  snap: LinkSnap,
): Promise<void> {
  if (snap.state === "symlink" && snap.target !== null) {
    await execSudo(activeDeps, target, ["ln", "-sfn", snap.target, snap.path]);
  } else if (snap.state === "file" && snap.content !== null) {
    await putRootFile(activeDeps, target, {
      path: snap.path,
      content: snap.content,
      mode: "0644",
      owner: "root",
      group: "root",
    });
  } else {
    await execSudo(activeDeps, target, ["rm", "-f", snap.path]);
  }
}

/**
 * The public URL base for a target: the `url_base` recorded by render_config or
 * install, or a plain `http://<host>` when neither has run yet.
 */
async function resolveBase(
  context: MethodContext,
  args: RootArgs,
): Promise<string> {
  const stored = await context.readResource?.(
    `config-${instanceKey(args)}`,
  ) as { url_base?: unknown } | null;
  const base = stored?.url_base;
  return typeof base === "string" && base !== ""
    ? base
    : `http://${args.ssh.host}`;
}

/** Reads nginx and the layout and persists the `server` resource. */
async function observeServer(
  activeDeps: SshDeps,
  target: SshTarget,
  args: { ssh: SshBlock; root: string },
  context: MethodContext,
): Promise<MethodResult> {
  const nginx = await readNginxState(activeDeps, target, NGINX_SITE_PATH);
  const layout = await readLayout(activeDeps, target, args.root);
  const handle = await context.writeResource(
    "server",
    `server-${instanceKey(args)}`,
    ServerSchema.parse({
      host: args.ssh.host,
      port: args.ssh.port,
      user: args.ssh.user,
      root: args.root,
      nginx_active: nginx.active,
      config_sha256: nginx.configSha256,
      tls: nginx.tls,
      basic_auth: nginx.basicAuth,
      blobs: layout.blobs.length,
      bundles: layout.bundles.length,
      refs: layout.refs.length,
      layout_version: layout.layoutVersion,
      observed_at: new Date(activeDeps.now()).toISOString(),
    }),
  );
  return {
    dataHandles: [handle],
    result: {
      nginx_active: nginx.active,
      config_sha256: nginx.configSha256,
      blobs: layout.blobs.length,
      bundles: layout.bundles.length,
      refs: layout.refs.length,
    },
  };
}
