/**
 * Swamp extension model that writes a secret file onto one host over SSH from
 * values held in a vault.
 *
 * The value travels only over stdin: it is never a command-line argument, never
 * logged, and never written to swamp state. Stored state holds file metadata, a
 * change flag, and at most a keyed HMAC of the content — never the content or
 * its plain hash. The file is written atomically (temp file, chmod, rename) and
 * converges by content hash, so a re-run with the same value is a no-op.
 *
 * The model is generic: global arguments are empty and every method takes its
 * own target. State is keyed by host, port, user and path.
 *
 * @module
 */

import { z } from "npm:zod@4.3.6";
import {
  assertRemotePath,
  base64Decode,
  denoDeps,
  exec as sshExec,
  HOST_RE,
  type HostKeyPolicy,
  MODE_RE,
  sha256Hex,
  SshConfigError,
  type SshDeps,
  SshError,
  type SshTarget,
  upload as sshUpload,
  USER_RE,
} from "./_lib/ssh.ts";

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
  /** Typed result for the caller. */
  result?: unknown;
}

/** The subset of the swamp method context this model uses. */
export interface MethodContext {
  /** Structured logger. */
  logger: {
    /** Info level. */
    info: (message: string, fields?: Record<string, unknown>) => void;
    /** Warn level. */
    warn: (message: string, fields?: Record<string, unknown>) => void;
  };
  /** Persists one resource and returns its handle. */
  writeResource: (
    specName: string,
    instanceName: string,
    data: Record<string, unknown>,
  ) => Promise<DataHandle>;
}

/** A resource specification exposed by the model. */
export interface ResourceSpec {
  /** Human-readable description. */
  description: string;
  /** Zod schema the resource is validated against. */
  schema: z.ZodType;
  /** Retention lifetime. */
  lifetime: string;
  /** Number of versions to keep. */
  garbageCollection: number;
}

/** A method exposed by the model. */
export interface SecretFileMethod {
  /** `action` for a non-lifecycle verb. */
  kind?: "action";
  /** Description. */
  description: string;
  /** Argument schema. */
  arguments: z.ZodType;
  /** Runs the method. */
  execute: (args: unknown, context: MethodContext) => Promise<MethodResult>;
}

/** The model definition returned by {@link createModel}. */
export interface SecretFileModel {
  /** Model type. */
  type: string;
  /** CalVer version. */
  version: string;
  /** One-line summary. */
  description: string;
  /** Empty globals. */
  globalArguments: z.ZodType;
  /** Resource specs. */
  resources: Record<string, ResourceSpec>;
  /** Methods. */
  methods: Record<string, SecretFileMethod>;
}

const SSH_FIELDS = {
  host: z.string().regex(HOST_RE).max(253).describe(
    "Hostname or IP literal of the target.",
  ),
  port: z.number().int().min(1).max(65535).default(22).describe("SSH port."),
  user: z.string().regex(USER_RE).describe("Remote user name."),
  host_key_policy: z.enum(["strict", "insecure_tofu"]).describe(
    "Required. strict verifies against host_keys; insecure_tofu records the first keys seen and pins them on later runs.",
  ),
  host_keys: z.array(z.string().max(8192)).max(64).nullish().describe(
    "ssh-keyscan-format lines. Required for strict.",
  ),
  private_key: z.string().max(65536).meta({ sensitive: true }).nullish()
    .describe(
      "Private key text, loaded into a temporary ssh-agent over stdin. Wire a vault reference.",
    ),
  password: z.string().max(4096).meta({ sensitive: true }).nullish().describe(
    "Password, delivered through an askpass helper; prefer private_key.",
  ),
  connect_timeout_s: z.number().int().min(1).max(120).default(15).describe(
    "Connection timeout in seconds.",
  ),
};

const CONTENT_FIELDS = {
  path: z.string().regex(
    /^\/[A-Za-z0-9._\/-]{1,4095}$/,
  ).refine(
    (value) => !value.endsWith("/"),
    "path must name a file, not a directory",
  ).refine(
    (value) => !value.split("/").some((part) => part === "." || part === ".."),
    "path must not contain . or .. components",
  ).describe("Absolute remote path of the file."),
  content: z.string().max(1_048_576).meta({ sensitive: true }).nullish()
    .describe("Literal file content. Wire a vault reference."),
  content_base64: z.string().max(1_398_102).meta({ sensitive: true }).nullish()
    .describe("Base64 file content, for binary values."),
  entries: z.record(
    z.string().max(128),
    z.string().max(65_536).meta({ sensitive: true }),
  ).meta({ sensitive: true }).nullish().describe(
    "Dotenv entries rendered as KEY=VALUE lines. Values are sensitive.",
  ),
  mode: z.string().regex(MODE_RE).default("0600").describe(
    "Octal file mode applied before the atomic rename.",
  ),
  owner: z.string().regex(/^(?:[A-Za-z_][A-Za-z0-9_-]{0,31}|\d{1,10})$/)
    .nullish().describe("Owner user name or numeric uid."),
  group: z.string().regex(/^(?:[A-Za-z_][A-Za-z0-9_-]{0,31}|\d{1,10})$/)
    .nullish().describe("Owner group name or numeric gid."),
  hmac_key: z.string().min(1).max(4096).meta({ sensitive: true }).nullish()
    .describe(
      "Optional key for a keyed HMAC of the content, stored instead of any plain hash.",
    ),
};

const WRITE_ARGS = z.strictObject({ ...SSH_FIELDS, ...CONTENT_FIELDS });

const VERIFY_ARGS = z.strictObject({
  ...SSH_FIELDS,
  ...CONTENT_FIELDS,
  // verify never writes, so mode/owner/group are only compared when given.
  mode: z.string().regex(MODE_RE).nullish().describe(
    "Expected mode; compared when given.",
  ),
});

const REMOVE_ARGS = z.strictObject({
  ...SSH_FIELDS,
  path: CONTENT_FIELDS.path,
});

/** Strict schema for `write` arguments. */
export const writeArgsSchema = WRITE_ARGS;

/** Strict schema for `verify` arguments. */
export const verifyArgsSchema = VERIFY_ARGS;

/** Strict schema for `remove` arguments. */
export const removeArgsSchema = REMOVE_ARGS;

const SecretFileStateSchema = z.strictObject({
  host: z.string(),
  port: z.number().int(),
  user: z.string(),
  path: z.string(),
  mode: z.string(),
  owner: z.string().optional(),
  group: z.string().optional(),
  bytes: z.number().int().optional(),
  changed: z.boolean(),
  content_hmac: z.string().optional(),
  matches: z.boolean().optional(),
  status: z.enum(["present", "not_found", "removed"]),
  observed_at: z.string(),
});

/** Stored state of one secret file. */
export type SecretFileState = z.infer<typeof SecretFileStateSchema>;

/** Arguments shared by every method. */
interface TargetArgs {
  host: string;
  port: number;
  user: string;
  host_key_policy: HostKeyPolicy;
  host_keys?: string[] | null;
  private_key?: string | null;
  password?: string | null;
  connect_timeout_s: number;
}

interface ContentArgs {
  path: string;
  content?: string | null;
  content_base64?: string | null;
  entries?: Record<string, string> | null;
  mode: string;
  owner?: string | null;
  group?: string | null;
  hmac_key?: string | null;
}

interface WriteArgs extends TargetArgs, ContentArgs {}

interface VerifyArgs extends TargetArgs, ContentArgs {
  mode: string;
}

interface RemoveArgs extends TargetArgs {
  path: string;
}

const DOTENV_KEY_RE = /^[A-Za-z_][A-Za-z0-9_]*$/;

/** Renders dotenv entries, refusing a key or value that would break the file. */
export function renderEntries(entries: Record<string, string>): string {
  const lines: string[] = [];
  for (const [key, value] of Object.entries(entries)) {
    if (!DOTENV_KEY_RE.test(key)) {
      throw new SshConfigError(`invalid dotenv key: ${key}`);
    }
    if (/[\r\n\0]/.test(value)) {
      throw new SshConfigError(
        `value for ${key} must not contain a newline or NUL`,
      );
    }
    lines.push(`${key}=${value}`);
  }
  return lines.length === 0 ? "" : `${lines.join("\n")}\n`;
}

/** True when exactly one content form is present. */
function contentCount(args: ContentArgs): number {
  return [
    args.content != null,
    args.entries != null,
    args.content_base64 != null,
  ]
    .filter(Boolean).length;
}

/** Resolves the file bytes from exactly one content form. */
export function resolveContent(args: ContentArgs): Uint8Array {
  const count = contentCount(args);
  if (count !== 1) {
    throw new SshConfigError(
      "pass exactly one of content, entries or content_base64",
    );
  }
  if (args.content != null) return new TextEncoder().encode(args.content);
  if (args.content_base64 != null) return base64Decode(args.content_base64);
  return new TextEncoder().encode(renderEntries(args.entries ?? {}));
}

/** Builds a `chown` target from an owner and/or group. */
export function chownSpec(
  owner?: string | null,
  group?: string | null,
): string | undefined {
  const hasOwner = owner != null && owner !== "";
  const hasGroup = group != null && group !== "";
  if (!hasOwner && !hasGroup) return undefined;
  if (hasOwner && hasGroup) return `${owner}:${group}`;
  if (hasOwner) return owner as string;
  return `:${group}`;
}

/** An unambiguous stored-state key for host, port, user and path. */
export function secretInstanceName(
  host: string,
  port: number,
  user: string,
  path: string,
): string {
  return `h${host.length}-${host}-p${port}-u${user.length}-${user}` +
    `-f${fnv1aHex(path)}`;
}

/** A small deterministic hash, so a path with `/` can key a record. */
function fnv1aHex(text: string): string {
  let hash = 0x811c9dc5;
  for (let i = 0; i < text.length; i++) {
    hash ^= text.charCodeAt(i);
    hash = Math.imul(hash, 0x01000193) >>> 0;
  }
  return hash.toString(16).padStart(8, "0");
}

/** A keyed HMAC-SHA256 of `data`, lowercase hex. */
export async function hmacSha256Hex(
  key: string,
  data: Uint8Array,
): Promise<string> {
  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(key),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const signature = await crypto.subtle.sign(
    "HMAC",
    cryptoKey,
    new Uint8Array(data),
  );
  return Array.from(new Uint8Array(signature))
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

/** Validates the target and returns the transport target. */
function toTarget(args: TargetArgs): SshTarget {
  const hostKeys = args.host_keys ?? undefined;
  if (
    args.host_key_policy === "strict" && (!hostKeys || hostKeys.length === 0)
  ) {
    throw new SshConfigError(
      "host_key_policy strict requires a non-empty host_keys list",
    );
  }
  if (args.private_key && args.password) {
    throw new SshConfigError("pass private_key or password, not both");
  }
  return {
    host: args.host,
    port: args.port,
    user: args.user,
    host_key_policy: args.host_key_policy,
    host_keys: hostKeys,
    private_key: args.private_key ?? undefined,
    password: args.password ?? undefined,
    connect_timeout_s: args.connect_timeout_s,
  };
}

/** Normalizes an octal mode for comparison. */
function normalizeMode(mode: string): string {
  const trimmed = mode.replace(/^0+/, "");
  return trimmed === "" ? "0" : trimmed;
}

/** Throws a typed error when a remote command exits non-zero. */
function requireOk(
  result: { exit_code: number; stderr: string },
  what: string,
): void {
  if (result.exit_code !== 0) {
    throw new SshError(
      `${what} failed (exit ${result.exit_code}): ${
        result.stderr.trim().slice(0, 200)
      }`,
    );
  }
}

/** Remote file metadata, read with GNU `stat`. */
interface FileStat {
  mode: string;
  owner: string;
  group: string;
  bytes: number;
}

/** Stats a remote path; null when it does not exist. */
async function statFile(
  deps: SshDeps,
  target: SshTarget,
  path: string,
): Promise<FileStat | null> {
  const result = await sshExec(deps, target, [
    "stat",
    "-c",
    "%a %U %G %s",
    path,
  ]);
  if (result.exit_code !== 0) return null;
  const [mode, owner, group, bytes] = result.stdout.trim().split(/\s+/);
  if (!mode || !owner || !group || bytes === undefined) return null;
  return { mode, owner, group, bytes: Number(bytes) };
}

/** The remote file's SHA-256, lowercase hex. */
async function remoteSha256(
  deps: SshDeps,
  target: SshTarget,
  path: string,
): Promise<string> {
  const result = await sshExec(deps, target, ["sha256sum", path]);
  requireOk(result, `sha256sum ${path}`);
  const sha = result.stdout.trim().split(/\s+/)[0] ?? "";
  if (!/^[0-9a-f]{64}$/.test(sha)) {
    throw new SshError(`could not read a SHA-256 for ${path}`);
  }
  return sha;
}

/** True when the path exists on the host. */
async function exists(
  deps: SshDeps,
  target: SshTarget,
  path: string,
): Promise<boolean> {
  const result = await sshExec(deps, target, ["test", "-e", path]);
  if (result.exit_code === 0) return true;
  if (result.exit_code === 1) return false;
  throw new SshError(`could not test ${path} (exit ${result.exit_code})`);
}

/** Writes one stored-state record. */
async function writeState(
  context: MethodContext,
  args: TargetArgs,
  state: Omit<SecretFileState, "host" | "port" | "user" | "observed_at">,
  observedAt: string,
): Promise<DataHandle> {
  const record: Record<string, unknown> = {
    host: args.host,
    port: args.port,
    user: args.user,
    observed_at: observedAt,
    ...state,
  };
  for (const [key, value] of Object.entries(record)) {
    if (value === undefined) delete record[key];
  }
  const full = SecretFileStateSchema.parse(record);
  return await context.writeResource(
    "secretFile",
    secretInstanceName(args.host, args.port, args.user, state.path),
    full,
  );
}

/**
 * Builds the model with injectable dependencies. The production export is
 * `createModel()`; tests pass a fake runner, clock and sleep so no process is
 * spawned and no socket is opened.
 */
export function createModel(deps: SshDeps = denoDeps): SecretFileModel {
  return {
    type: "@randybias/secret-file",
    version: "2026.10.17.1",
    description:
      "Write a secret file onto one host over SSH from vault values delivered over stdin, atomically and idempotently by content hash, with settable owner and group and a remove action. State holds metadata and at most a keyed HMAC of the content, never the value.",
    globalArguments: z.strictObject({}),
    resources: {
      secretFile: {
        description:
          "Secret-file metadata: path, mode, owner, group, byte count and change flag",
        schema: SecretFileStateSchema,
        lifetime: "infinite",
        garbageCollection: 10,
      },
    },
    methods: {
      write: {
        kind: "action",
        description:
          "DESTRUCTIVE. Write the file atomically over stdin (temp file, chmod, rename) with the given mode, owner and group. Idempotent by content and mode; an unchanged file is not rewritten. The value is never returned, logged or stored; state keeps only a keyed HMAC when hmac_key is given.",
        arguments: WRITE_ARGS,
        execute: async (
          rawArgs: unknown,
          context: MethodContext,
        ): Promise<MethodResult> => {
          const args = rawArgs as WriteArgs;
          assertRemotePath(args.path);
          const target = toTarget(args);
          const bytes = resolveContent(args);
          const result = await sshUpload(deps, target, {
            path: args.path,
            content: bytes,
            mode: args.mode,
          });
          let changed = result.changed;
          const spec = chownSpec(args.owner, args.group);
          if (spec !== undefined) {
            const stat = await statFile(deps, target, args.path);
            const wantOwner = args.owner ?? stat?.owner;
            const wantGroup = args.group ?? stat?.group;
            if (
              stat === null || stat.owner !== wantOwner ||
              stat.group !== wantGroup
            ) {
              requireOk(
                await sshExec(deps, target, ["chown", spec, args.path]),
                `chown ${args.path}`,
              );
              changed = true;
            }
          }
          const hmac = args.hmac_key != null
            ? await hmacSha256Hex(args.hmac_key, bytes)
            : undefined;
          const handle = await writeState(context, args, {
            path: args.path,
            mode: args.mode,
            owner: args.owner ?? undefined,
            group: args.group ?? undefined,
            bytes: bytes.length,
            changed,
            content_hmac: hmac,
            status: "present",
          }, new Date(deps.now()).toISOString());
          context.logger.info(
            "Wrote secret file {path} ({bytes} bytes, changed {changed})",
            { path: args.path, bytes: bytes.length, changed },
          );
          return {
            dataHandles: [handle],
            result: {
              path: args.path,
              mode: args.mode,
              bytes: bytes.length,
              changed,
            },
          };
        },
      },

      verify: {
        description:
          "READ-ONLY. Stat the file and, when a content form is given, compare its SHA-256 with the local value's; also compares mode, owner and group when given. Stores match flags and metadata only, never the content or a hash.",
        arguments: VERIFY_ARGS,
        execute: async (
          rawArgs: unknown,
          context: MethodContext,
        ): Promise<MethodResult> => {
          const args = rawArgs as VerifyArgs;
          assertRemotePath(args.path);
          const target = toTarget(args);
          const observedAt = new Date(deps.now()).toISOString();
          const stat = await statFile(deps, target, args.path);
          if (stat === null) {
            const handle = await writeState(context, args, {
              path: args.path,
              mode: args.mode ?? "",
              bytes: undefined,
              changed: false,
              matches: false,
              status: "not_found",
            }, observedAt);
            context.logger.info("Secret file {path} is absent", {
              path: args.path,
            });
            return {
              dataHandles: [handle],
              result: { present: false, matches: false },
            };
          }
          const expected = contentCount(args) === 1
            ? await sha256Hex(resolveContent(args))
            : undefined;
          const remote = expected === undefined
            ? undefined
            : await remoteSha256(deps, target, args.path);
          const matches = (expected === undefined || expected === remote) &&
            (args.mode == null ||
              normalizeMode(stat.mode) === normalizeMode(args.mode)) &&
            (args.owner == null || stat.owner === args.owner) &&
            (args.group == null || stat.group === args.group);
          const handle = await writeState(context, args, {
            path: args.path,
            mode: stat.mode,
            owner: stat.owner,
            group: stat.group,
            bytes: stat.bytes,
            changed: false,
            matches,
            status: "present",
          }, observedAt);
          context.logger.info("Secret file {path} matches {matches}", {
            path: args.path,
            matches,
          });
          return {
            dataHandles: [handle],
            result: {
              present: true,
              matches,
              mode: stat.mode,
              owner: stat.owner,
              group: stat.group,
              bytes: stat.bytes,
            },
          };
        },
      },

      remove: {
        kind: "action",
        description:
          "DESTRUCTIVE. Remove the file from the host and prove it is gone. Idempotent: an already-absent file is a clean no-op.",
        arguments: REMOVE_ARGS,
        execute: async (
          rawArgs: unknown,
          context: MethodContext,
        ): Promise<MethodResult> => {
          const args = rawArgs as RemoveArgs;
          assertRemotePath(args.path);
          const target = toTarget(args);
          const observedAt = new Date(deps.now()).toISOString();
          if (!await exists(deps, target, args.path)) {
            const handle = await writeState(context, args, {
              path: args.path,
              mode: "",
              changed: false,
              status: "not_found",
            }, observedAt);
            context.logger.info("Secret file {path} already absent", {
              path: args.path,
            });
            return {
              dataHandles: [handle],
              result: { path: args.path, removed: false },
            };
          }
          requireOk(
            await sshExec(deps, target, ["rm", "-f", args.path]),
            `rm ${args.path}`,
          );
          if (await exists(deps, target, args.path)) {
            throw new SshError(`secret file ${args.path} is still present`);
          }
          const handle = await writeState(context, args, {
            path: args.path,
            mode: "",
            changed: true,
            status: "removed",
          }, observedAt);
          context.logger.info("Removed secret file {path}", {
            path: args.path,
          });
          return {
            dataHandles: [handle],
            result: { path: args.path, removed: true },
          };
        },
      },
    },
  };
}

/** Production model: the factory with no overrides. */
export const model: SecretFileModel = createModel();
