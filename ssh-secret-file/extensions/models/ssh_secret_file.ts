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
  posixQuote,
  sha256Hex,
  SshConfigError,
  type SshDeps,
  SshError,
  type SshTarget,
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

/** One attribute migration. */
export interface Upgrade {
  /** Version this entry migrates to. */
  toVersion: string;
  /** What changed. */
  description: string;
  /** Identity unless stored attributes changed. */
  upgradeAttributes: (
    old: Record<string, unknown>,
  ) => Record<string, unknown>;
}

/** The model definition returned by {@link createModel}. */
export interface SecretFileModel {
  /** Model type. */
  type: string;
  /** CalVer version. */
  version: string;
  /** One-line summary. */
  description: string;
  /** Version migrations. */
  readonly upgrades: Upgrade[];
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
  host_key_policy: z.enum(["strict"]).describe(
    "Required. Only strict is offered: the host is verified against the pinned host_keys on every run, so no key is ever accepted unseen.",
  ),
  host_keys: z.array(z.string().max(8192)).min(1).max(64).describe(
    "ssh-keyscan-format lines; required, and the only accepted host keys.",
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
    "Dotenv entries; each value is rendered single-quoted as KEY='value'. Up to 256 entries and 1 MiB rendered.",
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
  // verify never writes, so mode/owner/group are only compared when given,
  // and hmac_key is not accepted because nothing is stored.
  mode: z.string().regex(MODE_RE).nullish().describe(
    "Expected mode; compared when given.",
  ),
  hmac_key: z.never().optional(),
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

const FileStateSchema = z.strictObject({
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
export type SecretFileState = z.infer<typeof FileStateSchema>;

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

interface VerifyArgs extends TargetArgs {
  path: string;
  content?: string | null;
  content_base64?: string | null;
  entries?: Record<string, string> | null;
  mode?: string | null;
  owner?: string | null;
  group?: string | null;
}

interface RemoveArgs extends TargetArgs {
  path: string;
}

const DOTENV_KEY_RE = /^[A-Za-z_][A-Za-z0-9_]*$/;
const MAX_ENTRIES = 256;

/**
 * Renders dotenv entries as `KEY='value'` lines for POSIX-shell sourcing. A
 * single quote in a value is escaped as `'\''`; a key must match the usual
 * identifier grammar. Up to 256 entries and 1 MiB of rendered output.
 */
export function renderEntries(entries: Record<string, string>): string {
  const names = Object.keys(entries);
  if (names.length > MAX_ENTRIES) {
    throw new SshConfigError(`entries must have at most ${MAX_ENTRIES} keys`);
  }
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
    lines.push(`${key}='${value.replace(/'/g, "'\\''")}'`);
  }
  const rendered = lines.length === 0 ? "" : `${lines.join("\n")}\n`;
  if (rendered.length > 1_048_576) {
    throw new SshConfigError("rendered entries must be at most 1048576 bytes");
  }
  return rendered;
}

/** Budget for the one stdin-fed write step, in milliseconds. */
export const WRITE_TIMEOUT_MS = 120_000;
/** Budget for hashing the destination file, in milliseconds. */
export const SHA_TIMEOUT_MS = 60_000;

/**
 * The remote script that turns the secret streamed on stdin into the
 * destination. An atomic publish needs a temp in the destination directory; the
 * temp and its cleanup stay on the remote, and the script refuses a short read
 * or a symlink/directory destination before the rename. It first verifies the
 * destination directory is owned by the running user or root and is not group-
 * or world-writable, so a symlink cannot be planted between the check and the
 * rename.
 */
export function stageWriteScript(
  path: string,
  mode: string,
  expectedBytes: number,
  spec?: string,
): string {
  const f = posixQuote(path);
  const dir = path.slice(0, path.lastIndexOf("/")) || "/";
  const lines = [
    "set -eu",
    `f=${f}`,
    `d=${posixQuote(dir)}`,
    "dmode=$(stat -c '%a' \"$d\")",
    "downer=$(stat -c '%u' \"$d\")",
    "duid=$(id -u)",
    "[ \"$((0$dmode & 022))\" -eq 0 ] || { echo 'destination directory is group- or world-writable; refusing' >&2; exit 1; }",
    '[ "$downer" = "$duid" ] || [ "$downer" = 0 ] || { echo \'destination directory is not owned by the running user or root; refusing\' >&2; exit 1; }',
    't=$(mktemp "$d/.secret-stage-XXXXXXXX")',
    "trap 'rm -f \"$t\"' EXIT",
    "trap 'exit 1' HUP INT TERM",
    'cat > "$t"',
    `[ "$(wc -c < "$t" | tr -d '[:space:]')" -eq ${expectedBytes} ]`,
    `chmod ${posixQuote(mode)} "$t"`,
  ];
  if (spec !== undefined) lines.push(`chown -h ${posixQuote(spec)} "$t"`);
  lines.push(
    // Re-check the destination with no-follow immediately before the rename.
    '[ ! -L "$f" ]',
    '[ ! -d "$f" ]',
    'mv -T "$t" "$f"',
    "trap - EXIT",
  );
  return lines.join("\n");
}

/** The content-bearing fields, shared by write and verify. */
interface ContentInput {
  /** Literal content. */
  content?: string | null;
  /** Base64 content. */
  content_base64?: string | null;
  /** Dotenv entries. */
  entries?: Record<string, string> | null;
}

/** True when exactly one content form is present. */
function contentCount(args: ContentInput): number {
  return [
    args.content != null,
    args.entries != null,
    args.content_base64 != null,
  ]
    .filter(Boolean).length;
}

/** Resolves the file bytes from exactly one content form. */
export function resolveContent(args: ContentInput): Uint8Array {
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

/**
 * An unambiguous stored-state key for host, port, user and path: a SHA-256 of
 * the canonical tuple, so two paths on one host can never collide.
 */
export async function secretInstanceName(
  host: string,
  port: number,
  user: string,
  path: string,
): Promise<string> {
  const digest = await sha256Hex(
    `${host}\u0000${port}\u0000${user}\u0000${path}`,
  );
  return `secret-${digest.slice(0, 32)}`;
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

/**
 * Validates the target and returns the transport target. Only `strict` is
 * offered, so the host is always verified against the pinned keys and no key is
 * ever accepted unseen.
 */
function toTarget(args: TargetArgs): SshTarget {
  const hostKeys = args.host_keys ?? undefined;
  if (!hostKeys || hostKeys.length === 0) {
    throw new SshConfigError(
      "host_keys is required: this model only offers strict host-key checking",
    );
  }
  if (args.private_key && args.password) {
    throw new SshConfigError("pass private_key or password, not both");
  }
  return {
    host: args.host,
    port: args.port,
    user: args.user,
    host_key_policy: "strict",
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
  ownerId: string;
  group: string;
  groupId: string;
  bytes: number;
}

/**
 * Stats a remote path. The caller must have confirmed it exists first; any
 * failure here is a real error, never silently an absent file.
 */
async function statFile(
  deps: SshDeps,
  target: SshTarget,
  path: string,
): Promise<FileStat> {
  const result = await sshExec(deps, target, [
    "stat",
    "-c",
    "%a %U %G %u %g %s",
    path,
  ]);
  requireOk(result, `stat ${path}`);
  const [mode, owner, group, ownerId, groupId, bytes] = result.stdout.trim()
    .split(/\s+/);
  if (
    !mode || !owner || !ownerId || !group || !groupId || bytes === undefined
  ) {
    throw new SshError(`could not parse stat output for ${path}`);
  }
  return { mode, owner, ownerId, group, groupId, bytes: Number(bytes) };
}

/** Defines whether `value` asks for a numeric or a named owner comparison. */
function matchesIdentity(
  requested: string | null | undefined,
  name: string,
  id: string,
): boolean {
  if (requested == null || requested === "") return true;
  return /^\d+$/.test(requested) ? requested === id : requested === name;
}

/** The remote file's SHA-256, lowercase hex. */
async function remoteSha256(
  deps: SshDeps,
  target: SshTarget,
  path: string,
): Promise<string> {
  const result = await sshExec(deps, target, ["sha256sum", path], {
    timeoutMs: SHA_TIMEOUT_MS,
  });
  requireOk(result, `sha256sum ${path}`);
  const sha = result.stdout.trim().split(/\s+/)[0] ?? "";
  if (!/^[0-9a-f]{64}$/.test(sha)) {
    throw new SshError(`could not read a SHA-256 for ${path}`);
  }
  return sha;
}

/**
 * True when the path exists, including a dangling symlink. Any exit other than
 * 0 or 1 is a real error, never a silent absence.
 */
async function exists(
  deps: SshDeps,
  target: SshTarget,
  path: string,
): Promise<boolean> {
  const entry = await sshExec(deps, target, ["test", "-e", path]);
  if (entry.exit_code === 0) return true;
  if (entry.exit_code !== 1) {
    throw new SshError(`could not test ${path} (exit ${entry.exit_code})`);
  }
  const link = await sshExec(deps, target, ["test", "-L", path]);
  if (link.exit_code === 0) return true;
  if (link.exit_code !== 1) {
    throw new SshError(`could not test ${path} (exit ${link.exit_code})`);
  }
  return false;
}

/**
 * Refuses a destination that is a symlink or a directory, tested with no-follow
 * so nothing is ever written through a link or into a directory.
 */
async function assertReplaceable(
  deps: SshDeps,
  target: SshTarget,
  path: string,
): Promise<void> {
  const link = await sshExec(deps, target, ["test", "-L", path]);
  if (link.exit_code === 0) {
    throw new SshError(
      `secret file destination ${path} is a symlink; refusing to replace it`,
    );
  }
  if (link.exit_code !== 1) {
    throw new SshError(`could not test ${path} (exit ${link.exit_code})`);
  }
  const dir = await sshExec(deps, target, ["test", "-d", path]);
  if (dir.exit_code === 0) {
    throw new SshError(
      `secret file destination ${path} is a directory; refusing to replace it`,
    );
  }
  if (dir.exit_code !== 1) {
    throw new SshError(`could not test ${path} (exit ${dir.exit_code})`);
  }
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
  const full = FileStateSchema.parse(record);
  return await context.writeResource(
    "secretFile",
    await secretInstanceName(args.host, args.port, args.user, state.path),
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
    type: "@randybias/ssh-secret-file",
    version: "2026.10.17.1",
    description:
      "Write a secret file onto one host over SSH from vault values delivered over stdin, atomically and idempotently by content hash, with settable owner and group and a remove action. State holds metadata and at most a keyed HMAC of the content, never the value.",
    upgrades: [],
    globalArguments: z.strictObject({}),
    resources: {
      secretFile: {
        description:
          "Secret-file metadata: path, mode, owner, group, byte count and change flag",
        schema: FileStateSchema,
        lifetime: "infinite",
        garbageCollection: 10,
      },
    },
    methods: {
      write: {
        kind: "action",
        description:
          "DESTRUCTIVE. Write the file atomically over stdin with the given mode, owner and group, idempotently by content. The owner and group are applied to a staged file before the rename, so the published file is never briefly wrong. The value is never returned, logged or stored; state keeps only a keyed HMAC when hmac_key is given.",
        arguments: WRITE_ARGS,
        execute: async (
          rawArgs: unknown,
          context: MethodContext,
        ): Promise<MethodResult> => {
          const args = rawArgs as WriteArgs;
          assertRemotePath(args.path);
          const target = toTarget(args);
          await assertReplaceable(deps, target, args.path);
          const bytes = resolveContent(args);
          const localSha = await sha256Hex(bytes);
          const spec = chownSpec(args.owner, args.group);
          let changed = true;
          if (await exists(deps, target, args.path)) {
            const stat = await statFile(deps, target, args.path);
            const remote = await remoteSha256(deps, target, args.path);
            if (
              remote === localSha &&
              normalizeMode(stat.mode) === normalizeMode(args.mode) &&
              matchesIdentity(args.owner, stat.owner, stat.ownerId) &&
              matchesIdentity(args.group, stat.group, stat.groupId)
            ) {
              changed = false;
            }
          }
          if (changed) {
            requireOk(
              await sshExec(
                deps,
                target,
                [
                  "sh",
                  "-c",
                  stageWriteScript(args.path, args.mode, bytes.length, spec),
                ],
                { stdin: bytes, timeoutMs: WRITE_TIMEOUT_MS },
              ),
              `write ${args.path}`,
            );
            const stat = await statFile(deps, target, args.path);
            const remote = await remoteSha256(deps, target, args.path);
            if (
              remote !== localSha ||
              normalizeMode(stat.mode) !== normalizeMode(args.mode) ||
              !matchesIdentity(args.owner, stat.owner, stat.ownerId) ||
              !matchesIdentity(args.group, stat.group, stat.groupId)
            ) {
              throw new SshError(
                `secret file ${args.path} did not converge`,
              );
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
          if (contentCount(args) > 1) {
            throw new SshConfigError(
              "pass at most one of content, entries or content_base64",
            );
          }
          const target = toTarget(args);
          const observedAt = new Date(deps.now()).toISOString();
          if (!await exists(deps, target, args.path)) {
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
          const stat = await statFile(deps, target, args.path);
          const expected = contentCount(args) === 1
            ? await sha256Hex(resolveContent(args))
            : undefined;
          const remote = expected === undefined
            ? undefined
            : await remoteSha256(deps, target, args.path);
          const matches = (expected === undefined || expected === remote) &&
            (args.mode == null ||
              normalizeMode(stat.mode) === normalizeMode(args.mode)) &&
            matchesIdentity(args.owner, stat.owner, stat.ownerId) &&
            matchesIdentity(args.group, stat.group, stat.groupId);
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
export const model = {
  ...createModel(),
  type: "@randybias/ssh-secret-file",
  version: "2026.10.17.1",
} satisfies SecretFileModel;
