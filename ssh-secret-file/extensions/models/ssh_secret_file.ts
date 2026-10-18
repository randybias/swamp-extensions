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

/** Maximum content size in bytes (1 MiB), enforced on the resolved bytes. */
export const MAX_CONTENT_BYTES = 1_048_576;

/** Maximum number of dotenv entries. */
export const MAX_ENTRIES = 256;

/** Owner/group grammar: a POSIX name or a numeric id. */
const IDENTITY_RE = /^(?:[A-Za-z_][A-Za-z0-9_-]{0,31}|\d{1,10})$/;

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
  content: z.string().max(MAX_CONTENT_BYTES).meta({ sensitive: true })
    .nullish()
    .describe("Literal file content, at most 1 MiB. Wire a vault reference."),
  content_base64: z.string().max(1_398_104).meta({ sensitive: true }).nullish()
    .describe(
      "Base64 file content, for binary values; at most 1 MiB decoded.",
    ),
  entries: z.record(
    z.string().max(128),
    z.string().max(65_536).meta({ sensitive: true }),
  ).refine(
    (entries) => Object.keys(entries).length <= MAX_ENTRIES,
    { message: `entries must have at most ${MAX_ENTRIES} keys` },
  ).meta({ sensitive: true }).nullish().describe(
    "Dotenv entries; each value is rendered single-quoted as KEY='value'. Up to 256 entries and 1 MiB rendered.",
  ),
  mode: z.string().regex(MODE_RE).default("0600").describe(
    "Octal file mode applied before the atomic rename.",
  ),
  owner: z.string().regex(IDENTITY_RE).nullish().describe(
    "Owner user name or numeric uid.",
  ),
  group: z.string().regex(IDENTITY_RE).nullish().describe(
    "Owner group name or numeric gid.",
  ),
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
  owner: z.string().regex(IDENTITY_RE).optional(),
  group: z.string().regex(IDENTITY_RE).optional(),
  bytes: z.number().int().optional(),
  changed: z.boolean(),
  content_hmac: z.string().optional(),
  matches: z.boolean().optional(),
  status: z.enum(["present", "not_found", "removed"]),
  observed_at: z.string(),
});

/** Stored state of one secret file. */
export type SecretFileState = z.infer<typeof FileStateSchema>;

// The argument types are inferred from the zod schemas so they cannot drift.
type WriteArgs = z.infer<typeof WRITE_ARGS>;
type VerifyArgs = z.infer<typeof VERIFY_ARGS>;
type RemoveArgs = z.infer<typeof REMOVE_ARGS>;
/** Arguments shared by every method. */
type TargetArgs = Pick<WriteArgs, keyof typeof SSH_FIELDS>;

const DOTENV_KEY_RE = /^[A-Za-z_][A-Za-z0-9_]*$/;

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
/** Budget for one short probe (`stat`, `test`, `rm`), in milliseconds. */
export const PROBE_TIMEOUT_MS = 30_000;

/**
 * The remote script that turns the secret streamed on stdin into the
 * destination. An atomic publish needs a temp in the destination directory; the
 * temp and its cleanup stay on the remote, and the script refuses a short read
 * or a symlink/directory destination before the rename.
 *
 * It changes into the destination directory first and refuses a path whose
 * canonical form differs, which catches a symlinked component at any depth. It
 * then anchors every later operation on the current directory inode: the
 * mode/owner checks read `.`, the stage file is created in `.`, and the rename
 * targets `./<basename>`. A user who can write an ancestor cannot swap a path
 * component for a symlink after the check and redirect the write. A directory
 * that is group- or world-writable, or not owned by the running user or root,
 * is refused. Owner and group are applied before the mode (a chown clears
 * set-ID bits), and the staged file stays 0600 until the rename.
 */
/** The `cd` + canonical-path refusal shared by the anchored remote scripts. */
function anchorLines(dir: string): string[] {
  return [
    `d=${posixQuote(dir)}`,
    'cd "$d"',
    '[ "$(pwd -P)" = "$d" ] || { echo \'destination directory has a symlinked path component; refusing\' >&2; exit 2; }',
  ];
}

export function stageWriteScript(
  path: string,
  mode: string,
  expectedBytes: number,
  spec?: string,
): string {
  const dir = path.slice(0, path.lastIndexOf("/")) || "/";
  const base = path.slice(path.lastIndexOf("/") + 1);
  const target = posixQuote(`./${base}`);
  const lines = [
    "set -eu",
    ...anchorLines(dir),
    "dmode=$(stat -c '%a' .)",
    "downer=$(stat -c '%u' .)",
    "duid=$(id -u)",
    "[ \"$((0$dmode & 022))\" -eq 0 ] || { echo 'destination directory is group- or world-writable; refusing' >&2; exit 3; }",
    '[ "$downer" = "$duid" ] || [ "$downer" = 0 ] || { echo \'destination directory is not owned by the running user or root; refusing\' >&2; exit 4; }',
    "t=$(mktemp ./.secret-stage-XXXXXXXX)",
    "trap 'rm -f \"$t\"' EXIT",
    "trap 'exit 1' HUP INT TERM",
    'cat > "$t"',
    `[ "$(wc -c < "$t" | tr -d '[:space:]')" -eq ${expectedBytes} ] || { echo 'short read; refusing' >&2; exit 5; }`,
  ];
  // chown first, then chmod: Linux clears the set-ID bits on any chown, even
  // one that sets the same owner and group, so chmod last publishes the
  // requested mode exactly. mktemp's 0600 keeps the bytes unreadable until the
  // rename.
  if (spec !== undefined) lines.push(`chown -h ${posixQuote(spec)} "$t"`);
  lines.push(
    `chmod ${posixQuote(mode)} "$t"`,
    // Re-check the destination with no-follow immediately before the rename.
    `[ ! -L ${target} ] || { echo 'destination changed; refusing' >&2; exit 6; }`,
    `[ ! -d ${target} ] || { echo 'destination changed; refusing' >&2; exit 6; }`,
    `mv -T "$t" ${target} || { echo 'destination changed; refusing' >&2; exit 6; }`,
    "trap - EXIT",
  );
  return lines.join("\n");
}

/**
 * One anchored remove: refuse a symlinked path component, unlink the relative
 * name, and prove it is gone, all in the pinned current directory.
 */
export function removeScript(path: string): string {
  const dir = path.slice(0, path.lastIndexOf("/")) || "/";
  const base = path.slice(path.lastIndexOf("/") + 1);
  const target = posixQuote(`./${base}`);
  return [
    "set -eu",
    ...anchorLines(dir),
    `rm -f ${target}`,
    `[ ! -e ${target} ] && [ ! -L ${target} ]`,
  ].join("\n");
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

/** Resolves the file bytes from exactly one content form, capped at 1 MiB. */
export function resolveContent(args: ContentInput): Uint8Array {
  const count = contentCount(args);
  if (count !== 1) {
    throw new SshConfigError(
      "pass exactly one of content, entries or content_base64",
    );
  }
  const bytes = args.content != null
    ? new TextEncoder().encode(args.content)
    : args.content_base64 != null
    ? base64Decode(args.content_base64)
    : new TextEncoder().encode(renderEntries(args.entries ?? {}));
  if (bytes.length > MAX_CONTENT_BYTES) {
    throw new SshConfigError(
      `content must be at most ${MAX_CONTENT_BYTES} bytes`,
    );
  }
  return bytes;
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

/**
 * Throws a typed error when a remote command exits non-zero. Remote stderr is
 * never included: a hostile or misconfigured target can reflect stdin or file
 * bytes into it, and an error reaches the run record and `--json`. The remote
 * scripts use distinct exit codes so a failure stays diagnosable.
 */
function requireOk(result: { exit_code: number }, what: string): void {
  if (result.exit_code !== 0) {
    throw new SshError(`${what} failed (exit ${result.exit_code})`);
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

/** Defines whether `value` asks for a numeric or a named owner comparison. */
function matchesIdentity(
  requested: string | null | undefined,
  name: string,
  id: string,
): boolean {
  if (requested == null || requested === "") return true;
  return /^\d+$/.test(requested) ? requested === id : requested === name;
}

/**
 * One anchored read: `cd` into the destination directory, refuse a symlinked
 * path component, then stat and hash the file by its relative name, so the cwd
 * inode anchors both reads to the same directory. Prints one stat line and one
 * `sha256sum` line.
 */
export function readFileScript(path: string): string {
  const dir = path.slice(0, path.lastIndexOf("/")) || "/";
  const base = path.slice(path.lastIndexOf("/") + 1);
  const target = posixQuote(`./${base}`);
  return [
    "set -eu",
    ...anchorLines(dir),
    // stat is no-follow but sha256sum follows, so refuse a link before either
    // runs: a symlink would pair the link's metadata with the target's bytes.
    `[ ! -L ${target} ] || { echo 'destination is a symlink; refusing' >&2; exit 7; }`,
    `stat -c '%a %U %G %u %g %s' ${target}`,
    `sha256sum ${target}`,
  ].join("\n");
}

/** One read of a remote file: metadata plus SHA-256, from one anchored script. */
interface FileObservation {
  stat: FileStat;
  sha: string;
}

async function readFile(
  deps: SshDeps,
  target: SshTarget,
  path: string,
): Promise<FileObservation> {
  const result = await sshExec(
    deps,
    target,
    ["sh", "-c", readFileScript(path)],
    { timeoutMs: SHA_TIMEOUT_MS },
  );
  requireOk(result, `read ${path}`);
  const lines = result.stdout.trim().split("\n");
  const [mode, owner, group, ownerId, groupId, bytes] = (lines[0] ?? "")
    .trim().split(/\s+/);
  if (
    // GNU stat %a strips leading zeros (0060 prints as "60"), so accept any
    // 1-4 octal digits here; the input schema still requires 3-4.
    mode === undefined || !/^[0-7]{1,4}$/.test(mode) ||
    owner === undefined || !IDENTITY_RE.test(owner) ||
    ownerId === undefined || !/^\d{1,10}$/.test(ownerId) ||
    group === undefined || !IDENTITY_RE.test(group) ||
    groupId === undefined || !/^\d{1,10}$/.test(groupId) ||
    bytes === undefined || !/^\d{1,10}$/.test(bytes)
  ) {
    throw new SshError(`could not parse stat output for ${path}`);
  }
  const sha = (lines[1] ?? "").trim().split(/\s+/)[0] ?? "";
  if (!/^[0-9a-f]{64}$/.test(sha)) {
    throw new SshError(`could not read a SHA-256 for ${path}`);
  }
  return {
    stat: { mode, owner, ownerId, group, groupId, bytes: Number(bytes) },
    sha,
  };
}

/** True when the remote file matches the wanted bytes, mode, owner and group. */
async function converged(
  deps: SshDeps,
  target: SshTarget,
  args: {
    path: string;
    mode: string;
    owner?: string | null;
    group?: string | null;
  },
  localSha: string,
): Promise<boolean> {
  const { stat, sha } = await readFile(deps, target, args.path);
  return sha === localSha &&
    normalizeMode(stat.mode) === normalizeMode(args.mode) &&
    matchesIdentity(args.owner, stat.owner, stat.ownerId) &&
    matchesIdentity(args.group, stat.group, stat.groupId);
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
  const entry = await sshExec(deps, target, ["test", "-e", path], {
    timeoutMs: PROBE_TIMEOUT_MS,
  });
  if (entry.exit_code === 0) return true;
  if (entry.exit_code !== 1) {
    throw new SshError(`could not test ${path} (exit ${entry.exit_code})`);
  }
  const link = await sshExec(deps, target, ["test", "-L", path], {
    timeoutMs: PROBE_TIMEOUT_MS,
  });
  if (link.exit_code === 0) return true;
  if (link.exit_code !== 1) {
    throw new SshError(`could not test ${path} (exit ${link.exit_code})`);
  }
  // `test` exits 1 for any stat failure, including a parent the running user
  // cannot search. Only a searchable parent with no entry is absent.
  const dir = path.slice(0, path.lastIndexOf("/")) || "/";
  const parent = await sshExec(deps, target, ["test", "-x", dir], {
    timeoutMs: PROBE_TIMEOUT_MS,
  });
  if (parent.exit_code !== 0) {
    throw new SshError(
      `could not search ${dir} (exit ${parent.exit_code}); refusing to report ${path} absent`,
    );
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
  const link = await sshExec(deps, target, ["test", "-L", path], {
    timeoutMs: PROBE_TIMEOUT_MS,
  });
  if (link.exit_code === 0) {
    throw new SshError(
      `secret file destination ${path} is a symlink; refusing to replace it`,
    );
  }
  if (link.exit_code !== 1) {
    throw new SshError(`could not test ${path} (exit ${link.exit_code})`);
  }
  const dir = await sshExec(deps, target, ["test", "-d", path], {
    timeoutMs: PROBE_TIMEOUT_MS,
  });
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
 * The methods, bound to one dependency set. Tests pass a fake runner, clock and
 * sleep so no process is spawned and no socket is opened.
 */
function methodsFor(deps: SshDeps): Record<string, SecretFileMethod> {
  return {
    write: {
      kind: "action",
      description:
        "DESTRUCTIVE. Write the file atomically over stdin with the given mode, owner and group, idempotently by content; the owner and group are applied to a staged file before the rename, so the published file is never briefly wrong. The value is never returned, logged or stored, and state keeps only a keyed HMAC when hmac_key is given.",
      arguments: WRITE_ARGS,
      execute: async (
        rawArgs: unknown,
        context: MethodContext,
      ): Promise<MethodResult> => {
        const args = rawArgs as WriteArgs;
        assertRemotePath(args.path);
        const target = toTarget(args);
        const bytes = resolveContent(args);
        const localSha = await sha256Hex(bytes);
        const spec = chownSpec(args.owner, args.group);
        await assertReplaceable(deps, target, args.path);
        let changed = true;
        if (await exists(deps, target, args.path)) {
          changed = !await converged(deps, target, args, localSha);
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
          if (!await converged(deps, target, args, localSha)) {
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
        // Resolve the content form first: an invalid value must not touch the
        // host, and the not_found record must not reflect a requested mode.
        const expected = contentCount(args) === 1
          ? await sha256Hex(resolveContent(args))
          : undefined;
        if (!await exists(deps, target, args.path)) {
          const handle = await writeState(context, args, {
            path: args.path,
            mode: "",
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
        const { stat, sha } = await readFile(deps, target, args.path);
        const matches = (expected === undefined || expected === sha) &&
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
          await sshExec(deps, target, ["sh", "-c", removeScript(args.path)], {
            timeoutMs: PROBE_TIMEOUT_MS,
          }),
          `remove ${args.path}`,
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
  };
}

/** The model definition, bound to the production dependencies. */
export const model = {
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
  methods: methodsFor(denoDeps),
} satisfies SecretFileModel;

/**
 * Builds the model with injectable dependencies. The production export is
 * `model`; tests call this with a fake runner, clock and sleep.
 */
export function createModel(deps: SshDeps = denoDeps): SecretFileModel {
  return { ...model, methods: methodsFor(deps) };
}
