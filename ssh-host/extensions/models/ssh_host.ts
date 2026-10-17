/**
 * Swamp extension model for SSH host transport: run one argv vector, push
 * bytes atomically, and wait for a host to answer with expected host keys.
 *
 * The model is generic: it holds no host and no credential in its definition.
 * Every method takes its target as arguments, so one definition serves any
 * host. Stored data is keyed by the host, never by the definition name. The
 * private key and password inputs are sensitive and reach the transport over
 * stdin or an askpass helper, never on the command line.
 *
 * @module
 */

import { z } from "npm:zod@4.3.6";
import {
  base64Decode,
  denoDeps,
  exec as sshExec,
  HOST_RE,
  type HostKeyPolicy,
  MODE_RE,
  REMOTE_PATH_RE,
  sha256Hex,
  SshConfigError,
  type SshDeps,
  type SshTarget,
  upload as sshUpload,
  USER_RE,
  waitConnection,
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
    /** Logs at error level. */
    error: (message: string, fields?: Record<string, unknown>) => void;
  };
  /** Persists one resource and returns its handle. */
  writeResource: (
    specName: string,
    instanceName: string,
    data: Record<string, unknown>,
  ) => Promise<DataHandle>;
  /** Reads the latest version of one stored resource, or null. */
  readResource: (
    instanceName: string,
  ) => Promise<Record<string, unknown> | null>;
}

/** A resource specification exposed by the model. */
export interface ResourceSpec {
  /** Human-readable description of the resource. */
  description: string;
  /** Zod schema the resource data is validated against. */
  schema: z.ZodType;
  /** Retention lifetime, e.g. `infinite`. */
  lifetime: string;
  /** Number of versions to keep. */
  garbageCollection: number;
}

/** A method exposed by the model. */
export interface SshHostMethod {
  /** `action` for a non-lifecycle verb; never a bare `delete`. */
  kind?: "action" | "create" | "update" | "query";
  /** One to three sentences: what it does, what it returns, the caveat. */
  description: string;
  /** Zod schema for the method arguments. */
  arguments: z.ZodType;
  /** Runs the method. */
  execute: (args: unknown, context: MethodContext) => Promise<MethodResult>;
}

/** The model definition returned by {@link createModel}. */
export interface SshHostModel {
  /** Model type, `@randybias/ssh-host`. */
  type: string;
  /** CalVer version, matching the manifest. */
  version: string;
  /** One-line summary of the model for `swamp model type describe`. */
  description: string;
  /** Empty: every method takes its own target. */
  globalArguments: z.ZodType;
  /** Resource specifications. */
  resources: Record<string, ResourceSpec>;
  /** Method implementations. */
  methods: Record<string, SshHostMethod>;
}

const TargetShape = {
  host: z.string().regex(HOST_RE).max(253).describe(
    "Hostname or IP literal of the target.",
  ),
  port: z.number().int().min(1).max(65535).default(22).describe("SSH port."),
  user: z.string().regex(USER_RE).describe("Remote user name."),
  host_key_policy: z.enum(["strict", "insecure_tofu"]).describe(
    "Required. strict verifies against host_keys; insecure_tofu records the first keys seen and pins them on every later run, refusing a change.",
  ),
  host_keys: z.array(z.string().max(8192)).max(64).nullish().describe(
    "ssh-keyscan-format lines. Required for strict; a recorded set may be supplied for insecure_tofu to pin it immediately.",
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

const ExecArgsSchema = z.strictObject({
  ...TargetShape,
  argv: z.array(z.string().max(131072)).min(1).max(1024).describe(
    "Command and arguments. Each element is passed as one literal argv word over SSH.",
  ),
});

const UploadArgsSchema = z.strictObject({
  ...TargetShape,
  path: z.string().regex(REMOTE_PATH_RE).refine(
    (p) => !p.endsWith("/"),
    "path must name a file, not a directory",
  ).refine(
    (p) => !p.split("/").some((part) => part === "." || part === ".."),
    "path must not contain . or .. components",
  ).describe("Absolute destination path naming one file."),
  content: z.string().max(4194304).meta({ sensitive: true }).nullish()
    .describe("UTF-8 content. Wire a vault reference."),
  content_base64: z.string().max(5592408).meta({ sensitive: true }).nullish()
    .describe("Base64 content, for binary payloads."),
  mode: z.string().regex(MODE_RE).default("0600").describe(
    "Octal file mode applied before the atomic rename.",
  ),
});

const WaitArgsSchema = z.strictObject({
  ...TargetShape,
  timeout_s: z.number().int().min(1).max(3600).default(60).describe(
    "Give up after this many seconds.",
  ),
  poll_interval_s: z.number().int().min(1).max(60).default(5).describe(
    "Seconds between polls.",
  ),
});

/** Strict schema for `exec` arguments. */
export const execArgsSchema = ExecArgsSchema;

/** Strict schema for `upload` arguments. */
export const uploadArgsSchema = UploadArgsSchema;

/** Strict schema for `wait_connection` arguments. */
export const waitArgsSchema = WaitArgsSchema;

const ExecutionSchema = z.strictObject({
  host: z.string(),
  port: z.number().int(),
  user: z.string(),
  argv_sha256: z.string(),
  stdout: z.string().meta({ sensitive: true }),
  stderr: z.string().meta({ sensitive: true }),
  exit_code: z.number().int(),
  ran_at: z.string(),
});

const UploadSchema = z.strictObject({
  host: z.string(),
  port: z.number().int(),
  user: z.string(),
  path: z.string(),
  mode: z.string(),
  bytes: z.number().int(),
  sha256: z.string(),
  changed: z.boolean(),
  uploaded_at: z.string(),
});

const ConnectionSchema = z.strictObject({
  host: z.string(),
  port: z.number().int(),
  reachable: z.boolean(),
  host_keys: z.array(z.strictObject({
    type: z.string(),
    key: z.string(),
    sha256: z.string(),
  })),
  checked_at: z.string(),
  waited_seconds: z.number(),
});

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

interface ExecArgs extends TargetArgs {
  argv: string[];
}

interface UploadArgs extends TargetArgs {
  path: string;
  content?: string | null;
  content_base64?: string | null;
  mode: string;
}

interface WaitArgs extends TargetArgs {
  timeout_s: number;
  poll_interval_s: number;
}

/** Maps the shared arguments onto the transport target, refusing bad combinations. */
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

/** Resolves the upload payload, refusing ambiguous or missing content. */
function resolveContent(
  args: UploadArgs,
): Uint8Array | string {
  if (args.content != null && args.content_base64 != null) {
    throw new SshConfigError("pass content or content_base64, not both");
  }
  if (args.content != null) return args.content;
  if (args.content_base64 != null) return base64Decode(args.content_base64);
  throw new SshConfigError("upload requires content or content_base64");
}

/**
 * The per-target suffix for stored data. Length-prefixed, labeled components
 * make it unambiguous: `h2-ab-p22-u3-x-y` and `h5-ab-22-p3-u2-y` differ, so two
 * different targets can never share a stored record (and a TOFU pin).
 */
function instanceSuffix(args: TargetArgs): string {
  return `h${args.host.length}-${args.host}-p${args.port}-u${args.user.length}-${args.user}`;
}

/** The keys recorded by an earlier `insecure_tofu` connection, if any. */
interface RecordedKeys {
  /** Recorded host keys. */
  host_keys?: { type: string; key: string }[];
}

/**
 * Applies host-key state. `strict` is used as given. `insecure_tofu` becomes
 * `strict` pinned to the keys recorded for this target on first use; with no
 * record it stays `insecure_tofu` for a genuine first connection.
 */
async function pinnedTarget(
  context: MethodContext,
  args: TargetArgs,
): Promise<SshTarget> {
  const target = toTarget(args);
  if (args.host_key_policy !== "insecure_tofu") return target;
  const stored = await context.readResource(
    `connection-${instanceSuffix(args)}`,
  ) as RecordedKeys | null;
  const keys = stored?.host_keys ?? [];
  if (keys.length === 0) return target;
  return {
    ...target,
    host_key_policy: "strict",
    host_keys: keys.map((k) => `${k.type} ${k.key}`),
  };
}

/** A resolved target plus a first-use pin that must be committed on success. */
interface ResolvedTarget {
  /** The target to connect to, already pinned when a record or scan exists. */
  target: SshTarget;
  /** Keys learned on a first `insecure_tofu` use, to persist after success. */
  pending?: { type: string; key: string; sha256: string }[];
}

/**
 * Resolves the target for a mutating transport call. On the first
 * `insecure_tofu` use it learns the host keys read-only and pins them for this
 * call, but does not persist them yet: a failed authentication or a changed key
 * must leave no durable trust behind. {@link commitPin} records them only after
 * the operation succeeds. Later calls verify against the record.
 */
async function resolveTarget(
  deps: SshDeps,
  context: MethodContext,
  args: TargetArgs,
): Promise<ResolvedTarget> {
  const target = await pinnedTarget(context, args);
  if (
    args.host_key_policy !== "insecure_tofu" ||
    target.host_key_policy === "strict"
  ) {
    return { target };
  }
  const learned = await waitConnection(deps, target, {
    timeout_s: args.connect_timeout_s,
    poll_interval_s: 1,
  });
  return {
    target: {
      ...target,
      host_key_policy: "strict",
      host_keys: learned.host_keys.map((k) => `${k.type} ${k.key}`),
    },
    pending: learned.host_keys,
  };
}

/**
 * Persists a first-use pin after the operation that proved it succeeded. A
 * non-zero remote exit still proves the host, so callers commit once the
 * transport returns without throwing.
 */
async function commitPin(
  deps: SshDeps,
  context: MethodContext,
  args: TargetArgs,
  pending: { type: string; key: string; sha256: string }[] | undefined,
): Promise<void> {
  if (!pending || pending.length === 0) return;
  await context.writeResource(
    "connection",
    `connection-${instanceSuffix(args)}`,
    ConnectionSchema.parse({
      host: args.host,
      port: args.port,
      reachable: true,
      host_keys: pending,
      checked_at: new Date(deps.now()).toISOString(),
      waited_seconds: 0,
    }),
  );
}

/**
 * Builds the model with injectable dependencies. The production export is
 * `createModel()`; tests pass a fake runner, clock and sleep so no process is
 * spawned and no socket is opened.
 */
export function createModel(deps: SshDeps = denoDeps): SshHostModel {
  return {
    type: "@randybias/ssh-host",
    version: "2026.10.17.1",
    description:
      "Run one argv vector, push bytes atomically, and wait for SSH host keys on any host. One generic definition with no host or credential in it; every method takes its target as arguments and stores evidence keyed by host, port and user.",
    globalArguments: z.strictObject({}),
    resources: {
      execution: {
        description:
          "Result of one remote command: stdout, stderr and exit code",
        schema: ExecutionSchema,
        lifetime: "infinite",
        garbageCollection: 10,
      },
      upload: {
        description: "Evidence of one uploaded file: path, mode, bytes, sha256",
        schema: UploadSchema,
        lifetime: "infinite",
        garbageCollection: 10,
      },
      connection: {
        description: "Read-only reachability evidence with accepted host keys",
        schema: ConnectionSchema,
        lifetime: "infinite",
        garbageCollection: 10,
      },
    },
    methods: {
      exec: {
        kind: "action",
        description:
          "DESTRUCTIVE. Run one argv vector on the host over SSH and return its stdout, stderr and exit code; each element is a literal argv word, never interpolated into a shell string, but argv can change or break the host and exec cannot roll that back. A non-zero remote exit is data while an unreachable host, rejected credential or host-key mismatch is an error. Never put a secret in argv; stored stdout and stderr are sensitive-marked.",
        arguments: ExecArgsSchema,
        execute: async (
          rawArgs: unknown,
          context: MethodContext,
        ): Promise<MethodResult> => {
          const args = rawArgs as ExecArgs;
          const { target, pending } = await resolveTarget(deps, context, args);
          const result = await sshExec(deps, target, args.argv);
          // The host is proven only now; a failed auth or key change left no
          // durable trust behind.
          await commitPin(deps, context, args, pending);
          const handle = await context.writeResource(
            "execution",
            `exec-${instanceSuffix(args)}`,
            ExecutionSchema.parse({
              host: args.host,
              port: args.port,
              user: args.user,
              argv_sha256: await sha256Hex(args.argv.join("\u0000")),
              stdout: result.stdout,
              stderr: result.stderr,
              exit_code: result.exit_code,
              ran_at: new Date(deps.now()).toISOString(),
            }),
          );
          context.logger.info(
            "Ran {argv0} on {host}: exit {exit_code}",
            {
              argv0: args.argv[0],
              host: args.host,
              exit_code: result.exit_code,
            },
          );
          return { dataHandles: [handle], result };
        },
      },

      upload: {
        kind: "action",
        description:
          "DESTRUCTIVE. Push bytes to an absolute path on the host over stdin, atomically: a temporary file in the destination directory is written, chmod'ed and renamed over the destination, overwriting it. Idempotent by bytes: an unchanged file is not rewritten and no new resource version is written. Returns the path, byte count, SHA-256 and whether it changed; an unwritable path is an error and leaves no partial file.",
        arguments: UploadArgsSchema,
        execute: async (
          rawArgs: unknown,
          context: MethodContext,
        ): Promise<MethodResult> => {
          const args = rawArgs as UploadArgs;
          const { target, pending } = await resolveTarget(deps, context, args);
          const result = await sshUpload(deps, target, {
            path: args.path,
            content: resolveContent(args),
            mode: args.mode,
          });
          // Persist a first-use pin only after the transport succeeded.
          await commitPin(deps, context, args, pending);
          if (!result.changed) {
            context.logger.info(
              "Upload to {host}:{path} already current; no write",
              { host: args.host, path: result.path },
            );
            return { result };
          }
          const handle = await context.writeResource(
            "upload",
            `upload-${instanceSuffix(args)}`,
            UploadSchema.parse({
              host: args.host,
              port: args.port,
              user: args.user,
              path: result.path,
              mode: args.mode,
              bytes: result.bytes,
              sha256: result.sha256,
              changed: result.changed,
              uploaded_at: new Date(deps.now()).toISOString(),
            }),
          );
          context.logger.info(
            "Uploaded {bytes} bytes to {host}:{path}",
            {
              bytes: result.bytes,
              host: args.host,
              path: result.path,
            },
          );
          return { dataHandles: [handle], result };
        },
      },

      wait_connection: {
        kind: "action",
        description:
          "READ-ONLY. Poll until the host answers SSH with acceptable host keys or the timeout expires; returns reachable and the accepted host keys with fingerprints. A strict or already-recorded key mismatch is refused immediately; insecure_tofu records the first keys seen for later runs.",
        arguments: WaitArgsSchema,
        execute: async (
          rawArgs: unknown,
          context: MethodContext,
        ): Promise<MethodResult> => {
          const args = rawArgs as WaitArgs;
          // A recorded insecure_tofu pin is enforced here too; only a genuine
          // first use learns and records keys.
          const target = await pinnedTarget(context, args);
          const started = deps.now();
          const result = await waitConnection(deps, target, {
            timeout_s: args.timeout_s,
            poll_interval_s: args.poll_interval_s,
          });
          const handle = await context.writeResource(
            "connection",
            `connection-${instanceSuffix(args)}`,
            ConnectionSchema.parse({
              host: args.host,
              port: args.port,
              reachable: result.reachable,
              host_keys: result.host_keys,
              checked_at: new Date(deps.now()).toISOString(),
              waited_seconds: (deps.now() - started) / 1000,
            }),
          );
          context.logger.info(
            "Host {host} answered SSH with {count} host key(s)",
            { host: args.host, count: result.host_keys.length },
          );
          return { dataHandles: [handle], result };
        },
      },
    },
  };
}

/** Production model: the factory with no overrides. */
export const model: SshHostModel = createModel();
