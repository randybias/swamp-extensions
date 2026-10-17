/**
 * Error vocabulary for the cephadm model.
 *
 * Every failure a method raises is one of these types. A phase-attributed
 * error names the step that failed and carries only non-secret detail, so a
 * halted workflow's message alone says what happened and to what. A transport
 * error is a distinct type carrying a kind and an optional pre-session cause,
 * which together tell a caller whether the remote command can be re-sent.
 *
 * @module
 */

/** Whether a lost session proves the remote command ran, cannot have run, or is unknown. */
export type TransportKind =
  /** OpenSSH dropped the session before authentication; the command never ran. */
  | "dropped-before-auth"
  /** We killed the session on our own budget; the command may still be running. */
  | "aborted"
  /** Anything else, including a mid-session loss; the command may have run. */
  | "other";

/** A cause that proves the remote command never started; null when unknown. */
export type PreSessionCause =
  | "connect-refused"
  | "name-resolution"
  | "connect-timeout"
  | "negotiation"
  | "auth"
  | null;

/** Renders one detail value: strings raw, everything else as JSON. */
function renderDetail(value: unknown): string {
  if (typeof value === "string") return value;
  return JSON.stringify(value);
}

/**
 * A method-level failure attributed to a phase. The message is
 * `cephadm[<phase>]: <message>`, followed by a parenthesised `key=value` list
 * when any detail value is defined.
 */
export class PhaseError extends Error {
  /** The phase label, e.g. `wipe.resolve` or `validate`. */
  readonly phase: string;
  /** Non-secret detail rendered into the message. */
  readonly detail: Record<string, unknown>;

  /** Builds a phase-attributed error. */
  constructor(
    phase: string,
    message: string,
    detail: Record<string, unknown> = {},
  ) {
    const parts: string[] = [];
    for (const [key, value] of Object.entries(detail)) {
      if (value === undefined) continue;
      parts.push(`${key}=${renderDetail(value)}`);
    }
    super(
      `cephadm[${phase}]: ${message}` +
        (parts.length > 0 ? ` (${parts.join(", ")})` : ""),
    );
    this.name = "PhaseError";
    this.phase = phase;
    this.detail = detail;
  }
}

/** Throws a {@link PhaseError}; always throws, so callers can use it as a statement. */
export function fail(
  phase: string,
  message: string,
  detail: Record<string, unknown> = {},
): never {
  throw new PhaseError(phase, message, detail);
}

/**
 * A lost SSH session, a connection-level failure or our own budget kill. Its
 * kind and pre-session cause decide whether a write may be re-sent. A command's
 * own non-zero exit is never this error.
 */
export class TransportError extends Error {
  /** Target host. */
  readonly host: string;
  /** Target port, defaulted to 22. */
  readonly port: number;
  /** Login user. */
  readonly user: string;
  /** Session-loss classification. */
  readonly kind: TransportKind;
  /** Set only when the remote command provably never ran. */
  readonly sessionCause: PreSessionCause;
  /** Raw stderr, for classification; never contains key material we put on argv. */
  readonly stderr: string;

  /** Builds a typed transport error for one target. */
  constructor(opts: {
    host: string;
    port: number;
    user: string;
    kind: TransportKind;
    cause: PreSessionCause;
    message: string;
    stderr?: string;
  }) {
    super(
      `cephadm transport failed for ${opts.user}@${opts.host}:${opts.port}: ${opts.message}`,
    );
    this.name = "TransportError";
    this.host = opts.host;
    this.port = opts.port;
    this.user = opts.user;
    this.kind = opts.kind;
    this.sessionCause = opts.cause;
    this.stderr = opts.stderr ?? "";
  }

  /** True when the session dropped before authentication, so the command never ran. */
  get preSession(): boolean {
    return this.kind === "dropped-before-auth" || this.sessionCause !== null;
  }
}

/** Raised when the target's sudo would prompt: passwordless sudo is required. */
export class SudoPolicyError extends Error {
  /** Builds a sudo policy error. */
  constructor(message: string) {
    super(`cephadm sudo policy: ${message}`);
    this.name = "SudoPolicyError";
  }
}

/** Raised when a remote command exits non-zero and the caller did not allow it. */
export class RemoteExitError extends Error {
  /** Remote exit code. */
  readonly code: number;
  /** Remote standard output. */
  readonly stdout: string;
  /** Remote standard error. */
  readonly stderr: string;

  /** Builds a remote-exit error. */
  constructor(code: number, stdout: string, stderr: string, context: string) {
    super(`cephadm remote exit ${code} (${context})`);
    this.name = "RemoteExitError";
    this.code = code;
    this.stdout = stdout;
    this.stderr = stderr;
  }
}

/** Raised for a local refusal: both identities set, a NUL byte, or an unsafe socket dir. */
export class LocalRefusalError extends Error {
  /** Builds a local refusal. */
  constructor(message: string) {
    super(`cephadm refused: ${message}`);
    this.name = "LocalRefusalError";
  }
}

/** True for the errors that are thrown regardless of an allow-non-zero setting. */
export function isTransportLike(
  e: unknown,
): e is TransportError | SudoPolicyError | LocalRefusalError {
  return e instanceof TransportError || e instanceof SudoPolicyError ||
    e instanceof LocalRefusalError;
}
