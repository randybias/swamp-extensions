/**
 * SSH readiness probing for freshly provisioned servers.
 *
 * Readiness is judged from the server itself, not from the provider API:
 * a TCP connection that returns an SSH banner, the host keys that answer
 * (checked against a host-key policy), and optionally a marker file that the
 * server's first-boot configuration writes when it finishes. Private keys are
 * loaded into a short-lived ssh-agent over stdin and never written to disk.
 *
 * @module
 */

/** How observed host keys are treated. */
export type HostKeyPolicy = "strict" | "accept-new" | "insecure";

/** Result of running an external command. */
export interface CommandResult {
  /** Process exit code. */
  code: number;
  /** Captured standard output. */
  stdout: string;
  /** Captured standard error. */
  stderr: string;
}

/** Runs an external command; injectable so tests need no real binaries. */
export type CommandRunner = (
  cmd: string,
  args: string[],
  options?: { stdin?: string; env?: Record<string, string> },
) => Promise<CommandResult>;

/** Opens a TCP connection and returns the first line the peer sends. */
export type BannerReader = (
  host: string,
  port: number,
  timeoutMs: number,
) => Promise<string>;

/** A host key as reported by ssh-keyscan or listed in known_hosts. */
export interface HostKey {
  /** Host pattern field from the line, when present (e.g. `[host]:2222`). */
  host?: string;
  /** Key algorithm, e.g. `ssh-ed25519`. */
  type: string;
  /** Base64 public key blob. */
  key: string;
}

/**
 * A probe failure that retrying cannot fix: invalid input, a rejected private
 * key, or no local ssh-agent. Callers stop polling when they see one.
 */
export class ProbeConfigError extends Error {
  /** Creates a non-retryable probe error. */
  constructor(message: string) {
    super(message);
    this.name = "ProbeConfigError";
  }
}

const HOST_RE =
  /^(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$|^[0-9a-fA-F:.]{2,45}$/;
/** Grammar for SSH user names (conventional POSIX names). */
export const USER_RE = /^[a-z_][a-z0-9_-]{0,31}$/;
/** Grammar for marker paths: absolute, safe characters only. */
export const MARKER_RE = /^\/[A-Za-z0-9._\/-]{1,255}$/;

/** Throws unless `host` is a plain hostname or IP literal. */
export function assertHost(host: string): void {
  if (!HOST_RE.test(host)) throw new ProbeConfigError(`Invalid host: ${host}`);
}

/** Throws unless `user` is a conventional POSIX user name. */
export function assertUser(user: string): void {
  if (!USER_RE.test(user)) {
    throw new ProbeConfigError(`Invalid SSH user: ${user}`);
  }
}

/** Throws unless `path` is an absolute path of safe characters. */
export function assertMarkerPath(path: string): void {
  if (!MARKER_RE.test(path) || path.split("/").includes("..")) {
    throw new ProbeConfigError(`Invalid marker path: ${path}`);
  }
}

/** Default command runner backed by `Deno.Command`. */
export const denoRunner: CommandRunner = async (cmd, args, options = {}) => {
  // Only ssh-keyscan, ssh-keygen, ssh-agent, ssh-add and ssh are run, with
  // arguments validated by the assert* grammars above; secrets go via stdin.
  let child: Deno.ChildProcess;
  try {
    // swamp-quality-ignore deno-command
    child = new Deno.Command(cmd, {
      args,
      stdin: options.stdin === undefined ? "null" : "piped",
      stdout: "piped",
      stderr: "piped",
      env: options.env,
    }).spawn();
  } catch (e) {
    // A missing OpenSSH tool will not appear by retrying.
    if (e instanceof Deno.errors.NotFound) {
      throw new ProbeConfigError(`${cmd} is not installed or not on PATH`);
    }
    throw e;
  }
  if (options.stdin !== undefined) {
    const writer = child.stdin.getWriter();
    await writer.write(new TextEncoder().encode(options.stdin));
    await writer.close();
  }
  const out = await child.output();
  return {
    code: out.code,
    stdout: new TextDecoder().decode(out.stdout),
    stderr: new TextDecoder().decode(out.stderr),
  };
};

/** Default banner reader backed by `Deno.connect`. */
export const denoBannerReader: BannerReader = async (host, port, timeoutMs) => {
  let conn: Deno.TcpConn | undefined;
  let timer: ReturnType<typeof setTimeout> | undefined;
  const timeout = new Promise<never>((_, reject) => {
    timer = setTimeout(() => {
      try {
        conn?.close();
      } catch { /* already closed */ }
      reject(new Error("banner timeout"));
    }, timeoutMs);
  });
  const read = (async () => {
    conn = await Deno.connect({ hostname: host, port });
    const buf = new Uint8Array(256);
    const n = await conn.read(buf);
    return n === null ? "" : new TextDecoder().decode(buf.subarray(0, n));
  })();
  try {
    return await Promise.race([read, timeout]);
  } finally {
    clearTimeout(timer);
    try {
      conn?.close();
    } catch { /* already closed */ }
    read.catch(() => {});
  }
};

/** Returns the SSH banner line if `raw` starts with one, else null. */
export function parseBanner(raw: string): string | null {
  const line = raw.split(/\r?\n/)[0].trim();
  return line.startsWith("SSH-") ? line : null;
}

/** Parses ssh-keyscan or known_hosts lines into host keys. */
export function parseHostKeys(text: string): HostKey[] {
  const keys: HostKey[] = [];
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (line === "" || line.startsWith("#")) continue;
    const parts = line.split(/\s+/);
    // known_hosts / keyscan: "<host> <type> <key>"; also accept "<type> <key>".
    const bare = parts[0].startsWith("ssh-") || parts[0].startsWith("ecdsa-");
    const [host, type, key] = bare
      ? [undefined, parts[0], parts[1]]
      : [parts[0], parts[1], parts[2]];
    if (type && key) keys.push(host ? { host, type, key } : { type, key });
  }
  return keys;
}

/**
 * Keeps the expected keys that apply to `host` on `port`: lines without a host
 * field, or whose comma-separated host list names `host` (port 22) or
 * `[host]:port`. Hashed known_hosts entries are not supported.
 */
export function keysForHost(
  keys: HostKey[],
  host: string,
  port: number,
): HostKey[] {
  const want = port === 22 ? host : `[${host}]:${port}`;
  return keys.filter((k) =>
    k.host === undefined || k.host.split(",").includes(want)
  );
}

/**
 * Applies the host-key policy. `strict` requires every observed key to be in
 * `expected` and at least one to be observed. `accept-new` and `insecure`
 * accept what was observed here; callers implement trust-on-first-use for
 * `accept-new` by passing previously recorded keys as `strict`.
 */
export function checkHostKeys(
  observed: HostKey[],
  policy: HostKeyPolicy,
  expected: HostKey[] = [],
): void {
  if (policy !== "strict") return;
  if (expected.length === 0) {
    throw new Error("host_key_policy strict requires known_hosts");
  }
  if (observed.length === 0) {
    throw new Error("no host keys observed to verify");
  }
  for (const k of observed) {
    if (!expected.some((e) => e.type === k.type && e.key === k.key)) {
      throw new Error(`host key mismatch for ${k.type}`);
    }
  }
}

/** Scans the host's public keys with ssh-keyscan. */
export async function scanHostKeys(
  run: CommandRunner,
  host: string,
  port: number,
): Promise<HostKey[]> {
  assertHost(host);
  const res = await run("ssh-keyscan", [
    "-T",
    "5",
    "-p",
    String(port),
    host,
  ]);
  return parseHostKeys(res.stdout);
}

/** Returns the SHA256 fingerprint of each key, via ssh-keygen over stdin. */
export async function fingerprints(
  run: CommandRunner,
  keys: HostKey[],
): Promise<{ type: string; sha256: string }[]> {
  const out: { type: string; sha256: string }[] = [];
  for (const k of keys) {
    const res = await run("ssh-keygen", ["-l", "-E", "sha256", "-f", "-"], {
      stdin: `${k.type} ${k.key}\n`,
    });
    const fp = res.stdout.split(/\s+/).find((p) => p.startsWith("SHA256:"));
    if (res.code !== 0 || !fp) {
      throw new Error(`ssh-keygen could not fingerprint a ${k.type} key`);
    }
    out.push({ type: k.type, sha256: fp });
  }
  return out;
}

/**
 * Checks whether `markerPath` exists on the host. Loads `privateKey` into a
 * temporary ssh-agent over stdin and pins the given host keys. Returns true
 * when present, false when absent, and throws on connection or auth errors.
 */
export async function checkMarker(
  run: CommandRunner,
  opts: {
    host: string;
    port: number;
    user: string;
    privateKey: string;
    hostKeys: HostKey[];
    markerPath: string;
  },
): Promise<boolean> {
  assertHost(opts.host);
  assertUser(opts.user);
  assertMarkerPath(opts.markerPath);
  if (opts.hostKeys.length === 0) {
    throw new ProbeConfigError("cannot check marker without pinned host keys");
  }
  const agent = await run("ssh-agent", ["-s"]);
  const sock = /SSH_AUTH_SOCK=([^;]+);/.exec(agent.stdout)?.[1];
  const pid = /SSH_AGENT_PID=(\d+);/.exec(agent.stdout)?.[1];
  if (agent.code !== 0 || !sock || !pid) {
    throw new ProbeConfigError("could not start ssh-agent");
  }
  const env = { SSH_AUTH_SOCK: sock, SSH_AGENT_PID: pid };
  let knownHosts: string | undefined;
  try {
    knownHosts = await Deno.makeTempFile({ prefix: "cherry-kh-" });
    const added = await run("ssh-add", ["-q", "-"], {
      stdin: opts.privateKey.endsWith("\n")
        ? opts.privateKey
        : `${opts.privateKey}\n`,
      env,
    });
    if (added.code !== 0) {
      throw new ProbeConfigError("ssh-add rejected the private key");
    }
    const hostField = opts.port === 22
      ? opts.host
      : `[${opts.host}]:${opts.port}`;
    await Deno.writeTextFile(
      knownHosts,
      opts.hostKeys.map((k) => `${hostField} ${k.type} ${k.key}`).join("\n") +
        "\n",
    );
    // -F /dev/null and IdentityFile=none keep the operator's ssh config and
    // default keys out of the check; only the temporary agent is used.
    const res = await run("ssh", [
      "-F",
      "/dev/null",
      "-o",
      "IdentityFile=none",
      "-o",
      `IdentityAgent=${sock}`,
      "-o",
      "BatchMode=yes",
      "-o",
      "StrictHostKeyChecking=yes",
      "-o",
      `UserKnownHostsFile=${knownHosts}`,
      "-o",
      "GlobalKnownHostsFile=/dev/null",
      "-o",
      "ConnectTimeout=10",
      "-o",
      "ServerAliveInterval=5",
      "-o",
      "ServerAliveCountMax=2",
      "-p",
      String(opts.port),
      "-l",
      opts.user,
      opts.host,
      `test -e '${opts.markerPath}'`,
    ], { env });
    if (res.code === 0) return true;
    if (res.code === 1) return false;
    throw new Error(`ssh marker check failed (exit ${res.code})`);
  } finally {
    if (knownHosts) await Deno.remove(knownHosts).catch(() => {});
    await run("ssh-agent", ["-k"], { env }).catch(() => undefined);
  }
}
