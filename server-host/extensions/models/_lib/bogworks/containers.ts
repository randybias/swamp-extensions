/**
 * Docker helpers for tests and the real-tool validators: run one command in a
 * named image with read-only bind mounts, no network, and a hard timeout that
 * also kills the container. Nothing here is specific to a tool; the gates
 * build their validators (`nft -c`, `kzonecheck`, `kea-dhcp4 -t`, ...) on
 * {@link runInContainer}, and the harness tests run rendered scripts under the
 * real `dash` of `ubuntu:24.04` with it.
 *
 * The module imports nothing, so it can be vendored byte-identical into an
 * extension's `extensions/models/_lib/bogworks/` directory.
 *
 * @module
 */

/** One bind mount. */
export interface Mount {
  /** Absolute host path. */
  host: string;
  /** Absolute path inside the container. */
  container: string;
  /** Mount read-only (default true). */
  readonly?: boolean;
}

/** Options for {@link runInContainer}. */
export interface ContainerRunOptions {
  /** Image reference, e.g. `ubuntu:24.04`. */
  image: string;
  /** Bind mounts; read-only unless a mount says otherwise. */
  mounts?: Mount[];
  /** The command and its arguments. */
  cmd: string[];
  /** Kill the container after this many milliseconds. */
  timeoutMs: number;
  /** Environment variables set inside the container. */
  env?: Record<string, string>;
  /** Working directory inside the container. */
  workdir?: string;
  /** Text fed to the command's stdin. */
  stdin?: string;
  /** Allow network access (default false: `--network none`). */
  network?: boolean;
  /** Run as this user (`uid[:gid]`); the image default when omitted. */
  user?: string;
}

/** Result of {@link runInContainer}. */
export interface ContainerRunResult {
  /** Exit code of the command; -1 when it timed out. */
  code: number;
  stdout: string;
  stderr: string;
  /** True when the timeout killed the container. */
  timedOut: boolean;
  /** Wall-clock milliseconds. */
  durationMs: number;
}

const IMAGE_RE =
  /^[a-z0-9]+(?:[._-][a-z0-9]+)*(?:\/[a-z0-9]+(?:[._-][a-z0-9]+)*)*(?::[A-Za-z0-9._-]{1,128})?(?:@sha256:[a-f0-9]{64})?$/;
const ABS_PATH_RE = /^\/[^\0:,]*$/;
const ENV_NAME_RE = /^[A-Za-z_][A-Za-z0-9_]*$/;

/** Builds the `docker run` argv for the options, validating every input. */
export function dockerRunArgs(
  name: string,
  opts: ContainerRunOptions,
): string[] {
  if (!IMAGE_RE.test(opts.image)) {
    throw new Error(`invalid image reference ${JSON.stringify(opts.image)}`);
  }
  if (!Array.isArray(opts.cmd) || opts.cmd.length === 0) {
    throw new Error("cmd must have at least one element");
  }
  if (!Number.isInteger(opts.timeoutMs) || opts.timeoutMs < 1) {
    throw new Error("timeoutMs must be a positive integer");
  }
  const args = ["run", "--rm", "--name", name, "--init"];
  if (!opts.network) args.push("--network", "none");
  if (opts.stdin !== undefined) args.push("-i");
  for (const m of opts.mounts ?? []) {
    if (!ABS_PATH_RE.test(m.host) || !ABS_PATH_RE.test(m.container)) {
      throw new Error(
        `mount paths must be absolute without ':' or ',': ${m.host} -> ${m.container}`,
      );
    }
    args.push("-v", `${m.host}:${m.container}:${m.readonly === false ? "rw" : "ro"}`);
  }
  for (const [k, v] of Object.entries(opts.env ?? {})) {
    if (!ENV_NAME_RE.test(k)) throw new Error(`invalid env name ${JSON.stringify(k)}`);
    args.push("-e", `${k}=${v}`);
  }
  if (opts.workdir !== undefined) {
    if (!ABS_PATH_RE.test(opts.workdir)) throw new Error("workdir must be absolute");
    args.push("-w", opts.workdir);
  }
  if (opts.user !== undefined) {
    if (!/^[0-9]+(?::[0-9]+)?$/.test(opts.user)) {
      throw new Error("user must be uid or uid:gid");
    }
    args.push("--user", opts.user);
  }
  args.push(opts.image, ...opts.cmd);
  return args;
}

/** Runs a local command to completion, capturing output. */
async function runLocal(
  cmd: string,
  args: string[],
  stdin?: string,
): Promise<{ code: number; stdout: string; stderr: string }> {
  const child = new Deno.Command(cmd, {
    args,
    stdin: stdin === undefined ? "null" : "piped",
    stdout: "piped",
    stderr: "piped",
  }).spawn();
  if (stdin !== undefined) {
    const w = child.stdin.getWriter();
    try {
      await w.write(new TextEncoder().encode(stdin));
      await w.close();
    } catch {
      // the child may exit before reading all of stdin
    }
  }
  const out = await child.output();
  const dec = new TextDecoder();
  return {
    code: out.code,
    stdout: dec.decode(out.stdout),
    stderr: dec.decode(out.stderr),
  };
}

/**
 * Runs `cmd` in `image` with the given mounts (read-only by default), no
 * network, and a hard timeout. On timeout the container is killed by name, so
 * nothing lingers, and the result has `timedOut: true` and `code: -1`.
 */
export async function runInContainer(
  opts: ContainerRunOptions,
): Promise<ContainerRunResult> {
  const name = `bogworks-${crypto.randomUUID().slice(0, 12)}`;
  const args = dockerRunArgs(name, opts);
  const started = Date.now();
  const child = new Deno.Command("docker", {
    args,
    stdin: opts.stdin === undefined ? "null" : "piped",
    stdout: "piped",
    stderr: "piped",
  }).spawn();
  const feed = (async () => {
    if (opts.stdin === undefined) return;
    const w = child.stdin.getWriter();
    try {
      await w.write(new TextEncoder().encode(opts.stdin));
      await w.close();
    } catch {
      // the command may exit before reading all of stdin
    }
  })();
  let timer: ReturnType<typeof setTimeout> | undefined;
  let timedOut = false;
  const deadline = new Promise<"timeout">((resolve) => {
    timer = setTimeout(() => resolve("timeout"), opts.timeoutMs);
  });
  const work = child.output();
  const outcome = await Promise.race([work, deadline]);
  if (outcome === "timeout") {
    timedOut = true;
    await runLocal("docker", ["kill", name]).catch(() => undefined);
    try {
      child.kill("SIGKILL");
    } catch {
      // already gone
    }
  }
  if (timer !== undefined) clearTimeout(timer);
  const out = await work;
  await feed;
  const dec = new TextDecoder();
  return {
    code: timedOut ? -1 : out.code,
    stdout: dec.decode(out.stdout),
    stderr: dec.decode(out.stderr),
    timedOut,
    durationMs: Date.now() - started,
  };
}

/** Why docker, or an image, is not usable; `null` when it is. */
export interface DockerAvailability {
  ok: boolean;
  /** One-line reason suitable for a test's skip message. */
  reason: string | null;
}

const availability = new Map<string, Promise<DockerAvailability>>();

/**
 * Reports whether `docker` runs here and, when `image` is given, whether that
 * image is present locally (no pull is attempted: tests must not reach the
 * network). The answer is cached per image for the process.
 */
export function dockerAvailable(image?: string): Promise<DockerAvailability> {
  const key = image ?? "";
  let cached = availability.get(key);
  if (!cached) {
    cached = (async () => {
      let version: { code: number; stderr: string };
      try {
        version = await runLocal("docker", [
          "version",
          "--format",
          "{{.Server.Version}}",
        ]);
      } catch (e) {
        if (e instanceof Deno.errors.NotFound) {
          return { ok: false, reason: "docker is not installed" };
        }
        throw e;
      }
      if (version.code !== 0) {
        return {
          ok: false,
          reason: `docker daemon not reachable: ${version.stderr.trim().slice(0, 120)}`,
        };
      }
      if (image) {
        const img = await runLocal("docker", [
          "image",
          "inspect",
          "--format",
          "ok",
          image,
        ]);
        if (img.code !== 0) {
          return { ok: false, reason: `image ${image} is not present locally` };
        }
      }
      return { ok: true, reason: null };
    })();
    availability.set(key, cached);
  }
  return cached;
}
