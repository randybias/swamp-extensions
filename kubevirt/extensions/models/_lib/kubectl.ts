/**
 * kubectl plumbing for the Secret model.
 *
 * Secret values never appear on a command line. The Secret manifest is built
 * in memory and streamed to `kubectl apply -f -` on stdin; the kubeconfig is
 * written to a `0600` temporary file that is removed in a `finally`. Every
 * failure is mapped to a fixed, typed message: remote `kubectl` output is
 * never returned, so neither the kubeconfig nor the Secret values (or their
 * base64 forms) can be read back out of an error.
 *
 * @module
 */

import { checkCanonical } from "./kubeconfig.ts";

/** Result of running kubectl. */
export interface KubectlResult {
  /** Process exit code. */
  code: number;
  /** Captured standard output. */
  stdout: string;
  /** Captured standard error. */
  stderr: string;
}

/** Spawns kubectl; injectable so tests start no process. */
export type KubectlRunner = (
  args: string[],
  options: { stdin?: string; env: Record<string, string> },
) => Promise<KubectlResult>;

/** Writes the kubeconfig to a private file; injectable for tests. */
export interface KubeconfigFiles {
  /** Writes `content` to a new `0600` file and returns its path. */
  write(content: string): Promise<string>;
  /** Removes a file written by `write`; must not throw if it is gone. */
  remove(path: string): Promise<void>;
}

/** Why a kubectl call failed. */
export type K8sErrorCode =
  | "unreachable"
  | "unauthorized"
  | "namespace_not_found"
  | "invalid_input"
  | "not_found"
  | "kubectl_failed";

/** A typed failure whose message carries no secret value. */
export class K8sSecretError extends Error {
  /** The failure class. */
  readonly code: K8sErrorCode;
  /** Creates a typed error. */
  constructor(code: K8sErrorCode, message: string) {
    super(message);
    this.name = "K8sSecretError";
    this.code = code;
  }
}

/** Injectable dependencies. */
export interface Deps {
  /** Runs kubectl. */
  run: KubectlRunner;
  /** Handles the temporary kubeconfig file. */
  files: KubeconfigFiles;
  /** Current time. */
  now: () => Date;
}

const denoRun: KubectlRunner = async (args, options) => {
  // swamp-quality-ignore deno-command
  const cmd = new Deno.Command("kubectl", {
    args,
    env: options.env,
    clearEnv: true,
    stdin: options.stdin === undefined ? "null" : "piped",
    stdout: "piped",
    stderr: "piped",
  });
  const child = cmd.spawn();
  if (options.stdin !== undefined) {
    const w = child.stdin.getWriter();
    await w.write(new TextEncoder().encode(options.stdin));
    await w.close();
  }
  const out = await child.output();
  const dec = new TextDecoder();
  return {
    code: out.code,
    stdout: dec.decode(out.stdout),
    stderr: dec.decode(out.stderr),
  };
};

/** Low-level file operations; injectable so the failure path is testable. */
export interface TempFileIo {
  /** Creates a private temporary file. */
  makeTempFile(options: { prefix: string }): Promise<string>;
  /** Restricts the file mode. */
  chmod(path: string, mode: number): Promise<void>;
  /** Writes text to the file. */
  writeText(path: string, content: string): Promise<void>;
  /** Removes the file. */
  remove(path: string): Promise<void>;
}

const denoTempIo: TempFileIo = {
  makeTempFile: (options) => Deno.makeTempFile(options),
  chmod: (path, mode) => Deno.chmod(path, mode),
  writeText: (path, content) => Deno.writeTextFile(path, content),
  remove: (path) => Deno.remove(path),
};

/**
 * Writes `content` to a new `0600` temporary file. If any step after creation
 * fails, the file is removed before the error is rethrown, so a partial
 * kubeconfig is never left behind.
 */
export async function writePrivateTempFile(
  content: string,
  io: TempFileIo = denoTempIo,
): Promise<string> {
  const path = await io.makeTempFile({ prefix: "kubeconfig-" });
  try {
    await io.chmod(path, 0o600);
    await io.writeText(path, content);
    return path;
  } catch (e) {
    try {
      await io.remove(path);
    } catch {
      // The file is already gone; nothing to clean up.
    }
    throw e;
  }
}

const denoFiles: KubeconfigFiles = {
  write: (content) => writePrivateTempFile(content),
  async remove(path) {
    try {
      await Deno.remove(path);
    } catch (e) {
      if (!(e instanceof Deno.errors.NotFound)) throw e;
    }
  },
};

/** Production dependencies. */
export function defaultDeps(): Deps {
  return { run: denoRun, files: denoFiles, now: () => new Date() };
}

/** Prefix of the server-side apply field manager. */
export const FIELD_MANAGER_PREFIX = "swamp-k8s-secret";

/**
 * Stable server-side apply field manager for one model definition. Deriving it
 * from the definition name keeps two definitions that target the same Secret
 * from sharing ownership, so neither prunes the other's keys.
 */
export async function fieldManager(definitionName: string): Promise<string> {
  return `${FIELD_MANAGER_PREFIX}-${
    (await sha256Hex(definitionName)).slice(0, 12)
  }`;
}

const DNS_LABEL = /^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$/;
const DNS_SUBDOMAIN =
  /^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?(\.[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?)*$/;
/** Allowed Secret key characters (Kubernetes rule). */
export const KEY_RE = /^[-._a-zA-Z0-9]{1,253}$/;
const CONTEXT_RE = /^[A-Za-z0-9][-A-Za-z0-9._:/@=+]{0,252}$/;
const TYPE_RE = /^[A-Za-z0-9][-A-Za-z0-9._/]{0,252}$/;

/** True for a valid DNS-1123 label (namespace). */
export const isNamespace = (s: string): boolean => DNS_LABEL.test(s);
/** True for a valid DNS-1123 subdomain (Secret name). */
export const isSecretName = (s: string): boolean =>
  s.length <= 253 && DNS_SUBDOMAIN.test(s);
/** True for a valid kubeconfig context name. */
export const isContext = (s: string): boolean => CONTEXT_RE.test(s);
/** True for a valid Secret type string. */
export const isSecretType = (s: string): boolean => TYPE_RE.test(s);
/** True for a valid Secret data key. */
export const isDataKey = (s: string): boolean =>
  KEY_RE.test(s) && s !== "." && s !== ".." && s !== "__proto__";

/** Decodes standard base64 to raw bytes. */
export function b64ToBytes(s: string): Uint8Array<ArrayBuffer> {
  const bin = atob(s);
  return Uint8Array.from(bin, (c) => c.charCodeAt(0));
}

/** Hex sha256 of raw bytes. */
export async function sha256HexBytes(
  bytes: Uint8Array<ArrayBuffer>,
): Promise<string> {
  const d = await crypto.subtle.digest("SHA-256", bytes);
  return [...new Uint8Array(d)].map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

/** Hex sha256 of a UTF-8 string. */
export async function sha256Hex(s: string): Promise<string> {
  return await sha256HexBytes(new TextEncoder().encode(s));
}

/**
 * Per-key sha256 of the desired values (their UTF-8 bytes). Used only
 * in-process to decide whether an apply is a no-op; never written to state or
 * returned.
 */
export async function hashData(
  data: Record<string, string>,
): Promise<Record<string, string>> {
  const keys: Record<string, string> = Object.create(null);
  for (const k of Object.keys(data).sort()) keys[k] = await sha256Hex(data[k]);
  return keys;
}

/**
 * Per-key sha256 of a live Secret's `data`, hashing the stored bytes rather
 * than a decoded string, so a binary value hashes correctly. Used only
 * in-process to compare against the desired values.
 */
export async function hashObserved(
  dataB64: Record<string, string>,
): Promise<Record<string, string>> {
  const keys: Record<string, string> = Object.create(null);
  for (const k of Object.keys(dataB64).sort()) {
    keys[k] = await sha256HexBytes(b64ToBytes(dataB64[k]));
  }
  return keys;
}

/** Standard base64 of a UTF-8 string. */
export function b64(s: string): string {
  let bin = "";
  for (const b of new TextEncoder().encode(s)) bin += String.fromCharCode(b);
  return btoa(bin);
}

/** Decodes standard base64 to a UTF-8 string. */
export function unb64(s: string): string {
  return new TextDecoder().decode(b64ToBytes(s));
}

/** Target of a kubectl call. */
export interface Target {
  /** Kubeconfig content. */
  kubeconfig: string;
  /** Context, or undefined for the current context. */
  context?: string;
  /** Namespace. */
  namespace: string;
  /** Secret name. */
  name: string;
}

/** Builds the Secret manifest; values are base64 in `data`, never argv. */
export function buildManifest(
  t: Target,
  type: string,
  data: Record<string, string>,
): string {
  const enc: Record<string, string> = Object.create(null);
  for (const k of Object.keys(data).sort()) enc[k] = b64(data[k]);
  return JSON.stringify({
    apiVersion: "v1",
    kind: "Secret",
    metadata: {
      name: t.name,
      namespace: t.namespace,
    },
    type,
    data: enc,
  });
}

function baseArgs(t: Target): string[] {
  return [
    ...(t.context ? ["--context", t.context] : []),
    "--namespace",
    t.namespace,
    "--request-timeout=30s",
  ];
}

/** One `metadata.managedFields` entry, narrowed to the fields we read. */
export interface ManagedFieldEntry {
  /** Who wrote the fields. */
  manager?: string;
  /** `Apply` for server-side apply, `Update` otherwise. */
  operation?: string;
  /** The applied field set. */
  fieldsV1?: { "f:data"?: Record<string, unknown> };
}

/**
 * The `data` keys a given field manager owns through server-side apply. Used
 * to ignore keys owned by other tools when deciding whether an apply is a
 * no-op, and to detect a key this manager must prune.
 */
export function ownedDataKeys(
  entries: ManagedFieldEntry[] | undefined,
  manager: string,
): string[] {
  const keys = new Set<string>();
  for (const e of entries ?? []) {
    if (e.manager !== manager || e.operation !== "Apply") continue;
    for (const k of Object.keys(e.fieldsV1?.["f:data"] ?? {})) {
      if (k.startsWith("f:")) keys.add(k.slice(2));
    }
  }
  return [...keys].sort();
}

/**
 * Maps kubectl stderr to a typed error with a fixed message. The stderr is
 * matched but never included: it can echo the manifest, including base64
 * values, which `scrub` cannot reliably remove.
 */
export function classify(stderr: string, t: Target): K8sSecretError {
  if (/namespaces? "[^"]*" not found/i.test(stderr)) {
    return new K8sSecretError(
      "namespace_not_found",
      `Namespace ${t.namespace} does not exist`,
    );
  }
  if (/unauthorized|forbidden|must be logged in|credentials/i.test(stderr)) {
    return new K8sSecretError(
      "unauthorized",
      "Not authorized to access the API server",
    );
  }
  if (
    /unable to connect|connection refused|no such host|i\/o timeout|timed out|dial tcp|tls: |context deadline|no route to host/i
      .test(stderr)
  ) {
    return new K8sSecretError("unreachable", "API server unreachable");
  }
  return new K8sSecretError("kubectl_failed", "kubectl failed");
}

/**
 * Runs `fn` with a kubectl runner bound to a temporary kubeconfig, removing
 * every file in a `finally`, even when `fn` throws. The caller's text is first
 * written to a private file only so `kubectl config view --raw -o json` can
 * resolve it exactly as kubectl will (merge keys and all; this does not
 * authenticate or run any plugin and does not read credential files). That
 * canonical document is validated, and only it is written to the file kubectl
 * uses afterwards. A failure to launch kubectl is reported without its
 * exception text.
 */
export async function withKubectl<T>(
  deps: Deps,
  t: Target,
  fn: (
    kubectl: (args: string[], stdin?: string) => Promise<KubectlResult>,
  ) => Promise<T>,
): Promise<T> {
  const base = {
    PATH: Deno.env.get("PATH") ?? "/usr/local/bin:/usr/bin:/bin",
    HOME: Deno.env.get("HOME") ?? "/tmp",
  };
  const written: string[] = [];
  try {
    const rawPath = await deps.files.write(t.kubeconfig);
    written.push(rawPath);
    let view: KubectlResult;
    try {
      view = await deps.run(["config", "view", "--raw", "-o", "json"], {
        env: { ...base, KUBECONFIG: rawPath },
      });
    } catch {
      throw new K8sSecretError("kubectl_failed", "Could not run kubectl");
    }
    if (view.code !== 0) {
      throw new K8sSecretError(
        "invalid_input",
        "kubectl could not load the kubeconfig",
      );
    }
    const check = checkCanonical(view.stdout);
    if (!check.ok) throw new K8sSecretError("invalid_input", check.reason);
    const path = await deps.files.write(view.stdout);
    written.push(path);
    const env: Record<string, string> = { ...base, KUBECONFIG: path };
    return await fn(async (args, stdin) => {
      try {
        return await deps.run([...args, ...baseArgs(t)], { stdin, env });
      } catch {
        throw new K8sSecretError(
          "kubectl_failed",
          "Could not run kubectl",
        );
      }
    });
  } finally {
    for (const path of written) await deps.files.remove(path);
  }
}
