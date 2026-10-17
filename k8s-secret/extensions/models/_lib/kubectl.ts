/**
 * kubectl plumbing for the Secret model.
 *
 * Secret values never appear on a command line. The Secret manifest is built
 * in memory and streamed to `kubectl apply -f -` on stdin; the kubeconfig is
 * written to a `0600` temporary file that is removed in a `finally`. Error
 * text is scrubbed of every secret value before it leaves this module.
 *
 * @module
 */

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

const denoFiles: KubeconfigFiles = {
  async write(content) {
    const path = await Deno.makeTempFile({ prefix: "kubeconfig-" });
    await Deno.chmod(path, 0o600);
    await Deno.writeTextFile(path, content);
    return path;
  },
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
  KEY_RE.test(s) && s !== "." && s !== "..";

/** Hex sha256 of a string. */
export async function sha256Hex(s: string): Promise<string> {
  const d = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s));
  return [...new Uint8Array(d)].map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

/** Per-key sha256 of the values, plus one digest over the sorted pairs. */
export async function hashData(
  data: Record<string, string>,
): Promise<{ keys: Record<string, string>; total: string }> {
  const keys: Record<string, string> = {};
  for (const k of Object.keys(data).sort()) keys[k] = await sha256Hex(data[k]);
  const total = await sha256Hex(
    Object.entries(keys).map(([k, h]) => `${k}=${h}`).join("\n"),
  );
  return { keys, total };
}

/** Standard base64 of a UTF-8 string. */
export function b64(s: string): string {
  let bin = "";
  for (const b of new TextEncoder().encode(s)) bin += String.fromCharCode(b);
  return btoa(bin);
}

/** Decodes standard base64 to a UTF-8 string. */
export function unb64(s: string): string {
  const bin = atob(s);
  return new TextDecoder().decode(Uint8Array.from(bin, (c) => c.charCodeAt(0)));
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
  const enc: Record<string, string> = {};
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

/** Replaces every secret fragment in `text` with a marker. */
export function scrub(text: string, secrets: string[]): string {
  let out = text;
  for (const s of secrets) {
    if (s.length >= 3) out = out.split(s).join("[redacted]");
  }
  return out.slice(0, 1000);
}

/** Maps kubectl stderr to a typed error. */
export function classify(
  stderr: string,
  t: Target,
  secrets: string[],
): K8sSecretError {
  const text = scrub(stderr.trim(), secrets);
  if (/namespaces? "[^"]*" not found/i.test(text)) {
    return new K8sSecretError(
      "namespace_not_found",
      `Namespace ${t.namespace} does not exist`,
    );
  }
  if (/unauthorized|forbidden|must be logged in|credentials/i.test(text)) {
    return new K8sSecretError("unauthorized", `Not authorized: ${text}`);
  }
  if (
    /unable to connect|connection refused|no such host|i\/o timeout|timed out|dial tcp|tls: |context deadline|no route to host/i
      .test(text)
  ) {
    return new K8sSecretError("unreachable", `API server unreachable: ${text}`);
  }
  return new K8sSecretError("kubectl_failed", `kubectl failed: ${text}`);
}

/**
 * Runs `fn` with a kubectl runner bound to a temporary kubeconfig, removing
 * the file in a `finally`, even when `fn` throws.
 */
export async function withKubectl<T>(
  deps: Deps,
  t: Target,
  secrets: string[],
  fn: (
    kubectl: (args: string[], stdin?: string) => Promise<KubectlResult>,
  ) => Promise<T>,
): Promise<T> {
  const path = await deps.files.write(t.kubeconfig);
  try {
    const env: Record<string, string> = {
      KUBECONFIG: path,
      PATH: Deno.env.get("PATH") ?? "/usr/local/bin:/usr/bin:/bin",
      HOME: Deno.env.get("HOME") ?? "/tmp",
    };
    return await fn(async (args, stdin) => {
      let r: KubectlResult;
      try {
        r = await deps.run([...args, ...baseArgs(t)], { stdin, env });
      } catch (e) {
        throw new K8sSecretError(
          "kubectl_failed",
          `Could not run kubectl: ${scrub(String(e), secrets)}`,
        );
      }
      return r;
    });
  } finally {
    await deps.files.remove(path);
  }
}
