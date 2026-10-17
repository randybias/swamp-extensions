/**
 * The seam between the k0s-cluster model and the vendored SSH transport.
 *
 * `ssh.ts` is the shared transport, copied unchanged from the SSH host
 * extension. This module narrows it to the three operations the model needs
 * and is the single place tests replace to avoid spawning ssh.
 *
 * @module
 */

import {
  denoDeps,
  exec,
  type ExecResult,
  type HostKey,
  type SshDeps,
  type SshTarget,
  upload,
  type UploadResult,
  waitConnection,
} from "./ssh.ts";

/** The transport the k0s-cluster model uses. */
export interface SshTransport {
  /**
   * Runs one argv on the host. A remote non-zero exit is returned as data; a
   * local `ssh` failure (exit 255) throws `SshError`.
   */
  exec(target: SshTarget, argv: string[]): Promise<ExecResult>;
  /** Writes bytes to a path atomically; unchanged bytes and mode are a no-op. */
  upload(
    target: SshTarget,
    file: { path: string; content: Uint8Array; mode: string },
  ): Promise<UploadResult>;
  /**
   * Reads the host's public keys once, for trust-on-first-use. Returns
   * `known_hosts` lines for exactly this host and port; the caller records
   * them and pins every later connection to them.
   */
  learnHostKeys(target: SshTarget, timeoutS: number): Promise<string[]>;
}

/** Formats one host key as a `known_hosts` line for `host` on `port`. */
export function hostKeyLine(
  host: string,
  port: number,
  key: Pick<HostKey, "type" | "key">,
): string {
  const field = port === 22 ? host : `[${host}]:${port}`;
  return `${field} ${key.type} ${key.key}`;
}

/** Builds the production transport over the vendored `ssh.ts`. */
export function createSshTransport(deps: SshDeps = denoDeps): SshTransport {
  return {
    exec: (target, argv) => exec(deps, target, argv),
    upload: (target, file) => upload(deps, target, file),
    learnHostKeys: async (target, timeoutS) => {
      const seen = await waitConnection(deps, target, {
        timeout_s: timeoutS,
        poll_interval_s: 1,
      });
      return seen.host_keys.map((k) =>
        hostKeyLine(target.host, target.port, k)
      );
    },
  };
}
