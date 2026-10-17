/**
 * Input decoding for one method call: the SSH block onto a transport target,
 * the stable data key, and the byte/base64 content helpers.
 *
 * @module
 */

import {
  assertHost,
  assertUser,
  type HostKeyPolicy,
  SshConfigError,
  type SshTarget,
} from "./ssh.ts";
import type { BasicAuthArgs, RootArgs, SshBlock, TlsArgs } from "./schema.ts";

/** Maps the SSH block onto a transport target, refusing bad combinations. */
export function toTarget(ssh: SshBlock): SshTarget {
  assertHost(ssh.host);
  assertUser(ssh.user);
  if (ssh.private_key && ssh.password) {
    throw new SshConfigError("pass private_key or password, not both");
  }
  return {
    host: ssh.host,
    port: ssh.port,
    user: ssh.user,
    host_key_policy: ssh.host_key_policy as HostKeyPolicy,
    host_keys: ssh.host_keys,
    private_key: ssh.private_key ?? undefined,
    password: ssh.password ?? undefined,
    connect_timeout_s: ssh.connect_timeout_s,
    max_output_bytes: ssh.max_output_bytes,
  };
}

/** Replaces every character outside `[A-Za-z0-9._-]` with `_`. */
function sanitizeKey(value: string): string {
  return value.replace(/[^A-Za-z0-9._-]/g, "_");
}

/** A short, stable FNV-1a hash in hex, to keep encoded keys distinct. */
function shortKeyHash(value: string): string {
  let h = 2166136261 >>> 0;
  for (let i = 0; i < value.length; i++) {
    h ^= value.charCodeAt(i);
    h = Math.imul(h, 16777619) >>> 0;
  }
  return h.toString(16).padStart(8, "0");
}

/**
 * The stable data key for one target and root. The target and root are encoded
 * so no `/`, `:` or other unsafe character reaches a resource instance name,
 * and a short hash keeps distinct targets from colliding after encoding.
 */
export function instanceKey(args: RootArgs): string {
  const raw = `${args.ssh.host}:${args.ssh.port}/${args.ssh.user}@${args.root}`;
  const host = sanitizeKey(args.ssh.host).slice(0, 40);
  const user = sanitizeKey(args.ssh.user).slice(0, 16);
  const root = sanitizeKey(args.root).slice(0, 32);
  return `${host}-${args.ssh.port}-${user}-${root}-${shortKeyHash(raw)}`;
}

/** Decodes `content`/`content_base64`, refusing both or neither. */
export function contentBytes(args: {
  content?: string | null;
  content_base64?: string | null;
}): Uint8Array {
  if (args.content != null && args.content_base64 != null) {
    throw new SshConfigError("pass content or content_base64, not both");
  }
  if (args.content != null) return new TextEncoder().encode(args.content);
  if (args.content_base64 != null) return base64Decode(args.content_base64);
  throw new SshConfigError("content is required");
}

/** Decodes strict base64, refusing invalid input. */
function base64Decode(value: string): Uint8Array {
  const binary = atob(value);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
  return out;
}

/** Validates the shared preconditions that need no remote call. */
export function validateCommon(
  args: RootArgs & {
    tls: TlsArgs;
    basic_auth?: BasicAuthArgs | null;
    basic_auth_plaintext_ack?: boolean | null;
  },
): void {
  if (
    args.basic_auth && args.tls.mode === "none" &&
    args.basic_auth_plaintext_ack !== true
  ) {
    throw new SshConfigError(
      "basic auth over plain HTTP requires basic_auth_plaintext_ack: true",
    );
  }
}
