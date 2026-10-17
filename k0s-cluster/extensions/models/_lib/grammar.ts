/**
 * Shared input grammars for every caller-supplied value that reaches a remote
 * shell or a filesystem path.
 *
 * One definition per grammar, so the SSH transport, the k0s helpers and the
 * model cannot drift apart. These are pure predicates and regular expressions;
 * callers turn a failure into their own typed error.
 *
 * @module
 */

/** Hostname or IP literal accepted for an SSH target, an API SAN or a URL host. */
export const HOST_RE =
  /^(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$|^[0-9a-fA-F:.]{2,45}$/;

/** Conventional POSIX user name. */
export const USER_RE = /^[a-z_][a-z0-9_-]{0,31}$/;

/** DNS-1123 label. */
export const NAME_RE = /^[a-z0-9](?:[-a-z0-9]{0,61}[a-z0-9])?$/;

/** Absolute remote path made only of safe characters. */
export const REMOTE_PATH_RE = /^\/[A-Za-z0-9._/-]{1,255}$/;

/** Octal file mode, with or without a leading zero. */
export const MODE_RE = /^[0-7]{3,4}$/;

/** Path relative to a manifest stack directory. */
export const MANIFEST_PATH_RE = /^[A-Za-z0-9._][A-Za-z0-9._/-]{0,254}$/;

/** One file name with no directory separator. */
export const SAFE_FILENAME_RE = /^[A-Za-z0-9._-]{1,255}$/;

/** HTTPS URL with no shell metacharacters. */
export const SAFE_URL_RE = /^https:\/\/[A-Za-z0-9][A-Za-z0-9._~:/!()*,=%+-]*$/;

/** True for an IPv4 or IPv6 CIDR with an in-range prefix. */
export function isCidr(value: string): boolean {
  const slash = value.indexOf("/");
  if (slash < 1) return false;
  const address = value.slice(0, slash);
  const prefix = value.slice(slash + 1);
  if (!/^\d{1,3}$/.test(prefix)) return false;
  const bits = Number(prefix);
  if (address.includes(":")) {
    if (!/^[0-9a-fA-F:]+$/.test(address)) return false;
    return bits >= 0 && bits <= 128;
  }
  const octets = address.split(".");
  if (octets.length !== 4) return false;
  return octets.every((octet) =>
    /^\d{1,3}$/.test(octet) && Number(octet) <= 255
  ) && bits >= 0 && bits <= 32;
}

/** True for one safe file name that is neither `.` nor `..`. */
export function isSafeFilename(name: string): boolean {
  return SAFE_FILENAME_RE.test(name) && name !== "." && name !== "..";
}

/** Collapses empty and `.` path segments; callers reject `..` before using it. */
export function normalizeManifestPath(path: string): string {
  return path.split("/").filter((segment) => segment !== "" && segment !== ".")
    .join("/");
}

/**
 * True when a URL carries anything that could hold a credential: user info, a
 * query string or a fragment. Authentication belongs in separate sensitive
 * inputs, never in a URL that is stored, logged or written to `k0s.yaml`.
 */
export function hasUrlCredentials(url: string): boolean {
  try {
    const parsed = new URL(url);
    return parsed.username !== "" || parsed.password !== "" ||
      parsed.search !== "" || parsed.hash !== "" || url.includes("?") ||
      url.includes("#") || url.includes("@");
  } catch {
    return true;
  }
}

/**
 * True for a manifest path that names one concrete file below the stack
 * directory: it must still be non-empty after empty and `.` segments are
 * removed, and may not contain `..`.
 */
export function isConcreteManifestPath(path: string): boolean {
  const normalized = normalizeManifestPath(path);
  return normalized !== "" && !normalized.split("/").includes("..") &&
    path !== "." && !path.endsWith("/");
}
