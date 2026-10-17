/**
 * Input grammars shared by every cephadm method, and POSIX single-quoting.
 *
 * Each field kind has a schema regex and a runtime assertion built from the
 * same rule. The schema is the first gate; the runtime form re-checks a value
 * at the point of assembly, because a value may come from stored state or a
 * remote host rather than from the caller. Values that legitimately contain
 * shell-significant characters are both validated and quoted.
 *
 * @module
 */

import { fail } from "./errors.ts";

/** Truncates a rejected value for an error detail, never longer than 100 chars. */
export function truncate(value: string, max = 100): string {
  return value.length <= max ? value : `${value.slice(0, max)}…`;
}

/** Checks a value against `rule`, returning it unchanged on success. */
export function assertGrammar(
  field: string,
  value: string,
  ok: boolean,
  rule: string,
): string {
  if (!ok) {
    fail("validate", `invalid ${field}`, {
      field,
      value: truncate(value),
      rule,
    });
  }
  return value;
}

/** Dotted release number as printed by `cephadm version`, e.g. `19.2.1`. */
export const CEPHADM_VERSION_RE = /^\d+(?:\.\d+)+$/;

/** Ceph identifier, create direction: no leading dot, hyphen or underscore. */
export const CEPH_ID_CREATE_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;

/** Ceph identifier, reference direction: may begin with a dot. */
export const CEPH_ID_REF_RE = /^[A-Za-z0-9.][A-Za-z0-9._-]{0,127}$/;

/** Ceph caps expression: letters, digits, space, quotes, `= * / , . _ -`. */
export const CAPS_RE = /^[A-Za-z0-9 '"=*/._,+-]{1,512}$/;

/** Device serial: 1–40 letters, digits or hyphens. */
export const SERIAL_RE = /^[A-Za-z0-9-]{1,40}$/;

/** Hostname: dot-separated RFC 1123 labels, each 1–63 characters. */
export const HOSTNAME_RE =
  /^(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$/;

/** POSIX portable username, at most 32 characters. */
export const SSH_USER_RE = /^[A-Za-z_][A-Za-z0-9_.-]{0,31}$/;

/** Cluster fsid: RFC 4122 textual UUID. */
export const FSID_RE =
  /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/;

/** Debian package name: at least two characters, no qualifier or pin. */
export const DEB_PACKAGE_RE = /^[a-z0-9][a-z0-9+.-]+$/;

/** systemd unit name for a time-sync service. */
export const UNIT_RE = /^[A-Za-z0-9@._:-]{1,255}$/;

/** Absolute local path with no control characters. */
export function isKeyPath(value: string): boolean {
  if (!value.startsWith("/")) return false;
  for (const ch of value) {
    const code = ch.codePointAt(0) ?? 0;
    if (code < 0x20 || code === 0x7f) return false;
  }
  return true;
}

/** True when `value` is exactly four dot-separated decimal octets, 0–255, no leading zero. */
export function isIpv4(value: string): boolean {
  const parts = value.split(".");
  if (parts.length !== 4) return false;
  return parts.every((p) => {
    if (!/^\d{1,3}$/.test(p)) return false;
    if (p.length > 1 && p.startsWith("0")) return false;
    const n = Number(p);
    return n >= 0 && n <= 255;
  });
}

/** True when `value` is a V12 host target (hostname or IPv4). */
export function isHostTarget(value: string): boolean {
  if (value.includes(":")) return false;
  // An all-numeric host must be a valid IPv4, never a bare-label hostname.
  if (/^\d+(?:\.\d+)*$/.test(value)) return isIpv4(value);
  return HOSTNAME_RE.test(value);
}

/** The IPv6 refusal message, used wherever a colon is out of scope. */
export const IPV6_REFUSAL = "IPv6 is not supported";

/** True for an IPv4 CIDR whose host bits are zero. */
export function isIpv4Cidr(value: string): boolean {
  const slash = value.indexOf("/");
  if (slash < 0) return false;
  const addr = value.slice(0, slash);
  const prefixRaw = value.slice(slash + 1);
  if (!isIpv4(addr)) return false;
  if (!/^\d{1,2}$/.test(prefixRaw)) return false;
  if (prefixRaw.length > 1 && prefixRaw.startsWith("0")) return false;
  const prefix = Number(prefixRaw);
  if (prefix < 0 || prefix > 32) return false;
  const octets = addr.split(".").map(Number);
  const asInt =
    ((octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3]) >>>
    0;
  const mask = prefix === 0 ? 0 : (~0 << (32 - prefix)) >>> 0;
  return (asInt & mask) >>> 0 === asInt;
}

/**
 * Allowlist for a raw HTTP(S) URL. Every character must be one this grammar
 * names, so shell metacharacters, whitespace, backslashes and userinfo are
 * refused by construction rather than by a denylist.
 */
const URL_ALLOWED =
  /^https?:\/\/[A-Za-z0-9.-]+(?::\d{1,5})?(?:\/[A-Za-z0-9._~%!+,=:@/-]*)?(?:\?[A-Za-z0-9._~%!+,=:@/?-]*)?(?:#[A-Za-z0-9._~%!+,=:@/?-]*)?$/;

/** True when `raw` is an absolute http/https URL with an allowlisted shape and no userinfo. */
export function isHttpUrl(raw: string): boolean {
  if (raw === "" || !URL_ALLOWED.test(raw)) return false;
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    return false;
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") return false;
  if (url.username !== "" || url.password !== "") return false;
  if (url.hostname === "") return false;
  return isHostTarget(url.hostname);
}

/** Removes any userinfo from a URL for safe display in an error or log. */
export function redactUrl(raw: string): string {
  // Drop userinfo, then any query or fragment, which can carry credentials.
  return raw
    .replace(/^([A-Za-z][A-Za-z0-9+.-]*:\/\/)[^@/\s]*@/, "$1")
    .replace(/^([A-Za-z][A-Za-z0-9+.-]*:\/\/\S*?)[?#].*$/, "$1");
}

/** LVM volume-group name: letters, digits, plus, underscore, dot, hyphen; no leading hyphen. */
export const VG_NAME_RE = /^[A-Za-z0-9+_.-]{1,128}$/;

/** Runtime assertion: `value` is a safe LVM volume-group name. */
export function assertVgName(field: string, value: string): string {
  return assertGrammar(
    field,
    value,
    VG_NAME_RE.test(value) && !value.startsWith("-"),
    "an LVM volume-group name",
  );
}

/** An md array path under `/dev/md`, no traversal. */
export const MD_ARRAY_RE = /^\/dev\/md[0-9A-Za-z._/-]*$/;

/** Runtime assertion: `value` is a safe md array path. */
export function assertMdArrayPath(field: string, value: string): string {
  return assertGrammar(
    field,
    value,
    MD_ARRAY_RE.test(value) && !value.includes(".."),
    "an md array path under /dev/md",
  );
}

const SSH_KEY_TYPES = new Set([
  "ssh-ed25519",
  "sk-ssh-ed25519@openssh.com", // leak-allow(public key algorithm name)
  "ecdsa-sha2-nistp256",
  "ecdsa-sha2-nistp384",
  "ecdsa-sha2-nistp521",
  "sk-ecdsa-sha2-nistp256@openssh.com", // leak-allow(public key algorithm name)
  "ssh-rsa",
  "ssh-dss",
]);

const KEY_BLOB_RE = /^[A-Za-z0-9+/]{20,}={0,2}$/;

/** True when `value` is exactly a typed SSH public key line, no options and no CR/LF. */
export function isSshPublicKey(value: string): boolean {
  if (/[\r\n]/.test(value) || value.length < 1 || value.length > 8192) {
    return false;
  }
  const fields = value.split(" ");
  if (fields.length !== 2 && fields.length !== 3) return false;
  if (fields.some((f) => f === "")) return false;
  if (!SSH_KEY_TYPES.has(fields[0])) return false;
  if (!KEY_BLOB_RE.test(fields[1])) return false;
  return true;
}

const IMAGE_COMPONENT_RE = /^[a-z0-9]+(?:(?:[._]|__|[-]+)[a-z0-9]+)*$/;
const TAG_RE = /^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$/;
const DIGEST_RE = /^sha256:[0-9a-f]{64}$/;

/** True when `value` is an OCI image reference with a tag or digest, so it is pinned. */
export function isContainerImage(value: string): boolean {
  if (value === "" || value.length > 255 || /\s/.test(value)) return false;
  let rest = value;
  let hasDigest = false;
  const at = rest.indexOf("@");
  if (at >= 0) {
    const digest = rest.slice(at + 1);
    if (!DIGEST_RE.test(digest)) return false;
    hasDigest = true;
    rest = rest.slice(0, at);
  }
  // A tag is a `:` after the last `/` (so a registry port is not mistaken for one).
  let tag: string | null = null;
  const lastSlash = rest.lastIndexOf("/");
  const lastColon = rest.lastIndexOf(":");
  if (lastColon > lastSlash) {
    tag = rest.slice(lastColon + 1);
    rest = rest.slice(0, lastColon);
    if (!TAG_RE.test(tag)) return false;
  }
  if (!hasDigest && tag === null) return false;
  const components = rest.split("/");
  if (components.some((c) => c === "")) return false;
  // The first component is a registry only when it looks like a host (dot, colon or localhost).
  const first = components[0];
  const firstIsRegistry = components.length > 1 &&
    (first.includes(".") || first.includes(":") || first === "localhost");
  const pathParts = firstIsRegistry ? components.slice(1) : components;
  if (firstIsRegistry && !isRegistryHost(first)) return false;
  if (pathParts.length === 0) return false;
  return pathParts.every((c) => IMAGE_COMPONENT_RE.test(c));
}

function isRegistryHost(value: string): boolean {
  const colon = value.lastIndexOf(":");
  if (colon >= 0) {
    const host = value.slice(0, colon);
    const port = value.slice(colon + 1);
    if (!/^\d{1,5}$/.test(port) || Number(port) > 65535) return false;
    return HOSTNAME_RE.test(host);
  }
  return HOSTNAME_RE.test(value) || value === "localhost";
}

/** Runtime assertion: `value` is a V1 ceph identifier. */
export function assertCephIdCreate(field: string, value: string): string {
  return assertGrammar(
    field,
    value,
    CEPH_ID_CREATE_RE.test(value),
    "letters, digits, dot, underscore or hyphen, starting with a letter or digit",
  );
}

/** Runtime assertion: `value` is a V2 ceph identifier (reference direction). */
export function assertCephIdRef(field: string, value: string): string {
  const ok = CEPH_ID_REF_RE.test(value) && !/^\.+$/.test(value);
  return assertGrammar(
    field,
    value,
    ok,
    "letters, digits, dot, underscore or hyphen, not only dots",
  );
}

/** Runtime assertion: `value` is a V3 caps expression. */
export function assertCaps(field: string, value: string): string {
  return assertGrammar(
    field,
    value,
    CAPS_RE.test(value),
    "letters, digits, spaces, quotes and the characters = * / , . _ - +",
  );
}

/** Runtime assertion: `value` is a V4 device serial. */
export function assertSerial(field: string, value: string): string {
  return assertGrammar(
    field,
    value,
    SERIAL_RE.test(value),
    "1-40 letters, digits or hyphens",
  );
}

/** Runtime assertion: `value` is a V5 hostname. */
export function assertHostname(field: string, value: string): string {
  return assertGrammar(
    field,
    value,
    HOSTNAME_RE.test(value),
    "an RFC 1123 hostname",
  );
}

/** Runtime assertion: `value` is a V12 host target. */
export function assertHostTarget(field: string, value: string): string {
  if (value.includes(":")) {
    fail("validate", `invalid ${field}`, {
      field,
      value: truncate(value),
      rule: IPV6_REFUSAL,
    });
  }
  return assertGrammar(
    field,
    value,
    isHostTarget(value),
    "a hostname or IPv4 address",
  );
}

/** Runtime assertion: `value` is a V7 IPv4 address. */
export function assertIpv4(field: string, value: string): string {
  if (value.includes(":")) {
    fail("validate", `invalid ${field}`, {
      field,
      value: truncate(value),
      rule: IPV6_REFUSAL,
    });
  }
  return assertGrammar(
    field,
    value,
    isIpv4(value),
    "a dotted-quad IPv4 address, no leading zeros",
  );
}

/** Runtime assertion: `value` is a V13 IPv4 CIDR with host bits zero. */
export function assertIpv4Cidr(field: string, value: string): string {
  if (value.includes(":")) {
    fail("validate", `invalid ${field}`, {
      field,
      value: truncate(value),
      rule: IPV6_REFUSAL,
    });
  }
  return assertGrammar(
    field,
    value,
    isIpv4Cidr(value),
    "an IPv4 CIDR with a prefix length 0-32 and host bits zero",
  );
}

/** Runtime assertion: `value` is a V8 HTTP(S) URL. */
export function assertHttpUrl(field: string, value: string): string {
  if (!isHttpUrl(value)) {
    // Never echo the URL: it can carry credentials in userinfo or a query.
    fail("validate", `invalid ${field}`, {
      field,
      rule:
        "an absolute http or https URL with no userinfo or shell metacharacters",
    });
  }
  return value;
}

/** Runtime assertion: `value` is a V9 SSH public key line. */
export function assertSshPublicKey(field: string, value: string): string {
  return assertGrammar(
    field,
    value,
    isSshPublicKey(value),
    "a single <keytype> <blob> [comment] line with no options",
  );
}

/** Runtime assertion: `value` is a V10 cluster fsid. */
export function assertFsid(field: string, value: string): string {
  return assertGrammar(field, value, FSID_RE.test(value), "an RFC 4122 UUID");
}

/** Runtime assertion: `value` is a V14 Debian package name. */
export function assertDebPackage(field: string, value: string): string {
  return assertGrammar(
    field,
    value,
    DEB_PACKAGE_RE.test(value),
    "a Debian package name with no architecture qualifier or version pin",
  );
}

/** Runtime assertion: `value` is a systemd unit name. */
export function assertUnit(field: string, value: string): string {
  return assertGrammar(
    field,
    value,
    UNIT_RE.test(value),
    "a systemd unit name",
  );
}

/** Runtime assertion: `value` is a dotted cephadm version. */
export function assertCephadmVersion(field: string, value: string): string {
  return assertGrammar(
    field,
    value,
    CEPHADM_VERSION_RE.test(value),
    "a dotted release number",
  );
}

/** Runtime assertion: `value` is a V15 container image reference. */
export function assertContainerImage(field: string, value: string): string {
  return assertGrammar(
    field,
    value,
    isContainerImage(value),
    "an OCI image reference with an explicit tag or digest",
  );
}

/** POSIX single-quotes `value` so a POSIX shell reproduces it byte for byte. */
export function quote(value: string): string {
  return `'${value.replaceAll("'", `'\\''`)}'`;
}
