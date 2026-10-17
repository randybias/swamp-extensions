/**
 * Input grammars shared by the argument schemas.
 *
 * Each grammar is deliberately narrow: a value that reaches remote argv, a
 * rendered manifest or a filesystem path is matched here first, in every place
 * it flows through.
 *
 * @module
 */

/** RFC 1123 label (a lowercase hostname). */
export const HOSTNAME_RE = /^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$/;
/** Autoinstall identity user name. */
export const USERNAME_RE = /^[a-z_][a-z0-9_-]{0,31}$/;
/** A curtin storage action id. */
export const ID_RE = /^[a-z][a-z0-9-]{0,31}$/;
/** An APT package name with an optional version. */
export const PACKAGE_RE =
  /^[a-z0-9][a-z0-9+.-]{0,127}(=[A-Za-z0-9.+~:-]{1,64})?$/;
/** A disk serial or by-id fragment. */
export const SERIAL_RE = /^[A-Za-z0-9._:-]{1,64}$/;
/** An absolute `/dev` path. */
export const DEVICE_PATH_RE = /^\/dev\/[A-Za-z0-9._/-]{1,255}$/;
/** An absolute mount path. */
export const MOUNT_PATH_RE = /^\/[A-Za-z0-9._/-]{0,255}$/;
/** Printable text with no control characters. */
// deno-lint-ignore no-control-regex
export const PRINTABLE_RE = /^[^\x00-\x1f\x7f]+$/;

const CRYPT_ALPHABET_RE = /^[./A-Za-z0-9$=,]+$/;
const CRYPT_ROUNDS_RE = /^rounds=\d{1,7}$/;
const BCRYPT_COST_RE = /^\d{2}$/;

/** Expected hash-field length per SHA/MD5 crypt id, matching crypt(3). */
const CRYPT_HASH_LEN: Record<string, number> = { "1": 22, "5": 43, "6": 86 };

/**
 * True for a real crypt(3) password hash: `$1$` MD5, `$2a/2b/2y$` bcrypt,
 * `$5$` SHA-256, `$6$` SHA-512 (each with a salt and a hash part), or `$y$`
 * yescrypt. A bare `$6$word` (one field) is a plaintext to cloud-init, so it is
 * refused, and a short hash field is not a real hash either.
 */
export function isCryptHash(value: string): boolean {
  if (value.length > 512 || !CRYPT_ALPHABET_RE.test(value)) return false;
  const [leading, id, ...rest] = value.split("$");
  if (leading !== "" || id === undefined) return false;
  const fields = rest.filter((f) => f !== "");
  if (id === "y") {
    return fields.length >= 2 && fields[fields.length - 1].length >= 40;
  }
  if (id === "1" || id === "5" || id === "6") {
    let salt: string;
    let hash: string;
    if (fields.length === 2) {
      [salt, hash] = fields;
    } else if (fields.length === 3 && CRYPT_ROUNDS_RE.test(fields[0])) {
      salt = fields[1];
      hash = fields[2];
    } else {
      return false;
    }
    return salt.length >= 1 && salt.length <= 16 &&
      hash.length === CRYPT_HASH_LEN[id];
  }
  if (id === "2a" || id === "2b" || id === "2y") {
    return fields.length === 2 && BCRYPT_COST_RE.test(fields[0]) &&
      fields[1].length === 53;
  }
  return false;
}

/** A lowercase colon-separated MAC address. */
export const MAC_RE = /^([0-9a-f]{2}:){5}[0-9a-f]{2}$/;
/** A volume group, logical volume or LVM name. */
export const LVM_NAME_RE = /^[A-Za-z0-9._-]{1,127}$/;

const SSH_KEY_TYPE_RE = /^(ssh-ed25519|ecdsa-sha2-nistp(256|384|521)|ssh-rsa)$/;
const BASE64_RE = /^[A-Za-z0-9+/]+={0,2}$/;

/** True for an IPv4 address (`a.b.c.d`). */
export function isIpv4(s: string): boolean {
  const parts = s.split(".");
  if (parts.length !== 4) return false;
  return parts.every((p) =>
    /^\d{1,3}$/.test(p) && Number(p) >= 0 && Number(p) <= 255
  );
}

/** True for an IPv6 address (a bounded relaxed form). */
export function isIpv6(s: string): boolean {
  return /^[0-9a-fA-F:]{2,45}$/.test(s) && s.includes(":");
}

/** True for an IPv4 or IPv6 address. */
export function isIp(s: string): boolean {
  return isIpv4(s) || isIpv6(s);
}

/** True for an IPv4 or IPv6 CIDR (`addr/prefix`). */
export function isCidr(s: string): boolean {
  const slash = s.lastIndexOf("/");
  if (slash < 1) return false;
  const addr = s.slice(0, slash);
  const prefix = s.slice(slash + 1);
  if (!/^\d{1,3}$/.test(prefix)) return false;
  if (isIpv4(addr)) return Number(prefix) <= 32;
  if (isIpv6(addr)) return Number(prefix) <= 128;
  return false;
}

/**
 * Parses an OpenSSH public key line: `type base64 [comment]`. RSA is accepted
 * only at 3072 bits or more; the modulus is read from the SSH wire format.
 */
export function isOpenSshPublicKey(line: string): boolean {
  const trimmed = line.trim();
  if (trimmed === "" || trimmed.length > 8192 || !PRINTABLE_RE.test(trimmed)) {
    return false;
  }
  const parts = trimmed.split(/\s+/);
  if (parts.length < 2) return false;
  const [type, blob] = parts;
  const comment = parts.slice(2).join(" ");
  if (comment !== "" && !PRINTABLE_RE.test(comment)) return false;
  if (!SSH_KEY_TYPE_RE.test(type) || !BASE64_RE.test(blob)) return false;
  return type !== "ssh-rsa" || rsaModulusBits(blob) >= 3072;
}

/** Reads an RSA public key blob's modulus size in bits, or 0 when malformed. */
function rsaModulusBits(blob: string): number {
  let bytes: Uint8Array;
  try {
    const bin = atob(blob);
    bytes = Uint8Array.from(bin, (c) => c.charCodeAt(0));
  } catch {
    return 0;
  }
  let off = 0;
  const readString = (): Uint8Array | null => {
    if (off + 4 > bytes.length) return null;
    const len = (bytes[off] << 24) | (bytes[off + 1] << 16) |
      (bytes[off + 2] << 8) | bytes[off + 3];
    off += 4;
    if (len < 0 || off + len > bytes.length) return null;
    const out = bytes.subarray(off, off + len);
    off += len;
    return out;
  };
  const tag = readString();
  if (!tag || new TextDecoder().decode(tag) !== "ssh-rsa") return 0;
  const e = readString();
  const n = readString();
  if (!e || !n || n.length === 0) return 0;
  let i = 0;
  while (i < n.length && n[i] === 0) i++;
  if (i >= n.length) return 0;
  return (n.length - i - 1) * 8 + (32 - Math.clz32(n[i]));
}
