/**
 * The validation pipeline for a seed's user-data.
 *
 * Independent layers: the YAML 1.1 round-trip guard, the vendored subiquity
 * autoinstall schema, the vendored cloud-init cloud-config schema, and our own
 * semantic checks (numbers, plaintext secrets, a refused LUKS passphrase, the
 * storage graph, one `/` mount, a boot partition per grub device, `version: 1`).
 * Findings carry JSON pointers and fixed messages and never echo a value.
 *
 * @module
 */

import { type Finding, validateCloudConfigSchema } from "./schemas.ts";
import {
  checkAutoinstallStructure,
  unknownAutoinstallKeys,
} from "./autoinstall.ts";
import { isCryptHash } from "./grammars.ts";
import { deepEqual, reparseCloudConfig } from "./yaml.ts";

export type { Finding } from "./schemas.ts";

const CLOUD_CONFIG_FIRST_LINE = "#cloud-config";
const JINJA_HEADER = /^##\s*template:\s*jinja\b/im;
const ID_RE = /^[a-z][a-z0-9-]{0,31}$/;
const SECRET_KEYS = new Set(["chpasswd", "plain_text_passwd", "password"]);

type Json = Record<string, unknown>;

function isRecord(v: unknown): v is Json {
  return v !== null && typeof v === "object" && !Array.isArray(v);
}

/** References a curtin storage action makes to earlier action ids. */
function refsOf(a: Json): string[] {
  const refs: string[] = [];
  const push = (v: unknown) => {
    if (typeof v === "string") refs.push(v);
    else if (Array.isArray(v)) {
      for (const x of v) if (typeof x === "string") refs.push(x);
    }
  };
  switch (a.type) {
    case "raid":
      push(a.devices);
      push(a.spare_devices);
      break;
    case "lvm_volgroup":
      push(a.devices);
      break;
    case "lvm_partition":
      push(a.volgroup);
      break;
    case "partition":
      push(a.device);
      break;
    case "format":
      push(a.volume);
      break;
    case "mount":
      push(a.device);
      break;
  }
  return refs;
}

/** Walk every node of a tree, calling `visit(value, pointer)`. */
function walk(
  value: unknown,
  pointer: string,
  visit: (v: unknown, p: string) => void,
): void {
  visit(value, pointer);
  if (Array.isArray(value)) {
    value.forEach((v, i) => walk(v, `${pointer}/${i}`, visit));
  } else if (isRecord(value)) {
    for (const [k, v] of Object.entries(value)) {
      walk(v, `${pointer}/${k}`, visit);
    }
  }
}

/**
 * Rejects any number that is not a safe integer. A float such as `1e21` is
 * emitted as `1e+21`, which this side reads back as a number but PyYAML reads
 * as a string, so the round-trip guard alone cannot catch it.
 */
export function checkNumbers(doc: unknown): Finding[] {
  const findings: Finding[] = [];
  walk(doc, "", (v, pointer) => {
    if (typeof v === "number" && !Number.isSafeInteger(v)) {
      findings.push({
        pointer: pointer === "" ? "/" : pointer,
        message:
          "only safe integers are allowed; a float is read differently by the installer's parser",
      });
    }
  });
  return findings;
}

/**
 * Rejects cloud-config keys that carry a plaintext secret into the served,
 * unauthenticated seed (`chpasswd`, `plain_text_passwd`, any `ssh_keys`
 * `*_private`). A crypt hash under `passwd` is allowed.
 */
export function checkNoPlaintextSecrets(doc: unknown): Finding[] {
  const findings: Finding[] = [];
  walk(doc, "", (v, pointer) => {
    if (!isRecord(v)) return;
    for (const [k, child] of Object.entries(v)) {
      if (SECRET_KEYS.has(k)) {
        // `identity.password` is a crypt hash and is required; a plaintext
        // `password` elsewhere is refused.
        const hashedPassword = k === "password" && typeof child === "string" &&
          isCryptHash(child);
        if (!hashedPassword) {
          findings.push({
            pointer: `${pointer}/${k}`,
            message: `"${k}" carries a plaintext secret and is refused`,
          });
        }
      }
      if (k === "ssh_keys" && isRecord(child)) {
        for (const key of Object.keys(child)) {
          if (key.endsWith("_private")) {
            findings.push({
              pointer: `${pointer}/${k}/${key}`,
              message: "a private SSH key is refused in the served seed",
            });
          }
        }
      }
    }
  });
  return findings;
}

/** True when a guided storage layout carries a LUKS passphrase. */
export function hasLuksPassword(storage: unknown): boolean {
  if (!isRecord(storage) || !isRecord(storage.layout)) return false;
  return typeof storage.layout.password === "string" &&
    storage.layout.password !== "";
}

/**
 * Semantic checks on the storage config: every action id is well formed and
 * every reference resolves to an earlier action (a DAG with no dangling edge
 * and no cycle), exactly one `/` mount exists, and every `grub_device` disk has
 * a `boot` or `bios_grub` partition.
 */
export function checkStorageGraph(storage: unknown): Finding[] {
  if (storage === undefined || storage === null) return [];
  if (!isRecord(storage)) {
    return [{ pointer: "/storage", message: "storage must be a mapping" }];
  }
  const config = storage.config;
  if (config === undefined) return [];
  if (!Array.isArray(config)) {
    return [{ pointer: "/storage/config", message: "config must be a list" }];
  }
  const findings: Finding[] = [];
  const seen = new Set<string>();
  const bootDisks = new Set<string>();
  const bootFlagged = new Set<string>();
  let rootMounts = 0;
  config.forEach((raw, i) => {
    const ptr = `/storage/config/${i}`;
    if (!isRecord(raw)) {
      findings.push({
        pointer: ptr,
        message: "a storage action must be a mapping",
      });
      return;
    }
    if (typeof raw.id !== "string" || !ID_RE.test(raw.id)) {
      findings.push({ pointer: `${ptr}/id`, message: "invalid action id" });
    }
    for (const ref of refsOf(raw)) {
      if (!seen.has(ref)) {
        findings.push({
          pointer: ptr,
          message:
            `reference "${ref}" does not resolve to an earlier action id`,
        });
      }
    }
    if (raw.type === "mount" && raw.path === "/") rootMounts += 1;
    if (
      raw.type === "disk" && raw.grub_device === true &&
      typeof raw.id === "string"
    ) {
      bootDisks.add(raw.id);
    }
    if (
      raw.type === "partition" && typeof raw.device === "string" &&
      (raw.flag === "boot" || raw.flag === "bios_grub")
    ) {
      bootFlagged.add(raw.device);
    }
    if (typeof raw.id === "string") seen.add(raw.id);
  });
  if (rootMounts !== 1) {
    findings.push({
      pointer: "/storage/config",
      message: "exactly one mount at / is required",
    });
  }
  for (const disk of bootDisks) {
    if (!bootFlagged.has(disk)) {
      findings.push({
        pointer: "/storage/config",
        message:
          `disk "${disk}" is a grub device without a boot or bios_grub partition`,
      });
    }
  }
  return findings;
}

/** Validates an `autoinstall:` object (already parsed) with every layer. */
export function validateAutoinstallObject(ai: unknown): Finding[] {
  if (!isRecord(ai)) {
    return [{
      pointer: "/autoinstall",
      message: "autoinstall must be a mapping",
    }];
  }
  const findings: Finding[] = [];
  const under = (f: Finding): Finding => ({
    pointer: `/autoinstall${f.pointer === "/" ? "" : f.pointer}`,
    message: f.message,
  });
  findings.push(...checkAutoinstallStructure(ai).map(under));
  findings.push(...unknownAutoinstallKeys(ai).map(under));
  const userData = ai["user-data"];
  if (isRecord(userData)) {
    const underUserData = (f: Finding): Finding => ({
      pointer: `/autoinstall/user-data${f.pointer === "/" ? "" : f.pointer}`,
      message: f.message,
    });
    findings.push(...validateCloudConfigSchema(userData).map(underUserData));
  }
  findings.push(...checkStorageGraph(ai.storage).map(under));
  findings.push(...checkNoPlaintextSecrets(ai).map(under));
  if (hasLuksPassword(ai.storage)) {
    findings.push({
      pointer: "/autoinstall/storage/layout/password",
      message:
        "a LUKS passphrase is refused: autoinstall takes it in plaintext and the seed is served unauthenticated",
    });
  }
  return findings;
}

/** Validates a parsed cloud-config user-data document as a whole. */
export function validateUserDataObject(doc: unknown): Finding[] {
  if (!isRecord(doc)) {
    return [{ pointer: "/", message: "user-data must be a mapping" }];
  }
  const findings: Finding[] = [];
  for (const key of Object.keys(doc)) {
    if (key !== "autoinstall") {
      findings.push({
        pointer: `/${key}`,
        message: "only autoinstall is allowed at the top level",
      });
    }
  }
  findings.push(...validateCloudConfigSchema(doc));
  findings.push(...checkNumbers(doc));
  // The secret walk runs once, inside validateAutoinstallObject on the
  // autoinstall subtree, which also covers first-boot user-data.
  findings.push(...validateAutoinstallObject(doc.autoinstall));
  return findings;
}

/** The two headers cloud-init treats specially in a user-data document. */
export function checkUserDataHeader(text: string): Finding[] {
  const firstLine = text.split("\n", 1)[0];
  if (firstLine !== CLOUD_CONFIG_FIRST_LINE) {
    return [{
      pointer: "/",
      message: "the document must start with the exact line #cloud-config",
    }];
  }
  if (JINJA_HEADER.test(text)) {
    return [{
      pointer: "/",
      message:
        "a jinja template header is refused: the validated text is not the text consumed",
    }];
  }
  return [];
}

/**
 * Parses a supplied user-data text with the strict YAML 1.1 loader and runs the
 * full pipeline. Returns findings; an empty list means valid.
 */
export function validateUserDataText(text: string): Finding[] {
  const header = checkUserDataHeader(text);
  if (header.length > 0) return header;
  const parsed = reparseCloudConfig(text);
  if (parsed.reason) return [{ pointer: "/", message: parsed.reason }];
  return validateUserDataObject(parsed.value);
}

/**
 * The parser-differential guard: re-parse the rendered bytes and deep-compare
 * to the object tree that produced them. Any difference (a string read back as
 * a boolean or an octal number) is a hard error.
 */
export function roundTripGuard(rendered: string, tree: unknown): Finding[] {
  const parsed = reparseCloudConfig(rendered);
  if (parsed.reason) return [{ pointer: "/", message: parsed.reason }];
  if (!deepEqual(tree, parsed.value)) {
    return [{
      pointer: "/",
      message: "the rendered document does not round-trip to the object tree",
    }];
  }
  return [];
}
