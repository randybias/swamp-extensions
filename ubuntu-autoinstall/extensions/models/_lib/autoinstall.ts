/**
 * Structural validation of an `autoinstall:` object.
 *
 * Written from the public subiquity autoinstall reference. Subiquity's own
 * JSON schema is AGPL-3.0 and is deliberately not shipped; a gated dev-only
 * test cross-checks these renders against it from a temp download.
 *
 * @module
 */

import type { Finding } from "./schemas.ts";
import { isCryptHash } from "./grammars.ts";

/**
 * The autoinstall keys the reference documents. Unknown keys are refused even
 * though version 1 only warns: the installer is slated to make them fatal.
 */
export const AUTOINSTALL_KEYS: ReadonlySet<string> = new Set([
  "version",
  "interactive-sections",
  "early-commands",
  "reporting",
  "error-commands",
  "user-data",
  "packages",
  "debconf-selections",
  "locale",
  "refresh-installer",
  "kernel",
  "keyboard",
  "source",
  "network",
  "ubuntu-pro",
  "ubuntu-advantage",
  "proxy",
  "apt",
  "storage",
  "identity",
  "ssh",
  "snaps",
  "active-directory",
  "codecs",
  "drivers",
  "oem",
  "timezone",
  "updates",
  "late-commands",
  "shutdown",
]);

const UPDATES = new Set(["security", "all"]);
const SHUTDOWN = new Set(["reboot", "poweroff"]);

type Json = Record<string, unknown>;

function isRecord(v: unknown): v is Json {
  return v !== null && typeof v === "object" && !Array.isArray(v);
}

/** Rejects keys the autoinstall reference does not document. */
export function unknownAutoinstallKeys(ai: unknown): Finding[] {
  if (!isRecord(ai)) return [];
  return Object.keys(ai)
    .filter((key) => !AUTOINSTALL_KEYS.has(key))
    .map((key) => ({
      pointer: `/${key}`,
      message: `unknown autoinstall key "${key}"`,
    }));
}

function expectString(v: Json, key: string, findings: Finding[]): void {
  if (v[key] !== undefined && typeof v[key] !== "string") {
    findings.push({ pointer: `/${key}`, message: `${key} must be a string` });
  }
}

function expectObject(v: Json, key: string, findings: Finding[]): void {
  if (v[key] !== undefined && !isRecord(v[key])) {
    findings.push({ pointer: `/${key}`, message: `${key} must be a mapping` });
  }
}

function checkIdentity(identity: unknown, findings: Finding[]): void {
  if (!isRecord(identity)) {
    findings.push({
      pointer: "/identity",
      message: "identity must be a mapping",
    });
    return;
  }
  for (const key of ["username", "hostname", "password"]) {
    if (typeof identity[key] !== "string" || identity[key] === "") {
      findings.push({
        pointer: `/identity/${key}`,
        message: `identity.${key} is required`,
      });
    }
  }
  if (
    typeof identity.password === "string" && identity.password !== "" &&
    !isCryptHash(identity.password)
  ) {
    findings.push({
      pointer: "/identity/password",
      message: "identity.password must be a crypt hash, not a plaintext",
    });
  }
  if (
    identity.realname !== undefined && typeof identity.realname !== "string"
  ) {
    findings.push({
      pointer: "/identity/realname",
      message: "identity.realname must be a string",
    });
  }
}

function checkSsh(ssh: unknown, findings: Finding[]): void {
  if (ssh === undefined) return;
  if (!isRecord(ssh)) {
    findings.push({ pointer: "/ssh", message: "ssh must be a mapping" });
    return;
  }
  for (const key of ["install-server", "allow-pw"]) {
    if (ssh[key] !== undefined && typeof ssh[key] !== "boolean") {
      findings.push({
        pointer: `/ssh/${key}`,
        message: `ssh.${key} must be a boolean`,
      });
    }
  }
  const keys = ssh["authorized-keys"];
  if (
    keys !== undefined &&
    (!Array.isArray(keys) || keys.some((k) => typeof k !== "string"))
  ) {
    findings.push({
      pointer: "/ssh/authorized-keys",
      message: "ssh.authorized-keys must be a list of strings",
    });
  }
}

function checkPackages(packages: unknown, findings: Finding[]): void {
  if (packages === undefined) return;
  if (!Array.isArray(packages) || packages.some((p) => typeof p !== "string")) {
    findings.push({
      pointer: "/packages",
      message: "packages must be a list of strings",
    });
  }
}

function checkLateCommands(commands: unknown, findings: Finding[]): void {
  if (commands === undefined) return;
  if (!Array.isArray(commands)) {
    findings.push({
      pointer: "/late-commands",
      message: "late-commands must be a list",
    });
    return;
  }
  commands.forEach((c, i) => {
    const ok = typeof c === "string" ||
      (Array.isArray(c) && c.every((w) => typeof w === "string"));
    if (!ok) {
      findings.push({
        pointer: `/late-commands/${i}`,
        message: "a late command must be a string or a list of strings",
      });
    }
  });
}

function checkEnums(ai: Json, findings: Finding[]): void {
  if (
    ai.updates !== undefined &&
    !(typeof ai.updates === "string" && UPDATES.has(ai.updates))
  ) {
    findings.push({
      pointer: "/updates",
      message: "updates must be the string security or all",
    });
  }
  if (
    ai.shutdown !== undefined &&
    !(typeof ai.shutdown === "string" && SHUTDOWN.has(ai.shutdown))
  ) {
    findings.push({
      pointer: "/shutdown",
      message: "shutdown must be the string reboot or poweroff",
    });
  }
}

function checkSnaps(snaps: unknown, findings: Finding[]): void {
  if (snaps === undefined) return;
  if (!Array.isArray(snaps)) {
    findings.push({ pointer: "/snaps", message: "snaps must be a list" });
    return;
  }
  snaps.forEach((snap, i) => {
    if (!isRecord(snap) || typeof snap.name !== "string" || snap.name === "") {
      findings.push({
        pointer: `/snaps/${i}/name`,
        message: "a snap needs a name",
      });
      return;
    }
    if (snap.channel !== undefined && typeof snap.channel !== "string") {
      findings.push({
        pointer: `/snaps/${i}/channel`,
        message: "channel must be a string",
      });
    }
    if (snap.classic !== undefined && typeof snap.classic !== "boolean") {
      findings.push({
        pointer: `/snaps/${i}/classic`,
        message: "classic must be a boolean",
      });
    }
  });
}

/** Structural checks on the documented autoinstall keys. */
export function checkAutoinstallStructure(ai: unknown): Finding[] {
  if (!isRecord(ai)) {
    return [{ pointer: "/", message: "autoinstall must be a mapping" }];
  }
  const findings: Finding[] = [];
  if (ai.version !== 1) {
    findings.push({ pointer: "/version", message: "version must be 1" });
  }
  checkIdentity(ai.identity, findings);
  checkSsh(ai.ssh, findings);
  checkPackages(ai.packages, findings);
  checkLateCommands(ai["late-commands"], findings);
  checkEnums(ai, findings);
  checkSnaps(ai.snaps, findings);
  for (const key of ["locale", "timezone", "proxy"]) {
    expectString(ai, key, findings);
  }
  for (
    const key of [
      "storage",
      "network",
      "user-data",
      "keyboard",
      "source",
      "apt",
    ]
  ) {
    expectObject(ai, key, findings);
  }
  return findings;
}
