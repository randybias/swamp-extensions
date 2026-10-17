/**
 * Deterministic cloud-config YAML emission and a strict, YAML 1.1-semantics
 * re-parse.
 *
 * The installer reads the seed with a YAML 1.1 loader; the control host emits
 * it with a different implementation. The differentials between the two would
 * silently change meaning (a hostname `on` becoming a boolean, `0644` becoming
 * octal 420, `22:22` becoming 1342), so the emitter quotes **every string** and
 * the re-parser uses YAML 1.1 semantics. Emitting and re-parsing are separate
 * implementations on purpose: a quoting bug in one is caught by the other.
 *
 * @module
 */

import {
  isAlias,
  isMap,
  isScalar,
  isSeq,
  parseDocument,
  stringify,
} from "npm:yaml@2.9.1";

/** Every cloud-config document starts with exactly this line. */
export const CLOUD_CONFIG_HEADER = "#cloud-config\n";

/** Matches a YAML merge tag in any spelling, however the key is written. */
const MERGE_TAG =
  /!!merge\b|!<tag:yaml\.org,2002:merge>|tag:yaml\.org,2002:merge/;

/**
 * Replaces every non-safe-integer number with its string form. `1e21` is
 * emitted as `1e+21` by the emitter, which this side reads back as a number but
 * the installer's PyYAML reads as a string; quoting it keeps both sides reading
 * the same text. The pipeline also rejects such a number outright.
 */
export function sanitizeScalars(v: unknown): unknown {
  if (typeof v === "number" && !Number.isSafeInteger(v)) return String(v);
  if (Array.isArray(v)) return v.map(sanitizeScalars);
  if (v !== null && typeof v === "object") {
    return Object.fromEntries(
      Object.entries(v as Record<string, unknown>).map(([k, x]) => [
        k,
        sanitizeScalars(x),
      ]),
    );
  }
  return v;
}

/**
 * Serializes a value with the fixed emission rules: every string and key
 * double-quoted, keys sorted, no anchors, aliases or tags. No header; used for
 * `meta-data`, which is not a cloud-config document.
 */
export function emitYamlBody(doc: unknown): string {
  return stringify(sanitizeScalars(doc), {
    defaultStringType: "QUOTE_DOUBLE",
    defaultKeyType: "QUOTE_DOUBLE",
    aliasDuplicateObjects: false,
    sortMapEntries: true,
    lineWidth: 0,
  });
}

/**
 * Serializes a value as cloud-config: the fixed `#cloud-config` header and the
 * quoted body. The same value stringifies to the same bytes.
 */
export function emitCloudConfig(doc: unknown): string {
  return CLOUD_CONFIG_HEADER + emitYamlBody(doc);
}

/** One difference found while re-parsing a rendered document. */
export interface ReparseResult {
  /** The parsed value when the re-parse succeeded. */
  value?: unknown;
  /** A fixed reason when it did not. */
  reason?: string;
}

interface YamlNode {
  tag?: unknown;
  anchor?: unknown;
  items?: unknown[];
  key?: YamlNode;
  value?: YamlNode;
}

/** True when a node carries an explicit tag, an anchor or is an alias. */
function nodeIsUnsafe(node: unknown): boolean {
  if (typeof node !== "object" || node === null) return false;
  const n = node as YamlNode;
  if (isAlias(node)) return true;
  if (typeof n.anchor === "string" && n.anchor !== "") return true;
  if (typeof n.tag === "string" && n.tag !== "") return true;
  return false;
}

function walkUnsafe(node: unknown): boolean {
  if (typeof node !== "object" || node === null) return false;
  if (nodeIsUnsafe(node)) return true;
  if (isMap(node)) {
    for (
      const item of (node as { items: { key: unknown; value: unknown }[] })
        .items
    ) {
      if (
        isScalar(item.key) && (item.key as { value?: unknown }).value === "<<"
      ) {
        return true;
      }
      if (walkUnsafe(item.key) || walkUnsafe(item.value)) return true;
    }
  } else if (isSeq(node)) {
    for (const item of (node as { items: unknown[] }).items) {
      if (walkUnsafe(item)) return true;
    }
  }
  return false;
}

/**
 * Re-parses a rendered cloud-config with YAML 1.1 semantics. Duplicate keys,
 * anchors, aliases, explicit tags and YAML merge keys are refused: any of them
 * would let the installer read a different document than the one compared here.
 */
export function reparseCloudConfig(text: string): ReparseResult {
  if (MERGE_TAG.test(text) || /^\s*<<\s*:/m.test(text)) {
    return { reason: "the document uses a YAML merge tag" };
  }
  const body = text.startsWith(CLOUD_CONFIG_HEADER)
    ? text.slice(CLOUD_CONFIG_HEADER.length)
    : text;
  let doc;
  try {
    doc = parseDocument(body, {
      version: "1.1",
      uniqueKeys: true,
      merge: false,
    });
  } catch {
    return { reason: "the document is not valid YAML" };
  }
  if (doc.errors.length > 0) {
    return { reason: "the document is not valid YAML" };
  }
  if (walkUnsafe(doc.contents)) {
    return {
      reason: "the document uses an anchor, alias or tag, which is not allowed",
    };
  }
  try {
    return { value: doc.toJS({ maxAliasCount: 0 }) };
  } catch {
    return { reason: "the document could not be read" };
  }
}

/** True when two values are deeply equal, treating arrays and objects structurally. */
export function deepEqual(a: unknown, b: unknown): boolean {
  if (a === b) return true;
  if (Array.isArray(a) && Array.isArray(b)) {
    if (a.length !== b.length) return false;
    return a.every((v, i) => deepEqual(v, b[i]));
  }
  if (
    a !== null && b !== null && typeof a === "object" &&
    typeof b === "object" && !Array.isArray(a) && !Array.isArray(b)
  ) {
    const ka = Object.keys(a as Record<string, unknown>).sort();
    const kb = Object.keys(b as Record<string, unknown>).sort();
    if (ka.length !== kb.length) return false;
    return ka.every((k, i) =>
      k === kb[i] &&
      deepEqual(
        (a as Record<string, unknown>)[k],
        (b as Record<string, unknown>)[k],
      )
    );
  }
  return false;
}
