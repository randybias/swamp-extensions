/**
 * RGW helpers: the secret redactor, the admin-plane bucket inventory and the
 * user-ensure path.
 *
 * Provisional secret path (Randy's P1 recommendation, pending confirmation):
 * `cephRgwUserEnsure` has RGW generate the key with `--gen-access-key
 * --gen-secret` and stores it only in a sensitive, vaulted field, exactly like
 * `cephFetchCsiKey`. No caller-supplied secret is accepted, so no secret ever
 * reaches a command line or script text, and no Admin Ops credential or
 * endpoint is needed. Exactly one path is implemented; there is no runtime
 * probing or fallback.
 *
 * RGW helpers: the secret redactor and the admin-plane bucket inventory.
 *
 * `radosgw-admin` is a separate binary, never a `ceph` subcommand. Output that
 * can carry key material is always redacted before it becomes error or log
 * text, and a parsed user view never carries a secret. Cluster-returned bucket
 * names are attacker-influenced and are put in a command only after passing
 * the safe-name charset.
 *
 * @module
 */

import { fail, TransportError } from "./errors.ts";
import type { SshSession } from "./ssh_session.ts";
import type { PrepDeps } from "./hostprep.ts";
import { runCephScript } from "./shell.ts";
import { quote } from "./validate.ts";

type Logger = {
  info: (m: string, p?: Record<string, unknown>) => void;
  warn: (m: string, p?: Record<string, unknown>) => void;
};

/** The fixed response page size for bucket listing. */
export const INVENTORY_PAGE_SIZE = 1000;

/** The safe-name charset a cluster-returned bucket name must match. */
export const SAFE_BUCKET_NAME_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,254}$/;

/**
 * Redacts secrets from arbitrary text: JSON `secret_key`/`secret` values, the
 * value after a `--secret`/`--secret-key` flag, and every literal occurrence
 * of a caller-supplied secret. Runs before any truncation.
 */
export function redactSecrets(text: string, secrets: string[] = []): string {
  let out = text
    .replace(/("secret_key"\s*:\s*)"(?:[^"\\]|\\.)*"/g, '$1"<redacted>"')
    .replace(/("secret"\s*:\s*)"(?:[^"\\]|\\.)*"/g, '$1"<redacted>"')
    .replace(
      /(--secret(?:-key)?[= ])(?:"(?:[^"\\]|\\.)*"|'(?:[^']*)'|\S+)/gi,
      "$1<redacted>",
    );
  for (const secret of secrets) {
    if (secret !== "") out = out.split(secret).join("<redacted>");
  }
  return out;
}

/** The parsed user view, which never carries a secret. */
export interface RgwUserView {
  /** RGW uid. */
  userId: string;
  /** Display name. */
  displayName: string;
  /** Email, or "". */
  email: string;
  /** Access key ids present. */
  accessKeys: string[];
  /** Max buckets, or -1 when not reported. */
  maxBuckets: number;
  /** Whether the user is suspended. */
  suspended: boolean;
}

/** Parses `radosgw-admin user info` JSON, omitting every secret. */
export function parseUserView(json: unknown): RgwUserView | null {
  if (json === null || typeof json !== "object") return null;
  const e = json as Record<string, unknown>;
  if (typeof e.user_id !== "string") return null;
  const keys = Array.isArray(e.keys) ? e.keys : [];
  const accessKeys = keys.flatMap((k) => {
    if (k === null || typeof k !== "object") return [];
    const access = (k as { access_key?: unknown }).access_key;
    return typeof access === "string" ? [access] : [];
  });
  return {
    userId: e.user_id,
    displayName: typeof e.display_name === "string" ? e.display_name : "",
    email: typeof e.email === "string" ? e.email : "",
    accessKeys,
    maxBuckets: typeof e.max_buckets === "number" ? e.max_buckets : -1,
    suspended: typeof e.suspended === "number" ? e.suspended !== 0 : false,
  };
}

/** Classification of a `user info` read. */
export type UserInfoState = "present" | "absent" | "unreadable";

/** Classifies a `user info` read, keeping absence distinct from unreadable. */
export function classifyUserInfo(
  code: number,
  stdout: string,
  stderr: string,
): { state: UserInfoState; view: RgwUserView | null } {
  if (code === 0) {
    let json: unknown;
    try {
      json = JSON.parse(stdout);
    } catch {
      return { state: "unreadable", view: null };
    }
    const view = parseUserView(json);
    return view === null
      ? { state: "unreadable", view: null }
      : { state: "present", view };
  }
  const combined = `${stdout}\n${stderr}`;
  if (/could not fetch user info:.*\(2\)/i.test(combined)) {
    return { state: "absent", view: null };
  }
  if (/could not fetch user info:.*no user info saved/i.test(combined)) {
    return { state: "absent", view: null };
  }
  if (/no such user/i.test(combined)) return { state: "absent", view: null };
  return { state: "unreadable", view: null };
}

/** Runs a `radosgw-admin` script, redacting any transport error. */
export async function runRadosgwAdmin(
  deps: PrepDeps,
  session: SshSession,
  body: string,
  opts: { phase: string; allowNonZero?: boolean; json?: boolean },
  secrets: string[] = [],
  log?: Logger,
): Promise<{ code: number; stdout: string; stderr: string; json?: unknown }> {
  try {
    const r = await runCephScript(
      deps,
      session,
      {
        body,
        phase: opts.phase,
        allowNonZero: opts.allowNonZero ?? true,
        json: opts.json,
      },
      {
        warn: (m, p) =>
          log?.warn(redactSecrets(m, secrets), redactProps(p, secrets)),
      },
    );
    return {
      code: r.result.code,
      stdout: r.result.stdout,
      stderr: r.result.stderr,
      ...(r.json !== undefined ? { json: r.json } : {}),
    };
  } catch (e) {
    if (e instanceof TransportError) {
      fail(opts.phase, redactSecrets(e.message, secrets), { kind: e.kind });
    }
    throw new Error(redactSecrets((e as Error).message, secrets));
  }
}

function redactProps(
  props: Record<string, unknown> | undefined,
  secrets: string[],
): Record<string, unknown> | undefined {
  if (props === undefined) return undefined;
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(props)) {
    out[k] = typeof v === "string" ? redactSecrets(v, secrets) : v;
  }
  return out;
}

// ---------------------------------------------------------------------------
// cephRgwBucketInventory
// ---------------------------------------------------------------------------

/** One inventoried bucket. */
export interface InventoryBucket {
  /** Bucket name. */
  bucket: string;
  /** Owner. */
  owner: string;
  /** Object count. */
  numObjects: number;
  /** Logical size. */
  sizeBytes: number;
  /** On-disk size. */
  sizeActualBytes: number;
  /** Placement rule, or "". */
  placementRule: string;
}

/** The bucket inventory record. */
export interface InventoryRecord {
  /** Method name. */
  method: string;
  /** Admin host. */
  host: string;
  /** Realm, or "". */
  rgwRealm: string;
  /** Buckets inventoried. */
  bucketCount: number;
  /** Per-bucket rows. */
  buckets: InventoryBucket[];
  /** Names that could not be safely stat'd. */
  unstattable: string[];
  /** List pages read. */
  pagesRead: number;
  /** Total objects. */
  totalObjects: number;
  /** Total logical size. */
  totalSizeBytes: number;
  /** Total on-disk size. */
  totalSizeActualBytes: number;
}

/** Parses one list page: an array of strings or of objects with `bucket`. */
export function parseBucketListPage(json: unknown): string[] | null {
  if (!Array.isArray(json)) return null;
  const out: string[] = [];
  for (const item of json) {
    if (typeof item === "string") out.push(item);
    else if (
      item !== null && typeof item === "object" &&
      typeof (item as { bucket?: unknown }).bucket === "string"
    ) {
      out.push((item as { bucket: string }).bucket);
    } else return null;
  }
  return out;
}

/** Sums usage categories, treating a missing or non-numeric figure as 0. */
export function sumUsage(
  json: unknown,
): { objects: number; size: number; actual: number } {
  const usage = (json as { usage?: unknown }).usage;
  let objects = 0, size = 0, actual = 0;
  if (usage !== null && typeof usage === "object") {
    for (const v of Object.values(usage as Record<string, unknown>)) {
      if (v === null || typeof v !== "object") continue;
      const s = v as Record<string, unknown>;
      if (typeof s.num_objects === "number") objects += s.num_objects;
      if (typeof s.size === "number") size += s.size;
      if (typeof s.size_actual === "number") actual += s.size_actual;
    }
  }
  return { objects, size, actual };
}

/** Lists every RGW bucket with owner, counts, sizes and placement rule. */
export async function bucketInventory(
  deps: PrepDeps,
  session: SshSession,
  host: string,
  rgwRealm: string,
  log?: Logger,
): Promise<InventoryRecord> {
  const realmFlag = rgwRealm !== "" ? ` --rgw-realm=${quote(rgwRealm)}` : "";
  const names: string[] = [];
  const seen = new Set<string>();
  let marker: string | null = null;
  let pagesRead = 0;
  for (let page = 0; page < 10_000; page++) {
    const markerArg = marker !== null ? ` --marker=${quote(marker)}` : "";
    const body =
      `radosgw-admin bucket list --format=json --max-entries=${INVENTORY_PAGE_SIZE}${markerArg}${realmFlag}`;
    const r = await runRadosgwAdmin(
      deps,
      session,
      body,
      { phase: "list", json: false, allowNonZero: true },
      [],
      log,
    );
    if (r.code !== 0) {
      fail("list", "bucket list failed", {
        code: r.code,
        stderr: r.stderr.slice(0, 300),
      });
    }
    pagesRead++;
    let parsed: unknown;
    try {
      parsed = JSON.parse(r.stdout);
    } catch {
      fail("parse", "bucket list returned non-JSON", {
        excerpt: r.stdout.slice(0, 500),
      });
    }
    const pageNames = parseBucketListPage(parsed);
    if (pageNames === null) {
      fail("parse", "bucket list returned an unexpected shape", {
        excerpt: r.stdout.slice(0, 500),
      });
    }
    let added = 0;
    for (const name of pageNames) {
      if (!seen.has(name)) {
        seen.add(name);
        names.push(name);
        added++;
      }
    }
    if (pageNames.length < INVENTORY_PAGE_SIZE) break;
    const last = pageNames.at(-1) ?? "";
    if (!SAFE_BUCKET_NAME_RE.test(last)) {
      fail(
        "list",
        "a full page ended with an unsafe name; cannot page safely",
        {},
      );
    }
    if (last === marker || added === 0) {
      fail("list", "bucket list paging made no progress", { marker });
    }
    marker = last;
  }

  const buckets: InventoryBucket[] = [];
  const unstattable: string[] = [];
  for (const name of names) {
    if (!SAFE_BUCKET_NAME_RE.test(name)) {
      unstattable.push(name);
      continue;
    }
    const body = `radosgw-admin bucket stats --bucket=${
      quote(name)
    } --format=json${realmFlag}`;
    const r = await runRadosgwAdmin(
      deps,
      session,
      body,
      { phase: "stats", json: false, allowNonZero: true },
      [],
      log,
    );
    if (r.code !== 0) {
      fail("stats", "bucket stats failed", {
        code: r.code,
        stderr: r.stderr.slice(0, 300),
      });
    }
    let json: unknown;
    try {
      json = JSON.parse(r.stdout);
    } catch {
      fail("stats", "bucket stats returned non-JSON", {});
    }
    const e = json as Record<string, unknown>;
    if (typeof e.owner !== "string") {
      fail("stats", "bucket stats has no owner", { bucket: name });
    }
    const sums = sumUsage(json);
    buckets.push({
      bucket: name,
      owner: e.owner,
      numObjects: sums.objects,
      sizeBytes: sums.size,
      sizeActualBytes: sums.actual,
      placementRule: typeof e.placement_rule === "string"
        ? e.placement_rule
        : "",
    });
  }
  const totalObjects = buckets.reduce((a, b) => a + b.numObjects, 0);
  const totalSizeBytes = buckets.reduce((a, b) => a + b.sizeBytes, 0);
  const totalSizeActualBytes = buckets.reduce(
    (a, b) => a + b.sizeActualBytes,
    0,
  );
  const record: InventoryRecord = {
    method: "cephRgwBucketInventory",
    host,
    rgwRealm,
    bucketCount: buckets.length,
    buckets,
    unstattable,
    pagesRead,
    totalObjects,
    totalSizeBytes,
    totalSizeActualBytes,
  };
  log?.info(
    "RGW inventory: {count} buckets, {pages} pages, {unstattable} unstattable",
    {
      count: record.bucketCount,
      pages: record.pagesRead,
      unstattable: record.unstattable.length,
    },
  );
  return record;
}

// ---------------------------------------------------------------------------
// cephRgwUserEnsure (option a: RGW generates the key)
// ---------------------------------------------------------------------------

/** Arguments for the RGW user ensure method. */
export interface RgwUserArgs {
  /** Admin host. */
  host: string;
  /** RGW uid. */
  uid: string;
  /** Display name. */
  displayName: string;
  /** Email to converge; empty/null means not managed. */
  email?: string | null;
  /** Generate a fresh key pair even when one exists. */
  rotateKeys?: boolean | null;
}

/** The RGW user record; the generated secret lives only in `key`. */
export interface RgwUserRecord {
  /** Method name. */
  method: string;
  /** Admin host. */
  host: string;
  /** RGW uid. */
  uid: string;
  /** Display name. */
  displayName: string;
  /** Email, or "". */
  email: string;
  /** Whether the user existed before this run. */
  existedBefore: boolean;
  /** Ordered change labels. */
  changes: string[];
  /** Access key id, present only when a key was generated this run. */
  accessKey?: string;
  /** Generated secret, present only when a key was generated this run. */
  key?: string;
  /** Max buckets, or -1. */
  maxBuckets: number;
  /** Whether the user is suspended. */
  suspended: boolean;
  /** Always `generated` on this path. */
  secretDelivery: "generated";
}

/** True when `email` is a managed value worth converging. */
export function isManagedEmail(email: string | null | undefined): boolean {
  return email !== undefined && email !== null && email !== "";
}

/** Parses the newly generated key from a user create/key create JSON body. */
export function parseGeneratedKey(
  stdout: string,
): { accessKey: string; key: string } | null {
  let json: unknown;
  try {
    json = JSON.parse(stdout);
  } catch {
    return null;
  }
  const keys = (json as { keys?: unknown }).keys;
  if (!Array.isArray(keys) || keys.length === 0) return null;
  for (let i = keys.length - 1; i >= 0; i--) {
    const k = keys[i];
    if (k === null || typeof k !== "object") continue;
    const access = (k as { access_key?: unknown }).access_key;
    const secret = (k as { secret_key?: unknown }).secret_key;
    if (
      typeof access === "string" && typeof secret === "string" && secret !== ""
    ) {
      return { accessKey: access, key: secret };
    }
  }
  return null;
}

/** Builds the redactor seed list from a generated key. */
function seed(record: { key?: string }): string[] {
  return record.key !== undefined ? [record.key] : [];
}

/**
 * Ensures an RGW user exists with the requested display name and email. Key
 * material is always generated by RGW and returned only in the sensitive `key`
 * field; no caller-supplied secret ever reaches a command line.
 */
export async function ensureRgwUser(
  deps: PrepDeps,
  session: SshSession,
  args: RgwUserArgs,
  log?: Logger,
): Promise<RgwUserRecord> {
  const emailManaged = isManagedEmail(args.email);
  const read = async (): Promise<
    { state: UserInfoState; view: RgwUserView | null }
  > => {
    const r = await runRadosgwAdmin(
      deps,
      session,
      `radosgw-admin user info --uid=${quote(args.uid)}`,
      { phase: "read", json: false, allowNonZero: true },
      [],
      log,
    );
    return classifyUserInfo(r.code, r.stdout, r.stderr);
  };

  const first = await read();
  if (first.state === "unreadable") {
    fail("read", "the initial user info read was unreadable", {
      uid: args.uid,
    });
  }

  let existedBefore = false;
  const changes: string[] = [];
  let accessKey: string | undefined;
  let key: string | undefined;

  const generated = (stdout: string, phase: string): void => {
    const parsed = parseGeneratedKey(stdout);
    if (parsed === null) {
      fail(phase, "the generated key could not be parsed", { uid: args.uid });
    }
    accessKey = parsed.accessKey;
    key = parsed.key;
  };

  if (first.state === "absent") {
    existedBefore = false;
    const emailArg = emailManaged ? ` --email=${quote(args.email!)}` : "";
    const body = `radosgw-admin user create --uid=${
      quote(args.uid)
    } --display-name=${
      quote(args.displayName)
    }${emailArg} --gen-access-key --gen-secret`;
    const r = await runRadosgwAdmin(
      deps,
      session,
      body,
      { phase: "user-create", json: false, allowNonZero: true },
      [],
      log,
    );
    if (r.code !== 0) {
      fail("user-create", "user create failed", {
        uid: args.uid,
        code: r.code,
        stderr: redactSecrets(r.stderr).slice(0, 300),
      });
    }
    generated(r.stdout, "user-create");
    changes.push("created user");
  } else {
    existedBefore = true;
    const view = first.view!;
    if (view.displayName !== args.displayName) {
      await modifyUser(
        deps,
        session,
        args.uid,
        "display-name",
        args.displayName,
        [],
        log,
      );
      changes.push("set display-name");
    }
    if (emailManaged && view.email !== args.email) {
      await modifyUser(deps, session, args.uid, "email", args.email!, [], log);
      changes.push("set email");
    }
    const rotate = args.rotateKeys === true;
    if (rotate || view.accessKeys.length === 0) {
      const body = `radosgw-admin key create --uid=${
        quote(args.uid)
      } --key-type=s3 --gen-access-key --gen-secret`;
      const r = await runRadosgwAdmin(
        deps,
        session,
        body,
        { phase: "key-create", json: false, allowNonZero: true },
        [],
        log,
      );
      if (r.code !== 0) {
        fail("key-create", "key create failed", {
          uid: args.uid,
          code: r.code,
          stderr: redactSecrets(r.stderr).slice(0, 300),
        });
      }
      generated(r.stdout, "key-create");
      changes.push(rotate ? "rotated s3 access key" : "created s3 access key");
    }
  }

  let finalView = first.view;
  if (changes.length > 0) {
    const verify = await read();
    if (verify.state !== "present" || verify.view === null) {
      fail("verify", "the user could not be read back after a write", {
        uid: args.uid,
        state: verify.state,
      });
    }
    finalView = verify.view;
    if (finalView.displayName !== args.displayName) {
      fail("verify", "the display name did not converge", { uid: args.uid });
    }
    if (emailManaged && finalView.email !== args.email) {
      fail("verify", "the email did not converge", { uid: args.uid });
    }
    if (accessKey !== undefined && !finalView.accessKeys.includes(accessKey)) {
      fail("verify", "the generated access key is not present on the user", {
        uid: args.uid,
      });
    }
  }

  if (changes.length === 0) {
    log?.info("RGW user {uid} already correct", { uid: args.uid });
  } else {
    log?.info("RGW user {uid} changes: {changes}", {
      uid: args.uid,
      changes: changes.join(", "),
    });
  }

  const record: RgwUserRecord = {
    method: "cephRgwUserEnsure",
    host: args.host,
    uid: args.uid,
    displayName: args.displayName,
    email: emailManaged ? args.email! : "",
    existedBefore,
    changes,
    ...(accessKey !== undefined ? { accessKey } : {}),
    ...(key !== undefined ? { key } : {}),
    maxBuckets: finalView?.maxBuckets ?? -1,
    suspended: finalView?.suspended ?? false,
    secretDelivery: "generated",
  };
  // The record is returned; nothing here logs the key.
  void seed(record);
  return record;
}

/** Runs one non-secret `radosgw-admin user modify` field update. */
async function modifyUser(
  deps: PrepDeps,
  session: SshSession,
  uid: string,
  field: "display-name" | "email",
  value: string,
  secrets: string[],
  log?: Logger,
): Promise<void> {
  const body = `radosgw-admin user modify --uid=${quote(uid)} --${field}=${
    quote(value)
  }`;
  const r = await runRadosgwAdmin(
    deps,
    session,
    body,
    { phase: "user-modify", json: false, allowNonZero: true },
    secrets,
    log,
  );
  if (r.code !== 0) {
    fail("user-modify", `${field} modify failed`, {
      uid,
      code: r.code,
      stderr: redactSecrets(r.stderr, secrets).slice(0, 300),
    });
  }
}
