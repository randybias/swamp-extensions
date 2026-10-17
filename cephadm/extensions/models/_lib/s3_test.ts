import { assertEquals, assertRejects } from "jsr:@std/assert@1.0.19";
import { createModelTestContext } from "jsr:@swamp-club/swamp-testing@0.20261014.55";
import { createCephadmModel } from "../cephadm.ts";
import {
  analysePolicy,
  bucketEnsure,
  bucketInspect,
  bucketPolicyEnsure,
  bucketVersioningEnsure,
  type FetchFn,
  HttpError,
  type HttpRequest,
  isBucketName,
  isCredential,
  md5,
  md5Base64,
  normaliseEndpoint,
  ownerLockout,
  parseAcl,
  parsePab,
  parseVersioning,
  PROBE_PREFIX,
  signRequest,
  uriEncode,
} from "./s3.ts";

const NOW = 1_760_400_000_000;
const ARGS = {
  endpoint: "https://203.0.113.10",
  region: "zg1",
  bucket: "data-01",
  accessKey: "AKIAEXAMPLE",
  secretKey: "ab+/cd=SECRET",
  requestTimeoutMs: 5000,
};

interface Req {
  method: string;
  url: string;
  headers: Record<string, string>;
  body: string;
}

type Reply =
  | { status: number; body?: string; headers?: Record<string, string> }
  | { fail: "refused" | "unreachable" };

function fakeFetch(handler: (req: Req, parsed: P) => Reply): {
  fetch: FetchFn;
  calls: Req[];
} {
  const calls: Req[] = [];
  const fetch: FetchFn = async (request: HttpRequest) => {
    await Promise.resolve();
    const req: Req = {
      method: request.method,
      url: request.url,
      headers: request.headers,
      body: request.body === undefined
        ? ""
        : new TextDecoder().decode(request.body),
    };
    calls.push(req);
    const reply = handler(req, parseReq(req));
    if ("fail" in reply) throw new HttpError(reply.fail, "test transport");
    return {
      status: reply.status,
      headers: reply.headers ?? {},
      body: reply.body ?? "",
    };
  };
  return { fetch, calls };
}

interface P {
  path: string;
  query: Record<string, string>;
  signed: boolean;
}

function parseReq(req: Req): P {
  const url = new URL(req.url);
  return {
    path: url.pathname,
    query: Object.fromEntries(url.searchParams.entries()),
    signed: req.headers["Authorization"] !== undefined,
  };
}

function modelWith(fetch: FetchFn) {
  return createCephadmModel({ fetch, now: () => NOW });
}

function ok(body = "", headers: Record<string, string> = {}): Reply {
  return { status: 200, body, headers };
}

const ACL_PRIVATE =
  `<AccessControlPolicy xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
   <Owner><ID>owner-1</ID></Owner>
   <AccessControlList><Grant>
     <Grantee xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="CanonicalUser"><ID>owner-1</ID></Grantee>
     <Permission>FULL_CONTROL</Permission>
   </Grant></AccessControlList></AccessControlPolicy>`;

const PAB_FULL =
  `<PublicAccessBlockConfiguration><BlockPublicAcls>true</BlockPublicAcls><IgnorePublicAcls>true</IgnorePublicAcls><BlockPublicPolicy>true</BlockPublicPolicy><RestrictPublicBuckets>true</RestrictPublicBuckets></PublicAccessBlockConfiguration>`;

const PAB_NONE_ERROR =
  `<Error><Code>NoSuchPublicAccessBlockConfiguration</Code></Error>`;

const POLICY_OK = JSON.stringify({
  Version: "2012-10-17",
  Statement: {
    Effect: "Deny",
    Principal: "*",
    Action: "s3:*",
    Resource: "arn:aws:s3:::data-01/*",
    Condition: { Bool: { "aws:SecureTransport": "false" } },
  },
});

// ---------------------------------------------------------------------------
// Pure helpers
// ---------------------------------------------------------------------------

Deno.test("md5 matches the RFC 1321 vectors", () => {
  const hex = (s: string) =>
    [...md5(new TextEncoder().encode(s))].map((b) =>
      b.toString(16).padStart(2, "0")
    ).join("");
  assertEquals(hex(""), "d41d8cd98f00b204e9800998ecf8427e");
  assertEquals(hex("abc"), "900150983cd24fb0d6963f7d28e17f72");
  assertEquals(
    md5Base64(new TextEncoder().encode("")),
    "1B2M2Y8AsgTpgAmY7PhCfg==",
  );
});

Deno.test("uriEncode follows the SigV4 rules", () => {
  assertEquals(uriEncode("a b/c"), "a%20b%2Fc");
  assertEquals(uriEncode("a b/c", false), "a%20b/c");
  assertEquals(
    uriEncode(".cephadm-pab-probe/1-canned", false),
    ".cephadm-pab-probe/1-canned",
  );
  assertEquals(uriEncode("a=1&b"), "a%3D1%26b");
});

Deno.test("endpoint validation: https origin only", () => {
  assertEquals(
    normaliseEndpoint("https://203.0.113.10", "https"),
    "https://203.0.113.10",
  );
  assertEquals(
    normaliseEndpoint("https://s3.example.test:8443/", "https"),
    "https://s3.example.test:8443",
  );
  for (
    const bad of [
      "http://s3.example.test",
      "https://s3.example.test/prefix",
      "https://s3.example.test/?x=1",
      "https://user:pw@s3.example.test",
      "not a url",
    ]
  ) {
    let threw = false;
    try {
      normaliseEndpoint(bad, "https");
    } catch {
      threw = true;
    }
    assertEquals(threw, true, bad);
  }
});

Deno.test("bucket and credential grammars ", () => {
  for (const good of ["a.b-c", "data-01"]) {
    assertEquals(isBucketName(good), true);
  }
  for (
    const bad of [
      "Upper-Case",
      "a..b",
      "192.0.2.1",
      "ab",
      "a/b",
      "-leading",
      "trailing-",
      "has space",
      "q?x",
    ]
  ) {
    assertEquals(isBucketName(bad), false, bad);
  }
  assertEquals(isCredential("AKIAEXAMPLE"), true);
  assertEquals(isCredential("ab+/cd="), true);
  assertEquals(isCredential(""), false);
  assertEquals(isCredential("has space"), false);
  assertEquals(isCredential("has\nnewline"), false);
  assertEquals(isCredential("caf\u00e9"), false);
});

Deno.test("signRequest: SigV4 shape, s3 scope, path-style, empty-body hash", async () => {
  const signed = await signRequest({
    method: "PUT",
    origin: "https://203.0.113.10",
    path: "/data-01/.cephadm-pab-probe/1-canned",
    query: {},
    headers: {},
    body: new TextEncoder().encode(""),
    region: "zg1",
    accessKey: "AKIAEXAMPLE",
    secretKey: "ab+/cd=SECRET",
    timestamp: NOW,
  });
  assertEquals(
    signed.url,
    "https://203.0.113.10/data-01/.cephadm-pab-probe/1-canned",
  );
  assertEquals(
    signed.headers["x-amz-content-sha256"],
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  );
  const auth = signed.headers["Authorization"];
  assertEquals(
    auth.startsWith("AWS4-HMAC-SHA256 Credential=AKIAEXAMPLE/"),
    true,
  );
  assertEquals(auth.includes("/zg1/s3/aws4_request"), true);
  assertEquals(
    auth.includes("SignedHeaders=host;x-amz-content-sha256;x-amz-date"),
    true,
  );
  assertEquals(auth.includes("Signature="), true);
});

// ---------------------------------------------------------------------------
// XML / ACL / PAB / versioning parsing
// ---------------------------------------------------------------------------

Deno.test("ACL: prefixed namespace and entity decoding parse like the plain form", () => {
  const namespaced =
    `<s3:AccessControlPolicy xmlns:s3="http://s3.amazonaws.com/doc/2006-03-01/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
     <s3:Owner><s3:ID>owner-1</s3:ID></s3:Owner>
     <s3:AccessControlList><s3:Grant>
       <s3:Grantee xsi:type="CanonicalUser"><s3:ID>owner-1</s3:ID></s3:Grantee>
       <s3:Permission>FULL_CONTROL</s3:Permission>
     </s3:Grant><s3:Grant>
       <s3:Grantee xsi:type="Group"><s3:URI>http://acs.amazonaws.com/groups/global/AllUsers</s3:URI></s3:Grantee>
       <s3:Permission>READ</s3:Permission>
     </s3:Grant></s3:AccessControlList></s3:AccessControlPolicy>`;
  const acl = parseAcl(namespaced);
  assertEquals(acl.ownerId, "owner-1");
  assertEquals(acl.grants.length, 2);
  assertEquals(acl.grants[1].granteeType, "Group");
  assertEquals(
    acl.grants[1].grantee,
    "http://acs.amazonaws.com/groups/global/AllUsers",
  );
  // The AllUsers grant means this is not private.
  assertEquals(acl.grants.length === 1, false);
});

Deno.test("ACL: an untyped grantee is a parse failure", () => {
  const xml =
    `<AccessControlPolicy><Owner><ID>o</ID></Owner><AccessControlList><Grant><Grantee><ID>o</ID></Grantee><Permission>FULL_CONTROL</Permission></Grant></AccessControlList></AccessControlPolicy>`;
  let threw = false;
  try {
    parseAcl(xml);
  } catch {
    threw = true;
  }
  assertEquals(threw, true);
});

Deno.test("versioning: three states, self-closing is never-configured, bad status throws", () => {
  assertEquals(
    parseVersioning(`<VersioningConfiguration/>`),
    "never-configured",
  );
  assertEquals(
    parseVersioning(
      `<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>`,
    ),
    "Enabled",
  );
  assertEquals(
    parseVersioning(
      `<VersioningConfiguration><Status>Suspended</Status></VersioningConfiguration>`,
    ),
    "Suspended",
  );
  let threw = false;
  try {
    parseVersioning(
      `<VersioningConfiguration><Status>Paused</Status></VersioningConfiguration>`,
    );
  } catch {
    threw = true;
  }
  assertEquals(threw, true);
});

Deno.test("PAB: missing flag reads false; a non-boolean throws", () => {
  const pab = parsePab(
    `<PublicAccessBlockConfiguration><BlockPublicPolicy>false</BlockPublicPolicy></PublicAccessBlockConfiguration>`,
  );
  assertEquals(pab.blockPublicPolicy, false);
  assertEquals(pab.blockPublicAcls, false);
  let threw = false;
  try {
    parsePab(
      `<PublicAccessBlockConfiguration><BlockPublicAcls>yes</BlockPublicAcls></PublicAccessBlockConfiguration>`,
    );
  } catch {
    threw = true;
  }
  assertEquals(threw, true);
});

// ---------------------------------------------------------------------------
// Policy validation, canonical form, owner lockout
// ---------------------------------------------------------------------------

Deno.test("policy: a public Allow is refused in every spelling", () => {
  for (
    const principal of [
      "*",
      { AWS: "*" },
      { AWS: ["*"] },
      undefined,
    ]
  ) {
    const doc = JSON.stringify({
      Version: "2012-10-17",
      Statement: {
        Effect: "Allow",
        Principal: principal,
        Action: "s3:GetObject",
        Resource: "arn:aws:s3:::data-01/*",
      },
    });
    let phase = "";
    try {
      analysePolicy(doc, "data-01");
    } catch (e) {
      phase = (e as { phase: string }).phase;
    }
    assertEquals(phase, "public-allow", JSON.stringify(principal));
  }
});

Deno.test("policy: a Deny * passes; NotPrincipal Allow, sibling ARN, bad JSON refused", () => {
  const deny = analysePolicy(POLICY_OK, "data-01");
  assertEquals(deny.statementCount, 1);
  assertEquals(deny.declaresSecureTransport, true);
  const notPrincipal = JSON.stringify({
    Version: "2012-10-17",
    Statement: {
      Effect: "Allow",
      NotPrincipal: { AWS: "arn:aws:iam::1:user/x" },
      Action: "s3:GetObject",
      Resource: "arn:aws:s3:::data-01/*",
    },
  });
  let phase = "";
  try {
    analysePolicy(notPrincipal, "data-01");
  } catch (e) {
    phase = (e as { phase: string }).phase;
  }
  assertEquals(phase, "public-allow");
  const sibling = JSON.stringify({
    Version: "2012-10-17",
    Statement: {
      Effect: "Deny",
      Principal: "*",
      Action: "s3:*",
      Resource: "arn:aws:s3:::other/*",
    },
  });
  phase = "";
  try {
    analysePolicy(sibling, "data-01");
  } catch (e) {
    phase = (e as { phase: string }).phase;
  }
  assertEquals(phase, "validate");
  for (
    const bad of [
      "not json",
      `{"Statement":[]}`,
      `{"Version":"","Statement":[{}]}`,
    ]
  ) {
    let threw = false;
    try {
      analysePolicy(bad, "data-01");
    } catch {
      threw = true;
    }
    assertEquals(threw, true, bad);
  }
});

Deno.test("policy canonical: reordering and scalar/list forms compare equal", () => {
  const a = JSON.stringify({
    Version: "2012-10-17",
    Statement: [
      {
        Effect: "Allow",
        Principal: { AWS: "arn:aws:iam::1:user/x" },
        Action: ["s3:GetObject", "s3:PutObject"],
        Resource: ["arn:aws:s3:::data-01/*"],
      },
      {
        Effect: "Deny",
        Principal: "*",
        Action: "s3:*",
        Resource: "arn:aws:s3:::data-01/*",
        Condition: { Bool: { "aws:SecureTransport": false } },
      },
    ],
  });
  const b = JSON.stringify({
    Statement: [
      {
        Resource: "arn:aws:s3:::data-01/*",
        Action: "s3:*",
        Principal: "*",
        Effect: "Deny",
        Condition: { Bool: { "aws:SecureTransport": "false" } },
      },
      {
        Resource: "arn:aws:s3:::data-01/*",
        Action: ["s3:PutObject", "s3:GetObject"],
        Principal: { AWS: ["arn:aws:iam::1:user/x"] },
        Effect: "Allow",
      },
    ],
    Version: "2012-10-17",
  });
  assertEquals(
    analysePolicy(a, "data-01").canonical,
    analysePolicy(b, "data-01").canonical,
  );
  const dropped = JSON.stringify({
    Version: "2012-10-17",
    Statement: [
      {
        Effect: "Allow",
        Principal: { AWS: "arn:aws:iam::1:user/x" },
        Action: ["s3:GetObject"],
        Resource: ["arn:aws:s3:::data-01/*"],
      },
      {
        Effect: "Deny",
        Principal: "*",
        Action: "s3:*",
        Resource: "arn:aws:s3:::data-01/*",
        Condition: { Bool: { "aws:SecureTransport": false } },
      },
    ],
  });
  assertEquals(
    analysePolicy(a, "data-01").canonical ===
      analysePolicy(dropped, "data-01").canonical,
    false,
  );
});

Deno.test("owner lockout: blanket deny, conditional deny, tenant principal", () => {
  const blanket = analysePolicy(
    JSON.stringify({
      Version: "2012-10-17",
      Statement: {
        Effect: "Deny",
        Principal: "*",
        Action: "s3:*",
        Resource: "arn:aws:s3:::data-01",
      },
    }),
    "data-01",
  );
  assertEquals(
    ownerLockout(blanket.statements, "owner-1", "data-01").length,
    3,
  );

  const conditional = analysePolicy(POLICY_OK, "data-01");
  assertEquals(
    ownerLockout(conditional.statements, "owner-1", "data-01").length,
    0,
  );

  const tenant = analysePolicy(
    JSON.stringify({
      Version: "2012-10-17",
      Statement: {
        Effect: "Deny",
        Principal: { AWS: "arn:aws:iam::tenant:user/uid" },
        Action: "s3:*Policy",
        Resource: "arn:aws:s3:::data-01",
      },
    }),
    "data-01",
  );
  assertEquals(
    ownerLockout(tenant.statements, "tenant$uid", "data-01").length,
    3,
  );
  assertEquals(
    ownerLockout(tenant.statements, "other$uid", "data-01").length,
    0,
  );
});

// ---------------------------------------------------------------------------
// cephRgwBucketInspect
// ---------------------------------------------------------------------------

Deno.test("inspect: owned bucket reads PAB, ACL, policy, versioning (GET/HEAD only)", async () => {
  const { fetch, calls } = fakeFetch((_req, p) => {
    if (p.path === "/data-01" && p.query.publicAccessBlock !== undefined) {
      return ok(PAB_FULL);
    }
    if (p.path === "/data-01" && p.query.acl !== undefined) {
      return ok(ACL_PRIVATE);
    }
    if (p.path === "/data-01" && p.query.policy !== undefined) {
      return ok(POLICY_OK);
    }
    if (p.path === "/data-01" && p.query.versioning !== undefined) {
      return ok(
        `<VersioningConfiguration><Status>Suspended</Status></VersioningConfiguration>`,
      );
    }
    if (p.path === "/data-01") return { status: 200 };
    return { status: 500 };
  });
  const record = await bucketInspect({ fetch, now: () => NOW }, ARGS);
  assertEquals(record.presence, "owned");
  assertEquals(record.aclPrivate, true);
  assertEquals(record.ownerId, "owner-1");
  assertEquals(record.hasPolicy, true);
  assertEquals(record.policy, POLICY_OK);
  assertEquals(record.policyCanonical.length > 0, true);
  assertEquals(record.versioning, "Suspended");
  assertEquals(record.publicAccessBlockFull, true);
  assertEquals(
    calls.every((c) => c.method === "GET" || c.method === "HEAD"),
    true,
  );
});

Deno.test("inspect: absent is recorded, unreadable presence throws", async () => {
  const absent = fakeFetch(() => ({ status: 404 }));
  const rec = await bucketInspect(
    { fetch: absent.fetch, now: () => NOW },
    ARGS,
  );
  assertEquals(rec.presence, "absent");
  assertEquals(rec.versioning, "");

  const broken = fakeFetch(() => ({ status: 503 }));
  await assertRejects(
    () => bucketInspect({ fetch: broken.fetch, now: () => NOW }, ARGS),
    Error,
    "cephadm[read]",
  );
});

Deno.test("inspect: foreign and credentials-rejected are recorded, no record on read", async () => {
  const foreign = fakeFetch((_req, p) => {
    if (p.path === "/data-01") return { status: 403 };
    if (p.path === "/") return ok();
    return { status: 500 };
  });
  const f = await bucketInspect(
    { fetch: foreign.fetch, now: () => NOW },
    ARGS,
  );
  assertEquals(f.presence, "foreign");

  const rejected = fakeFetch((_req, p) => {
    if (p.path === "/data-01") return { status: 403 };
    if (p.path === "/") {
      return { status: 403, body: `<Error><Code>AccessDenied</Code></Error>` };
    }
    return { status: 500 };
  });
  const r = await bucketInspect(
    { fetch: rejected.fetch, now: () => NOW },
    ARGS,
  );
  assertEquals(r.presence, "credentials-rejected");
});

Deno.test("inspect: no PAB configuration is null and not full", async () => {
  const { fetch } = fakeFetch((_req, p) => {
    if (p.query.publicAccessBlock !== undefined) {
      return { status: 404, body: PAB_NONE_ERROR };
    }
    if (p.query.acl !== undefined) return ok(ACL_PRIVATE);
    if (p.query.policy !== undefined) {
      return {
        status: 404,
        body: `<Error><Code>NoSuchBucketPolicy</Code></Error>`,
      };
    }
    if (p.query.versioning !== undefined) {
      return ok(`<VersioningConfiguration/>`);
    }
    return { status: 200 };
  });
  const rec = await bucketInspect({ fetch, now: () => NOW }, ARGS);
  assertEquals(rec.publicAccessBlock, null);
  assertEquals(rec.publicAccessBlockFull, false);
});

// ---------------------------------------------------------------------------
// cephRgwBucketEnsure
// ---------------------------------------------------------------------------

function ensureBase(overrides: Partial<typeof ARGS> = {}) {
  return { ...ARGS, placementTarget: "default", ...overrides };
}

function ensureHandler(opts: {
  head?: (n: number) => Reply;
  pab?: PabState;
  acl?: string;
  cannedAnonymous?: number;
  grantAnonymous?: number;
  grantPut?: number;
  cannedPut?: number;
  deleteFail?: boolean;
  control?: number;
  anonList?: number;
  versionId?: string;
}) {
  let headCount = 0;
  let pab: ReturnType<typeof parsePab> | null = opts.pab === null
    ? null
    : opts.pab === undefined
    ? null
    : opts.pab === "full"
    ? parsePab(PAB_FULL)
    : parsePab(opts.pab);
  return (_req: Req, p: P): Reply => {
    if (p.path === "/data-01" && p.query.publicAccessBlock !== undefined) {
      if (_req.method === "PUT") {
        pab = parsePab(_req.body);
        return ok();
      }
      return pab === null
        ? { status: 404, body: PAB_NONE_ERROR }
        : ok(renderPabBody(pab));
    }
    if (p.path === "/data-01" && p.query.acl !== undefined) {
      if (_req.method === "PUT") {
        opts.acl = ACL_PRIVATE;
        return ok();
      }
      return ok(opts.acl ?? ACL_PRIVATE);
    }
    if (p.path === "/data-01" && p.query["list-type"] !== undefined) {
      if (p.signed) return { status: opts.control ?? 200 };
      return { status: opts.anonList ?? 403 };
    }
    if (p.path === "/data-01" && _req.method === "PUT") {
      return ok("", { "x-amz-version-id": opts.versionId ?? "" });
    }
    if (p.path.startsWith("/data-01/")) {
      const isGrant = p.path.endsWith("-grant");
      if (_req.method === "PUT") {
        const status = isGrant
          ? (opts.grantPut ?? 200)
          : (opts.cannedPut ?? 200);
        return {
          status,
          headers: { "x-amz-version-id": opts.versionId ?? "" },
        };
      }
      if (_req.method === "GET") {
        return {
          status: isGrant
            ? (opts.grantAnonymous ?? 403)
            : (opts.cannedAnonymous ?? 403),
        };
      }
      if (_req.method === "DELETE") {
        return { status: opts.deleteFail ? 403 : 204 };
      }
    }
    if (p.path === "/data-01") {
      return opts.head?.(headCount++) ?? { status: 200 };
    }
    return { status: 500 };
  };
}

type PabState = "full" | null | string;

function renderPabBody(pab: ReturnType<typeof parsePab>): string {
  return `<PublicAccessBlockConfiguration>` +
    `<BlockPublicAcls>${pab.blockPublicAcls}</BlockPublicAcls>` +
    `<IgnorePublicAcls>${pab.ignorePublicAcls}</IgnorePublicAcls>` +
    `<BlockPublicPolicy>${pab.blockPublicPolicy}</BlockPublicPolicy>` +
    `<RestrictPublicBuckets>${pab.restrictPublicBuckets}</RestrictPublicBuckets>` +
    `</PublicAccessBlockConfiguration>`;
}

Deno.test("ensure: absent creates with the location constraint, then probes", async () => {
  const { fetch, calls } = fakeFetch(
    ensureHandler({
      head: (n) => n === 0 ? { status: 404 } : { status: 200 },
      pab: "full",
    }),
  );
  const rec = await bucketEnsure({ fetch, now: () => NOW }, ensureBase());
  assertEquals(rec.created, true);
  assertEquals(rec.existedBefore, false);
  assertEquals(rec.placementRequested, "zg1:default");
  assertEquals(rec.aclPrivate, true);
  assertEquals(rec.pabChanged, false);
  assertEquals(rec.controlStatus, 200);
  assertEquals(rec.anonymousStatus, 403);
  const create = calls.find((c) =>
    c.method === "PUT" && new URL(c.url).pathname === "/data-01" &&
    new URL(c.url).search === ""
  );
  assertEquals(create !== undefined, true);
  assertEquals(
    create!.body.includes(
      "<LocationConstraint>zg1:default</LocationConstraint>",
    ),
    true,
  );
  assertEquals(create!.headers["x-amz-acl"], "private");
  const probePuts = calls.filter((c) =>
    c.method === "PUT" &&
    new URL(c.url).pathname.startsWith(`/data-01/${PROBE_PREFIX}`)
  );
  assertEquals(probePuts.length >= 2, true);
  assertEquals(rec.objectLeakProbe, "refused");
  assertEquals(rec.objectLeakProbeKey.startsWith(PROBE_PREFIX), true);
  assertEquals(rec.objectLeakProbeWriter, "owner-1");
});

Deno.test("ensure: idempotent on an owned, private, full bucket", async () => {
  const { fetch, calls } = fakeFetch(
    ensureHandler({ pab: "full" }),
  );
  const rec = await bucketEnsure({ fetch, now: () => NOW }, ensureBase());
  assertEquals(rec.created, false);
  assertEquals(rec.existedBefore, true);
  assertEquals(rec.pabChanged, false);
  assertEquals(rec.aclChanged, false);
  const bucketWrites = calls.filter((c) =>
    c.method === "PUT" && new URL(c.url).pathname === "/data-01" &&
    new URL(c.url).search === ""
  );
  assertEquals(bucketWrites.length, 0);
});

Deno.test("ensure: a public ACL grant is replaced with a private one", async () => {
  const publicAcl =
    `<AccessControlPolicy><Owner><ID>owner-1</ID></Owner><AccessControlList><Grant><Grantee xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="CanonicalUser"><ID>owner-1</ID></Grantee><Permission>FULL_CONTROL</Permission></Grant><Grant><Grantee xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="Group"><URI>http://acs.amazonaws.com/groups/global/AllUsers</URI></Grantee><Permission>READ</Permission></Grant></AccessControlList></AccessControlPolicy>`;
  const { fetch, calls } = fakeFetch(
    ensureHandler({ pab: "full", acl: publicAcl }),
  );
  const rec = await bucketEnsure({ fetch, now: () => NOW }, ensureBase());
  assertEquals(rec.aclChanged, true);
  assertEquals(rec.aclPrivate, true);
  assertEquals(rec.aclGrantsBefore.length, 2);
  assertEquals(rec.aclGrantsAfter.length, 1);
  assertEquals(
    calls.some((c) => c.method === "PUT" && new URL(c.url).search === "?acl="),
    true,
  );
});

Deno.test("ensure: foreign and rejected credentials refuse, no writes", async () => {
  const foreign = fakeFetch((_req, p) => {
    if (p.path === "/data-01") return { status: 403 };
    if (p.path === "/") return ok();
    return { status: 500 };
  });
  await assertRejects(
    () => bucketEnsure({ fetch: foreign.fetch, now: () => NOW }, ensureBase()),
    Error,
    "cephadm[foreign]",
  );
  assertEquals(
    foreign.calls.some((c) => c.method === "PUT"),
    false,
  );

  const rejected = fakeFetch((_req, p) => {
    if (p.path === "/data-01") return { status: 403 };
    if (p.path === "/") {
      return { status: 403, body: `<Error><Code>AccessDenied</Code></Error>` };
    }
    return { status: 500 };
  });
  await assertRejects(
    () => bucketEnsure({ fetch: rejected.fetch, now: () => NOW }, ensureBase()),
    Error,
    "cephadm[credentials]",
  );
});

Deno.test("ensure: unknown placement and unreadable head refuse", async () => {
  const placement = fakeFetch((_req, p) => {
    if (p.path === "/data-01" && _req.method === "HEAD") return { status: 404 };
    if (p.path === "/data-01" && _req.method === "PUT") {
      return {
        status: 400,
        body: `<Error><Code>InvalidLocationConstraint</Code></Error>`,
      };
    }
    return { status: 500 };
  });
  await assertRejects(
    () =>
      bucketEnsure({ fetch: placement.fetch, now: () => NOW }, ensureBase()),
    Error,
    "cephadm[placement]",
  );

  const timeout = fakeFetch(() => ({ fail: "unreachable" }));
  await assertRejects(
    () => bucketEnsure({ fetch: timeout.fetch, now: () => NOW }, ensureBase()),
    Error,
    "cephadm[read]",
  );
});

Deno.test("ensure: anonymous list allowed refuses before the object probe", async () => {
  const { fetch, calls } = fakeFetch(
    ensureHandler({ pab: "full", anonList: 200 }),
  );
  await assertRejects(
    () => bucketEnsure({ fetch, now: () => NOW }, ensureBase()),
    Error,
    "cephadm[anonymous-allowed]",
  );
  assertEquals(
    calls.some((c) =>
      new URL(c.url).pathname.startsWith(`/data-01/${PROBE_PREFIX}`)
    ),
    false,
  );
});

Deno.test("ensure: a failed control list refuses and sends no unsigned list", async () => {
  const { fetch, calls } = fakeFetch(
    ensureHandler({ pab: "full", control: 500 }),
  );
  await assertRejects(
    () => bucketEnsure({ fetch, now: () => NOW }, ensureBase()),
    Error,
    "cephadm[control]",
  );
  assertEquals(
    calls.filter((c) =>
      c.method === "GET" && new URL(c.url).search.includes("list-type")
    ).length,
    1,
  );
});

Deno.test("ensure: no PAB becomes all four on with a Content-MD5 header", async () => {
  const { fetch, calls } = fakeFetch(ensureHandler({ pab: null }));
  const rec = await bucketEnsure({ fetch, now: () => NOW }, ensureBase());
  assertEquals(rec.pabBefore, null);
  assertEquals(rec.pabChanged, true);
  assertEquals(rec.pabAfter.blockPublicAcls, true);
  const put = calls.find((c) =>
    c.method === "PUT" && new URL(c.url).search.includes("publicAccessBlock")
  );
  assertEquals(put !== undefined, true);
  assertEquals(typeof put!.headers["content-md5"], "string");
});

Deno.test("ensure: PAB accepted but not stored rejects pab-set", async () => {
  let pabWrites = 0;
  const { fetch } = fakeFetch((_req, p) => {
    if (p.path === "/data-01" && p.query.publicAccessBlock !== undefined) {
      if (_req.method === "PUT") {
        pabWrites++;
        return ok();
      }
      return pabWrites === 0 ? { status: 404, body: PAB_NONE_ERROR } : ok(
        `<PublicAccessBlockConfiguration><BlockPublicAcls>true</BlockPublicAcls></PublicAccessBlockConfiguration>`,
      );
    }
    if (p.path === "/data-01" && p.query.acl !== undefined) {
      return ok(ACL_PRIVATE);
    }
    if (p.path === "/data-01") return { status: 200 };
    return { status: 500 };
  });
  await assertRejects(
    () => bucketEnsure({ fetch, now: () => NOW }, ensureBase()),
    Error,
    "cephadm[pab-set]",
  );
});

Deno.test("ensure: a stored-but-unenforced PAB detects the leak and deletes the probes", async () => {
  const { fetch, calls } = fakeFetch(
    ensureHandler({ pab: "full", cannedAnonymous: 200 }),
  );
  await assertRejects(
    () => bucketEnsure({ fetch, now: () => NOW }, ensureBase()),
    Error,
    "cephadm[object-leak]",
  );
  const deletes = calls.filter((c) => c.method === "DELETE");
  assertEquals(deletes.length, 2);
});

Deno.test("ensure: canned PutObject 500 is object-leak-probe, distinct and no delete", async () => {
  const { fetch, calls } = fakeFetch(
    ensureHandler({ pab: "full", cannedPut: 500 }),
  );
  await assertRejects(
    () => bucketEnsure({ fetch, now: () => NOW }, ensureBase()),
    Error,
    "could not run",
  );
  assertEquals(calls.some((c) => c.method === "DELETE"), false);
});

Deno.test("ensure: a refused cleanup DELETE rejects object-leak-cleanup naming the keys", async () => {
  const { fetch } = fakeFetch(
    ensureHandler({ pab: "full", deleteFail: true }),
  );
  await assertRejects(
    () => bucketEnsure({ fetch, now: () => NOW }, ensureBase()),
    Error,
    "could not be deleted",
  );
});

Deno.test("ensure: skipped probe sends no object request and records skipped", async () => {
  const { fetch, calls } = fakeFetch(ensureHandler({ pab: "full" }));
  const rec = await bucketEnsure(
    { fetch, now: () => NOW },
    { ...ensureBase(), skipObjectLeakProbe: true },
  );
  assertEquals(rec.objectLeakProbe, "skipped");
  assertEquals(rec.objectLeakProbeWriter, "");
  assertEquals(
    calls.some((c) =>
      new URL(c.url).pathname.startsWith(`/data-01/${PROBE_PREFIX}`)
    ),
    false,
  );
});

Deno.test("ensure: a versioned bucket deletes by versionId", async () => {
  const { fetch, calls } = fakeFetch(
    ensureHandler({ pab: "full", versionId: "v-abc" }),
  );
  await bucketEnsure({ fetch, now: () => NOW }, ensureBase());
  const deletes = calls.filter((c) => c.method === "DELETE");
  assertEquals(deletes.length, 2);
  for (const d of deletes) {
    assertEquals(new URL(d.url).searchParams.get("versionId"), "v-abc");
  }
});

// ---------------------------------------------------------------------------
// cephRgwBucketVersioningEnsure
// ---------------------------------------------------------------------------

function versioningHandler(initial: string | null, putApplies: boolean) {
  let status = initial;
  return (_req: Req, p: P): Reply => {
    if (p.path === "/data-01" && p.query.versioning !== undefined) {
      if (_req.method === "PUT") {
        if (putApplies) {
          const m = /<Status>([^<]*)<\/Status>/.exec(_req.body);
          status = m ? m[1] : status;
        }
        return ok();
      }
      return ok(
        status === null
          ? `<VersioningConfiguration/>`
          : `<VersioningConfiguration><Status>${status}</Status></VersioningConfiguration>`,
      );
    }
    if (p.path === "/data-01") return { status: 200 };
    return { status: 500 };
  };
}

Deno.test("versioning: never-configured to Enabled writes once", async () => {
  const { fetch, calls } = fakeFetch(versioningHandler(null, true));
  const rec = await bucketVersioningEnsure(
    { fetch, now: () => NOW },
    { ...ARGS, desired: "Enabled" },
  );
  assertEquals(rec.before, "never-configured");
  assertEquals(rec.after, "Enabled");
  assertEquals(rec.changed, true);
  assertEquals(rec.conditionalWritesUnsafe, true);
  assertEquals(calls.filter((c) => c.method === "PUT").length, 1);
});

Deno.test("versioning: already Suspended writes nothing", async () => {
  const { fetch, calls } = fakeFetch(versioningHandler("Suspended", true));
  const rec = await bucketVersioningEnsure(
    { fetch, now: () => NOW },
    { ...ARGS, desired: "Suspended" },
  );
  assertEquals(rec.changed, false);
  assertEquals(rec.conditionalWritesUnsafe, false);
  assertEquals(calls.some((c) => c.method === "PUT"), false);
});

Deno.test("versioning: a PUT accepted but not applied rejects verify", async () => {
  const { fetch } = fakeFetch(versioningHandler(null, false));
  await assertRejects(
    () =>
      bucketVersioningEnsure(
        { fetch, now: () => NOW },
        { ...ARGS, desired: "Enabled" },
      ),
    Error,
    "cephadm[verify]",
  );
});

Deno.test("versioning: absent refuses with the absent phase and no writes", async () => {
  const { fetch, calls } = fakeFetch(() => ({ status: 404 }));
  await assertRejects(
    () =>
      bucketVersioningEnsure(
        { fetch, now: () => NOW },
        { ...ARGS, desired: "Enabled" },
      ),
    Error,
    "cephadm[absent]",
  );
  assertEquals(calls.some((c) => c.method === "PUT"), false);
});

// ---------------------------------------------------------------------------
// cephRgwBucketPolicyEnsure
// ---------------------------------------------------------------------------

function policyHandler(opts: {
  owned?: boolean;
  storedPolicy?: string | null;
  pab?: PabState;
  readBackPolicy?: string | null;
  control?: number;
  anonList?: number;
  pabRestore?: number;
  policyPutOk?: boolean;
}) {
  let stored = opts.storedPolicy ?? null;
  let pab: ReturnType<typeof parsePab> | null = opts.pab === "full"
    ? parsePab(PAB_FULL)
    : opts.pab === undefined || opts.pab === null
    ? null
    : parsePab(opts.pab);
  let policyPuts = 0;
  return (_req: Req, p: P): Reply => {
    if (p.path === "/data-01" && _req.method === "HEAD") {
      return { status: opts.owned === false ? 404 : 200 };
    }
    if (p.path === "/data-01" && p.query.acl !== undefined) {
      return ok(ACL_PRIVATE);
    }
    if (p.path === "/data-01" && p.query.publicAccessBlock !== undefined) {
      if (_req.method === "PUT") {
        pab = parsePab(_req.body);
        return ok();
      }
      return pab === null
        ? { status: 404, body: PAB_NONE_ERROR }
        : ok(renderPabBody(pab));
    }
    if (p.path === "/data-01" && p.query.policy !== undefined) {
      if (_req.method === "PUT") {
        policyPuts++;
        if (opts.policyPutOk === false) return { status: 403 };
        stored = opts.readBackPolicy ?? _req.body;
        return ok();
      }
      if (_req.method === "DELETE") {
        stored = null;
        return { status: 204 };
      }
      return stored === null
        ? {
          status: 404,
          body: `<Error><Code>NoSuchBucketPolicy</Code></Error>`,
        }
        : ok(stored);
    }
    if (p.path === "/data-01" && p.query["list-type"] !== undefined) {
      if (p.signed) return { status: opts.control ?? 200 };
      return { status: opts.anonList ?? 403 };
    }
    if (p.path === "/data-01") return { status: 200 };
    return { status: 500 };
  };
}

Deno.test("policy: a new policy is written, proven and recorded", async () => {
  const { fetch, calls } = fakeFetch(policyHandler({ pab: "full" }));
  const rec = await bucketPolicyEnsure(
    { fetch, now: () => NOW },
    { ...ARGS, policyDocument: POLICY_OK },
  );
  assertEquals(rec.changed, true);
  assertEquals(rec.hadPolicyBefore, false);
  assertEquals(rec.declaresSecureTransport, true);
  assertEquals(rec.controlStatus, 200);
  assertEquals(rec.anonymousStatus, 403);
  assertEquals(rec.pabLiftedForWrite, true);
  assertEquals(rec.plainHttp, "not-tested");
  assertEquals(
    calls.filter((c) =>
      c.method === "PUT" && new URL(c.url).search.includes("policy")
    ).length,
    1,
  );
});

Deno.test("policy: an equivalent stored policy writes nothing and touches no PAB", async () => {
  const reordered = JSON.stringify({
    Statement: [{
      Condition: { Bool: { "aws:SecureTransport": "false" } },
      Resource: "arn:aws:s3:::data-01/*",
      Action: "s3:*",
      Principal: "*",
      Effect: "Deny",
    }],
    Version: "2012-10-17",
  });
  const { fetch, calls } = fakeFetch(
    policyHandler({ storedPolicy: reordered, pab: "full" }),
  );
  const rec = await bucketPolicyEnsure(
    { fetch, now: () => NOW },
    { ...ARGS, policyDocument: POLICY_OK },
  );
  assertEquals(rec.changed, false);
  assertEquals(rec.pabLiftedForWrite, false);
  assertEquals(calls.some((c) => c.method === "PUT"), false);
  assertEquals(
    calls.some((c) => new URL(c.url).search.includes("publicAccessBlock")),
    false,
  );
});

Deno.test("policy: a public Allow is refused with zero requests", async () => {
  const publicDoc = JSON.stringify({
    Version: "2012-10-17",
    Statement: {
      Effect: "Allow",
      Principal: "*",
      Action: "s3:GetObject",
      Resource: "arn:aws:s3:::data-01/*",
    },
  });
  const { fetch, calls } = fakeFetch(() => ({ status: 500 }));
  await assertRejects(
    () =>
      bucketPolicyEnsure(
        { fetch, now: () => NOW },
        { ...ARGS, policyDocument: publicDoc },
      ),
    Error,
    "cephadm[public-allow]",
  );
  assertEquals(calls.length, 0);
});

Deno.test("policy: absent refuses and creates nothing", async () => {
  const { fetch, calls } = fakeFetch(policyHandler({ owned: false }));
  await assertRejects(
    () =>
      bucketPolicyEnsure(
        { fetch, now: () => NOW },
        { ...ARGS, policyDocument: POLICY_OK },
      ),
    Error,
    "cephadm[absent]",
  );
  assertEquals(calls.some((c) => c.method === "PUT"), false);
});

Deno.test("policy: a self-locking draft refuses with zero writes", async () => {
  const lockout = JSON.stringify({
    Version: "2012-10-17",
    Statement: [
      {
        Effect: "Deny",
        Principal: "*",
        Action: "s3:*",
        Resource: "arn:aws:s3:::data-01",
      },
      {
        Effect: "Allow",
        Principal: { AWS: "arn:aws:iam::1:user/x" },
        Action: "s3:GetObject",
        Resource: "arn:aws:s3:::data-01/*",
      },
    ],
  });
  const { fetch, calls } = fakeFetch(policyHandler({ pab: "full" }));
  await assertRejects(
    () =>
      bucketPolicyEnsure(
        { fetch, now: () => NOW },
        { ...ARGS, policyDocument: lockout },
      ),
    Error,
    "cephadm[self-lockout]",
  );
  assertEquals(calls.some((c) => c.method === "PUT"), false);
});

Deno.test("policy: a mangled read-back rolls back and rethrows the phase", async () => {
  const mangled = JSON.stringify({
    Version: "2012-10-17",
    Statement: {
      Effect: "Deny",
      Principal: "*",
      Action: "s3:ListBucket",
      Resource: "arn:aws:s3:::data-01",
    },
  });
  const { fetch, calls } = fakeFetch(
    policyHandler({ readBackPolicy: mangled }),
  );
  await assertRejects(
    () =>
      bucketPolicyEnsure(
        { fetch, now: () => NOW },
        { ...ARGS, policyDocument: POLICY_OK },
      ),
    Error,
    "cephadm[verify]",
  );
  assertEquals(
    calls.some((c) =>
      c.method === "DELETE" && new URL(c.url).search.includes("policy")
    ),
    true,
  );
});

Deno.test("policy: a control failure rolls back with RESTORED and no record", async () => {
  const { fetch } = fakeFetch(
    policyHandler({ control: 500, pab: "full" }),
  );
  let message = "";
  try {
    await bucketPolicyEnsure(
      { fetch, now: () => NOW },
      { ...ARGS, policyDocument: POLICY_OK },
    );
  } catch (e) {
    message = (e as Error).message;
  }
  assertEquals(message.includes("RESTORED"), true);
});

Deno.test("policy: PAB restore failure rejects pab-restore", async () => {
  // The lift succeeds and its read-back matches; the restore write is refused.
  let writes = 0;
  let pab = parsePab(PAB_FULL);
  let stored: string | null = null;
  const { fetch } = fakeFetch((_req, p) => {
    if (p.path === "/data-01" && p.query.publicAccessBlock !== undefined) {
      if (_req.method === "PUT") {
        writes++;
        if (writes === 1) {
          pab = parsePab(_req.body);
          return ok();
        }
        return { status: 500 };
      }
      return ok(renderPabBody(pab));
    }
    if (p.path === "/data-01" && p.query.acl !== undefined) {
      return ok(ACL_PRIVATE);
    }
    if (p.path === "/data-01" && p.query.policy !== undefined) {
      if (_req.method === "PUT") {
        stored = _req.body;
        return ok();
      }
      if (_req.method === "DELETE") {
        stored = null;
        return { status: 204 };
      }
      return stored === null
        ? {
          status: 404,
          body: `<Error><Code>NoSuchBucketPolicy</Code></Error>`,
        }
        : ok(stored);
    }
    if (p.path === "/data-01" && p.query["list-type"] !== undefined) {
      return p.signed ? { status: 200 } : { status: 403 };
    }
    if (p.path === "/data-01") return { status: 200 };
    return { status: 500 };
  });
  await assertRejects(
    () =>
      bucketPolicyEnsure(
        { fetch, now: () => NOW },
        { ...ARGS, policyDocument: POLICY_OK },
      ),
    Error,
    "cephadm[pab-restore]",
  );
});

Deno.test("policy: plain HTTP served plus a TLS deny rejects secure-transport-ignored", async () => {
  const handler = policyHandler({ pab: "full" });
  const { fetch } = fakeFetch((_req, p) => {
    if (
      p.path === "/data-01" && p.query["list-type"] !== undefined && p.signed &&
      _req.url.startsWith("http://")
    ) {
      return { status: 200 };
    }
    return handler(_req, p);
  });
  await assertRejects(
    () =>
      bucketPolicyEnsure(
        { fetch, now: () => NOW },
        {
          ...ARGS,
          policyDocument: POLICY_OK,
          plainHttpEndpoint: "http://198.51.100.10",
        },
      ),
    Error,
    "cephadm[secure-transport-ignored]",
  );
});

Deno.test("policy: a refused plain connection is recorded as no-listener", async () => {
  const handler = policyHandler({ pab: "full" });
  const { fetch } = fakeFetch((_req, p) => {
    if (p.query["list-type"] !== undefined && _req.url.startsWith("http://")) {
      return { fail: "refused" };
    }
    return handler(_req, p);
  });
  const rec = await bucketPolicyEnsure(
    { fetch, now: () => NOW },
    {
      ...ARGS,
      policyDocument: POLICY_OK,
      plainHttpEndpoint: "http://198.51.100.10",
    },
  );
  assertEquals(rec.plainHttp, "no-listener");
});

// ---------------------------------------------------------------------------
// Model wiring and secret hygiene
// ---------------------------------------------------------------------------

Deno.test("wiring: the four methods exist, inspect is read-only, the rest are actions", () => {
  const m = modelWith(() =>
    Promise.resolve({ status: 200, headers: {}, body: "" })
  );
  for (
    const name of [
      "cephRgwBucketInspect",
      "cephRgwBucketEnsure",
      "cephRgwBucketPolicyEnsure",
      "cephRgwBucketVersioningEnsure",
    ] as const
  ) {
    assertEquals(typeof (m.methods as Record<string, unknown>)[name], "object");
  }
  assertEquals(
    (m.methods.cephRgwBucketInspect as { kind?: string }).kind,
    undefined,
  );
  for (
    const name of [
      "cephRgwBucketEnsure",
      "cephRgwBucketPolicyEnsure",
      "cephRgwBucketVersioningEnsure",
    ] as const
  ) {
    assertEquals((m.methods[name] as { kind?: string }).kind, "action");
  }
});

Deno.test("wiring: accessKey and secretKey are sensitive on all four methods", () => {
  const m = modelWith(() =>
    Promise.resolve({ status: 200, headers: {}, body: "" })
  );
  for (
    const name of [
      "cephRgwBucketInspect",
      "cephRgwBucketEnsure",
      "cephRgwBucketPolicyEnsure",
      "cephRgwBucketVersioningEnsure",
    ] as const
  ) {
    const shape = (m.methods[name].arguments as unknown as {
      shape: Record<string, { meta: () => { sensitive?: boolean } }>;
    }).shape;
    assertEquals(shape.accessKey.meta().sensitive, true, name);
    assertEquals(shape.secretKey.meta().sensitive, true, name);
  }
});

Deno.test("wiring: a fetched success writes one stable record with capturedAt", async () => {
  const { fetch } = fakeFetch(versioningHandler(null, true));
  const m = modelWith(fetch);
  const { context, getWrittenResources } = createModelTestContext({
    globalArgs: {},
  });
  const out = await m.methods.cephRgwBucketVersioningEnsure.execute(
    m.methods.cephRgwBucketVersioningEnsure.arguments.parse({
      ...ARGS,
      desired: "Enabled",
    }),
    context,
  );
  assertEquals(out.dataHandles.length, 1);
  const written = getWrittenResources()[0];
  assertEquals(written.name, "rgwBucketVersioning-zg1-data-01");
  assertEquals(typeof written.data.capturedAt, "string");
});

Deno.test("hygiene: no record, log or error carries the secret", async () => {
  const captured: string[] = [];
  const log = {
    info: (m: string, p?: Record<string, unknown>) =>
      captured.push(`${m} ${JSON.stringify(p ?? {})}`),
    warn: (m: string, p?: Record<string, unknown>) =>
      captured.push(`${m} ${JSON.stringify(p ?? {})}`),
  };
  const { fetch } = fakeFetch(versioningHandler(null, true));
  const rec = await bucketVersioningEnsure(
    { fetch, now: () => NOW },
    { ...ARGS, desired: "Enabled" },
    log,
  );
  const blob = JSON.stringify(rec) + captured.join("\n");
  assertEquals(blob.includes(ARGS.secretKey), false);
  assertEquals(blob.includes("secretKey"), false);
  assertEquals(blob.length > 0, true);
});

Deno.test("SigV4 known-answer: AWS examplebucket GET Object", async () => {
  const signed = await signRequest({
    method: "GET",
    origin: "https://examplebucket.s3.amazonaws.com",
    path: "/test.txt",
    query: {},
    headers: { range: "bytes=0-9" },
    body: new Uint8Array(),
    region: "us-east-1",
    accessKey: "AKIDEXAMPLE",
    secretKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    timestamp: Date.UTC(2013, 4, 24, 0, 0, 0),
  });
  assertEquals(
    signed.headers["Authorization"].includes(
      "Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41",
    ),
    true,
    signed.headers["Authorization"],
  );
});

Deno.test("SigV4 known-answer: AWS examplebucket List Objects", async () => {
  const signed = await signRequest({
    method: "GET",
    origin: "https://examplebucket.s3.amazonaws.com",
    path: "/",
    query: { "max-keys": "2", prefix: "J" },
    headers: {},
    body: new Uint8Array(),
    region: "us-east-1",
    accessKey: "AKIDEXAMPLE",
    secretKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    timestamp: Date.UTC(2013, 4, 24, 0, 0, 0),
  });
  assertEquals(
    signed.headers["Authorization"].includes(
      "Signature=34b48302e7b5fa45bde8084f4b7868a86f0a534bc59db6670ed5711ef69dc6f7",
    ),
    true,
    signed.headers["Authorization"],
  );
});

Deno.test("owner lockout: SecureTransport matching both true and false locks out", () => {
  const doc = JSON.stringify({
    Version: "2012-10-17",
    Statement: {
      Effect: "Deny",
      Principal: "*",
      Action: "s3:*",
      Resource: "arn:aws:s3:::data-01",
      Condition: { Bool: { "aws:SecureTransport": ["true", "false"] } },
    },
  });
  assertEquals(
    ownerLockout(analysePolicy(doc, "data-01").statements, "owner-1", "data-01")
      .length,
    3,
  );
});

Deno.test("ensure: public-read is PutObjectAcl and every probe version is deleted", async () => {
  const stem = `${PROBE_PREFIX}${NOW}`;
  const cannedKey = `${stem}-canned`;
  const grantKey = `${stem}-grant`;
  const objectPuts: string[] = [];
  const deletes: string[] = [];
  const { fetch, calls } = fakeFetch((_req, p) => {
    if (p.path === "/data-01" && p.query.publicAccessBlock !== undefined) {
      if (_req.method === "PUT") return ok();
      return ok(PAB_FULL);
    }
    if (p.path === "/data-01" && p.query.acl !== undefined) {
      return ok(ACL_PRIVATE);
    }
    if (p.path === "/data-01" && p.query["list-type"] !== undefined) {
      return p.signed ? { status: 200 } : { status: 403 };
    }
    if (p.path === "/data-01" && p.query.versions !== undefined) {
      const key = p.query.prefix ?? "";
      if (key === cannedKey) {
        return ok(
          `<ListVersionsResult><Version><Key>${cannedKey}</Key><VersionId>v1</VersionId></Version><Version><Key>${cannedKey}</Key><VersionId>v2</VersionId></Version></ListVersionsResult>`,
        );
      }
      if (key === grantKey) {
        return ok(
          `<ListVersionsResult><Version><Key>${grantKey}</Key><VersionId>g1</VersionId></Version></ListVersionsResult>`,
        );
      }
      return ok(`<ListVersionsResult/>`);
    }
    if (p.path === "/data-01" && _req.method === "HEAD") return { status: 200 };
    if (p.path.startsWith("/data-01/")) {
      const key = p.path.slice("/data-01/".length);
      if (_req.method === "PUT") {
        if (p.query.acl !== undefined) return ok();
        objectPuts.push(key);
        return {
          status: 200,
          headers: {
            "x-amz-version-id": key.endsWith("-grant") ? "g1" : "v-new",
          },
        };
      }
      if (_req.method === "GET") return { status: 403 };
      if (_req.method === "DELETE") {
        deletes.push(`${key}@${p.query.versionId ?? ""}`);
        return { status: 204 };
      }
    }
    return { status: 500 };
  });
  const rec = await bucketEnsure({ fetch, now: () => NOW }, ensureBase());
  assertEquals(rec.objectLeakProbe, "refused");
  assertEquals(objectPuts.length, 2);
  assertEquals(
    calls.some((c) =>
      c.method === "PUT" && new URL(c.url).searchParams.has("acl")
    ),
    true,
  );
  assertEquals(deletes.includes(`${cannedKey}@v1`), true);
  assertEquals(deletes.includes(`${cannedKey}@v2`), true);
  assertEquals(deletes.includes(`${grantKey}@g1`), true);
});

Deno.test("policy: a failed PAB lift restores the original block and says so", async () => {
  let pabWrites = 0;
  let full = true;
  const { fetch } = fakeFetch((_req, p) => {
    if (p.path === "/data-01" && p.query.publicAccessBlock !== undefined) {
      if (_req.method === "PUT") {
        pabWrites++;
        if (pabWrites === 1) throw new HttpError("unreachable", "lost");
        full = parsePab(_req.body).blockPublicPolicy;
        return ok();
      }
      return ok(renderPabBody(parsePab(PAB_FULL)));
    }
    if (p.path === "/data-01" && p.query.acl !== undefined) {
      return ok(ACL_PRIVATE);
    }
    if (p.path === "/data-01" && p.query.policy !== undefined) {
      return {
        status: 404,
        body: `<Error><Code>NoSuchBucketPolicy</Code></Error>`,
      };
    }
    if (p.path === "/data-01") return { status: 200 };
    return { status: 500 };
  });
  let message = "";
  try {
    await bucketPolicyEnsure(
      { fetch, now: () => NOW },
      { ...ARGS, policyDocument: POLICY_OK },
    );
  } catch (e) {
    message = (e as Error).message;
  }
  assertEquals(message.includes("cephadm[pab-lift]"), true);
  assertEquals(message.includes("restored"), true);
  assertEquals(full, true);
});

Deno.test("policy: the validated, re-serialised document is what is sent", async () => {
  // Two Statement keys: JSON.parse keeps the last, which is what was validated.
  const ignored = {
    Effect: "Allow",
    Principal: "*",
    Action: "s3:GetObject",
    Resource: "arn:aws:s3:::data-01/*",
  };
  const text = `{"Version":"2012-10-17","Statement":${
    JSON.stringify(ignored)
  },"Statement":${
    JSON.stringify({
      Effect: "Deny",
      Principal: "*",
      Action: "s3:*",
      Resource: "arn:aws:s3:::data-01/*",
      Condition: { Bool: { "aws:SecureTransport": "false" } },
    })
  }}`;
  const { fetch, calls } = fakeFetch(policyHandler({ pab: "full" }));
  await bucketPolicyEnsure(
    { fetch, now: () => NOW },
    { ...ARGS, policyDocument: text },
  );
  const put = calls.find((c) =>
    c.method === "PUT" && new URL(c.url).search.includes("policy")
  )!;
  assertEquals(put.body, JSON.stringify(JSON.parse(text)));
  assertEquals(put.body.includes("s3:GetObject"), false);
  assertEquals(put.body === text, false);
});

Deno.test("owner lockout: a Deny on SecureTransport true locks out over https, false does not", () => {
  const deny = (value: unknown, operator = "Bool") =>
    analysePolicy(
      JSON.stringify({
        Version: "2012-10-17",
        Statement: {
          Effect: "Deny",
          Principal: "*",
          Action: "s3:*",
          Resource: "arn:aws:s3:::data-01",
          Condition: { [operator]: { "aws:SecureTransport": value } },
        },
      }),
      "data-01",
    );
  for (
    const locked of [
      deny("true"),
      deny(true),
      deny(["true"]),
      deny(["false", "true"]),
      deny("TRUE"),
      deny("true", "BoolIfExists"),
    ]
  ) {
    assertEquals(
      ownerLockout(locked.statements, "owner-1", "data-01").length > 0,
      true,
    );
  }
  for (
    const fine of [deny("false"), deny(false), deny("false", "BoolIfExists")]
  ) {
    assertEquals(ownerLockout(fine.statements, "owner-1", "data-01").length, 0);
  }
});

Deno.test("policy: a SecureTransport-true Deny is refused as self-lockout before any write", async () => {
  const doc = JSON.stringify({
    Version: "2012-10-17",
    Statement: {
      Effect: "Deny",
      Principal: "*",
      Action: "s3:*",
      Resource: "arn:aws:s3:::data-01",
      Condition: { Bool: { "aws:SecureTransport": "true" } },
    },
  });
  const { fetch, calls } = fakeFetch(policyHandler({ pab: "full" }));
  await assertRejects(
    () =>
      bucketPolicyEnsure(
        { fetch, now: () => NOW },
        { ...ARGS, policyDocument: doc },
      ),
    Error,
    "cephadm[self-lockout]",
  );
  assertEquals(calls.some((c) => c.method === "PUT"), false);
});
