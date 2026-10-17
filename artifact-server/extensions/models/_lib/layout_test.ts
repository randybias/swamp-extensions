import { assertEquals } from "jsr:@std/assert@1.0.19";
import {
  BLOB_DIR,
  blobRelPath,
  blobUrl,
  BUNDLE_DIR,
  bundleRelPath,
  bundleUrl,
  LAYOUT_VERSION,
  parseSha256Sums,
  planPrune,
  renderSha256Sums,
  treeHash,
  urlBase,
} from "./layout.ts";

const TWO = "ab".repeat(32);
const ONE = "0".repeat(64);
const hash = (t: string): Promise<string> => Promise.resolve(t);

Deno.test("blobRelPath and bundleRelPath are the served layout", () => {
  assertEquals(
    blobRelPath({ sha256: ONE, filename: "a.tar.gz" }),
    `${BLOB_DIR}/${ONE}/a.tar.gz`,
  );
  assertEquals(bundleRelPath(ONE), `${BUNDLE_DIR}/${ONE}`);
  assertEquals(LAYOUT_VERSION, 1);
});

Deno.test("renderSha256Sums emits sha256sum -c format, sorted, trailing newline", () => {
  const text = renderSha256Sums([
    { sha256: TWO, filename: "z" },
    { sha256: ONE, filename: "a" },
  ]);
  assertEquals(
    text,
    `${ONE}  ${BLOB_DIR}/${ONE}/a\n${TWO}  ${BLOB_DIR}/${TWO}/z\n`,
  );
  assertEquals(text.endsWith("\n"), true);
});

Deno.test("parseSha256Sums round-trips renderSha256Sums and skips junk", () => {
  const text = renderSha256Sums([
    { sha256: ONE, filename: "a" },
    { sha256: TWO, filename: "b" },
  ]);
  const parsed = parseSha256Sums(
    `${text}\nnot a line\n${ONE} *${BLOB_DIR}/${ONE}/a\n`,
  );
  assertEquals(parsed[0], { sha256: ONE, path: `${BLOB_DIR}/${ONE}/a` });
  assertEquals(parsed[1], { sha256: TWO, path: `${BLOB_DIR}/${TWO}/b` });
  // The `*` binary marker is accepted and stripped.
  assertEquals(parsed[2], { sha256: ONE, path: `${BLOB_DIR}/${ONE}/a` });
});

Deno.test("treeHash is the hash of sorted SHA256SUMS lines", async () => {
  const tree = await treeHash(
    [{ name: "b", sha256: TWO }, { name: "a", sha256: ONE }],
    hash,
  );
  assertEquals(tree, `${ONE}  a\n${TWO}  b\n`);
});

Deno.test("planPrune keeps refs and keep entries and hashes the sorted paths", async () => {
  const plan = await planPrune(
    {
      refs: [{ name: "stable", target: { kind: "blob", hash: ONE } }],
      blobs: [
        { kind: "blob", hash: ONE, bytes: 1, path: `${BLOB_DIR}/${ONE}/a` },
        { kind: "blob", hash: TWO, bytes: 2, path: `${BLOB_DIR}/${TWO}/b` },
      ],
      bundles: [{
        kind: "bundle",
        hash: "cc".repeat(32),
        bytes: 3,
        path: `${BUNDLE_DIR}/x`,
      }],
      keep: [],
    },
    hash,
  );
  assertEquals(plan.objects.map((o) => o.path), [
    `${BUNDLE_DIR}/x`,
    `${BLOB_DIR}/${TWO}/b`,
  ]);
  assertEquals(plan.totalBytes, 5);
  assertEquals(plan.planSha256, `${BUNDLE_DIR}/x\n${BLOB_DIR}/${TWO}/b`);
});

Deno.test("planPrune with everything referenced prunes nothing", async () => {
  const plan = await planPrune(
    {
      refs: [{ name: "r", target: { kind: "bundle", hash: ONE } }],
      blobs: [],
      bundles: [{
        kind: "bundle",
        hash: ONE,
        bytes: 9,
        path: `${BUNDLE_DIR}/${ONE}`,
      }],
      keep: [],
    },
    hash,
  );
  assertEquals(plan.objects.length, 0);
  assertEquals(plan.totalBytes, 0);
});

Deno.test("urlBase suppresses the default port and brackets IPv6", () => {
  assertEquals(
    urlBase("cdn.example.test", 443, "https"),
    "https://cdn.example.test",
  );
  assertEquals(
    urlBase("cdn.example.test", 8443, "https"),
    "https://cdn.example.test:8443",
  );
  assertEquals(urlBase("192.0.2.10", 80, "http"), "http://192.0.2.10");
  assertEquals(urlBase("2001:db8::1", 443, "https"), "https://[2001:db8::1]");
});

Deno.test("blobUrl and bundleUrl build public URLs", () => {
  assertEquals(
    blobUrl("https://cdn.example.test", { sha256: ONE, filename: "a" }),
    `https://cdn.example.test/${BLOB_DIR}/${ONE}/a`,
  );
  assertEquals(
    bundleUrl("https://cdn.example.test", ONE),
    `https://cdn.example.test/${BUNDLE_DIR}/${ONE}/`,
  );
});
