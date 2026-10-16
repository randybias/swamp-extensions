import { assertEquals, assertRejects } from "jsr:@std/assert@1.0.13";
import { loadDenylist, scanText } from "./leak-scan.ts";

Deno.test("denylist from env, comments and blanks dropped, lowercased", async () => {
  assertEquals(await loadDenylist("# c\n\nAcmeCorp\nlab-7\n", "/nonexistent"), [
    "acmecorp",
    "lab-7",
  ]);
});

Deno.test("empty or comment-only denylist fails closed", async () => {
  await assertRejects(() => loadDenylist("# only comments\n\n", "/nonexistent"));
  await assertRejects(() => loadDenylist("", "/nonexistent"));
  await assertRejects(() => loadDenylist(undefined, "/nonexistent"));
});

Deno.test("denylist hit is reported by index, never by term", () => {
  assertEquals(scanText("README.md", "Built at ACMECORP", ["foo", "acmecorp"], true), [
    "README.md:1 denylist <denylisted:1>",
  ]);
});

Deno.test("leak-allow does not exempt a denylisted term", () => {
  assertEquals(scanText("a.ts", "acmecorp // leak-allow(reason)", ["acmecorp"], true).length, 1);
});

Deno.test("private address anywhere, documentation address fine", () => {
  assertEquals(scanText("LOGBOOK.md", "ran on 10.20.30.40 and 192.0.2.5", ["zzz"], false), [
    "LOGBOOK.md:1 private-address 10.20.30.40",
  ]);
});

Deno.test("foreign email flagged, example and trailer emails fine", () => {
  assertEquals(
    scanText(
      "a.ts",
      "ops@realcorp.io admin@example.com x@host.test noreply@anthropic.com",
      ["zzz"],
      true,
    ),
    ["a.ts:1 email ops@realcorp.io"],
  );
});

Deno.test("npm and jsr specifiers are not emails", () => {
  assertEquals(
    scanText("a.ts", 'import "npm:zod@4.1.12"; "jsr:@std/assert@1.0.13"', ["zzz"], true),
    [],
  );
});

Deno.test("unresolvable references only in packaged files", () => {
  const t = "per the spec\nTODO: later\nsee section 6\nD21 applies\n";
  assertEquals(scanText("README.md", t, ["zzz"], true).length, 4);
  assertEquals(scanText("LOGBOOK.md", t, ["zzz"], false), []);
});

Deno.test("leak-allow exempts non-denylist classes", () => {
  assertEquals(
    scanText("README.md", "TODO // leak-allow(literal word in example)", ["zzz"], true),
    [],
  );
});

Deno.test("private IPv6 flagged", () => {
  assertEquals(scanText("README.md", "host fd12::1234", ["zzz"], true), [
    "README.md:1 private-address fd12::1234",
  ]);
});

Deno.test("a reference finding never echoes the line", () => {
  const out = scanText("README.md", "TODO acmecorp", ["acmecorp"], true);
  assertEquals(out, ["README.md:1 denylist <denylisted:0>", "README.md:1 reference rule:3"]);
});

Deno.test("a denylisted term in the path is a finding, and redacted", () => {
  assertEquals(scanText("fixtures/acmecorp-out.txt", "x 10.0.0.1", ["acmecorp"], false), [
    "fixtures/<denylisted:0>-out.txt:0 denylist-path <denylisted:0>",
    "fixtures/<denylisted:0>-out.txt:1 private-address 10.0.0.1",
  ]);
});

Deno.test("a clean file with a denylisted path is still a finding", () => {
  assertEquals(scanText("models/acmecorp-notes.md", "nothing here", ["acmecorp"], true).length, 1);
});

Deno.test("a denylisted term inside an email detail is redacted", () => {
  assertEquals(scanText("a.ts", "ops@acmecorp.io", ["acmecorp"], true), [
    "a.ts:1 denylist <denylisted:0>",
    "a.ts:1 email ops@<denylisted:0>.io",
  ]);
});
