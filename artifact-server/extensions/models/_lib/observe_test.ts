import { assertEquals } from "jsr:@std/assert@1.0.19";
import { splitSections } from "./observe.ts";

Deno.test("splitSections routes lines to their marker section", () => {
  const out = splitSections(
    [
      "##VERSION",
      "1",
      "##SUMS",
      "aa  sha256/aa/a",
      "##REFS",
      "stable\tblob  " + "0".repeat(64),
      "##BLOBS",
      "aa/a\t3\t1.5",
      "##BUNDLES",
      "bb\t9\t2.5",
      "##END",
      "ignored",
    ].join("\n"),
  );
  assertEquals(out.version, "1");
  assertEquals(out.sums, ["aa  sha256/aa/a"]);
  assertEquals(out.refs, [`stable\tblob  ${"0".repeat(64)}`]);
  assertEquals(out.blobs, ["aa/a\t3\t1.5"]);
  assertEquals(out.bundles, ["bb\t9\t2.5"]);
});

Deno.test("splitSections ignores text before the first marker and CR line endings", () => {
  const out = splitSections("noise\r\n##VERSION\r\n2\r\n##END\r\n");
  assertEquals(out.version, "2");
  assertEquals(out.sums, []);
});

Deno.test("splitSections yields empty sections for empty output", () => {
  const out = splitSections("");
  assertEquals(out, {
    version: "",
    sums: [],
    refs: [],
    blobs: [],
    bundles: [],
  });
});
