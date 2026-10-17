import { assertEquals } from "jsr:@std/assert@1.0.19";
import { mapScriptError } from "./errors.ts";

Deno.test("a missing tool is a tool_missing error, not the tool's verdict", () => {
  for (
    const [stderr, exit, mention] of [
      ["KZONECHECK_MISSING\n", 3, "kzonecheck"],
      ["KRESCTL_MISSING\n", 3, "kresctl"],
      ["TOOL_MISSING kzonecheck\n", 127, "kzonecheck"],
      ["sh: 1: kzonecheck: not found\n", 127, "tool"],
    ] as const
  ) {
    const e = mapScriptError(stderr, exit);
    assertEquals(e.code, "tool_missing", stderr);
    assertEquals(e.message.includes(mention), true, e.message);
  }
});

Deno.test("a rejected zone is still reported as the tool's verdict", () => {
  assertEquals(mapScriptError("KZONECHECK_FAILED\n", 4).code, "tool_failed");
});

Deno.test("repository and version problems are typed and carry no remote text", () => {
  assertEquals(mapScriptError("KEY_MISMATCH\n", 12).code, "invalid_input");
  assertEquals(
    mapScriptError("UNEXPECTED_VERSION knot knotc 4.0.0\n", 13).code,
    "verify_failed",
  );
  assertEquals(
    mapScriptError("UNEXPECTED_VERSION knot knotc 4.0.0\n", 13)
      .message.includes("4.0.0"),
    false,
  );
});
