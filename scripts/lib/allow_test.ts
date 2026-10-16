import { assertEquals } from "jsr:@std/assert@1.0.13";
import { allowReason } from "./allow.ts";

Deno.test("marker with reason", () => {
  assertEquals(
    allowReason('x = "1.2.3.4"; // leak-allow(semver of upstream tool)'),
    "semver of upstream tool",
  );
});
Deno.test("marker without reason is not an allow", () => {
  assertEquals(allowReason("x // leak-allow()"), null);
  assertEquals(allowReason("x // leak-allow(   )"), null);
});
Deno.test("no marker", () => assertEquals(allowReason("plain"), null));
