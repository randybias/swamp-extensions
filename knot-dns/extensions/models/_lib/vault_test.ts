import { assert, assertEquals, assertRejects } from "jsr:@std/assert@1.0.19";
import { KnotError, resolveSecret } from "./vault.ts";

Deno.test("resolveSecret reads a plain {get,put} object", async () => {
  const asked: [string, string][] = [];
  const service = {
    get: (v: string, k: string) => {
      asked.push([v, k]);
      return Promise.resolve("secret-value");
    },
    put: () => Promise.resolve(),
  };
  assertEquals(
    await resolveSecret(service, { vault: "app", key: "k" }),
    "secret-value",
  );
  assertEquals(asked, [["app", "k"]]);
});

Deno.test("resolveSecret fails with a fixed message and never echoes a value", async () => {
  const leak = "placeholder-value";
  const cases: unknown[] = [
    undefined,
    () => ({ get: () => Promise.resolve(leak) }),
    { put: () => Promise.resolve() },
    { get: () => Promise.reject(new Error(leak)) },
    { get: () => Promise.resolve("") },
  ];
  for (const service of cases) {
    const e = await assertRejects(() =>
      resolveSecret(service as never, { vault: "app", key: "db" })
    ) as KnotError;
    assert(e instanceof KnotError);
    assert(!e.message.includes(leak));
  }
});
