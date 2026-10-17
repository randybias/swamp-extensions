import { assert, assertEquals, assertRejects } from "jsr:@std/assert@1.0.19";
import { K8sSecretError } from "./kubectl.ts";
import {
  isVaultKey,
  isVaultName,
  resolveDataFromVault,
  VAULT_NAME_RE,
} from "./vault.ts";

Deno.test("vault name and key grammar", () => {
  for (const ok of ["default", "app", "prod.vault", "team_1", "a-b"]) {
    assertEquals(isVaultName(ok), true, ok);
    assertEquals(isVaultKey(ok), true, ok);
  }
  for (
    const bad of ["", " leading", "has space", "a/b", "a;b", "x".repeat(129)]
  ) {
    assertEquals(isVaultName(bad), false, bad);
    assertEquals(isVaultKey(bad), false, bad);
  }
  assertEquals(VAULT_NAME_RE.test("default"), true);
});

Deno.test("resolveDataFromVault reads each ref through a plain {get,put} object", async () => {
  const asked: [string, string][] = [];
  const service = {
    get: (vault: string, key: string) => {
      asked.push([vault, key]);
      return Promise.resolve(`value-for-${key}`);
    },
    put: () => Promise.resolve(),
  };
  const data = await resolveDataFromVault(service, {
    password: { vault: "app", key: "db-password" },
    user: { vault: "app", key: "db-user" },
  });
  assertEquals(asked, [["app", "db-password"], ["app", "db-user"]]);
  assertEquals(data, {
    password: "value-for-db-password",
    user: "value-for-db-user",
  });
});

Deno.test("resolveDataFromVault allows an empty string value", async () => {
  const data = await resolveDataFromVault(
    { get: () => Promise.resolve("") },
    { empty: { vault: "app", key: "blank" } },
  );
  assertEquals(data, { empty: "" });
});

Deno.test("resolveDataFromVault fails with a fixed message naming vault and key", async () => {
  const leak = "placeholder-value-one";
  const call = (service: unknown) =>
    resolveDataFromVault(service as never, {
      password: { vault: "app", key: "db-password" },
    });
  // A failed lookup names the vault and key, never the value.
  for (
    const service of [
      { get: () => Promise.reject(new Error(leak)) },
      { get: () => Promise.resolve(undefined) },
      { get: () => Promise.resolve(42) },
    ]
  ) {
    const e = await assertRejects(() => call(service)) as K8sSecretError;
    assertEquals(e.code, "invalid_input");
    assert(e.message.includes("app") && e.message.includes("db-password"));
    assert(!e.message.includes(leak));
  }
  // A missing or wrong-shaped service is its own fixed error.
  for (
    const service of [
      undefined,
      () => ({ get: () => leak }),
      { put: () => Promise.resolve() },
    ]
  ) {
    const e = await assertRejects(() => call(service)) as K8sSecretError;
    assertEquals(e.code, "invalid_input");
    assert(e.message.includes("No vault service"));
    assert(!e.message.includes(leak));
  }
});

Deno.test("vault values never appear in a thrown error", async () => {
  const leak = "placeholder-value-two";
  const e = await assertRejects(() =>
    resolveDataFromVault(
      { get: () => Promise.reject(new Error(`boom ${leak}`)) },
      { k: { vault: "app", key: "db" } },
    )
  ) as K8sSecretError;
  assert(!e.message.includes(leak));
  assert(!e.message.includes("boom"));
});
