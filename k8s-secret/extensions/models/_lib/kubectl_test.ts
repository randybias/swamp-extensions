import { assertEquals, assertRejects } from "jsr:@std/assert@1.0.19";
import {
  b64,
  b64ToBytes,
  buildManifest,
  classify,
  hashData,
  hashObserved,
  isContext,
  isDataKey,
  isNamespace,
  isSecretName,
  scrub,
  sha256HexBytes,
  unb64,
  withKubectl,
} from "./kubectl.ts";

const T = { kubeconfig: "kc", namespace: "app", name: "s" };

Deno.test("base64 round-trips UTF-8", () => {
  assertEquals(unb64(b64("héllo\n")), "héllo\n");
});

Deno.test("manifest carries base64 data and no plaintext", () => {
  const m = buildManifest(T, "Opaque", { k: "plain-value" });
  assertEquals(m.includes("plain-value"), false);
  assertEquals(JSON.parse(m).data.k, b64("plain-value"));
});

Deno.test("hashData is stable and order independent", async () => {
  const a = await hashData({ a: "1", b: "2" });
  const b = await hashData({ b: "2", a: "1" });
  assertEquals(a.total, b.total);
  assertEquals((await hashData({ a: "1", b: "3" })).total === a.total, false);
});

Deno.test("hashObserved hashes raw bytes, not a lossy decode", async () => {
  // A UTF-8 value hashes the same as the desired value's UTF-8 bytes.
  assertEquals(
    (await hashObserved({ k: b64("héllo") })).keys.k,
    (await hashData({ k: "héllo" })).keys.k,
  );
  // 0xff cannot be decoded as UTF-8; hashing the stored bytes is correct.
  const raw = b64ToBytes("/w==");
  assertEquals(raw, Uint8Array.of(0xff));
  assertEquals(
    (await hashObserved({ k: "/w==" })).keys.k,
    await sha256HexBytes(raw),
  );
  // The lossy decode replaces 0xff with U+FFFD, a different digest.
  assertEquals(
    (await hashObserved({ k: "/w==" })).keys.k ===
      (await hashData({ k: unb64("/w==") })).keys.k,
    false,
  );
});

Deno.test("grammars", () => {
  assertEquals(isNamespace("a-b"), true);
  assertEquals(isNamespace("A"), false);
  assertEquals(isNamespace("a".repeat(64)), false);
  assertEquals(isSecretName("a.b-c"), true);
  assertEquals(isSecretName("a..b"), false);
  assertEquals(isDataKey(".dockerconfigjson"), true);
  assertEquals(isDataKey("."), false);
  assertEquals(isContext("kind-test"), true);
  assertEquals(isContext("-x"), false);
});

Deno.test("scrub redacts and classify names the namespace", () => {
  assertEquals(scrub("a secret-x b", ["secret-x"]), "a [redacted] b");
  const e = classify(
    'namespaces "zz" not found',
    { ...T, namespace: "zz" },
    [],
  );
  assertEquals(e.code, "namespace_not_found");
});

Deno.test("withKubectl removes the file when fn throws", async () => {
  const removed: string[] = [];
  await assertRejects(() =>
    withKubectl(
      {
        run: () => Promise.resolve({ code: 0, stdout: "", stderr: "" }),
        files: {
          write: () => Promise.resolve("/p"),
          remove: (p) => {
            removed.push(p);
            return Promise.resolve();
          },
        },
        now: () => new Date(),
      },
      T,
      [],
      () => Promise.reject(new Error("x")),
    )
  );
  assertEquals(removed, ["/p"]);
});

Deno.test("default file writer makes a 0600 file and removes it", async () => {
  const { defaultDeps } = await import("./kubectl.ts");
  const d = defaultDeps();
  const p = await d.files.write("x");
  assertEquals((await Deno.stat(p)).mode! & 0o777, 0o600);
  await d.files.remove(p);
  await d.files.remove(p);
  await assertRejects(() => Deno.stat(p));
});
