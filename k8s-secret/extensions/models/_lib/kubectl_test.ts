import { assert, assertEquals, assertRejects } from "jsr:@std/assert@1.0.19";
import {
  b64,
  b64ToBytes,
  buildManifest,
  classify,
  fieldManager,
  hashData,
  hashObserved,
  isContext,
  isDataKey,
  isNamespace,
  isSecretName,
  K8sSecretError,
  ownedDataKeys,
  sha256HexBytes,
  unb64,
  withKubectl,
  writePrivateTempFile,
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
  assertEquals(a, b);
  const c = await hashData({ a: "1", b: "3" });
  assertEquals(c.a, a.a);
  assertEquals(c.b === a.b, false);
});

Deno.test("hashObserved hashes raw bytes, not a lossy decode", async () => {
  // A UTF-8 value hashes the same as the desired value's UTF-8 bytes.
  assertEquals(
    (await hashObserved({ k: b64("héllo") })).k,
    (await hashData({ k: "héllo" })).k,
  );
  // 0xff cannot be decoded as UTF-8; hashing the stored bytes is correct.
  const raw = b64ToBytes("/w==");
  assertEquals(raw, Uint8Array.of(0xff));
  assertEquals(
    (await hashObserved({ k: "/w==" })).k,
    await sha256HexBytes(raw),
  );
  // The lossy decode replaces 0xff with U+FFFD, a different digest.
  assertEquals(
    (await hashObserved({ k: "/w==" })).k ===
      (await hashData({ k: unb64("/w==") })).k,
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

Deno.test("fieldManager is stable per definition and distinct across them", async () => {
  const a = await fieldManager("db-secret");
  assertEquals(a, await fieldManager("db-secret"));
  assert(a.startsWith("swamp-k8s-secret-"));
  assert(a !== await fieldManager("other-secret"));
});

Deno.test("ownedDataKeys reads only this manager's applied data keys", () => {
  const manager = "swamp-k8s-secret-abc123def456";
  const entries = [
    {
      manager,
      operation: "Apply",
      fieldsV1: { "f:data": { "f:password": {}, "f:user": {} } },
    },
    {
      manager: "other-tool",
      operation: "Apply",
      fieldsV1: { "f:data": { "f:extra": {} } },
    },
    {
      manager,
      operation: "Update",
      fieldsV1: { "f:data": { "f:ignored": {} } },
    },
  ];
  assertEquals(ownedDataKeys(entries, manager), ["password", "user"]);
  assertEquals(ownedDataKeys(undefined, manager), []);
});

Deno.test("classify returns fixed messages that never echo stderr", () => {
  const value = "hunter2";
  const encoded = b64(value);
  const leaky =
    `Error from server: data.password value ${value} (${encoded}) is invalid`;
  const e = classify(leaky, T);
  assertEquals(e.code, "kubectl_failed");
  assert(!e.message.includes(value));
  assert(!e.message.includes(encoded));
  assert(!e.message.includes("Error from server"));
  const ns = classify('namespaces "zz" not found', { ...T, namespace: "zz" });
  assertEquals(ns.code, "namespace_not_found");
  assert(ns.message.includes("zz"));
  assertEquals(
    classify("Unable to connect to the server: dial tcp", T).code,
    "unreachable",
  );
  assertEquals(
    classify("Error from server (Forbidden): secrets is forbidden", T).code,
    "unauthorized",
  );
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
      () => Promise.reject(new Error("x")),
    )
  );
  assertEquals(removed, ["/p"]);
});

Deno.test("withKubectl never surfaces a runner exception", async () => {
  const deps = {
    run: () => Promise.reject(new Error("boom secret-value-x")),
    files: {
      write: () => Promise.resolve("/p"),
      remove: () => Promise.resolve(),
    },
    now: () => new Date(),
  };
  try {
    await withKubectl(deps, T, (kubectl) => kubectl([]));
    throw new Error("expected a rejection");
  } catch (e) {
    assert(e instanceof K8sSecretError);
    assertEquals((e as K8sSecretError).code, "kubectl_failed");
    assert(!(e as Error).message.includes("secret-value-x"));
    assert(!(e as Error).message.includes("boom"));
  }
});

Deno.test("writePrivateTempFile removes the file when a later step fails", async () => {
  for (const failAt of ["chmod", "writeText"]) {
    const removed: string[] = [];
    const io = {
      makeTempFile: () => Promise.resolve("/tmp/kc-fail"),
      chmod: () =>
        failAt === "chmod"
          ? Promise.reject(new Error("chmod failed"))
          : Promise.resolve(),
      writeText: () =>
        failAt === "writeText"
          ? Promise.reject(new Error("write failed"))
          : Promise.resolve(),
      remove: (p: string) => {
        removed.push(p);
        return Promise.resolve();
      },
    };
    await assertRejects(() => writePrivateTempFile("x", io));
    assertEquals(removed, ["/tmp/kc-fail"]);
  }
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
