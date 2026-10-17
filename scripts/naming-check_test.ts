import { assertEquals } from "jsr:@std/assert@1.0.13";
import { checkExtension, type ExtInfo, lintName } from "./naming-check.ts";

const LOGBOOK = "# Maintainer logbook\n\nvisibility: public\naudience: general\n";
const base = (over: Partial<ExtInfo> = {}): ExtInfo => ({
  ext: "acme-dns",
  release: { visibility: "public", audience: "general" },
  manifestName: "@randybias/acme-dns",
  workflows: [],
  logbook: LOGBOOK,
  ...over,
});
const failed = (info: ExtInfo, deny: string[] = []) =>
  checkExtension(info, deny).filter((f) => !f.waived).map((f) => f.rule);

Deno.test("a clean public extension passes", () => {
  assertEquals(failed(base()), []);
});

Deno.test("missing visibility and audience fail", () => {
  assertEquals(failed(base({ release: {}, logbook: undefined })), [
    "visibility",
    "audience",
    "logbook",
  ]);
  assertEquals(failed(base({ release: undefined, logbook: undefined })), [
    "release",
    "visibility",
    "audience",
    "logbook",
  ]);
});

Deno.test("inconsistent pair fails", () => {
  assertEquals(failed(base({ release: { visibility: "public", audience: "personal" } })), [
    "audience",
    "logbook",
  ]);
});

Deno.test("a private extension in the public repo fails", () => {
  const info = base({
    ext: "ops1-kea-dhcp-lab",
    manifestName: "@randybias/ops1-kea-dhcp-lab",
    manifestVisibility: "private",
    release: { visibility: "private", audience: "personal" },
    logbook: "visibility: private\naudience: personal\n",
  });
  assertEquals(failed(info), ["private-in-public-repo"]);
});

Deno.test("server-stack's waiver is the only one, and is still reported", () => {
  const info = base({
    ext: "server-stack",
    manifestName: "@randybias/server-stack",
    release: { visibility: "private", audience: "personal" },
    workflows: ["@randybias/server-stack-provision-host"],
  });
  const all = checkExtension(info, []);
  assertEquals(all.filter((f) => !f.waived), []);
  assertEquals(all.map((f) => f.rule).sort(), ["manifest-visibility", "private-in-public-repo"]);
});

Deno.test("banned nouns fail for a new public name", () => {
  for (const n of ["foo-stack", "stack", "kea-tools", "ops-server"]) {
    assertEquals(failed(base({ ext: n, manifestName: `@randybias/${n}` })), ["name"], n);
  }
  assertEquals(failed(base({ ext: "ssh-host", manifestName: "@randybias/ssh-host" })), []);
});

Deno.test("charset, version, date and length rules", () => {
  assertEquals(lintName("kea-dhcp"), []);
  assertEquals(lintName("k0s-cluster"), []);
  assertEquals(lintName("kea--dhcp").length, 1);
  assertEquals(lintName("Kea-dhcp").length, 1);
  assertEquals(lintName("kea-dhcp-v2").length, 1);
  assertEquals(lintName("kea-2026").length, 1);
  assertEquals(
    failed(base({ ext: "a-b-c-d", manifestName: "@randybias/a-b-c-d" })),
    ["name"],
  );
});

Deno.test("manifest name must match the dir and the collective", () => {
  assertEquals(failed(base({ manifestName: "@bogworks/acme-dns" })), ["collective"]);
  assertEquals(failed(base({ manifestName: "@randybias/acme" })), ["name"]);
});

Deno.test("denylist hits in names fail", () => {
  assertEquals(failed(base(), ["acme"]), ["denylist"]);
  assertEquals(
    failed(base({ workflows: ["@randybias/acme-dns-apply-secretlab"] }), ["secretlab"]),
    ["denylist"],
  );
});

Deno.test("workflow names: prefix, verb, segments, exceptions", () => {
  const wf = (w: string) => failed(base({ workflows: [`@randybias/${w}`] }));
  assertEquals(wf("acme-dns-apply-config"), []);
  assertEquals(wf("other-apply-config"), ["workflow", "workflow"]);
  assertEquals(wf("acme-dns-frob-config"), ["workflow"]);
  assertEquals(wf("acme-dns-apply-a-b-c"), ["workflow"]);
  assertEquals(
    failed(base({
      ext: "cephadm",
      manifestName: "@randybias/cephadm",
      workflows: ["@randybias/cephadm-add-host"],
    })),
    [],
  );
});

Deno.test("LOGBOOK must carry literal visibility and audience lines", () => {
  assertEquals(failed(base({ logbook: "# Maintainer logbook\n" })), ["logbook", "logbook"]);
  assertEquals(failed(base({ logbook: undefined })), ["logbook"]);
  assertEquals(failed(base({ logbook: "visibility: private\naudience: general\n" })), ["logbook"]);
});
