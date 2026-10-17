import {
  assert,
  assertEquals,
  assertStringIncludes,
} from "jsr:@std/assert@1.0.19";

const read = (name: string) =>
  Deno.readTextFile(new URL(`./${name}/workflow.yaml`, import.meta.url));

Deno.test("provision workflow is schema-shaped and carries no secret", async () => {
  const s = await read("server-stack-provision-host");
  assertStringIncludes(s, 'name: "@randybias/server-stack-provision-host"');
  assertStringIncludes(s, "type: model_method");
  assertEquals(s.includes("type: model\n"), false);
  assertStringIncludes(s, "vaults:\n  - server-stack");
  for (
    const step of [
      "check-inputs",
      "probe-server",
      "check-cloudflare-token",
      "apply-base",
      "join-mesh",
      "apply-firewall",
      "lockdown",
      "install-k0s",
      "kubeconfig",
      "apply-secrets",
      "apply-nats",
      "probe-nats",
      "create-record",
      "check-record",
    ]
  ) {
    assertStringIncludes(s, `name: ${step}`);
  }
  assertEquals(/BEGIN [A-Z ]*PRIVATE KEY/.test(s), false);
  assertEquals(/insecure_tofu/.test(s), false);
});

Deno.test("teardown removes DNS and resets k0s before deleting the server", async () => {
  const s = await read("server-stack-teardown-host");
  assertStringIncludes(s, 'name: "@randybias/server-stack-teardown-host"');
  assert(s.indexOf("name: delete-record") < s.indexOf("name: delete-server"));
  assert(s.indexOf("name: reset-k0s") < s.indexOf("name: delete-server"));
  assert(s.indexOf("name: verify-cherry") < s.indexOf("name: verify-dns"));
  assertEquals(/BEGIN [A-Z ]*PRIVATE KEY/.test(s), false);
});
