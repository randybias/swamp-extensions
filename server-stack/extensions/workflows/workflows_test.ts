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

/** The text of one step, from its `- name:` line to the next step. */
function stepText(s: string, name: string): string {
  const a = s.indexOf(`      - name: ${name}\n`);
  assert(a >= 0, name);
  const b = s.indexOf("\n      - name: ", a + 1);
  return s.slice(a, b < 0 ? undefined : b);
}

Deno.test("both firewall steps pass the trusted interfaces, so a k0s node's pods are not cut off", async () => {
  const s = await read("server-stack-provision-host");
  assertStringIncludes(s, "    trusted_interfaces:\n      type: array");
  assertStringIncludes(s, "default: [kube-bridge]");
  for (const step of ["apply-firewall", "lockdown"]) {
    assertStringIncludes(
      stepText(s, step),
      "trusted_interfaces: ${{ inputs.trusted_interfaces }}",
    );
  }
});

Deno.test("the API address is the mesh address for install, kubeconfig and the chart, and the kubeconfig is checked against it", async () => {
  const s = await read("server-stack-provision-host");
  const api = 'api_address: ${{ inputs.mesh_node.address.split("/")[0] }}';
  for (const step of ["install-k0s", "kubeconfig", "apply-nats"]) {
    assertStringIncludes(stepText(s, step), api);
  }
  // The stored record masks the host (`https://***:6443`), so the check can only
  // assert a server URL exists; the step's log line shows the mesh URL.
  assertStringIncludes(stepText(s, "check-kubeconfig"), 'endsWith(":6443")');
});

Deno.test("the NATS probe passes its port as a string and its timeout in milliseconds", async () => {
  const s = await read("server-stack-provision-host");
  const probe = stepText(s, "probe-nats");
  assertStringIncludes(
    probe,
    "NATS_PORT: ${{ string(inputs.nats_probe_port) }}",
  );
  assertStringIncludes(probe, "timeout: ${{ inputs.verify_timeout_s * 1000 }}");
});

Deno.test("apply-nats never waits on the forEach secrets step when there are no secrets", async () => {
  const s = await read("server-stack-provision-host");
  const plain = stepText(s, "apply-nats");
  assertEquals(plain.includes("step: apply-secrets"), false);
  assertStringIncludes(plain, "guard: ${{ size(inputs.cluster_secrets) > 0 }}");
  // With secrets the chart waits for them to have succeeded, and for nothing weaker.
  const after = stepText(s, "apply-nats-after-secrets");
  assertStringIncludes(
    after,
    "guard: ${{ size(inputs.cluster_secrets) == 0 }}",
  );
  assertStringIncludes(
    after,
    "- step: apply-secrets\n            condition:\n              type: succeeded\n",
  );
});
