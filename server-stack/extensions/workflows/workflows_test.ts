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

Deno.test("no path re-applies allow_ssh_from_anywhere after lockdown: the first firewall step reads the recorded exposure", async () => {
  const s = await read("server-stack-provision-host");
  assertEquals(s.includes("allow_ssh_from_anywhere: true"), false);
  const fw = stepText(s, "apply-firewall");
  assertStringIncludes(fw, "allow_ssh_from_anywhere: >-");
  assertStringIncludes(fw, "inputs.adopt");
  assertStringIncludes(fw, 'ssh_exposure == "management-only"');
  // Lockdown itself never opens SSH, and nothing else mentions the input.
  assertEquals(
    stepText(s, "lockdown").includes("allow_ssh_from_anywhere"),
    false,
  );
  assertEquals((s.match(/allow_ssh_from_anywhere/g) ?? []).length, 1);
});

Deno.test("every server-host step carries the provider server id as the record identity", async () => {
  const s = await read("server-stack-provision-host");
  const id =
    "identity: ${{ string(data.latest(inputs.server_model, inputs.hostname).attributes.id) }}";
  for (
    const step of [
      "apply-base",
      "apply-firewall",
      "commit-firewall",
      "lockdown",
      "inspect-lockdown",
      "commit-lockdown",
    ]
  ) {
    assertStringIncludes(stepText(s, step), id);
  }
});

Deno.test("teardown forgets the server-host records, only after the server is verifiably gone", async () => {
  const s = await read("server-stack-teardown-host");
  for (const step of ["forget-public-record", "forget-mesh-record"]) {
    const t = stepText(s, step);
    assertStringIncludes(t, "methodName: forget");
    assertStringIncludes(
      t,
      "- step: check-cherry\n            condition:\n              type: succeeded\n",
    );
    assertEquals(t.includes("skipped"), false);
    assertStringIncludes(
      t,
      "identity: ${{ string(data.latest(inputs.server_model, inputs.hostname).attributes.id) }}",
    );
  }
  assertStringIncludes(
    stepText(s, "forget-mesh-record"),
    'inputs.mesh_address.split("/")[0]',
  );
});

Deno.test("DNS inputs are optional while publish_dns is false, and required when it is true", async () => {
  for (
    const name of ["server-stack-provision-host", "server-stack-teardown-host"]
  ) {
    const s = await read(name);
    const required = s.slice(
      s.indexOf("  required:"),
      s.indexOf("  properties:"),
    );
    for (
      const k of [
        "cloudflare_token_key",
        "cloudflare_zone_id",
        "dns_record_name",
      ]
    ) {
      assertEquals(required.includes(`- ${k}`), false, `${name} ${k}`);
    }
    const first = stepText(s, "check-inputs");
    assertStringIncludes(first, 'inputs.cloudflare_zone_id != ""');
    assertStringIncludes(first, 'inputs.dns_record_name != ""');
    assertStringIncludes(first, 'inputs.cloudflare_token_key != ""');
  }
});

Deno.test("known_hosts lines may omit the host field: the mesh mapping reads the last two fields", async () => {
  const s = await read("server-stack-provision-host");
  assertEquals(s.includes('line.split(" ")[1]'), false);
  for (const step of ["join-mesh", "verify-mesh"]) {
    assertStringIncludes(
      stepText(s, step),
      'line.split(" ")[size(line.split(" ")) - 2]',
    );
  }
});

Deno.test("check-mesh waits a bounded time for the first handshake and cannot be bypassed by a failed join", async () => {
  const s = await read("server-stack-provision-host");
  const wait = stepText(s, "wait-mesh");
  assertStringIncludes(wait, "guard: ${{ inputs.mesh_handshake_wait_s == 0 }}");
  assertStringIncludes(
    wait,
    "timeout: ${{ (inputs.mesh_handshake_wait_s + 15) * 1000 }}",
  );
  assertStringIncludes(wait, "ignoreExitCode: true");
  // Skipping the wait is allowed; skipping past a failed join is not.
  const verify = stepText(s, "verify-mesh");
  assertStringIncludes(
    verify,
    "- step: join-mesh\n            condition:\n              type: succeeded\n",
  );
  assertStringIncludes(verify, "- step: wait-mesh");
  // The assertion stays the gate.
  assertStringIncludes(
    stepText(s, "check-mesh"),
    "message: No mesh peer handshake was recorded",
  );
});

Deno.test("NATS auth is off by default: its steps are guarded and the plain probe is the unchanged one", async () => {
  const s = await read("server-stack-provision-host");
  assertStringIncludes(
    s,
    "    nats_auth_token_key:\n      type: string",
  );
  assertStringIncludes(s, "      default: null\n      maxLength: 256");
  assertStringIncludes(
    stepText(s, "apply-nats-auth"),
    "guard: ${{ inputs.nats_auth_token_key == null }}",
  );
  assertStringIncludes(
    stepText(s, "probe-nats-auth"),
    "guard: ${{ inputs.nats_auth_token_key == null }}",
  );
  const plain = stepText(s, "probe-nats");
  assertStringIncludes(
    plain,
    "guard: ${{ inputs.nats_auth_token_key != null }}",
  );
  assertEquals(plain.includes("NATS_TOKEN"), false);
});

Deno.test("the NATS token travels as a vault value in an environment variable or a Secret, never in a script or argv", async () => {
  const s = await read("server-stack-provision-host");
  const probe = stepText(s, "probe-nats-auth");
  assertStringIncludes(
    probe,
    'NATS_TOKEN: ${{ vault.get("server-stack", inputs.nats_auth_token_key) }}',
  );
  const run = probe.slice(probe.indexOf("run: |"), probe.indexOf("env:"));
  assertEquals(run.includes("vault.get"), false);
  assertStringIncludes(
    stepText(s, "apply-nats-auth"),
    'token: ${{ vault.get("server-stack", inputs.nats_auth_token_key) }}',
  );
  for (const step of ["apply-nats", "apply-nats-after-secrets"]) {
    assertStringIncludes(
      stepText(s, step),
      "- step: apply-nats-auth\n            condition:\n              type: or\n",
    );
  }
});

Deno.test("with auth on, check-nats requires an authenticated session and a refused anonymous one", async () => {
  const s = await read("server-stack-provision-host");
  const check = stepText(s, "check-nats");
  for (
    const need of [
      '\\"auth_required\\":true',
      '\\n+OK"',
      "Authorization Violation",
    ]
  ) {
    assertStringIncludes(check, need);
  }
});
