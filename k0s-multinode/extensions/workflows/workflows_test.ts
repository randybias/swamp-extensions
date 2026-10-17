/**
 * Structural tests for the k0s-multinode workflows.
 *
 * These assert the graph shape and secret discipline offline. `swamp workflow
 * validate` against the real model types needs the extension installed in a
 * scratch repo (it is unpublished), so it runs before the first live cell.
 *
 * @module
 */

import {
  assert,
  assertEquals,
  assertStringIncludes,
} from "jsr:@std/assert@1.0.19";

const read = (name: string) =>
  Deno.readTextFile(new URL(`./${name}/workflow.yaml`, import.meta.url));

Deno.test("create workflow installs the first controller before any token", async () => {
  const s = await read("k0s-multinode-create-cluster");
  assertStringIncludes(s, 'name: "@randybias/k0s-multinode-create-cluster"');
  assertStringIncludes(s, "type: model_method");
  assertEquals(s.includes("type: model\n"), false);
  assertStringIncludes(s, "vaults:\n  - k0s-multinode\n  - default");
  // The first controller is installed and waited for before the join job.
  assert(s.indexOf("install-first-controller") < s.indexOf("mint-"));
  assert(s.indexOf("wait-first-controller") < s.indexOf("name: join"));
  // One mint, install, wait and invalidate step per extra node.
  for (
    const step of [
      "mint-${{ self.node.name }}",
      "install-${{ self.node.name }}",
      "wait-${{ self.node.name }}",
      "invalidate-${{ self.node.name }}",
    ]
  ) {
    assertStringIncludes(s, `name: ${step}`);
  }
  // The invalidate runs whether or not the join succeeded.
  assertStringIncludes(s, "type: completed");
  // The token is read from the vault, never passed literally.
  assertStringIncludes(
    s,
    'join_token: ${{ vault.get("k0s-multinode", inputs.token_key_prefix + self.node.name) }}',
  );
  assertEquals(/BEGIN [A-Z ]*PRIVATE KEY/.test(s), false);
  // private_key is a vault reference, not a literal.
  assertStringIncludes(s, 'private_key: ${{ vault.get("k0s-multinode"');
});

Deno.test("create workflow touches the token vault by key, never a literal token", async () => {
  const s = await read("k0s-multinode-create-cluster");
  assertStringIncludes(
    s,
    "key: ${{ inputs.token_key_prefix + self.node.name }}",
  );
  // No step carries a bare token-shaped value.
  assertEquals(/\bjoin_token: [^$]/.test(s), false);
});
