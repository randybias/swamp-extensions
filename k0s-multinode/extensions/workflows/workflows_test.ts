/**
 * Structural tests for the k0s-multinode workflows.
 *
 * The graph is also validated and run in a scratch swamp repo
 * (`swamp extension source add` + `swamp workflow validate`); these offline
 * checks guard the shape and the secret discipline in CI.
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

Deno.test("create workflow installs the first controller, then calls the join child", async () => {
  const s = await read("k0s-multinode-create-cluster");
  assertStringIncludes(s, 'name: "@randybias/k0s-multinode-create-cluster"');
  assertEquals(s.includes("type: model\n"), false);
  assertStringIncludes(s, "vaults:\n  - k0s-multinode\n  - default");
  // The first controller is installed and waited for before the join job.
  assert(
    s.indexOf("install-first-controller") < s.indexOf("name: join-controllers"),
  );
  assert(
    s.indexOf("wait-first-controller") < s.indexOf("name: join-controllers"),
  );
  // The join job calls the per-node child workflow once per node, ordered
  // controllers-first, with no mint/install steps of its own.
  assertStringIncludes(s, "type: workflow");
  assertStringIncludes(
    s,
    'workflowIdOrName: "@randybias/k0s-multinode-join-node"',
  );
  assertStringIncludes(s, "name: join-controller-${{ self.node.name }}");
  assertStringIncludes(s, "name: join-worker-${{ self.node.name }}");
  assertStringIncludes(s, 'n.role != "worker"');
  assertEquals(s.includes("methodName: mint_join_token"), false);
  assertEquals(/BEGIN [A-Z ]*PRIVATE KEY/.test(s), false);
  assertStringIncludes(s, 'private_key: ${{ vault.get("k0s-multinode"');
});

Deno.test("join child mints, installs, waits and invalidates on both failure paths", async () => {
  const s = await read("k0s-multinode-join-node");
  assertStringIncludes(s, 'name: "@randybias/k0s-multinode-join-node"');
  for (
    const step of ["mint", "install", "wait", "invalidate", "invalidate-failed"]
  ) {
    assertStringIncludes(s, `name: ${step}`);
  }
  // install depends on mint succeeded-only; wait on install succeeded-only.
  assertStringIncludes(s, "type: succeeded");
  // invalidate runs after the wait whether it succeeded or failed,
  // invalidate-failed runs when the install failed.
  assertStringIncludes(s, "type: completed");
  assertStringIncludes(s, "type: failed");
  // The token is read from the vault by a plain per-node key.
  assertStringIncludes(
    s,
    'join_token: ${{ vault.get("k0s-multinode", inputs.node.token_key) }}',
  );
  assertStringIncludes(s, "key: ${{ inputs.node.token_key }}");
  assertEquals(/\bjoin_token: [^$]/.test(s), false);
  assertEquals(/BEGIN [A-Z ]*PRIVATE KEY/.test(s), false);
});
