/**
 * Entry-point contract tests for `@randybias/apt-cache`: the factory wiring and
 * the published method surface (actions, read-only and destructive markers).
 * Method behaviour is tested beside each `_lib/` module.
 *
 * @module
 */

import { assertEquals } from "jsr:@std/assert@1.0.19";
import { createModel, model } from "./apt_cache.ts";
import { deps, setDeps } from "./_lib/remote.ts";

Deno.test("createModel installs dependency overrides and returns the model", async () => {
  const resolveSecret = () => Promise.resolve("placeholder");
  const previous = setDeps({});
  try {
    assertEquals(createModel({ resolveSecret }).type, "@randybias/apt-cache");
    assertEquals(deps.resolveSecret, resolveSecret);
    assertEquals(await deps.resolveSecret?.("v", "k"), "placeholder");
  } finally {
    // Spread alone would keep the override when the previous deps had none.
    setDeps({ ...previous, resolveSecret: previous.resolveSecret });
  }
});

Deno.test("schema: empty globals; mutating methods are actions; read-only and destructive markers", () => {
  assertEquals(Object.keys(model.globalArguments.shape), []);
  for (
    const name of [
      "install_server",
      "apply_server",
      "remove_server",
      "configure_client",
      "unconfigure_client",
    ] as const
  ) {
    assertEquals(
      (model.methods[name] as { kind?: string }).kind,
      "action",
      name,
    );
  }
  for (
    const name of [
      "render_server",
      "get",
      "sync",
      "stats",
      "client_get",
    ] as const
  ) {
    assertEquals(
      (model.methods[name] as { kind?: string }).kind,
      undefined,
      name,
    );
    assertEquals(
      (model.methods[name].description as string).startsWith("READ-ONLY."),
      true,
      name,
    );
  }
  assertEquals(
    model.methods.remove_server.description.startsWith("DESTRUCTIVE."),
    true,
  );
});
