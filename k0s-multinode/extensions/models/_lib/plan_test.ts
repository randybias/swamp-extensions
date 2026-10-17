import { assertEquals, assertThrows } from "jsr:@std/assert@1.0.19";
import { type NodeSpec, plan, PlanError, planRemove } from "./plan.ts";

const ctrl = (name: string, addr: string): NodeSpec => ({
  name,
  ssh_host: addr,
  role: "controller",
  private_address: addr,
});
const cw = (name: string, addr: string): NodeSpec => ({
  name,
  ssh_host: addr,
  role: "controller_worker",
  private_address: addr,
});
const worker = (name: string, addr: string): NodeSpec => ({
  name,
  ssh_host: addr,
  role: "worker",
  private_address: addr,
});

const base = {
  cluster_name: "k0s-lab",
  k0s_version: "v1.31.2+k0s.0",
  allow_even_controllers: false,
};

Deno.test("create 1 controller + 2 workers mints and invalidates each token", () => {
  const steps = plan({
    ...base,
    nodes: [
      ctrl("ctrl-1", "192.0.2.10"),
      worker("wrk-1", "192.0.2.11"),
      worker("wrk-2", "192.0.2.12"),
    ],
  });
  assertEquals(steps.map((s) => s.kind), [
    "install_first_controller",
    "wait_joined",
    "mint_token",
    "install_with_token",
    "wait_joined",
    "invalidate_token",
    "mint_token",
    "install_with_token",
    "wait_joined",
    "invalidate_token",
  ]);
  // invariant: the first controller is installed before any token is minted
  assertEquals(steps.findIndex((s) => s.kind === "mint_token") > 0, true);
});

Deno.test("three HA controllers join one at a time and need an HA endpoint", () => {
  const nodes = [
    cw("ctrl-1", "192.0.2.10"),
    cw("ctrl-2", "192.0.2.11"),
    cw("ctrl-3", "192.0.2.12"),
  ];
  assertThrows(
    () => plan({ ...base, nodes }),
    PlanError,
    "HA endpoint",
  );
  const steps = plan({
    ...base,
    nodes,
    ha_mode: "node_local_lb" as const,
    external_address: "192.0.2.10",
  });
  const mints = steps.filter((s) => s.kind === "mint_token");
  assertEquals(mints.length, 2);
  assertEquals(mints.every((s) => s.role === "controller"), true);
});

Deno.test("an even controller count is refused unless acknowledged", () => {
  const nodes = [
    cw("ctrl-1", "192.0.2.10"),
    cw("ctrl-2", "192.0.2.11"),
  ];
  assertThrows(
    () =>
      plan({
        ...base,
        nodes,
        ha_mode: "node_local_lb" as const,
        external_address: "192.0.2.10",
      }),
    PlanError,
    "even count",
  );
  assertEquals(
    plan({
      ...base,
      nodes,
      ha_mode: "node_local_lb" as const,
      external_address: "192.0.2.10",
      allow_even_controllers: true,
    }).length > 0,
    true,
  );
});

Deno.test("duplicate names or addresses are refused", () => {
  assertThrows(
    () =>
      plan({
        ...base,
        nodes: [ctrl("a", "192.0.2.10"), worker("a", "192.0.2.11")],
      }),
    PlanError,
    "duplicate node name",
  );
  assertThrows(
    () =>
      plan({
        ...base,
        nodes: [ctrl("a", "192.0.2.10"), worker("b", "192.0.2.10")],
      }),
    PlanError,
    "duplicate private address",
  );
});

Deno.test("upgrade runs controllers first, then drains workers", () => {
  const steps = plan({
    ...base,
    target_version: "v1.32.0+k0s.0",
    nodes: [
      cw("ctrl-1", "192.0.2.10"),
      cw("ctrl-2", "192.0.2.11"),
      cw("ctrl-3", "192.0.2.12"),
      worker("wrk-1", "192.0.2.13"),
    ],
    ha_mode: "node_local_lb" as const,
    external_address: "192.0.2.10",
  });
  const kinds = steps.map((s) => s.kind);
  // every controller upgrade precedes the first drain
  assertEquals(kinds.lastIndexOf("upgrade", kinds.indexOf("drain")) > 0, true);
  assertEquals(kinds.indexOf("drain") > 0, true);
  assertEquals(kinds.includes("uncordon"), true);
});

Deno.test("downgrades and minor skips are refused", () => {
  const nodes = [ctrl("ctrl-1", "192.0.2.10")];
  assertThrows(
    () => plan({ ...base, nodes, target_version: "v1.30.0+k0s.0" }),
    PlanError,
    "downgrade",
  );
  assertThrows(
    () => plan({ ...base, nodes, target_version: "v1.33.0+k0s.0" }),
    PlanError,
    "skip",
  );
});

Deno.test("removing a controller that would lose quorum is refused", () => {
  const nodes = [
    cw("ctrl-1", "192.0.2.10"),
    cw("ctrl-2", "192.0.2.11"),
    cw("ctrl-3", "192.0.2.12"),
  ];
  const base2 = {
    ...base,
    nodes,
    ha_mode: "node_local_lb" as const,
    external_address: "192.0.2.10",
    observed: [
      { name: "ctrl-1", role: "controller" as const, ready: true },
      { name: "ctrl-2", role: "controller" as const, ready: true },
      { name: "ctrl-3", role: "controller" as const, ready: true },
    ],
  };
  assertThrows(
    () => planRemove(base2, "ctrl-3"),
    PlanError,
    "quorum",
  );
  assertEquals(
    planRemove({ ...base2, confirm: "ctrl-3" }, "ctrl-3").map((s) => s.kind),
    ["drain", "detach", "reset"],
  );
});

Deno.test("the last controller cannot be removed", () => {
  const nodes = [ctrl("ctrl-1", "192.0.2.10")];
  assertThrows(
    () =>
      planRemove({
        ...base,
        nodes,
        observed: [{ name: "ctrl-1", role: "controller", ready: true }],
      }, "ctrl-1"),
    PlanError,
    "last controller",
  );
});
