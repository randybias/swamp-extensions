import { assertEquals, assertThrows } from "jsr:@std/assert@1.0.19";
import {
  assertArmBeforeApply,
  mtuLowerOrder,
  mtuRaiseOrder,
  planApply,
  planRemove,
  type Step,
} from "./plan.ts";
import type { NetConfig } from "./validate.ts";

const CFG: NetConfig = {
  backend: "netplan",
  bridgeType: "linux",
  mode: "additive",
  managementChangeAck: false,
  managementInterface: "enp1s0",
  ethernets: [{ name: "enp1s0", mtu: 9000 }],
  vlans: [{
    id: 100,
    link: "enp1s0",
    mtu: 9000,
    addresses: ["198.51.100.10/24"],
    optional: true,
  }],
  bridge: { name: "br0", interfaces: ["enp1s0.100"], mtu: 9000, addresses: [] },
};

Deno.test("MTU raise is parent-first; lower is child-first", () => {
  // Only existing parents are raised before apply; created devices get their
  // MTU from the renderer.
  assertEquals(mtuRaiseOrder(CFG).map((n) => n.name), ["enp1s0"]);
  assertEquals(mtuLowerOrder(CFG).map((n) => n.name), ["enp1s0"]);
});

Deno.test("arm precedes every mtu/write/apply step", () => {
  const steps = planApply(CFG, {
    token: "0000000000000000",
    revertAfterS: 300,
    writtenPaths: ["/etc/netplan/90-host-net.yaml"],
  });
  assertArmBeforeApply(steps);
  const armAt = steps.findIndex((s) => s.kind === "arm");
  for (const kind of ["mtu", "write", "apply"] as const) {
    const at = steps.findIndex((s) => s.kind === kind);
    assertEquals(at > armAt, true, `${kind} after arm`);
  }
  const remove = planRemove(CFG);
  assertArmBeforeApply(remove);
});

Deno.test("a plan with the arm moved after the apply fails the invariant", () => {
  const steps: Step[] = [
    { kind: "apply", id: "apply-config", description: "apply" },
    { kind: "arm", id: "arm", description: "arm" },
  ];
  assertThrows(() => assertArmBeforeApply(steps), Error, "precedes the arm");
  const stageAsArm: Step[] = [
    { kind: "stage", id: "arm", description: "stage pretending to be arm" },
    { kind: "mtu", id: "mtu", description: "raise" },
  ];
  assertThrows(() => assertArmBeforeApply(stageAsArm), Error);
});
