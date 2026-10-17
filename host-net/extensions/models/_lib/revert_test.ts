import { assertEquals, assertThrows } from "jsr:@std/assert@1.0.19";
import {
  renderMarker,
  renderRestoreScript,
  type RevertContext,
  revertDir,
} from "./revert.ts";

const CTX: RevertContext = {
  token: "0000000000000000",
  backend: "netplan",
  bridgeType: "ovs",
  created: ["enp1s0.100", "br0"],
  createdBridges: ["br0"],
  managedFiles: ["/etc/netplan/90-host-net.yaml"],
};

Deno.test("the restore deletes only the created devices and never flushes OVS", () => {
  const script = renderRestoreScript(CTX);
  assertEquals(script.includes('ip link delete dev "$dev"'), true);
  assertEquals(script.includes(`for dev in 'enp1s0.100' 'br0'`), true);
  assertEquals(script.includes('ovs-vsctl --if-exists del-br "$br"'), true);
  assertEquals(script.includes(`for br in 'br0'`), true);
  // It must never restore or flush the whole database.
  assertEquals(script.includes("ovsdb-client"), false);
  assertEquals(script.includes("del-br --all"), false);
  assertEquals(script.includes("ip link delete dev enp1s0"), false);
});

Deno.test("the restore is token-guarded and never reboots", () => {
  const script = renderRestoreScript(CTX);
  assertEquals(script.includes("superseded"), true);
  assertEquals(script.includes("flock -n 9"), true);
  assertEquals(script.includes("systemctl reboot"), false);
  assertEquals(script.includes("shutdown -r"), false);
  assertEquals(script.includes("fired_at"), true);
});

Deno.test("marker round-trips and rejects a bad token", () => {
  const marker = {
    token: CTX.token,
    armed_at: 1,
    expires_at: 2,
    armed_sha256: "a".repeat(64),
    created: CTX.created,
    result: "pending" as const,
    fired_at: null,
  };
  assertEquals(JSON.parse(renderMarker(marker)).token, CTX.token);
  assertThrows(() => revertDir("../etc"), Error);
  assertThrows(() => renderMarker({ ...marker, token: "short" }), Error);
});

Deno.test("networkd restore removes only the managed prefix and restores the snapshot", () => {
  const script = renderRestoreScript({
    ...CTX,
    backend: "networkd",
    bridgeType: "linux",
    createdBridges: [],
  });
  assertEquals(script.includes("90-host-net-*"), true);
  assertEquals(script.includes("networkctl reload"), true);
  assertEquals(script.includes("netplan apply"), false);
});
