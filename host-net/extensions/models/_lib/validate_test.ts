import { assertEquals, assertThrows } from "jsr:@std/assert@1.0.19";
import {
  assertIface,
  assertMac,
  assertMtu,
  assertNoManagementOverlap,
  assertVlanId,
  cidrOverlaps,
  deviceGraph,
  HostNetConfigError,
  isIface,
  type NetConfig,
  parseCidr,
  validateConfig,
  vlanName,
} from "./validate.ts";

Deno.test("interface names follow IFNAMSIZ and reject separators", () => {
  for (const good of ["eth0", "enp1s0", "br0", "vlan.100", "bond_0"]) {
    assertEquals(isIface(good), true, good);
    assertIface(good);
  }
  for (const bad of ["", "-lead", "a/b", "a:b", "a b", "..", "x".repeat(16)]) {
    assertThrows(() => assertIface(bad), HostNetConfigError, undefined, bad);
  }
});

Deno.test("MAC must be lowercase and unicast", () => {
  assertMac("02:00:00:00:00:01");
  assertThrows(() => assertMac("02:00:00:00:00:0"), HostNetConfigError);
  assertThrows(() => assertMac("01:00:00:00:00:01"), HostNetConfigError); // leak-allow(multicast rejection test)
  assertThrows(() => assertMac("02:00:00:00:00:0G"), HostNetConfigError);
});

Deno.test("VLAN id and MTU bounds", () => {
  assertVlanId(1);
  assertVlanId(4094);
  for (const bad of [0, 4095, -1, 1.5]) {
    assertThrows(() => assertVlanId(bad), HostNetConfigError);
  }
  assertMtu(1280);
  assertMtu(9216);
  for (const bad of [1279, 9217, 9000.5]) {
    assertThrows(() => assertMtu(bad), HostNetConfigError);
  }
});

Deno.test("CIDR parsing is strict and refuses prefix zero and metacharacters", () => {
  const cidr = parseCidr("198.51.100.10/24");
  assertEquals(cidr.family, 4);
  assertEquals(cidr.prefix, 24);
  assertEquals(parseCidr("2001:db8:10::10/64").family, 6);
  for (
    const bad of [
      "198.51.100.10/0",
      "198.51.100.10",
      "198.51.100.10/33",
      "2001:db8::1/129",
      "198.51.100.10/24;id",
      "198.51.100.10/24`id`",
      "198.51.100.10/24\nroot",
    ]
  ) {
    assertThrows(() => parseCidr(bad), HostNetConfigError, undefined, bad);
  }
});

Deno.test("CIDR overlap is symmetric", () => {
  assertEquals(
    cidrOverlaps(parseCidr("198.51.100.0/24"), parseCidr("198.51.100.5/32")),
    true,
  );
  assertEquals(
    cidrOverlaps(parseCidr("198.51.100.0/24"), parseCidr("192.0.2.0/24")),
    false,
  );
  assertEquals(
    cidrOverlaps(parseCidr("2001:db8::/32"), parseCidr("2001:db8:1::/48")),
    true,
  );
});

const BASE: NetConfig = {
  backend: "netplan",
  bridgeType: "linux",
  mode: "additive",
  managementChangeAck: false,
  managementInterface: "eno1",
  ethernets: [{ name: "enp1s0", mtu: 9000 }],
  vlans: [{
    id: 100,
    link: "enp1s0",
    mtu: 9000,
    addresses: ["198.51.100.10/24"],
    optional: true,
  }],
};

Deno.test("validateConfig accepts a matching chain and rejects a broken MTU chain", () => {
  validateConfig(BASE);
  const bad: NetConfig = {
    ...BASE,
    vlans: [{
      id: 100,
      link: "enp1s0",
      mtu: 9216,
      addresses: ["198.51.100.10/24"],
      optional: true,
    }],
  };
  assertThrows(
    () => validateConfig(bad),
    HostNetConfigError,
    "exceeds link MTU",
  );
  const bridgeBad: NetConfig = {
    ...BASE,
    bridge: {
      name: "br0",
      interfaces: [vlanName(BASE.vlans[0])],
      mtu: 9216,
      addresses: [],
    },
  };
  assertThrows(
    () => validateConfig(bridgeBad),
    HostNetConfigError,
    "smallest port MTU",
  );
});

Deno.test("validateConfig rejects duplicate names, unknown links and networkd+ovs", () => {
  assertThrows(
    () =>
      validateConfig({ ...BASE, vlans: [BASE.vlans[0], { ...BASE.vlans[0] }] }),
    HostNetConfigError,
  );
  assertThrows(
    () =>
      validateConfig({
        ...BASE,
        vlans: [{
          id: 100,
          link: "eno9",
          addresses: ["198.51.100.10/24"],
          optional: true,
        }],
      }),
    HostNetConfigError,
    "not a declared ethernet",
  );
  assertThrows(
    () => validateConfig({ ...BASE, backend: "networkd", bridgeType: "ovs" }),
    HostNetConfigError,
    "linux bridges",
  );
});

Deno.test("management overlap is refused", () => {
  assertThrows(
    () => assertNoManagementOverlap(["198.51.100.0/24"], ["198.51.100.1/24"]),
    HostNetConfigError,
  );
  assertNoManagementOverlap(["198.51.100.0/24"], ["192.0.2.0/24"]);
});

Deno.test("deviceGraph orders ethernets, VLANs then the bridge", () => {
  const graph = deviceGraph({
    ...BASE,
    bridge: { name: "br0", interfaces: ["enp1s0"], mtu: 9000, addresses: [] },
  });
  assertEquals(graph.map((n) => n.kind), ["ethernet", "vlan", "bridge"]);
  assertEquals(graph.map((n) => n.name), ["enp1s0", "enp1s0.100", "br0"]);
});

Deno.test("the management interface is protected unless takeover is acknowledged", () => {
  const withMgmtBridge: NetConfig = {
    ...BASE,
    managementInterface: "enp1s0",
    bridge: { name: "br0", interfaces: ["enp1s0"], mtu: 9000, addresses: [] },
  };
  assertThrows(
    () => validateConfig(withMgmtBridge),
    HostNetConfigError,
    "management interface",
  );
  validateConfig({
    ...withMgmtBridge,
    mode: "takeover",
    managementChangeAck: true,
  });
});
