import { assertEquals, assertThrows } from "jsr:@std/assert@1.0.19";
import {
  managementCidrs,
  parseAddrs,
  parseDefaultRoute,
  parseLinks,
  parseRouteGet,
  probeCommands,
} from "./probe.ts";
import { HostNetConfigError } from "./validate.ts";

Deno.test("parseLinks reads MTU, kind, VLAN id and master", () => {
  const links = parseLinks(JSON.stringify([
    {
      ifname: "enp1s0",
      mtu: 9000,
      operstate: "UP",
      linkinfo: { info_kind: "ether" },
    },
    {
      ifname: "enp1s0.100",
      mtu: 9000,
      operstate: "UP",
      master: "br0",
      linkinfo: { info_kind: "vlan", info_data: { id: 100 } },
    },
  ]));
  assertEquals(links[0].kind, "ether");
  assertEquals(links[1].vlanId, 100);
  assertEquals(links[1].master, "br0");
});

Deno.test("a truncated probe is rejected, never treated as empty", () => {
  assertThrows(() => parseLinks("not json"), HostNetConfigError);
  assertThrows(() => parseAddrs("{}"), HostNetConfigError);
  assertThrows(() => parseDefaultRoute("["), HostNetConfigError);
});

Deno.test("parseAddrs and managementCidrs", () => {
  const addrs = parseAddrs(JSON.stringify([
    {
      ifname: "enp1s0",
      addr_info: [{ family: "inet", local: "192.0.2.10", prefixlen: 24 }],
    },
    {
      ifname: "enp1s0",
      addr_info: [{ family: "inet6", local: "2001:db8::10", prefixlen: 64 }],
    },
  ]));
  assertEquals(addrs.length, 2);
  assertEquals(managementCidrs(addrs, "enp1s0"), ["192.0.2.10/24"]);
});

Deno.test("parseDefaultRoute and parseRouteGet", () => {
  assertEquals(
    parseDefaultRoute(
      JSON.stringify([{
        dst: "default",
        gateway: "192.0.2.1",
        dev: "enp1s0",
        metric: 100,
      }]),
    ),
    "default via 192.0.2.1 dev enp1s0 metric 100",
  );
  assertEquals(parseRouteGet(JSON.stringify([{ dev: "enp1s0" }])), "enp1s0");
});

Deno.test("the probe discovers management from SSH_CONNECTION without brace expansion", () => {
  const cmds = probeCommands();
  const get = cmds.find((c) => c[0] === "sh" && c[2].includes("route get"));
  assertEquals(get !== undefined, true);
  assertEquals(get![2].includes("SSH_CONNECTION"), true);
});
