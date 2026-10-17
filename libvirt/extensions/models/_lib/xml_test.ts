import { assertEquals } from "jsr:@std/assert@1.0.19";
import {
  domainState,
  isOffState,
  isPausedState,
  isRunningState,
  memoryMib,
  networkProjection,
  parseKeyValues,
  parseNameList,
  parseVolList,
  renderDomainXml,
  renderNetworkXml,
} from "./xml.ts";

Deno.test("network xml: deterministic nat with a dhcp range", () => {
  const xml = renderNetworkXml({
    name: "net-a",
    mode: "nat",
    gateway: "192.0.2.1",
    prefix: 24,
    dhcpStart: "192.0.2.10",
    dhcpEnd: "192.0.2.99",
  });
  assertEquals(
    xml,
    `<network>
  <name>net-a</name>
  <forward mode='nat'/>
  <bridge name='virbr-net-a'/>
  <ip address='192.0.2.1' prefix='24'>
    <dhcp>
      <range start='192.0.2.10' end='192.0.2.99'/>
    </dhcp>
  </ip>
</network>
`,
  );
});

Deno.test("network xml: bridge mode carries the requested bridge", () => {
  const xml = renderNetworkXml({
    name: "net-b",
    mode: "bridge",
    bridge: "br0",
  });
  assertEquals(xml.includes("<bridge name='br0'/>"), true);
  assertEquals(xml.includes("<forward mode='bridge'/>"), true);
  assertEquals(xml.includes("<ip "), false);
});

Deno.test("domain xml: boots from a pool volume, carries a pty console", () => {
  const xml = renderDomainXml({
    name: "node-a",
    pool: "pool-a",
    volume: "node-a-root",
    vcpus: 2,
    memoryMib: 2048,
    format: "qcow2",
    arch: "x86_64",
    network: "net-a",
    mac: "02:00:00:00:00:01",
  });
  assertEquals(xml.startsWith("<domain type='kvm'>"), true);
  assertEquals(
    xml.includes("<source pool='pool-a' volume='node-a-root'/>"),
    true,
  );
  assertEquals(xml.includes("<interface type='network'>"), true);
  assertEquals(xml.includes("<source network='net-a'/>"), true);
  assertEquals(xml.includes("<mac address='02:00:00:00:00:01'/>"), true);
  assertEquals(xml.includes("<serial type='pty'>"), true);
  assertEquals(xml.includes("<console type='pty'>"), true);
  assertEquals(xml.includes(`<memory unit='MiB'>2048</memory>`), true);
});

Deno.test("projection: re-render and reformatted dumpxml compare equal", () => {
  const rendered = renderNetworkXml({
    name: "net-a",
    mode: "nat",
    gateway: "192.0.2.1",
    prefix: 24,
    dhcpStart: "192.0.2.10",
    dhcpEnd: "192.0.2.99",
  });
  const dumpxml = `<network>
    <name>net-a</name>
    <forward mode="nat"/>
    <bridge name="virbr-net-a"/>
    <ip prefix="24" address="192.0.2.1">
      <dhcp>
        <range end="192.0.2.99" start="192.0.2.10"/>
      </dhcp>
    </ip>
</network>`;
  assertEquals(networkProjection(rendered), networkProjection(dumpxml));
});

Deno.test("projection: a changed field is detected", () => {
  const a = renderNetworkXml({
    name: "net-a",
    mode: "nat",
    gateway: "192.0.2.1",
    prefix: 24,
  });
  const b = renderNetworkXml({
    name: "net-a",
    mode: "route",
    gateway: "192.0.2.1",
    prefix: 24,
  });
  assertEquals(networkProjection(a) === networkProjection(b), false);
});

Deno.test("parsers: key-values, name lists and volume lists", () => {
  const kv = parseKeyValues(
    "Name:          default\nUUID:          abc\nActive:        yes\nMax memory:    2097152 KiB\nState:          running\n",
  );
  assertEquals(kv["name"], "default");
  assertEquals(kv["active"], "yes");
  assertEquals(kv["max memory"], "2097152 KiB");
  assertEquals(memoryMib(kv), 2048);
  assertEquals(parseNameList("\nnet-a\n\nnet-b\n"), ["net-a", "net-b"]);
  assertEquals(
    parseVolList(`
 Name                 Path
--------------------------------------------
 node-a-root         /var/lib/libvirt/images/node-a-root.qcow2
 golden              /var/lib/libvirt/images/golden.qcow2
`),
    [
      {
        name: "node-a-root",
        path: "/var/lib/libvirt/images/node-a-root.qcow2",
      },
      { name: "golden", path: "/var/lib/libvirt/images/golden.qcow2" },
    ],
  );
});

Deno.test("state helpers: running, paused and off", () => {
  assertEquals(domainState({ state: "Running" }), "running");
  assertEquals(isRunningState("running"), true);
  assertEquals(isRunningState("shut off"), false);
  assertEquals(isPausedState("paused"), true);
  assertEquals(isOffState("shut off"), true);
  assertEquals(isOffState("crashed"), true);
  assertEquals(isOffState("running"), false);
});
