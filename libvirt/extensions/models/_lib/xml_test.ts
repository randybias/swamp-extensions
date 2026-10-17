import { assertEquals, assertThrows } from "jsr:@std/assert@1.0.19";
import { LibvirtConfigError } from "./validate.ts";
import {
  defaultBridgeName,
  domainState,
  isOffState,
  isPausedState,
  isRunningState,
  memoryMib,
  networkProjection,
  parseBlkListDetails,
  parseDomainDisks,
  parseKeyValues,
  parseNameList,
  parseVolList,
  parseVolumeFormat,
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
  <bridge name='${defaultBridgeName("net-a")}'/>
  <ip address='192.0.2.1' prefix='24'>
    <dhcp>
      <range start='192.0.2.10' end='192.0.2.99'/>
    </dhcp>
  </ip>
</network>
`,
  );
});

Deno.test("network xml: the default bridge is short and deterministic", () => {
  const name = "e2e-longnet-x";
  const bridge = defaultBridgeName(name);
  assertEquals(bridge.length <= 15, true);
  assertEquals(/^vb-[0-9a-f]{8}$/.test(bridge), true);
  assertEquals(defaultBridgeName(name), bridge);
  const xml = renderNetworkXml({ name, mode: "nat", gateway: "192.0.2.1" });
  assertEquals(xml.includes(`<bridge name='${bridge}'/>`), true);
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

Deno.test("domain xml: boots from a resolved file, carries ACPI and a pty console", () => {
  const xml = renderDomainXml({
    name: "node-a",
    vcpus: 2,
    memoryMib: 2048,
    arch: "x86_64",
    disks: [{
      path: "/var/lib/libvirt/e2e-pool/node-a-root.qcow2",
      format: "qcow2",
      target: "vda",
      bus: "virtio",
      device: "disk",
      readonly: false,
    }],
    network: "net-a",
    mac: "02:00:00:00:00:01",
  });
  assertEquals(xml.startsWith("<domain type='kvm'>"), true);
  assertEquals(xml.includes("<disk type='file' device='disk'>"), true);
  assertEquals(
    xml.includes(
      "<source file='/var/lib/libvirt/e2e-pool/node-a-root.qcow2'/>",
    ),
    true,
  );
  assertEquals(xml.includes("<source pool="), false);
  assertEquals(xml.includes("<features>"), true);
  assertEquals(xml.includes("<acpi/>"), true);
  assertEquals(xml.includes("<apic/>"), true);
  assertEquals(xml.includes("<interface type='network'>"), true);
  assertEquals(xml.includes("<source network='net-a'/>"), true);
  assertEquals(xml.includes("<mac address='02:00:00:00:00:01'/>"), true);
  assertEquals(xml.includes("<serial type='pty'>"), true);
  assertEquals(xml.includes("<console type='pty'>"), true);
  assertEquals(xml.includes(`<memory unit='MiB'>2048</memory>`), true);
});

Deno.test("domain xml: a read-only cdrom seed is attached", () => {
  const xml = renderDomainXml({
    name: "node-a",
    vcpus: 1,
    memoryMib: 1024,
    arch: "x86_64",
    disks: [
      {
        path: "/pool/root.qcow2",
        format: "qcow2",
        target: "vda",
        bus: "virtio",
        device: "disk",
        readonly: false,
      },
      {
        path: "/pool/seed.iso",
        format: "raw",
        target: "sda",
        bus: "sata",
        device: "cdrom",
        readonly: true,
      },
    ],
  });
  assertEquals(xml.includes("<disk type='file' device='cdrom'>"), true);
  assertEquals(xml.includes("<source file='/pool/seed.iso'/>"), true);
  assertEquals(xml.includes("<target dev='sda' bus='sata'/>"), true);
  assertEquals(xml.includes("<readonly/>"), true);
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
    <bridge name="${defaultBridgeName("net-a")}"/>
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

Deno.test("domain xml: an unaccepted arch is refused", () => {
  assertThrows(
    () =>
      renderDomainXml({
        name: "node-a",
        vcpus: 2,
        memoryMib: 2048,
        arch: "x86_64'> <script/>",
        disks: [{
          path: "/pool/root.qcow2",
          format: "qcow2",
          target: "vda",
          bus: "virtio",
          device: "disk",
          readonly: false,
        }],
      }),
    LibvirtConfigError,
  );
});

Deno.test("parseDomainDisks: single- and double-quoted disk XML", () => {
  const rendered = renderDomainXml({
    name: "node-a",
    vcpus: 1,
    memoryMib: 1024,
    arch: "x86_64",
    disks: [
      {
        path: "/pool/root.qcow2",
        format: "qcow2",
        target: "vda",
        bus: "virtio",
        device: "disk",
        readonly: false,
      },
      {
        path: "/pool/seed.iso",
        format: "raw",
        target: "sda",
        bus: "sata",
        device: "cdrom",
        readonly: true,
      },
    ],
  });
  assertEquals(parseDomainDisks(rendered), [
    { device: "disk", path: "/pool/root.qcow2", readonly: false },
    { device: "cdrom", path: "/pool/seed.iso", readonly: true },
  ]);
  const dumpxml = `<domain><devices>
    <disk type="file" device="disk"><source file="/p/root.qcow2"/></disk>
    <disk type="file" device="cdrom"><source file="/p/seed.iso"/><readonly/></disk>
  </devices></domain>`;
  assertEquals(parseDomainDisks(dumpxml).length, 2);
  assertEquals(parseDomainDisks(dumpxml)[1].readonly, true);
});

Deno.test("parseBlkListDetails and parseVolumeFormat read virsh output", () => {
  assertEquals(
    parseBlkListDetails(
      ` Type   Device   Target   Source
-----------------------------------------------
 file   disk     vda      /pool/root.qcow2
 file   cdrom    sda      /pool/seed.iso
`,
    ),
    [
      {
        type: "file",
        device: "disk",
        target: "vda",
        source: "/pool/root.qcow2",
      },
      {
        type: "file",
        device: "cdrom",
        target: "sda",
        source: "/pool/seed.iso",
      },
    ],
  );
  assertEquals(
    parseVolumeFormat(
      `<volume type='file'><target><format type='qcow2'/></target></volume>`,
    ),
    "qcow2",
  );
  assertEquals(
    parseVolumeFormat(`<volume><format type="raw"/></volume>`),
    "raw",
  );
  assertEquals(parseVolumeFormat("<volume/>"), "");
});

Deno.test("network xml: a dns domain with a quote is refused", () => {
  assertThrows(
    () =>
      renderNetworkXml({
        name: "net-a",
        mode: "nat",
        gateway: "192.0.2.1",
        prefix: 24,
        dhcpStart: "192.0.2.10",
        dhcpEnd: "192.0.2.99",
        domain: "a'b",
      }),
    LibvirtConfigError,
  );
});

Deno.test("network xml: the dns domain is a top-level <network> child", () => {
  const xml = renderNetworkXml({
    name: "net-a",
    mode: "nat",
    gateway: "192.0.2.1",
    prefix: 24,
    dhcpStart: "192.0.2.10",
    dhcpEnd: "192.0.2.99",
    domain: "example.test",
  });
  assertEquals(
    xml.includes("<domain name='example.test' localOnly='yes'/>"),
    true,
  );
  assertEquals(/<dhcp>[\s\S]*?<domain /.test(xml), false);
  assertEquals(xml.includes("<bootp/>"), false);
});

Deno.test("projection: a commented-out <name> does not win", () => {
  const xml =
    `<!-- <name>wrong</name> -->\n<network><name>net-a</name></network>`;
  assertEquals(
    JSON.parse(networkProjection(xml)).name,
    "net-a",
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

Deno.test("domain xml: an unaccepted disk format is refused", () => {
  assertThrows(
    () =>
      renderDomainXml({
        name: "node-a",
        vcpus: 1,
        memoryMib: 1024,
        arch: "x86_64",
        disks: [{
          path: "/p/root.qcow2",
          format: "vmdk" as unknown as "qcow2",
          target: "vda",
          bus: "virtio",
          device: "disk",
          readonly: false,
        }],
      }),
    LibvirtConfigError,
  );
});
