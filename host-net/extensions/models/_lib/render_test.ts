import { assertEquals } from "jsr:@std/assert@1.0.19";
import {
  renderConfig,
  renderNetplanYaml,
  renderNetworkdFiles,
} from "./render.ts";
import type { NetConfig } from "./validate.ts";

const CFG: NetConfig = {
  backend: "netplan",
  bridgeType: "linux",
  mode: "additive",
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

Deno.test("golden netplan: linux bridge on a VLAN at MTU 9000", () => {
  assertEquals(
    renderNetplanYaml(CFG),
    `network:
  version: 2
  renderer: networkd
  ethernets:
    enp1s0:
      mtu: 9000
  vlans:
    enp1s0.100:
      id: 100
      link: enp1s0
      mtu: 9000
      addresses:
        - 198.51.100.10/24
      accept-ra: false
      optional: true
  bridges:
    br0:
      interfaces:
        - enp1s0.100
      mtu: 9000
`,
  );
});

Deno.test("golden netplan: OVS bridge renders openvswitch", () => {
  const yaml = renderNetplanYaml({ ...CFG, bridgeType: "ovs" });
  assertEquals(yaml.includes("      openvswitch: {}"), true);
  assertEquals(yaml.includes("parameters:"), false);
});

Deno.test("golden netplan: takeover writes the cloud-init drop-in", async () => {
  const render = await renderConfig({ ...CFG, mode: "takeover" });
  const paths = render.files.map((f) => f.path);
  assertEquals(
    paths.includes("/etc/cloud/cloud.cfg.d/99-disable-network-config.cfg"),
    true,
  );
  const dropIn = render.files.find((f) =>
    f.path.endsWith("99-disable-network-config.cfg")
  )!;
  assertEquals(dropIn.content, "network: {config: disabled}\n");
  assertEquals(dropIn.mode, "0644");
  const netplan = render.files.find((f) =>
    f.path.endsWith("90-host-net.yaml")
  )!;
  assertEquals(netplan.mode, "0600");
});

Deno.test("networkd backend renders the prefixed file set with optional flags", () => {
  const files = renderNetworkdFiles(CFG);
  const byPath = new Map(files.map((f) => [f.path, f.content]));
  assertEquals(
    byPath.has("/etc/systemd/network/90-host-net-enp1s0.100.netdev"),
    true,
  );
  assertEquals(byPath.has("/etc/systemd/network/90-host-net-br0.netdev"), true);
  const vlan = byPath.get(
    "/etc/systemd/network/90-host-net-enp1s0.100.network",
  )!;
  assertEquals(vlan.includes("Address=198.51.100.10/24"), true);
  assertEquals(vlan.includes("RequiredForOnline=no"), true);
  assertEquals(vlan.includes("Bridge=br0"), true);
  const eth = byPath.get("/etc/systemd/network/90-host-net-enp1s0.network")!;
  assertEquals(eth.includes("VLAN=enp1s0.100"), true);
});

Deno.test("rendering is byte-stable and the sha256 is the config identity", async () => {
  const a = await renderConfig(CFG);
  const b = await renderConfig(CFG);
  assertEquals(a.sha256, b.sha256);
  const reordered = await renderConfig({
    ...CFG,
    ethernets: [{ name: "enp1s0", mtu: 9000 }],
    vlans: [...CFG.vlans],
  });
  assertEquals(reordered.sha256, a.sha256);
});

Deno.test("created devices are only the virtual ones", async () => {
  const render = await renderConfig(CFG);
  assertEquals(render.created, ["enp1s0.100", "br0"]);
  assertEquals(render.managed, ["enp1s0", "enp1s0.100", "br0"]);
});
