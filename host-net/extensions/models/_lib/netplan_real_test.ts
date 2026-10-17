/**
 * Runs every netplan render through the REAL netplan parser
 * (`netplan generate --root-dir <scratch root>`) when netplan is installed.
 * String goldens never ran netplan, which is how a keyless ethernet rendered as
 * a null mapping that netplan 1.1 rejects. Without netplan the cases are
 * reported as ignored, visibly, rather than passing.
 */
import { assert, assertEquals } from "jsr:@std/assert@1.0.19";
import { renderConfig } from "./render.ts";
import type { NetConfig } from "./validate.ts";

async function sh(
  script: string,
  args: string[] = [],
): Promise<{ code: number; stdout: string; stderr: string } | null> {
  try {
    const out = await new Deno.Command("sh", {
      args: ["-c", script, "sh", ...args],
      stdout: "piped",
      stderr: "piped",
    }).output();
    return {
      code: out.code,
      stdout: new TextDecoder().decode(out.stdout),
      stderr: new TextDecoder().decode(out.stderr),
    };
  } catch {
    return null; // no permission to start sh
  }
}

const HAVE_NETPLAN = (await sh("command -v netplan >/dev/null"))?.code === 0;

const BASE: NetConfig = {
  backend: "netplan",
  bridgeType: "linux",
  mode: "additive",
  managementChangeAck: false,
  managementInterface: "enp7s0",
  ethernets: [{ name: "enp7s0" }],
  vlans: [],
};

const VLAN = (link: string, id = 100, extra: object = {}) => ({
  id,
  link,
  addresses: ["198.51.100.10/24"],
  optional: true,
  ...extra,
});

const CASES: [string, NetConfig][] = [
  // The management NIC also carries the provider VLAN 2429 on the real host;
  // that VLAN lives in another file, so ours only adds the storage VLAN.
  ["a keyless ethernet with a VLAN on it", {
    ...BASE,
    vlans: [VLAN("enp7s0")],
  }],
  ["a VLAN at MTU 9000 on a keyless ethernet", {
    ...BASE,
    vlans: [VLAN("enp7s0", 100, { mtu: 9000 })],
  }],
  ["a NIC with only an MTU (takeover)", {
    ...BASE,
    mode: "takeover",
    managementChangeAck: true,
    ethernets: [{ name: "enp7s0", mtu: 9000 }],
  }],
  ["a NIC with no carrier next to the managed one", {
    ...BASE,
    ethernets: [{ name: "enp7s0" }, { name: "eno1" }, { name: "eno2" }],
    vlans: [VLAN("enp7s0")],
  }],
  ["a NIC matched by MAC", {
    ...BASE,
    ethernets: [{ name: "storage0", matchMac: "02:00:00:00:00:07", mtu: 9000 }],
    vlans: [VLAN("storage0")],
  }],
  ["a Linux bridge on a VLAN", {
    ...BASE,
    vlans: [VLAN("enp7s0", 100, { mtu: 9000 })],
    bridge: {
      name: "br0",
      interfaces: ["enp7s0.100"],
      mtu: 9000,
      addresses: [],
    },
  }],
  ["a Linux bridge with addresses and STP", {
    ...BASE,
    ethernets: [{ name: "enp7s0" }, { name: "eno1" }],
    bridge: {
      name: "br0",
      interfaces: ["eno1"],
      addresses: ["198.51.100.30/24"],
      stp: false,
    },
  }],
  ["two VLANs on one NIC", {
    ...BASE,
    vlans: [
      VLAN("enp7s0", 100),
      VLAN("enp7s0", 200, {
        addresses: ["198.51.100.20/24"],
      }),
    ],
  }],
];

for (const [name, cfg] of CASES) {
  Deno.test({
    name: `real netplan accepts: ${name}`,
    ignore: !HAVE_NETPLAN,
    fn: async () => {
      const render = await renderConfig(cfg);
      const root = await Deno.makeTempDir({ prefix: "netplan-real-" });
      try {
        for (const file of render.files) {
          const path = `${root}${file.path}`;
          await Deno.mkdir(path.slice(0, path.lastIndexOf("/")), {
            recursive: true,
          });
          await Deno.writeTextFile(path, file.content);
          await Deno.chmod(path, 0o600);
        }
        const netplanFiles = render.files.filter((f) =>
          f.path.startsWith("/etc/netplan/")
        );
        assert(netplanFiles.length > 0, "the render has a netplan file");
        const res = await sh(
          'netplan generate --root-dir "$1" 2>&1',
          [root],
        );
        assert(res !== null, "sh could not be started");
        // netplan reports a rejected definition on stderr/stdout and exits
        // non-zero (older versions exit 0 with the message), so check both.
        assertEquals(res.code, 0, res.stdout + res.stderr);
        assertEquals(
          /Error in network definition|expected mapping|is not defined/.test(
            res.stdout + res.stderr,
          ),
          false,
          res.stdout + res.stderr,
        );
      } finally {
        await Deno.remove(root, { recursive: true });
      }
    },
  });
}

Deno.test({
  name: "the real parser does reject a bare (null) ethernet",
  ignore: !HAVE_NETPLAN,
  fn: async () => {
    // Guards the test itself: if netplan stopped complaining about the old
    // output, the cases above would prove nothing.
    const root = await Deno.makeTempDir({ prefix: "netplan-real-" });
    try {
      await Deno.mkdir(`${root}/etc/netplan`, { recursive: true });
      const path = `${root}/etc/netplan/90-host-net.yaml`;
      await Deno.writeTextFile(
        path,
        'network:\n  version: 2\n  renderer: networkd\n  ethernets:\n    "enp7s0":\n  vlans:\n    "enp7s0.100":\n      id: 100\n      link: "enp7s0"\n      addresses:\n        - "198.51.100.10/24"\n',
      );
      await Deno.chmod(path, 0o600);
      const res = await sh('netplan generate --root-dir "$1" 2>&1', [root]);
      assert(res !== null);
      assertEquals(
        /expected mapping/.test(res.stdout + res.stderr),
        true,
        res.stdout + res.stderr,
      );
    } finally {
      await Deno.remove(root, { recursive: true });
    }
  },
});

Deno.test("an ethernet with no settings renders as an empty mapping", async () => {
  const render = await renderConfig({ ...BASE, vlans: [VLAN("enp7s0")] });
  const yaml = render.files[0].content;
  assert(yaml.includes('    "enp7s0": {}\n'));
  assertEquals(/"enp7s0":\n/.test(yaml), false);
});

const CLOUD_INIT = `network:
  version: 2
  ethernets:
    enp7s0:
      dhcp4: true
      match:
        macaddress: "02:00:00:00:00:07"
      set-name: enp7s0
  vlans:
    enp7s0.2429:
      id: 2429
      link: enp7s0
      addresses:
        - "203.0.113.5/29"
`;

async function generate(
  files: Record<string, string>,
): Promise<{ code: number; out: string }> {
  const root = await Deno.makeTempDir({ prefix: "netplan-real-" });
  try {
    await Deno.mkdir(`${root}/etc/netplan`, { recursive: true });
    for (const [name, content] of Object.entries(files)) {
      const path = `${root}/etc/netplan/${name}`;
      await Deno.writeTextFile(path, content);
      await Deno.chmod(path, 0o600);
    }
    const res = await sh('netplan generate --root-dir "$1" 2>&1', [root]);
    assert(res !== null, "sh could not be started");
    return { code: res.code, out: res.stdout + res.stderr };
  } finally {
    await Deno.remove(root, { recursive: true });
  }
}

Deno.test({
  name:
    "real netplan, two files: a VLAN on a NIC defined by cloud-init needs the merged config",
  ignore: !HAVE_NETPLAN,
  fn: async () => {
    // Our file declares only the VLAN; the NIC is cloud-init's. The management
    // interface may be a VLAN link without being declared by us.
    const render = await renderConfig({
      ...BASE,
      ethernets: [],
      vlans: [VLAN("enp7s0", 3011)],
    });
    const ours = render.files.find((f) =>
      f.path === "/etc/netplan/90-host-net.yaml"
    )!;
    assertEquals(ours.content.includes("ethernets:"), false);
    // Staged alone (what the pre-check used to do) the parser rejects it ...
    const alone = await generate({ "90-host-net.yaml": ours.content });
    assertEquals(/is not defined/.test(alone.out), true, alone.out);
    // ... staged with the live directory's files, as now, it is accepted.
    const merged = await generate({
      "50-cloud-init.yaml": CLOUD_INIT,
      "90-host-net.yaml": ours.content,
    });
    assertEquals(merged.code, 0, merged.out);
    assertEquals(
      /Error in network definition|is not defined/.test(merged.out),
      false,
      merged.out,
    );
  },
});

Deno.test({
  name:
    "real netplan, two files: a declared (empty) NIC merges with cloud-init's definition",
  ignore: !HAVE_NETPLAN,
  fn: async () => {
    const render = await renderConfig({
      ...BASE,
      vlans: [VLAN("enp7s0", 3011)],
    });
    const ours = render.files[0].content;
    assert(ours.includes('"enp7s0": {}'));
    const merged = await generate({
      "50-cloud-init.yaml": CLOUD_INIT,
      "90-host-net.yaml": ours,
    });
    assertEquals(merged.code, 0, merged.out);
    assertEquals(/Error in network definition/.test(merged.out), false);
  },
});
