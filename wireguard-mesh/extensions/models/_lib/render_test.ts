import { assertEquals, assertThrows } from "jsr:@std/assert@1.0.19";
import {
  fullMesh,
  HUB,
  hubSelf,
  hubSpoke,
  key,
  S1,
  S2,
  S3,
} from "./fixtures.ts";
import {
  isEndpoint,
  KeySchema,
  MeshError,
  MeshSchema,
  PeerNotAllowedError,
  renderMesh,
} from "./render.ts";

const golden = async (name: string, actual: string) => {
  const path = new URL(`./testdata/${name}.conf`, import.meta.url);
  if (Deno.env.get("UPDATE_GOLDEN")) await Deno.writeTextFile(path, actual);
  assertEquals(actual, await Deno.readTextFile(path), name);
};

Deno.test("golden: hub-and-spoke spoke peers only with the relay", async () => {
  const r = renderMesh(hubSpoke());
  await golden("hub-spoke-spoke", r.config);
  assertEquals(r.peers.map((p) => p.name), ["hub"]);
  assertEquals(r.excluded, ["spoke-2", "spoke-3"]);
  assertEquals(r.peers[0].allowed_ips, [
    "192.0.2.1/32",
    "192.0.2.3/32",
    "192.0.2.4/32",
  ]);
});

Deno.test("golden: the hub keeps every spoke as a direct peer", async () => {
  const r = renderMesh(hubSelf());
  await golden("hub-spoke-hub", r.config);
  assertEquals(r.peers.map((p) => p.name), ["spoke-1", "spoke-2", "spoke-3"]);
  assertEquals(r.excluded, []);
});

Deno.test("golden: full mesh, allowlist by public key", async () => {
  const r = renderMesh(fullMesh());
  await golden("full-mesh", r.config);
  assertEquals(r.peers.map((p) => p.name), ["hub", "spoke-1", "spoke-3"]);
});

Deno.test("excluded relay never appears as a direct peer", () => {
  const m = hubSpoke();
  m.relay_exclusion = [{ exclude: ["hub"], for_nodes: ["spoke-1"] }];
  const r = renderMesh(m);
  assertEquals(r.peers.some((p) => p.name === "hub"), false);
  assertEquals(r.config.includes(key("H")), false);
});

Deno.test("render is deterministic and ignores input order", () => {
  const a = renderMesh(hubSpoke());
  const m = hubSpoke();
  m.peers = [...m.peers].reverse();
  m.peers_allowlist = [...m.peers_allowlist].reverse();
  assertEquals(renderMesh(m).config, a.config);
  assertEquals(renderMesh(hubSpoke()).config, a.config);
});

Deno.test("the config never contains a private key, only a key-file reference", () => {
  const { config } = renderMesh(hubSpoke());
  assertEquals(config.includes("PrivateKey"), false);
  assertEquals(
    config.includes(
      "PostUp = wg set '%i' private-key '/etc/wireguard/%i.key'",
    ),
    true,
  );
});

Deno.test("a peer not on the allowlist is rejected by name", () => {
  const m = hubSpoke();
  m.peers_allowlist = ["hub", "spoke-1", "spoke-3"];
  const e = assertThrows(() => renderMesh(m), PeerNotAllowedError);
  assertEquals(e.peer, "spoke-2");
  assertEquals(e.message.includes("spoke-2"), true);
});

Deno.test("an empty allowlist rejects every peer", () => {
  const m = fullMesh();
  m.peers_allowlist = [];
  assertThrows(() => renderMesh(m), PeerNotAllowedError);
});

Deno.test("overlapping or duplicate allowed_ips are rejected", () => {
  const m = fullMesh();
  m.peers = [...m.peers, { ...S2, name: "x", public_key: key("X") }];
  m.peers_allowlist = [...m.peers_allowlist, "x"];
  assertThrows(() => renderMesh(m), MeshError, "overlaps");
  const n = fullMesh();
  n.peers = n.peers.map((p) =>
    p.name === "hub" ? { ...HUB, allowed_ips: ["192.0.2.0/24"] } : p
  );
  assertThrows(() => renderMesh(n), MeshError, "overlaps");
});

Deno.test("duplicate peer names and keys are rejected", () => {
  const m = fullMesh();
  m.peers = [...m.peers, { ...S1, allowed_ips: ["192.0.2.99/32"] }];
  assertThrows(() => renderMesh(m), MeshError, "duplicate peer name");
  const n = fullMesh();
  n.peers = [
    ...n.peers,
    { ...S1, name: "dup", allowed_ips: ["192.0.2.99/32"] },
  ];
  n.peers_allowlist.push("dup");
  assertThrows(() => renderMesh(n), MeshError, "public key");
});

Deno.test("a peer claiming the node's own address is rejected", () => {
  const m = fullMesh();
  m.peers = m.peers.filter((p) => p.name !== "spoke-2").map((p) =>
    p.name === "hub" ? { ...HUB, allowed_ips: ["192.0.2.3/32"] } : p
  );
  assertThrows(() => renderMesh(m), MeshError, "node address");
});

Deno.test("relay rules naming unknown peers or contradicting themselves fail", () => {
  const bad = (rule: Record<string, unknown>) => {
    const m = hubSpoke();
    // deno-lint-ignore no-explicit-any
    m.relay_exclusion = [rule as any];
    return () => renderMesh(m);
  };
  assertThrows(
    bad({ exclude: ["ghost"], for_nodes: ["*"] }),
    MeshError,
    "unknown",
  );
  assertThrows(
    bad({ exclude: ["hub"], for_nodes: ["spoke-1"], via: "hub" }),
    MeshError,
    "itself",
  );
  assertThrows(
    bad({ exclude: ["spoke-2"], for_nodes: ["hub"], via: "hub" }),
    MeshError,
    "itself",
  );
  // A typo in for_nodes must fail loudly, not silently drop the rule.
  assertThrows(
    bad({ exclude: ["spoke-2"], for_nodes: ["spoke-9"] }),
    MeshError,
    "for_nodes names unknown node",
  );
  // The rendering node itself may be named even when it is not a peer entry.
  assertEquals(
    renderMesh({
      node: { name: "spoke-1", address: "192.0.2.2/32", listen_port: 51820 },
      peers: [S3, S2],
      peers_allowlist: ["spoke-3", "spoke-2"],
      relay_exclusion: [{
        exclude: ["spoke-2"],
        for_nodes: ["spoke-1"],
      }],
    }).peers.map((p) => p.name),
    ["spoke-3"],
  );
});

Deno.test("schema rejects bad keys, CIDRs, ports, endpoints and extra fields", () => {
  const base = hubSpoke();
  const parse = (m: unknown) => MeshSchema.safeParse(m).success;
  assertEquals(parse(base), true);
  const withPeer = (p: Record<string, unknown>) => ({
    ...base,
    peers: [{ ...S1, ...p }],
  });
  assertEquals(parse(withPeer({ public_key: "short" })), false);
  assertEquals(parse(withPeer({ public_key: "A".repeat(43) + "!" })), false);
  assertEquals(parse(withPeer({ allowed_ips: ["192.0.2.1"] })), false);
  assertEquals(parse(withPeer({ allowed_ips: ["192.0.2.1/33"] })), false);
  assertEquals(parse(withPeer({ allowed_ips: ["256.0.2.1/32"] })), false);
  assertEquals(parse(withPeer({ allowed_ips: [] })), false);
  assertEquals(parse(withPeer({ endpoint: "198.51.100.1:99999" })), false);
  assertEquals(parse(withPeer({ extra: 1 })), false);
  assertEquals(parse({ ...base, extra: 1 }), false);
  assertEquals(
    parse({ ...base, node: { ...base.node, listen_port: 0 } }),
    false,
  );
  assertEquals(parse({ ...base, interface: "wg0; reboot" }), false);
});

Deno.test("names and endpoints cannot inject config lines or shell", () => {
  for (const name of ["a\n[Peer]", "a b", "a;b", "$(x)", "", "-x"]) {
    assertEquals(
      MeshSchema.safeParse({ ...hubSpoke(), peers: [{ ...S1, name }] }).success,
      false,
      JSON.stringify(name),
    );
  }
  for (
    const ep of ["h:1\nAllowedIPs = 0.0.0.0/0", "a b:1", "$(x):1", "h;x:1"]
  ) {
    assertEquals(isEndpoint(ep), false, ep);
  }
  assertEquals(isEndpoint("[2001:db8::1]:51820"), true);
  assertEquals(isEndpoint("peer.example.com:1"), true);
});

Deno.test("key grammar", () => {
  assertEquals(KeySchema.safeParse(key("Z")).success, true);
  assertEquals(KeySchema.safeParse("x".repeat(44)).success, false);
});
