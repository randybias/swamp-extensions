// Synthetic mesh fixtures: RFC 5737 addresses, example.com names, fake keys.
import type { z } from "npm:zod@4.3.6";
import type { MeshSchema } from "./render.ts";

type MeshInput = z.input<typeof MeshSchema>;

/** A clearly fake but well-formed WireGuard public key. */
export const key = (c: string) => c.repeat(42) + "A=";

const peer = (name: string, c: string, ip: string, extra = {}) => ({
  name,
  public_key: key(c),
  allowed_ips: [`${ip}/32`],
  ...extra,
});

export const HUB = peer("hub", "H", "192.0.2.1", {
  endpoint: "198.51.100.10:51820",
  keepalive: 25,
});
export const S1 = peer("spoke-1", "B", "192.0.2.2");
export const S2 = peer("spoke-2", "C", "192.0.2.3", {
  endpoint: "spoke-2.example.com:51820",
});
export const S3 = peer("spoke-3", "D", "192.0.2.4");

const nodeOf = (name: string, ip: string, endpoint?: string) => ({
  name,
  address: `${ip}/32`,
  listen_port: 51820,
  ...(endpoint ? { endpoint } : {}),
});

/** Spoke-1 in a hub-and-spoke mesh where the hub relays between spokes. */
export const hubSpoke = (): MeshInput => ({
  node: nodeOf("spoke-1", "192.0.2.2"),
  peers: [S3, HUB, S1, S2],
  peers_allowlist: ["hub", "spoke-1", "spoke-2", "spoke-3"],
  relay_exclusion: [{
    exclude: ["spoke-1", "spoke-2", "spoke-3"],
    for_nodes: ["*"],
    via: "hub",
  }],
});

/** The hub itself in the same mesh: it peers directly with every spoke. */
export const hubSelf = (): MeshInput => ({
  ...hubSpoke(),
  node: nodeOf("hub", "192.0.2.1", "198.51.100.10:51820"),
});

/** Spoke-2 in a full mesh: every other node is a direct peer. */
export const fullMesh = (): MeshInput => ({
  node: nodeOf("spoke-2", "192.0.2.3", "spoke-2.example.com:51820"),
  peers: [S3, S2, HUB, S1],
  peers_allowlist: [key("H"), key("B"), key("C"), key("D")],
  relay_exclusion: [],
});
