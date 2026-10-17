/**
 * Tests for the cluster-scope parsers and command builders.
 *
 * @module
 */

import { assertEquals } from "jsr:@std/assert@1.0.19";
import {
  controlNodeListArgs,
  cordonArgs,
  deleteControlNodeArgs,
  deleteNodeArgs,
  drainArgs,
  etcdLeaveArgs,
  etcdMemberListArgs,
  isJoinToken,
  joinTokenId,
  newTokenIds,
  nodeListArgs,
  nodePodListArgs,
  parseClusterNodes,
  parseEtcdMembers,
  parseItemNames,
  parseJoinTokens,
  tokenCreateArgs,
  tokenInvalidateArgs,
  tokenListArgs,
  uncordonArgs,
} from "./cluster.ts";

const NODES = JSON.stringify({
  items: [
    {
      metadata: {
        name: "ctrl-1",
        labels: { "node.k0sproject.io/role": "control-plane" },
      },
      spec: { unschedulable: true },
      status: {
        nodeInfo: { kubeletVersion: "v1.31.2" },
        conditions: [{ type: "Ready", status: "True" }],
      },
    },
    {
      metadata: {
        name: "worker-1",
        labels: { "node.k0sproject.io/role": "worker" },
      },
      spec: {},
      status: {
        nodeInfo: { kubeletVersion: "v1.31.2" },
        conditions: [{ type: "Ready", status: "False" }],
      },
    },
    {
      metadata: {
        name: "old",
        labels: { "node-role.kubernetes.io/control-plane": "" },
      },
      spec: {},
      status: { nodeInfo: { kubeletVersion: "v1.30.0" }, conditions: [] },
    },
  ],
});

Deno.test("parseClusterNodes reads role, readiness, cordon and versions", () => {
  const nodes = parseClusterNodes(NODES);
  assertEquals(nodes.length, 3);
  assertEquals(nodes[0], {
    name: "ctrl-1",
    role: "controller",
    ready: true,
    cordoned: true,
    kubelet_version: "v1.31.2",
    k0s_version: null,
  });
  assertEquals(nodes[1].role, "worker");
  assertEquals(nodes[1].ready, false);
  assertEquals(nodes[1].cordoned, false);
  assertEquals(nodes[2].role, "controller");
});

Deno.test("parseClusterNodes reads the k0s version label and tolerates junk", () => {
  const text = JSON.stringify({
    items: [{
      metadata: {
        name: "c",
        labels: {
          "node.k0sproject.io/role": "control-plane",
          "node.k0sproject.io/version": "v1.31.2+k0s.0",
        },
      },
      status: { conditions: [{ type: "Ready", status: "True" }] },
    }],
  });
  assertEquals(parseClusterNodes(text)[0].k0s_version, "v1.31.2+k0s.0");
  assertEquals(parseClusterNodes("not json"), []);
  assertEquals(parseClusterNodes("{}"), []);
});

Deno.test("parseEtcdMembers reads both the map and array envelopes", () => {
  const map = JSON.stringify({
    members: {
      "ctrl-1": {
        name: "ctrl-1",
        peerURLs: ["https://192.0.2.11:2380"],
        clientURLs: ["https://192.0.2.11:2379"],
      },
    },
  });
  assertEquals(parseEtcdMembers(map), [{
    name: "ctrl-1",
    peer_urls: ["https://192.0.2.11:2380"],
    client_urls: ["https://192.0.2.11:2379"],
  }]);
  const arr = JSON.stringify([{ name: "w", peerURLs: [], clientURLs: [] }]);
  assertEquals(parseEtcdMembers(arr).length, 1);
  assertEquals(parseEtcdMembers("nope"), []);
});

Deno.test("parseJoinTokens reads the table and a JSON list", () => {
  const table = [
    "ID            Role       Expiry",
    "abc123        worker     2026-10-18T00:00:00Z",
    "def456        controller 2026-10-18T01:00:00Z",
  ].join("\n");
  assertEquals(parseJoinTokens(table), [
    { id: "abc123", role: "worker", expiry: "2026-10-18T00:00:00Z" },
    { id: "def456", role: "controller", expiry: "2026-10-18T01:00:00Z" },
  ]);
  const json = JSON.stringify([
    { id: "aaa", role: "worker", expiry: "x" },
  ]);
  assertEquals(parseJoinTokens(json), [
    { id: "aaa", role: "worker", expiry: "x" },
  ]);
  assertEquals(parseJoinTokens(""), []);
});

Deno.test("token diff finds only the new id", () => {
  const before = parseJoinTokens("abc123 worker x");
  const after = parseJoinTokens("abc123 worker x\ndef456 worker y");
  assertEquals(newTokenIds(before, after), ["def456"]);
});

Deno.test("join token shape and id", () => {
  assertEquals(isJoinToken("abc123.0123456789abcdef"), true);
  assertEquals(isJoinToken("no-dot"), false);
  assertEquals(joinTokenId("abc123.0123456789abcdef"), "abc123");
});

Deno.test("command builders name no token value on argv", () => {
  assertEquals(nodeListArgs(), [
    "k0s",
    "kubectl",
    "get",
    "nodes",
    "-o",
    "json",
  ]);
  assertEquals(etcdMemberListArgs(), ["k0s", "etcd", "member-list"]);
  assertEquals(tokenListArgs("worker"), [
    "k0s",
    "token",
    "list",
    "--role",
    "worker",
  ]);
  assertEquals(tokenCreateArgs("controller", "1h"), [
    "k0s",
    "token",
    "create",
    "--role",
    "controller",
    "--expiry",
    "1h",
  ]);
  assertEquals(tokenInvalidateArgs("abc"), [
    "k0s",
    "token",
    "invalidate",
    "abc",
  ]);
  assertEquals(cordonArgs("w1"), ["k0s", "kubectl", "cordon", "w1"]);
  assertEquals(uncordonArgs("w1"), ["k0s", "kubectl", "uncordon", "w1"]);
  assertEquals(drainArgs("w1", 300), [
    "k0s",
    "kubectl",
    "drain",
    "w1",
    "--ignore-daemonsets",
    "--delete-emptydir-data",
    "--timeout=300s",
  ]);
  assertEquals(deleteNodeArgs("w1").includes("--ignore-not-found"), true);
  assertEquals(deleteControlNodeArgs("c1").slice(0, 4), [
    "k0s",
    "kubectl",
    "delete",
    "controlnode",
  ]);
  assertEquals(etcdLeaveArgs("192.0.2.11"), [
    "k0s",
    "etcd",
    "leave",
    "--peer-address",
    "192.0.2.11",
  ]);
  assertEquals(controlNodeListArgs().slice(0, 4), [
    "k0s",
    "kubectl",
    "get",
    "controlnodes",
  ]);
  assertEquals(nodePodListArgs("w1").includes("spec.nodeName=w1"), true);
});

Deno.test("parseItemNames reads node names from a list", () => {
  const text = JSON.stringify({
    items: [{ metadata: { name: "a" } }, { metadata: { name: "b" } }, {}],
  });
  assertEquals(parseItemNames(text), ["a", "b"]);
  assertEquals(parseItemNames("junk"), []);
});
