import { assertEquals } from "jsr:@std/assert@1.0.19";
import { model as plans } from "./plans.ts";
import { model as projects } from "./projects.ts";
import { model as servers } from "./servers.ts";
import { model as sshKeys } from "./ssh_keys.ts";

const MODELS = { plans, projects, servers, sshKeys };

Deno.test("every model's last upgrade reaches its current version", () => {
  for (const [name, m] of Object.entries(MODELS)) {
    assertEquals(m.upgrades.at(-1)?.toVersion, m.version, name);
  }
});

Deno.test("upgrades to 2026.10.16.3 keep existing attributes unchanged", () => {
  const old = {
    project_id: 1001,
    hostname: "node-1",
    plan: "test-plan",
    region: "test-region",
    cycle: "hourly",
    token: '${{ vault.get("example", "TOKEN") }}',
  };
  for (const [name, m] of Object.entries(MODELS)) {
    const step = m.upgrades.find((u) => u.toVersion === "2026.10.16.3");
    assertEquals(step?.upgradeAttributes({ ...old }), old, name);
  }
  // Attributes a 2026.10.16.2 servers definition held still validate.
  assertEquals(servers.globalArguments.safeParse(old).success, true);
});

Deno.test("deletes are actions, so swamp never tombstones other records", () => {
  for (const [name, m] of Object.entries({ projects, servers, sshKeys })) {
    assertEquals(m.methods.delete.kind, "action", name);
  }
});
