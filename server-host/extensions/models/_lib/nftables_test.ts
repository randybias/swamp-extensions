import { assertEquals, assertThrows } from "jsr:@std/assert@1.0.19";
import {
  assertFirewallRules,
  canonicalTable,
  type FirewallRules,
  managedTableSha256,
  managedTableText,
  renderRuleset,
  rulesetSha256,
  splitCidrs,
} from "./nftables.ts";
import { HostConfigError } from "./validate.ts";

const FIX = new URL("./fixtures/", import.meta.url);

async function golden(name: string): Promise<string> {
  return await Deno.readTextFile(new URL(name, FIX));
}

const BASE: FirewallRules = {
  managementCidrs: ["192.0.2.0/24", "198.51.100.0/24"],
  allowTcp: [80, 443],
  allowUdp: [53],
  defaultPolicy: "drop",
  sshPort: 22,
  allowSshFromAnywhere: false,
};

Deno.test("render: golden files for the base, management-only, service and ipv6 cases", async () => {
  const cases: [string, FirewallRules][] = [
    ["base.nft", BASE],
    [
      "mgmt-only.nft",
      {
        ...BASE,
        managementCidrs: ["203.0.113.0/24"],
        allowTcp: [],
        allowUdp: [],
      },
    ],
    [
      "service-ports.nft",
      {
        ...BASE,
        managementCidrs: ["192.0.2.0/24"],
        allowTcp: [8443, 443, 22],
        allowUdp: [51820],
        sshPort: 2222,
      },
    ],
    [
      "anywhere.nft",
      {
        ...BASE,
        managementCidrs: [],
        allowTcp: [80],
        allowUdp: [],
        allowSshFromAnywhere: true,
      },
    ],
    [
      "ipv6.nft",
      {
        ...BASE,
        managementCidrs: ["2001:db8::/32", "192.0.2.0/24"],
        allowTcp: [443],
        allowUdp: [],
      },
    ],
    [
      "lockdown.nft",
      {
        ...BASE,
        managementCidrs: ["192.0.2.0/24"],
        allowTcp: [80, 22],
        allowUdp: [53],
      },
    ],
  ];
  for (const [name, rules] of cases) {
    assertEquals(renderRuleset(rules), await golden(name), name);
  }
});

Deno.test("render: stable order whatever the input order", () => {
  const a = renderRuleset(BASE);
  const shuffled = renderRuleset({
    ...BASE,
    managementCidrs: ["198.51.100.0/24", "192.0.2.0/24", "192.0.2.0/24"],
    allowTcp: [443, 80, 80],
    allowUdp: [53],
  });
  assertEquals(shuffled, a);
});

Deno.test("render: the SSH port is never opened by the blanket port sets", () => {
  const text = renderRuleset({
    ...BASE,
    managementCidrs: ["192.0.2.0/24"],
    allowTcp: [22, 443],
    allowUdp: [22, 53],
    sshPort: 22,
  });
  assertEquals(text.includes("tcp dport { 22"), false);
  assertEquals(text.includes("udp dport { 22"), false);
  assertEquals(text.includes("tcp dport { 443 }"), true);
  assertEquals(text.includes("udp dport { 53 }"), true);
});

Deno.test("render: splitCidrs groups and sorts the two families", () => {
  assertEquals(splitCidrs(["2001:db8::/32", "192.0.2.0/24", "192.0.2.0/24"]), {
    v4: ["192.0.2.0/24"],
    v6: ["2001:db8::/32"],
  });
});

Deno.test("sha256: deterministic and content-addressed", async () => {
  const text = renderRuleset(BASE);
  const one = await rulesetSha256(text);
  assertEquals(one, await rulesetSha256(text));
  assertEquals(one.length, 64);
  assertEquals(one === await rulesetSha256(text + "# x\n"), false);
});

Deno.test("canonical: a rendered script and an nft listing agree, other tables do not confuse it", async () => {
  const rendered = renderRuleset(BASE);
  const listing = `table inet other {\n\tchain x {\n\t}\n}\n${
    rendered.split("\n").slice(2).join("\n")
  }`;
  assertEquals(canonicalTable(rendered), canonicalTable(listing));
  assertEquals(
    await managedTableSha256(rendered),
    await managedTableSha256(listing),
  );
  assertEquals(
    managedTableText(listing).startsWith("table inet server_host {"),
    true,
  );
  assertEquals(managedTableText("table inet other {\n}\n"), "");
});

Deno.test("canonical: the full-script hash differs from the managed-table hash", async () => {
  const rendered = renderRuleset(BASE);
  assertEquals(
    await rulesetSha256(rendered) === await managedTableSha256(rendered),
    false,
  );
});

Deno.test("assertFirewallRules: a /0 needs the acknowledgement", () => {
  assertThrows(
    () => assertFirewallRules({ ...BASE, managementCidrs: ["0.0.0.0/0"] }),
    HostConfigError,
  );
  assertFirewallRules({
    ...BASE,
    managementCidrs: [],
    allowSshFromAnywhere: true,
  });
  assertThrows(
    () => assertFirewallRules({ ...BASE, managementCidrs: [] }),
    HostConfigError,
  );
});
