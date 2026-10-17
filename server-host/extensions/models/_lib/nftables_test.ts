import { assertEquals, assertThrows } from "jsr:@std/assert@1.0.19";
import {
  assertFirewallRules,
  assertListingMatches,
  expectedManagedSha256,
  type FirewallRules,
  listingSha256,
  managedSha256,
  normalizeListing,
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

interface Sample {
  trusted_interfaces?: string[];
  management_cidrs: string[];
  allow_tcp: number[];
  allow_udp: number[] | null;
  text: string;
  json: unknown;
}

const REAL: Record<string, Sample> = JSON.parse(
  await Deno.readTextFile(new URL("nft-real-listings.json", FIX)),
);

const rulesOf = (x: Sample): FirewallRules => ({
  managementCidrs: x.management_cidrs,
  allowTcp: x.allow_tcp,
  allowUdp: x.allow_udp ?? [],
  defaultPolicy: "drop",
  sshPort: 22,
  allowSshFromAnywhere: false,
  ...(x.trusted_interfaces ? { trustedInterfaces: x.trusted_interfaces } : {}),
});

Deno.test("real nft output differs from the rendered text, yet matches the rendered rules", async () => {
  for (const [name, x] of Object.entries(REAL)) {
    const rules = rulesOf(x);
    const rendered = renderRuleset(rules);
    // nft drops braces on one-element sets, collapses /32 and reorders: the
    // text a hash of the render would have been compared against is different.
    const sshLine = rendered.split("\n").find((l) => l.includes("saddr"))!
      .trim();
    assertEquals(x.text.includes(sshLine), false, name);
    const live = JSON.stringify(x.json);
    assertListingMatches(rules, live);
    assertEquals(
      await managedSha256(normalizeListing(live)),
      await expectedManagedSha256(rules),
      name,
    );
  }
});

Deno.test("real nft output shapes: the properties the old hash tripped on are really there", () => {
  assertEquals(
    REAL.single_cidr.text.includes("ip saddr 198.51.100.0/24 tcp"),
    true,
  );
  assertEquals(REAL.single_cidr.text.includes("{ 198.51.100"), false);
  assertEquals(REAL.slash32.text.includes("ip saddr 198.51.100.3 tcp"), true);
  assertEquals(REAL.slash32.text.includes("198.51.100.3/32"), false);
  // Numeric order (.64 before .128) where the renderer sorts text (.128 first).
  assertEquals(
    REAL.numeric_vs_lexical.text.includes(
      "{ 198.51.100.64/26, 198.51.100.128/25 }",
    ),
    true,
  );
  assertEquals(
    renderRuleset(rulesOf(REAL.numeric_vs_lexical)).includes(
      "{ 198.51.100.128/25, 198.51.100.64/26 }",
    ),
    true,
  );
  assertEquals(
    REAL.numeric_vs_lexical.text.includes("tcp dport { 80, 443 }"),
    true,
  );
});

Deno.test("a wrong apply is still caught: extra, missing, reordered or altered rules", () => {
  const x = REAL.numeric_vs_lexical;
  const rules = rulesOf(x);
  const doc = () =>
    JSON.parse(JSON.stringify(x.json)) as {
      nftables: Record<string, Record<string, unknown>>[];
    };
  const bad = (edit: (d: ReturnType<typeof doc>) => void, text: string) => {
    const d = doc();
    edit(d);
    assertThrows(
      () => assertListingMatches(rules, JSON.stringify(d)),
      HostConfigError,
      text,
    );
  };
  // An extra accept rule.
  bad((d) => {
    const r = d.nftables.find((o) => o.rule)!;
    d.nftables.push({
      rule: { ...r.rule, handle: 99, expr: [{ accept: null }] },
    });
  }, "extra or reordered");
  // The SSH rule lost one allowed network.
  bad((d) => {
    for (const o of d.nftables) {
      const e = (o.rule?.expr as
        | { match?: { right?: { set?: unknown[] } } }[]
        | undefined)?.[0];
      if (e?.match?.right?.set && e.match.right.set.length === 2) {
        e.match.right.set.pop();
      }
    }
  }, "missing");
  // A changed policy.
  bad((d) => {
    const c = d.nftables.find((o) => o.chain?.name === "input")!;
    (c.chain as Record<string, unknown>).policy = "accept";
  }, "policy");
  // Table gone.
  assertThrows(
    () => assertListingMatches(rules, JSON.stringify({ nftables: [] })),
    HostConfigError,
    "not present",
  );
});

Deno.test("normalize: addresses compare numerically and other tables are ignored", async () => {
  const rules = rulesOf(REAL.single_cidr);
  const other = {
    nftables: [
      { table: { family: "inet", name: "k0s", handle: 1 } },
      { chain: { family: "inet", table: "k0s", name: "input", handle: 1 } },
      ...(JSON.parse(JSON.stringify(REAL.single_cidr.json))
        .nftables as unknown[]),
    ],
  };
  assertListingMatches(rules, JSON.stringify(other));
  assertEquals(normalizeListing(JSON.stringify({ nftables: [] })), null);
  // A different network changes the hash.
  assertEquals(
    await expectedManagedSha256(rules) ===
      await expectedManagedSha256({
        ...rules,
        managementCidrs: ["203.0.113.0/24"],
      }),
    false,
  );
  // IPv6 forms of one address agree.
  const v6a = { ...rules, managementCidrs: ["2001:db8:0:0:0:0:0:1/128"] };
  const v6b = { ...rules, managementCidrs: ["2001:db8::1/128"] };
  assertEquals(
    await expectedManagedSha256(v6a),
    await expectedManagedSha256(v6b),
  );
});

Deno.test("listing sha ignores handles and metainfo", async () => {
  const a = JSON.stringify(REAL.single_cidr.json);
  const b = a.replace(
    /"handle":(\d+)/g,
    (_m, n) => `"handle":${Number(n) + 100}`,
  )
    .replace("1.0.9", "1.0.10");
  assertEquals(await listingSha256(a), await listingSha256(b));
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

Deno.test("the rendered script owns exactly one table and never flushes anything else", () => {
  const text = renderRuleset({
    managementCidrs: ["192.0.2.0/24"],
    allowTcp: [443],
    allowUdp: [],
    defaultPolicy: "drop",
    sshPort: 22,
    allowSshFromAnywhere: false,
  });
  assertEquals(/flush/i.test(text), false);
  // `destroy` needs kernel 6.3; add + delete works on older kernels too.
  assertEquals(text.includes("destroy"), false);
  assertEquals(
    text.includes(
      "add table inet server_host\ndelete table inet server_host\n",
    ),
    true,
  );
  // Every table statement names the managed table.
  const tables = text.split("\n").filter((l) =>
    /^(add |delete )?table /.test(l)
  );
  assertEquals(tables.length, 3);
  for (const l of tables) assertEquals(l.includes("inet server_host"), true, l);
});

Deno.test("real nft merges overlapping and adjacent set entries; the structure compares the covered addresses", async () => {
  // Each of these was listed by nftables 1.0.9 as fewer elements than rendered,
  // or as a range, yet is exactly the rendered rule once merged.
  for (
    const name of [
      "contained",
      "adjacent",
      "unaligned_range",
      "same_network_host_bits",
      "v6_contained",
    ]
  ) {
    const x = REAL[name];
    const rules = rulesOf(x);
    assertListingMatches(rules, JSON.stringify(x.json));
    assertEquals(
      await managedSha256(normalizeListing(JSON.stringify(x.json))),
      await expectedManagedSha256(rules),
      name,
    );
  }
  assertEquals(
    REAL.unaligned_range.text.includes("198.51.100.64-198.51.100.191"),
    true,
  );
  // Merging does not paper over a real difference: a hole is still a hole.
  const gap = {
    ...rulesOf(REAL.adjacent),
    managementCidrs: ["198.51.100.0/26", "198.51.100.128/25"],
  };
  assertEquals(
    await expectedManagedSha256(gap) ===
      await expectedManagedSha256(rulesOf(REAL.adjacent)),
    false,
  );
});

Deno.test("table flags and extra sets are part of the structure", async () => {
  const x = REAL.single_cidr;
  const rules = rulesOf(x);
  const withTable = (edit: (t: Record<string, unknown>) => void) => {
    const d = JSON.parse(JSON.stringify(x.json)) as {
      nftables: Record<string, Record<string, unknown>>[];
    };
    edit(d.nftables.find((o) => o.table)!.table);
    return JSON.stringify(d);
  };
  const dormant = withTable((t) => t.flags = ["dormant"]);
  assertThrows(
    () => assertListingMatches(rules, dormant),
    HostConfigError,
    "flags",
  );
  assertEquals(
    await managedSha256(normalizeListing(dormant)) ===
      await expectedManagedSha256(rules),
    false,
  );
  const withSet = JSON.stringify({
    nftables: [
      ...(x.json as { nftables: unknown[] }).nftables,
      {
        set: {
          family: "inet",
          table: "server_host",
          name: "extra",
          type: "ipv4_addr",
          handle: 9,
        },
      },
    ],
  });
  assertThrows(
    () => assertListingMatches(rules, withSet),
    HostConfigError,
    "sets or other",
  );
});

const TRUSTED_BASE: FirewallRules = {
  managementCidrs: ["198.51.100.0/24"],
  allowTcp: [4222],
  allowUdp: [],
  defaultPolicy: "drop",
  sshPort: 22,
  allowSshFromAnywhere: false,
};

Deno.test("trusted_interfaces: unset or empty renders exactly the earlier ruleset", () => {
  const plain = renderRuleset(TRUSTED_BASE);
  assertEquals(
    renderRuleset({ ...TRUSTED_BASE, trustedInterfaces: [] }),
    plain,
  );
  assertEquals(plain.includes('iifname "kube'), false);
  assertEquals(plain.includes("oifname"), false);
});

Deno.test("trusted_interfaces: input accepts the interface, forward accepts both directions, sorted and deduped", () => {
  const text = renderRuleset({
    ...TRUSTED_BASE,
    trustedInterfaces: ["tunl0", "kube-bridge", "cali*", "kube-bridge"],
  });
  const input = text.slice(
    text.indexOf("chain input"),
    text.indexOf("chain forward"),
  );
  const forward = text.slice(
    text.indexOf("chain forward"),
    text.indexOf("chain output"),
  );
  assertEquals(
    input.match(/iifname "[^"]+" accept/g),
    [
      'iifname "lo" accept',
      'iifname "cali*" accept',
      'iifname "kube-bridge" accept',
      'iifname "tunl0" accept',
    ],
  );
  assertEquals(
    forward.match(/[io]ifname "[^"]+" accept/g),
    [
      'iifname "cali*" accept',
      'oifname "cali*" accept',
      'iifname "kube-bridge" accept',
      'oifname "kube-bridge" accept',
      'iifname "tunl0" accept',
      'oifname "tunl0" accept',
    ],
  );
  // The default policy of both chains is untouched.
  assertEquals(forward.includes("policy drop;"), true);
});

Deno.test("trusted_interfaces: a good pattern passes, a bad one is refused before anything is rendered", () => {
  for (
    const ok of [
      "kube-bridge",
      "cali*",
      "tunl0",
      "vxlan.calico",
      "a",
      "abcdefghijklmno",
      "abcdefghijklmn*",
    ]
  ) {
    assertFirewallRules({ ...TRUSTED_BASE, trustedInterfaces: [ok] });
  }
  for (
    const bad of [
      "*",
      "",
      "a b",
      'a"b',
      "x;y",
      "a\nb",
      "-x",
      "abcdefghijklmnop",
      "a*b",
      "cali**",
      "*cali",
      "a{b}",
    ]
  ) {
    assertThrows(
      () => assertFirewallRules({ ...TRUSTED_BASE, trustedInterfaces: [bad] }),
      HostConfigError,
      "interface",
    );
  }
});

Deno.test("trusted_interfaces: the real nft listing matches the rendered rules and hashes the same", async () => {
  for (const name of ["trusted_one", "trusted_wildcards"]) {
    const x = REAL[name];
    const rules = rulesOf(x);
    assertListingMatches(rules, JSON.stringify(x.json));
    assertEquals(
      await managedSha256(normalizeListing(JSON.stringify(x.json))),
      await expectedManagedSha256(rules),
      name,
    );
  }
  // Dropping the forward return-path rule of a trusted interface is caught.
  const x = REAL.trusted_one;
  const d = JSON.parse(JSON.stringify(x.json)) as {
    nftables: Record<string, Record<string, unknown>>[];
  };
  d.nftables = d.nftables.filter((o) =>
    !(o.rule && o.rule.chain === "forward" &&
      JSON.stringify(o.rule.expr).includes("oifname"))
  );
  assertThrows(
    () => assertListingMatches(rulesOf(x), JSON.stringify(d)),
    HostConfigError,
    "forward",
  );
});

Deno.test("trusted_interfaces: the hash differs from the plain ruleset's", async () => {
  assertEquals(
    await expectedManagedSha256(TRUSTED_BASE) ===
      await expectedManagedSha256({
        ...TRUSTED_BASE,
        trustedInterfaces: ["kube-bridge"],
      }),
    false,
  );
});
