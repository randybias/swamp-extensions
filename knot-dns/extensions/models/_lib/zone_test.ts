import { assert, assertEquals, assertThrows } from "jsr:@std/assert@1.0.19";
import {
  canonicalIpv6,
  canonicalNameCompare,
  canonicalRecords,
  canonicalZoneFile,
  declaredTuples,
  diffDeclared,
  isApex,
  isFqdn,
  isIpv4,
  isIpv6,
  isLabel,
  normalizeApex,
  noSignerOwned,
  ownerFqdn,
  quoteTxt,
  RecordSchema,
  renderRdata,
  renderZoneConfig,
  renderZoneFile,
  SoaSchema,
  type ZoneRecord,
} from "./zone.ts";

const SOA = SoaSchema.parse({
  primary_ns: "ns1.example.com.",
  contact: "hostmaster.example.com.",
  refresh: 7200,
  retry: 3600,
  expire: 1209600,
  minimum: 3600,
});

const NS = { name: "@", type: "NS", data: "ns1.example.com." } as const;

function rec(
  r: Partial<ZoneRecord> & { type: string; data: unknown },
): ZoneRecord {
  return r as ZoneRecord;
}

Deno.test("grammars", () => {
  assert(isApex("example.com"));
  assert(isApex("example.com."));
  assert(isApex("Example.com"));
  assert(!isApex("-bad.example"));
  assert(isApex("_dns.example"));
  assert(isFqdn("www.example.com"));
  assert(!isFqdn("bad..example"));
  assert(isLabel("a-b"));
  assert(!isLabel("-a"));
  assert(isIpv4("192.0.2.1"));
  assert(!isIpv4("192.0.2.256"));
  assert(!isIpv4("192.0.2.01"));
  assert(isIpv6("2001:db8::1"));
  assert(!isIpv6("2001:db8:::1"));
  assertEquals(normalizeApex("Example.COM."), "example.com.");
});

Deno.test("owner resolution and zone boundary", () => {
  assertEquals(ownerFqdn("example.com.", "@"), "example.com.");
  assertEquals(ownerFqdn("example.com.", "www"), "www.example.com.");
  assertEquals(
    ownerFqdn("example.com.", "www.example.com."),
    "www.example.com.",
  );
  assertEquals(ownerFqdn("example.com.", "*"), "*.example.com.");
  assertEquals(
    ownerFqdn("example.com.", "_443._tcp.www"),
    "_443._tcp.www.example.com.",
  );
  assertEquals(ownerFqdn("example.com.", "_dmarc"), "_dmarc.example.com.");
  assertThrows(() => ownerFqdn("example.com.", "www.other.test."));
  assertThrows(() => ownerFqdn("example.com.", "bad..name"));
});

Deno.test("canonical name order sorts right-to-left", () => {
  const names = ["b.example.com.", "a.example.com.", "example.com."];
  names.sort(canonicalNameCompare);
  assertEquals(names, [
    "example.com.",
    "a.example.com.",
    "b.example.com.",
  ]);
});

Deno.test("rdata rendering for every supported type", () => {
  assertEquals(renderRdata(rec({ type: "A", data: "192.0.2.1" })), "192.0.2.1");
  assertEquals(
    renderRdata(rec({ type: "AAAA", data: "2001:db8::1" })),
    "2001:db8::1",
  );
  assertEquals(
    renderRdata(rec({ type: "CNAME", data: "target.example.com." })),
    "target.example.com.",
  );
  assertEquals(
    renderRdata(rec({
      type: "MX",
      data: { preference: 10, exchange: "mail.example.com." },
    })),
    "10 mail.example.com.",
  );
  assertEquals(renderRdata(rec({ type: "TXT", data: ["a", "b"] })), '"a" "b"');
  assertEquals(
    renderRdata(rec({
      type: "SRV",
      data: { priority: 0, weight: 5, port: 443, target: "svc.example.com." },
    })),
    "0 5 443 svc.example.com.",
  );
  assertEquals(
    renderRdata(rec({
      type: "CAA",
      data: { flags: 0, tag: "issue", value: "ca.example" },
    })),
    '0 issue "ca.example"',
  );
  assertEquals(
    renderRdata(rec({
      type: "DS",
      data: {
        key_tag: 12345,
        algorithm: 13,
        digest_type: 2,
        digest: "ab".repeat(32),
      },
    })),
    `12345 13 2 ${"AB".repeat(32)}`,
  );
  assertEquals(
    renderRdata(rec({
      type: "SSHFP",
      data: { algorithm: 4, fp_type: 2, fingerprint: "abcdef" },
    })),
    "4 2 ABCDEF",
  );
  assertEquals(
    renderRdata(rec({
      type: "TLSA",
      data: { usage: 3, selector: 1, matching_type: 1, certificate: "ab" },
    })),
    "3 1 1 AB",
  );
});

Deno.test("TXT and CAA values are quoted and escaped, never bare", () => {
  assertEquals(quoteTxt('a"b\\c'), '"a\\"b\\\\c"');
  const rendered = renderRdata(rec({ type: "TXT", data: ['"; rm -rf /'] }));
  assertEquals(rendered, '"\\"; rm -rf /"');
  assert(rendered.startsWith('"') && rendered.endsWith('"'));
});

Deno.test("semantic rules: apex CNAME, CNAME conflict, RRset TTL, refused types", () => {
  assertThrows(
    () =>
      canonicalRecords("example.com.", SOA, [
        rec({ name: "@", type: "CNAME", data: "x.example.com." }),
      ]),
    Error,
    "CNAME",
  );
  assertThrows(
    () =>
      canonicalRecords("example.com.", SOA, [
        rec({ name: "www", type: "CNAME", data: "x.example.com." }),
        rec({ name: "www", type: "A", data: "192.0.2.1" }),
      ]),
    Error,
    "CNAME",
  );
  assertThrows(
    () =>
      canonicalRecords("example.com.", SOA, [
        rec({ name: "www", type: "A", data: "192.0.2.1", ttl: 60 }),
        rec({ name: "www", type: "A", data: "192.0.2.2", ttl: 120 }),
      ]),
    Error,
    "TTL",
  );
  assertEquals(noSignerOwned([{ type: "A" }, { type: "NS" }]), true);
  assertEquals(noSignerOwned([{ type: "DNSKEY" }]), false);
  assertEquals(noSignerOwned([{ type: "SOA" }]), false);
});

Deno.test("duplicate records collapse", () => {
  const records = canonicalRecords("example.com.", SOA, [
    rec({ name: "www", type: "A", data: "192.0.2.1" }),
    rec({ name: "www", type: "A", data: "192.0.2.1" }),
    NS,
  ]);
  assertEquals(records.filter((r) => r.type === "A").length, 1);
});

Deno.test("domain-valued fields reject control characters and directives", () => {
  const bad = [
    {
      name: "www",
      type: "CNAME",
      data: "www.example.com.\nevil.example.com. 60 IN A 192.0.2.66\n;",
    },
    { name: "www", type: "NS", data: "ns.$INCLUDE x" },
    {
      name: "@",
      type: "MX",
      data: { preference: 10, exchange: "a;b.example.com." },
    },
    {
      name: "_sip._tcp",
      type: "SRV",
      data: { priority: 0, weight: 0, port: 5060, target: "t\tevil" },
    },
  ];
  for (const r of bad) {
    assertEquals(RecordSchema.safeParse(r).success, false, JSON.stringify(r));
  }
  assertEquals(
    SoaSchema.safeParse({ ...SOA, primary_ns: "ns1;rm -rf /" }).success,
    false,
  );
});

Deno.test("IPv6 rdata is canonicalized for comparison", () => {
  assertEquals(canonicalIpv6("2001:DB8:0:0::1"), "2001:db8::1");
  assertEquals(canonicalIpv6("2001:db8::1"), "2001:db8::1");
  assertEquals(
    renderRdata(rec({ type: "AAAA", data: "2001:DB8:0:0::1" })),
    "2001:db8::1",
  );
});

Deno.test("config fragment is a valid top-level shape, not inline blocks", () => {
  const fragment = renderZoneConfig({
    apex: "example.com.",
    file: "/var/lib/knot/zones/example.com.zone",
    signed: true,
    dnssec: { algorithm: "ecdsap256sha256", nsec3: false },
    notifySecondaries: ["192.0.2.2@53"],
    allowTransfer: ["192.0.2.3"],
    tsigKeyNames: ["xfer"],
  });
  assert(fragment.startsWith("policy:"));
  assert(fragment.includes("dnssec-policy: managed-example-com"));
  assert(fragment.includes("remote:"));
  assert(fragment.includes("acl:"));
  assert(fragment.includes("notify: managed-example-com-notify"));
  assert(!fragment.includes("disable-any"));
  assert(!/^\s+notify:$/m.test(fragment));
});

Deno.test("golden plain zone file", () => {
  const file = renderZoneFile("example.com.", SOA, [
    NS,
    rec({ name: "www", type: "A", data: "192.0.2.10" }),
    rec({ name: "@", type: "TXT", data: ["hello"] }),
  ]);
  assertEquals(
    file,
    [
      "; managed by @randybias/knot-dns; edits are overwritten on the next apply",
      "example.com.\t3600\tIN\tSOA\tns1.example.com. hostmaster.example.com. ( 1 7200 3600 1209600 3600 )",
      "example.com.\t3600\tIN\tNS\tns1.example.com.",
      'example.com.\t3600\tIN\tTXT\t"hello"',
      "www.example.com.\t3600\tIN\tA\t192.0.2.10",
      "",
    ].join("\n"),
  );
});

Deno.test("canonical order is stable under shuffled input", () => {
  const records = [
    NS,
    rec({ name: "zzz", type: "A", data: "192.0.2.2" }),
    rec({ name: "aaa", type: "A", data: "192.0.2.1" }),
    rec({
      name: "@",
      type: "MX",
      data: { preference: 10, exchange: "mx.example.com." },
    }),
    rec({ name: "sub", type: "NS", data: "ns2.example.com." }),
    rec({ name: "sub", type: "A", data: "192.0.2.3" }),
  ];
  const a = canonicalZoneFile("example.com.", SOA, records);
  const b = canonicalZoneFile("example.com.", SOA, [...records].reverse());
  assertEquals(a, b);
});

Deno.test("delegation with DS and glue, and a reverse zone", () => {
  const delegation = renderZoneFile("example.com.", SOA, [
    NS,
    rec({ name: "sub", type: "NS", data: "ns1.sub.example.com." }),
    rec({ name: "ns1.sub", type: "A", data: "192.0.2.53" }),
    rec({
      name: "sub",
      type: "DS",
      data: {
        key_tag: 12345,
        algorithm: 13,
        digest_type: 2,
        digest: "cd".repeat(32),
      },
    }),
  ]);
  assert(
    delegation.includes("sub.example.com.\t3600\tIN\tNS\tns1.sub.example.com."),
  );
  assert(delegation.includes("ns1.sub.example.com.\t3600\tIN\tA\t192.0.2.53"));
  assert(/sub\.example\.com\.\t3600\tIN\tDS\t12345 13 2 CD/.test(delegation));

  const reverse = renderZoneFile("2.0.192.in-addr.arpa.", SOA, [
    { name: "@", type: "NS", data: "ns1.example.com." },
    rec({ name: "10", type: "PTR", data: "www.example.com." }),
  ]);
  const ptrOwner = ["10", "2.0.192.in-addr.arpa."].join(".");
  assert(reverse.includes(`${ptrOwner}\t3600\tIN\tPTR\twww.example.com.`));
});

Deno.test("wildcard owner only as the leftmost label", () => {
  const file = renderZoneFile("example.com.", SOA, [
    NS,
    rec({ name: "*", type: "A", data: "192.0.2.9" }),
  ]);
  assert(file.includes("*.example.com.\t3600\tIN\tA\t192.0.2.9"));
  assertThrows(() => ownerFqdn("example.com.", "a.*.b"));
});

Deno.test("config fragment is deterministic and owned", () => {
  const fragment = renderZoneConfig({
    apex: "example.com.",
    file: "/var/lib/knot/zones/example.com.zone",
    signed: true,
    dnssec: { algorithm: "ecdsap256sha256", nsec3: false },
    notifySecondaries: ["192.0.2.2@53"],
    allowTransfer: ["192.0.2.3"],
    tsigKeyNames: ["xfer"],
  });
  assert(fragment.includes("domain: example.com."));
  assert(fragment.includes("zonefile-sync: -1"));
  assert(fragment.includes("zonefile-load: difference-no-serial"));
  assert(fragment.includes("serial-policy: unixtime"));
  assert(fragment.includes("dnssec-signing: on"));
  assert(fragment.includes("notify:"));
});

Deno.test("served-vs-declared diff", () => {
  const declared = declaredTuples("example.com.", SOA, [
    NS,
    rec({ name: "www", type: "A", data: "192.0.2.10" }),
  ]);
  const served = [
    { name: "example.com.", type: "NS", data: "ns1.example.com." },
    { name: "old.example.com.", type: "A", data: "192.0.2.99" },
  ];
  const diff = diffDeclared(declared, served);
  assertEquals(diff.added, [
    { name: "www.example.com.", type: "A", data: "192.0.2.10" },
  ]);
  assertEquals(diff.removed, [
    { name: "old.example.com.", type: "A", data: "192.0.2.99" },
  ]);
});
