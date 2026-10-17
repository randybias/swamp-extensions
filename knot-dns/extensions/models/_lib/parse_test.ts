import { assertEquals } from "jsr:@std/assert@1.0.19";
import { normalizeServedRdata, parseDsLines, parseZoneRead } from "./parse.ts";

Deno.test("parseZoneRead resolves owners and drops signer-owned types", () => {
  const text = [
    "example.com.\t3600\tIN\tSOA\tns1.example.com. hostmaster.example.com. 1 7200 3600 1209600 3600",
    "example.com.\t3600\tIN\tNS\tns1.example.com.",
    "www\t3600\tIN\tA\t192.0.2.10",
    "example.com.\t3600\tIN\tRRSIG\tA 13 2 3600 20300101000000 20200101000000 12345 example.com. AAAA",
    "example.com.\t3600\tIN\tDNSKEY\t257 3 13 AAAA",
    '*.example.com.\t3600\tIN\tTXT\t"wild"',
  ].join("\n");
  assertEquals(parseZoneRead(text, "example.com."), [
    { name: "example.com.", type: "NS", data: "ns1.example.com." },
    { name: "www.example.com.", type: "A", data: "192.0.2.10" },
    { name: "*.example.com.", type: "TXT", data: '"wild"' },
  ]);
});

Deno.test("normalizeServedRdata matches rendered rdata shapes", () => {
  assertEquals(
    normalizeServedRdata("NS", "ns1.example.com"),
    "ns1.example.com.",
  );
  assertEquals(
    normalizeServedRdata("MX", "10 mail.example.com"),
    "10 mail.example.com.",
  );
  assertEquals(
    normalizeServedRdata("DS", "12345 13 2 abcd"),
    "12345 13 2 ABCD",
  );
  assertEquals(normalizeServedRdata("TXT", '"a" "b"'), '"a" "b"');
});

Deno.test("parseDsLines keeps only DS lines", () => {
  const text = [
    "; DS records",
    "example.com. DS 12345 13 2 ABCD",
    "example.com. DNSKEY 257 3 13 AAAA",
  ].join("\n");
  assertEquals(parseDsLines(text), ["example.com. DS 12345 13 2 ABCD"]);
});
