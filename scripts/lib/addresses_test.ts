import { assertEquals } from "jsr:@std/assert@1.0.13";
import { findAddresses, isPrivateIpv4, isPrivateIpv6 } from "./addresses.ts";

const kinds = (t: string) => findAddresses(t).map((h) => [h.kind, h.value, h.documentation]);

Deno.test("RFC 5737 IPv4 is documentation-safe", () => {
  assertEquals(kinds("host 192.0.2.10 and 198.51.100.7, 203.0.113.255"), [
    ["ipv4", "192.0.2.10", true],
    ["ipv4", "198.51.100.7", true],
    ["ipv4", "203.0.113.255", true],
  ]);
});

Deno.test("private and public IPv4 are flagged", () => {
  assertEquals(kinds("10.1.2.3 172.20.0.1 192.168.1.1 8.8.8.8"), [
    ["ipv4", "10.1.2.3", false],
    ["ipv4", "172.20.0.1", false],
    ["ipv4", "192.168.1.1", false],
    ["ipv4", "8.8.8.8", false],
  ]);
});

Deno.test("CalVer and five-part versions are not addresses", () => {
  assertEquals(kinds('version: "2026.10.16.1" and 1.2.3.4.5'), []);
});

Deno.test("out-of-range octet is not an address", () => {
  assertEquals(kinds("999.1.1.1"), []);
});

Deno.test("loopback and any are documentation-safe", () => {
  assertEquals(kinds("127.0.0.1 0.0.0.0"), [
    ["ipv4", "127.0.0.1", true],
    ["ipv4", "0.0.0.0", true],
  ]);
});

Deno.test("CIDR suffix still yields the address", () => {
  assertEquals(kinds("route 10.0.0.0/8"), [["ipv4", "10.0.0.0", false]]);
});

Deno.test("IPv6 documentation prefix vs real", () => {
  assertEquals(kinds("2001:db8::1 2a01:4f8::1 ::1"), [
    ["ipv6", "2001:db8::1", true],
    ["ipv6", "2a01:4f8::1", false],
    ["ipv6", "::1", true],
  ]);
});

Deno.test("clock times and TS type annotations are not IPv6", () => {
  assertEquals(kinds("at 12:30:45 UTC; const a: string = b ? c : d; x::y"), []);
});

Deno.test("MACs: RFC 7042 and synthetic prefixes pass, others flagged", () => {
  assertEquals(kinds("00:00:5E:00:53:01 02-00-00-00-00-0a 3c:22:fb:01:02:03"), [
    ["mac", "00:00:5E:00:53:01", true],
    ["mac", "02-00-00-00-00-0a", true],
    ["mac", "3c:22:fb:01:02:03", false],
  ]);
});

Deno.test("line numbers are 1-based", () => {
  assertEquals(findAddresses("a\nb 10.0.0.1")[0].line, 2);
});

Deno.test("isPrivateIpv4", () => {
  assertEquals(
    [
      "10.0.0.1",
      "172.31.255.1",
      "172.32.0.1",
      "100.64.0.1",
      "169.254.1.1",
      "192.0.2.1",
    ].map(
      isPrivateIpv4,
    ),
    [true, true, false, true, true, false],
  );
});

Deno.test("isPrivateIpv6: ULA and link-local", () => {
  assertEquals(
    ["fd12::1234", "fc00::1", "fe80::1", "febf::1", "2001:db8::1", "2a01:4f8::1"].map(
      isPrivateIpv6,
    ),
    [true, true, true, true, false, false],
  );
});
