import { assert, assertEquals, assertThrows } from "jsr:@std/assert@1.0.19";
import {
  assertCidr,
  assertIpv4,
  assertMac,
  cidrContains,
  cidrsOverlap,
  ipv4ToString,
  isCidr,
  isFqdn,
  isInterfaceName,
  isIpv4,
  isLabel,
  isMac,
  KeaInputError,
  parseCidr,
  parseInterface,
  parseIpv4,
  parsePool,
  rangesOverlap,
  renderOption,
  targetKey,
} from "./grammar.ts";

Deno.test("IPv4 literals round-trip and reject bad input", () => {
  assertEquals(parseIpv4("192.0.2.10"), 0xc000020a);
  assertEquals(ipv4ToString(0xc000020a), "192.0.2.10");
  for (const bad of ["256.0.0.1", "1.2.3", "1.2.3.4.5", "a.b.c.d", "", "-1"]) {
    assertEquals(isIpv4(bad), false, bad);
    assertThrows(() => assertIpv4(bad, "ip"), KeaInputError);
  }
  assertIpv4("198.51.100.7", "ip");
});

Deno.test("CIDRs require network form and prefix /8-/30", () => {
  const cidr = parseCidr("198.51.100.0/24");
  assert(cidr);
  assertEquals(cidr.text, "198.51.100.0/24");
  assertEquals(cidrContains(cidr, parseIpv4("198.51.100.55") as number), true);
  assertEquals(cidrContains(cidr, parseIpv4("198.51.100.255") as number), true);
  assertEquals(cidrContains(cidr, parseIpv4("203.0.113.1") as number), false);
  for (
    const bad of [
      "198.51.100.1/24",
      "198.51.100.0/31",
      "198.51.100.0/7",
      "192.0.2.0/33",
      "nope",
    ]
  ) {
    assertEquals(isCidr(bad), false, bad);
    assertThrows(() => assertCidr(bad, "subnet"), KeaInputError);
  }
});

Deno.test("CIDR overlap", () => {
  const a = parseCidr("192.0.2.0/24") as ReturnType<typeof parseCidr>;
  const b = parseCidr("192.0.2.128/25") as ReturnType<typeof parseCidr>;
  const c = parseCidr("198.51.100.0/24") as ReturnType<typeof parseCidr>;
  assertEquals(cidrsOverlap(a as never, b as never), true);
  assertEquals(cidrsOverlap(a as never, c as never), false);
});

Deno.test("MAC grammar is lowercase and unicast", () => {
  assert(isMac("02:00:00:aa:bb:cc"));
  assertEquals(isMac("01:00:00:aa:bb:cc"), false, "multicast refused"); // leak-allow(multicast MAC under test)
  assertEquals(isMac("02:00:00:AA:BB:CC"), false, "uppercase refused");
  assertThrows(() => assertMac("02-00-00-aa-bb-cc", "hw"), KeaInputError);
});

Deno.test("interface specs, labels and FQDNs", () => {
  assert(isInterfaceName("eth0"));
  assert(isInterfaceName("enp0s3.100"));
  assertEquals(isInterfaceName("*"), false);
  assertEquals(isInterfaceName("1eth"), false);
  assertEquals(parseInterface("eth0/192.0.2.1"), {
    name: "eth0",
    address: "192.0.2.1",
  });
  assertEquals(parseInterface("eth0"), { name: "eth0" });
  assertEquals(parseInterface("eth0/nope"), null);
  assert(isLabel("web-1"));
  assertEquals(isLabel("-web"), false);
  assert(isFqdn("db.example.test"));
  assertEquals(isFqdn("a..b"), false);
  assertEquals(isFqdn(`${"a".repeat(64)}.example`), false);
});

Deno.test("pools stay inside a subnet and off its edges", () => {
  const subnet = parseCidr("192.0.2.0/24") as ReturnType<typeof parseCidr>;
  const range = parsePool("192.0.2.10 - 192.0.2.50", subnet as never);
  assertEquals(range?.start, "192.0.2.10");
  assertEquals(range?.end, "192.0.2.50");
  const asCidr = parsePool("192.0.2.64/26", subnet as never);
  assertEquals(asCidr?.start, "192.0.2.64");
  assertEquals(asCidr?.end, "192.0.2.127");
  for (
    const bad of [
      "198.51.100.10 - 198.51.100.20",
      "192.0.2.0 - 192.0.2.10",
      "192.0.2.0/26",
      "192.0.2.200 - 192.0.2.255",
      "192.0.2.50 - 192.0.2.10",
    ]
  ) {
    assertEquals(parsePool(bad, subnet as never), null, bad);
  }
  assertEquals(rangesOverlap(1, 5, 5, 9), true);
  assertEquals(rangesOverlap(1, 4, 5, 9), false);
});

Deno.test("target key lowercases the host", () => {
  assertEquals(
    targetKey("Web-1.Example.Test", 22, "root"),
    targetKey("web-1.example.test", 22, "root"),
  );
  assert(targetKey("192.0.2.10", 2222, "ops").includes("-p2222-"));
});

Deno.test("option rendering honours the allowlist and types", () => {
  const subnet = parseCidr("192.0.2.0/24") as ReturnType<typeof parseCidr>;
  assertEquals(
    renderOption({ name: "routers", value: ["192.0.2.1"] }, subnet as never),
    {
      name: "routers",
      data: "192.0.2.1",
    },
  );
  assertEquals(
    renderOption({
      name: "domain-name-servers",
      value: ["192.0.2.53", "198.51.100.53"],
    }),
    { name: "domain-name-servers", data: "192.0.2.53, 198.51.100.53" },
  );
  assertEquals(renderOption({ name: "domain-name", value: "example.test" }), {
    name: "domain-name",
    data: "example.test",
  });
  assertEquals(
    renderOption({
      name: "domain-search",
      value: ["a.example.test", "b.example.test"],
    }),
    { name: "domain-search", data: "a.example.test, b.example.test" },
  );
  assertEquals(renderOption({ name: "interface-mtu", value: 1500 }), {
    name: "interface-mtu",
    data: "1500",
  });
  assertEquals(
    renderOption({
      name: "classless-static-route",
      value: [{ prefix: "198.51.100.0/24", router: "192.0.2.1" }],
    }),
    { name: "classless-static-route", data: "198.51.100.0/24,192.0.2.1" },
  );
  assertThrows(
    () =>
      renderOption(
        { name: "routers", value: ["198.51.100.1"] },
        subnet as never,
      ),
    KeaInputError,
    "inside",
  );
  assertThrows(
    () => renderOption({ name: "made-up", value: "x" }),
    KeaInputError,
    "unknown",
  );
});
