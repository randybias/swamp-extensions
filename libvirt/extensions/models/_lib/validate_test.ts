import { assertEquals, assertThrows } from "jsr:@std/assert@1.0.19";
import {
  ARCHES,
  assertArch,
  assertDnsName,
  assertIpv4,
  assertMac,
  assertName,
  assertUri,
  DNS_NAME_RE,
  isIpv4,
  LibvirtConfigError,
  NAME_RE,
  URI_RE,
} from "./validate.ts";

Deno.test("name: allowlisted object names only", () => {
  for (const good of ["default", "net-a", "golden.vol", "node_1"]) {
    assertEquals(NAME_RE.test(good), true, good);
    assertName(good);
  }
  for (
    const bad of [
      "",
      "-lead",
      "net a",
      "net;id",
      "net`id`",
      "net$(id)",
      "net\nroot",
      "../etc",
      "x".repeat(64),
    ]
  ) {
    assertThrows(() => assertName(bad), LibvirtConfigError);
  }
});

Deno.test("uri: local schemes only, no nested ssh, userinfo or query", () => {
  for (
    const good of [
      "qemu:///system",
      "qemu:///session",
      "qemu:///",
      "test:///default",
      "lxc:///",
    ]
  ) {
    assertEquals(URI_RE.test(good), true, good);
    assertUri(good);
  }
  for (
    const bad of [
      "qemu:///system; id",
      "qemu:///system && id",
      "http://example.com",
      "qemu:///system`id`",
      "",
      // A remote URI would open a second SSH/TLS session outside our policy.
      "qemu+ssh://root@192.0.2.10/system",
      "qemu+tls://hv.example.com/system",
      "xen+ssh://root@192.0.2.10/",
      // Userinfo and query parameters are refused too.
      "qemu://root@host/system",
      "qemu:///system?command=/bin/sh",
      "qemu:///system?keyfile=/tmp/key",
      "qemu:///system?no_verify=1",
      "qemu:///" + "x".repeat(240),
    ]
  ) {
    assertThrows(() => assertUri(bad), LibvirtConfigError);
  }
});

Deno.test("arch: only the accepted guest architectures", () => {
  for (const good of ARCHES) assertArch(good);
  for (const bad of ["x86_64'> <script/>", "", "arm64", "amd64"]) {
    assertThrows(() => assertArch(bad), LibvirtConfigError);
  }
});

Deno.test("dns name: no quote or element injection", () => {
  for (const good of ["example.test", "a.b.example.com", "host-1"]) {
    assertEquals(DNS_NAME_RE.test(good), true, good);
    assertDnsName(good);
  }
  for (const bad of ["a'b", "a b", "a<b>", "-lead", "trail-", ""]) {
    assertThrows(() => assertDnsName(bad), LibvirtConfigError);
  }
});

Deno.test("addresses: IPv4 and MAC grammars", () => {
  for (const good of ["192.0.2.10", "198.51.100.1", "203.0.113.255"]) {
    assertEquals(isIpv4(good), true, good);
    assertIpv4(good);
  }
  for (const bad of ["999.0.0.1", "192.0.2", "192.0.2.10/24", "a.b.c.d"]) {
    assertThrows(() => assertIpv4(bad), LibvirtConfigError);
  }
  assertMac("02:00:00:00:00:01");
  assertThrows(
    () => assertMac("02:00:00:00:00"),
    LibvirtConfigError,
  );
  assertThrows(() => assertMac("not-a-mac"), LibvirtConfigError);
});
