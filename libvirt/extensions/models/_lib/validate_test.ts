import { assertEquals, assertThrows } from "jsr:@std/assert@1.0.19";
import {
  assertIpv4,
  assertMac,
  assertName,
  assertUri,
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

Deno.test("uri: accepted libvirt schemes, no shell metacharacters", () => {
  for (
    const good of [
      "qemu:///system",
      "qemu:///session",
      "qemu+ssh://root@192.0.2.10/system",
      "qemu+tls://hv.example.com/system",
      "test:///default",
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
      "qemu:///" + "x".repeat(240),
    ]
  ) {
    assertThrows(() => assertUri(bad), LibvirtConfigError);
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
