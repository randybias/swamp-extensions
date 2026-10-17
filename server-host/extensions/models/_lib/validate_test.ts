import { assertEquals, assertThrows } from "jsr:@std/assert@1.0.19";
import {
  assertAuthorizedKey,
  assertCidr,
  assertPackage,
  assertSysctlKey,
  assertSysctlValue,
  assertTimezone,
  assertUser,
  dedupeSorted,
  dedupeSortedNumbers,
  HostConfigError,
  isCidr,
  isDefaultRoute,
  isEffectivelyAnywhere,
  isPort,
} from "./validate.ts";

const KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeKeyMaterialForTests";

Deno.test("cidr: accepts documentation ranges and both families, rejects junk", () => {
  for (
    const good of [
      "192.0.2.0/24",
      "198.51.100.0/24",
      "203.0.113.128/25",
      "192.0.2.128/26",
      "2001:db8::/32",
      "::/0", // leak-allow(address-space halves are the case under test)
      "0.0.0.0/0", // leak-allow(address-space halves are the case under test)
    ]
  ) {
    assertEquals(isCidr(good), true, good);
    assertCidr(good);
  }
  for (
    const bad of [
      "192.0.2.0",
      "999.0.0.0/24",
      "192.0.2.0/33",
      "2001:db8::/129",
      "192.0.2.0/24; rm -rf /",
      "",
      "example.com/24",
    ]
  ) {
    assertEquals(isCidr(bad), false, bad);
    assertThrows(() => assertCidr(bad), HostConfigError);
  }
  assertEquals(isDefaultRoute("0.0.0.0/0"), true); // leak-allow(address-space halves are the case under test)
  assertEquals(isDefaultRoute("::/0"), true); // leak-allow(address-space halves are the case under test)
  assertEquals(isDefaultRoute("192.0.2.0/24"), false);
});

Deno.test("port: bounds are enforced", () => {
  for (const good of [1, 22, 443, 65535]) assertEquals(isPort(good), true);
  for (const bad of [0, -1, 65536, 1.5, Number.NaN]) {
    assertEquals(isPort(bad), false, String(bad));
  }
});

Deno.test("package: allowlisted names only", () => {
  for (const good of ["curl", "openssh-server", "python3.12", "libfoo:amd64"]) {
    assertPackage(good);
  }
  for (
    const bad of [
      "curl; rm -rf /",
      "curl && whoami",
      "curl`id`",
      "curl$IFS",
      "curl\nnc",
      "../../bin/sh",
      "",
    ]
  ) {
    assertThrows(() => assertPackage(bad), HostConfigError, bad);
  }
});

Deno.test("user: conventional POSIX names only", () => {
  for (const good of ["ops", "rocky_admin", "a", "_svc"]) assertUser(good);
  for (const bad of ["Ops", "ops;id", "ops root", "1ops", "", "ops\n"]) {
    assertThrows(() => assertUser(bad), HostConfigError, bad);
  }
});

Deno.test("sysctl: dotted keys and shell-free values", () => {
  for (
    const good of [
      "net.ipv4.ip_forward",
      "vm.swappiness",
      "kernel.dmesg_restrict",
    ]
  ) {
    assertSysctlKey(good);
  }
  for (const bad of ["net..ipv4", "net ipv4", "net.ipv4;id", "Net.ipv4", ""]) {
    assertThrows(() => assertSysctlKey(bad), HostConfigError, bad);
  }
  for (const good of ["1", "0", "yes", "200M", "1 2 3"]) {
    assertSysctlValue(good);
  }
  for (const bad of ["1;id", "1&&id", "1`id`", "1\nnet", ""]) {
    assertThrows(() => assertSysctlValue(bad), HostConfigError, bad);
  }
});

Deno.test("timezone: region/city and UTC only", () => {
  for (const good of ["UTC", "Etc/UTC", "America/New_York", "Europe/Berlin"]) {
    assertTimezone(good);
  }
  for (const bad of ["UTC;id", "../etc/passwd", "UTC/", "/UTC", "UTC UTC"]) {
    assertThrows(() => assertTimezone(bad), HostConfigError, bad);
  }
});

Deno.test("authorized key: one key line, no options prefix, no newline", () => {
  assertAuthorizedKey(KEY);
  assertAuthorizedKey(`${KEY} ops@example.com`);
  assertThrows(() => assertAuthorizedKey(`${KEY}\nssh-rsa AAAAB3NzaC1yc2E`));
  assertThrows(() => assertAuthorizedKey('command="id" ssh-ed25519 AAAA'));
  assertThrows(() => assertAuthorizedKey("ssh-ed25519 not-base64!"));
  assertThrows(() => assertAuthorizedKey(""));
});

Deno.test("dedupe: stable sorted sets", () => {
  assertEquals(dedupeSorted(["b", "a", "b", "c"]), ["a", "b", "c"]);
  assertEquals(dedupeSortedNumbers([443, 80, 443, 22]), [22, 80, 443]);
});

Deno.test("isDefaultRoute: any numerically zero prefix is anywhere, in any spelling", () => {
  for (
    const anywhere of [
      "0.0.0.0/0", // leak-allow(address-space halves are the case under test)
      "::/0", // leak-allow(address-space halves are the case under test)
      "0:0:0:0:0:0:0:0/0", // leak-allow(expanded IPv6 zero is the case under test)
      "0000:0000:0000:0000:0000:0000:0000:0000/0", // leak-allow(zero-padded IPv6 zero is the case under test)
      "::/00", // leak-allow(address-space halves are the case under test)
      "0.0.0.0/00", // leak-allow(address-space halves are the case under test)
      "192.0.2.0/0",
      "2001:db8::/000",
    ]
  ) {
    assertEquals(isCidr(anywhere), true, anywhere);
    assertEquals(isDefaultRoute(anywhere), true, anywhere);
  }
  for (const narrow of ["192.0.2.0/24", "2001:db8::/32", "::/1", "0.0.0.0/1"]) { // leak-allow(address-space halves are the case under test)
    assertEquals(isDefaultRoute(narrow), false, narrow);
  }
  // Not a CIDR at all: never reported as a default route.
  assertEquals(isDefaultRoute("not-a-cidr/0"), false);
});

Deno.test("isCidr: IPv6 follows a strict grammar and refuses injected characters", () => {
  for (
    const ok of [
      "2001:db8::1/64",
      "2001:db8::/32",
      "::1/128",
      "::ffff:192.0.2.1/128", // leak-allow(grammar edge case under test)
      "2001:DB8:0:0:0:0:0:1/64",
      "2001:db8::/10",
    ]
  ) {
    assertEquals(isCidr(ok), true, ok);
  }
  for (
    const bad of [
      "2001:db8::1]/x/64",
      "::1]#x/64",
      "[2001:db8::1]/64",
      "2001:db8::1 /64",
      "2001:db8::1@x/64",
      "2001:db8::1/129",
      "2001::db8::1/64",
      "1:2:3:4:5:6:7/64", // leak-allow(grammar edge case under test)
      "1:2:3:4:5:6:7:8:9/64", // leak-allow(grammar edge case under test)
      "12345::/64",
      ":::/0",
      "::192.0.2.1:1/64", // leak-allow(grammar edge case under test)
      "192.0.2.1::/64", // leak-allow(grammar edge case under test)
      "2001:db8::1%eth0/64",
      "2001:db8::1/64\n",
      "2001:db8::1/6 4",
    ]
  ) {
    assertEquals(isCidr(bad), false, JSON.stringify(bad));
  }
});

Deno.test("isEffectivelyAnywhere: wide networks and covering unions, but not ordinary ranges", () => {
  for (
    const wide of [
      ["0.0.0.0/1", "128.0.0.0/1"], // leak-allow(address-space halves are the case under test)
      ["::/1", "8000::/1"], // leak-allow(address-space halves are the case under test)
      ["0.0.0.0/2", "64.0.0.0/2", "128.0.0.0/2", "192.0.0.0/2"], // leak-allow(address-space halves are the case under test)
      ["0.0.0.0/7"], // leak-allow(address-space halves are the case under test)
      ["2000::/15"], // leak-allow(address-space halves are the case under test)
      ["192.0.2.0/24", "0.0.0.0/0"], // leak-allow(address-space halves are the case under test)
    ]
  ) {
    assertEquals(isEffectivelyAnywhere(wide), true, wide.join());
  }
  for (
    const fine of [
      ["203.0.113.0/8"],
      ["192.0.2.0/24", "198.51.100.0/24"],
      ["2001:db8::/32"],
      ["0.0.0.0/8", "128.0.0.0/8"], // leak-allow(address-space halves are the case under test)
      [],
    ]
  ) {
    assertEquals(isEffectivelyAnywhere(fine), false, fine.join());
  }
});
