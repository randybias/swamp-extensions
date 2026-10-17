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
      "::/0",
      "0.0.0.0/0",
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
  assertEquals(isDefaultRoute("0.0.0.0/0"), true);
  assertEquals(isDefaultRoute("::/0"), true);
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
