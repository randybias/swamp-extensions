import { assertEquals, assertThrows } from "jsr:@std/assert@1.0.19";
import {
  assertAddressPrefix,
  assertArmId,
  assertGuid,
  assertLocation,
  assertName,
  assertPortRange,
  assertPriority,
  assertResourceGroup,
  assertSshPublicKey,
  canonicalList,
  childInstanceName,
  GrammarError,
  isAddressPrefix,
  isGuid,
  isPortRange,
  resourceInstanceName,
} from "./validate.ts";

const GUID = "33333333-3333-3333-3333-333333333333";

Deno.test("GUID, name, resource group and location grammars", () => {
  assertEquals(isGuid(GUID), true);
  assertEquals(isGuid("nope"), false);
  assertGuid(GUID, "subscriptionId");
  for (
    const bad of [
      "a/b",
      "a b",
      "-leading",
      "has;semicolon",
      "x".repeat(65),
      "$(id)",
      "name`cmd`",
    ]
  ) {
    assertThrows(() => assertName(bad, "name"), GrammarError);
  }
  assertName("web-1.example", "name");
  for (const bad of ["", "a".repeat(91), "trailing.", "a/b", "a b"]) {
    assertThrows(() => assertResourceGroup(bad), GrammarError);
  }
  assertResourceGroup("rg-1.example");
  assertLocation("eastus2");
  for (const bad of ["EastUS", "east us", "east/us", ""]) {
    assertThrows(() => assertLocation(bad), GrammarError);
  }
});

Deno.test("ARM id and SSH public key grammars", () => {
  assertArmId(
    `/subscriptions/${GUID}/resourceGroups/rg/providers/Microsoft.Network/networkInterfaces/nic`,
    "networkInterfaceId",
  );
  for (
    const bad of [
      "relative/path",
      `/subscriptions/${GUID}/resourceGroups/../providers/x`,
      "/subscriptions/$(id)",
      "/subscriptions/a b",
    ]
  ) {
    assertThrows(() => assertArmId(bad, "id"), GrammarError);
  }
  assertSshPublicKey(
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeKey user@example",
  );
  assertSshPublicKey("ssh-rsa AAAAB3NzaC1yc2EAAAADAQABFake");
  for (
    const bad of [
      "ssh-ed25519",
      'command="x" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeKey',
      "ssh-ed25519 ",
      "",
    ]
  ) {
    assertThrows(() => assertSshPublicKey(bad), GrammarError);
  }
});

Deno.test("address prefix and port grammars", () => {
  for (
    const good of [
      "*",
      "0.0.0.0/0",
      "192.0.2.0/24",
      "198.51.100.10/32",
      "2001:db8::/32",
      "VirtualNetwork",
      "Internet",
      "AzureLoadBalancer",
    ]
  ) {
    assertEquals(isAddressPrefix(good), true, good);
    assertAddressPrefix(good, "source");
  }
  for (
    const bad of ["999.0.0.0/24", "192.0.2.0/33", "a b", "$(id)", "192.0.2.0/"]
  ) {
    assertEquals(isAddressPrefix(bad), false, bad);
    assertThrows(() => assertAddressPrefix(bad, "source"), GrammarError);
  }
  for (const good of ["*", "22", "443", "1024-65535"]) {
    assertEquals(isPortRange(good), true, good);
    assertPortRange(good, "port");
  }
  for (const bad of ["70000", "100-99", "a", "-1", "1;2"]) {
    assertEquals(isPortRange(bad), false, bad);
    assertThrows(() => assertPortRange(bad, "port"), GrammarError);
  }
  assertPriority(100);
  assertPriority(4096);
  for (const bad of [99, 4097, 1.5]) {
    assertThrows(() => assertPriority(bad), GrammarError);
  }
});

Deno.test("instance names are unambiguous and length-prefixed", () => {
  const a = resourceInstanceName("a", "22", "x-3-y");
  const b = resourceInstanceName("a-22-x", "3", "y");
  assertEquals(a === b, false, `${a} must differ from ${b}`);
  assertEquals(
    childInstanceName(GUID, "rg", "nsg", "rule"),
    `${resourceInstanceName(GUID, "rg", "nsg")}-c4-rule`,
  );
  assertEquals(canonicalList(["b", "a"]), canonicalList(["a", "b"]));
});
