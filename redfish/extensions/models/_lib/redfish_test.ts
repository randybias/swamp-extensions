import { assertEquals, assertThrows } from "jsr:@std/assert@1.0.19";
import { RedfishError } from "./http.ts";
import {
  allowableBootTargets,
  BOOT_ENABLED,
  bootBody,
  desiredPowerState,
  isPowerNoop,
  isSystemId,
  normalizeEndpoint,
  parseSystem,
  RESET_TYPES,
  resetAction,
  resetBody,
  resolveOdata,
} from "./redfish.ts";

const SYSTEM = JSON.parse(
  await Deno.readTextFile(new URL("./fixtures/system.json", import.meta.url)),
) as Record<string, unknown>;

Deno.test("normalizeEndpoint accepts only an https origin", () => {
  assertEquals(
    normalizeEndpoint("https://bmc.example.com"),
    "https://bmc.example.com",
  );
  assertEquals(
    normalizeEndpoint("https://bmc.example.com:8443/"),
    "https://bmc.example.com:8443",
  );
  for (
    const bad of [
      "http://bmc.example.com",
      "https://bmc.example.com/redfish/v1",
      "https://bmc.example.com?a=1",
      "https://bmc.example.com#x",
      ["https://user:", "pass", "@bmc.example.com"].join(""),
      "not a url",
      "ftp://bmc.example.com",
    ]
  ) {
    assertThrows(() => normalizeEndpoint(bad), RedfishError, undefined, bad);
  }
});

Deno.test("resolveOdata keeps paths on the endpoint origin", () => {
  const origin = "https://bmc.example.com";
  assertEquals(
    resolveOdata(origin, "/redfish/v1/Systems/1"),
    "https://bmc.example.com/redfish/v1/Systems/1",
  );
  assertEquals(
    resolveOdata(origin, "https://bmc.example.com:443/x"),
    "https://bmc.example.com/x",
  );
  for (
    const bad of [
      "https://evil.example.com/redfish/v1",
      "http://bmc.example.com/x",
      "javascript:alert(1)",
      "//evil.example.com/x",
    ]
  ) {
    assertThrows(() => resolveOdata(origin, bad), RedfishError, undefined, bad);
  }
});

Deno.test("system id grammar", () => {
  assertEquals(isSystemId("437XR1138R2"), true);
  assertEquals(isSystemId("System.Embedded.1"), true);
  assertEquals(isSystemId("1"), true);
  for (const bad of ["", "../1", "a/b", "a b", "a;b", "-x", "x".repeat(129)]) {
    assertEquals(isSystemId(bad), false, bad);
  }
});

Deno.test("parseSystem maps the allowlist from DMTF-shaped JSON", () => {
  const s = parseSystem(
    SYSTEM,
    "https://bmc.example.com",
    "2026-10-17T00:00:00.000Z",
    "present",
    'W/"etag-1"',
  );
  assertEquals(s.system_id, "437XR1138R2");
  assertEquals(s.name, "WebFrontEnd483");
  assertEquals(s.manufacturer, "Contoso");
  assertEquals(s.model, "3500RX");
  assertEquals(s.serial_number, "PLACEHOLDER-SERIAL-0001");
  assertEquals(s.power_state, "On");
  assertEquals(s.health, "OK");
  assertEquals(s.health_rollup, "OK");
  assertEquals(s.boot_target, "Pxe");
  assertEquals(s.boot_enabled, "Once");
  assertEquals(s.etag, 'W/"etag-1"');
  assertEquals(s.status, "present");
  assertEquals(s.observed_at, "2026-10-17T00:00:00.000Z");
  // No credential field is read or stored.
  assertEquals(JSON.stringify(s).toLowerCase().includes("password"), false);
});

Deno.test("reset action and boot allowables come from the resource", () => {
  assertEquals(
    resetAction(SYSTEM).target,
    "/redfish/v1/Systems/437XR1138R2/Actions/ComputerSystem.Reset",
  );
  assertEquals(resetAction(SYSTEM).allowable, [...RESET_TYPES]);
  assertEquals(allowableBootTargets(SYSTEM), [
    "None",
    "Pxe",
    "Hdd",
    "Cd",
    "BiosSetup",
    "Usb",
  ]);
  assertEquals(resetAction({}).target, undefined);
});

Deno.test("power mapping and idempotency", () => {
  assertEquals(desiredPowerState("On", "Off"), "On");
  assertEquals(desiredPowerState("ForceOff", "On"), "Off");
  assertEquals(desiredPowerState("GracefulShutdown", "On"), "Off");
  assertEquals(desiredPowerState("ForceRestart", "On"), "On");
  assertEquals(desiredPowerState("PushPowerButton", "On"), "Off");
  assertEquals(desiredPowerState("PushPowerButton", "Off"), "On");
  assertEquals(isPowerNoop("On", "On"), true);
  assertEquals(isPowerNoop("On", "Off"), false);
  assertEquals(isPowerNoop("ForceOff", "Off"), true);
  assertEquals(isPowerNoop("GracefulShutdown", "Off"), true);
  assertEquals(isPowerNoop("ForceRestart", "On"), false);
  assertEquals(isPowerNoop("PushPowerButton", "On"), false);
});

Deno.test("reset and boot bodies", () => {
  assertEquals(resetBody("ForceOff"), { ResetType: "ForceOff" });
  assertEquals(bootBody("Pxe", "Once"), {
    Boot: {
      BootSourceOverrideTarget: "Pxe",
      BootSourceOverrideEnabled: "Once",
    },
  });
  assertEquals(bootBody("Pxe", "Disabled"), {
    Boot: {
      BootSourceOverrideTarget: "None",
      BootSourceOverrideEnabled: "Disabled",
    },
  });
  assertEquals([...BOOT_ENABLED], ["Once", "Continuous", "Disabled"]);
});
