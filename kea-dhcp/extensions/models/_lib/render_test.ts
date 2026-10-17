import { assert, assertEquals, assertThrows } from "jsr:@std/assert@1.0.19";
import { KeaInputError } from "./grammar.ts";
import { APPLY_PLAN, renderConfig, type RenderInput } from "./render.ts";

/** A minimal one-subnet input. */
function base(overrides: Partial<RenderInput> = {}): RenderInput {
  return {
    interfaces: ["eth1"],
    socket_type: "raw",
    valid_lifetime_s: 3600,
    options: [],
    subnets: [{
      id: 10,
      subnet: "192.0.2.0/24",
      pools: ["192.0.2.10 - 192.0.2.50"],
      reservations: [],
      options: [],
    }],
    ...overrides,
  };
}

/** Narrows the rendered config to its Dhcp4 body. */
function dhcp4(
  rendered: ReturnType<typeof renderConfig>,
): Record<string, unknown> {
  return (rendered.config as { Dhcp4: Record<string, unknown> }).Dhcp4;
}

Deno.test("apply plan arms before every write", () => {
  const arm = APPLY_PLAN.indexOf("arm");
  const write = APPLY_PLAN.indexOf("write");
  const set = APPLY_PLAN.indexOf("config-set");
  const snapshot = APPLY_PLAN.indexOf("snapshot");
  assert(snapshot < arm, "snapshot precedes arm");
  assert(arm < write, "arm precedes write");
  assert(write < set, "write precedes config-set");
});

Deno.test("one subnet and pool renders the expected shape", () => {
  const rendered = renderConfig(base());
  const body = dhcp4(rendered);
  assertEquals(body["valid-lifetime"], 3600);
  assertEquals(
    (body["interfaces-config"] as Record<string, unknown>).interfaces,
    ["eth1"],
  );
  assertEquals(
    (body["control-socket"] as Record<string, unknown>)["socket-name"],
    "/run/kea/kea4-ctrl-socket",
  );
  assertEquals(
    (body["lease-database"] as Record<string, unknown>).type,
    "memfile",
  );
  const subnets = body.subnet4 as Record<string, unknown>[];
  assertEquals(subnets.length, 1);
  assertEquals(subnets[0].id, 10);
  assertEquals(subnets[0].subnet, "192.0.2.0/24");
  assertEquals(subnets[0].pools, [{ pool: "192.0.2.10 - 192.0.2.50" }]);
  assert(rendered.json.endsWith("\n"));
});

Deno.test("reservations, options, relay and per-subnet lifetime render", () => {
  const rendered = renderConfig(base({
    options: [
      { name: "routers", value: ["192.0.2.1"] },
      { name: "domain-name-servers", value: ["192.0.2.53"] },
      { name: "domain-name", value: "example.test" },
    ],
    subnets: [{
      id: 20,
      subnet: "198.51.100.0/24",
      pools: ["198.51.100.100 - 198.51.100.200"],
      reservations: [
        {
          hw_address: "02:00:00:00:00:02",
          ip_address: "198.51.100.9",
          hostname: "printer",
        },
        { hw_address: "02:00:00:00:00:01", ip_address: "198.51.100.8" },
      ],
      options: [{ name: "ntp-servers", value: ["198.51.100.123"] }],
      valid_lifetime_s: 600,
      relay_addresses: ["203.0.113.1"],
    }],
  }));
  const subnet = (dhcp4(rendered).subnet4 as Record<string, unknown>[])[0];
  assertEquals(subnet["valid-lifetime"], 600);
  assertEquals(subnet.relay, { "ip-addresses": ["203.0.113.1"] });
  // Reservations are sorted by address.
  const reservations = subnet.reservations as Record<string, unknown>[];
  assertEquals(reservations.map((r) => r["ip-address"]), [
    "198.51.100.8",
    "198.51.100.9",
  ]);
  assertEquals(reservations[1].hostname, "printer");
  assertEquals(subnet["option-data"], [{
    name: "ntp-servers",
    data: "198.51.100.123",
  }]);
  // Global options are sorted by name.
  assertEquals(
    (dhcp4(rendered)["option-data"] as Record<string, unknown>[]).map((o) =>
      o.name
    ),
    ["domain-name", "domain-name-servers", "routers"],
  );
});

Deno.test("render is stable under input reordering", () => {
  const input = base({
    interfaces: ["eth3", "eth1"],
    options: [
      { name: "domain-name", value: "example.test" },
      { name: "routers", value: ["192.0.2.1"] },
    ],
    subnets: [
      {
        id: 2,
        subnet: "198.51.100.0/24",
        pools: ["198.51.100.10 - 198.51.100.20"],
        reservations: [],
        options: [],
      },
      {
        id: 1,
        subnet: "192.0.2.0/24",
        pools: ["192.0.2.20 - 192.0.2.30", "192.0.2.10 - 192.0.2.15"],
        reservations: [],
        options: [],
      },
    ],
  });
  const forward = renderConfig(input).json;
  const reordered: RenderInput = {
    ...input,
    interfaces: [...input.interfaces].reverse(),
    options: [...input.options].reverse(),
    subnets: [...input.subnets].reverse().map((subnet) => ({
      ...subnet,
      pools: [...subnet.pools].reverse(),
    })),
  };
  assertEquals(renderConfig(reordered).json, forward);
});

Deno.test("lease_api renders the hook library only with a path", () => {
  const rendered = renderConfig(base({
    lease_api: true,
    lease_cmds_path: "/usr/lib/kea/hooks/libdhcp_lease_cmds.so",
  }));
  assertEquals(dhcp4(rendered)["hooks-libraries"], [{
    library: "/usr/lib/kea/hooks/libdhcp_lease_cmds.so",
  }]);
  assertThrows(
    () => renderConfig(base({ lease_api: true })),
    KeaInputError,
    "lease_cmds_path",
  );
});

Deno.test("invalid combinations are refused", () => {
  const overlapping = base({
    subnets: [
      {
        id: 1,
        subnet: "192.0.2.0/24",
        pools: ["192.0.2.10 - 192.0.2.20"],
        reservations: [],
        options: [],
      },
      {
        id: 2,
        subnet: "192.0.2.128/25",
        pools: ["192.0.2.200 - 192.0.2.210"],
        reservations: [],
        options: [],
      },
    ],
  });
  assertThrows(() => renderConfig(overlapping), KeaInputError, "overlap");
  assertThrows(
    () =>
      renderConfig(base({
        subnets: [
          {
            id: 1,
            subnet: "192.0.2.0/24",
            pools: ["192.0.2.10 - 192.0.2.20"],
            reservations: [],
            options: [],
          },
          {
            id: 1,
            subnet: "198.51.100.0/24",
            pools: ["198.51.100.10 - 198.51.100.20"],
            reservations: [],
            options: [],
          },
        ],
      })),
    KeaInputError,
    "duplicate subnet id",
  );
  assertThrows(
    () =>
      renderConfig(base({
        subnets: [{
          id: 1,
          subnet: "192.0.2.0/24",
          pools: ["192.0.2.10 - 192.0.2.20"],
          reservations: [
            { hw_address: "02:00:00:00:00:01", ip_address: "192.0.2.5" },
            { hw_address: "02:00:00:00:00:01", ip_address: "192.0.2.6" },
          ],
          options: [],
        }],
      })),
    KeaInputError,
    "duplicate MAC",
  );
  assertThrows(
    () => renderConfig(base({ interfaces: ["*"] })),
    KeaInputError,
    "interface",
  );
  assertThrows(
    () =>
      renderConfig(base({
        valid_lifetime_s: 3600,
        renew_timer_s: 2000,
        rebind_timer_s: 1800,
      })),
    KeaInputError,
    "renew_timer_s",
  );
});

Deno.test("a reservation inside a pool is a warning, not an error", () => {
  const rendered = renderConfig(base({
    subnets: [{
      id: 1,
      subnet: "192.0.2.0/24",
      pools: ["192.0.2.10 - 192.0.2.50"],
      reservations: [
        { hw_address: "02:00:00:00:00:01", ip_address: "192.0.2.20" },
      ],
      options: [],
    }],
  }));
  assertEquals(rendered.warnings.length, 1);
  assert(rendered.warnings[0].includes("inside a pool"));
});
