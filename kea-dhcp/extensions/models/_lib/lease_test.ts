import { assert, assertEquals, assertThrows } from "jsr:@std/assert@1.0.19";
import { KeaInputError } from "./grammar.ts";
import {
  filterLeases,
  parseLeaseCsv,
  parseLeaseCsvFiles,
  parseLeaseJson,
} from "./lease.ts";

const HEADER =
  "address,hwaddr,client_id,valid_lifetime,expire,subnet_id,fqdn_fwd,fqdn_rev,hostname,state";

Deno.test("parseLeaseCsv reads rows, skips the header and maps state", () => {
  const leases = parseLeaseCsv(
    `${HEADER}\n` +
      "192.0.2.10,02:00:00:00:00:01,,3600,2000000000,10,0,0,web-1,0\n" +
      "192.0.2.11,02:00:00:00:00:02,,3600,2000000010,10,0,0,,1\n" +
      "# comment\n",
  );
  assertEquals(leases.length, 2);
  assertEquals(leases[0].ip_address, "192.0.2.10");
  assertEquals(leases[0].hw_address, "02:00:00:00:00:01");
  assertEquals(leases[0].hostname, "web-1");
  assertEquals(leases[0].subnet_id, 10);
  assertEquals(leases[0].state, "default");
  assertEquals(leases[1].state, "declined");
  assertEquals(leases[1].hostname, undefined);
});

Deno.test("parseLeaseCsvFiles collapses the append log and drops expired rows", () => {
  const first =
    `${HEADER}\n192.0.2.10,02:00:00:00:00:01,,3600,2000000000,10,0,0,web-1,0\n`;
  const second =
    `${HEADER}\n192.0.2.10,02:00:00:00:00:01,,3600,2100000000,10,0,0,web-1,0\n` +
    "192.0.2.11,02:00:00:00:00:02,,3600,1000000000,10,0,0,,0\n";
  const leases = parseLeaseCsvFiles([first, second], 1_900_000_000);
  assertEquals(leases.length, 1);
  assertEquals(leases[0].ip_address, "192.0.2.10");
  // The later row wins.
  assertEquals(Date.parse(leases[0].expires_at), 2_100_000_000_000);
});

Deno.test("parseLeaseJson reads a lease_cmds answer", () => {
  const leases = parseLeaseJson({
    result: 0,
    arguments: {
      leases: [
        {
          "ip-address": "192.0.2.10",
          "hw-address": "02:00:00:00:00:01",
          "subnet-id": 10,
          cltt: 1_900_000_000,
          hostname: "web-1",
        },
      ],
    },
  });
  assertEquals(leases.length, 1);
  assertEquals(leases[0].ip_address, "192.0.2.10");
  assertEquals(leases[0].expires_at, new Date(1_900_003_600_000).toISOString());
  assertThrows(() => parseLeaseJson({ result: 0 }), KeaInputError, "leases");
});

Deno.test("filterLeases matches subnet, address and MAC", () => {
  const leases = parseLeaseCsv(
    `${HEADER}\n` +
      "192.0.2.10,02:00:00:00:00:01,,3600,2000000000,10,0,0,,0\n" +
      "198.51.100.10,02:00:00:00:00:02,,3600,2000000000,20,0,0,,0\n",
  );
  assertEquals(filterLeases(leases, { subnet_id: 20 }).length, 1);
  assertEquals(filterLeases(leases, { ip_address: "192.0.2.10" }).length, 1);
  assertEquals(
    filterLeases(leases, { hw_address: "02:00:00:00:00:02" }).length,
    1,
  );
  assertEquals(filterLeases(leases, {}).length, 2);
  assert(filterLeases(leases, { subnet_id: 99 }).length === 0);
});
