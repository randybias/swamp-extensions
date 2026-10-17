/**
 * Unit tests for host-key pin resolution and the pin record schema.
 *
 * @module
 */

import { assertEquals, assertThrows } from "jsr:@std/assert@1.0.19";
import { LocalRefusalError } from "./errors.ts";
import {
  assertPinsNamed,
  hostKeysName,
  HostKeysSchema,
  resolvePins,
} from "./hostkeys.ts";

const KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeKey";
const BARE = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQFakeKey";
const HOST_PORT = `[192.0.2.10]:2222 ${KEY}`;
const HOST_22 = `192.0.2.10 ${KEY}`;
const OTHER_HOST = `192.0.2.99 ${KEY}`;

Deno.test("hostKeysName keys a pin by host and port", () => {
  assertEquals(hostKeysName("192.0.2.10", 22), "hostkeys-192.0.2.10-22");
  assertEquals(
    hostKeysName("node1.example.com", 2222),
    "hostkeys-node1.example.com-2222",
  );
});

Deno.test("assertPinsNamed accepts any pin that names a host", () => {
  assertPinsNamed([HOST_PORT]);
  assertPinsNamed([HOST_22, OTHER_HOST]);
});

Deno.test(
  "assertPinsNamed refuses a bare key line: it would apply to every host",
  () => {
    assertThrows(
      () => assertPinsNamed([BARE]),
      LocalRefusalError,
      "must name its host",
    );
  },
);

Deno.test("assertPinsNamed refuses a malformed line", () => {
  assertThrows(
    () => assertPinsNamed(["not a key"]),
    LocalRefusalError,
    "not an ssh-keyscan line",
  );
});

Deno.test("resolvePins: strict uses supplied or stored pins and refuses none", () => {
  assertEquals(
    resolvePins({
      host: "192.0.2.10",
      port: 22,
      host_key_policy: "strict",
      supplied: [HOST_22],
    }),
    { hostKeys: [HOST_22], learn: false },
  );
  const stored = HostKeysSchema.parse({
    host: "192.0.2.10",
    port: 22,
    host_keys: [HOST_22],
    learned_at: "2030-01-01T00:00:00Z",
  });
  assertEquals(
    resolvePins({
      host: "192.0.2.10",
      port: 22,
      host_key_policy: "strict",
      stored,
    }),
    { hostKeys: [HOST_22], learn: false },
  );
  assertThrows(
    () =>
      resolvePins({
        host: "192.0.2.10",
        port: 22,
        host_key_policy: "strict",
      }),
    LocalRefusalError,
    "strict requires host_keys",
  );
});

Deno.test("resolvePins: insecure_tofu learns only with no pins", () => {
  assertEquals(
    resolvePins({
      host: "192.0.2.10",
      port: 22,
      host_key_policy: "insecure_tofu",
    }),
    { hostKeys: [], learn: true },
  );
  assertEquals(
    resolvePins({
      host: "192.0.2.10",
      port: 22,
      host_key_policy: "insecure_tofu",
      supplied: [HOST_22],
    }),
    { hostKeys: [HOST_22], learn: false },
  );
});

Deno.test("resolvePins: an explicit pin wins over a stored one", () => {
  const stored = HostKeysSchema.parse({
    host: "192.0.2.10",
    port: 22,
    host_keys: [OTHER_HOST],
    learned_at: "2030-01-01T00:00:00Z",
  });
  assertEquals(
    resolvePins({
      host: "192.0.2.10",
      port: 22,
      host_key_policy: "strict",
      supplied: [HOST_22, OTHER_HOST],
      stored,
    }),
    { hostKeys: [HOST_22, OTHER_HOST], learn: false },
  );
});

Deno.test("HostKeysSchema refuses a bare or malformed host key line", () => {
  for (const keys of [["nope"], [BARE], [KEY]]) {
    assertEquals(
      HostKeysSchema.safeParse({
        host: "192.0.2.10",
        port: 22,
        host_keys: keys,
        learned_at: "2030-01-01T00:00:00Z",
      }).success,
      false,
      keys.join(","),
    );
  }
});
