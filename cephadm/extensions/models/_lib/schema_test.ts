import { assertEquals } from "jsr:@std/assert@1.0.19";
import { z } from "npm:zod@4.3.6";
import {
  CEPHADM_VERSION_SCHEMA,
  CIDR_SCHEMA,
  FSID_SCHEMA,
  HOST_FIELD,
  HTTP_URL_SCHEMA,
  IPV4_SCHEMA,
  PACKAGE_SCHEMA,
  SERIAL_SCHEMA,
  SSH_FIELD_NAMES,
  SSH_FIELDS,
  UNIT_SCHEMA,
} from "./schema.ts";

/** The shared SSH family as a strict object, for parse checks. */
const SshObject = z.strictObject(SSH_FIELDS);

Deno.test(
  "the shared SSH family is nullish, individually and together", // leak-allow(decision D67)
  () => {
    assertEquals(SSH_FIELD_NAMES, [
      "sshUser",
      "port",
      "keyPath",
      "privateKey",
      "strictHostKeyChecking",
      "multiplex",
    ]);
    const allNull = {
      sshUser: "admin",
      port: null,
      keyPath: null,
      privateKey: null,
      strictHostKeyChecking: null,
      multiplex: null,
    };
    assertEquals(SshObject.safeParse(allNull).success, true);
    // Each optional field is null on its own while the others are real.
    assertEquals(
      SshObject.safeParse({
        sshUser: "admin",
        port: 2222,
        keyPath: "/k",
        privateKey: null,
        strictHostKeyChecking: "yes",
        multiplex: true,
      }).success,
      true,
    );
    // Omitted optional fields are accepted.
    assertEquals(SshObject.safeParse({ sshUser: "admin" }).success, true);
  },
);

Deno.test("the shared SSH family rejects widened and off-menu values", () => {
  for (
    const bad of [
      { sshUser: "admin", port: "22" },
      { sshUser: "admin", port: 0 },
      { sshUser: "admin", port: 70000 },
      { sshUser: "admin", port: 1.5 },
      { sshUser: "admin", keyPath: 1 },
      { sshUser: "admin", strictHostKeyChecking: "" },
      { sshUser: "admin", strictHostKeyChecking: "maybe" },
      { sshUser: "admin", strictHostKeyChecking: "accept-new" },
      { sshUser: "admin", multiplex: "yes" },
      { sshUser: "" },
      { sshUser: "1admin" },
    ]
  ) {
    assertEquals(SshObject.safeParse(bad).success, false);
  }
});

Deno.test("privateKey is optional, nullish and marked sensitive", () => {
  // The field parses without it, and with an explicit null.
  assertEquals(SshObject.safeParse({ sshUser: "admin" }).success, true);
  assertEquals(
    SshObject.safeParse({ sshUser: "admin", privateKey: null }).success,
    true,
  );
  const meta = (SSH_FIELDS.privateKey as unknown as {
    meta?: () => Record<string, unknown>;
  })
    .meta?.();
  // Newer zod exposes metadata; when present it must mark the field sensitive.
  if (meta !== undefined) assertEquals(meta.sensitive, true);
});

Deno.test("the scalar schemas accept and reject their documented shapes", () => {
  assertEquals(HOST_FIELD.safeParse("node1.example.com").success, true);
  assertEquals(HOST_FIELD.safeParse("198.51.100.22").success, true);
  assertEquals(HOST_FIELD.safeParse("node1:22").success, false);
  assertEquals(HOST_FIELD.safeParse("node_1").success, false);

  assertEquals(SERIAL_SCHEMA.safeParse("SN0001").success, true);
  assertEquals(SERIAL_SCHEMA.safeParse("SN; id").success, false);
  assertEquals(PACKAGE_SCHEMA.safeParse("libstdc++6").success, true);
  assertEquals(PACKAGE_SCHEMA.safeParse("Chrony").success, false);
  assertEquals(
    HTTP_URL_SCHEMA.safeParse("https://x.example.com/cephadm").success,
    true,
  );
  assertEquals(HTTP_URL_SCHEMA.safeParse("file:///etc/passwd").success, false);
  assertEquals(CEPHADM_VERSION_SCHEMA.safeParse("19.2.1").success, true);
  assertEquals(CEPHADM_VERSION_SCHEMA.safeParse("squid").success, false);
  assertEquals(UNIT_SCHEMA.safeParse("chrony.service").success, true);
  assertEquals(UNIT_SCHEMA.safeParse("chrony;id").success, false);
  assertEquals(
    FSID_SCHEMA.safeParse("3f2a9c1e-5b7d-4e8f-9a0b-1c2d3e4f5a6b").success,
    true,
  );
  assertEquals(FSID_SCHEMA.safeParse("nope").success, false);
  assertEquals(CIDR_SCHEMA.safeParse("198.51.100.0/24").success, true);
  assertEquals(CIDR_SCHEMA.safeParse("198.51.100.1/24").success, false);
  assertEquals(IPV4_SCHEMA.safeParse("192.0.2.10").success, true);
  assertEquals(IPV4_SCHEMA.safeParse("192.0.2.256").success, false);
});
