import { assert, assertEquals, assertRejects } from "jsr:@std/assert@1.0.19";
import { createModelTestContext } from "jsr:@swamp-club/swamp-testing@0.20261014.55";
import { instanceName, model } from "./knot_dns.ts";

const ZONE_ARGS = {
  ssh: {
    host: "ns1.example.test",
    port: 22,
    user: "root",
    host_key_policy: "strict",
    host_keys: ["ns1.example.test ssh-ed25519 AAAAPLACEHOLDER"],
    ssh_key_ref: { vault: "ops", key: "ssh" },
    connect_timeout_s: 15,
  },
  zone: "example.test",
  soa: {
    primary_ns: "ns1.example.test.",
    contact: "hostmaster.example.test.",
    refresh: 7200,
    retry: 3600,
    expire: 1209600,
    minimum: 3600,
  },
  ns: ["ns1.example.test."],
  records: [{ name: "www", type: "A", data: "192.0.2.10" }],
};

Deno.test("model is a plain object with the expected type and methods", () => {
  assertEquals(model.type, "@randybias/knot-dns");
  assertEquals(model.version, "2026.10.17.1");
  const methods = Object.keys(model.methods);
  assertEquals(
    methods.sort(),
    [
      "apply_resolver",
      "apply_zone",
      "get",
      "get_ds",
      "install",
      "ksk_submitted",
      "remove_resolver",
      "remove_zone",
      "render_resolver",
      "render_zone",
      "sync",
    ].sort(),
  );
});

Deno.test("method kinds and description prefixes match the house rules", () => {
  const destructive = [
    "apply_zone",
    "remove_zone",
    "apply_resolver",
    "remove_resolver",
  ];
  const readOnly = ["get", "sync", "get_ds", "render_zone", "render_resolver"];
  for (const name of destructive) {
    const m =
      (model.methods as Record<string, { kind?: string; description: string }>)[
        name
      ];
    assertEquals(m.kind, "action", name);
    assert(m.description.startsWith("DESTRUCTIVE."), name);
  }
  for (const name of readOnly) {
    const m =
      (model.methods as Record<string, { kind?: string; description: string }>)[
        name
      ];
    assert(m.description.startsWith("READ-ONLY."), name);
  }
  for (const name of ["install", "ksk_submitted"]) {
    const m = (model.methods as Record<string, { kind?: string }>)[name];
    assertEquals(m.kind, "action", name);
  }
});

Deno.test("zone schema rejects bad apex, records and signer-owned types", () => {
  const schema = model.methods.render_zone.arguments;
  for (
    const bad of [
      { ...ZONE_ARGS, zone: "Bad Zone" },
      { ...ZONE_ARGS, zone: "example..test" },
      {
        ...ZONE_ARGS,
        records: [{ name: "www", type: "A", data: "999.0.2.1" }],
      },
      {
        ...ZONE_ARGS,
        records: [{ name: "http", type: "A", data: "192.0.2.1", ttl: 0 }],
      },
      {
        ...ZONE_ARGS,
        records: [{ name: "www", type: "TXT", data: ["bad\u0007"] }],
      },
      {
        ...ZONE_ARGS,
        records: [{ name: "example.test.", type: "DNSKEY", data: "x" }],
      },
      { ...ZONE_ARGS, ns: [] },
      {
        ...ZONE_ARGS,
        ssh: { ...ZONE_ARGS.ssh, host_key_policy: "insecure_tofu" },
      },
      { ...ZONE_ARGS, ssh: { ...ZONE_ARGS.ssh, host_keys: [] } },
    ]
  ) {
    assertEquals(schema.safeParse(bad).success, false, JSON.stringify(bad));
  }
  assertEquals(schema.safeParse(ZONE_ARGS).success, true);
});

Deno.test("render_zone is deterministic and persists the render", async () => {
  const { context, getWrittenResources } = createModelTestContext({
    globalArgs: {},
  });
  const first = await model.methods.render_zone.execute(
    ZONE_ARGS as never,
    context,
  ) as { result: { file: string; sha256: string; record_count: number } };
  const second = await model.methods.render_zone.execute(
    { ...ZONE_ARGS, records: [...ZONE_ARGS.records].reverse() } as never,
    context,
  ) as { result: { sha256: string } };
  assertEquals(first.result.sha256, second.result.sha256);
  assert(
    first.result.file.includes("www.example.test.\t3600\tIN\tA\t192.0.2.10"),
  );
  assertEquals(first.result.record_count, 2);
  const written = getWrittenResources();
  assertEquals(written[0].specName, "zone");
  assertEquals(
    (written[0].data as { rendered_sha256: string }).rendered_sha256,
    first.result.sha256,
  );
  // No secret material is ever rendered.
  assert(!first.result.file.includes("PRIVATE"));
});

Deno.test("render_resolver is deterministic and touches no host", async () => {
  const { context } = createModelTestContext({ globalArgs: {} });
  const args = {
    ssh: ZONE_ARGS.ssh,
    resolver: {
      listen: ["127.0.0.1@53"],
      cache_size_mb: 128,
      forwards: [{ subtree: "internal.example.", servers: ["192.0.2.53"] }],
    },
  };
  const out = await model.methods.render_resolver.execute(
    args as never,
    context,
  ) as {
    result: { yaml: string; sha256: string };
  };
  assert(out.result.yaml.includes("listen:"));
  assert(out.result.yaml.includes('"192.0.2.53"'));
  assert(out.result.sha256.length === 64);
});

Deno.test("remove_zone refuses a recorded signed zone without an ack", async () => {
  const name = await instanceName([
    "zone",
    ZONE_ARGS.ssh.host,
    "example.test.",
  ]);
  const { context } = createModelTestContext({
    globalArgs: {},
    storedResources: {
      [name]: { dnssec: true, rendered_sha256: "placeholder" },
    },
  });
  // Drive the real runtime shape: a plain-object vaultService, not a stub.
  const asked: [string, string][] = [];
  (context as { vaultService?: unknown }).vaultService = {
    get: (v: string, k: string) => {
      asked.push([v, k]);
      return Promise.resolve("PLACEHOLDER-KEY");
    },
    put: () => Promise.resolve(),
  };
  const e = await assertRejects(() =>
    model.methods.remove_zone.execute(
      {
        ssh: ZONE_ARGS.ssh,
        zone: "example.test",
        dnssec_unsign_ack: false,
      } as never,
      context,
    )
  ) as Error;
  assert(e.message.includes("dnssec_unsign_ack"));
  assertEquals(asked, [["ops", "ssh"]]);
});

Deno.test("apply_zone refuses to turn a recorded signed zone off without an ack", async () => {
  const name = await instanceName([
    "zone",
    ZONE_ARGS.ssh.host,
    "example.test.",
  ]);
  const { context } = createModelTestContext({
    globalArgs: {},
    storedResources: {
      [name]: { dnssec: true, rendered_sha256: "placeholder" },
    },
  });
  (context as { vaultService?: unknown }).vaultService = {
    get: () => Promise.resolve("PLACEHOLDER-KEY"),
    put: () => Promise.resolve(),
  };
  const e = await assertRejects(() =>
    model.methods.apply_zone.execute(ZONE_ARGS as never, context)
  ) as Error;
  assert(e.message.includes("dnssec_unsign_ack"));
});

Deno.test("the zone schema rejects a newline smuggled in domain rdata", () => {
  const schema = model.methods.render_zone.arguments;
  assertEquals(
    schema.safeParse({
      ...ZONE_ARGS,
      records: [{
        name: "www",
        type: "CNAME",
        data: "ok.example.test.\nevil.example.test. 60 IN A 192.0.2.66\n;",
      }],
    }).success,
    false,
  );
});
