import { assert, assertEquals, assertRejects } from "jsr:@std/assert@1.0.19";
import { createModelTestContext } from "jsr:@swamp-club/swamp-testing@0.20261014.55";
import { instanceName, model } from "./knot_dns.ts";
import { applyResolverScript } from "./_lib/scripts.ts";
import { fakeHost } from "./_lib/test_support.ts";

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
  assertEquals(model.version, "2026.10.17.2");
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
  // The refusal happens before the transport is built, so the vault is never
  // read for a call the method rejects.
  assertEquals(asked, []);
});

Deno.test("remove_zone refuses to purge keys for a zone it never applied", async () => {
  const host = fakeHost(() => ({}));
  try {
    // (a) No record at all: an apex this model does not manage.
    const bare = vaultContext();
    const e1 = await assertRejects(() =>
      model.methods.remove_zone.execute(
        {
          ssh: ZONE_ARGS.ssh,
          zone: "other.example.test",
          purge_keys_ack: true,
        } as never,
        bare.context,
      )
    ) as { code?: string; message: string };
    assertEquals(e1.code, "invalid_input");
    assert(e1.message.includes("purge_keys_ack"));
    // (b) A render-only record: the zone was never applied on the host.
    const name = await instanceName([
      "zone",
      ZONE_ARGS.ssh.host,
      "example.test.",
    ]);
    const rendered = createModelTestContext({
      globalArgs: {},
      storedResources: {
        [name]: { status: "rendered", rendered_sha256: "placeholder" },
      },
    });
    (rendered.context as { vaultService?: unknown }).vaultService = {
      get: () => Promise.resolve("PLACEHOLDER-KEY"),
      put: () => Promise.resolve(),
    };
    const e2 = await assertRejects(() =>
      model.methods.remove_zone.execute(
        {
          ssh: ZONE_ARGS.ssh,
          zone: "example.test",
          purge_keys_ack: true,
        } as never,
        rendered.context,
      )
    ) as { code?: string };
    assertEquals(e2.code, "invalid_input");
    // Fail before any host work: no keymgr, no script.
    assertEquals(host.commands.length, 0);
  } finally {
    host.restore();
  }
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

Deno.test("apply_zone fails closed when the recorded zones cannot be read", async () => {
  const { context } = createModelTestContext({ globalArgs: {} });
  Object.assign(context, {
    vaultService: {
      get: () => Promise.resolve("PLACEHOLDER-KEY"),
      put: () => Promise.resolve(),
    },
    readModelData: () => Promise.reject(new Error("store offline")),
  });
  const e = await assertRejects(() =>
    model.methods.apply_zone.execute(
      { ...ZONE_ARGS, listen: ["192.0.2.53"] } as never,
      context,
    )
  ) as Error;
  assert(e.message.includes("could not read the recorded zones"));
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

const RESOLVER_ARGS = {
  ssh: ZONE_ARGS.ssh,
  resolver: {
    listen: ["127.0.0.3@53"],
    forwards: [{
      subtree: "example.test.",
      servers: ["127.0.0.1"],
      authoritative: true,
      dnssec: false,
    }],
  },
};

/** A context whose vault answers the SSH key. */
function vaultContext() {
  const c = createModelTestContext({ globalArgs: {} });
  (c.context as { vaultService?: unknown }).vaultService = {
    get: () => Promise.resolve("PLACEHOLDER-KEY"),
    put: () => Promise.resolve(),
  };
  return c;
}

Deno.test("apply_resolver tests a name the upstream serves, and records what it did", async () => {
  const host = fakeHost((command) =>
    command.includes("50-managed-*.conf")
      ? { stdout: "a.example.test.\nb.example.test.\n" }
      : command.includes("kresctl")
      ? { stdout: "changed=yes\n" }
      : {}
  );
  try {
    const c = vaultContext();
    const out = await model.methods.apply_resolver.execute(
      RESOLVER_ARGS as never,
      c.context,
    ) as { result: { changed: boolean } };
    assertEquals(out.result.changed, true);
    // The script queries the served child, not the forwarded parent (which
    // the upstream REFUSES), so a correct config is not rolled back.
    const script = host.commands.find((cmd) => cmd.includes("kresctl"))!;
    assert(script.includes("a.example.test."), script);
    assert(!script.includes("'example.test.' SOA"), script);
    const records = c.getWrittenResources();
    assertEquals(records.map((r) => r.specName), ["resolver", "outcome"]);
    assertEquals(records[1].data, {
      action: "apply_resolver",
      host: "ns1.example.test",
      changed: true,
      listen: ["127.0.0.3@53"],
      forwards: ["example.test."],
      test_name: "a.example.test.",
      observed_at: (records[1].data as { observed_at: string }).observed_at,
    });
  } finally {
    host.restore();
  }
});

Deno.test("every resource name written in one apply_resolver run is unique", async () => {
  const host = fakeHost((command) =>
    command.includes("50-managed-*.conf")
      ? { stdout: "a.example.test.\n" }
      : command.includes("kresctl")
      ? { stdout: "changed=yes\n" }
      : {}
  );
  try {
    const c = vaultContext();
    await model.methods.apply_resolver.execute(
      RESOLVER_ARGS as never,
      c.context,
    );
    const records = c.getWrittenResources();
    assertEquals(records.length, 2);
    // The per-method spec names are distinct ...
    assertEquals(new Set(records.map((r) => r.specName)).size, records.length);
    // ... and so are the state instance names they are keyed by.
    const resolverName = await instanceName([
      "resolver",
      RESOLVER_ARGS.ssh.host,
    ]);
    const outcomeName = await instanceName([
      "outcome",
      "apply_resolver",
      RESOLVER_ARGS.ssh.host,
      "",
    ]);
    assertEquals(resolverName === outcomeName, false);
  } finally {
    host.restore();
  }
});

Deno.test("a failed apply_resolver removes the staged file and records nothing", async () => {
  const host = fakeHost((command) =>
    command.includes("kresctl") ? { code: 4, stderr: "KRESCTL_FAILED\n" } : {}
  );
  try {
    const c = vaultContext();
    const e = await assertRejects(() =>
      model.methods.apply_resolver.execute(RESOLVER_ARGS as never, c.context)
    ) as { code?: string };
    assertEquals(e.code, "tool_failed");
    assert(
      host.commands.some((cmd) =>
        cmd.includes("'rm' '-f' '--'") &&
        cmd.includes("/etc/knot-resolver/.config.yaml.staged")
      ),
    );
    assertEquals(c.getWrittenResources().length, 0);
  } finally {
    host.restore();
  }
});

Deno.test("the resolver script removes its staged file on every exit", () => {
  const script = applyResolverScript({
    liveYaml: "/l",
    packageBackup: "/p",
    stagedYaml: "/s",
    testListen: "127.0.0.3@53",
    testName: "a.example.test.",
  });
  // The script runs inside `flock ... sh -c '<inner>'`, so quotes are escaped.
  assert(/trap .*rm -f "\$st".* EXIT/.test(script), script);
  assert(script.indexOf("trap") < script.indexOf("kresctl validate"));
});

Deno.test("allow_transfer and notify_secondaries take addresses, never free text", () => {
  const schema = model.methods.render_zone.arguments;
  for (
    const [field, value] of [
      ["allow_transfer", '127.0.0.1"\n    action: update'],
      ["allow_transfer", "any"],
      ["allow_transfer", "192.0.2.0/33"],
      ["notify_secondaries", "ns2.example.test"],
      ["notify_secondaries", "192.0.2.1@99999"],
      ["notify_secondaries", "192.0.2.1\nx"],
    ] as const
  ) {
    assertEquals(
      schema.safeParse({ ...ZONE_ARGS, [field]: [value] }).success,
      false,
      `${field}: ${value}`,
    );
  }
  for (
    const [field, value] of [
      ["allow_transfer", "192.0.2.0/24"],
      ["allow_transfer", "2001:db8::/32"],
      ["notify_secondaries", "192.0.2.1"],
      ["notify_secondaries", "192.0.2.1@853"],
    ] as const
  ) {
    assertEquals(
      schema.safeParse({ ...ZONE_ARGS, [field]: [value] }).success,
      true,
      `${field}: ${value}`,
    );
  }
});

Deno.test("install records its versions as an outcome", async () => {
  const host = fakeHost(() => ({
    stdout:
      "knot_version=knotc (Knot DNS), version 3.3.4\nkresd_version=Knot Resolver, version 6.5.0\n",
  }));
  try {
    const c = vaultContext();
    await model.methods.install.execute(
      { ssh: ZONE_ARGS.ssh, resolver: true } as never,
      c.context,
    );
    const [record] = c.getWrittenResources();
    assertEquals(record.specName, "outcome");
    assertEquals((record.data as { action: string }).action, "install");
    assertEquals(
      (record.data as { kresd_version: string }).kresd_version,
      "Knot Resolver, version 6.5.0",
    );
  } finally {
    host.restore();
  }
});

Deno.test("an install whose tool check fails is a tool_missing error", async () => {
  const host = fakeHost(() => ({
    code: 127,
    stderr: "TOOL_MISSING kzonecheck\n",
  }));
  try {
    const e = await assertRejects(() =>
      model.methods.install.execute(
        { ssh: ZONE_ARGS.ssh } as never,
        vaultContext().context,
      )
    ) as { code?: string };
    assertEquals(e.code, "tool_missing");
  } finally {
    host.restore();
  }
});
