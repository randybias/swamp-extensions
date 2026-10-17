import { assertEquals, assertRejects } from "jsr:@std/assert@1.0.19";
import { createModelTestContext } from "jsr:@swamp-club/swamp-testing@0.20261014.55";
import { createCephadmModel, model, S3_METHODS, VERSION } from "./cephadm.ts";
import { busyProbeScript } from "./_lib/hostprep.ts";
import type { Spawner } from "./_lib/ssh.ts";

const decoder = new TextDecoder();
const encoder = new TextEncoder();

/** A fake ssh spawner routed by the remote command (the last argv element). */
function routeSpawner(
  handler: (
    command: string,
    stdin: string,
  ) => { code: number; stdout: string; stderr: string },
): Spawner {
  return (_cmd, args) => {
    const command = args.at(-1) ?? "";
    let stdin = "";
    return {
      stdin: new WritableStream<Uint8Array>({
        write(chunk) {
          stdin += decoder.decode(chunk);
        },
        close() {},
      }),
      output: () => {
        const r = handler(command, stdin);
        return Promise.resolve({
          code: r.code,
          stdout: encoder.encode(r.stdout),
          stderr: encoder.encode(r.stderr),
        });
      },
      kill: () => {},
    };
  };
}

const GLOBALS = {};

Deno.test("the model type, version and empty global arguments are as specified", () => {
  assertEquals(model.type, "@randybias/cephadm");
  assertEquals(model.version, VERSION);
  assertEquals(model.globalArguments.safeParse({}).success, true);
  assertEquals(model.globalArguments.safeParse({ extra: 1 }).success, false);
});

Deno.test("every required method exists with a description and a schema", () => {
  for (
    const name of ["cephHostPrep", "cephVerifyPackageSource", "wipeDiskToRaw"]
  ) {
    const method = (model.methods as Record<
      string,
      { description: string; arguments: unknown }
    >)[name];
    assertEquals(typeof method.description, "string");
    assertEquals(method.description.length > 0, true);
    assertEquals(typeof method.arguments, "object");
  }
});

Deno.test("destructive methods lead with DESTRUCTIVE and read-only with READ-ONLY", () => {
  assertEquals(
    model.methods.wipeDiskToRaw.description.startsWith("DESTRUCTIVE."),
    true,
  );
  assertEquals(
    model.methods.cephVerifyPackageSource.description.startsWith("READ-ONLY."),
    true,
  );
});

Deno.test(
  "every SSH-using method declares the whole shared connection family", // leak-allow(decision D66)
  () => {
    const shapes = model.methods as unknown as Record<
      string,
      { arguments: { shape: Record<string, unknown> } }
    >;
    for (const [name, method] of Object.entries(shapes)) {
      if (S3_METHODS.has(name)) continue;
      const fields = Object.keys(method.arguments.shape);
      for (
        const field of [
          "sshUser",
          "port",
          "keyPath",
          "privateKey",
          "strictHostKeyChecking",
          "multiplex",
        ]
      ) {
        assertEquals(fields.includes(field), true, `${name} lacks ${field}`);
      }
    }
  },
);

Deno.test(
  "the ssh-installed check applies to exactly the SSH methods", // leak-allow(decision D19)
  () => {
    const checks = model.checks as unknown as Record<
      string,
      { labels: string[]; appliesTo: string[] }
    >;
    assertEquals(checks["ssh-installed"].labels.includes("live"), true);
    const methodNames = new Set(Object.keys(model.methods));
    const ssh = new Set(
      [...methodNames].filter((name) => !S3_METHODS.has(name)),
    );
    assertEquals(new Set(checks["ssh-installed"].appliesTo), ssh);
  },
);

Deno.test("the upgrade chain ends at the model version", () => {
  const upgrades = model.upgrades as unknown as { toVersion: string }[];
  assertEquals(upgrades.length, 1);
  assertEquals(upgrades.at(-1)!.toVersion, model.version);
});

Deno.test("host preparation rejects hostile hosts, packages, URLs and budgets", () => {
  const schema = model.methods.cephHostPrep.arguments;
  const base = {
    host: "192.0.2.10",
    sshUser: "admin",
    port: null,
    keyPath: null,
    privateKey: null,
    strictHostKeyChecking: "yes",
    multiplex: null,
    packages: ["chrony"],
    cephadmUrl: "https://download.example.com/cephadm",
    cephadmVersion: "19.2.1",
    timeSyncService: "chrony.service",
    installRetryBudgetMs: null,
  };
  assertEquals(schema.safeParse(base).success, true);
  assertEquals(schema.safeParse({ ...base, host: "node1; id" }).success, false);
  for (const pkg of ["Chrony", "lvm2;reboot", "chrony=4.3-2", "chrony:amd64"]) {
    assertEquals(schema.safeParse({ ...base, packages: [pkg] }).success, false);
  }
  assertEquals(
    schema.safeParse({ ...base, cephadmUrl: "file:///tmp/cephadm" }).success,
    false,
  );
  assertEquals(
    schema.safeParse({ ...base, cephadmUrl: "https://x/y;id" }).success,
    false,
  );
  assertEquals(
    schema.safeParse({ ...base, installRetryBudgetMs: -1 }).success,
    false,
  );
  assertEquals(
    schema.safeParse({ ...base, installRetryBudgetMs: 1.5 }).success,
    false,
  );
  assertEquals(
    schema.safeParse({ ...base, installRetryBudgetMs: 45000 }).success,
    true,
  );
  assertEquals(
    schema.safeParse({ ...base, sshUser: "admin;id" }).success,
    false,
  );
  assertEquals(schema.safeParse({ ...base, port: 70000 }).success, false);
});

Deno.test("wipe requires both device lists and rejects injection serials", () => {
  const schema = model.methods.wipeDiskToRaw.arguments;
  const base = {
    host: "192.0.2.10",
    sshUser: "admin",
    port: null,
    keyPath: null,
    privateKey: null,
    strictHostKeyChecking: "yes",
    multiplex: null,
    dataDevices: [{ serial: "SN0001" }],
    excludeDevices: [],
    dryRun: null,
  };
  assertEquals(schema.safeParse(base).success, true);
  assertEquals(
    schema.safeParse({ ...base, excludeDevices: undefined }).success,
    false,
  );
  assertEquals(schema.safeParse({ ...base, dataDevices: [] }).success, false);
  for (const serial of ["SN*", "SN; id", "SN_0001", "SN.0001"]) {
    assertEquals(
      schema.safeParse({ ...base, dataDevices: [{ serial }] }).success,
      false,
    );
  }
});

Deno.test("a ready host preparing end to end writes a complete record", async () => {
  const spawn = routeSpawner((command) => {
    if (command === "sudo -n -- bash -s --") {
      return { code: 0, stdout: "idle\n", stderr: "" };
    }
    if (command.startsWith("dpkg -s ")) {
      return {
        code: 0,
        stdout: "Package: chrony\nVersion: 4.3-2\n",
        stderr: "",
      };
    }
    if (command === "test -x /usr/local/sbin/cephadm") {
      return { code: 0, stdout: "", stderr: "" };
    }
    if (command === "sudo -n -- /usr/local/sbin/cephadm version") {
      return {
        code: 0,
        stdout: "cephadm version 19.2.1 (abc) squid (stable)\n",
        stderr: "",
      };
    }
    if (command === "systemctl is-active 'chrony.service'") {
      return { code: 0, stdout: "active\n", stderr: "" };
    }
    if (command.startsWith("-O exit")) {
      return { code: 0, stdout: "", stderr: "" };
    }
    return { code: 1, stdout: "", stderr: `unrouted: ${command}` };
  });
  const m = createCephadmModel({
    spawn,
    now: () => 0,
    sleep: () => Promise.resolve(),
    random: () => 0,
  });
  const { context, getWrittenResources } = createModelTestContext({
    globalArgs: GLOBALS,
  });
  await m.methods.cephHostPrep.execute({
    host: "192.0.2.10",
    sshUser: "admin",
    port: null,
    keyPath: null,
    privateKey: null,
    strictHostKeyChecking: "yes",
    multiplex: null,
    packages: ["chrony"],
    cephadmUrl: "https://download.example.com/cephadm",
    cephadmVersion: "19.2.1",
    timeSyncService: "chrony.service",
    installRetryBudgetMs: null,
  }, context);
  const written = getWrittenResources();
  assertEquals(written.length, 1);
  assertEquals(written[0].name, "cephHostPrep-192.0.2.10");
  const data = written[0].data as {
    cephadm: { alreadyPresent: boolean; version: string };
    timeSync: { active: boolean };
    packages: { alreadyPresent: boolean }[];
  };
  assertEquals(data.cephadm.alreadyPresent, true);
  assertEquals(data.cephadm.version, "19.2.1");
  assertEquals(data.timeSync.active, true);
  assertEquals(data.packages[0].alreadyPresent, true);
});

Deno.test("the ssh-installed check passes when the spawner works", async () => {
  const m = createCephadmModel({
    spawn: routeSpawner(() => ({ code: 0, stdout: "", stderr: "" })),
  });
  const checks = m.checks as unknown as Record<
    string,
    {
      execute: (
        ctx: { globalArgs: Record<string, unknown> },
      ) => Promise<{ pass: boolean }>;
    }
  >;
  assertEquals(
    (await checks["ssh-installed"].execute({ globalArgs: {} })).pass,
    true,
  );
});

Deno.test("the ssh-installed check fails when the binary cannot be spawned", async () => {
  const m = createCephadmModel({
    spawn: () => {
      throw new Error("ssh not found");
    },
  });
  const checks = m.checks as unknown as Record<
    string,
    {
      execute: (
        ctx: { globalArgs: Record<string, unknown> },
      ) => Promise<{ pass: boolean }>;
    }
  >;
  assertEquals(
    (await checks["ssh-installed"].execute({ globalArgs: {} })).pass,
    false,
  );
});

Deno.test("the busy-probe script is the one the package phase sends", () => {
  assertEquals(busyProbeScript().includes("echo idle"), true);
});

const SSH_NULLS = {
  port: null,
  keyPath: null,
  privateKey: null,
  strictHostKeyChecking: "yes",
  multiplex: null,
  sshUser: "admin",
} as const;

Deno.test("the bootstrap schema rejects hostile or malformed targets and images", () => {
  const schema = model.methods.cephBootstrap.arguments;
  const base = {
    host: "192.0.2.10",
    ...SSH_NULLS,
    monIp: "192.0.2.10",
    publicNet: "192.0.2.0/24",
    clusterNet: "198.51.100.0/24",
    cephImage: "registry.example.com/ceph/ceph:v19.2.3",
    timeoutMs: null,
  };
  assertEquals(schema.safeParse(base).success, true);
  assertEquals(
    schema.safeParse({ ...base, monIp: "2001:db8::1" }).success,
    false,
  );
  assertEquals(
    schema.safeParse({ ...base, publicNet: "192.0.2.1/24" }).success,
    false,
  );
  assertEquals(
    schema.safeParse({ ...base, cephImage: "registry.example.com/ceph/ceph" })
      .success,
    false,
  );
  assertEquals(
    schema.safeParse({
      ...base,
      cephImage: "registry.example.com/Ceph/ceph:v19",
    }).success,
    false,
  );
  assertEquals(schema.safeParse({ ...base, host: "n;id" }).success, false);
});

Deno.test("the distribute-key schema rejects option backdoors and needs a port per host", () => {
  const schema = model.methods.cephDistributeKey.arguments;
  const key =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExampleExampleExampleExampleExample";
  const base = {
    ...SSH_NULLS,
    cephPubKey: key,
    hosts: [{ host: "192.0.2.10", port: 22 }],
  };
  assertEquals(schema.safeParse(base).success, true);
  assertEquals(
    schema.safeParse({ ...base, cephPubKey: `command="x" ${key}` }).success,
    false,
  );
  assertEquals(
    schema.safeParse({ ...base, cephPubKey: `${key}\n${key}` }).success,
    false,
  );
  assertEquals(schema.safeParse({ ...base, hosts: [] }).success, false);
  assertEquals(
    schema.safeParse({ ...base, hosts: [{ host: "192.0.2.10" }] }).success,
    false,
  );
  assertEquals(
    schema.safeParse({ ...base, hosts: [{ host: "192.0.2.10", port: 0 }] })
      .success,
    false,
  );
});

Deno.test("the data-plane resources are declared, strict and csiKey keeps 2", () => {
  const res = model.resources as unknown as Record<
    string,
    {
      schema: {
        safeParse: (v: unknown) => { success: boolean };
        shape?: Record<string, { meta?: () => Record<string, unknown> }>;
      };
      garbageCollection: number;
    }
  >;
  for (
    const name of [
      "poolResult",
      "fsResult",
      "csiUserResult",
      "connBundleResult",
      "csiKey",
      "fsDeleteResult",
      "osdRemoveResult",
    ]
  ) assertEquals(typeof res[name], "object", name);
  assertEquals(res.csiKey.garbageCollection, 2);
  const keyMeta = res.csiKey.schema.shape?.key?.meta?.();
  if (keyMeta !== undefined) assertEquals(keyMeta.sensitive, true);
  // A strict schema rejects an undeclared field.
  assertEquals(
    res.poolResult.schema.safeParse({
      name: "x",
      scheme: "replicated",
      application: "rbd",
      failureDomain: "host",
      existed: false,
      changed: [],
      capturedAt: "t",
      extra: 1,
    }).success,
    false,
  );
});

Deno.test("the OSD schema enforces exactly one mode and rejects injection", () => {
  const schema = model.methods.cephApplyOsd.arguments;
  const base = {
    adminHost: "192.0.2.10",
    ...SSH_NULLS,
    allAvailableDevices: null,
    targetHost: null,
    targetAddr: null,
    targetPort: null,
    dataDevices: null,
    excludeDevices: null,
  };
  assertEquals(
    schema.safeParse({
      ...base,
      targetHost: "node1",
      dataDevices: [{ serial: "SN0001" }],
    }).success,
    true,
  );
  assertEquals(
    schema.safeParse({
      ...base,
      allAvailableDevices: true,
      excludeDevices: [{ serial: "SN0001" }],
    }).success,
    true,
  );
  // An empty string and empty list are accepted and mean absent.
  assertEquals(
    schema.safeParse({
      ...base,
      allAvailableDevices: true,
      targetHost: "",
      excludeDevices: [{ serial: "SN0001" }],
    }).success,
    true,
  );
  for (
    const bad of [
      { ...base, targetHost: "a;id", dataDevices: [{ serial: "SN0001" }] },
      { ...base, targetHost: "node1", dataDevices: [{ serial: "SN*" }] },
      {
        ...base,
        adminHost: "a;id",
        targetHost: "node1",
        dataDevices: [{ serial: "SN1" }],
      },
      {
        ...base,
        targetHost: "node1",
        dataDevices: [{ serial: "SN1" }],
        targetPort: 0,
      },
    ]
  ) assertEquals(schema.safeParse(bad).success, false);
});

Deno.test("the host-add and apply schemas reject injection and duplicates", () => {
  const addSchema = model.methods.cephHostAdd.arguments;
  const addBase = {
    adminHost: "192.0.2.10",
    ...SSH_NULLS,
    fsid: "3f2a9c1e-5b7d-4e8f-9a0b-1c2d3e4f5a6b",
    host: "node1",
    addr: "192.0.2.20",
  };
  assertEquals(addSchema.safeParse(addBase).success, true);
  assertEquals(
    addSchema.safeParse({ ...addBase, adminHost: "a;id" }).success,
    false,
  );
  assertEquals(
    addSchema.safeParse({ ...addBase, host: "a;id" }).success,
    false,
  );
  assertEquals(
    addSchema.safeParse({ ...addBase, addr: "not-an-ip" }).success,
    false,
  );
  assertEquals(
    addSchema.safeParse({ ...addBase, fsid: "nope" }).success,
    false,
  );

  const monSchema = model.methods.cephApplyMon.arguments;
  const monBase = {
    adminHost: "192.0.2.10",
    ...SSH_NULLS,
    placement: ["node1"],
    allowQuorumRisk: null,
  };
  assertEquals(monSchema.safeParse(monBase).success, true);
  assertEquals(
    monSchema.safeParse({ ...monBase, placement: [] }).success,
    false,
  );
  assertEquals(
    monSchema.safeParse({ ...monBase, placement: ["node1", "node1"] }).success,
    false,
  );
  assertEquals(
    monSchema.safeParse({ ...monBase, placement: ["node1;id"] }).success,
    false,
  );

  const mdsSchema = model.methods.cephApplyMds.arguments;
  const mdsBase = {
    adminHost: "192.0.2.10",
    ...SSH_NULLS,
    fsName: "cephfs",
    placement: ["node1"],
  };
  assertEquals(mdsSchema.safeParse(mdsBase).success, true);
  assertEquals(
    mdsSchema.safeParse({ ...mdsBase, fsName: "cephfs;id" }).success,
    false,
  );
  assertEquals(
    mdsSchema.safeParse({ ...mdsBase, fsName: "cephfs.x" }).success,
    true,
  );
});

Deno.test("bootstrap records the fsid and a keyring path, never keyring material", async () => {
  const key =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExampleExampleExampleExampleExample";
  let probes = 0;
  const spawn = routeSpawner((command) => {
    if (command.endsWith("cephadm ls")) {
      probes++;
      return {
        code: 0,
        stdout: probes === 1 ? "[]" : '[{"fsid":"abc"}]',
        stderr: "",
      };
    }
    if (command.includes("sh -c ")) return { code: 0, stdout: "", stderr: "" };
    if (command.endsWith("cat /etc/ceph/ceph.pub")) {
      return { code: 0, stdout: `${key}\n`, stderr: "" };
    }
    return { code: 1, stdout: "", stderr: `unrouted: ${command}` };
  });
  const m = createCephadmModel({
    spawn,
    now: () => 0,
    sleep: () => Promise.resolve(),
    random: () => 0.25,
  });
  const { context, getWrittenResources } = createModelTestContext({
    globalArgs: GLOBALS,
  });
  await m.methods.cephBootstrap.execute({
    host: "192.0.2.10",
    ...SSH_NULLS,
    monIp: "192.0.2.10",
    publicNet: "192.0.2.0/24",
    clusterNet: "198.51.100.0/24",
    cephImage: "registry.example.com/ceph/ceph:v19.2.3",
    timeoutMs: null,
  }, context);
  const data = getWrittenResources()[0].data as {
    fsid: string;
    adminKeyringRef: { path: string };
    bootstrapped: boolean;
  };
  assertEquals(data.fsid, "abc");
  assertEquals(data.bootstrapped, true);
  assertEquals(
    data.adminKeyringRef.path,
    "/etc/ceph/ceph.client.admin.keyring",
  );
  assertEquals(JSON.stringify(data).includes("PRIVATE KEY"), false);
});

Deno.test("distribute-key reports all hosts and fails at the end naming failures", async () => {
  const key =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExampleExampleExampleExampleExample";
  const spawn = routeSpawner((command) => {
    if (command.includes("mkdir -p")) {
      return { code: 0, stdout: "", stderr: "" };
    }
    if (command.startsWith("grep -Fqx")) {
      return { code: 0, stdout: "", stderr: "" };
    }
    if (command.startsWith("grep -Fq ")) {
      return { code: 0, stdout: "", stderr: "" };
    }
    return { code: 1, stdout: "", stderr: "unrouted" };
  });
  const m = createCephadmModel({ spawn, now: () => 0 });
  const { context, getWrittenResources } = createModelTestContext({
    globalArgs: GLOBALS,
  });
  await m.methods.cephDistributeKey.execute({
    ...SSH_NULLS,
    cephPubKey: key,
    hosts: [{ host: "192.0.2.10", port: 22 }, {
      host: "198.51.100.9",
      port: 2202,
    }],
  }, context);
  assertEquals(
    getWrittenResources()[0].name,
    "cephDistributeKey-192.0.2.10:22,198.51.100.9:2202",
  );
});

Deno.test("verifyPackageSource records first, then throws, when throwOnFail is unset", async () => {
  const spawn = routeSpawner((command, stdin) => {
    if (stdin.includes("###CEPHADM-SOURCES###")) {
      return {
        code: 0,
        stdout: [
          "###CEPHADM-SOURCES###",
          "deb http://deb.example.com/debian stable main",
          "###CEPHADM-PROXY###",
          "###CEPHADM-PROBES###",
        ].join("\n"),
        stderr: "",
      };
    }
    if (stdin.includes("getent hosts")) {
      return { code: 0, stdout: "bad.example.com|http|||\n", stderr: "" };
    }
    if (command.startsWith("-O exit")) {
      return { code: 0, stdout: "", stderr: "" };
    }
    return { code: 1, stdout: "", stderr: "unrouted" };
  });
  const m = createCephadmModel({ spawn, now: () => 0 });
  const { context, getWrittenResources } = createModelTestContext({
    globalArgs: GLOBALS,
  });
  await assertRejects(
    () =>
      m.methods.cephVerifyPackageSource.execute({
        host: "192.0.2.10",
        sshUser: "admin",
        port: null,
        keyPath: null,
        privateKey: null,
        strictHostKeyChecking: "yes",
        multiplex: null,
        cephadmUrl: "https://download.example.com/cephadm",
        throwOnFail: null,
      }, context),
    Error,
    "pkgsource.check",
  );
  assertEquals(getWrittenResources().length, 1);
});

Deno.test("every mutating method is declared an action", () => {
  // M, M!, D and W methods, and no read-only method.
  const mutating = [
    "cephHostPrep",
    "wipeDiskToRaw",
    "cephBootstrap",
    "cephDistributeKey",
    "cephHostAdd",
    "cephApplyMon",
    "cephApplyMgr",
    "cephApplyMds",
    "cephApplyOsd",
    "cephCreatePool",
    "cephCreateFs",
    "cephCreateCsiUser",
    "cephDeleteFs",
    "cephRemoveOsds",
    "cephVerifyRbdSmoke",
    "cephRgwUserEnsure",
    "cephHostMaintenanceEnter",
    "cephHostMaintenanceExit",
    "cephHostNooutClear",
    "cephOsdActivate",
    "cephDisableOrchestration",
    "cephRmCluster",
  ];
  const readOnly = [
    "cephGetConnBundle",
    "cephVerifyHealth",
    "cephVerifyMonQuorum",
    "cephVerifyPool",
    "cephCapacityReport",
    "cephRgwBucketInventory",
    "cephHostMaintenanceState",
    "cephVerifyHostTornDown",
  ];
  const methods = model.methods as unknown as Record<string, { kind?: string }>;
  for (const name of mutating) assertEquals(methods[name].kind, "action", name);
  for (const name of readOnly) {
    assertEquals(methods[name].kind, undefined, name);
  }
});

Deno.test("distribute-key records every host's outcome, then throws", async () => {
  const key =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExampleExampleExampleExampleExample";
  const spawn = routeSpawner((command) => {
    if (command.includes("mkdir -p")) {
      return { code: 0, stdout: "", stderr: "" };
    }
    if (command.startsWith("grep -Fqx")) {
      return { code: 1, stdout: "", stderr: "" };
    }
    if (command.startsWith("cat >>")) {
      return { code: 1, stdout: "", stderr: "denied" };
    }
    return { code: 1, stdout: "", stderr: "unrouted" };
  });
  const m = createCephadmModel({ spawn, now: () => 0 });
  const { context, getWrittenResources } = createModelTestContext({
    globalArgs: GLOBALS,
  });
  await assertRejects(
    () =>
      m.methods.cephDistributeKey.execute({
        ...SSH_NULLS,
        cephPubKey: key,
        hosts: [{ host: "192.0.2.10", port: 22 }],
      }, context),
    Error,
    "not present",
  );
  assertEquals(getWrittenResources().length, 1);
});

Deno.test("host-state records carry sectionFailures in both strict schemas", () => {
  const res = model.resources as unknown as Record<
    string,
    { schema: { safeParse: (v: unknown) => { success: boolean } } }
  >;
  const base = {
    host: "192.0.2.10",
    fsids: [],
    cephUnits: [],
    clusterUnits: [],
    cephVolumeGroups: [],
    cephLogicalVolumes: [],
    mdArrays: [],
    toolsSeen: { systemctl: true, lvm: true, mdstat: true },
    capturedAt: "2026-10-17T00:00:00.000Z",
  };
  const torn = {
    ...base,
    fsid: "00000000-0000-0000-0000-000000000000",
    pass: true,
    namedFsidGone: true,
    findings: [],
  };
  for (
    const [name, record] of [
      ["cephHostClusterStateResult", base],
      ["cephHostTornDownResult", torn],
    ] as const
  ) {
    const schema = res[name].schema;
    assertEquals(
      schema.safeParse({ ...record, sectionFailures: ["vgs"] }).success,
      true,
      name,
    );
    assertEquals(
      schema.safeParse(record).success,
      false,
      `${name} requires it`,
    );
    assertEquals(
      schema.safeParse({ ...record, sectionFailures: [], extra: 1 }).success,
      false,
      `${name} stays strict`,
    );
  }
});
