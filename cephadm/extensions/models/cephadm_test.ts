import { assertEquals, assertRejects } from "jsr:@std/assert@1.0.19";
import { createModelTestContext } from "jsr:@swamp-club/swamp-testing@0.20261014.55";
import { createCephadmModel, model, VERSION } from "./cephadm.ts";
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
    const ssh = methodNames;
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
    strictHostKeyChecking: null,
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
    strictHostKeyChecking: null,
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
    strictHostKeyChecking: null,
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
        strictHostKeyChecking: null,
        multiplex: null,
        cephadmUrl: "https://download.example.com/cephadm",
        throwOnFail: null,
      }, context),
    Error,
    "pkgsource.check",
  );
  assertEquals(getWrittenResources().length, 1);
});
