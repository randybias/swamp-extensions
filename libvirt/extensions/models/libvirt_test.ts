import {
  assertEquals,
  assertRejects,
  assertThrows,
} from "jsr:@std/assert@1.0.19";
import { createModelTestContext } from "jsr:@swamp-club/swamp-testing@0.20261014.55";
import {
  createModel,
  instanceName,
  type LibvirtDeps,
  targetKey,
} from "./libvirt.ts";
import { type CommandRunner, sha256Hex, SshError } from "./_lib/ssh.ts";
import { renderNetworkXml } from "./_lib/xml.ts";

const NOW = 1_700_000_000_000;
const TOKEN = "0000000000000000";
const PEM =
  "-----BEGIN OPENSSH PRIVATE KEY-----\nZmFrZS1rZXktbWF0ZXJpYWw=\n-----END OPENSSH PRIVATE KEY-----";

const SSH = {
  host: "192.0.2.20",
  port: 22,
  user: "root",
  host_key_policy: "strict" as const,
  host_keys: ["192.0.2.20 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeKey"],
  private_key: PEM,
  connect_timeout_s: 15,
};

const URI = "qemu:///system";
const NET = { ...SSH, uri: URI, name: "net-a" };
const TARGET = targetKey(SSH);

const RUNNING =
  "Id: 1\nName: node-a\nUUID: uuid-a\nState: running\nCPU(s): 2\nMax memory: 2097152 KiB\n";
const SHUT_OFF =
  "Name: node-a\nUUID: uuid-a\nState: shut off\nCPU(s): 2\nMax memory: 2097152 KiB\n";

interface Resp {
  code: number;
  stdout?: string;
  stderr?: string;
}

type Respond = (command: string) => Resp;

interface Fake {
  deps: Partial<LibvirtDeps>;
  commands: string[];
  uploads: string[];
  clock: { value: number };
}

/** A transport fake: records ssh command strings and dispatches responses. */
function fakeLibvirt(respond: Respond): Fake {
  const commands: string[] = [];
  const uploads: string[] = [];
  const clock = { value: NOW };
  const run: CommandRunner = async (cmd, args, options = {}) => {
    await Promise.resolve();
    if (cmd === "ssh-agent") {
      return args[0] === "-s"
        ? {
          code: 0,
          stdout: "SSH_AUTH_SOCK=/tmp/a.sock;\nSSH_AGENT_PID=1;\n",
          stderr: "",
        }
        : { code: 0, stdout: "", stderr: "" };
    }
    if (cmd === "ssh-add") return { code: 0, stdout: "", stderr: "" };
    if (cmd !== "ssh") return { code: 0, stdout: "", stderr: "" };
    const command = args[args.length - 1];
    commands.push(command);
    if (command.includes("echo MISSING")) {
      return { code: 0, stdout: "MISSING\n", stderr: "" };
    }
    if (command.includes(".ssh-host-upload")) {
      const bytes = options.stdin === undefined
        ? new Uint8Array()
        : typeof options.stdin === "string"
        ? new TextEncoder().encode(options.stdin)
        : options.stdin;
      uploads.push(new TextDecoder().decode(bytes));
      // The new transport reads the destination's own hash and mode back from
      // the remote and compares them locally; return what the write produced.
      const digest = await sha256Hex(bytes);
      return { code: 0, stdout: `${digest} 0600\n`, stderr: "" };
    }
    const r = respond(command);
    return { code: r.code, stdout: r.stdout ?? "", stderr: r.stderr ?? "" };
  };
  const deps: Partial<LibvirtDeps> = {
    run,
    now: () => clock.value,
    sleep: (ms) => {
      clock.value += ms;
      return Promise.resolve();
    },
    token: () => TOKEN,
  };
  return { deps, commands, uploads, clock };
}

/** A responder that consumes a per-matcher sequence of replies. */
function seq(pairs: [string, (n: number) => Resp][]): Respond {
  const counts = new Map<string, number>();
  return (command) => {
    for (const [key, fn] of pairs) {
      if (command.includes(key)) {
        const n = counts.get(key) ?? 0;
        counts.set(key, n + 1);
        return fn(n);
      }
    }
    return { code: 0 };
  };
}

function has(f: Fake, sub: string): boolean {
  return f.commands.some((c) => c.includes(sub));
}

function modelWith(f: Fake) {
  return createModel(f.deps);
}

/** A stored domain_state record with its resolved root disk. */
function domState(name: string, rootDisk: string) {
  return {
    [instanceName("dom", SSH, name)]: {
      target: TARGET,
      name,
      present: true,
      root_disk: rootDisk,
      observed_at: "2026-10-17T00:00:00.000Z",
    },
  };
}

Deno.test("schema: empty globals; mutating methods are actions; private_key sensitive", () => {
  const m = createModel();
  assertEquals(Object.keys(m.globalArguments.shape), []);
  for (
    const name of [
      "define_network",
      "undefine_network",
      "clone_volume",
      "define_domain",
      "power",
      "undefine_domain",
    ] as const
  ) {
    assertEquals((m.methods[name] as { kind?: string }).kind, "action", name);
  }
  for (const name of ["console", "get", "sync"] as const) {
    assertEquals((m.methods[name] as { kind?: string }).kind, undefined, name);
  }
  for (
    const name of [
      "define_network",
      "undefine_network",
      "clone_volume",
      "define_domain",
      "power",
      "console",
      "undefine_domain",
      "get",
      "sync",
    ] as const
  ) {
    const shape = m.methods[name].arguments.shape as Record<
      string,
      { meta: () => { sensitive?: boolean } }
    >;
    assertEquals(shape.private_key.meta().sensitive, true, name);
  }
  assertEquals(
    m.methods.power.arguments.safeParse({
      ...SSH,
      uri: URI,
      name: "n",
      action: "detonate",
    })
      .success,
    false,
  );
});

Deno.test("schema: names and uri are rejected by grammar before any call", () => {
  const m = createModel();
  for (
    const args of [
      { ...NET, name: "net;a" },
      { ...NET, name: "../etc" },
      { ...NET, uri: "qemu:///system; id" },
      { ...NET, uri: "http://example.com" },
      { ...NET, name: "net-a", extra: true },
    ]
  ) {
    assertEquals(
      m.methods.define_network.arguments.safeParse(args).success,
      false,
      JSON.stringify(args),
    );
  }
  assertEquals(
    m.methods.clone_volume.arguments.safeParse({
      ...SSH,
      uri: URI,
      pool: "pool-a",
      source_volume: "golden",
      target_volume: "node-a-root",
      format: "vmdk",
    }).success,
    false,
  );
});

Deno.test("define_network: creates, starts and autostarts, then records state", async () => {
  const f = fakeLibvirt(seq([
    [
      "'net-info'",
      (n) =>
        n === 0
          ? { code: 1, stderr: "error: failed to get network" }
          : n === 1
          ? {
            code: 0,
            stdout: "Name: net-a\nActive: no\nAutostart: no\nUUID: u1\n",
          }
          : n === 2
          ? {
            code: 0,
            stdout: "Name: net-a\nActive: yes\nAutostart: no\nUUID: u1\n",
          }
          : {
            code: 0,
            stdout: "Name: net-a\nActive: yes\nAutostart: yes\nUUID: u1\n",
          },
    ],
    ["'net-define'", () => ({ code: 0 })],
    ["'net-start'", () => ({ code: 0 })],
    ["'net-autostart'", () => ({ code: 0 })],
  ]));
  const m = modelWith(f);
  const { context, getWrittenResources } = createModelTestContext({
    globalArgs: {},
  });
  const out = await m.methods.define_network.execute(
    m.methods.define_network.arguments.parse({
      ...NET,
      mode: "nat",
      gateway: "192.0.2.1",
      prefix: 24,
      dhcp_start: "192.0.2.10",
      dhcp_end: "192.0.2.99",
    }),
    context,
  );
  assertEquals(out.result.changed, true);
  assertEquals(out.result.active, true);
  assertEquals(has(f, "'net-define'"), true);
  assertEquals(has(f, "'net-start'"), true);
  assertEquals(has(f, "'net-autostart'"), true);
  assertEquals(getWrittenResources().length, 1);
});

Deno.test("define_network: an identical projection is a no-op", async () => {
  const xml = renderNetworkXml({
    name: "net-a",
    mode: "nat",
    gateway: "192.0.2.1",
    prefix: 24,
  });
  const f = fakeLibvirt(seq([
    [
      "'net-info'",
      () => ({
        code: 0,
        stdout: "Name: net-a\nActive: yes\nAutostart: yes\nUUID: u1\n",
      }),
    ],
    ["'net-dumpxml'", () => ({ code: 0, stdout: xml })],
  ]));
  const m = modelWith(f);
  const { context } = createModelTestContext({ globalArgs: {} });
  const out = await m.methods.define_network.execute(
    m.methods.define_network.arguments.parse({
      ...NET,
      mode: "nat",
      gateway: "192.0.2.1",
      prefix: 24,
    }),
    context,
  );
  assertEquals(out.result.changed, false);
  assertEquals(has(f, "'net-define'"), false);
  assertEquals(has(f, "'net-destroy'"), false);
});

Deno.test("define_network: a changed projection with replace=true is replaced", async () => {
  const existing = renderNetworkXml({
    name: "net-a",
    mode: "route",
    gateway: "192.0.2.1",
    prefix: 24,
  });
  const f = fakeLibvirt(seq([
    [
      "'net-info'",
      () => ({
        code: 0,
        stdout: "Name: net-a\nActive: yes\nAutostart: yes\nUUID: u1\n",
      }),
    ],
    ["'net-dumpxml'", () => ({ code: 0, stdout: existing })],
    ["'net-destroy'", () => ({ code: 0 })],
    ["'net-undefine'", () => ({ code: 0 })],
    ["'net-define'", () => ({ code: 0 })],
  ]));
  const m = modelWith(f);
  const { context } = createModelTestContext({ globalArgs: {} });
  const out = await m.methods.define_network.execute(
    m.methods.define_network.arguments.parse({
      ...NET,
      mode: "nat",
      gateway: "192.0.2.1",
      prefix: 24,
      replace: true,
    }),
    context,
  );
  assertEquals(out.result.changed, true);
  assertEquals(has(f, "'net-destroy'"), true);
  assertEquals(has(f, "'net-undefine'"), true);
  assertEquals(has(f, "'net-define'"), true);
});

Deno.test("define_network: a differing network without replace is left untouched", async () => {
  const existing = renderNetworkXml({
    name: "net-a",
    mode: "route",
    gateway: "192.0.2.1",
    prefix: 24,
  });
  const f = fakeLibvirt(seq([
    [
      "'net-info'",
      () => ({
        code: 0,
        stdout: "Name: net-a\nActive: yes\nAutostart: yes\nUUID: u1\n",
      }),
    ],
    ["'net-dumpxml'", () => ({ code: 0, stdout: existing })],
  ]));
  const m = modelWith(f);
  const { context } = createModelTestContext({ globalArgs: {} });
  const out = await m.methods.define_network.execute(
    m.methods.define_network.arguments.parse({
      ...NET,
      mode: "nat",
      gateway: "192.0.2.1",
      prefix: 24,
    }),
    context,
  );
  assertEquals(out.result.changed, false);
  assertEquals(out.result.drift, true);
  assertEquals(has(f, "'net-define'"), false);
  assertEquals(has(f, "'net-destroy'"), false);
  assertEquals(has(f, "'net-undefine'"), false);
});

Deno.test("define_network: raw xml must name the requested network", async () => {
  const f = fakeLibvirt(seq([]));
  const m = modelWith(f);
  const { context } = createModelTestContext({ globalArgs: {} });
  await assertRejects(
    () =>
      m.methods.define_network.execute(
        m.methods.define_network.arguments.parse({
          ...NET,
          xml: "<network><name>other</name></network>",
        }),
        context,
      ),
    Error,
    "names the network",
  );
  assertEquals(has(f, "'net-define'"), false);
});

Deno.test("define_network: a commented-out <name> cannot spoof the raw xml check", async () => {
  const f = fakeLibvirt(seq([
    [
      "'net-info'",
      () => ({ code: 1, stderr: "error: failed to get network" }),
    ],
  ]));
  const m = modelWith(f);
  const { context } = createModelTestContext({ globalArgs: {} });
  await assertRejects(
    () =>
      m.methods.define_network.execute(
        m.methods.define_network.arguments.parse({
          ...NET,
          xml:
            "<!-- <name>net-a</name> --><network><name>other</name></network>",
        }),
        context,
      ),
    Error,
    "names the network",
  );
  assertEquals(has(f, "'net-define'"), false);
});

Deno.test("schema: devname uses the name grammar; arch is enum-bound", () => {
  const m = createModel();
  assertEquals(
    m.methods.console.arguments.safeParse({
      ...SSH,
      uri: URI,
      name: "n",
      devname: "serial0",
    }).success,
    true,
  );
  assertEquals(
    m.methods.console.arguments.safeParse({
      ...SSH,
      uri: URI,
      name: "n",
      devname: "serial;0",
    }).success,
    false,
  );
  const domain = (arch: string) => ({
    ...SSH,
    uri: URI,
    name: "n",
    pool: "p",
    volume: "v",
    vcpus: 1,
    memory_mib: 1024,
    arch,
  });
  assertEquals(
    m.methods.define_domain.arguments.safeParse(domain("x86_64")).success,
    true,
  );
  assertEquals(
    m.methods.define_domain.arguments.safeParse(domain("amd64")).success,
    false,
  );
});

Deno.test("networkInfo: a hard error is surfaced, not read as absent", async () => {
  const f = fakeLibvirt(seq([
    [
      "'net-info'",
      () => ({
        code: 1,
        stderr: "error: failed to connect to the hypervisor",
      }),
    ],
  ]));
  const m = modelWith(f);
  const { context, getWrittenResources } = createModelTestContext({
    globalArgs: {},
  });
  await assertRejects(
    () =>
      m.methods.undefine_network.execute(
        m.methods.undefine_network.arguments.parse(NET),
        context,
      ),
    Error,
    "could not read network",
  );
  assertEquals(has(f, "'net-undefine'"), false);
  assertEquals(getWrittenResources().length, 0);
});

Deno.test("undefine_network: absent is a no-op; active is stopped and undefined", async () => {
  const absent = fakeLibvirt(seq([
    ["'net-info'", () => ({ code: 1, stderr: "error: failed to get network" })],
  ]));
  const absentModel = modelWith(absent);
  const ctxA = createModelTestContext({ globalArgs: {} });
  const outA = await absentModel.methods.undefine_network.execute(
    absentModel.methods.undefine_network.arguments.parse(NET),
    ctxA.context,
  );
  assertEquals(outA.result.changed, false);
  assertEquals(has(absent, "'net-undefine'"), false);

  const active = fakeLibvirt(seq([
    [
      "'net-info'",
      () => ({
        code: 0,
        stdout: "Name: default\nActive: yes\nAutostart: yes\nUUID: u1\n",
      }),
    ],
    ["'net-destroy'", () => ({ code: 0 })],
    ["'net-undefine'", () => ({ code: 0 })],
  ]));
  const activeModel = modelWith(active);
  const ctxB = createModelTestContext({ globalArgs: {} });
  const outB = await activeModel.methods.undefine_network.execute(
    activeModel.methods.undefine_network.arguments.parse({
      ...NET,
      name: "default",
    }),
    ctxB.context,
  );
  assertEquals(outB.result.changed, true);
  assertEquals(has(active, "'net-destroy'"), true);
  assertEquals(has(active, "'net-undefine'"), true);
});

Deno.test("clone_volume: clones once, then is a no-op on an existing target", async () => {
  const f = fakeLibvirt(seq([
    [
      "'golden'",
      () => ({ code: 0, stdout: "Name: golden\nPath: /p/golden\n" }),
    ],
    [
      "'node-a-root'",
      (n) =>
        n === 0 ? { code: 1, stderr: "error: Storage volume not found" } : {
          code: 0,
          stdout: "Name: node-a-root\nPath: /p/node-a-root\nCapacity: 20 GiB\n",
        },
    ],
    ["'vol-clone'", () => ({ code: 0 })],
    [
      "'vol-info'",
      () => ({ code: 0, stdout: "Name: node-a-root\nPath: /p/node-a-root\n" }),
    ],
  ]));
  const m = modelWith(f);
  const args = m.methods.clone_volume.arguments.parse({
    ...SSH,
    uri: URI,
    pool: "pool-a",
    source_volume: "golden",
    target_volume: "node-a-root",
  });
  const ctx = createModelTestContext({ globalArgs: {} });
  const out = await m.methods.clone_volume.execute(args, ctx.context);
  assertEquals(out.result.changed, true);
  assertEquals(has(f, "'vol-clone'"), true);
});

Deno.test("clone_volume: a missing golden volume is a typed error", async () => {
  const f = fakeLibvirt(seq([
    [
      "'golden'",
      () => ({ code: 1, stderr: "error: Storage volume not found" }),
    ],
  ]));
  const m = modelWith(f);
  const ctx = createModelTestContext({ globalArgs: {} });
  await assertRejects(
    () =>
      m.methods.clone_volume.execute(
        m.methods.clone_volume.arguments.parse({
          ...SSH,
          uri: URI,
          pool: "pool-a",
          source_volume: "golden",
          target_volume: "node-a-root",
        }),
        ctx.context,
      ),
    Error,
    "not found",
  );
  assertEquals(ctx.getWrittenResources().length, 0);
});

Deno.test("define_domain: defines from the clone and starts when asked", async () => {
  const f = fakeLibvirt(seq([
    [
      "'vol-info'",
      () => ({ code: 0, stdout: "Name: node-a-root\nPath: /p/x\n" }),
    ],
    ["'vol-path'", () => ({ code: 0, stdout: "/p/node-a-root.qcow2\n" })],
    [
      "'dominfo'",
      (n) =>
        n === 0
          ? { code: 1, stderr: "error: failed to get domain" }
          : { code: 0, stdout: SHUT_OFF },
    ],
    ["'define'", () => ({ code: 0 })],
    ["'start'", () => ({ code: 0 })],
  ]));
  const m = modelWith(f);
  const ctx = createModelTestContext({ globalArgs: {} });
  const out = await m.methods.define_domain.execute(
    m.methods.define_domain.arguments.parse({
      ...SSH,
      uri: URI,
      name: "node-a",
      pool: "pool-a",
      volume: "node-a-root",
      vcpus: 2,
      memory_mib: 2048,
      network: "net-a",
      start: true,
    }),
    ctx.context,
  );
  assertEquals(out.result.changed, true);
  assertEquals(has(f, "'vol-path'"), true);
  assertEquals(has(f, "'define'"), true);
  assertEquals(has(f, "'start'"), true);
  // The uploaded XML must use type='file' with the resolved path, and ACPI.
  const xml = f.uploads[0];
  assertEquals(xml.includes("<disk type='file' device='disk'>"), true);
  assertEquals(xml.includes("<source file='/p/node-a-root.qcow2'/>"), true);
  assertEquals(xml.includes("<source pool="), false);
  assertEquals(xml.includes("<acpi/>"), true);
});

Deno.test("define_domain: extra_disks attach a read-only seed", async () => {
  const f = fakeLibvirt(seq([
    ["'vol-info'", () => ({ code: 0, stdout: "Name: node-a-root\n" })],
    ["'vol-path'", () => ({ code: 0, stdout: "/p/node-a-root.qcow2\n" })],
    [
      "'dominfo'",
      (n) =>
        n === 0
          ? { code: 1, stderr: "error: failed to get domain" }
          : { code: 0, stdout: SHUT_OFF },
    ],
    ["'define'", () => ({ code: 0 })],
  ]));
  const m = modelWith(f);
  const ctx = createModelTestContext({ globalArgs: {} });
  await m.methods.define_domain.execute(
    m.methods.define_domain.arguments.parse({
      ...SSH,
      uri: URI,
      name: "node-a",
      pool: "pool-a",
      volume: "node-a-root",
      vcpus: 1,
      memory_mib: 1024,
      extra_disks: [{ path: "/p/seed.iso", device: "cdrom" }],
    }),
    ctx.context,
  );
  const xml = f.uploads[0];
  assertEquals(xml.includes("<disk type='file' device='cdrom'>"), true);
  assertEquals(xml.includes("<source file='/p/seed.iso'/>"), true);
  assertEquals(xml.includes("<readonly/>"), true);
});

Deno.test("power: idempotent toward the state; destroy runs; reboot off refuses", async () => {
  const running = fakeLibvirt(seq([
    ["'dominfo'", () => ({ code: 0, stdout: RUNNING })],
  ]));
  const rm = modelWith(running);
  const rc = createModelTestContext({ globalArgs: {} });
  const startArgs = rm.methods.power.arguments.parse({
    ...SSH,
    uri: URI,
    name: "node-a",
    action: "start",
  });
  const noop = await rm.methods.power.execute(startArgs, rc.context);
  assertEquals(noop.result.changed, false);
  assertEquals(has(running, "'start'"), false);

  const destroy = fakeLibvirt(seq([
    [
      "'dominfo'",
      (n) =>
        n === 0 ? { code: 0, stdout: RUNNING } : { code: 0, stdout: SHUT_OFF },
    ],
    ["'destroy'", () => ({ code: 0 })],
  ]));
  const dm = modelWith(destroy);
  const dc = createModelTestContext({ globalArgs: {} });
  const destroyed = await dm.methods.power.execute(
    dm.methods.power.arguments.parse({
      ...SSH,
      uri: URI,
      name: "node-a",
      action: "destroy",
    }),
    dc.context,
  );
  assertEquals(destroyed.result.changed, true);
  assertEquals(has(destroy, "'destroy'"), true);

  const off = fakeLibvirt(
    seq([["'dominfo'", () => ({ code: 0, stdout: SHUT_OFF })]]),
  );
  const om = modelWith(off);
  await assertRejects(
    () =>
      om.methods.power.execute(
        om.methods.power.arguments.parse({
          ...SSH,
          uri: URI,
          name: "node-a",
          action: "reboot",
        }),
        createModelTestContext({ globalArgs: {} }).context,
      ),
    Error,
    "not running",
  );
});

Deno.test("console: bounded capture stores the text and returns only its digest", async () => {
  const f = fakeLibvirt(seq([
    ["'dominfo'", () => ({ code: 0, stdout: RUNNING })],
    ["'console'", () => ({ code: 0, stdout: "boot log line\nlogin: " })],
  ]));
  const m = modelWith(f);
  const ctx = createModelTestContext({ globalArgs: {} });
  const out = await m.methods.console.execute(
    m.methods.console.arguments.parse({
      ...SSH,
      uri: URI,
      name: "node-a",
      timeout_s: 5,
    }),
    ctx.context,
  );
  assertEquals(out.result.bytes, "boot log line\nlogin: ".length);
  assertEquals(typeof out.result.sha256, "string");
  assertEquals((out.result as Record<string, unknown>).text, undefined);
  assertEquals(has(f, "console"), true);
  assertEquals(f.commands.some((c) => c.includes("timeout")), true);
  assertEquals(f.commands.some((c) => c.includes("script")), true);
  assertEquals(has(f, "--force"), true);
  assertEquals(has(f, "--force"), true);
  const written = ctx.getWrittenResources()[0];
  assertEquals(written.data.text, "boot log line\nlogin: ");
  assertEquals(written.data.sha256, out.result.sha256);
  const textMeta = (m.resources.console_capture.schema as unknown as {
    shape: Record<string, { meta: () => { sensitive?: boolean } }>;
  }).shape.text.meta();
  assertEquals(textMeta.sensitive, true);
  assertEquals(written.name.includes("console"), true);
});

Deno.test("undefine_domain: absent no-op; running destroy + undefine with volumes", async () => {
  const absent = fakeLibvirt(seq([
    ["'dominfo'", () => ({ code: 1, stderr: "error: failed to get domain" })],
  ]));
  const am = modelWith(absent);
  const ac = createModelTestContext({ globalArgs: {} });
  const a = await am.methods.undefine_domain.execute(
    am.methods.undefine_domain.arguments.parse({
      ...SSH,
      uri: URI,
      name: "node-a",
    }),
    ac.context,
  );
  assertEquals(a.result.changed, false);
  assertEquals(has(absent, "'undefine'"), false);

  const running = fakeLibvirt(seq([
    ["'dominfo'", () => ({ code: 0, stdout: RUNNING })],
    ["'destroy'", () => ({ code: 0 })],
    [
      "'domblklist'",
      () => ({
        code: 0,
        stdout:
          " Type   Device   Target   Source\n----\n file   disk     vda      /p/root.qcow2\n",
      }),
    ],
    ["'undefine'", () => ({ code: 0 })],
  ]));
  const rm = modelWith(running);
  const rc = createModelTestContext({
    globalArgs: {},
    storedResources: domState("node-a", "/p/root.qcow2"),
  });
  const out = await rm.methods.undefine_domain.execute(
    rm.methods.undefine_domain.arguments.parse({
      ...SSH,
      uri: URI,
      name: "node-a",
      remove_volumes: true,
    }),
    rc.context,
  );
  assertEquals(out.result.changed, true);
  assertEquals(has(running, "'destroy'"), true);
  assertEquals(has(running, "--remove-all-storage"), true);
});

Deno.test("get and sync: inventory and drift", async () => {
  const f = fakeLibvirt(seq([
    ["'net-list'", () => ({ code: 0, stdout: "net-a\n" })],
    [
      "'net-info'",
      () => ({
        code: 0,
        stdout: "Name: net-a\nActive: yes\nAutostart: yes\nUUID: u1\n",
      }),
    ],
    ["'list'", () => ({ code: 0, stdout: "node-a\n" })],
    ["'dominfo'", () => ({ code: 0, stdout: RUNNING })],
    [
      "'vol-list'",
      () => ({ code: 0, stdout: "Name Path\n---- ----\nroot /p/root\n" }),
    ],
  ]));
  const m = modelWith(f);
  const ctx = createModelTestContext({ globalArgs: {} });
  const args = {
    ...SSH,
    uri: URI,
    pool: "pool-a",
  };
  const got = await m.methods.get.execute(
    m.methods.get.arguments.parse(args),
    ctx.context,
  );
  assertEquals(got.result.networks.length, 1);
  assertEquals(got.result.domains.length, 1);
  assertEquals(got.result.volumes.length, 1);
  assertEquals(got.result.target, TARGET);
});

Deno.test("transport failure: typed error, no state written", async () => {
  const f = fakeLibvirt(() => ({
    code: 255,
    stderr: "Permission denied (publickey).",
  }));
  // Bypass the fake's ssh handling for a direct transport failure.
  const m = modelWith(f);
  const ctx = createModelTestContext({ globalArgs: {} });
  await assertRejects(
    () =>
      m.methods.get.execute(
        m.methods.get.arguments.parse({ ...SSH, uri: URI }),
        ctx.context,
      ),
    SshError,
  );
  assertEquals(ctx.getWrittenResources().length, 0);
});

Deno.test("virsh non-zero exit: typed error, no success state written", async () => {
  const f = fakeLibvirt(seq([
    [
      "'net-list'",
      () => ({ code: 1, stderr: "failed to connect to the hypervisor" }),
    ],
  ]));
  const m = modelWith(f);
  const ctx = createModelTestContext({ globalArgs: {} });
  await assertRejects(
    () =>
      m.methods.get.execute(
        m.methods.get.arguments.parse({ ...SSH, uri: URI }),
        ctx.context,
      ),
    Error,
    "virsh net-list failed",
  );
  assertEquals(ctx.getWrittenResources().length, 0);
});

Deno.test("console: a timed-out capture returns the text so far, never hangs", async () => {
  // The console wrapper turns the timeout (SIGKILL 137 / timeout 124) into
  // exit 0, so the bytes read before the bound are a normal capture.
  const f = fakeLibvirt(seq([
    ["'dominfo'", () => ({ code: 0, stdout: RUNNING })],
    ["'console'", () => ({ code: 0, stdout: "partial boot log\n" })],
  ]));
  const m = modelWith(f);
  const ctx = createModelTestContext({ globalArgs: {} });
  const out = await m.methods.console.execute(
    m.methods.console.arguments.parse({
      ...SSH,
      uri: URI,
      name: "node-a",
      timeout_s: 1,
    }),
    ctx.context,
  );
  assertEquals(out.result.bytes, "partial boot log\n".length);
  assertEquals((out.result as Record<string, unknown>).text, undefined);
  assertEquals(ctx.getWrittenResources()[0].data.text, "partial boot log\n");
  assertEquals(ctx.getWrittenResources().length, 1);
});

Deno.test("console refuses a domain that is not running", async () => {
  const f = fakeLibvirt(seq([
    ["'dominfo'", () => ({ code: 0, stdout: SHUT_OFF })],
  ]));
  const m = modelWith(f);
  await assertRejects(
    () =>
      m.methods.console.execute(
        m.methods.console.arguments.parse({
          ...SSH,
          uri: URI,
          name: "node-a",
        }),
        createModelTestContext({ globalArgs: {} }).context,
      ),
    Error,
    "not running",
  );
  assertEquals(has(f, "'console'"), false);
});

Deno.test("console: a virsh error is a typed error, not a capture", async () => {
  const f = fakeLibvirt(seq([
    ["'dominfo'", () => ({ code: 0, stdout: RUNNING })],
    [
      "'console'",
      () => ({ code: 1, stdout: "error: The domain is not running\n" }),
    ],
  ]));
  const m = modelWith(f);
  const ctx = createModelTestContext({ globalArgs: {} });
  await assertRejects(
    () =>
      m.methods.console.execute(
        m.methods.console.arguments.parse({
          ...SSH,
          uri: URI,
          name: "node-a",
        }),
        ctx.context,
      ),
    Error,
    "could not attach to the console",
  );
  assertEquals(ctx.getWrittenResources().length, 0);
});

Deno.test("power shutdown waits for the guest to power off", async () => {
  const f = fakeLibvirt(seq([
    [
      "'dominfo'",
      (n) =>
        n < 2 ? { code: 0, stdout: RUNNING } : { code: 0, stdout: SHUT_OFF },
    ],
    ["'shutdown'", () => ({ code: 0 })],
  ]));
  const m = modelWith(f);
  const ctx = createModelTestContext({ globalArgs: {} });
  const out = await m.methods.power.execute(
    m.methods.power.arguments.parse({
      ...SSH,
      uri: URI,
      name: "node-a",
      action: "shutdown",
      shutdown_timeout_s: 60,
      poll_interval_s: 5,
    }),
    ctx.context,
  );
  assertEquals(out.result.changed, true);
  assertEquals(out.result.state, "shut off");
});

Deno.test("power shutdown times out rather than reporting success", async () => {
  const f = fakeLibvirt(seq([
    ["'dominfo'", () => ({ code: 0, stdout: RUNNING })],
    ["'shutdown'", () => ({ code: 0 })],
  ]));
  const m = modelWith(f);
  const ctx = createModelTestContext({ globalArgs: {} });
  await assertRejects(
    () =>
      m.methods.power.execute(
        m.methods.power.arguments.parse({
          ...SSH,
          uri: URI,
          name: "node-a",
          action: "shutdown",
          shutdown_timeout_s: 10,
          poll_interval_s: 5,
        }),
        ctx.context,
      ),
    Error,
    "did not shut down within 10s",
  );
  assertEquals(ctx.getWrittenResources().length, 0);
});

Deno.test("define_network: a start failure is typed and rolls back", async () => {
  const f = fakeLibvirt(seq([
    [
      "'net-info'",
      (n) =>
        n === 0 ? { code: 1, stderr: "error: failed to get network" } : {
          code: 0,
          stdout: "Name: net-a\nActive: no\nAutostart: no\nUUID: u1\n",
        },
    ],
    ["'net-define'", () => ({ code: 0 })],
    [
      "'net-start'",
      () => ({
        code: 1,
        stderr:
          "error: error creating bridge interface virbr-x: Numerical result out of range",
      }),
    ],
    ["'net-undefine'", () => ({ code: 0 })],
  ]));
  const m = modelWith(f);
  const ctx = createModelTestContext({ globalArgs: {} });
  await assertRejects(
    () =>
      m.methods.define_network.execute(
        m.methods.define_network.arguments.parse({
          ...NET,
          mode: "nat",
          gateway: "192.0.2.1",
          start: true,
        }),
        ctx.context,
      ),
    Error,
    "Numerical result out of range",
  );
  assertEquals(has(f, "'net-define'"), true);
  assertEquals(has(f, "'net-undefine'"), true);
  assertEquals(ctx.getWrittenResources().length, 0);
});

Deno.test("undefine_domain keeps a seed ISO unless asked to remove it", async () => {
  const mk = () =>
    fakeLibvirt(seq([
      ["'dominfo'", () => ({ code: 0, stdout: SHUT_OFF })],
      [
        "'domblklist'",
        () => ({
          code: 0,
          stdout:
            " Type   Device   Target   Source\n-----------------------------------------------\n file   disk     vda      /p/root.qcow2\n file   cdrom    sda      /p/seed.iso\n",
        }),
      ],
      ["'detach-disk'", () => ({ code: 0 })],
      ["'undefine'", () => ({ code: 0 })],
    ]));
  const kept = mk();
  await modelWith(kept).methods.undefine_domain.execute(
    modelWith(kept).methods.undefine_domain.arguments.parse({
      ...SSH,
      uri: URI,
      name: "node-a",
      remove_volumes: true,
    }),
    createModelTestContext({
      globalArgs: {},
      storedResources: domState("node-a", "/p/root.qcow2"),
    }).context,
  );
  assertEquals(has(kept, "'detach-disk'"), true);
  assertEquals(
    kept.commands.some((c) =>
      c.includes("'undefine'") && c.includes("--remove-all-storage")
    ),
    true,
  );

  const removed = mk();
  await modelWith(removed).methods.undefine_domain.execute(
    modelWith(removed).methods.undefine_domain.arguments.parse({
      ...SSH,
      uri: URI,
      name: "node-a",
      remove_volumes: true,
      remove_attached_media: true,
    }),
    createModelTestContext({ globalArgs: {} }).context,
  );
  assertEquals(has(removed, "'detach-disk'"), false);
});

Deno.test("clone_volume records the qemu format from the volume XML", async () => {
  const f = fakeLibvirt(seq([
    [
      "'vol-dumpxml'",
      () => ({
        code: 0,
        stdout:
          "<volume type='file'><target><format type='raw'/></target></volume>",
      }),
    ],
    ["'golden'", () => ({ code: 0, stdout: "Name: golden\n" })],
    [
      "'node-a-root'",
      (n) =>
        n === 0
          ? { code: 1, stderr: "error: Storage volume not found" }
          : { code: 0, stdout: "Name: node-a-root\nPath: /p/node-a-root\n" },
    ],
    ["'vol-clone'", () => ({ code: 0 })],
    [
      "'vol-info'",
      () => ({ code: 0, stdout: "Name: node-a-root\nPath: /p/x\n" }),
    ],
    [
      "'vol-dumpxml'",
      () => ({
        code: 0,
        stdout:
          "<volume type='file'><target><format type='raw'/></target></volume>",
      }),
    ],
  ]));
  const m = modelWith(f);
  const ctx = createModelTestContext({ globalArgs: {} });
  await m.methods.clone_volume.execute(
    m.methods.clone_volume.arguments.parse({
      ...SSH,
      uri: URI,
      pool: "pool-a",
      source_volume: "golden",
      target_volume: "node-a-root",
    }),
    ctx.context,
  );
  assertEquals(ctx.getWrittenResources()[0].data.format, "raw");
});

Deno.test("schema: max_output_bytes is bounded and defaults to the transport cap", () => {
  const m = createModel();
  const parsed = m.methods.get.arguments.parse({ ...SSH, uri: URI });
  assertEquals(parsed.max_output_bytes, 10485760);
  assertEquals(
    m.methods.get.arguments.safeParse({ ...SSH, uri: URI, max_output_bytes: 0 })
      .success,
    false,
  );
  assertEquals(
    m.methods.get.arguments.safeParse({
      ...SSH,
      uri: URI,
      max_output_bytes: 104857601,
    }).success,
    false,
  );
  assertEquals(
    m.methods.get.arguments.safeParse({
      ...SSH,
      uri: URI,
      max_output_bytes: 4096,
    }).success,
    true,
  );
});

Deno.test("undefine_domain detaches every non-boot disk before removing volumes", async () => {
  const f = fakeLibvirt(seq([
    ["'dominfo'", () => ({ code: 0, stdout: SHUT_OFF })],
    [
      "'domblklist'",
      () => ({
        code: 0,
        stdout:
          " Type   Device   Target   Source\n----\n file   disk     vda      /p/root.qcow2\n file   disk     vdb      /p/other-root.qcow2\n file   cdrom    sda      /p/seed.iso\n",
      }),
    ],
    ["'detach-disk'", () => ({ code: 0 })],
    ["'undefine'", () => ({ code: 0 })],
  ]));
  await modelWith(f).methods.undefine_domain.execute(
    modelWith(f).methods.undefine_domain.arguments.parse({
      ...SSH,
      uri: URI,
      name: "node-a",
      remove_volumes: true,
    }),
    createModelTestContext({
      globalArgs: {},
      storedResources: domState("node-a", "/p/root.qcow2"),
    }).context,
  );
  const detached = f.commands.filter((c) => c.includes("'detach-disk'"));
  assertEquals(detached.some((c) => c.includes("'vdb'")), true);
  assertEquals(detached.some((c) => c.includes("'sda'")), true);
  assertEquals(detached.some((c) => c.includes("'vda'")), false);
});

Deno.test("undefine_domain refuses an invalid disk target from domblklist", async () => {
  const f = fakeLibvirt(seq([
    ["'dominfo'", () => ({ code: 0, stdout: SHUT_OFF })],
    [
      "'domblklist'",
      () => ({
        code: 0,
        stdout:
          " Type   Device   Target   Source\n----\n file   disk     vda      /p/root.qcow2\n file   disk     vda;id   /p/x\n",
      }),
    ],
    ["'undefine'", () => ({ code: 0 })],
  ]));
  await assertRejects(
    () =>
      modelWith(f).methods.undefine_domain.execute(
        modelWith(f).methods.undefine_domain.arguments.parse({
          ...SSH,
          uri: URI,
          name: "node-a",
          remove_volumes: true,
        }),
        createModelTestContext({
          globalArgs: {},
          storedResources: domState("node-a", "/p/root.qcow2"),
        }).context,
      ),
    Error,
    "Not a valid disk target",
  );
  assertEquals(has(f, "'undefine'"), false);
});

Deno.test("define_domain rejects a duplicate explicit disk target", async () => {
  const f = fakeLibvirt(seq([
    ["'vol-info'", () => ({ code: 0, stdout: "Name: node-a-root\n" })],
    ["'vol-path'", () => ({ code: 0, stdout: "/p/node-a-root.qcow2\n" })],
  ]));
  await assertRejects(
    () =>
      modelWith(f).methods.define_domain.execute(
        modelWith(f).methods.define_domain.arguments.parse({
          ...SSH,
          uri: URI,
          name: "node-a",
          pool: "pool-a",
          volume: "node-a-root",
          vcpus: 1,
          memory_mib: 1024,
          extra_disks: [{ path: "/p/a.iso", target: "vda" }],
        }),
        createModelTestContext({ globalArgs: {} }).context,
      ),
    Error,
    "duplicate disk target",
  );
});

Deno.test("define_domain skips an explicitly reserved disk target", async () => {
  const f = fakeLibvirt(seq([
    ["'vol-info'", () => ({ code: 0, stdout: "Name: node-a-root\n" })],
    ["'vol-path'", () => ({ code: 0, stdout: "/p/node-a-root.qcow2\n" })],
    [
      "'dominfo'",
      (n) =>
        n === 0
          ? { code: 1, stderr: "error: failed to get domain" }
          : { code: 0, stdout: SHUT_OFF },
    ],
    ["'define'", () => ({ code: 0 })],
  ]));
  await modelWith(f).methods.define_domain.execute(
    modelWith(f).methods.define_domain.arguments.parse({
      ...SSH,
      uri: URI,
      name: "node-a",
      pool: "pool-a",
      volume: "node-a-root",
      vcpus: 1,
      memory_mib: 1024,
      extra_disks: [{ path: "/p/a.qcow2", target: "vdb" }, {
        path: "/p/b.qcow2",
      }],
    }),
    createModelTestContext({ globalArgs: {} }).context,
  );
  const xml = f.uploads[0];
  assertEquals(xml.includes("<target dev='vdb' bus='virtio'/>"), true);
  assertEquals(xml.includes("<target dev='vdc' bus='virtio'/>"), true);
});

Deno.test("define_network: the start error strips control characters", async () => {
  const f = fakeLibvirt(seq([
    [
      "'net-info'",
      (n) =>
        n === 0 ? { code: 1, stderr: "error: failed to get network" } : {
          code: 0,
          stdout: "Name: net-a\nActive: no\nAutostart: no\nUUID: u1\n",
        },
    ],
    ["'net-define'", () => ({ code: 0 })],
    ["'net-start'", () => ({ code: 1, stderr: "error: bad\u0001bridge\n" })],
    ["'net-undefine'", () => ({ code: 0 })],
  ]));
  const error = await assertRejects(
    () =>
      modelWith(f).methods.define_network.execute(
        modelWith(f).methods.define_network.arguments.parse({
          ...NET,
          mode: "nat",
          gateway: "192.0.2.1",
          start: true,
        }),
        createModelTestContext({ globalArgs: {} }).context,
      ),
    Error,
    "bad bridge",
  );
  assertEquals(error.message.includes("\u0001"), false);
});

Deno.test("undefine_domain refuses remove_volumes without a recorded root", async () => {
  const f = fakeLibvirt(seq([
    ["'dominfo'", () => ({ code: 0, stdout: SHUT_OFF })],
  ]));
  await assertRejects(
    () =>
      modelWith(f).methods.undefine_domain.execute(
        modelWith(f).methods.undefine_domain.arguments.parse({
          ...SSH,
          uri: URI,
          name: "node-a",
          remove_volumes: true,
        }),
        createModelTestContext({ globalArgs: {} }).context,
      ),
    Error,
    "no recorded root disk",
  );
  assertEquals(has(f, "'undefine'"), false);
});

Deno.test("undefine_domain refuses when no disk matches the recorded root", async () => {
  const f = fakeLibvirt(seq([
    ["'dominfo'", () => ({ code: 0, stdout: SHUT_OFF })],
    [
      "'domblklist'",
      () => ({
        code: 0,
        stdout:
          " Type   Device   Target   Source\n----\n file   disk     sda      /p/other.qcow2\n",
      }),
    ],
  ]));
  await assertRejects(
    () =>
      modelWith(f).methods.undefine_domain.execute(
        modelWith(f).methods.undefine_domain.arguments.parse({
          ...SSH,
          uri: URI,
          name: "node-a",
          remove_volumes: true,
        }),
        createModelTestContext({
          globalArgs: {},
          storedResources: domState("node-a", "/p/root.qcow2"),
        }).context,
      ),
    Error,
    "no attached disk matches the recorded root",
  );
});

Deno.test("undefine_domain keeps a root disk at a non-vda target", async () => {
  const f = fakeLibvirt(seq([
    ["'dominfo'", () => ({ code: 0, stdout: SHUT_OFF })],
    [
      "'domblklist'",
      () => ({
        code: 0,
        stdout:
          " Type   Device   Target   Source\n----\n file   disk     sda      /p/root.qcow2\n file   disk     sdb      /p/extra.qcow2\n",
      }),
    ],
    ["'detach-disk'", () => ({ code: 0 })],
    ["'undefine'", () => ({ code: 0 })],
  ]));
  await modelWith(f).methods.undefine_domain.execute(
    modelWith(f).methods.undefine_domain.arguments.parse({
      ...SSH,
      uri: URI,
      name: "node-a",
      remove_volumes: true,
    }),
    createModelTestContext({
      globalArgs: {},
      storedResources: domState("node-a", "/p/root.qcow2"),
    }).context,
  );
  const detached = f.commands.filter((c) => c.includes("'detach-disk'"));
  assertEquals(detached.some((c) => c.includes("'sdb'")), true);
  assertEquals(detached.some((c) => c.includes("'sda'")), false);
});

Deno.test("define_domain reserves explicit targets before allocating implicit", async () => {
  const run = async (extra_disks: unknown[]) => {
    const f = fakeLibvirt(seq([
      ["'vol-info'", () => ({ code: 0, stdout: "Name: node-a-root\n" })],
      ["'vol-path'", () => ({ code: 0, stdout: "/p/node-a-root.qcow2\n" })],
      [
        "'dominfo'",
        (n) =>
          n === 0
            ? { code: 1, stderr: "error: failed to get domain" }
            : { code: 0, stdout: SHUT_OFF },
      ],
      ["'define'", () => ({ code: 0 })],
    ]));
    await modelWith(f).methods.define_domain.execute(
      modelWith(f).methods.define_domain.arguments.parse({
        ...SSH,
        uri: URI,
        name: "node-a",
        pool: "pool-a",
        volume: "node-a-root",
        vcpus: 1,
        memory_mib: 1024,
        extra_disks,
      }),
      createModelTestContext({ globalArgs: {} }).context,
    );
    return f.uploads[0];
  };
  // An implicit disk before the explicit vdb must not take vdb.
  const implicitFirst = await run([
    { path: "/p/a.qcow2" },
    { path: "/p/b.qcow2", target: "vdb" },
  ]);
  assertEquals(
    implicitFirst.includes("<target dev='vdc' bus='virtio'/>"),
    true,
  );
  // And the same when the explicit vdb comes first.
  const explicitFirst = await run([
    { path: "/p/b.qcow2", target: "vdb" },
    { path: "/p/a.qcow2" },
  ]);
  assertEquals(
    explicitFirst.includes("<target dev='vdc' bus='virtio'/>"),
    true,
  );
});

Deno.test("schema: host_key_policy is strict-only with required host_keys", () => {
  const m = createModel();
  assertThrows(() =>
    m.methods.get.arguments.parse({
      ...SSH,
      host_key_policy: "insecure_tofu",
    })
  );
  assertThrows(() => m.methods.get.arguments.parse({ ...SSH, host_keys: [] }));
  assertEquals(
    m.methods.get.arguments.safeParse({ ...SSH, uri: URI }).success,
    true,
  );
});
