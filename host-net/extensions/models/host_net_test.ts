import { assertEquals, assertRejects } from "jsr:@std/assert@1.0.19";
import { createModelTestContext } from "jsr:@swamp-club/swamp-testing@0.20261014.55";
import { createModel, denoHostNetDeps, VERSION } from "./host_net.ts";
import type { CommandRunner } from "./_lib/ssh.ts";

const SSH = {
  host: "192.0.2.20",
  port: 22,
  user: "root",
  host_key_policy: "strict" as const,
  host_keys: ["192.0.2.20 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFake"],
  ssh_key_ref: { vault: "prod", key: "host-net-key" },
  connect_timeout_s: 15,
};

const NET = {
  ...SSH,
  backend: "netplan" as const,
  bridge_type: "linux" as const,
  management_interface: "enp1s0",
  ethernets: [{ name: "enp1s0" }],
  vlans: [{
    id: 100,
    link: "enp1s0",
    mtu: 9000,
    addresses: ["198.51.100.10/24"],
  }],
  revert_after_s: 300,
};

interface Fake {
  run: CommandRunner;
  calls: string[];
}

function fakeRun(opts: { links?: unknown[]; armCode?: number } = {}): Fake {
  const calls: string[] = [];
  const run: CommandRunner = (cmd, args, _options = {}) => {
    if (cmd === "ssh-agent") {
      return Promise.resolve(
        args[0] === "-s"
          ? {
            code: 0,
            stdout: "SSH_AUTH_SOCK=/tmp/a.sock;\nSSH_AGENT_PID=1;\n",
            stderr: "",
          }
          : { code: 0, stdout: "", stderr: "" },
      );
    }
    if (cmd === "ssh-add") {
      return Promise.resolve({ code: 0, stdout: "", stderr: "" });
    }
    if (cmd !== "ssh") {
      return Promise.resolve({ code: 0, stdout: "", stderr: "" });
    }
    const command = args[args.length - 1];
    calls.push(command);
    if (command.includes("systemd-run")) {
      return Promise.resolve({
        code: opts.armCode ?? 0,
        stdout: "",
        stderr: "",
      });
    }
    if (command.includes("echo MISSING")) {
      return Promise.resolve({ code: 0, stdout: "MISSING\n", stderr: "" });
    }
    if (command.includes(".ssh-host-upload")) {
      return Promise.resolve({ code: 0, stdout: "", stderr: "" });
    }
    if (command.includes("'-d' '-j' 'link'")) {
      return Promise.resolve({
        code: 0,
        stdout: JSON.stringify(opts.links ?? []),
        stderr: "",
      });
    }
    if (command.includes("'-j' 'addr'")) {
      return Promise.resolve({
        code: 0,
        stdout: JSON.stringify([{
          ifname: "enp1s0",
          addr_info: [{ family: "inet", local: "192.0.2.10", prefixlen: 24 }],
        }]),
        stderr: "",
      });
    }
    if (command.includes("'route' 'show' 'default'")) {
      return Promise.resolve({
        code: 0,
        stdout: JSON.stringify([{
          dst: "default",
          gateway: "192.0.2.1",
          dev: "enp1s0",
          metric: 100,
        }]),
        stderr: "",
      });
    }
    if (command.includes("route get")) {
      return Promise.resolve({
        code: 0,
        stdout: JSON.stringify([{ dev: "enp1s0" }]),
        stderr: "",
      });
    }
    if (command.includes("command -v")) {
      return Promise.resolve({ code: 0, stdout: "yes\n", stderr: "" });
    }
    return Promise.resolve({ code: 0, stdout: "", stderr: "" });
  };
  return { run, calls };
}

function modelWith(fake: Fake) {
  return createModel({
    run: fake.run,
    now: () => 1_760_400_000_000,
    sleep: () => Promise.resolve(),
    resolveSecret: () => Promise.resolve("FAKEKEY"),
    token: () => "0000000000000000",
  });
}

Deno.test("the model type and version match the manifest", () => {
  const m = createModel();
  assertEquals(m.type, "@randybias/host-net");
  assertEquals(m.version, VERSION);
  assertEquals(m.globalArguments.safeParse({}).success, true);
  assertEquals(denoHostNetDeps.token !== undefined, true);
});

Deno.test("bridge_type is required with no default; ssh_key_ref is sensitive", () => {
  const m = createModel();
  const without = { ...NET } as Record<string, unknown>;
  delete without.bridge_type;
  assertEquals(m.methods.apply.arguments.safeParse(without).success, false);
  const shape = (m.methods.apply.arguments as unknown as {
    shape: Record<string, { meta: () => { sensitive?: boolean } }>;
  }).shape;
  assertEquals(shape.ssh_key_ref.meta().sensitive, true);
});

Deno.test("hostile values are rejected by the schema before any call", () => {
  const m = createModel();
  const args = m.methods.apply.arguments;
  for (
    const bad of [
      { ...NET, management_interface: "enp;rm" },
      {
        ...NET,
        vlans: [{
          id: 100,
          link: "enp1s0",
          addresses: ["198.51.100.10/24;id"],
        }],
      },
      {
        ...NET,
        vlans: [{ id: 0, link: "enp1s0", addresses: ["198.51.100.10/24"] }],
      },
      {
        ...NET,
        vlans: [{
          id: 100,
          link: "enp1s0",
          mtu: 100,
          addresses: ["198.51.100.10/24"],
        }],
      },
      { ...NET, extra: true },
    ]
  ) {
    assertEquals(args.safeParse(bad).success, false, JSON.stringify(bad));
  }
});

Deno.test("render is deterministic, touches no host, and returns the plan", async () => {
  const fake = fakeRun();
  const m = modelWith(fake);
  const out = await m.methods.render.execute(
    m.methods.render.arguments.parse({ ...NET }),
  ) as {
    result: { files: unknown[]; sha256: string; steps: { kind: string }[] };
  };
  assertEquals(out.result.files.length >= 1, true);
  assertEquals(out.result.sha256.length, 64);
  assertEquals(out.result.steps.some((s) => s.kind === "arm"), true);
  assertEquals(fake.calls.length, 0);
});

Deno.test("apply arms before it writes or applies", async () => {
  const fake = fakeRun();
  const m = modelWith(fake);
  const ctx = createModelTestContext({ globalArgs: {} });
  const out = await m.methods.apply.execute(
    m.methods.apply.arguments.parse({ ...NET }),
    ctx.context as never,
  ) as { result: { revert_token: string } };
  assertEquals(out.result.revert_token, "0000000000000000");
  const armAt = fake.calls.findIndex((c) => c.includes("systemd-run"));
  const mtuAt = fake.calls.findIndex((c) => c.includes("'ip' 'link' 'set'"));
  const applyAt = fake.calls.findIndex((c) => c.includes("superseded"));
  assertEquals(armAt >= 0, true);
  assertEquals(armAt < applyAt, true);
  assertEquals(armAt < mtuAt || mtuAt < 0, true);
  const written = ctx.getWrittenResources();
  assertEquals(written[0].specName, "revert");
  assertEquals(written[1].specName, "config");
  assertEquals(String(written[0].data.token), "0000000000000000");
});

Deno.test("apply refuses when a revert is already armed", async () => {
  const fake = fakeRun();
  const m = modelWith(fake);
  const ctx = createModelTestContext({
    globalArgs: {},
    storedResources: {
      "revert-root@192.0.2.20:22": {
        token: "deadbeefdeadbeef",
        target: "root@192.0.2.20:22",
        armedAt: new Date(1_760_400_000_000).toISOString(),
        expiresAt: new Date(1_760_400_300_000).toISOString(),
      },
    },
  });
  await assertRejects(
    () =>
      m.methods.apply.execute(
        m.methods.apply.arguments.parse({ ...NET }),
        ctx.context as never,
      ),
    Error,
    "already armed",
  );
});

Deno.test("remove arms before deleting and deletes only created devices", async () => {
  const fake = fakeRun({
    links: [{
      ifname: "enp1s0.100",
      mtu: 9000,
      operstate: "UP",
      linkinfo: { info_kind: "vlan", info_data: { id: 100 } },
    }],
  });
  const m = modelWith(fake);
  const ctx = createModelTestContext({ globalArgs: {} });
  await m.methods.remove.execute(
    m.methods.remove.arguments.parse({ ...NET, bridge_type: "linux" }),
    ctx.context as never,
  );
  const armAt = fake.calls.findIndex((c) => c.includes("systemd-run"));
  const delAt = fake.calls.findIndex((c) => c.includes("'ip' 'link' 'delete'"));
  assertEquals(armAt >= 0 && armAt < delAt, true);
  const deletes = fake.calls.filter((c) => c.includes("'ip' 'link' 'delete'"));
  assertEquals(deletes.length, 1);
  assertEquals(deletes[0].includes("enp1s0.100"), true);
  assertEquals(deletes[0].includes("'enp1s0'"), false);
});

Deno.test("revert_now runs the restore script for the token", async () => {
  const fake = fakeRun();
  const m = modelWith(fake);
  const ctx = createModelTestContext({
    globalArgs: {},
    storedResources: {
      "revert-root@192.0.2.20:22": {
        token: "0000000000000000",
        target: "root@192.0.2.20:22",
        armedAt: new Date(1_760_400_000_000).toISOString(),
        expiresAt: new Date(1_760_400_300_000).toISOString(),
      },
    },
  });
  const out = await m.methods.revert_now.execute(
    m.methods.revert_now.arguments.parse({ ...SSH, token: "0000000000000000" }),
    ctx.context as never,
  ) as { result: { fired: boolean } };
  assertEquals(out.result.fired, true);
  assertEquals(
    fake.calls.some((c) =>
      c.includes("/revert/0000000000000000/restore.sh") &&
      c.includes("0000000000000000")
    ),
    true,
  );
});

Deno.test("commit refuses without an armed revert", async () => {
  const fake = fakeRun();
  const m = modelWith(fake);
  const ctx = createModelTestContext({ globalArgs: {} });
  await assertRejects(
    () =>
      m.methods.commit.execute(
        m.methods.commit.arguments.parse({ ...NET }),
        ctx.context as never,
      ),
    Error,
    "no armed revert",
  );
});

Deno.test("an arm failure aborts before any network change", async () => {
  const fake = fakeRun({ armCode: 76 });
  const m = modelWith(fake);
  const ctx = createModelTestContext({ globalArgs: {} });
  await assertRejects(
    () =>
      m.methods.apply.execute(
        m.methods.apply.arguments.parse({ ...NET }),
        ctx.context as never,
      ),
    Error,
    "already armed",
  );
  assertEquals(fake.calls.some((c) => c.includes("'ip' 'link' 'set'")), false);
  // The real config is never written (only the staged pre-check copy is).
  assertEquals(
    fake.calls.some((c) => c.includes("f='/etc/netplan/90-host-net.yaml'")),
    false,
  );
  assertEquals(fake.calls.some((c) => c.includes("superseded")), false);
  assertEquals(ctx.getWrittenResources().length, 0);
});

Deno.test("the vaultService object resolves the SSH key", async () => {
  const fake = fakeRun();
  const m = createModel({
    run: fake.run,
    now: () => 1_760_400_000_000,
    sleep: () => Promise.resolve(),
    token: () => "0000000000000000",
  });
  const ctx = createModelTestContext({ globalArgs: {} });
  const calls: [string, string][] = [];
  (ctx.context as unknown as {
    vaultService: { get: (v: string, k: string) => Promise<string> };
  }).vaultService = {
    get: (v, k) => {
      calls.push([v, k]);
      return Promise.resolve("FAKEKEY");
    },
  };
  await m.methods.get.execute(
    m.methods.get.arguments.parse({
      ...SSH,
      backend: "netplan",
      bridge_type: "linux",
      management_interface: "enp1s0",
      revert_after_s: 300,
    }),
    ctx.context as never,
  );
  assertEquals(calls, [["prod", "host-net-key"]]);
});
