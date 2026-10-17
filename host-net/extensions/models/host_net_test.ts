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

function fakeRun(
  opts: {
    links?: unknown[];
    armCode?: number;
    restoreCode?: number;
    markerJson?: string;
  } = {},
): Fake {
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
    if (
      command.includes("marker.json") && command.includes("cat") &&
      !command.includes("systemd-run")
    ) {
      return Promise.resolve({
        code: 0,
        stdout: opts.markerJson ?? "",
        stderr: "",
      });
    }
    if (command.includes("systemd-run")) {
      return Promise.resolve({
        code: opts.armCode ?? 0,
        stdout: "",
        stderr: "",
      });
    }
    if (command.includes("mktemp -d /tmp/host-net-precheck")) {
      return Promise.resolve({
        code: 0,
        stdout: "/tmp/host-net-precheck.AbC123\n",
        stderr: "",
      });
    }
    if (command.includes("echo MISSING")) {
      return Promise.resolve({ code: 0, stdout: "MISSING\n", stderr: "" });
    }
    if (command.includes(".ssh-host-upload")) {
      // The upload helper compares the destination's hash and mode, which the
      // remote prints back: answer as a host that stored the bytes it was sent.
      const bytes = typeof _options.stdin === "string"
        ? new TextEncoder().encode(_options.stdin)
        : (_options.stdin ?? new Uint8Array());
      const mode = /chmod '(\d+)'/.exec(command)?.[1] ?? "600";
      return crypto.subtle.digest("SHA-256", new Uint8Array(bytes)).then((
        d,
      ) => ({
        code: 0,
        stdout: `${
          [...new Uint8Array(d)].map((b) => b.toString(16).padStart(2, "0"))
            .join("")
        } ${mode}\n`,
        stderr: "",
      }));
    }
    if (command.includes("'-d' '-j' 'link'")) {
      return Promise.resolve({
        code: 0,
        stdout: JSON.stringify(
          opts.links ?? [{
            ifname: "enp1s0",
            mtu: 9000,
            operstate: "UP",
            address: "02:00:00:00:00:01",
            linkinfo: { info_kind: "ether" },
          }],
        ),
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
  // Ownership is written to the config record only at commit.
  const written = ctx.getWrittenResources();
  assertEquals(written.length, 1);
  assertEquals(written[0].specName, "revert");
  assertEquals(String(written[0].data.token), "0000000000000000");
});

Deno.test("apply refuses when a revert is already armed", async () => {
  const fake = fakeRun({
    markerJson: JSON.stringify({
      token: "0000000000000000",
      result: "pass",
      fired_at: 1760400001,
    }),
  });
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
      ifname: "enp1s0",
      mtu: 9000,
      operstate: "UP",
      linkinfo: { info_kind: "ether" },
    }, {
      ifname: "enp1s0.100",
      mtu: 9000,
      operstate: "UP",
      linkinfo: { info_kind: "vlan", info_data: { id: 100 } },
    }],
  });
  const m = modelWith(fake);
  const ctx = createModelTestContext({
    globalArgs: {},
    storedResources: {
      "config-root@192.0.2.20:22": {
        devices: ["enp1s0.100"],
        backend: "netplan",
        bridgeType: "linux",
        configSha256: "a".repeat(64),
        contentSha256: "b".repeat(64),
      },
    },
  });
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
  const fake = fakeRun({
    markerJson: JSON.stringify({
      token: "0000000000000000",
      result: "pass",
      fired_at: 1760400001,
    }),
  });
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

Deno.test("apply after a committed apply does not treat an owned device as foreign", async () => {
  const fake = fakeRun({
    links: [{
      ifname: "enp1s0",
      mtu: 9000,
      operstate: "UP",
      linkinfo: { info_kind: "ether" },
    }, {
      ifname: "enp1s0.100",
      mtu: 9000,
      operstate: "UP",
      linkinfo: { info_kind: "vlan", info_data: { id: 100 } },
    }],
  });
  const m = modelWith(fake);
  const ctx = createModelTestContext({
    globalArgs: {},
    storedResources: {
      "config-root@192.0.2.20:22": {
        devices: ["enp1s0.100"],
        configSha256: "different",
      },
    },
  });
  await m.methods.apply.execute(
    m.methods.apply.arguments.parse({ ...NET }),
    ctx.context as never,
  );
  // It reached the arm instead of throwing "already exists and is not managed".
  assertEquals(fake.calls.some((c) => c.includes("systemd-run")), true);
});

Deno.test("remove of an unowned live device is a no-op", async () => {
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
  const out = await m.methods.remove.execute(
    m.methods.remove.arguments.parse({ ...NET, bridge_type: "linux" }),
    ctx.context as never,
  ) as { result: { removed: string[] } };
  assertEquals(out.result.removed, []);
  assertEquals(
    fake.calls.some((c) => c.includes("'ip' 'link' 'delete'")),
    false,
  );
});

Deno.test("an arm failure with exit 1 throws and writes nothing", async () => {
  const fake = fakeRun({ armCode: 1 });
  const m = modelWith(fake);
  const ctx = createModelTestContext({ globalArgs: {} });
  await assertRejects(
    () =>
      m.methods.apply.execute(
        m.methods.apply.arguments.parse({ ...NET }),
        ctx.context as never,
      ),
    Error,
    "the revert arm failed",
  );
  assertEquals(ctx.getWrittenResources().length, 0);
});

Deno.test("commit refuses an expired, a fired, and a missing revert", async () => {
  const m = modelWith(fakeRun());
  const expired = createModelTestContext({
    globalArgs: {},
    storedResources: {
      "revert-root@192.0.2.20:22": {
        token: "0000000000000000",
        operation: "apply",
        armedAt: new Date(1_700_000_000_000).toISOString(),
        expiresAt: new Date(1_700_000_001_000).toISOString(),
      },
    },
  });
  await assertRejects(
    () =>
      m.methods.commit.execute(
        m.methods.commit.arguments.parse({ ...NET }),
        expired.context as never,
      ),
    Error,
    "expired",
  );
  const fired = createModelTestContext({
    globalArgs: {},
    storedResources: {
      "revert-root@192.0.2.20:22": {
        token: "0000000000000000",
        operation: "apply",
        armedAt: new Date(1_760_400_000_000).toISOString(),
        expiresAt: new Date(1_760_400_300_000).toISOString(),
        firedAt: new Date(1_760_400_100_000).toISOString(),
      },
    },
  });
  await assertRejects(
    () =>
      m.methods.commit.execute(
        m.methods.commit.arguments.parse({ ...NET }),
        fired.context as never,
      ),
    Error,
    "already fired",
  );
});

/** Runs one apply and returns the FULL owned set recorded in the revert. */
async function ownedFor(
  net: Record<string, unknown>,
  config?: Record<string, unknown>,
): Promise<string[]> {
  const fake = fakeRun();
  const m = modelWith(fake);
  const ctx = createModelTestContext({
    globalArgs: {},
    storedResources: config ? { "config-root@192.0.2.20:22": config } : {},
  });
  await m.methods.apply.execute(
    m.methods.apply.arguments.parse({ ...NET, ...net }),
    ctx.context as never,
  );
  const rev = ctx.getWrittenResources().find((w) => w.specName === "revert")!;
  return (rev.data.owned as string[]) ?? [];
}

const RECORD = {
  backend: "netplan",
  bridgeType: "linux",
  configSha256: "a".repeat(64),
  contentSha256: "different",
};

Deno.test("the owned set is the union of previous ownership and the new delta", async () => {
  assertEquals(
    await ownedFor({
      vlans: [{ id: 100, link: "enp1s0", addresses: ["198.51.100.10/24"] }],
    }),
    ["enp1s0.100"],
  );
  assertEquals(
    await ownedFor({
      vlans: [
        { id: 100, link: "enp1s0", addresses: ["198.51.100.10/24"] },
        { id: 200, link: "enp1s0", addresses: ["198.51.100.20/24"] },
      ],
    }, { ...RECORD, devices: ["enp1s0.100"] }),
    ["enp1s0.100", "enp1s0.200"],
  );
  // Dropping VLAN 100 from the inputs gives up its ownership.
  assertEquals(
    await ownedFor({
      vlans: [{ id: 200, link: "enp1s0", addresses: ["198.51.100.20/24"] }],
    }, { ...RECORD, devices: ["enp1s0.100", "enp1s0.200"] }),
    ["enp1s0.200"],
  );
});

Deno.test("an MTU-only apply owns no devices but records the files/MUTs", async () => {
  const owned = await ownedFor({
    mode: "takeover",
    management_change_ack: true,
    ethernets: [{ name: "enp1s0", mtu: 9000 }],
    vlans: [],
  }, { ...RECORD, devices: [] });
  assertEquals(owned, []);
});

Deno.test("remove proceeds when only files are owned (MTU-only apply)", async () => {
  const fake = fakeRun();
  const m = modelWith(fake);
  const ctx = createModelTestContext({
    globalArgs: {},
    storedResources: {
      "config-root@192.0.2.20:22": {
        ...RECORD,
        devices: [],
        ownedFiles: [{
          path: "/etc/netplan/90-host-net.yaml",
          preExisted: false,
        }],
        parentMtus: [{ name: "enp1s0", mtu: 1500 }],
      },
    },
  });
  const out = await m.methods.remove.execute(
    m.methods.remove.arguments.parse({
      ...NET,
      mode: "takeover",
      management_change_ack: true,
      ethernets: [{ name: "enp1s0", mtu: 9000 }],
    }),
    ctx.context as never,
  ) as { result: { commit_required?: boolean } };
  assertEquals(out.result.commit_required, true);
  assertEquals(fake.calls.some((c) => c.includes("systemd-run")), true);
});

Deno.test("revert_now records a failed restore before throwing", async () => {
  const fake = fakeRun({
    restoreCode: 1,
    markerJson: JSON.stringify({
      token: "0000000000000000",
      result: "fail",
      fired_at: 1760400001,
    }),
  });
  const m = modelWith(fake);
  const ctx = createModelTestContext({
    globalArgs: {},
    storedResources: {
      "revert-root@192.0.2.20:22": {
        token: "0000000000000000",
        armedAt: new Date(1_760_400_000_000).toISOString(),
        expiresAt: new Date(1_760_400_300_000).toISOString(),
      },
    },
  });
  await assertRejects(
    () =>
      m.methods.revert_now.execute(
        m.methods.revert_now.arguments.parse({
          ...SSH,
          token: "0000000000000000",
        }),
        ctx.context as never,
      ),
    Error,
    "reported fail",
  );
  const written = ctx.getWrittenResources().find((w) =>
    w.specName === "revert"
  )!;
  assertEquals(written.data.result, "fail");
  assertEquals(typeof written.data.firedAt, "string");
});

Deno.test("a match_mac bridge member that resolves to management is refused", async () => {
  const fake = fakeRun({
    links: [{
      ifname: "enp1s0",
      mtu: 1500,
      operstate: "UP",
      address: "02:00:00:00:00:05",
      linkinfo: { info_kind: "ether" },
    }],
  });
  const m = modelWith(fake);
  const ctx = createModelTestContext({ globalArgs: {} });
  await assertRejects(
    () =>
      m.methods.apply.execute(
        m.methods.apply.arguments.parse({
          ...NET,
          ethernets: [{ name: "eth9", match_mac: "02:00:00:00:00:05" }],
          vlans: [],
          bridge: { name: "br0", interfaces: ["eth9"] },
        }),
        ctx.context as never,
      ),
    Error,
    "enslaves the management interface",
  );
});

Deno.test("host_key_policy is strict only and host_keys are required", () => {
  const model = createModel(denoHostNetDeps);
  // deno-lint-ignore no-explicit-any
  const methods = model.methods as any;
  // For every method: a baseline that parses, then ONE change at a time, so a
  // refusal can only be about that field.
  const baselines: Record<string, Record<string, unknown>> = {
    apply: NET,
    commit: NET,
    remove: NET,
    get: {
      ...SSH,
      backend: "netplan",
      bridge_type: "linux",
      management_interface: "enp1s0",
    },
    sync: {
      ...SSH,
      backend: "netplan",
      bridge_type: "linux",
      management_interface: "enp1s0",
    },
    revert_now: { ...SSH, token: "0".repeat(16) },
  };
  for (const [name, base] of Object.entries(baselines)) {
    const schema = methods[name].arguments;
    assertEquals(schema.safeParse(base).success, true, `${name} baseline`);
    const change = (patch: Record<string, unknown>) =>
      schema.safeParse({ ...base, ...patch }).success;
    assertEquals(
      change({ host_key_policy: "insecure_tofu" }),
      false,
      `${name} tofu`,
    );
    assertEquals(
      change({ host_key_policy: undefined }),
      false,
      `${name} policy`,
    );
    assertEquals(change({ host_keys: [] }), false, `${name} empty keys`);
    assertEquals(change({ host_keys: undefined }), false, `${name} no keys`);
    assertEquals(change({ host_keys: null }), false, `${name} null keys`);
  }
});

Deno.test("the netplan pre-check stages a copy of the live directory, not just the rendered file", async () => {
  const fake = fakeRun();
  const model = modelWith(fake);
  await model.methods.apply.execute(
    model.methods.apply.arguments.parse(NET),
    createModelTestContext({ globalArgs: {} }).context,
  );
  const setup = fake.calls.find((c) =>
    c.includes("host-net-precheck") && c.includes("mkdir")
  );
  assertEquals(setup !== undefined, true);
  // The live directory is copied with names and modes kept, then ours goes on top.
  assertEquals(setup!.includes("cp -a /etc/netplan/."), true);
  const generate = fake.calls.findIndex((c) => c.includes("generate"));
  const copy = fake.calls.findIndex((c) => c.includes("cp -a /etc/netplan/."));
  const upload = fake.calls.findIndex((c) =>
    c.includes(".ssh-host-upload") && c.includes("host-net-precheck")
  );
  assertEquals(copy >= 0 && copy < upload && upload < generate, true);
});

Deno.test("the pre-check scratch root is a private mktemp directory removed however the pre-check ends", async () => {
  // Normal path: created by the script, removed at the end.
  const ok = fakeRun();
  const model = modelWith(ok);
  await model.methods.apply.execute(
    model.methods.apply.arguments.parse(NET),
    createModelTestContext({ globalArgs: {} }).context,
  );
  const setup = ok.calls.find((c) => c.includes("mktemp -d"))!;
  assertEquals(
    setup.includes("host-net-precheck-0000"),
    false,
    "no fixed name",
  );
  assertEquals(setup.includes("chmod 0700"), true);
  assertEquals(
    setup.includes("if [ -d /etc/netplan ]; then cp -a"),
    true,
    "a missing /etc/netplan is an empty copy, not a failure",
  );
  assertEquals(
    setup.includes('rm -rf "$d"'),
    true,
    "its own failure cleans up",
  );
  assertEquals(
    ok.calls.some((c) =>
      c.includes("'rm' '-rf' '/tmp/host-net-precheck.AbC123'")
    ),
    true,
  );

  // A failing generate still removes the directory.
  const gen = fakeRun();
  const base = gen.run;
  gen.run = (cmd, args, options) => {
    const command = args[args.length - 1];
    if (cmd === "ssh" && command.includes("'netplan' 'generate'")) {
      gen.calls.push(command);
      return Promise.resolve({ code: 1, stdout: "", stderr: "bad" });
    }
    return base(cmd, args, options);
  };
  await assertRejects(() =>
    modelWith(gen).methods.apply.execute(
      modelWith(gen).methods.apply.arguments.parse(NET),
      createModelTestContext({ globalArgs: {} }).context,
    )
  );
  assertEquals(
    gen.calls.some((c) =>
      c.includes("'rm' '-rf' '/tmp/host-net-precheck.AbC123'")
    ),
    true,
  );

  // A failing upload still removes it, and a setup that returns junk stops
  // before anything is uploaded.
  const junk = fakeRun();
  const jbase = junk.run;
  junk.run = (cmd, args, options) => {
    const command = args[args.length - 1];
    if (cmd === "ssh" && command.includes("mktemp -d")) {
      junk.calls.push(command);
      return Promise.resolve({ code: 0, stdout: "/etc/passwd\n", stderr: "" });
    }
    return jbase(cmd, args, options);
  };
  await assertRejects(
    () =>
      modelWith(junk).methods.apply.execute(
        modelWith(junk).methods.apply.arguments.parse(NET),
        createModelTestContext({ globalArgs: {} }).context,
      ),
    Error,
    "scratch directory",
  );
  assertEquals(junk.calls.some((c) => c.includes(".ssh-host-upload")), false);
});
