import { assertEquals, assertRejects } from "jsr:@std/assert@1.0.19";
import { createModelTestContext } from "jsr:@swamp-club/swamp-testing@0.20261014.55";
import { createModel, type HostDeps, hostInstance } from "./server_host.ts";
import { type CommandRunner } from "./_lib/ssh.ts";
import {
  type FirewallRules,
  managedTableSha256,
  renderRuleset,
  rulesetSha256,
} from "./_lib/nftables.ts";
import { renderSysctlConf } from "./_lib/plans.ts";

const NOW = 1_700_000_000_000;
const TOKEN = "0".repeat(16);
const PLACEHOLDER_SHA = "a".repeat(64);
const KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeKeyMaterialForTests";
const PEM =
  "-----BEGIN OPENSSH PRIVATE KEY-----\nZmFrZS1rZXktbWF0ZXJpYWw=\n-----END OPENSSH PRIVATE KEY-----";

const FIREWALL: FirewallRules = {
  managementCidrs: ["192.0.2.0/24"],
  allowTcp: [443],
  allowUdp: [53],
  defaultPolicy: "drop",
  sshPort: 22,
  allowSshFromAnywhere: false,
};

const SSH = {
  host: "192.0.2.10",
  port: 22,
  user: "root",
  host_key_policy: "insecure_tofu" as const,
  ssh_key_ref: { vault: "prod", key: "ssh-key" },
  connect_timeout_s: 15,
  sudo: true,
};

const FIREWALL_ARGS = {
  ...SSH,
  management_cidrs: FIREWALL.managementCidrs,
  allow_tcp: FIREWALL.allowTcp,
  allow_udp: FIREWALL.allowUdp,
  default_policy: "drop" as const,
  ssh_port: 22,
  allow_ssh_from_anywhere: false,
};

async function sha256Hex(text: string): Promise<string> {
  const d = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(text),
  );
  return [...new Uint8Array(d)].map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

interface Fake {
  deps: Partial<HostDeps>;
  commands: string[];
  stdins: string[];
  secrets: [string, string][];
}

/** A fake transport that records ssh commands, stdin and secret lookups. */
function fakeTransport(
  respond: (command: string) => { code: number; stdout?: string } = () => ({
    code: 0,
  }),
): Fake {
  const commands: string[] = [];
  const stdins: string[] = [];
  const secrets: [string, string][] = [];
  const run: CommandRunner = async (cmd, args, options = {}) => {
    await Promise.resolve();
    if (options.stdin) stdins.push(new TextDecoder().decode(options.stdin));
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
    const r = respond(command);
    return { code: r.code, stdout: r.stdout ?? "", stderr: "" };
  };
  const deps: Partial<HostDeps> = {
    run,
    makeTempDir: () => Promise.resolve("/tmp/t"),
    writeFile: () => Promise.resolve(),
    removeDir: () => Promise.resolve(),
    now: () => NOW,
    sleep: () => Promise.resolve(),
    token: () => TOKEN,
    resolveSecret: (vault, key) => {
      secrets.push([vault, key]);
      return Promise.resolve(PEM);
    },
  };
  return { deps, commands, stdins, secrets };
}

function modelWith(f: Fake) {
  return createModel(f.deps);
}

function liveResponse(rendered: string) {
  return (command: string): { code: number; stdout?: string } => {
    if (command.includes("'nft' 'list' 'ruleset'")) {
      return { code: 0, stdout: rendered };
    }
    return { code: 0 };
  };
}

Deno.test("schema: empty globals; mutating methods are actions; strict objects", () => {
  const m = createModel();
  assertEquals(Object.keys(m.globalArguments.shape), []);
  for (
    const name of [
      "apply_base",
      "apply_firewall",
      "lockdown",
      "commit",
    ] as const
  ) {
    assertEquals((m.methods[name] as { kind?: string }).kind, "action", name);
  }
  for (const name of ["render_firewall", "get", "sync"] as const) {
    assertEquals((m.methods[name] as { kind?: string }).kind, undefined, name);
  }
  assertEquals(
    typeof (m as { description?: string }).description,
    "string",
  );
  assertEquals(
    m.methods.apply_base.arguments.safeParse({
      ...SSH,
      admin_user: "ops",
      extra: 1,
    }).success,
    false,
  );
  const { host_key_policy: _p, ...noPolicy } = SSH;
  assertEquals(
    m.methods.apply_base.arguments.safeParse({ ...noPolicy, admin_user: "ops" })
      .success,
    false,
  );
});

Deno.test("schema: a literal private_key is rejected; ssh_key_ref is required", () => {
  const m = createModel();
  const literal = {
    host: SSH.host,
    port: 22,
    user: "root",
    host_key_policy: "insecure_tofu",
    private_key: PEM,
  };
  assertEquals(
    m.methods.apply_base.arguments.safeParse({ ...literal, admin_user: "ops" })
      .success,
    false,
  );
  const { ssh_key_ref: _r, ...noRef } = SSH;
  assertEquals(
    m.methods.apply_base.arguments.safeParse({ ...noRef, admin_user: "ops" })
      .success,
    false,
  );
  assertEquals(
    m.methods.apply_base.arguments.safeParse({
      ...SSH,
      admin_user: "ops",
      ssh_key_ref: { vault: "prod" },
    }).success,
    false,
  );
});

Deno.test("schema: invalid CIDR, port, key names and bounds are rejected", () => {
  const m = createModel();
  for (
    const args of [
      { host: SSH.host, management_cidrs: ["999.1.1.1/24"] },
      { host: SSH.host, allow_tcp: [70000] },
      { host: SSH.host, allow_udp: [0] },
      { host: SSH.host, management_cidrs: ["192.0.2.0/24"], extra: true },
    ]
  ) {
    assertEquals(
      m.methods.render_firewall.arguments.safeParse(args).success,
      false,
    );
  }
  assertEquals(
    m.methods.apply_base.arguments.safeParse({
      ...SSH,
      admin_user: "ops; rm -rf /",
    }).success,
    false,
  );
  assertEquals(
    m.methods.apply_base.arguments.safeParse({
      ...SSH,
      admin_user: "ops",
      packages: ["curl; rm -rf /"],
    }).success,
    false,
  );
  assertEquals(
    m.methods.apply_base.arguments.safeParse({
      ...SSH,
      admin_user: "ops",
      authorized_keys: [`${KEY}\nssh-rsa AAAAB3NzaC1yc2E`],
    }).success,
    false,
  );
  const big: Record<string, string> = {};
  for (let i = 0; i < 129; i++) big[`k${i}.x`] = "1";
  assertEquals(
    m.methods.apply_base.arguments.safeParse({
      ...SSH,
      admin_user: "ops",
      sysctl: big,
    }).success,
    false,
  );
});

Deno.test("apply_base: reads the key from the vault, never the arguments", async () => {
  const f = fakeTransport();
  const m = modelWith(f);
  const { context, getWrittenResources } = createModelTestContext({
    globalArgs: {},
  });
  const out = await m.methods.apply_base.execute(
    m.methods.apply_base.arguments.parse({
      ...SSH,
      packages: ["curl"],
      admin_user: "ops",
      authorized_keys: [KEY],
      sysctl: { "net.ipv4.ip_forward": "1" },
      timezone: "UTC",
    }),
    context,
  );
  assertEquals(f.secrets, [["prod", "ssh-key"]]);
  assertEquals(out.result.changed.includes("packages"), true);
  assertEquals(JSON.stringify(out.result).includes("PRIVATE KEY"), false);
  assertEquals(
    JSON.stringify(getWrittenResources()).includes("PRIVATE KEY"),
    false,
  );
  // The key reached ssh-add on stdin, not any argv.
  assertEquals(f.stdins.some((s) => s.includes("PRIVATE KEY")), true);
  assertEquals(f.commands.some((c) => c.includes("PRIVATE KEY")), false);
});

Deno.test("apply_base: an unchanged re-run emits no steps and reports nothing changed", async () => {
  const f = fakeTransport();
  const m = modelWith(f);
  const sysctl = { "net.ipv4.ip_forward": "1" };
  const name = `state-${hostInstance(SSH.host)}`;
  const { context } = createModelTestContext({
    globalArgs: {},
    storedResources: {
      [name]: {
        host: SSH.host,
        base: {
          packages: ["curl"],
          admin_user: "ops",
          authorized_keys_sha256: await sha256Hex([KEY].join("\n")),
          sysctl_sha256: await sha256Hex(renderSysctlConf(sysctl)),
          timezone: "UTC",
          applied_at: "2026-01-01T00:00:00.000Z",
        },
        observed_at: "2026-01-01T00:00:00.000Z",
      },
    },
  });
  const out = await m.methods.apply_base.execute(
    m.methods.apply_base.arguments.parse({
      ...SSH,
      packages: ["curl"],
      admin_user: "ops",
      authorized_keys: [KEY],
      sysctl,
      timezone: "UTC",
    }),
    context,
  );
  assertEquals(out.result.applied, []);
  assertEquals(out.result.changed, []);
  assertEquals(f.commands.length, 0);
});

Deno.test("apply_base: changing the account reinstalls the managed keys", async () => {
  const f = fakeTransport();
  const m = modelWith(f);
  const name = `state-${hostInstance(SSH.host)}`;
  const { context } = createModelTestContext({
    globalArgs: {},
    storedResources: {
      [name]: {
        host: SSH.host,
        base: {
          packages: [],
          admin_user: "oldops",
          authorized_keys_sha256: await rulesetSha256([KEY].join("\n")),
          sysctl_sha256: await rulesetSha256(renderSysctlConf({})),
          timezone: "UTC",
          applied_at: "2026-01-01T00:00:00.000Z",
        },
        observed_at: "2026-01-01T00:00:00.000Z",
      },
    },
  });
  const out = await m.methods.apply_base.execute(
    m.methods.apply_base.arguments.parse({
      ...SSH,
      packages: [],
      admin_user: "ops",
      authorized_keys: [KEY],
      sysctl: {},
      timezone: "UTC",
    }),
    context,
  );
  assertEquals(out.result.changed.includes("admin_user"), true);
  assertEquals(out.result.changed.includes("authorized_keys"), true);
  assertEquals(
    f.commands.some((c) => c.includes("authorized_keys")),
    true,
  );
});

Deno.test("render_firewall: also returns the canonical managed-table hash", async () => {
  const f = fakeTransport();
  const m = modelWith(f);
  const { context } = createModelTestContext({ globalArgs: {} });
  const rendered = renderRuleset(FIREWALL);
  const out = await m.methods.render_firewall.execute(
    m.methods.render_firewall.arguments.parse({
      host: SSH.host,
      management_cidrs: FIREWALL.managementCidrs,
      allow_tcp: FIREWALL.allowTcp,
      allow_udp: FIREWALL.allowUdp,
    }),
    context,
  );
  assertEquals(out.result.ruleset, rendered);
  assertEquals(out.result.ruleset_sha256, await rulesetSha256(rendered));
  assertEquals(out.result.managed_sha256, await managedTableSha256(rendered));
});

Deno.test("apply_firewall: the ssh command stream arms before it applies", async () => {
  const f = fakeTransport();
  const m = modelWith(f);
  const { context } = createModelTestContext({ globalArgs: {} });
  const out = await m.methods.apply_firewall.execute(
    m.methods.apply_firewall.arguments.parse(FIREWALL_ARGS),
    context,
  );
  assertEquals(out.result.revert_token, TOKEN);
  assertEquals(out.result.changed, true);
  const stageAt = f.commands.findIndex((c) =>
    c.includes("revert-") && c.includes("mktemp")
  );
  const armAt = f.commands.findIndex((c) => c.includes("systemd-run"));
  const applyAt = f.commands.findIndex((c) =>
    c.includes("'nft' '-f' '-'") && !c.includes("'-c'")
  );
  assertEquals(stageAt >= 0, true, "revert script staged");
  assertEquals(stageAt < armAt, true, "script staged before timer");
  assertEquals(armAt >= 0, true, "timer armed");
  assertEquals(applyAt > armAt, true, "timer armed before apply");
  assertEquals(
    f.commands.some((c) => c.includes("'nft' '-c' '-f' '-'")),
    true,
  );
});

Deno.test("apply_firewall: a matching ruleset that is still live is a no-op", async () => {
  const rendered = renderRuleset(FIREWALL);
  const ruleset_sha256 = await rulesetSha256(rendered);
  const managed_sha256 = await managedTableSha256(rendered);
  const name = `state-${hostInstance(SSH.host)}`;
  const f = fakeTransport(liveResponse(rendered));
  const m = modelWith(f);
  const { context } = createModelTestContext({
    globalArgs: {},
    storedResources: {
      [name]: {
        host: SSH.host,
        firewall: {
          ruleset_sha256,
          managed_sha256,
          mode: "firewall",
          ssh_exposure: "management-only",
          applied_at: "2026-01-01T00:00:00.000Z",
        },
        observed_at: "2026-01-01T00:00:00.000Z",
      },
    },
  });
  const out = await m.methods.apply_firewall.execute(
    m.methods.apply_firewall.arguments.parse(FIREWALL_ARGS),
    context,
  );
  assertEquals(out.result.changed, false);
  assertEquals(out.result.revert_token, null);
  assertEquals(f.commands.some((c) => c.includes("systemd-run")), false);
  assertEquals(
    f.commands.some((c) => c.includes("'nft' '-f' '-'") && !c.includes("'-c'")),
    false,
  );
});

Deno.test("apply_firewall: a stale record re-applies instead of trusting the sha", async () => {
  const rendered = renderRuleset(FIREWALL);
  const ruleset_sha256 = await rulesetSha256(rendered);
  const managed_sha256 = await managedTableSha256(rendered);
  const name = `state-${hostInstance(SSH.host)}`;
  // Live output has no managed table, as after a fired revert.
  const f = fakeTransport((c) =>
    c.includes("'nft' 'list' 'ruleset'") ? { code: 0, stdout: "" } : { code: 0 }
  );
  const m = modelWith(f);
  const { context } = createModelTestContext({
    globalArgs: {},
    storedResources: {
      [name]: {
        host: SSH.host,
        firewall: {
          ruleset_sha256,
          managed_sha256,
          mode: "firewall",
          ssh_exposure: "management-only",
          applied_at: "2026-01-01T00:00:00.000Z",
        },
        observed_at: "2026-01-01T00:00:00.000Z",
      },
    },
  });
  const out = await m.methods.apply_firewall.execute(
    m.methods.apply_firewall.arguments.parse(FIREWALL_ARGS),
    context,
  );
  assertEquals(out.result.changed, true);
  assertEquals(f.commands.some((c) => c.includes("systemd-run")), true);
});

Deno.test("apply_firewall: refuses a new change while a revert is armed", async () => {
  const rendered = renderRuleset(FIREWALL);
  const managed_sha256 = await managedTableSha256(rendered);
  const f = fakeTransport((c) => {
    if (c.includes("'nft' 'list' 'ruleset'")) {
      return { code: 0, stdout: rendered };
    }
    if (c.includes("'systemctl' 'is-active'")) {
      return { code: 0, stdout: "active\n" };
    }
    return { code: 0 };
  });
  const m = modelWith(f);
  const { context } = createModelTestContext({
    globalArgs: {},
    storedResources: {
      [`state-${hostInstance(SSH.host)}`]: {
        host: SSH.host,
        firewall: {
          ruleset_sha256: "different",
          managed_sha256: "different",
          mode: "firewall",
          ssh_exposure: "anywhere",
          applied_at: "2026-01-01T00:00:00.000Z",
        },
        observed_at: "2026-01-01T00:00:00.000Z",
      },
      [`revert-${hostInstance(SSH.host)}`]: {
        host: SSH.host,
        token: TOKEN,
        phase: "lockdown",
        unit: `server-host-revert-${TOKEN}`,
        expires_at: new Date(NOW + 60_000).toISOString(),
        armed_at: "2026-01-01T00:00:00.000Z",
        ruleset_sha256: PLACEHOLDER_SHA,
        managed_sha256,
      },
    },
  });
  await assertRejects(
    () =>
      m.methods.apply_firewall.execute(
        m.methods.apply_firewall.arguments.parse(FIREWALL_ARGS),
        context,
      ),
    Error,
    "still active",
  );
  assertEquals(f.commands.some((c) => c.includes("systemd-run")), false);
});

Deno.test("lockdown: an identical live ruleset with an armed revert is a no-op, not a stack", async () => {
  const rendered = renderRuleset(FIREWALL);
  const ruleset_sha256 = await rulesetSha256(rendered);
  const managed_sha256 = await managedTableSha256(rendered);
  const f = fakeTransport((c) => {
    if (c.includes("'nft' 'list' 'ruleset'")) {
      return { code: 0, stdout: rendered };
    }
    if (c.includes("'systemctl' 'is-active'")) {
      return { code: 0, stdout: "active\n" };
    }
    return { code: 0 };
  });
  const m = modelWith(f);
  const { context } = createModelTestContext({
    globalArgs: {},
    storedResources: {
      [`state-${hostInstance(SSH.host)}`]: {
        host: SSH.host,
        firewall: {
          ruleset_sha256,
          managed_sha256,
          mode: "lockdown",
          ssh_exposure: "management-only",
          applied_at: "2026-01-01T00:00:00.000Z",
        },
        observed_at: "2026-01-01T00:00:00.000Z",
      },
      [`revert-${hostInstance(SSH.host)}`]: {
        host: SSH.host,
        token: TOKEN,
        phase: "lockdown",
        unit: `server-host-revert-${TOKEN}`,
        expires_at: new Date(NOW + 60_000).toISOString(),
        armed_at: "2026-01-01T00:00:00.000Z",
        ruleset_sha256,
        managed_sha256,
      },
    },
  });
  const out = await m.methods.lockdown.execute(
    m.methods.lockdown.arguments.parse(FIREWALL_ARGS),
    context,
  );
  assertEquals(out.result.changed, false);
  assertEquals(out.result.revert_token, TOKEN);
  assertEquals(f.commands.some((c) => c.includes("systemd-run")), false);
});

Deno.test("apply_firewall: a /0 without acknowledgement is refused", async () => {
  const f = fakeTransport();
  const m = modelWith(f);
  const { context } = createModelTestContext({ globalArgs: {} });
  await assertRejects(
    () =>
      m.methods.apply_firewall.execute(
        m.methods.apply_firewall.arguments.parse({
          ...FIREWALL_ARGS,
          management_cidrs: ["0.0.0.0/0"],
        }),
        context,
      ),
    Error,
  );
  assertEquals(f.commands.length, 0);
});

Deno.test("lockdown: never allows SSH from anywhere and arms before applying", async () => {
  const f = fakeTransport();
  const m = modelWith(f);
  const { context } = createModelTestContext({ globalArgs: {} });
  await assertRejects(
    () =>
      m.methods.lockdown.execute(
        m.methods.lockdown.arguments.parse({
          ...FIREWALL_ARGS,
          allow_ssh_from_anywhere: true,
        }),
        context,
      ),
    Error,
  );
  const out = await m.methods.lockdown.execute(
    m.methods.lockdown.arguments.parse(FIREWALL_ARGS),
    context,
  );
  assertEquals(out.result.revert_token, TOKEN);
  assertEquals(
    f.commands.findIndex((c) => c.includes("systemd-run")) <
      f.commands.findIndex((c) =>
        c.includes("'nft' '-f' '-'") && !c.includes("'-c'")
      ),
    true,
  );
});

Deno.test("commit: probes the timer and rules, then records a verified cancel", async () => {
  const rendered = renderRuleset(FIREWALL);
  const managed_sha256 = await managedTableSha256(rendered);
  const name = `revert-${hostInstance(SSH.host)}`;
  const active = [true, false];
  const f = fakeTransport((c) => {
    if (c.includes("'nft' 'list' 'ruleset'")) {
      return { code: 0, stdout: rendered };
    }
    if (c.includes("'systemctl' 'is-active'")) {
      return { code: 0, stdout: active.shift() ? "active\n" : "inactive\n" };
    }
    return { code: 0 };
  });
  const m = modelWith(f);
  const { context } = createModelTestContext({
    globalArgs: {},
    storedResources: {
      [name]: {
        host: SSH.host,
        token: TOKEN,
        phase: "firewall",
        unit: `server-host-revert-${TOKEN}`,
        expires_at: new Date(NOW + 60_000).toISOString(),
        armed_at: "2026-01-01T00:00:00.000Z",
        ruleset_sha256: PLACEHOLDER_SHA,
        managed_sha256,
      },
    },
  });
  const out = await m.methods.commit.execute(
    m.methods.commit.arguments.parse(SSH),
    context,
  );
  assertEquals(out.result, { host: SSH.host, committed: true });
  assertEquals(f.commands.some((c) => c.includes("systemctl stop")), true);
  const after = await context.readResource(name) as { committed_at?: string };
  assertEquals(typeof after.committed_at, "string");
});

Deno.test("commit: a failed cancellation is fatal and records nothing", async () => {
  const rendered = renderRuleset(FIREWALL);
  const managed_sha256 = await managedTableSha256(rendered);
  const name = `revert-${hostInstance(SSH.host)}`;
  const f = fakeTransport((c) => {
    if (c.includes("'nft' 'list' 'ruleset'")) {
      return { code: 0, stdout: rendered };
    }
    if (c.includes("'systemctl' 'is-active'")) {
      return { code: 0, stdout: "active\n" };
    }
    if (c.includes("systemctl stop")) return { code: 1 };
    return { code: 0 };
  });
  const m = modelWith(f);
  const ctx = createModelTestContext({
    globalArgs: {},
    storedResources: {
      [name]: {
        host: SSH.host,
        token: TOKEN,
        phase: "firewall",
        unit: `server-host-revert-${TOKEN}`,
        expires_at: new Date(NOW + 60_000).toISOString(),
        armed_at: "2026-01-01T00:00:00.000Z",
        ruleset_sha256: PLACEHOLDER_SHA,
        managed_sha256,
      },
    },
  });
  await assertRejects(
    () =>
      m.methods.commit.execute(
        m.methods.commit.arguments.parse(SSH),
        ctx.context,
      ),
    Error,
  );
  assertEquals(ctx.getWrittenResources().length, 0);
});

Deno.test("commit: refuses nothing armed, expired, not active, and mismatched rules", async () => {
  const name = `revert-${hostInstance(SSH.host)}`;
  const future = new Date(NOW + 60_000).toISOString();
  const base = {
    host: SSH.host,
    token: TOKEN,
    phase: "firewall",
    unit: `server-host-revert-${TOKEN}`,
    expires_at: future,
    armed_at: "2026-01-01T00:00:00.000Z",
    ruleset_sha256: PLACEHOLDER_SHA,
    managed_sha256: "b".repeat(64),
  };
  const noRevert = fakeTransport();
  await assertRejects(
    () =>
      modelWith(noRevert).methods.commit.execute(
        modelWith(noRevert).methods.commit.arguments.parse(SSH),
        createModelTestContext({ globalArgs: {} }).context,
      ),
    Error,
  );
  const expired = createModelTestContext({
    globalArgs: {},
    storedResources: {
      [name]: { ...base, expires_at: new Date(NOW - 1).toISOString() },
    },
  });
  await assertRejects(
    () =>
      modelWith(fakeTransport()).methods.commit.execute(
        modelWith(fakeTransport()).methods.commit.arguments.parse(SSH),
        expired.context,
      ),
    Error,
  );
  // Timer not active.
  const inactive = fakeTransport((c) => {
    if (c.includes("'nft' 'list' 'ruleset'")) {
      return { code: 0, stdout: renderRuleset(FIREWALL) };
    }
    if (c.includes("'systemctl' 'is-active'")) {
      return { code: 3, stdout: "inactive\n" };
    }
    return { code: 0 };
  });
  const inactiveCtx = createModelTestContext({
    globalArgs: {},
    storedResources: { [name]: base },
  });
  await assertRejects(
    () =>
      modelWith(inactive).methods.commit.execute(
        modelWith(inactive).methods.commit.arguments.parse(SSH),
        inactiveCtx.context,
      ),
    Error,
  );
  // Live rules no longer match the armed revert.
  const mismatch = fakeTransport((c) => {
    if (c.includes("'nft' 'list' 'ruleset'")) {
      return { code: 0, stdout: renderRuleset(FIREWALL) };
    }
    if (c.includes("'systemctl' 'is-active'")) {
      return { code: 0, stdout: "active\n" };
    }
    return { code: 0 };
  });
  const mismatchCtx = createModelTestContext({
    globalArgs: {},
    storedResources: { [name]: base },
  });
  await assertRejects(
    () =>
      modelWith(mismatch).methods.commit.execute(
        modelWith(mismatch).methods.commit.arguments.parse(SSH),
        mismatchCtx.context,
      ),
    Error,
  );
});

Deno.test("get and sync: probe the host and report phase state and drift", async () => {
  const rendered = renderRuleset(FIREWALL);
  const f = fakeTransport((c) => {
    if (c.includes("'nft' 'list' 'ruleset'")) {
      return { code: 0, stdout: rendered };
    }
    if (c.includes("'systemctl' 'is-active'")) {
      return { code: 3, stdout: "inactive\n" };
    }
    return { code: 0 };
  });
  const m = modelWith(f);
  const ctx = createModelTestContext({ globalArgs: {} });
  const got = await m.methods.get.execute(
    m.methods.get.arguments.parse(SSH),
    ctx.context,
  );
  assertEquals(got.result.managed_table, true);
  assertEquals(got.result.revert_armed, false);
  assertEquals(got.result.managed_sha256.length, 64);
  const synced = await m.methods.sync.execute(
    m.methods.sync.arguments.parse(SSH),
    ctx.context,
  );
  assertEquals(synced.result.managed_table, true);
  assertEquals(Array.isArray(synced.result.drift), true);
});

Deno.test("get: a failed probe is an error and writes no state", async () => {
  const f = fakeTransport((c) =>
    c.includes("'nft' 'list' 'ruleset'") ? { code: 1 } : { code: 0 }
  );
  const m = modelWith(f);
  const ctx = createModelTestContext({ globalArgs: {} });
  await assertRejects(
    () =>
      m.methods.get.execute(
        m.methods.get.arguments.parse(SSH),
        ctx.context,
      ),
    Error,
  );
  assertEquals(ctx.getWrittenResources().length, 0);
});

Deno.test("injection: metacharacters in a valid-looking user are refused by grammar", () => {
  const m = createModel();
  for (
    const admin of ["ops;id", "ops && id", "ops`id`", "$(id)", "ops\nroot"]
  ) {
    assertEquals(
      m.methods.apply_base.arguments.safeParse({ ...SSH, admin_user: admin })
        .success,
      false,
      admin,
    );
  }
});

Deno.test("host key policy: strict without pinned keys is refused before any spawn", async () => {
  const f = fakeTransport();
  const m = modelWith(f);
  const { context } = createModelTestContext({ globalArgs: {} });
  await assertRejects(
    () =>
      m.methods.get.execute(
        m.methods.get.arguments.parse({
          ...SSH,
          host_key_policy: "strict",
        }),
        context,
      ),
    Error,
  );
  assertEquals(f.commands.length, 0);
});
