import {
  assertEquals,
  assertRejects,
  assertThrows,
} from "jsr:@std/assert@1.0.19";
import { createModelTestContext } from "jsr:@swamp-club/swamp-testing@0.20261014.55";
import { createModel, type HostDeps, hostInstance } from "./server_host.ts";
import { type CommandRunner } from "./_lib/ssh.ts";
import { bodyOf, fakeHost, unquoteBody } from "./_lib/test_support.ts";
import {
  assertNoRemoteSecretWrite,
  assertNoSecretOnArgv,
  createRecordingRunner,
  type Recording,
} from "./_lib/bogworks/recording-runner.ts";
import {
  expectedListing,
  expectedManagedSha256,
  type FirewallRules,
  managedSha256,
  renderRuleset,
  rulesetSha256,
} from "./_lib/nftables.ts";
import { renderSysctlConf } from "./_lib/plans.ts";
import { renderRevertScript } from "./_lib/armed_revert.ts";

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
  host_key_policy: "strict" as const,
  host_keys: [`192.0.2.10 ${KEY}`],
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
  /** Every remote call: its ssh argument, then the script it runs on stdin. */
  commands: string[];
  stdins: string[];
  secrets: [string, string][];
  /** Arguments of every ssh-keyscan call. */
  scans: string[][];
  /** The argv of every ssh call, in order. */
  sshArgs(): string[][];
  /** The harness recording of every local command. */
  recording: Recording;
}

/** A fake transport that records ssh scripts, stdin and secret lookups. */
function fakeTransport(
  respond: (command: string) => { code: number; stdout?: string } = () => ({
    code: 0,
  }),
  capture = false,
): Fake {
  const stdins: string[] = [];
  const secrets: [string, string][] = [];
  const scans: string[][] = [];
  const host = fakeHost((body, call) => {
    const command = `${call.argv[call.argv.length - 1]}\n${body}`;
    const r = respond(command);
    // Unscripted nft reads answer like a host: no managed table in the
    // ruleset, and the rendered table when it is read back after an apply.
    const stdout = r.stdout ??
      (command.includes("ip -4 -j route show default")
        ? '[{"dst":"default","dev":"enp1s0"}]\n---\n[]\n---\n[{"dev":"wg0"}]'
        : command.includes("nft -j list ruleset")
        ? '{"nftables":[]}'
        : command.includes("nft -j list table")
        ? expectedListing(FIREWALL)
        : "");
    return { code: r.code, stdout };
  }, capture);
  const base = host.run;
  const run: CommandRunner = (cmd, args, options = {}) => {
    if (options.stdin) {
      stdins.push(
        typeof options.stdin === "string"
          ? options.stdin
          : new TextDecoder().decode(options.stdin),
      );
    }
    if (cmd === "ssh-keyscan") scans.push(args);
    return base(cmd, args, options);
  };
  const deps: Partial<HostDeps> = {
    run,
    now: () => NOW,
    sleep: () => Promise.resolve(),
    token: () => TOKEN,
    resolveSecret: (vault, key) => {
      secrets.push([vault, key]);
      return Promise.resolve(PEM);
    },
  };
  return {
    deps,
    get commands() {
      return host.sshCalls().map((c) =>
        `${c.argv[c.argv.length - 1]}\n${bodyOf(c)}`
      );
    },
    stdins,
    secrets,
    scans,
    sshArgs: () => host.sshCalls().map((c) => c.argv),
    recording: host.recording,
  };
}

/** The apply step: the guarded `nft -f -` script that checks the revert first. */
const isGuardedApply = (c: string) =>
  c.includes("| nft -f -") && c.includes("exit 70");
const isArm = (c: string) => c.includes("systemd-run");
/** The read-only timer probe, not the scripts that merely mention the command. */
const isTimerProbe = (c: string) =>
  /systemctl is-active 'server-host-revert-[0-9a-f]+\.timer'\n/.test(c);
const isDisarm = (c: string) => c.includes('"$unit.timer" 2>/dev/null || true');

function modelWith(f: Fake) {
  return createModel(f.deps);
}

function liveResponse() {
  return (command: string): { code: number; stdout?: string } => {
    if (command.includes("nft -j list ruleset")) {
      return { code: 0, stdout: expectedListing(FIREWALL) };
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
    host_key_policy: "strict",
    host_keys: [`192.0.2.10 ${KEY}`],
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
  assertEquals(
    out.result.managed_sha256,
    await expectedManagedSha256(FIREWALL),
  );
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
  const applyAt = f.commands.findIndex(isGuardedApply);
  const checkAt = f.commands.findIndex((c) => c.includes("nft -c -f -"));
  assertEquals(checkAt >= 0 && checkAt < stageAt, true, "syntax check first");
  assertEquals(stageAt >= 0, true, "revert script staged");
  assertEquals(stageAt < armAt, true, "script staged before timer");
  assertEquals(armAt >= 0, true, "timer armed");
  assertEquals(applyAt > armAt, true, "timer armed before apply");
});

Deno.test("apply_firewall: a matching ruleset that is still live is a no-op", async () => {
  const rendered = renderRuleset(FIREWALL);
  const ruleset_sha256 = await rulesetSha256(rendered);
  const managed_sha256 = await expectedManagedSha256(FIREWALL);
  const name = `state-${hostInstance(SSH.host)}`;
  const f = fakeTransport(liveResponse());
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
  const managed_sha256 = await expectedManagedSha256(FIREWALL);
  const name = `state-${hostInstance(SSH.host)}`;
  // Live output has no managed table, as after a fired revert.
  const f = fakeTransport((c) =>
    c.includes("nft -j list ruleset")
      ? { code: 0, stdout: '{"nftables":[]}' }
      : { code: 0 }
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

Deno.test("apply_firewall: the host refusing to arm (earlier revert busy) is a clear error and cleans up", async () => {
  const f = fakeTransport((c) => isArm(c) ? { code: 75 } : { code: 0 });
  const m = modelWith(f);
  const { context, getWrittenResources } = createModelTestContext({
    globalArgs: {},
  });
  await assertRejects(
    () =>
      m.methods.apply_firewall.execute(
        m.methods.apply_firewall.arguments.parse(FIREWALL_ARGS),
        context,
      ),
    Error,
    "still active or firing",
  );
  // Nothing was applied, nothing was recorded, and this attempt's files are removed.
  assertEquals(f.commands.some(isGuardedApply), false);
  assertEquals(getWrittenResources().length, 0);
  assertEquals(f.commands.some(isDisarm), true);
});

Deno.test("lockdown: an identical live ruleset with an armed revert is a no-op, not a stack", async () => {
  const rendered = renderRuleset(FIREWALL);
  const ruleset_sha256 = await rulesetSha256(rendered);
  const managed_sha256 = await expectedManagedSha256(FIREWALL);
  const f = fakeTransport((c) => {
    if (c.includes("nft -j list ruleset")) {
      return { code: 0, stdout: expectedListing(FIREWALL) };
    }
    if (isTimerProbe(c)) {
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
          management_cidrs: ["0.0.0.0/0"], // leak-allow(address-space halves are the case under test)
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
      f.commands.findIndex(isGuardedApply),
    true,
  );
});

Deno.test("commit: probes the timer and rules, then records a verified cancel", async () => {
  const managed_sha256 = await expectedManagedSha256(FIREWALL);
  const name = `revert-${hostInstance(SSH.host)}`;
  const active = [true, false];
  const f = fakeTransport((c) => {
    if (c.includes("nft -j list ruleset")) {
      return { code: 0, stdout: expectedListing(FIREWALL) };
    }
    if (isTimerProbe(c)) {
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
  const managed_sha256 = await expectedManagedSha256(FIREWALL);
  const name = `revert-${hostInstance(SSH.host)}`;
  const f = fakeTransport((c) => {
    if (c.includes("nft -j list ruleset")) {
      return { code: 0, stdout: expectedListing(FIREWALL) };
    }
    if (isTimerProbe(c)) {
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
    "No armed revert is recorded",
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
    "expired",
  );
  // Timer not active.
  const inactive = fakeTransport((c) => {
    if (c.includes("nft -j list ruleset")) {
      return { code: 0, stdout: expectedListing(FIREWALL) };
    }
    if (isTimerProbe(c)) {
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
    "is not active",
  );
  // Live rules no longer match the armed revert.
  const mismatch = fakeTransport((c) => {
    if (c.includes("nft -j list ruleset")) {
      return { code: 0, stdout: expectedListing(FIREWALL) };
    }
    if (isTimerProbe(c)) {
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
    "no longer matches",
  );
});

Deno.test("get and sync: probe the host and report phase state and drift", async () => {
  const f = fakeTransport((c) => {
    if (c.includes("nft -j list ruleset")) {
      return { code: 0, stdout: expectedListing(FIREWALL) };
    }
    if (isTimerProbe(c)) {
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
    c.includes("nft -j list ruleset") ? { code: 1 } : { code: 0 }
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

Deno.test("host key policy: strict without pinned keys is refused by the schema, before any spawn", () => {
  const f = fakeTransport();
  const m = modelWith(f);
  assertThrows(() => m.methods.get.arguments.parse({ ...SSH, host_keys: [] }));
  assertEquals(f.commands.length, 0);
});

/** Reads which resources were written, in order. */
const writes = (
  r: { getWrittenResources(): { name: string; spec?: string }[] },
) => r.getWrittenResources().map((w) => w.name);

Deno.test("apply_firewall: the revert is recorded when arming succeeds, BEFORE the apply runs", async () => {
  let recordedAtApply: string[] = [];
  const ctxRef = createModelTestContext({ globalArgs: {} });
  const f = fakeTransport((c) => {
    if (isGuardedApply(c)) recordedAtApply = writes(ctxRef);
    return { code: 0 };
  });
  const m = modelWith(f);
  await m.methods.apply_firewall.execute(
    m.methods.apply_firewall.arguments.parse(FIREWALL_ARGS),
    ctxRef.context,
  );
  assertEquals(recordedAtApply, [`revert-${hostInstance(SSH.host)}`]);
});

Deno.test("apply_firewall: a step failing after arming leaves the timer armed and the record open", async () => {
  // The read-back fails after the apply went through: the outcome is unknown,
  // so the host must keep the revert that will restore it.
  const f = fakeTransport((c) =>
    c.includes("nft -j list table") ? { code: 1 } : { code: 0 }
  );
  const m = modelWith(f);
  const ctx = createModelTestContext({ globalArgs: {} });
  await assertRejects(
    () =>
      m.methods.apply_firewall.execute(
        m.methods.apply_firewall.arguments.parse(FIREWALL_ARGS),
        ctx.context,
      ),
    Error,
    "read table back",
  );
  assertEquals(f.commands.some(isDisarm), false);
  const rec = ctx.getWrittenResources().find((w) =>
    w.name.startsWith("revert-")
  );
  assertEquals(rec !== undefined, true);
  assertEquals(
    (rec!.data as { cancelled_at?: string }).cancelled_at,
    undefined,
  );
});

Deno.test("apply_firewall: a definite apply failure disarms its own timer and marks the record cancelled", async () => {
  const f = fakeTransport((c) => isGuardedApply(c) ? { code: 1 } : { code: 0 });
  const m = modelWith(f);
  const ctx = createModelTestContext({ globalArgs: {} });
  await assertRejects(
    () =>
      m.methods.apply_firewall.execute(
        m.methods.apply_firewall.arguments.parse(FIREWALL_ARGS),
        ctx.context,
      ),
    Error,
    "apply ruleset",
  );
  assertEquals(f.commands.some(isDisarm), true);
  const last = ctx.getWrittenResources().filter((w) =>
    w.name.startsWith("revert-")
  ).at(-1)!;
  assertEquals(
    typeof (last.data as { cancelled_at?: string }).cancelled_at,
    "string",
  );
  // A cancelled record no longer blocks: a retry starts a fresh change.
  const again = await ctx.context.readResource(
    `revert-${hostInstance(SSH.host)}`,
  );
  assertEquals(again !== null, true);
});

Deno.test("apply_firewall: a failing syntax check arms nothing and needs no cleanup", async () => {
  const f = fakeTransport((c) =>
    c.includes("nft -c -f -") ? { code: 1 } : { code: 0 }
  );
  const m = modelWith(f);
  const ctx = createModelTestContext({ globalArgs: {} });
  await assertRejects(
    () =>
      m.methods.apply_firewall.execute(
        m.methods.apply_firewall.arguments.parse(FIREWALL_ARGS),
        ctx.context,
      ),
    Error,
    "nft syntax check",
  );
  assertEquals(f.commands.some(isArm), false);
  assertEquals(f.commands.some(isDisarm), false);
  assertEquals(ctx.getWrittenResources().length, 0);
});

Deno.test("apply_firewall: a retry after a failed change does not depend on any model record to be safe", async () => {
  // The record is lost; the host's own refusal (75) is what stops a stacked timer.
  const f = fakeTransport((c) => isArm(c) ? { code: 75 } : { code: 0 });
  const m = modelWith(f);
  const ctx = createModelTestContext({ globalArgs: {} });
  await assertRejects(
    () =>
      m.methods.lockdown.execute(
        m.methods.lockdown.arguments.parse(FIREWALL_ARGS),
        ctx.context,
      ),
    Error,
    "still active or firing",
  );
});

Deno.test("strict is the only host-key policy: trust-on-first-use is rejected and host_keys is required", () => {
  const m = createModel();
  const ok = m.methods.get.arguments.safeParse({ ...SSH });
  assertEquals(ok.success, true);
  for (const policy of ["insecure_tofu", "accept-new", "insecure", ""]) {
    assertEquals(
      m.methods.get.arguments.safeParse({ ...SSH, host_key_policy: policy })
        .success,
      false,
      policy,
    );
  }
  const { host_keys: _k, ...noKeys } = SSH;
  assertEquals(m.methods.get.arguments.safeParse(noKeys).success, false);
  assertEquals(
    m.methods.get.arguments.safeParse({ ...SSH, host_keys: [] }).success,
    false,
  );
});

Deno.test("every ssh step verifies the pinned host keys strictly and nothing is scanned", async () => {
  const f = fakeTransport();
  const m = modelWith(f);
  const ctx = createModelTestContext({ globalArgs: {} });
  await m.methods.apply_firewall.execute(
    m.methods.apply_firewall.arguments.parse(FIREWALL_ARGS),
    ctx.context,
  );
  assertEquals(f.scans.length, 0);
  const ssh = f.sshArgs();
  assertEquals(ssh.length, f.commands.length);
  for (const args of ssh) {
    assertEquals(args.includes("StrictHostKeyChecking=yes"), true);
    assertEquals(args.includes("StrictHostKeyChecking=accept-new"), false);
  }
});

Deno.test("commit: an armed revert the model never recorded is found through the host's marker", async () => {
  const liveHash = await managedSha256(null);
  const f = fakeTransport((c) => {
    if (c.includes("/var/lib/server-host/current") && c.includes("cat")) {
      return {
        code: 0,
        stdout: `${TOKEN} ${Math.floor(NOW / 1000) + 200} ${liveHash}\n`,
      };
    }
    if (isTimerProbe(c)) {
      return { code: 0, stdout: "active\n" };
    }
    return { code: 0 };
  });
  const ctx = createModelTestContext({ globalArgs: {} });
  // The first probe sees it armed, the post-cancel probe must not.
  let cancelled = false;
  const base = f.deps.run!;
  f.deps.run = (cmd, args, o) => {
    const script = String(o?.stdin ?? "");
    if (cmd === "ssh" && script.includes('systemctl stop "$unit.timer"')) {
      cancelled = true;
    }
    if (cmd === "ssh" && cancelled && isTimerProbe(unquoteBody(script))) {
      return Promise.resolve({ code: 3, stdout: "inactive\n", stderr: "" });
    }
    return base(cmd, args, o);
  };
  const m = modelWith(f);
  const out = await m.methods.commit.execute(
    m.methods.commit.arguments.parse({ ...SSH }),
    ctx.context,
  );
  assertEquals(out.result.committed, true);
});

Deno.test("commit is described as DESTRUCTIVE", () => {
  assertEquals(
    createModel().methods.commit.description.startsWith("DESTRUCTIVE."),
    true,
  );
});

Deno.test("commit: the marker fallback refuses when the host recorded no ruleset hash", async () => {
  const f = fakeTransport((c) => {
    if (c.includes("/var/lib/server-host/current") && c.includes("cat")) {
      return { code: 0, stdout: `${TOKEN} ${Math.floor(NOW / 1000) + 200}\n` };
    }
    if (isTimerProbe(c)) {
      return { code: 0, stdout: "active\n" };
    }
    return { code: 0 };
  });
  const m = modelWith(f);
  const ctx = createModelTestContext({ globalArgs: {} });
  await assertRejects(
    () =>
      m.methods.commit.execute(
        m.methods.commit.arguments.parse({ ...SSH }),
        ctx.context,
      ),
    Error,
    "unverified",
  );
  assertEquals(f.commands.some(isDisarm), false);
  assertEquals(
    f.commands.some((c) => c.includes('systemctl stop "$unit.timer"')),
    false,
  );
});

Deno.test("marker read: an unreadable, truncated or garbled marker is an error, never 'no revert'", async () => {
  const cases: [string, { code: number; stdout?: string }][] = [
    ["read failure", { code: 1 }],
    ["garbled", { code: 0, stdout: "not a marker\n" }],
    ["half a marker", { code: 0, stdout: `${TOKEN}\n` }],
  ];
  for (const [name, reply] of cases) {
    const f = fakeTransport((c) =>
      c.includes("/var/lib/server-host/current") && c.includes("cat")
        ? reply
        : { code: 0 }
    );
    const m = modelWith(f);
    const ctx = createModelTestContext({ globalArgs: {} });
    await assertRejects(
      () =>
        m.methods.get.execute(
          m.methods.get.arguments.parse({ ...SSH }),
          ctx.context,
        ),
      Error,
      "",
      name,
    );
  }
});

Deno.test("marker read: absent marker (empty output) is no revert", async () => {
  const f = fakeTransport();
  const m = modelWith(f);
  const ctx = createModelTestContext({ globalArgs: {} });
  const out = await m.methods.get.execute(
    m.methods.get.arguments.parse({ ...SSH }),
    ctx.context,
  );
  assertEquals(out.result.revert_armed, false);
});

Deno.test("management_cidrs: halves of the address space need the SSH-from-anywhere acknowledgement", async () => {
  const m = createModel();
  const ctx = createModelTestContext({ globalArgs: {} });
  for (
    const cidrs of [
      ["0.0.0.0/1", "128.0.0.0/1"], // leak-allow(address-space halves are the case under test)
      ["::/1", "8000::/1"], // leak-allow(address-space halves are the case under test)
      ["0.0.0.0/2", "64.0.0.0/2", "128.0.0.0/1"], // leak-allow(address-space halves are the case under test)
      ["0.0.0.0/1"], // leak-allow(address-space halves are the case under test)
      ["2000::/3"], // leak-allow(address-space halves are the case under test)
    ]
  ) {
    const args = {
      host: SSH.host,
      management_cidrs: cidrs,
    };
    await assertRejects(
      () =>
        m.methods.render_firewall.execute(
          m.methods.render_firewall.arguments.parse(args),
          ctx.context,
        ),
      Error,
      "(nearly) everyone",
    );
    // With the acknowledgement the same input renders.
    await m.methods.render_firewall.execute(
      m.methods.render_firewall.arguments.parse({
        ...args,
        allow_ssh_from_anywhere: true,
      }),
      ctx.context,
    );
  }
});

Deno.test("apply_base: an account change with an empty key list still rewrites the managed keys", async () => {
  const f = fakeTransport();
  const m = modelWith(f);
  const { context } = createModelTestContext({
    globalArgs: {},
    storedResources: {
      [`state-${hostInstance(SSH.host)}`]: {
        host: SSH.host,
        base: {
          packages: [],
          admin_user: "oldops",
          authorized_keys_sha256: await rulesetSha256(""),
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
      authorized_keys: [],
      sysctl: {},
      timezone: "UTC",
    }),
    context,
  );
  assertEquals(out.result.changed.includes("authorized_keys"), true);
  const i = f.commands.findIndex((c) => c.includes("authorized_keys"));
  assertEquals(i >= 0, true);
});

Deno.test("lockdown: a re-run with identical inputs after commit is a no-op, with other tables present", async () => {
  const rendered = renderRuleset(FIREWALL);
  const ruleset_sha256 = await rulesetSha256(rendered);
  const managed_sha256 = await expectedManagedSha256(FIREWALL);
  // What `nft -j list ruleset` prints once other software has added its own
  // tables around ours (and nft has numbered everything with handles).
  const live = JSON.stringify({
    nftables: [
      { metainfo: { version: "1.0.9", json_schema_version: 1 } },
      { table: { family: "inet", name: "k0s", handle: 1 } },
      { chain: { family: "inet", table: "k0s", name: "forward", handle: 1 } },
      ...(JSON.parse(expectedListing(FIREWALL)).nftables as unknown[]),
      { table: { family: "ip", name: "nat", handle: 3 } },
    ],
  });
  const f = fakeTransport((c) =>
    c.includes("nft -j list ruleset") ? { code: 0, stdout: live } : { code: 0 }
  );
  const m = modelWith(f);
  const { context, getWrittenResources } = createModelTestContext({
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
        expires_at: "2026-01-01T00:05:00.000Z",
        armed_at: "2026-01-01T00:00:00.000Z",
        ruleset_sha256,
        managed_sha256,
        committed_at: "2026-01-01T00:01:00.000Z",
      },
    },
  });
  const out = await m.methods.lockdown.execute(
    m.methods.lockdown.arguments.parse(FIREWALL_ARGS),
    context,
  );
  assertEquals(out.result.changed, false);
  assertEquals(out.result.revert_token, null);
  // Only read-only probes ran: nothing armed, staged or applied.
  assertEquals(
    f.commands.some((c) =>
      c.includes("systemd-run") || c.includes("| nft -f -") ||
      c.includes("'nft' '-f'")
    ),
    false,
  );
  assertEquals(getWrittenResources().length, 0);
});

/** A model whose only secret source is the runtime's vault service. */
function vaultOnly(f: Fake) {
  return createModel({ ...f.deps, resolveSecret: undefined });
}

Deno.test("vault: the real runtime shape (a plain {get, put} object, no injected resolver) resolves the key", async () => {
  const f = fakeTransport();
  const m = vaultOnly(f);
  const asked: [string, string][] = [];
  const { context } = createModelTestContext({ globalArgs: {} });
  const withVault = {
    ...context,
    vaultService: {
      get: (v: string, k: string) => {
        asked.push([v, k]);
        return Promise.resolve(PEM);
      },
      put: () => Promise.resolve(),
    },
  };
  const out = await m.methods.get.execute(
    m.methods.get.arguments.parse({ ...SSH }),
    withVault as never,
  );
  assertEquals(asked, [["prod", "ssh-key"]]);
  assertEquals(out.result.host, SSH.host);
  // The key reached ssh-add over stdin and nowhere else.
  assertEquals(f.stdins.some((s) => s.includes("PRIVATE KEY")), true);
  assertEquals(f.commands.some((c) => c.includes("PRIVATE KEY")), false);
});

Deno.test("vault: a missing, malformed or empty vault service is a clear error that never echoes a secret", async () => {
  const f = fakeTransport();
  const m = vaultOnly(f);
  const base = createModelTestContext({ globalArgs: {} }).context;
  const args = m.methods.get.arguments.parse({ ...SSH });
  const cases: [string, unknown, string][] = [
    ["absent", undefined, "No vault service"],
    [
      "factory function (the old shape)",
      () => ({ get: () => PEM }),
      "No vault service",
    ],
    ["no get", { put: () => Promise.resolve() }, "No vault service"],
    ["empty secret", { get: () => Promise.resolve("") }, "returned no secret"],
  ];
  for (const [name, vaultService, text] of cases) {
    const e = await assertRejects(
      () => m.methods.get.execute(args, { ...base, vaultService } as never),
      Error,
      text,
      name,
    );
    assertEquals(e.message.includes("PRIVATE KEY"), false, name);
  }
  assertEquals(f.commands.length, 0);
});

Deno.test("real nft output: apply verifies, then commit and an identical re-apply succeed although the live text differs from the render", async () => {
  const samples = JSON.parse(
    await Deno.readTextFile(
      new URL("./_lib/fixtures/nft-real-listings.json", import.meta.url),
    ),
  ) as Record<
    string,
    {
      management_cidrs: string[];
      allow_tcp: number[];
      trusted_interfaces?: string[];
      json: unknown;
    }
  >;
  for (const [name, x] of Object.entries(samples)) {
    const live = JSON.stringify(x.json);
    let cancelled = false;
    let applied = false;
    const f = fakeTransport((c) => {
      if (isGuardedApply(c)) applied = true;
      if (c.includes('systemctl stop "$unit.timer"')) cancelled = true;
      if (c.includes("nft -j list")) {
        return { code: 0, stdout: applied ? live : '{"nftables":[]}' };
      }
      if (isTimerProbe(c)) {
        return cancelled
          ? { code: 3, stdout: "inactive\n" }
          : { code: 0, stdout: "active\n" };
      }
      return { code: 0 };
    });
    const m = modelWith(f);
    const args = m.methods.apply_firewall.arguments.parse({
      ...FIREWALL_ARGS,
      management_cidrs: x.management_cidrs,
      allow_tcp: x.allow_tcp,
      trusted_interfaces: x.trusted_interfaces ?? [],
      allow_udp: [],
    });
    const ctx = createModelTestContext({ globalArgs: {} });
    const out = await m.methods.apply_firewall.execute(args, ctx.context);
    assertEquals(out.result.changed, true, name);
    // The host marker carries the structural hash, not a hash of the text.
    const arm = f.commands.find(isArm)!;
    assertEquals(arm.includes(String(out.result.managed_sha256)), true, name);
    // commit: same live listing hashes to the stored value.
    const committed = await m.methods.commit.execute(
      m.methods.commit.arguments.parse({ ...SSH }),
      ctx.context,
    );
    assertEquals(committed.result.committed, true, name);
    // An identical re-apply is a no-op against the same real listing.
    const again = await m.methods.apply_firewall.execute(args, ctx.context);
    assertEquals(again.result.changed, false, name);
  }
});

const BASE_ARGS = {
  ...SSH,
  packages: [],
  authorized_keys: [KEY],
  sysctl: {},
  timezone: "UTC",
};

async function baseStored(adminUser: string) {
  return {
    [`state-${hostInstance(SSH.host)}`]: {
      host: SSH.host,
      base: {
        packages: [],
        admin_user: adminUser,
        authorized_keys_sha256: await rulesetSha256([KEY].join("\n")),
        sysctl_sha256: await rulesetSha256(renderSysctlConf({})),
        timezone: "UTC",
        applied_at: "2026-01-01T00:00:00.000Z",
      },
      observed_at: "2026-01-01T00:00:00.000Z",
    },
  };
}

Deno.test("apply_base: an account change revokes the previous account's grants FIRST", async () => {
  const f = fakeTransport();
  const m = modelWith(f);
  const { context } = createModelTestContext({
    globalArgs: {},
    storedResources: await baseStored("oldops"),
  });
  const out = await m.methods.apply_base.execute(
    m.methods.apply_base.arguments.parse({
      ...BASE_ARGS,
      admin_user: "newops",
    }),
    context,
  );
  assertEquals(out.result.changed.includes("revoke_previous"), true);
  const revoke = f.commands.findIndex((c) =>
    c.includes("sudo-granted-$user") && c.includes("'oldops'")
  );
  const create = f.commands.findIndex((c) => c.includes("useradd"));
  const keys = f.commands.findIndex((c) =>
    c.includes("authorized_keys.XXXXXX")
  );
  assertEquals(revoke >= 0 && revoke < create && create < keys, true);
  // The account is not deleted.
  assertEquals(f.commands.some((c) => c.includes("userdel")), false);
});

Deno.test("apply_base: no revoke for the first apply, the same account, root, or the login account", async () => {
  const cases: [string, string, string?][] = [
    ["first apply", ""],
    ["same account", "ops"],
    ["previous was root", "root"],
    ["previous is the login user", "loginops"],
  ];
  for (const [name, prev, login] of cases) {
    const f = fakeTransport();
    const m = modelWith(f);
    const { context } = createModelTestContext({
      globalArgs: {},
      storedResources: prev ? await baseStored(prev) : {},
    });
    const out = await m.methods.apply_base.execute(
      m.methods.apply_base.arguments.parse({
        ...BASE_ARGS,
        user: login ?? "root",
        ...(prev === "loginops" ? { user: "loginops" } : {}),
        admin_user: "ops",
      }),
      context,
    );
    assertEquals(out.result.changed.includes("revoke_previous"), false, name);
    assertEquals(
      f.commands.some((c) => c.includes("sudo-granted-$user")),
      false,
      name,
    );
  }
});

Deno.test("get and sync persist their observation as a resource readable with swamp data", async () => {
  const live = JSON.stringify({
    nftables: [
      ...(JSON.parse(expectedListing(FIREWALL)).nftables as unknown[]),
    ],
  });
  const f = fakeTransport((c) => {
    if (c.includes("nft -j list ruleset")) {
      return { code: 0, stdout: live };
    }
    if (isTimerProbe(c)) {
      return { code: 0, stdout: "active\n" };
    }
    return { code: 0 };
  });
  const m = modelWith(f);
  const expires = new Date(NOW + 60_000).toISOString();
  const { context, getWrittenResources } = createModelTestContext({
    globalArgs: {},
    storedResources: {
      [`state-${hostInstance(SSH.host)}`]: {
        host: SSH.host,
        firewall: {
          ruleset_sha256: "x",
          managed_sha256: await expectedManagedSha256(FIREWALL),
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
        expires_at: expires,
        armed_at: "2026-01-01T00:00:00.000Z",
        ruleset_sha256: "x",
        managed_sha256: await expectedManagedSha256(FIREWALL),
      },
    },
  });
  for (const method of ["get", "sync"] as const) {
    await m.methods[method].execute(
      m.methods[method].arguments.parse({ ...SSH }),
      context,
    );
    const w = getWrittenResources().filter((r) =>
      r.name.startsWith("observation-")
    ).at(-1)!;
    const o = w.data as Record<string, unknown>;
    assertEquals(o.observed_by, method);
    assertEquals(o.managed_table, true);
    assertEquals(o.revert_armed, true);
    assertEquals(o.revert_token, TOKEN);
    assertEquals(o.revert_expires_at, expires);
    assertEquals(o.ssh_exposure, "management-only");
    assertEquals(o.firewall_mode, "lockdown");
    assertEquals(o.drift, []);
    assertEquals(
      o.managed_sha256,
      await expectedManagedSha256(FIREWALL),
    );
    assertEquals(JSON.stringify(o).includes("PRIVATE KEY"), false);
  }
});

Deno.test("sync records drift: a revert that fired, and a changed ruleset", async () => {
  const f = fakeTransport((c) =>
    isTimerProbe(c) ? { code: 3, stdout: "inactive\n" } : { code: 0 }
  );
  const m = modelWith(f);
  const { context, getWrittenResources } = createModelTestContext({
    globalArgs: {},
    storedResources: {
      [`state-${hostInstance(SSH.host)}`]: {
        host: SSH.host,
        firewall: {
          ruleset_sha256: "x",
          managed_sha256: await expectedManagedSha256(FIREWALL),
          mode: "firewall",
          ssh_exposure: "anywhere",
          applied_at: "2026-01-01T00:00:00.000Z",
        },
        observed_at: "2026-01-01T00:00:00.000Z",
      },
      [`revert-${hostInstance(SSH.host)}`]: {
        host: SSH.host,
        token: TOKEN,
        phase: "firewall",
        unit: `server-host-revert-${TOKEN}`,
        expires_at: new Date(NOW - 1000).toISOString(),
        armed_at: "2026-01-01T00:00:00.000Z",
        ruleset_sha256: "x",
      },
    },
  });
  await m.methods.sync.execute(
    m.methods.sync.arguments.parse({ ...SSH }),
    context,
  );
  const o = getWrittenResources().find((r) =>
    r.name.startsWith("observation-")
  )!
    .data as { drift: string[]; managed_table: boolean };
  assertEquals(o.managed_table, false);
  assertEquals(o.drift.includes("ruleset"), true);
  assertEquals(o.drift.includes("revert_fired"), true);
});

Deno.test("apply_base: logging in as the previous admin defers its revoke; the next run completes it", async () => {
  const resources = await baseStored("oldops");
  const f1 = fakeTransport();
  const ctx1 = createModelTestContext({
    globalArgs: {},
    storedResources: resources,
  });
  // Run 1 logs in AS oldops, so oldops cannot be revoked yet.
  await modelWith(f1).methods.apply_base.execute(
    modelWith(f1).methods.apply_base.arguments.parse({
      ...BASE_ARGS,
      user: "oldops",
      admin_user: "newops",
    }),
    ctx1.context,
  );
  assertEquals(
    f1.commands.some((c) => c.includes("sudo-granted-$user")),
    false,
  );
  const state1 = ctx1.getWrittenResources().find((r) =>
    r.name.startsWith("state-")
  )!.data as { base: { admin_user: string }; pending_revoke?: string[] };
  assertEquals(state1.base.admin_user, "newops");
  assertEquals(state1.pending_revoke, ["oldops"]);

  // Run 2 logs in as root with the same inputs: the pending revoke is done.
  const f2 = fakeTransport();
  const ctx2 = createModelTestContext({
    globalArgs: {},
    storedResources: {
      [`state-${hostInstance(SSH.host)}`]: {
        ...state1,
        host: SSH.host,
        observed_at: "2026-01-01T00:00:00.000Z",
      },
    },
  });
  const out = await modelWith(f2).methods.apply_base.execute(
    modelWith(f2).methods.apply_base.arguments.parse({
      ...BASE_ARGS,
      admin_user: "newops",
    }),
    ctx2.context,
  );
  assertEquals(out.result.changed.includes("revoke_previous"), true);
  assertEquals(
    f2.commands.some((c) =>
      c.includes("sudo-granted-$user") && c.includes("'oldops'")
    ),
    true,
  );
  const state2 = ctx2.getWrittenResources().find((r) =>
    r.name.startsWith("state-")
  )!.data as { pending_revoke?: string[] };
  assertEquals(state2.pending_revoke, undefined);
});

Deno.test("apply_base: a revoke that fails stops the run and records nothing, so a rerun retries", async () => {
  const f = fakeTransport((c) =>
    c.includes("sudo-granted-$user") ? { code: 1 } : { code: 0 }
  );
  const m = modelWith(f);
  const ctx = createModelTestContext({
    globalArgs: {},
    storedResources: await baseStored("oldops"),
  });
  await assertRejects(
    () =>
      m.methods.apply_base.execute(
        m.methods.apply_base.arguments.parse({
          ...BASE_ARGS,
          admin_user: "newops",
        }),
        ctx.context,
      ),
    Error,
    "failed with exit code 1",
  );
  assertEquals(ctx.getWrittenResources().length, 0);
  // The new account was not granted anything either: the revoke comes first.
  assertEquals(f.commands.some((c) => c.includes("useradd")), false);
});

Deno.test("apply_base: keys left alone (exit 3) keep the account on the pending list", async () => {
  const f = fakeTransport((c) =>
    c.includes("sudo-granted-$user") ? { code: 3 } : { code: 0 }
  );
  const m = modelWith(f);
  const ctx = createModelTestContext({
    globalArgs: {},
    storedResources: await baseStored("oldops"),
  });
  await m.methods.apply_base.execute(
    m.methods.apply_base.arguments.parse({
      ...BASE_ARGS,
      admin_user: "newops",
    }),
    ctx.context,
  );
  const st = ctx.getWrittenResources().find((r) => r.name.startsWith("state-"))!
    .data as { pending_revoke?: string[] };
  assertEquals(st.pending_revoke, ["oldops"]);
});

Deno.test("observation: ssh_exposure is unknown when the host disagrees with the record, and pending revokes are listed", async () => {
  const f = fakeTransport((c) =>
    isTimerProbe(c) ? { code: 3, stdout: "inactive\n" } : { code: 0 }
  );
  const m = modelWith(f);
  const { context, getWrittenResources } = createModelTestContext({
    globalArgs: {},
    storedResources: {
      [`state-${hostInstance(SSH.host)}`]: {
        host: SSH.host,
        pending_revoke: ["oldops"],
        firewall: {
          ruleset_sha256: "x",
          managed_sha256: await expectedManagedSha256(FIREWALL),
          mode: "lockdown",
          ssh_exposure: "management-only",
          applied_at: "2026-01-01T00:00:00.000Z",
        },
        observed_at: "2026-01-01T00:00:00.000Z",
      },
    },
  });
  await m.methods.get.execute(
    m.methods.get.arguments.parse({ ...SSH }),
    context,
  );
  const o = getWrittenResources().find((r) =>
    r.name.startsWith("observation-")
  )!
    .data as {
      ssh_exposure: string;
      drift: string[];
      pending_revoke: string[];
    };
  assertEquals(o.drift.includes("ruleset"), true);
  assertEquals(o.ssh_exposure, "unknown");
  assertEquals(o.pending_revoke, ["oldops"]);
});

const isRouteProbe = (c: string) => c.includes("ip -4 -j route show default");
const ROUTES = [
  '[{"dst":"default","gateway":"192.0.2.1","dev":"enp1s0"}]',
  "---",
  "[]",
  "---",
  '[{"dst":"198.51.100.100","dev":"wg0","prefsrc":"198.51.100.2"}]',
].join("\n");

function applyWithTrusted(
  trusted: string[],
  reply: { code: number; stdout?: string } = { code: 0, stdout: ROUTES },
) {
  const f = fakeTransport((c) =>
    // Under sudo, env_reset strips SSH_CLIENT: the real script exits 3 there.
    isRouteProbe(c)
      ? (c.includes("'sudo'") ? { code: 3 } : reply)
      : c.includes("nft -j list table")
      ? {
        code: 0,
        stdout: expectedListing({ ...FIREWALL, trustedInterfaces: trusted }),
      }
      : { code: 0 }
  );
  const m = modelWith(f);
  const ctx = createModelTestContext({ globalArgs: {} });
  const run = () =>
    m.methods.apply_firewall.execute(
      m.methods.apply_firewall.arguments.parse({
        ...FIREWALL_ARGS,
        trusted_interfaces: trusted,
      }),
      ctx.context,
    );
  return { f, run, ctx };
}

Deno.test("trusted_interfaces: the CNI bridge is accepted, with the uplink and session interfaces left out", async () => {
  const { f, run } = applyWithTrusted(["kube-bridge", "cali*"]);
  const out = await run();
  assertEquals(out.result.changed, true);
  assertEquals(f.commands.filter(isRouteProbe).length, 1);
  // sudo is on (the default) yet the probe is not wrapped in it.
  assertEquals(f.commands.find(isRouteProbe)!.includes("'sudo'"), false);
  // The probe is read-only and comes before anything is armed.
  assertEquals(
    f.commands.findIndex(isRouteProbe) < f.commands.findIndex(isArm),
    true,
  );
});

Deno.test("trusted_interfaces: an interface that carries the default route or the SSH session is refused before arming", async () => {
  for (
    const trusted of [["enp1s0"], ["enp*"], ["wg0"], ["wg*"], [
      "kube-bridge",
      "enp1s0",
    ]]
  ) {
    const { f, run, ctx } = applyWithTrusted(trusted);
    await assertRejects(
      run,
      Error,
      "carries the SSH session or the default route",
    );
    assertEquals(f.commands.some(isArm), false, trusted.join());
    assertEquals(f.commands.some(isGuardedApply), false, trusted.join());
    assertEquals(ctx.getWrittenResources().length, 0, trusted.join());
  }
});

Deno.test("trusted_interfaces: a route probe that fails or returns junk refuses rather than guessing", async () => {
  for (
    const reply of [
      { code: 1 },
      { code: 0, stdout: "not json" },
      { code: 0, stdout: '{"dev":"eth0"}' },
    ]
  ) {
    const { f, run } = applyWithTrusted(["kube-bridge"], reply);
    await assertRejects(run, Error);
    assertEquals(f.commands.some(isArm), false);
  }
});

Deno.test("trusted_interfaces: with none set no route probe runs, so the command stream is the 17.1 one", async () => {
  const { f, run } = applyWithTrusted([]);
  await run();
  assertEquals(f.commands.some(isRouteProbe), false);
});

Deno.test("trusted_interfaces: one-character prefixes and a leading dash are refused by the schema", () => {
  const m = createModel();
  const parse = (v: string) =>
    m.methods.render_firewall.arguments.safeParse({
      host: SSH.host,
      management_cidrs: ["192.0.2.0/24"],
      trusted_interfaces: [v],
    }).success;
  for (const bad of ["e*", "-x", "*", "l*"]) {
    assertEquals(parse(bad), false, bad);
  }
  for (const ok of ["kube-bridge", "cali*", "tunl0", "lo0*"]) {
    assertEquals(parse(ok), true, ok);
  }
});

Deno.test("trusted_interfaces: render_firewall rejects patterns that match loopback", async () => {
  const m = createModel();
  const ctx = createModelTestContext({ globalArgs: {} });
  for (const bad of ["lo", "lo*"]) {
    await assertRejects(
      () =>
        m.methods.render_firewall.execute(
          m.methods.render_firewall.arguments.parse({
            host: SSH.host,
            management_cidrs: ["192.0.2.0/24"],
            trusted_interfaces: [bad],
          }),
          ctx.context,
        ),
      Error,
      "loopback",
    );
  }
});

Deno.test("trusted_interfaces: a management NIC that is not the default route is caught through the session route, and ECMP next hops count", async () => {
  const eth1Session = [
    '[{"dst":"default","gateway":"192.0.2.1","dev":"eth0"}]',
    "---",
    "[]",
    "---",
    '[{"dst":"198.51.100.100","dev":"eth1"}]',
  ].join("\n");
  const ecmp = [
    '[{"dst":"default","flags":[],"nexthops":[{"gateway":"192.0.2.1","dev":"eth0"},{"gateway":"192.0.2.2","dev":"eth2"}]}]',
    "---",
    "[]",
    "---",
    '[{"dst":"198.51.100.100","dev":"wg0"}]',
  ].join("\n");
  for (
    const [trusted, stdout] of [
      [["eth1"], eth1Session],
      [["eth*"], eth1Session],
      [["eth2"], ecmp],
      [["wg0"], ecmp],
    ] as const
  ) {
    const { f, run } = applyWithTrusted([...trusted], { code: 0, stdout });
    await assertRejects(
      run,
      Error,
      "carries the SSH session or the default route",
    );
    assertEquals(f.commands.some(isArm), false, trusted.join());
  }
});

Deno.test("trusted_interfaces: the probe fails closed: no ip, no default route, no session route, a bad shape", async () => {
  const cases: [string, { code: number; stdout?: string }][] = [
    ["ip missing", { code: 127 }],
    ["SSH_CLIENT empty", { code: 3 }],
    ["no default route", {
      code: 0,
      stdout: '[]\n---\n[]\n---\n[{"dev":"wg0"}]',
    }],
    ["no session route", {
      code: 0,
      stdout: '[{"dev":"eth0"}]\n---\n[]\n---\n[]',
    }],
    ["two parts", {
      code: 0,
      stdout: '[{"dev":"eth0"}]\n---\n[{"dev":"wg0"}]',
    }],
    ["empty", { code: 0, stdout: "" }],
  ];
  for (const [name, reply] of cases) {
    const { f, run } = applyWithTrusted(["kube-bridge"], reply);
    await assertRejects(run, Error, "", name);
    assertEquals(f.commands.some(isArm), false, name);
  }
});

Deno.test("trusted_interfaces: the probe script is read-only and fails closed", async () => {
  const { UPLINK_CALL, UPLINK_SCRIPT } = await import("./_lib/plans.ts");
  assertEquals(UPLINK_CALL.sudo, false);
  assertEquals(UPLINK_SCRIPT.includes("exit 3"), true);
  assertEquals(UPLINK_SCRIPT.includes("2>/dev/null"), false);
  assertEquals(UPLINK_SCRIPT.includes("exit 3"), true);
  assertEquals(
    /route (add|del|flush|replace|change)/.test(UPLINK_SCRIPT),
    false,
  );
});

const MGMT_LISTING = () => expectedListing(FIREWALL);
const ANYWHERE_LISTING = () =>
  expectedListing({ ...FIREWALL, allowSshFromAnywhere: true });

function widen(
  live: string,
  extra: Record<string, unknown> = {},
  tool: "apply_firewall" | "lockdown" = "apply_firewall",
) {
  const f = fakeTransport((c) =>
    c.includes("nft -j list ruleset")
      ? { code: 0, stdout: live }
      : c.includes("nft -j list table")
      ? {
        code: 0,
        stdout: expectedListing({
          ...FIREWALL,
          sshPort: Number(extra.ssh_port ?? 22),
          allowSshFromAnywhere: tool === "apply_firewall",
        }),
      }
      : { code: 0 }
  );
  const m = modelWith(f);
  const ctx = createModelTestContext({ globalArgs: {} });
  const run = () =>
    m.methods[tool].execute(
      m.methods[tool].arguments.parse({
        ...FIREWALL_ARGS,
        allow_ssh_from_anywhere: tool === "apply_firewall",
        ...extra,
      }),
      ctx.context,
    );
  return { f, run };
}

Deno.test("exposure: apply_firewall refuses to reopen SSH to anywhere on a host the live table has locked down", async () => {
  const { f, run } = widen(MGMT_LISTING());
  await assertRejects(run, Error, "refusing to open SSH to anywhere again");
  assertEquals(f.commands.some(isArm), false);
  assertEquals(f.commands.some(isGuardedApply), false);
});

Deno.test("exposure: it proceeds when asked, when already open, when there is no table, and lockdown is unaffected", async () => {
  const asked = widen(MGMT_LISTING(), { allow_widening_ssh_exposure: true });
  assertEquals((await asked.run()).result.changed, true);
  const open = widen(ANYWHERE_LISTING());
  assertEquals((await open.run()).result.changed, true);
  const none = widen('{"nftables":[]}');
  assertEquals((await none.run()).result.changed, true);
  const lock = widen(MGMT_LISTING(), {}, "lockdown");
  assertEquals((await lock.run()).result.changed, true);
});

Deno.test("exposure: liveSshManagementOnly reads any source-limited rule of the input chain", async () => {
  const { liveSshManagementOnly } = await import("./server_host.ts");
  assertEquals(
    liveSshManagementOnly(["ip.saddr in a4:1-2 ; tcp.dport in n:22 ; accept"]),
    true,
  );
  // Whatever the port: a change of ssh_port cannot hide the restriction.
  assertEquals(
    liveSshManagementOnly([
      "ip6.saddr in a6:1-2 ; tcp.dport in n:2222 ; accept",
    ]),
    true,
  );
  assertEquals(liveSshManagementOnly(["tcp.dport in n:22 ; accept"]), false);
  assertEquals(liveSshManagementOnly(["tcp.dport in n:80 ; accept"]), false);
  assertEquals(liveSshManagementOnly([]), false);
});

Deno.test("identity: a record made for another machine is refused by every method, not trusted", async () => {
  const stored = await baseStored("ops");
  const key = `state-${hostInstance(SSH.host)}`;
  (stored[key] as Record<string, unknown>).identity = "server-1";
  const args = { ...BASE_ARGS, admin_user: "ops" };
  for (
    const [name, call] of [
      [
        "apply_base",
        (m: ReturnType<typeof modelWith>, c: never) =>
          m.methods.apply_base.execute(
            m.methods.apply_base.arguments.parse({
              ...args,
              identity: "server-2",
            }),
            c,
          ),
      ],
      [
        "get",
        (m: ReturnType<typeof modelWith>, c: never) =>
          m.methods.get.execute(
            m.methods.get.arguments.parse({ ...SSH, identity: "server-2" }),
            c,
          ),
      ],
      [
        "apply_firewall",
        (m: ReturnType<typeof modelWith>, c: never) =>
          m.methods.apply_firewall.execute(
            m.methods.apply_firewall.arguments.parse({
              ...FIREWALL_ARGS,
              identity: "server-2",
            }),
            c,
          ),
      ],
      [
        "commit",
        (m: ReturnType<typeof modelWith>, c: never) =>
          m.methods.commit.execute(
            m.methods.commit.arguments.parse({ ...SSH, identity: "server-2" }),
            c,
          ),
      ],
    ] as const
  ) {
    const f = fakeTransport();
    const ctx = createModelTestContext({
      globalArgs: {},
      storedResources: stored,
    });
    await assertRejects(
      () => call(modelWith(f), ctx.context as never),
      Error,
      "made for another machine",
    );
    assertEquals(
      f.commands.some(isArm) || f.commands.some(isGuardedApply),
      false,
      name,
    );
    assertEquals(ctx.getWrittenResources().length, 0, name);
  }
});

Deno.test("identity: the same identity, or none given, works, and the identity is recorded", async () => {
  const stored = await baseStored("ops");
  const key = `state-${hostInstance(SSH.host)}`;
  (stored[key] as Record<string, unknown>).identity = "server-1";
  const f = fakeTransport();
  const ctx = createModelTestContext({
    globalArgs: {},
    storedResources: stored,
  });
  const m = modelWith(f);
  await m.methods.apply_base.execute(
    m.methods.apply_base.arguments.parse({
      ...BASE_ARGS,
      admin_user: "ops",
      identity: "server-1",
    }),
    ctx.context,
  );
  await m.methods.apply_base.execute(
    m.methods.apply_base.arguments.parse({ ...BASE_ARGS, admin_user: "ops" }),
    ctx.context,
  );
  const last = ctx.getWrittenResources().filter((r) =>
    r.name.startsWith("state-")
  )
    .at(-1)!.data as { identity?: string };
  assertEquals(last.identity, "server-1");
  // A first record gets the identity that was given.
  const fresh = createModelTestContext({ globalArgs: {} });
  await modelWith(fakeTransport()).methods.apply_base.execute(
    m.methods.apply_base.arguments.parse({
      ...BASE_ARGS,
      admin_user: "ops",
      identity: "server-9",
    }),
    fresh.context,
  );
  assertEquals(
    (fresh.getWrittenResources().find((r) => r.name.startsWith("state-"))!
      .data as { identity?: string }).identity,
    "server-9",
  );
});

Deno.test("forget: empties the record so a rebuilt host is configured from scratch", async () => {
  const stored = await baseStored("ops");
  const key = `state-${hostInstance(SSH.host)}`;
  (stored[key] as Record<string, unknown>).identity = "server-1";
  const keep = structuredClone(stored);
  const f = fakeTransport();
  const ctx = createModelTestContext({
    globalArgs: {},
    storedResources: stored,
  });
  const m = modelWith(f);
  assertEquals(m.methods.forget.kind, "action");
  assertEquals(m.methods.forget.description.startsWith("DESTRUCTIVE."), true);
  const out = await m.methods.forget.execute(
    m.methods.forget.arguments.parse({ host: SSH.host, identity: "server-1" }),
    ctx.context,
  );
  assertEquals(out.result.forgotten, true);
  assertEquals(f.commands.length, 0);
  const rec = ctx.getWrittenResources().find((r) => r.name === key)!
    .data as Record<
      string,
      unknown
    >;
  assertEquals(Object.keys(rec).sort(), [
    "forgotten_at",
    "host",
    "observed_at",
  ]);
  // A mismatched identity is refused (on a context that still holds the record).
  const again = createModelTestContext({
    globalArgs: {},
    storedResources: keep,
  });
  await assertRejects(
    () =>
      m.methods.forget.execute(
        m.methods.forget.arguments.parse({
          host: SSH.host,
          identity: "server-2",
        }),
        again.context,
      ),
    Error,
    "another machine",
  );
});

Deno.test("forget: the next apply_base on the same address runs every step (not '0 steps')", async () => {
  const f = fakeTransport();
  // The record after forget holds no base, so nothing is considered applied.
  const ctx = createModelTestContext({
    globalArgs: {},
    storedResources: {
      [`state-${hostInstance(SSH.host)}`]: {
        host: SSH.host,
        forgotten_at: "2026-01-01T00:00:00.000Z",
        observed_at: "2026-01-01T00:00:00.000Z",
      },
    },
  });
  const m = modelWith(f);
  const out = await m.methods.apply_base.execute(
    m.methods.apply_base.arguments.parse({ ...BASE_ARGS, admin_user: "ops" }),
    ctx.context,
  );
  assertEquals(
    out.result.changed.includes("packages") || f.commands.length > 0,
    true,
  );
  assertEquals(f.commands.length > 0, true);
});

Deno.test("exposure: a changed ssh_port cannot hide a management-only rule from the widening guard", async () => {
  // The live table limits SSH on port 22 to the management CIDRs; the request
  // opens port 2222 to anywhere.
  const { f, run } = widen(MGMT_LISTING(), { ssh_port: 2222 });
  await assertRejects(run, Error, "refusing to open SSH to anywhere again");
  assertEquals(f.commands.some(isArm), false);
  const ok = widen(MGMT_LISTING(), {
    ssh_port: 2222,
    allow_widening_ssh_exposure: true,
  });
  assertEquals((await ok.run()).result.changed, true);
});

Deno.test("forget: a repeat is a no-op, not a new record version", async () => {
  const key = `state-${hostInstance(SSH.host)}`;
  const stored = await baseStored("ops");
  const m = modelWith(fakeTransport());
  const first = createModelTestContext({
    globalArgs: {},
    storedResources: stored,
  });
  const args = m.methods.forget.arguments.parse({ host: SSH.host });
  const out = await m.methods.forget.execute(args, first.context);
  assertEquals(out.result, { host: SSH.host, forgotten: true, changed: true });
  const emptied = first.getWrittenResources().find((r) => r.name === key)!;
  // The second run sees the emptied record and the host with nothing recorded.
  for (
    const again of [
      { [key]: emptied.data },
      {},
    ]
  ) {
    const ctx = createModelTestContext({
      globalArgs: {},
      storedResources: again,
    });
    const repeat = await m.methods.forget.execute(args, ctx.context);
    assertEquals(repeat.result, {
      host: SSH.host,
      forgotten: true,
      changed: false,
    });
    assertEquals(ctx.getWrittenResources().length, 0);
  }
});

Deno.test("forget: an open revert recorded for another machine is refused, and nothing is written", async () => {
  const revertKey = `revert-${hostInstance(SSH.host)}`;
  const ctx = createModelTestContext({
    globalArgs: {},
    storedResources: {
      [revertKey]: {
        host: SSH.host,
        identity: "server-1",
        token: TOKEN,
        phase: "lockdown",
        unit: `server-host-revert-${TOKEN}`,
        expires_at: new Date(NOW + 60_000).toISOString(),
        armed_at: "2026-01-01T00:00:00.000Z",
        ruleset_sha256: PLACEHOLDER_SHA,
      },
    },
  });
  const m = modelWith(fakeTransport());
  await assertRejects(
    () =>
      m.methods.forget.execute(
        m.methods.forget.arguments.parse({
          host: SSH.host,
          identity: "server-2",
        }),
        ctx.context,
      ),
    Error,
    "another machine",
  );
  assertEquals(ctx.getWrittenResources().length, 0);
  // The matching identity cancels the open revert record.
  const ok = await m.methods.forget.execute(
    m.methods.forget.arguments.parse({ host: SSH.host, identity: "server-1" }),
    ctx.context,
  );
  assertEquals(ok.result.changed, true);
  const written = ctx.getWrittenResources().find((r) => r.name === revertKey)!;
  assertEquals(
    typeof (written.data as Record<string, unknown>).cancelled_at,
    "string",
  );
});

Deno.test("transport: scripts and the key travel on stdin; no remote command line carries them, and nothing is written to a remote temp path", async () => {
  const f = fakeTransport();
  const m = modelWith(f);
  const ctx = createModelTestContext({ globalArgs: {} });
  await m.methods.apply_base.execute(
    m.methods.apply_base.arguments.parse({
      ...SSH,
      packages: ["curl"],
      admin_user: "ops",
      authorized_keys: [KEY],
      sysctl: { "net.ipv4.ip_forward": "1" },
    }),
    ctx.context,
  );
  await m.methods.apply_firewall.execute(
    m.methods.apply_firewall.arguments.parse(FIREWALL_ARGS),
    ctx.context,
  );
  const remote = f.sshArgs().map((a) => a[a.length - 1]);
  assertEquals(remote.length > 5, true);
  for (const r of remote) {
    // The only thing on the remote command line is the shell that reads stdin.
    assertEquals(["'sh' '-s'", "'sudo' '-n' 'sh' '-s'"].includes(r), true, r);
  }
  await assertNoSecretOnArgv(f.recording, [PEM, "PRIVATE KEY"]);
  await assertNoRemoteSecretWrite(f.recording, [PEM, "PRIVATE KEY"]);
  assertEquals(f.recording.uploads, []);
});

Deno.test("apply_firewall: an apply that hits its remote deadline leaves the revert armed and recorded", async () => {
  const f = fakeTransport((c) =>
    isGuardedApply(c) ? { code: 124 } : { code: 0 }
  );
  const m = modelWith(f);
  const ctx = createModelTestContext({ globalArgs: {} });
  await assertRejects(
    () =>
      m.methods.apply_firewall.execute(
        m.methods.apply_firewall.arguments.parse(FIREWALL_ARGS),
        ctx.context,
      ),
    Error,
    "deadline",
  );
  // nft may have committed after the deadline fired: disarming would strand
  // the new ruleset, so the timer stays and the record stays open.
  assertEquals(f.commands.some(isDisarm), false);
  const rec = ctx.getWrittenResources().find((r) =>
    r.name === `revert-${hostInstance(SSH.host)}`
  )!.data as Record<string, unknown>;
  assertEquals(rec.cancelled_at, undefined);
});

Deno.test("resources: data names are distinct within one method run, and carry no path characters", async () => {
  const f = fakeTransport();
  const m = modelWith(f);
  const cases: [string, (c: never) => Promise<unknown>][] = [
    [
      "apply_base",
      (c) =>
        m.methods.apply_base.execute(
          m.methods.apply_base.arguments.parse({
            ...BASE_ARGS,
            admin_user: "ops",
          }),
          c,
        ),
    ],
    [
      "apply_firewall",
      (c) =>
        m.methods.apply_firewall.execute(
          m.methods.apply_firewall.arguments.parse(FIREWALL_ARGS),
          c,
        ),
    ],
    [
      "get",
      (c) => m.methods.get.execute(m.methods.get.arguments.parse(SSH), c),
    ],
    [
      "render_firewall",
      (c) =>
        m.methods.render_firewall.execute(
          m.methods.render_firewall.arguments.parse({
            host: "../a/b",
            management_cidrs: FIREWALL.managementCidrs,
            allow_tcp: FIREWALL.allowTcp,
          }),
          c,
        ),
    ],
  ];
  for (const [name, call] of cases) {
    const ctx = createModelTestContext({ globalArgs: {} });
    await call(ctx.context as never);
    const names = ctx.getWrittenResources().map((r) => r.name);
    assertEquals(new Set(names).size, names.length, name);
    for (const n of names) assertEquals(/[\/\\\0]|\.\./.test(n), false, n);
  }
});

Deno.test("capture: one pass over every script shape, for the dash and bashism gates", async () => {
  let cancelled = false;
  let applied = false;
  const f = fakeTransport((c) => {
    if (isGuardedApply(c)) applied = true;
    if (c.includes('systemctl stop "$unit.timer"')) cancelled = true;
    if (isRouteProbe(c)) return { code: 0, stdout: ROUTES };
    if (c.includes("nft -j list ruleset")) {
      return {
        code: 0,
        stdout: applied
          ? expectedListing({ ...FIREWALL, trustedInterfaces: ["cali*"] })
          : '{"nftables":[]}',
      };
    }
    if (c.includes("nft -j list table")) {
      return {
        code: 0,
        stdout: expectedListing({ ...FIREWALL, trustedInterfaces: ["cali*"] }),
      };
    }
    if (isTimerProbe(c)) {
      return cancelled
        ? { code: 3, stdout: "inactive\n" }
        : { code: 0, stdout: "active\n" };
    }
    return { code: 0 };
  }, true);
  const m = modelWith(f);
  const stored = await baseStored("oldops");
  const ctx = createModelTestContext({
    globalArgs: {},
    storedResources: stored,
  });
  await m.methods.apply_base.execute(
    m.methods.apply_base.arguments.parse({
      ...BASE_ARGS,
      packages: ["curl", "nftables"],
      admin_user: "ops",
      sysctl: { "net.ipv4.ip_forward": "1" },
    }),
    ctx.context,
  );
  await m.methods.apply_firewall.execute(
    m.methods.apply_firewall.arguments.parse({
      ...FIREWALL_ARGS,
      trusted_interfaces: ["cali*"],
    }),
    ctx.context,
  );
  await m.methods.get.execute(m.methods.get.arguments.parse(SSH), ctx.context);
  await m.methods.commit.execute(
    m.methods.commit.arguments.parse(SSH),
    ctx.context,
  );
  await m.methods.sync.execute(
    m.methods.sync.arguments.parse(SSH),
    ctx.context,
  );
  const commands = f.commands;
  for (
    const shape of [
      "apt-get install",
      "useradd",
      "authorized_keys",
      "sysctl --system",
      "systemd-run",
      "| nft -c -f -",
      "| nft -f -",
      "gpasswd",
      'systemctl stop "$unit.timer"',
      "ip -j route get",
    ]
  ) {
    assertEquals(commands.some((c) => c.includes(shape)), true, shape);
  }
  // The restore script runs from a file on the host, under systemd; it is
  // captured as the shell script it is.
  const revert = createRecordingRunner();
  await revert.run("sh", ["-c", renderRevertScript(TOKEN)]);
  assertEquals(revert.recording.calls.length, 1);
});
