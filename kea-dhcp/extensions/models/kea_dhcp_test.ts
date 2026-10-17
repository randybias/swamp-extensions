import { assert, assertEquals, assertRejects } from "jsr:@std/assert@1.0.19";
import { KeaInputError } from "./_lib/grammar.ts";
import { type CommandRunner, sha256Hex, SshConfigError } from "./_lib/ssh.ts";
import { renderConfig } from "./_lib/render.ts";
import { keaVersion } from "./_lib/transport.ts";
import {
  configName,
  ConfigStateSchema,
  instanceKey,
  observationName,
  pendingName,
  PendingStateSchema,
} from "./_lib/schemas.ts";
import {
  applyArgsSchema,
  claimScript,
  commitScript,
  configArgsSchema,
  configSetRequest,
  groupScript,
  hookLibraryScript,
  installFileScript,
  type KeaDeps,
  managementScript,
  type MethodContext,
  model,
  renderAndHash,
  restoreScript,
  setDeps,
} from "./kea_dhcp.ts";

const HOST = "192.0.2.10";
const KEY_LINE = `${HOST} ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeKey`;
const SSH = {
  host: HOST,
  port: 22,
  user: "root",
  host_key_policy: "strict" as const,
  host_keys: [KEY_LINE],
  ssh_key_ref: "default/KEY",
  connect_timeout_s: 15,
};
const DHCP = {
  interfaces: ["eth1"],
  socket_type: "raw" as const,
  valid_lifetime_s: 3600,
  options: [{ name: "routers" as const, value: ["192.0.2.1"] }],
  subnets: [{
    id: 10,
    subnet: "192.0.2.0/24",
    pools: ["192.0.2.10 - 192.0.2.50"],
    reservations: [{
      hw_address: "02:00:00:00:00:01",
      ip_address: "192.0.2.9",
    }],
    options: [],
  }],
  lease_api: false,
  canary_hosts: [],
  revert_after_s: 600,
  serve_on_management_ack: false,
};

interface Call {
  cmd: string;
  command: string;
  stdin?: Uint8Array | string;
}

interface Written {
  specName: string;
  name: string;
  data: Record<string, unknown>;
}

type Exec = { code: number; stdout: string; stderr: string };
type Handler = (
  stdin: Uint8Array | string | undefined,
  command: string,
) => Exec | Promise<Exec>;
type Match = string | ((command: string) => boolean);

const OK: Exec = { code: 0, stdout: "", stderr: "" };
const out = (stdout: string, code = 0): Exec => ({ code, stdout, stderr: "" });

function text(value?: Uint8Array | string): string {
  return typeof value === "string"
    ? value
    : value
    ? new TextDecoder().decode(value)
    : "";
}

function matches(match: Match, command: string): boolean {
  return typeof match === "string" ? command.includes(match) : match(command);
}

/**
 * A fake SSH host driven by ordered matchers. It answers the common verbs
 * (validate, arm, upload, config-set, probe) and tracks the calls and the last
 * uploaded payload; tests override specific verbs with `when`.
 */
function fakeHost(): {
  runner: CommandRunner;
  calls: Call[];
  when: (match: Match, handler: Handler) => void;
  armed: () => boolean;
} {
  const calls: Call[] = [];
  const overrides: [Match, Handler][] = [];
  let armed = false;
  let uploaded = "";
  const base: [Match, Handler][] = [
    ["kea-dhcp4 -t", () => OK],
    ["systemd-run", () => {
      armed = true;
      return OK;
    }],
    ["ip -o route get", () => out("eth9\n")],
    ["systemctl show", () => out("_kea\n")],
    ["is-enabled", () => out("enabled\n")],
    ["is-active", () => out("active\n")],
    ["MISSING", () => out("MISSING\n")],
    ["DIRECTORY", () => out("MISSING\n")],
    ["mktemp", async (stdin, command) => {
      uploaded = text(stdin);
      const mode = /chmod '(\d+)'/.exec(command)?.[1] ?? "600";
      return out(`${await sha256Hex(uploaded)} ${mode}\n`);
    }],
    ["UNIX-CONNECT", () => {
      const request = JSON.parse(uploaded || "{}") as { command?: string };
      return out(JSON.stringify(
        request.command === "config-hash-get"
          ? { result: 0, arguments: { hash: "kea-hash" } }
          : { result: 0 },
      ));
    }],
    ["sha256sum", () => out(`${"0".repeat(64)}\n`)],
  ];
  const runner: CommandRunner = async (cmd, args, options = {}) => {
    const command = args.at(-1) ?? "";
    calls.push({ cmd, command, stdin: options.stdin });
    if (cmd === "ssh-agent") {
      return out(
        "SSH_AUTH_SOCK=/tmp/agent.test; export SSH_AUTH_SOCK;\nSSH_AGENT_PID=42; export SSH_AGENT_PID;\n",
      );
    }
    if (cmd === "ssh-add") return OK;
    if (cmd !== "ssh") return OK;
    for (const [match, handler] of [...overrides, ...base]) {
      if (matches(match, command)) return await handler(options.stdin, command);
    }
    return OK;
  };
  return {
    runner,
    calls,
    when: (match, handler) => overrides.push([match, handler]),
    armed: () => armed,
  };
}

/** A plain-object method context, as swamp actually passes one. */
function makeContext(vaultValue = "PLACEHOLDER-KEY"): {
  context: MethodContext;
  written: Written[];
  store: Map<string, Record<string, unknown>>;
} {
  const written: Written[] = [];
  const store = new Map<string, Record<string, unknown>>();
  const context: MethodContext = {
    logger: { info: () => {}, warn: () => {} },
    writeResource: (
      specName: string,
      name: string,
      data: Record<string, unknown>,
    ) => {
      written.push({ specName, name, data });
      store.set(name, data);
      return Promise.resolve({
        name,
        specName,
        kind: "resource",
        dataId: "d0",
        version: 1,
        size: 0,
      });
    },
    readResource: (name: string) => Promise.resolve(store.get(name) ?? null),
    vaultService: {
      get: (_vault: string, _key: string) => Promise.resolve(vaultValue),
    },
  };
  return { context, written, store };
}

const depsFor = (
  run: CommandRunner,
  extra: Partial<KeaDeps> = {},
): Partial<KeaDeps> => ({
  run,
  now: () => 1_700_000_000_000,
  sleep: () => Promise.resolve(),
  token: () => "token-1",
  resolveSecret: () => Promise.resolve(""),
  ...extra,
});

Deno.test("schemas refuse invalid interfaces, options and combinations", () => {
  const bad = [
    { ...SSH, ...DHCP, interfaces: ["*"] },
    { ...SSH, ...DHCP, interfaces: ["eth0", "eth0"] },
    {
      ...SSH,
      ...DHCP,
      subnets: [{ ...DHCP.subnets[0], pools: ["203.0.113.0/24"] }],
    },
    {
      ...SSH,
      ...DHCP,
      subnets: [
        DHCP.subnets[0],
        {
          id: 11,
          subnet: "192.0.2.128/25",
          pools: ["192.0.2.200 - 192.0.2.210"],
          reservations: [],
          options: [],
        },
      ],
    },
    { ...SSH, ...DHCP, lease_api: true },
  ];
  for (const args of bad) {
    assertEquals(applyArgsSchema.safeParse(args).success, false);
  }
  assertEquals(applyArgsSchema.safeParse({ ...SSH, ...DHCP }).success, true);
  assertEquals(configArgsSchema.safeParse(DHCP).success, true);
});

Deno.test("host scripts encode the revert and hook semantics", () => {
  const claim = claimScript("/var/lib/kea-dhcp-revert/tok", '{"token":"tok"}');
  assert(claim.includes("flock -w 30"), "the claim is serialized");
  assert(claim.includes("exit 9"), "an armed revert refuses a second claim");

  const active = restoreScript("tok", "/run/kea/kea4-ctrl-socket", true, true);
  assert(active.includes("result=pass"));
  assert(active.includes("previous.conf"));
  assert(active.includes('rm -f "$a"'), "the restore always clears active");
  assert(active.includes('systemctl restart "$svc"'));
  // Kea answers with a space after the colon; the match must allow it.
  assert(
    active.includes(`grep -Eq '"result": *0'`),
    "the socket answer match allows Kea's spacing",
  );
  assert(active.includes("flock -w 30 9"), "the restore takes the lock");
  assert(
    active.includes('-f "$d/committed"'),
    "a committed revert is never undone",
  );
  assert(active.includes('systemctl enable "$svc"'));
  assert(active.includes('systemctl is-enabled "$svc"'));

  const inactive = restoreScript(
    "tok",
    "/run/kea/kea4-ctrl-socket",
    false,
    false,
  );
  assert(inactive.includes('systemctl stop "$svc"'));
  assert(inactive.includes('systemctl disable "$svc"'));

  const commit = commitScript(
    "/var/lib/kea-dhcp-revert/tok",
    "tok",
    "a".repeat(64),
  );
  assert(commit.includes("flock -w 30 9"), "the commit takes the lock");
  assert(commit.includes("committed"));
  assert(commit.includes("fired.json"));
  assert(commit.includes("kea-dhcp-revert-tok.service"));

  const hook = hookLibraryScript("/usr/lib/kea/hooks/libdhcp_lease_cmds.so");
  assert(hook.includes("no-hooks-dir"));
  assert(hook.includes("readlink -f"));

  const install = installFileScript("/etc/kea/kea-dhcp4.conf.staged-t", "_kea");
  assert(install.includes("chgrp '_kea'"));
  assert(install.includes("chmod 0640"));
  assert(install.includes("mv -T"));

  assert(managementScript().includes("ip -o route get"));
  assert(groupScript().includes("systemctl show -p User"));
});

Deno.test("keaVersion parses the bare 2.4 version string", () => {
  assertEquals(keaVersion("2.4.1"), "2.4.1");
  assertEquals(keaVersion("Kea 2.4.1\n"), "2.4.1");
  assertEquals(keaVersion("no version here"), undefined);
});

Deno.test("configSetRequest sends the whole Dhcp4 object", async () => {
  const rendered = await renderAndHash(configArgsSchema.parse(DHCP));
  const request = configSetRequest(rendered);
  assertEquals(request.command, "config-set");
  assertEquals(request.service, ["dhcp4"]);
  const args = request.arguments as { Dhcp4?: unknown };
  assertEquals(typeof args.Dhcp4, "object");
  assertEquals(args.Dhcp4, (rendered.config as { Dhcp4: unknown }).Dhcp4);
});

Deno.test("render is host-free, deterministic and exposes the plan", async () => {
  const { context } = makeContext();
  const result = await model.methods.render.execute(DHCP, context);
  const expected = await renderAndHash(configArgsSchema.parse(DHCP));
  const body =
    (result as { result: { sha256: string; plan: string[] } }).result;
  assertEquals(body.sha256, expected.sha256);
  assertEquals(body.plan[0], "validate");
  assertEquals(body.plan.includes("arm"), true);
});

Deno.test("apply arms the revert before writing and setting the config", async () => {
  const host = fakeHost();
  const prior = setDeps(depsFor(host.runner));
  try {
    const { context, written } = makeContext();
    const result = await model.methods.apply.execute(
      { ...SSH, ...DHCP },
      context,
    );
    assert(
      (result as { result: { revert_token: string } }).result.revert_token,
    );
    const order = host.calls.map((call) => call.command);
    const armAt = order.findIndex((c) => c.includes("systemd-run"));
    const writeAt = order.findIndex((c) =>
      c.includes("mv -T") && c.includes("'/etc/kea/kea-dhcp4.conf'")
    );
    const setAt = order.findIndex((c, i) =>
      i > writeAt && c.includes("UNIX-CONNECT")
    );
    assert(armAt >= 0, "arm step ran");
    assert(writeAt >= 0, "config write ran");
    assert(armAt < writeAt, "arm precedes the config write");
    assert(setAt > writeAt, "config write precedes config-set");
    assert(written.some((w) => w.specName === "revert"), "revert persisted");
    assert(written.some((w) => w.specName === "pending"), "pending persisted");
    assert(written.some((w) => w.specName === "action"), "action persisted");
  } finally {
    setDeps(prior);
  }
});

Deno.test("apply is a no-op when the live config already matches", async () => {
  const rendered = await renderAndHash(configArgsSchema.parse(DHCP));
  const host = fakeHost();
  host.when(
    (c) => c.includes("sha256sum") && c.includes("'/etc/kea/kea-dhcp4.conf'"),
    () => out(`${rendered.sha256}\n`),
  );
  const prior = setDeps(depsFor(host.runner));
  try {
    const { context } = makeContext();
    const result = await model.methods.apply.execute(
      { ...SSH, ...DHCP },
      context,
    );
    assertEquals(host.armed(), false, "no timer is armed on a no-op");
    assertEquals(
      (result as { result: { revert_token: string } }).result.revert_token,
      "",
    );
  } finally {
    setDeps(prior);
  }
});

Deno.test("apply refuses the management interface without an ack", async () => {
  const host = fakeHost();
  host.when("ip -o route get", () => out("eth1\n"));
  const prior = setDeps(depsFor(host.runner));
  try {
    const { context } = makeContext();
    await assertRejects(
      () => model.methods.apply.execute({ ...SSH, ...DHCP }, context),
      SshConfigError,
      "management",
    );
  } finally {
    setDeps(prior);
  }
});

Deno.test("get resolves the key through vaultService, never on argv", async () => {
  const host = fakeHost();
  // Deliberately no resolveSecret: this drives context.vaultService.get and the
  // ssh-agent path with a plain-object context, as swamp passes one.
  const prior = setDeps(depsFor(host.runner, { resolveSecret: undefined }));
  try {
    const { context, written } = makeContext();
    const result = await model.methods.get.execute(SSH, context);
    assertEquals(
      (result as { result: { service_active: boolean } }).result.service_active,
      true,
    );
    assertEquals(written[0].specName, "observation");
    const add = host.calls.find((call) => call.cmd === "ssh-add");
    assert(add && text(add.stdin).includes("PLACEHOLDER-KEY"));
    assert(
      !host.calls.some((call) => call.command.includes("PLACEHOLDER-KEY")),
      "the key is never on argv",
    );
  } finally {
    setDeps(prior);
  }
});

Deno.test("leases parses the memfile without writing", async () => {
  const csv =
    "address,hwaddr,client_id,valid_lifetime,expire,subnet_id,fqdn_fwd,fqdn_rev,hostname,state\n" +
    "192.0.2.10,02:00:00:00:00:01,,3600,4000000000,10,0,0,web-1,0\n";
  const host = fakeHost();
  host.when("'.2'", () => out("", 1));
  host.when("'cat'", () => out(csv));
  const prior = setDeps(depsFor(host.runner));
  try {
    const { context, written } = makeContext();
    const result = await model.methods.leases.execute(
      { ...SSH, lease_api: false },
      context,
    );
    assertEquals((result as { result: { count: number } }).result.count, 1);
    assertEquals(written[0].specName, "leases");
  } finally {
    setDeps(prior);
  }
});

Deno.test("a rejected kea-dhcp4 -t stops before arming anything", async () => {
  const host = fakeHost();
  host.when("kea-dhcp4 -t", () => ({ code: 1, stdout: "", stderr: "bad\n" }));
  const prior = setDeps(depsFor(host.runner));
  try {
    const { context, written } = makeContext();
    await assertRejects(
      () => model.methods.apply.execute({ ...SSH, ...DHCP }, context),
      KeaInputError,
      "rejected",
    );
    assertEquals(host.armed(), false);
    assertEquals(written.length, 0);
  } finally {
    setDeps(prior);
  }
});

Deno.test("remove arms the revert before disabling and restoring", async () => {
  // The stock Ubuntu/Debian config carries // comments, so it is not JSON.
  const original = [
    "// This is a stock Kea configuration file.",
    "{",
    "  // Listen on no interfaces by default.",
    '  "Dhcp4": { "interfaces-config": { "interfaces": [] } }',
    "}",
    "",
  ].join("\n");
  const originalSha = await sha256Hex(original);
  const host = fakeHost();
  host.when(
    (c) => c.includes("sha256sum") && c.includes("original.conf"),
    () => out(`${originalSha}\n`),
  );
  host.when(
    (c) => c.includes("sha256sum") && c.includes("'/etc/kea/kea-dhcp4.conf'"),
    () => out(`${"1".repeat(64)}\n`),
  );
  host.when(
    (c) => c.includes("cat") && c.includes("original.conf"),
    () => out(original),
  );
  const prior = setDeps(depsFor(host.runner));
  try {
    const { context, written } = makeContext();
    const result = await model.methods.remove.execute(SSH, context);
    assert(host.armed(), "the revert timer is armed before converging");
    assertEquals(
      (result as { result: { removed: boolean } }).result.removed,
      true,
    );
    const order = host.calls.map((call) => call.command);
    const armAt = order.findIndex((c) => c.includes("systemd-run"));
    const disableAt = order.findIndex((c) => c.includes("systemctl disable"));
    assert(armAt >= 0, "the arm step ran");
    assert(disableAt > armAt, "the arm precedes disable");
    assert(written.some((w) => w.specName === "revert"), "revert persisted");
    assert(written.some((w) => w.specName === "pending"), "pending persisted");
    assert(written.some((w) => w.specName === "action"), "action persisted");
  } finally {
    setDeps(prior);
  }
});

Deno.test("each resource kind is stored under its own name", async () => {
  const rendered = await renderAndHash(configArgsSchema.parse(DHCP));
  const key = instanceKey(SSH);
  const host = fakeHost();
  let armed = false;
  // The live file must differ before the arm and match afterwards.
  host.when("committed", () => out("committed"));
  host.when("fired.json", () => out("", 1));
  host.when(
    "active.json",
    () =>
      out(
        JSON.stringify({
          token: "token-1",
          expires_at: "2030-01-01T00:00:00Z",
        }),
      ),
  );
  host.when("systemd-run", () => {
    armed = true;
    return OK;
  });
  host.when("ss -lunp", () => out("0.0.0.0:67\n"));
  host.when(
    (c) => c.includes("sha256sum") && c.includes("'/etc/kea/kea-dhcp4.conf'"),
    () => out(armed ? `${rendered.sha256}\n` : `${"0".repeat(64)}\n`),
  );
  const prior = setDeps(depsFor(host.runner));
  try {
    const { context, store, written } = makeContext();
    const applyResult = await model.methods.apply.execute(
      { ...SSH, ...DHCP },
      context,
    );
    const token =
      (applyResult as { result: { revert_token: string } }).result.revert_token;
    assertEquals(token, "token-1");

    // These must not overwrite the pending apply record.
    await model.methods.leases.execute({ ...SSH, lease_api: false }, context);
    await model.methods.get.execute(SSH, context);
    assertEquals(
      (store.get(pendingName(key)) as { kea_hash?: string }).kea_hash,
      "kea-hash",
    );

    // Commit reads the pending record and writes the committed one.
    const commitResult = await model.methods.commit.execute(SSH, context);
    assertEquals(
      (commitResult as { result: { committed: boolean } }).result.committed,
      true,
    );

    const names = (spec: string) =>
      new Set(written.filter((w) => w.specName === spec).map((w) => w.name));
    for (
      const [spec, prefix] of [
        ["config", "config-"],
        ["pending", "pending-"],
        ["revert", "revert-"],
        ["observation", "observation-"],
        ["leases", "leases-"],
      ] as const
    ) {
      const set = names(spec);
      assert(set.size >= 1, `${spec} was written`);
      for (const name of set) assert(name.startsWith(prefix), `${name} prefix`);
    }
    // Action outcomes are named by method so each is separately visible.
    const actionNames = names("action");
    assert(actionNames.has(`apply-${key}`), "apply outcome written");
    assert(actionNames.has(`commit-${key}`), "commit outcome written");
    assert(store.has(configName(key)), "committed config record exists");
  } finally {
    setDeps(prior);
  }
});

Deno.test("a fired revert discards the pending apply without drift", async () => {
  const key = instanceKey(SSH);
  const committedSha = "a".repeat(64);
  const host = fakeHost();
  host.when(
    (c) => c.includes("sha256sum") && c.includes("'/etc/kea/kea-dhcp4.conf'"),
    () => out(`${committedSha}\n`),
  );
  host.when(
    "fired.json",
    () =>
      out(JSON.stringify({
        token: "tok",
        fired_at: "2030-01-01T00:00:00Z",
        result: "pass",
      })),
  );
  const prior = setDeps(depsFor(host.runner));
  try {
    const { context, store } = makeContext();
    const now = new Date(1_700_000_000_000).toISOString();
    await context.writeResource(
      "config",
      configName(key),
      ConfigStateSchema.parse({
        host: HOST,
        config_sha256: committedSha,
        kea_hash: "kea-committed",
        committed_at: now,
        applied_at: now,
        subnets: 1,
      }),
    );
    await context.writeResource(
      "pending",
      pendingName(key),
      PendingStateSchema.parse({
        host: HOST,
        config_sha256: "b".repeat(64),
        kea_hash: "kea-pending",
        applied_at: now,
        subnets: 1,
        status: "pending",
      }),
    );
    const result = await model.methods.sync.execute(SSH, context);
    assertEquals((result as { result: { drift: string[] } }).result.drift, []);
    assertEquals(
      (store.get(pendingName(key)) as { status: string }).status,
      "discarded",
    );
    assert(
      (store.get(observationName(key)) as { drift: string[] }).drift.length ===
        0,
    );
  } finally {
    setDeps(prior);
  }
});

Deno.test("rendered goldens pass kea-dhcp4 -t when the tool is present", async () => {
  const probe = new Deno.Command("bash", {
    args: ["-c", "command -v kea-dhcp4 || true"],
  }).outputSync();
  if (new TextDecoder().decode(probe.stdout).trim() === "") {
    assert(true, "kea-dhcp4 is not installed; the live cell covers this");
    return;
  }
  const rendered = renderConfig({
    interfaces: ["eth1"],
    socket_type: "raw",
    valid_lifetime_s: 3600,
    options: [
      { name: "routers", value: ["192.0.2.1"] },
      { name: "domain-name-servers", value: ["192.0.2.53", "192.0.2.54"] },
      { name: "ntp-servers", value: ["192.0.2.123"] },
      { name: "domain-name", value: "example.test" },
      { name: "domain-search", value: ["example.test", "corp.example.test"] },
      { name: "interface-mtu", value: 1500 },
    ],
    subnets: [{
      id: 10,
      subnet: "192.0.2.0/24",
      pools: ["192.0.2.10 - 192.0.2.50"],
      reservations: [{
        hw_address: "02:00:00:00:00:01",
        ip_address: "192.0.2.9",
      }],
      options: [],
      relay_addresses: [],
    }],
  });
  const path = await Deno.makeTempFile({
    prefix: "kea-test-",
    suffix: ".conf",
  });
  await Deno.writeTextFile(path, rendered.json);
  try {
    const result = new Deno.Command("bash", {
      args: ["-c", `kea-dhcp4 -t ${path}`],
    }).outputSync();
    assertEquals(result.code, 0, new TextDecoder().decode(result.stderr));
  } finally {
    await Deno.remove(path);
  }
});
