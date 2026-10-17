import { assert, assertEquals, assertRejects } from "jsr:@std/assert@1.0.19";
import { KeaInputError } from "./_lib/grammar.ts";
import { type CommandRunner, sha256Hex, SshConfigError } from "./_lib/ssh.ts";
import { renderConfig } from "./_lib/render.ts";
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

interface Event {
  kind: string;
  detail: string;
}

function text(value?: Uint8Array | string): string {
  return typeof value === "string"
    ? value
    : value
    ? new TextDecoder().decode(value)
    : "";
}

interface Written {
  specName: string;
  name: string;
  data: Record<string, unknown>;
}

/** A plain-object method context, as swamp actually passes one. */
function makeContext(vaultValue = "PLACEHOLDER-KEY"): {
  context: MethodContext;
  written: Written[];
} {
  const written: Written[] = [];
  const context: MethodContext = {
    logger: { info: () => {}, warn: () => {} },
    writeResource: (
      specName: string,
      name: string,
      data: Record<string, unknown>,
    ) => {
      written.push({ specName, name, data });
      return Promise.resolve({
        name,
        specName,
        kind: "resource",
        dataId: "d0",
        version: 1,
        size: 0,
      });
    },
    readResource: () => Promise.resolve(null),
    vaultService: {
      get: (_vault: string, _key: string) => Promise.resolve(vaultValue),
    },
  };
  return { context, written };
}

/** The full apply runner: kea test, arm, uploads, config-set, probes. */
function applyHandler() {
  let uploaded = "";
  return async (command: string, stdin?: Uint8Array | string) => {
    if (command.includes("kea-dhcp4 -t")) {
      return { code: 0, stdout: "", stderr: "" };
    }
    if (command.includes("systemd-run")) {
      return { code: 0, stdout: "", stderr: "" };
    }
    if (command.includes("ip -o route get")) {
      return { code: 0, stdout: "eth9\n", stderr: "" };
    }
    if (command.includes("systemctl show")) {
      return { code: 0, stdout: "_kea\n", stderr: "" };
    }
    if (command.includes("MISSING") || command.includes("DIRECTORY")) {
      return { code: 0, stdout: "MISSING\n", stderr: "" };
    }
    if (command.includes("mktemp")) {
      uploaded = text(stdin);
      const mode = /chmod '(\d+)'/.exec(command)?.[1] ?? "600";
      return {
        code: 0,
        stdout: `${await sha256Hex(uploaded)} ${mode}\n`,
        stderr: "",
      };
    }
    if (command.includes("UNIX-CONNECT")) {
      const request = JSON.parse(uploaded) as { command?: string };
      return {
        code: 0,
        stdout: JSON.stringify(
          request.command === "config-hash-get"
            ? { result: 0, arguments: { hash: "kea-hash" } }
            : { result: 0 },
        ),
        stderr: "",
      };
    }
    if (command.includes("is-active")) {
      return { code: 0, stdout: "active\n", stderr: "" };
    }
    if (command.includes("sha256sum")) {
      return { code: 0, stdout: `${"0".repeat(64)}\n`, stderr: "" };
    }
    if (command.includes("ip -o -4 addr")) {
      return { code: 0, stdout: "", stderr: "" };
    }
    return { code: 0, stdout: "", stderr: "" };
  };
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
  assert(
    (configArgsSchema as unknown as { _def: unknown })._def !== undefined,
  );
});

Deno.test("host scripts encode the revert and hook semantics", () => {
  const claim = claimScript(
    "/var/lib/kea-dhcp-revert/tok",
    '{"token":"tok"}',
  );
  assert(claim.includes("flock -w 30"), "the claim is serialized");
  assert(claim.includes("exit 9"), "an armed revert refuses a second claim");

  const active = restoreScript(
    "tok",
    "/run/kea/kea4-ctrl-socket",
    true,
    true,
  );
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

  const install = installFileScript(
    "/etc/kea/kea-dhcp4.conf.staged-t",
    "_kea",
  );
  assert(install.includes("chgrp '_kea'"));
  assert(install.includes("chmod 0640"));
  assert(install.includes("mv -T"));

  assert(managementScript().includes("ip -o route get"));
  assert(groupScript().includes("systemctl show -p User"));
});

Deno.test("configSetRequest sends the whole Dhcp4 object", async () => {
  const rendered = await renderAndHash(configArgsSchema.parse(DHCP));
  const request = configSetRequest(rendered);
  assertEquals(request.command, "config-set");
  assertEquals(request.service, ["dhcp4"]);
  const args = request.arguments as { Dhcp4?: unknown };
  assertEquals(typeof args.Dhcp4, "object");
  assertEquals(
    args.Dhcp4,
    (rendered.config as { Dhcp4: unknown }).Dhcp4,
  );
});

Deno.test("render is host-free, deterministic and exposes the plan", async () => {
  const result = await model.methods.render.execute(DHCP);
  const expected = await renderAndHash(configArgsSchema.parse(DHCP));
  assertEquals(
    (result as { result: { sha256: string } }).result.sha256,
    expected.sha256,
  );
  assertEquals(
    (result as { result: { plan: string[] } }).result.plan[0],
    "validate",
  );
  assertEquals(
    (result as { result: { plan: string[] } }).result.plan.includes("arm"),
    true,
  );
});

Deno.test("apply arms the revert before writing and setting the config", async () => {
  const calls: Call[] = [];
  const handle = applyHandler();
  const runner: CommandRunner = async (cmd, args, options = {}) => {
    const command = args.at(-1) ?? "";
    calls.push({ cmd, command, stdin: options.stdin });
    if (cmd !== "ssh") return { code: 0, stdout: "", stderr: "" };
    return await handle(command, options.stdin);
  };
  const prior = setDeps(depsFor(runner));
  try {
    const { context, written } = makeContext();
    const result = await model.methods.apply.execute(
      { ...SSH, ...DHCP },
      context,
    );
    assert(
      (result as { result: { revert_token: string } }).result.revert_token,
    );
    const order = calls.map((c) => c.command);
    const armAt = order.findIndex((c) => c.includes("systemd-run"));
    const writeAt = order.findIndex((c) =>
      c.includes("mv -T") && c.includes("'/etc/kea/kea-dhcp4.conf'")
    );
    // The first socket call is the pre-check hash; the config-set follows the
    // config write.
    const setAt = order.findIndex((c, i) =>
      i > writeAt && c.includes("UNIX-CONNECT")
    );
    assert(armAt >= 0, "arm step ran");
    assert(writeAt >= 0, "config write ran");
    assert(armAt < writeAt, "arm precedes the config write");
    assert(setAt > writeAt, "config write precedes config-set");
    assert(written.some((w) => w.specName === "revert"), "revert persisted");
    assert(written.some((w) => w.specName === "config"), "config persisted");
  } finally {
    setDeps(prior);
  }
});

Deno.test("apply is a no-op when the live config already matches", async () => {
  const rendered = await renderAndHash(configArgsSchema.parse(DHCP));
  let armed = false;
  const runner: CommandRunner = async (cmd, args, options = {}) => {
    const command = args.at(-1) ?? "";
    const stdin = options.stdin;
    if (cmd !== "ssh") return { code: 0, stdout: "", stderr: "" };
    if (command.includes("systemd-run")) {
      armed = true;
      return { code: 0, stdout: "", stderr: "" };
    }
    if (command.includes("kea-dhcp4 -t")) {
      return { code: 0, stdout: "", stderr: "" };
    }
    if (command.includes("ip -o route get")) {
      return { code: 0, stdout: "eth9\n", stderr: "" };
    }
    if (command.includes("is-active")) {
      return { code: 0, stdout: "active\n", stderr: "" };
    }
    if (command.includes("mktemp")) {
      const mode = /chmod '(\d+)'/.exec(command)?.[1] ?? "600";
      return {
        code: 0,
        stdout: `${await sha256Hex(text(stdin))} ${mode}\n`,
        stderr: "",
      };
    }
    if (command.includes("MISSING") || command.includes("DIRECTORY")) {
      return { code: 0, stdout: "MISSING\n", stderr: "" };
    }
    if (command.includes("UNIX-CONNECT")) {
      return {
        code: 0,
        stdout: JSON.stringify({ result: 0, arguments: { hash: "kea-hash" } }),
        stderr: "",
      };
    }
    if (command.includes("sha256sum")) {
      return { code: 0, stdout: `${rendered.sha256}\n`, stderr: "" };
    }
    return { code: 0, stdout: "", stderr: "" };
  };
  setDeps(depsFor(runner));
  try {
    const { context } = makeContext();
    const result = await model.methods.apply.execute(
      { ...SSH, ...DHCP },
      context,
    );
    assertEquals(armed, false, "no timer is armed on a no-op");
    assertEquals(
      (result as { result: { revert_token: string } }).result.revert_token,
      "",
    );
  } finally {
    setDeps({ resolveSecret: undefined });
  }
});

Deno.test("apply refuses the management interface without an ack", async () => {
  const runner: CommandRunner = async (cmd, args) => {
    await Promise.resolve();
    const command = args.at(-1) ?? "";
    if (cmd !== "ssh") return { code: 0, stdout: "", stderr: "" };
    if (command.includes("ip -o route get")) {
      return { code: 0, stdout: "eth1\n", stderr: "" };
    }
    return { code: 0, stdout: "", stderr: "" };
  };
  setDeps(depsFor(runner));
  try {
    const { context } = makeContext();
    await assertRejects(
      () => model.methods.apply.execute({ ...SSH, ...DHCP }, context),
      SshConfigError,
      "management",
    );
  } finally {
    setDeps({ resolveSecret: undefined });
  }
});

Deno.test("get persists its observation through vaultService", async () => {
  let sawKeyOnArgv = false;
  const runner: CommandRunner = async (cmd, args, options = {}) => {
    await Promise.resolve();
    const command = args.at(-1) ?? "";
    if (cmd === "ssh-add") {
      assertEquals(text(options.stdin).includes("PLACEHOLDER-KEY"), true);
      return { code: 0, stdout: "", stderr: "" };
    }
    if (cmd === "ssh-agent" && args[0] === "-s") {
      return {
        code: 0,
        stdout:
          "SSH_AUTH_SOCK=/tmp/agent.test; export SSH_AUTH_SOCK;\nSSH_AGENT_PID=42; export SSH_AGENT_PID;\n",
        stderr: "",
      };
    }
    if (cmd !== "ssh") return { code: 0, stdout: "", stderr: "" };
    if (command.includes("PLACEHOLDER-KEY")) sawKeyOnArgv = true;
    if (command.includes("is-active")) {
      return { code: 0, stdout: "active\n", stderr: "" };
    }
    if (command.includes("kea-dhcp4 -V")) {
      return { code: 0, stdout: "Kea 2.4.1\n", stderr: "" };
    }
    if (command.includes("UNIX-CONNECT")) {
      return {
        code: 0,
        stdout: JSON.stringify({ result: 0, arguments: { hash: "kea-hash" } }),
        stderr: "",
      };
    }
    return { code: 0, stdout: "", stderr: "" };
  };
  // Deliberately no resolveSecret: this drives context.vaultService.get and
  // the ssh-agent path with a plain-object context, as swamp passes one.
  setDeps(depsFor(runner, { resolveSecret: undefined }));
  try {
    const { context, written } = makeContext();
    const result = await model.methods.get.execute(SSH, context);
    assertEquals(
      (result as { result: { service_active: boolean } }).result.service_active,
      true,
    );
    assertEquals(written[0].specName, "observation");
    assertEquals(sawKeyOnArgv, false, "the key is never on argv");
  } finally {
    setDeps({ resolveSecret: undefined });
  }
});

Deno.test("leases parses the memfile without writing", async () => {
  const csv =
    "address,hwaddr,client_id,valid_lifetime,expire,subnet_id,fqdn_fwd,fqdn_rev,hostname,state\n" +
    "192.0.2.10,02:00:00:00:00:01,,3600,4000000000,10,0,0,web-1,0\n";
  const runner: CommandRunner = async (cmd, args) => {
    await Promise.resolve();
    const command = args.at(-1) ?? "";
    if (cmd !== "ssh") return { code: 0, stdout: "", stderr: "" };
    if (command.includes("'.2'")) {
      return { code: 1, stdout: "", stderr: "" };
    }
    if (command.includes("'cat'")) {
      return { code: 0, stdout: csv, stderr: "" };
    }
    return { code: 0, stdout: "", stderr: "" };
  };
  setDeps(depsFor(runner));
  try {
    const { context, written } = makeContext();
    const result = await model.methods.leases.execute(
      { ...SSH, lease_api: false },
      context,
    );
    assertEquals((result as { result: { count: number } }).result.count, 1);
    assertEquals(written[0].specName, "leases");
  } finally {
    setDeps({ resolveSecret: undefined });
  }
});

Deno.test("a rejected kea-dhcp4 -t stops before arming anything", async () => {
  let armed = false;
  const runner: CommandRunner = async (cmd, args, options = {}) => {
    const command = args.at(-1) ?? "";
    if (cmd === "ssh-add") return { code: 0, stdout: "", stderr: "" };
    if (cmd === "ssh-agent" && args[0] === "-s") {
      return {
        code: 0,
        stdout:
          "SSH_AUTH_SOCK=/tmp/a; export SSH_AUTH_SOCK;\nSSH_AGENT_PID=1; export SSH_AGENT_PID;\n",
        stderr: "",
      };
    }
    if (cmd !== "ssh") return { code: 0, stdout: "", stderr: "" };
    if (command.includes("systemd-run")) armed = true;
    if (command.includes("kea-dhcp4 -t")) {
      return { code: 1, stdout: "", stderr: "config error\n" };
    }
    if (command.includes("mktemp")) {
      const mode = /chmod '(\d+)'/.exec(command)?.[1] ?? "600";
      return {
        code: 0,
        stdout: `${await sha256Hex(text(options.stdin))} ${mode}\n`,
        stderr: "",
      };
    }
    return { code: 0, stdout: "MISSING\n", stderr: "" };
  };
  setDeps(depsFor(runner));
  try {
    const { context, written } = makeContext();
    await assertRejects(
      () => model.methods.apply.execute({ ...SSH, ...DHCP }, context),
      KeaInputError,
      "rejected",
    );
    assertEquals(armed, false);
    assertEquals(written.length, 0);
  } finally {
    setDeps({ resolveSecret: undefined });
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
  const calls: Call[] = [];
  let armed = false;
  const runner: CommandRunner = async (cmd, args, options = {}) => {
    const command = args.at(-1) ?? "";
    calls.push({ cmd, command, stdin: options.stdin });
    if (cmd !== "ssh") return { code: 0, stdout: "", stderr: "" };
    if (command.includes("kea-dhcp4 -t")) {
      return { code: 0, stdout: "", stderr: "" };
    }
    if (command.includes("systemd-run")) {
      armed = true;
      return { code: 0, stdout: "", stderr: "" };
    }
    if (command.includes("systemctl show")) {
      return { code: 0, stdout: "_kea\n", stderr: "" };
    }
    if (command.includes("is-active")) {
      return { code: 0, stdout: "active\n", stderr: "" };
    }
    if (command.includes("mktemp")) {
      const mode = /chmod '(\d+)'/.exec(command)?.[1] ?? "600";
      return {
        code: 0,
        stdout: `${await sha256Hex(text(options.stdin))} ${mode}\n`,
        stderr: "",
      };
    }
    if (command.includes("MISSING") || command.includes("DIRECTORY")) {
      return { code: 0, stdout: "MISSING\n", stderr: "" };
    }
    if (command.includes("sha256sum") && command.includes("original.conf")) {
      return { code: 0, stdout: `${originalSha}\n`, stderr: "" };
    }
    if (command.includes("sha256sum")) {
      return { code: 0, stdout: `${"1".repeat(64)}\n`, stderr: "" };
    }
    if (command.includes("cat") && command.includes("original.conf")) {
      return { code: 0, stdout: original, stderr: "" };
    }
    if (command.includes("UNIX-CONNECT")) {
      return {
        code: 0,
        stdout: JSON.stringify({ result: 0, arguments: { hash: "kea-hash" } }),
        stderr: "",
      };
    }
    return { code: 0, stdout: "", stderr: "" };
  };
  setDeps(depsFor(runner));
  try {
    const { context, written } = makeContext();
    const result = await model.methods.remove.execute(SSH, context);
    assert(armed, "the revert timer is armed before converging");
    assertEquals(
      (result as { result: { removed: boolean } }).result.removed,
      true,
    );
    const order = calls.map((c) => c.command);
    const armAt = order.findIndex((c) => c.includes("systemd-run"));
    const disableAt = order.findIndex((c) => c.includes("systemctl disable"));
    assert(armAt >= 0, "the arm step ran");
    assert(disableAt > armAt, "the arm precedes disable");
    assert(written.some((w) => w.specName === "revert"), "revert persisted");
    assert(written.some((w) => w.specName === "config"), "config persisted");
  } finally {
    setDeps({ resolveSecret: undefined });
  }
});

Deno.test("rendered goldens pass kea-dhcp4 -t when the tool is present", async () => {
  const probe = new Deno.Command("bash", {
    args: ["-c", "command -v kea-dhcp4 || true"],
  }).outputSync();
  const found = new TextDecoder().decode(probe.stdout).trim() !== "";
  if (!found) {
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
    assertEquals(
      result.code,
      0,
      new TextDecoder().decode(result.stderr),
    );
  } finally {
    await Deno.remove(path);
  }
});
