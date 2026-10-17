import {
  assertEquals,
  assertRejects,
  assertThrows,
} from "jsr:@std/assert@1.0.19";
import { type CommandRunner, type SshDeps, type Target } from "./ssh.ts";
import {
  assertArmedBeforeApply,
  executePlan,
  HostOpsError,
  isArmedBeforeApply,
  planApplyBase,
  planCommit,
  planFirewallChange,
  probeState,
  renderJournaldConf,
  renderSysctlConf,
} from "./plans.ts";
import { type FirewallRules, renderRuleset } from "./nftables.ts";
import { HostConfigError } from "./validate.ts";

const TARGET: Target = {
  host: "192.0.2.10",
  port: 22,
  user: "root",
  hostKeyPolicy: "insecure_tofu",
  privateKey:
    "-----BEGIN OPENSSH PRIVATE KEY-----\nZmFrZS1rZXktbWF0ZXJpYWw=\n-----END OPENSSH PRIVATE KEY-----",
  connectTimeoutS: 15,
};

const RULES: FirewallRules = {
  managementCidrs: ["192.0.2.0/24"],
  allowTcp: [443],
  allowUdp: [53],
  defaultPolicy: "drop",
  sshPort: 22,
  allowSshFromAnywhere: false,
};

const KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeKeyMaterialForTests";
const TOKEN = "0".repeat(16);

interface Fake {
  deps: SshDeps;
  commands: string[];
}

/** A transport whose only real work is recording the ssh command strings. */
function fakeTransport(
  respond: (command: string) => { code: number; stdout?: string } = () => ({
    code: 0,
  }),
): Fake {
  const commands: string[] = [];
  const run: CommandRunner = async (cmd, args, _options = {}) => {
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
    const r = respond(command);
    return { code: r.code, stdout: r.stdout ?? "", stderr: "" };
  };
  const deps: SshDeps = {
    run,
    makeTempDir: () => Promise.resolve("/tmp/t"),
    writeFile: () => Promise.resolve(),
    removeDir: () => Promise.resolve(),
    now: () => 1_700_000_000_000,
    sleep: () => Promise.resolve(),
  };
  return { deps, commands };
}

Deno.test("armed-revert: the arm step precedes the apply step in the plan", () => {
  const steps = planFirewallChange({
    token: TOKEN,
    revertAfterS: 300,
    sudo: true,
    rulesText: renderRuleset(RULES),
  });
  assertEquals(isArmedBeforeApply(steps), true);
  assertArmedBeforeApply(steps);
  const kinds = steps.map((s) => s.kind);
  assertEquals(kinds.indexOf("stage") < kinds.indexOf("arm"), true);
  assertEquals(kinds.indexOf("snapshot") < kinds.indexOf("stage"), true);
  assertEquals(kinds.indexOf("arm") < kinds.indexOf("precheck"), true);
  assertEquals(kinds.indexOf("precheck") < kinds.indexOf("apply"), true);
  assertEquals(kinds.indexOf("apply") < kinds.indexOf("verify"), true);
});

Deno.test("armed-revert: the emitted command stream arms before it applies", async () => {
  const f = fakeTransport();
  const steps = planFirewallChange({
    token: TOKEN,
    revertAfterS: 300,
    sudo: true,
    rulesText: renderRuleset(RULES),
  });
  const emitted = await executePlan(f.deps, TARGET, steps);
  assertEquals(
    emitted.map((e) => e.kind).join(",").includes("arm,precheck,apply"),
    true,
  );
  const armAt = f.commands.findIndex((c) => c.includes("systemd-run"));
  const checkAt = f.commands.findIndex((c) =>
    c.includes("'nft' '-c' '-f' '-'")
  );
  const applyAt = f.commands.findIndex((c) =>
    c.includes("'nft' '-f' '-'") && !c.includes("'-c'")
  );
  assertEquals(armAt >= 0, true, "arm emitted");
  assertEquals(checkAt > armAt, true, "pre-check after arm");
  assertEquals(applyAt > checkAt, true, "apply after pre-check");
});

Deno.test("pre-check failure stops the plan before apply", async () => {
  const f = fakeTransport((c) =>
    c.includes("'nft' '-c' '-f' '-'") ? { code: 1 } : { code: 0 }
  );
  const steps = planFirewallChange({
    token: TOKEN,
    revertAfterS: 60,
    sudo: false,
    rulesText: renderRuleset(RULES),
  });
  await assertRejects(
    () => executePlan(f.deps, TARGET, steps),
    HostOpsError,
    "nft syntax check",
  );
  assertEquals(
    f.commands.some((c) => c.includes("'nft' '-f' '-'") && !c.includes("'-c'")),
    false,
  );
});

Deno.test("base plan: caller values are separate argv words, keys on stdin", () => {
  const steps = planApplyBase({
    sudo: true,
    packages: ["curl", "openssh-server"],
    adminUser: "ops",
    authorizedKeys: [KEY],
    sysctl: { "net.ipv4.ip_forward": "1" },
    timezone: "UTC",
  }, [
    "packages",
    "admin_user",
    "authorized_keys",
    "sysctl",
    "journald",
    "timezone",
    "time_sync",
  ]);
  const pkg = steps.find((s) => s.label === "install packages");
  assertEquals(pkg !== undefined, true);
  if (pkg !== undefined) {
    assertEquals(pkg.argv.slice(-2), ["curl", "openssh-server"]);
    assertEquals(pkg.argv[4].includes("curl"), false);
  }
  const keys = steps.find((s) => s.label === "authorize admin keys");
  assertEquals(keys !== undefined, true);
  if (keys !== undefined) {
    assertEquals(JSON.stringify(keys.argv).includes(KEY), false);
    assertEquals(new TextDecoder().decode(keys.stdin).includes(KEY), true);
  }
});

Deno.test("base plan: an injected package stays one literal argv word", () => {
  const evil = "curl; rm -rf /";
  const steps = planApplyBase({
    sudo: false,
    packages: [evil],
    adminUser: "ops",
    authorizedKeys: [],
    sysctl: {},
    timezone: "UTC",
  }, ["packages"]);
  const pkg = steps.find((s) => s.label === "install packages");
  if (pkg === undefined) throw new Error("no package step");
  assertEquals(pkg.argv.includes(evil), true);
  assertEquals(pkg.argv[2].includes(evil), false);
});

Deno.test("base plan: an unchanged re-run emits no steps", () => {
  const input = {
    sudo: true,
    packages: ["curl"],
    adminUser: "ops",
    authorizedKeys: [KEY],
    sysctl: { "net.ipv4.ip_forward": "1" },
    timezone: "UTC",
  };
  assertEquals(planApplyBase(input, []), []);
});

Deno.test("base plan: a cleared managed file is still written", () => {
  const cleared = planApplyBase({
    sudo: true,
    packages: [],
    adminUser: "ops",
    authorizedKeys: [],
    sysctl: {},
    timezone: "UTC",
  }, ["authorized_keys", "sysctl"]);
  const keys = cleared.find((s) => s.label === "authorize admin keys");
  assertEquals(keys !== undefined, true);
  assertEquals(keys?.stdin?.length, 0);
  const sysctl = cleared.find((s) => s.label === "write sysctl drop-in");
  assertEquals(sysctl !== undefined, true);
  assertEquals(
    new TextDecoder().decode(sysctl?.stdin).includes("net.ipv4"),
    false,
  );
});

Deno.test("writeFileStep: same-directory temp, parent dir, atomic mv", () => {
  const step = planStepWrite();
  const script = step.argv[4];
  assertEquals(script.includes('dir=$(dirname "'), true);
  assertEquals(script.includes('install -d -m 0755 "$dir"'), true);
  assertEquals(script.includes('tmp=$(mktemp "'), true);
  assertEquals(script.includes(".XXXXXX"), true);
  assertEquals(script.includes('mv -f "$tmp"'), true);
  assertEquals(script.includes("cmp -s"), true);
});

function planStepWrite() {
  const steps = planApplyBase({
    sudo: true,
    packages: [],
    adminUser: "ops",
    authorizedKeys: [],
    sysctl: { "net.ipv4.ip_forward": "1" },
    timezone: "UTC",
  }, ["sysctl"]);
  const step = steps.find((s) => s.label === "write sysctl drop-in");
  if (step === undefined) throw new Error("no write step");
  return step;
}

Deno.test("base config: deterministic sorted sysctl and a fixed journald drop-in", () => {
  assertEquals(
    renderSysctlConf({ "vm.swappiness": "10", "net.ipv4.ip_forward": "1" }),
    "# Managed by @randybias/server-host. Generated; do not edit.\nnet.ipv4.ip_forward = 1\nvm.swappiness = 10\n",
  );
  assertEquals(renderJournaldConf().includes("[Journal]"), true);
  assertEquals(renderJournaldConf().includes("ForwardToSyslog=no"), true);
});

Deno.test("probe: reads the ruleset sha and timer state without mutating", async () => {
  const f = fakeTransport((c) => {
    if (c.includes("'nft' 'list' 'ruleset'")) {
      return { code: 0, stdout: "table inet server_host {\n}\n" };
    }
    if (c.includes("'systemctl' 'is-active'")) {
      return { code: 0, stdout: "active\n" };
    }
    return { code: 0 };
  });
  const probe = await probeState(f.deps, TARGET, {
    sudo: true,
    token: TOKEN,
  });
  assertEquals(probe.managed_table, true);
  assertEquals(probe.armed, true);
  assertEquals(probe.ruleset_sha256.length, 64);
  assertEquals(probe.managed_sha256.length, 64);
  assertEquals(f.commands.every((c) => !c.includes("nft -f")), true);
});

Deno.test("probe: a failed or truncated ruleset read is an error, not an observation", async () => {
  const failed = fakeTransport((c) =>
    c.includes("'nft' 'list' 'ruleset'") ? { code: 1 } : { code: 0 }
  );
  await assertRejects(
    () => probeState(failed.deps, TARGET, { sudo: true }),
    HostOpsError,
    "nft list ruleset",
  );
  const truncated = fakeTransport((c) => {
    if (c.includes("'nft' 'list' 'ruleset'")) {
      return { code: 0, stdout: "x".repeat(2_000_000) };
    }
    return { code: 0 };
  });
  await assertRejects(
    () => probeState(truncated.deps, TARGET, { sudo: true }),
    HostOpsError,
    "truncated",
  );
});

Deno.test("probe: an unexpected timer-probe exit is an error", async () => {
  const f = fakeTransport((c) => {
    if (c.includes("'nft' 'list' 'ruleset'")) {
      return { code: 0, stdout: "table inet server_host {\n}\n" };
    }
    if (c.includes("'systemctl' 'is-active'")) return { code: 1 };
    return { code: 0 };
  });
  await assertRejects(
    () => probeState(f.deps, TARGET, { sudo: true, token: TOKEN }),
    HostOpsError,
    "timer probe",
  );
});

Deno.test("probe: inactive and unknown timers are simply not armed", async () => {
  for (const code of [3, 4]) {
    const f = fakeTransport((c) => {
      if (c.includes("'nft' 'list' 'ruleset'")) {
        return { code: 0, stdout: "table inet server_host {\n}\n" };
      }
      if (c.includes("'systemctl' 'is-active'")) {
        return { code, stdout: "inactive\n" };
      }
      return { code: 0 };
    });
    const probe = await probeState(f.deps, TARGET, {
      sudo: true,
      token: TOKEN,
    });
    assertEquals(probe.armed, false, String(code));
  }
});

Deno.test("commit plan: a single cleanup step", () => {
  const steps = planCommit(TOKEN, true);
  assertEquals(steps.length, 1);
  assertEquals(steps[0].kind, "cleanup");
  assertThrows(() => planCommit("bad token", true), HostConfigError);
});
