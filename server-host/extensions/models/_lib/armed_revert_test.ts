import { assertEquals, assertThrows } from "jsr:@std/assert@1.0.19";
import {
  isTimerActive,
  renderArmArgv,
  renderCommitArgv,
  renderProbeArgv,
  renderRevertScript,
  renderSnapshotArgv,
  scriptPath,
  snapshotPath,
  TOKEN_RE,
  unitName,
  withSudo,
} from "./armed_revert.ts";
import { HostConfigError } from "./validate.ts";

const TOKEN = "0".repeat(16);

Deno.test("token: paths and units reject anything but lowercase hex", () => {
  assertEquals(TOKEN_RE.test(TOKEN), true);
  assertEquals(snapshotPath(TOKEN), `/var/lib/server-host/revert-${TOKEN}.nft`);
  assertEquals(scriptPath(TOKEN), `/var/lib/server-host/revert-${TOKEN}.sh`);
  assertEquals(unitName(TOKEN), `server-host-revert-${TOKEN}`);
  for (
    const bad of [
      "../../etc/passwd",
      "ABC",
      "0123",
      "x".repeat(16),
      `${TOKEN};id`,
    ]
  ) {
    assertThrows(() => snapshotPath(bad), HostConfigError);
  }
});

Deno.test("withSudo: prefixes only when asked", () => {
  assertEquals(withSudo(true, ["nft", "-f", "-"]), [
    "sudo",
    "-n",
    "nft",
    "-f",
    "-",
  ]);
  assertEquals(withSudo(false, ["nft", "-f", "-"]), ["nft", "-f", "-"]);
});

Deno.test("snapshot: created before the change and rooted in the state dir", () => {
  const argv = renderSnapshotArgv(TOKEN, true);
  assertEquals(argv.slice(0, 2), ["sudo", "-n"]);
  assertEquals(argv[2], "sh");
  assertEquals(argv[3], "-c");
  assertEquals(argv[4].includes('mkdir -p "/var/lib/server-host"'), true);
  assertEquals(
    argv[4].includes(
      `nft list ruleset > "/var/lib/server-host/revert-${TOKEN}.nft"`,
    ),
    true,
  );
});

Deno.test("revert script: locked, atomic, and abort-safe", () => {
  const script = renderRevertScript(TOKEN);
  assertEquals(script.includes("echo 'flush ruleset'"), true);
  assertEquals(script.includes("| nft -f -"), true);
  assertEquals(script.includes("nft flush ruleset\n"), false);
  assertEquals(
    script.includes('exec 9>"/var/lib/server-host/revert.lock"'),
    true,
  );
  assertEquals(script.includes("flock 9"), true);
  assertEquals(
    script.includes('if [ ! -f "$snap" ]; then'),
    true,
  );
  assertEquals(
    script.includes(`cat "$snap"`),
    true,
  );
  assertEquals(
    script.includes('rm -f "$snap"'),
    true,
  );
  assertEquals(
    script.includes(`rm -f "/var/lib/server-host/revert-${TOKEN}.sh"`),
    true,
  );
});

Deno.test("arm: a transient on-active timer that survives the session", () => {
  const argv = renderArmArgv(TOKEN, 300, true);
  assertEquals(argv.slice(0, 2), ["sudo", "-n"]);
  assertEquals(argv[2], "systemd-run");
  assertEquals(argv.includes("--on-active=300s"), true);
  assertEquals(argv.includes(`--unit=server-host-revert-${TOKEN}`), true);
  assertEquals(argv.includes("--collect"), true);
  assertEquals(argv.at(-1), scriptPath(TOKEN));
  for (const bad of [59, 1801, 0, -1, 1.5]) {
    assertThrows(() => renderArmArgv(TOKEN, bad, false), HostConfigError);
  }
});

Deno.test("commit: locked, fails unless the timer is active, then cleanup", () => {
  const argv = renderCommitArgv(TOKEN, false);
  assertEquals(argv[0], "sh");
  assertEquals(argv[1], "-c");
  const script = argv[2];
  assertEquals(script.startsWith("set -e"), true);
  assertEquals(
    script.includes('exec 9>"/var/lib/server-host/revert.lock"'),
    true,
  );
  assertEquals(script.includes("flock 9"), true);
  assertEquals(script.includes('if [ "$state" != "active" ]; then'), true);
  assertEquals(script.includes("exit 1"), true);
  assertEquals(
    script.includes(`systemctl stop "$unit.timer"`),
    true,
  );
  assertEquals(
    script.includes(
      `rm -f '/var/lib/server-host/revert-${TOKEN}.nft' '/var/lib/server-host/revert-${TOKEN}.sh'`,
    ),
    true,
  );
  // The stop itself must not be tolerant of failure.
  const stopLine = script.split("\n").find((l) =>
    l.startsWith("systemctl stop") && l.includes(".timer")
  );
  assertEquals(stopLine?.includes("|| true"), false);
});

Deno.test("probe: reads the timer state without changing it", () => {
  assertEquals(renderProbeArgv(TOKEN, true), [
    "sudo",
    "-n",
    "systemctl",
    "is-active",
    `server-host-revert-${TOKEN}.timer`,
  ]);
  assertEquals(isTimerActive("active\n"), true);
  assertEquals(isTimerActive("inactive\n"), false);
  assertEquals(isTimerActive(""), false);
});
