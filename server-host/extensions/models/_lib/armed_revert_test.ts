import { assertEquals, assertThrows } from "jsr:@std/assert@1.0.19";
import {
  armCall,
  commitCall,
  CURRENT_PATH,
  disarmCall,
  guardedApplyCall,
  isTimerActive,
  markerCall,
  parseMarker,
  probeCall,
  renderRevertScript,
  scriptPath,
  snapshotPath,
  TOKEN_RE,
  unitName,
} from "./armed_revert.ts";
import { renderRemote, renderScript, withSudo } from "./remote.ts";
import { HostConfigError } from "./validate.ts";

const TOKEN = "0".repeat(16);
const SHA = "c".repeat(64);

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

Deno.test("revert script: locked, atomic, and abort-safe", () => {
  const script = renderRevertScript(TOKEN);
  assertEquals(script.includes("echo 'add table inet server_host'"), true);
  assertEquals(script.includes("echo 'delete table inet server_host'"), true);
  assertEquals(script.includes("destroy"), false);
  // Only the managed table is ever restored: never the whole ruleset.
  assertEquals(script.includes("flush ruleset"), false);
  assertEquals(script.includes("| nft -f -"), true);
  assertEquals(script.includes("nft flush ruleset\n"), false);
  assertEquals(
    script.includes('exec 9>"/var/lib/server-host/revert.lock"'),
    true,
  );
  assertEquals(script.includes("flock -w 120 9"), true);
  assertEquals(
    script.includes('[ ! -f "$snap" ]'),
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
    script.includes(`"/var/lib/server-host/revert-${TOKEN}.sh"`),
    true,
  );
});

Deno.test("revert script: restores only while it is still the current revert", () => {
  const script = renderRevertScript(TOKEN);
  assertEquals(script.includes(`if [ "$ctok" != '${TOKEN}' ]`), true);
  assertEquals(script.includes(CURRENT_PATH), true);
  // A superseded restore exits without touching the ruleset.
  const guard = script.indexOf(`"$ctok" != '${TOKEN}'`);
  assertEquals(guard > 0 && guard < script.indexOf("nft -f -"), true);
  // It holds the lock before reading the marker.
  assertEquals(script.indexOf("flock -w") < guard, true);
});

Deno.test("arm: under the host lock, snapshots, records the marker, then starts the timer", () => {
  const call = armCall(TOKEN, 300, true, SHA);
  const { argv, stdin } = renderRemote(call);
  assertEquals(argv, ["sudo", "-n", "sh", "-s"]);
  const s = renderScript(call);
  assertEquals(s.indexOf("flock -w") > 0, true);
  const snap = s.indexOf(
    `nft list table inet server_host > "$snap"`,
  );
  const mark = s.indexOf(`'${TOKEN}'`, s.indexOf("printf"));
  const run = s.indexOf("systemd-run");
  assertEquals(s.indexOf("flock -w") < snap, true);
  assertEquals(snap < mark && mark < run, true);
  assertEquals(s.includes("--on-active=300s"), true);
  assertEquals(s.includes(`--unit=server-host-revert-${TOKEN}`), true);
  assertEquals(s.includes("--collect"), true);
  assertEquals(s.includes(`'${scriptPath(TOKEN)}'`), true);
  // A failed timer start removes the marker and the snapshot it just wrote.
  assertEquals(
    s.includes(`rm -f "$cur" "/var/lib/server-host/revert-${TOKEN}.nft"`),
    true,
  );
  // The script travels on stdin, bounded by a remote deadline.
  assertEquals(stdin.startsWith("timeout -k 5 60 sh -c "), true);
  assertEquals(stdin.endsWith("; exit $?"), true);
  for (const bad of [59, 1801, 0, -1, 1.5]) {
    assertThrows(() => armCall(TOKEN, bad, false, SHA), HostConfigError);
  }
});

Deno.test("commit: locked, fails unless the timer is active, then cleanup", () => {
  const call = commitCall(TOKEN, false);
  assertEquals(renderRemote(call).argv, ["sh", "-s"]);
  const script = renderScript(call);
  assertEquals(script.startsWith("set -eu"), true);
  assertEquals(
    script.includes("exec 9>'/var/lib/server-host/revert.lock'"),
    true,
  );
  assertEquals(script.includes("flock -w 20 9"), true);
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
  const call = probeCall(TOKEN, true);
  assertEquals(renderRemote(call).argv, ["sudo", "-n", "sh", "-s"]);
  assertEquals(
    call.script,
    `systemctl is-active 'server-host-revert-${TOKEN}.timer'\n`,
  );
  assertEquals(isTimerActive("active\n"), true);
  assertEquals(isTimerActive("inactive\n"), false);
  assertEquals(isTimerActive(""), false);
});

Deno.test("arm: the table listing's exit status is checked on its own, not through a pipe", () => {
  const s = armCall(TOKEN, 300, false, SHA).script;
  assertEquals(s.includes("tables=$(nft list tables)"), true);
  assertEquals(s.includes("nft list tables |"), false);
  assertEquals(
    s.indexOf("tables=$(nft list tables)") < s.indexOf("systemd-run"),
    true,
  );
});

Deno.test("arm: refuses (75) while an earlier revert's timer OR service is busy, or its files remain", () => {
  const s = armCall(TOKEN, 300, false, SHA).script;
  assertEquals(s.includes('busy "$ou.timer" || busy "$ou.service"'), true);
  assertEquals(s.includes("exit 75"), true);
  // "Inactive" alone is not enough: artifacts within the grace window still block.
  assertEquals(
    s.includes('revert-$otok.nft" ] && [ "$(date +%s)" -lt $((oexp + 120))'),
    true,
  );
  // Leftovers are cleared only after both checks passed.
  assertEquals(
    s.indexOf("exit 75") <
      s.indexOf('rm -f "/var/lib/server-host/revert-$otok.nft"'),
    true,
  );
  for (const state of ["active", "activating", "deactivating"]) {
    assertEquals(s.includes(state), true, state);
  }
});

Deno.test("guarded apply: locked, and refused unless this revert still guards the change", () => {
  const rules = new TextEncoder().encode("table inet server_host\n");
  const call = guardedApplyCall(TOKEN, true, rules);
  assertEquals(renderRemote(call).argv, ["sudo", "-n", "sh", "-s"]);
  const s = renderScript(call);
  const checks = [
    "flock -w 10 9",
    `[ "$ctok" = '${TOKEN}' ] || exit 70`,
    `revert-${TOKEN}.nft" ] || exit 71`,
    `"$cexp" ] || exit 72`,
    `.timer' || true)" = active ] || exit 73`,
    "bw_data | nft -f -",
  ].map((c) => s.indexOf(c));
  assertEquals(checks.every((i) => i >= 0), true, JSON.stringify(checks));
  assertEquals([...checks].sort((a, b) => a - b), checks);
  // The ruleset is data, not shell text, and the apply is bounded under the
  // shortest revert.
  assertEquals(s.includes("add table"), false);
  assertEquals(call.deadlineS < 60, true);
});

Deno.test("disarm: tolerant and idempotent; commit stays strict", () => {
  const d = disarmCall(TOKEN, false).script;
  const c = commitCall(TOKEN, false).script;
  assertEquals(d.includes('"$unit.timer" 2>/dev/null || true'), true);
  assertEquals(d.includes("exit 1"), false);
  assertEquals(c.includes("exit 1"), true);
  for (const x of [d, c]) {
    assertEquals(x.includes(`rm -f "${CURRENT_PATH}"`), true);
    assertEquals(x.includes(`'${TOKEN}'`), true);
  }
  for (const call of [disarmCall(TOKEN, false), commitCall(TOKEN, false)]) {
    assertEquals(renderScript(call).includes("flock -w 20 9"), true);
  }
});

Deno.test("marker: read-only call and strict parsing", () => {
  assertEquals(renderRemote(markerCall(false)).argv, ["sh", "-s"]);
  assertEquals(parseMarker(`${TOKEN} 1700000300\n`), {
    token: TOKEN,
    expires_at_s: 1700000300,
  });
  for (const bad of ["", "garbage", `${TOKEN}`, `../x 5`, `${TOKEN} 5; id`]) {
    assertEquals(parseMarker(bad), null, bad);
  }
});
