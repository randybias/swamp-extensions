import { assertEquals, assertThrows } from "jsr:@std/assert@1.0.19";
import {
  renderArmScript,
  renderClearFailedScript,
  renderDisarmScript,
  renderMarker,
  renderMarkerReadScript,
  renderRestoreScript,
  restorePath,
  type RevertContext,
  revertDir,
} from "./revert.ts";

const CTX: RevertContext = {
  token: "0000000000000000",
  backend: "netplan",
  bridgeType: "ovs",
  created: ["enp1s0.100", "br0"],
  createdBridges: ["br0"],
  ownedFiles: ["/etc/netplan/90-host-net.yaml"],
  parentMtus: [{ name: "enp1s0", mtu: 1500 }],
};

Deno.test("restore deletes only created devices (bridge first) and never flushes OVS", () => {
  const script = renderRestoreScript(CTX);
  assertEquals(
    script.includes(
      `for dev in 'br0' 'enp1s0.100'; do ip link delete dev "$dev"`,
    ),
    true,
  );
  assertEquals(script.includes("ovs-vsctl --if-exists del-br"), true);
  assertEquals(script.includes("ovsdb-client"), false);
  assertEquals(script.includes("ip link delete dev 'enp1s0'"), false);
  // Restores the parent MTU and only the owned file.
  assertEquals(script.includes("ip link set dev 'enp1s0' mtu 1500"), true);
  assertEquals(script.includes('while IFS="$(printf'), true);
  assertEquals(script.includes("$DIR/owned.txt"), true);
  assertEquals(script.includes("$DIR/owned.txt"), true);
});

Deno.test("restore is token-guarded, fail-closed and never reboots", () => {
  const script = renderRestoreScript(CTX);
  assertEquals(script.includes("read cur _ <"), true);
  assertEquals(script.includes('rm -rf "$DIR"'), true);
  assertEquals(script.includes("trap 'RESULT=fail; write_result' EXIT"), true);
  // The trap is installed only once the restore is really running.
  const trap = script.indexOf("trap 'RESULT=fail");
  assertEquals(trap > script.indexOf("exit 64"), true);
  assertEquals(trap > script.indexOf("flock -w 30"), true);
  assertEquals(trap > script.indexOf('if [ "$cur" != "$TOKEN" ]'), true);
  assertEquals(script.includes("write_result"), true);
  assertEquals(script.includes("systemctl reboot"), false);
  assertEquals(script.includes("shutdown -r"), false);
  // The default-route check must require a non-empty route.
  assertEquals(script.includes('. "$DIR/checks.sh"'), true);
  assertEquals(script.includes('[ "$CHECK" = pass ] || CHECK=fail'), true);
  // The apply exit status is advisory: captured, logged, never fatal.
  assertEquals(script.includes("netplan apply || applyrc=$?"), true);
  assertEquals(script.includes("logger -t host-net"), true);
  assertEquals(script.includes("RESULT=$CHECK"), true);
  assertEquals(/^netplan apply$/m.test(script), false);
});

Deno.test("the clear script gates on a fail marker and passing checks, then stops the leftover timer", () => {
  const script = renderClearFailedScript();
  assertEquals(script.includes('"result":"fail"'), true);
  assertEquals(script.includes("systemctl stop"), true);
  assertEquals(script.includes('CHECK" != pass'), true);
  assertEquals(
    script.indexOf('CHECK" != pass') < script.indexOf("rm -f"),
    true,
  );
});

Deno.test("restore exits non-zero when invoked with the wrong token", () => {
  const script = renderRestoreScript(CTX);
  assertEquals(script.includes('[ "${1-}" = "$TOKEN" ]'), true);
  assertEquals(script.includes("exit 64"), true);
});

Deno.test("arm script creates state, snapshots owned files, writes the per-token restore and arms", () => {
  const script = renderArmScript(CTX, {
    revertAfterS: 300,
    armedSha256: "a".repeat(64),
    contentSha256: "b".repeat(64),
    operation: "apply",
  });
  assertEquals(script.includes('mkdir -p "/var/lib/host-net"'), true);
  assertEquals(script.includes("flock -w 30 9"), true);
  assertEquals(script.includes("systemd-run"), true);
  assertEquals(script.includes(restorePath(CTX.token)), true);
  assertEquals(script.includes("HOST_NET_RESTORE"), true);
  assertEquals(script.includes("exit 76"), true);
  assertEquals(script.includes("/etc/netplan"), true);
  // Regression: the shellQuote'd restore path must be bare, not double-wrapped.
  assertEquals(script.includes("\"'/var/lib/host-net"), false);
});

Deno.test("arm refuses an invalid sha and honours the token check", () => {
  assertThrows(
    () =>
      renderArmScript(CTX, {
        revertAfterS: 300,
        armedSha256: "short",
        contentSha256: "b".repeat(64),
        operation: "apply",
      }),
    Error,
  );
  assertThrows(() => revertDir("../etc"), Error);
});

Deno.test("disarm requires an active timer for commit and is tolerant for abandon", () => {
  const commit = renderDisarmScript(CTX.token, true);
  assertEquals(commit.includes("state=$(systemctl is-active"), true);
  assertEquals(commit.includes("exit 1"), true);
  assertEquals(
    commit.includes(`systemctl stop "host-net-revert-${CTX.token}.service"`),
    true,
  );
  const abandon = renderDisarmScript(CTX.token, false);
  assertEquals(abandon.includes("exit 1"), false);
  assertEquals(abandon.includes("2>/dev/null || true"), true);
});

Deno.test("marker round-trips; the read script only cats the current marker", () => {
  const marker = {
    token: CTX.token,
    expires_at: 2,
    armed_sha256: "a".repeat(64),
    content_sha256: "b".repeat(64),
    operation: "apply",
    created: CTX.created,
    result: "pending" as const,
    fired_at: null,
  };
  assertEquals(JSON.parse(renderMarker(marker)).token, CTX.token);
  assertEquals(renderMarkerReadScript().includes("cat"), true);
});

Deno.test("the arm script records the path actually used and refuses if it does not pass its own checks", () => {
  const script = renderArmScript(CTX, {
    revertAfterS: 300,
    armedSha256: "a".repeat(64),
    contentSha256: "b".repeat(64),
    operation: "apply",
  });
  assertEquals(
    script.includes('ip -j route get "$peer" from "$local_ip"'),
    true,
  );
  assertEquals(script.includes("exit 77"), true);
  assertEquals(script.includes("linkdown"), true);
  assertEquals(script.includes("prefixlen"), true);
  // The checks run before the timer is armed and before current is written.
  assertEquals(
    script.indexOf("its own checks") < script.indexOf("systemd-run"),
    true,
  );
});
