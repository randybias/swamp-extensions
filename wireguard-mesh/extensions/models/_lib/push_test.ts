import {
  assertEquals,
  assertStringIncludes,
  assertThrows,
} from "jsr:@std/assert@1.0.19";
import {
  applyScript,
  confirmScript,
  deleteScript,
  getScript,
  parseKnownHosts,
  parseRollbackDir,
  shQuote,
  sshTransport,
} from "./push.ts";

Deno.test("scripts accept only valid interface names", () => {
  for (const f of [applyScript, getScript]) {
    assertEquals(f("wg0").includes("'wg0'"), true);
    for (const bad of ["", "WG0", "wg0;id", "wg 0", "../x", "a".repeat(16)]) {
      assertThrows(() => f(bad), Error, "Invalid interface");
    }
  }
  for (const bad of ["", "WG0", "wg0;id", "wg 0", "../x", "a".repeat(16)]) {
    assertThrows(() => deleteScript(bad, 120), Error, "Invalid interface");
  }
  assertThrows(() => deleteScript("wg0", 0), Error, "Invalid rollback");
  assertThrows(() => deleteScript("wg0", 1.5), Error, "Invalid rollback");
});

Deno.test("shell-bound values are quoted, never bare", () => {
  assertEquals(applyScript("wg0").includes("i='wg0'"), true);
  assertEquals(deleteScript("wg0", 120).includes("i='wg0'"), true);
  assertEquals(getScript("wg0").includes("wg show 'wg0' dump"), true);
});

Deno.test("apply stages, backs up both files, and restores both on failure", () => {
  const s = applyScript("wg0");
  assertEquals(s.includes("umask 077"), true);
  assertStringIncludes(s, 'mktemp -d "$d/.$i.stage.XXXXXX"');
  // both durable files are backed up before anything is committed
  assertStringIncludes(s, 'cp -p "$d/$i.conf" "$rb/$i.conf"');
  assertStringIncludes(s, 'cp -p "$d/$i.key" "$rb/$i.key"');
  // both are committed as one guarded step, and the restore helper is used
  assertStringIncludes(s, 'mv "$kf" "$d/$i.key" && mv "$cfg" "$d/$i.conf"');
  assertStringIncludes(s, "restore_previous");
  assertEquals(/echo[^\n]*\$key/.test(s), false);
});

Deno.test("apply proves live convergence before reporting a no-op", () => {
  const s = applyScript("wg0");
  assertStringIncludes(s, 'wg show "$i" dump');
  assertStringIncludes(s, 'wg-quick strip "$cfg"');
  assertStringIncludes(s, "addr_ok");
  assertStringIncludes(s, 'echo "changed=0"');
});

Deno.test("apply recreates the interface when the live address does not match", () => {
  const s = applyScript("wg0");
  assertStringIncludes(s, 'wg-quick down "$i"');
  assertStringIncludes(s, 'wg-quick up "$i"');
  assertStringIncludes(s, 'touch "$rb/disarm"');
});

Deno.test("apply and delete take a remote lock when flock is available", () => {
  for (const s of [applyScript("wg0"), deleteScript("wg0", 120)]) {
    assertStringIncludes(s, "flock -w 60 9");
    assertStringIncludes(s, 'exec 9>"$d/.$i.lock"');
  }
});

Deno.test("delete arms a detached rollback that tears down a replacement first", () => {
  const s = deleteScript("wg0", 300);
  assertStringIncludes(s, "ROLLBACK");
  assertStringIncludes(s, "disarm");
  assertStringIncludes(s, "300");
  assertEquals(s.includes("setsid") || s.includes("nohup"), true);
  // the rollback restores live config, not only files
  assertStringIncludes(
    s,
    'wg-quick down "$i" >/dev/null 2>&1 || ip link delete "$i"',
  );
  // success leaves the rollback armed and reports its directory for confirmation
  assertStringIncludes(s, 'echo "rb=$rb"');
  assertEquals(s.includes('touch "$rb/disarm"'), false);
});

Deno.test("the rollback takes the lock and refuses to restore a stale generation", () => {
  const s = deleteScript("wg0", 120);
  // the rollback body acquires the same lock as the mutation
  assertStringIncludes(s, 'exec 9>"$d/.$i.lock"');
  assertStringIncludes(s, "flock -w 60 9");
  // and compares its captured epoch with the current generation
  assertStringIncludes(
    s,
    'if [ "$(cat "$d/.$i.epoch" 2>/dev/null || echo stale)" != "$epoch" ]',
  );
  // the mutation writes a new generation and stamps the backup with it
  assertStringIncludes(s, "epoch=$((epoch + 1))");
  assertStringIncludes(s, 'echo "$epoch" > "$rb/epoch"');
});

Deno.test("apply recreates the interface when routed prefixes change, then checks routes", () => {
  const s = applyScript("wg0");
  assertStringIncludes(s, "route_sig");
  assertStringIncludes(s, 'old_routes=$(route_sig "$d/$i.conf")');
  assertStringIncludes(s, 'new_routes=$(route_sig "$d/$i.conf")');
  assertStringIncludes(s, '[ "$old_routes" = "$new_routes" ]');
  assertStringIncludes(s, "route_check");
  assertStringIncludes(s, 'ip -4 route get "${p%/*}"');
});

Deno.test("confirmScript disarms only the current generation of its own rollback", () => {
  const rb = "/etc/wireguard/.wg0.rollback.AbC123";
  const s = confirmScript("wg0", rb);
  assertStringIncludes(s, `rb='${rb}'`);
  assertStringIncludes(s, 'touch "$rb/disarm"');
  assertStringIncludes(s, '"$(cat "$rb/epoch")" = "$(cat "$d/.$i.epoch")"');
  assertThrows(() => confirmScript("wg0", "/etc/passwd"), Error, "rollback");
  assertThrows(
    () => confirmScript("wg0", "/etc/wireguard/.wg0.rollback;x"),
    Error,
  );
});

Deno.test("parseRollbackDir accepts only this interface's rollback directory", () => {
  const out = "changed=1\nrb=/etc/wireguard/.wg0.rollback.AbC123\n";
  assertEquals(
    parseRollbackDir(out, "wg0"),
    "/etc/wireguard/.wg0.rollback.AbC123",
  );
  assertEquals(parseRollbackDir("changed=1\n", "wg0"), undefined);
  assertEquals(
    parseRollbackDir("rb=/etc/wireguard/.wg9.rollback.AbC\n", "wg0"),
    undefined,
  );
  assertEquals(
    parseRollbackDir("rb=/tmp/.wg0.rollback.AbC\n", "wg0"),
    undefined,
  );
});

Deno.test("parseKnownHosts keeps unique type/key pairs and ignores comments", () => {
  const text = [
    "# comment",
    "192.0.2.1 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEXAMPLE",
    "ssh-rsa AAAAB3NzaC1yc2EAAAAEXAMPLE",
    "192.0.2.1 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEXAMPLE",
    "",
  ].join("\n");
  assertEquals(parseKnownHosts(text), [
    { type: "ssh-ed25519", key: "AAAAC3NzaC1lZDI1NTE5AAAAIEXAMPLE" },
    { type: "ssh-rsa", key: "AAAAB3NzaC1yc2EAAAAEXAMPLE" },
  ]);
});

Deno.test("ssh transport returns the known_hosts it accepted, for TOFU pinning", async () => {
  const path = await Deno.makeTempFile({ prefix: "wgmesh-kh-test-" });
  const spawn = (cmd: string) => {
    if (cmd === "ssh") {
      // Simulate ssh's accept-new appending the accepted key.
      Deno.writeTextFileSync(
        path,
        Deno.readTextFileSync(path) +
          "198.51.100.20 ssh-ed25519 AAAATOFUPINNED\n",
      );
    }
    return Promise.resolve({ code: 0, stdout: "", stderr: "" });
  };
  const t = sshTransport(
    {
      host: "198.51.100.20",
      user: "root",
      port: 22,
      host_key_policy: "accept-new",
      host_keys: [],
    },
    spawn,
    { tempFile: () => Promise.resolve(path) },
  );
  const res = await t("true");
  assertEquals(parseKnownHosts(res.known_hosts ?? ""), [
    { type: "ssh-ed25519", key: "AAAATOFUPINNED" },
  ]);
  assertEquals(
    await Deno.stat(path).then(() => true).catch(() => false),
    false,
  );
});

Deno.test("shQuote survives single quotes in the script", () => {
  assertEquals(shQuote("echo 'a'"), `sh -c 'echo '\\''a'\\'''`);
});
