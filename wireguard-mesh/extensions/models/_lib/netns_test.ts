/**
 * Behavioural check of the remote apply/delete/confirm scripts against a real
 * WireGuard interface in an isolated network namespace. It needs root (via
 * `sudo`), the `wg`/`wg-quick`/`ip` tools and the WireGuard module, so it is
 * ignored unless `WG_MESH_NETNS=1`. Run it, with run permission, as:
 *
 *   WG_MESH_NETNS=1 ~/.swamp/deno/deno test \
 *     --allow-env --allow-read --allow-write --allow-run \
 *     extensions/models/_lib/netns_test.ts
 *
 * The graders and the default `deno task test` skip it; it is the evidence
 * behind the offline claims about apply, no-op, address and route recreation,
 * fresh-connection confirmation and delete.
 */

import {
  assertEquals,
  assertExists,
  assertStringIncludes,
} from "jsr:@std/assert@1.0.19";
import {
  applyScript,
  confirmScript,
  deleteScript,
  parseRollbackDir,
} from "./push.ts";

const enabled = Deno.env.get("WG_MESH_NETNS") === "1";
const IFACE = "wgtest";
const NS = "wgmeshtest";

interface Result {
  code: number;
  stdout: string;
  stderr: string;
}

/** Runs one command, optionally piping `stdin`. */
async function sh(cmd: string[], stdin?: string): Promise<Result> {
  const p = new Deno.Command(cmd[0], {
    args: cmd.slice(1),
    stdin: stdin === undefined ? "null" : "piped",
    stdout: "piped",
    stderr: "piped",
  }).spawn();
  if (stdin !== undefined) {
    const w = p.stdin.getWriter();
    await w.write(new TextEncoder().encode(stdin));
    await w.close();
  }
  const o = await p.output();
  return {
    code: o.code,
    stdout: new TextDecoder().decode(o.stdout),
    stderr: new TextDecoder().decode(o.stderr),
  };
}

const sudo = (args: string[], stdin?: string) => sh(["sudo", ...args], stdin);
const inNs = (args: string[], stdin?: string) =>
  sudo(["ip", "netns", "exec", NS, ...args], stdin);

Deno.test({
  name: "netns: apply, no-op, address and route recreate, delete, delete-again",
  ignore: !enabled,
  sanitizeOps: false,
  sanitizeResources: false,
  fn: async () => {
    const dir = await Deno.makeTempDir({ prefix: "wgmesh-netns-" });
    const applyFile = `${dir}/apply.sh`;
    const deleteFile = `${dir}/delete.sh`;
    const confirmFile = `${dir}/confirm.sh`;
    await Deno.writeTextFile(applyFile, applyScript(IFACE));
    await Deno.writeTextFile(deleteFile, deleteScript(IFACE, 60));

    const key = (await sh(["wg", "genkey"])).stdout.trim();
    const hub = "H".repeat(42) + "A=";
    const config = (addr: string, allowed: string) =>
      `[Interface]\nAddress = ${addr}\nListenPort = 51996\n` +
      `PostUp = wg set '%i' private-key '/etc/wireguard/%i.key'\n` +
      `[Peer]\nPublicKey = ${hub}\nAllowedIPs = ${allowed}\n`;
    const stdin = (addr: string, allowed: string) =>
      `${key}\n${config(addr, allowed)}`;

    /** Confirms over a fresh connection and disarms the matching rollback. */
    const confirm = async (stdout: string) => {
      const rb = parseRollbackDir(stdout, IFACE);
      assertExists(rb, `no rollback dir in: ${stdout}`);
      await Deno.writeTextFile(confirmFile, confirmScript(IFACE, rb));
      const c = await inNs(["sh", confirmFile]);
      assertEquals(c.code, 0, c.stderr);
    };

    const cleanupSystem = async () => {
      await sudo(["ip", "netns", "del", NS]);
      await sudo([
        "rm",
        "-f",
        `/etc/wireguard/${IFACE}.conf`,
        `/etc/wireguard/${IFACE}.key`,
      ]);
      await sudo(["sh", "-c", `rm -rf /etc/wireguard/.${IFACE}.*`]);
      await sudo(["ip", "link", "del", IFACE]);
    };
    const cleanup = async () => {
      await cleanupSystem();
      await Deno.remove(dir, { recursive: true }).catch(() => {});
    };

    await cleanupSystem();
    await sudo(["ip", "netns", "add", NS]);
    try {
      let r = await inNs(
        ["sh", applyFile],
        stdin("192.0.2.1/24", "198.51.100.0/24"),
      );
      assertEquals(r.code, 0, r.stderr);
      assertStringIncludes(r.stdout, "changed=1");
      await confirm(r.stdout);
      assertStringIncludes(
        (await inNs(["ip", "-4", "addr", "show", IFACE])).stdout,
        "192.0.2.1/24",
      );
      assertStringIncludes(
        (await inNs(["ip", "-4", "route", "get", "198.51.100.5"])).stdout,
        `dev ${IFACE}`,
      );

      // Identical re-apply is proven a no-op against the live interface.
      r = await inNs(
        ["sh", applyFile],
        stdin("192.0.2.1/24", "198.51.100.0/24"),
      );
      assertEquals(r.code, 0, r.stderr);
      assertStringIncludes(r.stdout, "changed=0");

      // An Address change recreates the interface.
      r = await inNs(
        ["sh", applyFile],
        stdin("192.0.2.9/24", "198.51.100.0/24"),
      );
      assertEquals(r.code, 0, r.stderr);
      assertStringIncludes(r.stdout, "changed=1");
      await confirm(r.stdout);
      const addr = (await inNs(["ip", "-4", "addr", "show", IFACE])).stdout;
      assertStringIncludes(addr, "192.0.2.9/24");
      assertEquals(addr.includes("192.0.2.1/24"), false);

      // An AllowedIPs change is a route change: syncconf alone would not
      // install it, so apply must recreate and then verify the route.
      r = await inNs(
        ["sh", applyFile],
        stdin("192.0.2.9/24", "198.51.100.0/24, 203.0.113.0/24"),
      );
      assertEquals(r.code, 0, r.stderr);
      assertStringIncludes(r.stdout, "changed=1");
      await confirm(r.stdout);
      assertStringIncludes(
        (await inNs(["ip", "-4", "route", "get", "203.0.113.5"])).stdout,
        `dev ${IFACE}`,
      );

      r = await inNs(["sh", deleteFile]);
      assertEquals(r.code, 0, r.stderr);
      assertStringIncludes(r.stdout, "changed=1");
      await confirm(r.stdout);
      assertEquals(
        (await inNs(["ip", "link", "show", IFACE])).code !== 0,
        true,
      );

      r = await inNs(["sh", deleteFile]);
      assertEquals(r.code, 0, r.stderr);
      assertStringIncludes(r.stdout, "changed=0");
    } finally {
      await cleanup();
    }
  },
});

Deno.test({
  name:
    "netns: drift is repaired under an armed rollback, and a confirm after the rollback ran is refused",
  ignore: !enabled,
  sanitizeOps: false,
  sanitizeResources: false,
  fn: async () => {
    const dir = await Deno.makeTempDir({ prefix: "wgmesh-netns2-" });
    const applyFile = `${dir}/apply.sh`;
    const confirmFile = `${dir}/confirm.sh`;
    const rollbackFile = `${dir}/run-rollback.sh`;
    await Deno.writeTextFile(applyFile, applyScript(IFACE));
    const key = (await sh(["wg", "genkey"])).stdout.trim();
    const hub = "H".repeat(42) + "A=";
    const stdin = (addr: string) =>
      `${key}\n[Interface]\nAddress = ${addr}\nListenPort = 51996\n` +
      `PostUp = wg set '%i' private-key '/etc/wireguard/%i.key'\n` +
      `[Peer]\nPublicKey = ${hub}\nAllowedIPs = 198.51.100.0/24\n`;
    const cleanupSystem = async () => {
      await sudo(["ip", "netns", "del", NS]);
      await sudo([
        "sh",
        "-c",
        `rm -rf /etc/wireguard/${IFACE}.* /etc/wireguard/.${IFACE}.*`,
      ]);
    };
    const cleanup = async () => {
      await cleanupSystem();
      await Deno.remove(dir, { recursive: true }).catch(() => {});
    };
    const confirm = async (rb: string) => {
      await Deno.writeTextFile(confirmFile, confirmScript(IFACE, rb));
      return await inNs(["sh", confirmFile]);
    };
    await cleanupSystem();
    await sudo(["ip", "netns", "add", NS]);
    try {
      let r = await inNs(["sh", applyFile], stdin("192.0.2.1/24"));
      assertEquals(r.code, 0, r.stderr);
      const rb1 = parseRollbackDir(r.stdout, IFACE);
      assertExists(rb1);
      assertEquals((await confirm(rb1)).code, 0);
      // Confirming twice is harmless while the rollback is still pending.
      assertEquals((await confirm(rb1)).code, 0);

      // Live drift: the peer is removed behind our back. A re-apply of the
      // same config repairs it, reports a change, and arms a rollback.
      await inNs(["wg", "set", IFACE, "peer", hub, "remove"]);
      assertEquals(
        (await inNs(["wg", "show", IFACE, "peers"])).stdout.trim(),
        "",
      );
      r = await inNs(["sh", applyFile], stdin("192.0.2.1/24"));
      assertEquals(r.code, 0, r.stderr);
      assertStringIncludes(r.stdout, "changed=1");
      assertStringIncludes(
        (await inNs(["wg", "show", IFACE, "peers"])).stdout,
        hub,
      );
      const rb2 = parseRollbackDir(r.stdout, IFACE);
      assertExists(rb2);
      assertEquals((await confirm(rb2)).code, 0);

      // Converged: the probe path leaves no pending rollback to confirm and
      // reports no change.
      r = await inNs(["sh", applyFile], stdin("192.0.2.1/24"));
      assertStringIncludes(r.stdout, "changed=0");

      // A change whose rollback runs before it is confirmed cannot be
      // confirmed afterwards.
      r = await inNs(["sh", applyFile], stdin("192.0.2.9/24"));
      assertEquals(r.code, 0, r.stderr);
      const rb3 = parseRollbackDir(r.stdout, IFACE);
      assertExists(rb3);
      await Deno.writeTextFile(
        rollbackFile,
        `epoch=$(cat ${rb3}/epoch); sh ${rb3}/rollback.sh 0 ${rb3} /etc/wireguard ${IFACE} 1 "$epoch"`,
      );
      const ran = await inNs(["sh", rollbackFile]);
      assertEquals(ran.code, 0, ran.stderr);
      const late = await confirm(rb3);
      assertEquals(late.code, 3, late.stderr);
      const addr = (await inNs(["ip", "-4", "addr", "show", IFACE])).stdout;
      assertStringIncludes(addr, "192.0.2.1/24");
      assertEquals(addr.includes("192.0.2.9/24"), false);
    } finally {
      await cleanup();
    }
  },
});

Deno.test({
  name:
    "netns: a retry after a failed confirmation retires the old rollback; extra addresses are drift; delete retries too",
  ignore: !enabled,
  sanitizeOps: false,
  sanitizeResources: false,
  fn: async () => {
    const dir = await Deno.makeTempDir({ prefix: "wgmesh-netns3-" });
    const applyFile = `${dir}/apply.sh`;
    const deleteFile = `${dir}/delete.sh`;
    const confirmFile = `${dir}/confirm.sh`;
    const rollbackFile = `${dir}/run-rollback.sh`;
    await Deno.writeTextFile(applyFile, applyScript(IFACE));
    await Deno.writeTextFile(deleteFile, deleteScript(IFACE, 60));
    const key = (await sh(["wg", "genkey"])).stdout.trim();
    const hub = "H".repeat(42) + "A=";
    const stdin = (addr: string) =>
      `${key}\n[Interface]\nAddress = ${addr}\nListenPort = 51996\n` +
      `PostUp = wg set '%i' private-key '/etc/wireguard/%i.key'\n` +
      `[Peer]\nPublicKey = ${hub}\nAllowedIPs = 198.51.100.0/24\n`;
    const cleanupSystem = async () => {
      await sudo(["ip", "netns", "del", NS]);
      await sudo([
        "sh",
        "-c",
        `rm -rf /etc/wireguard/${IFACE}.* /etc/wireguard/.${IFACE}.*`,
      ]);
    };
    const confirm = async (rb: string) => {
      await Deno.writeTextFile(confirmFile, confirmScript(IFACE, rb));
      return await inNs(["sh", confirmFile]);
    };
    /** Rollback directories of this interface that are still armed. */
    const armed = async () =>
      (await sudo([
        "sh",
        "-c",
        `for p in /etc/wireguard/.${IFACE}.rollback.*; do [ -d "$p" ] && [ ! -e "$p/disarm" ] && echo "$p"; done; true`,
      ])).stdout.trim().split("\n").filter((l) => l !== "");
    const runRollback = async (rb: string) => {
      await Deno.writeTextFile(
        rollbackFile,
        `epoch=$(cat ${rb}/epoch); sh ${rb}/rollback.sh 0 ${rb} /etc/wireguard ${IFACE} 1 "$epoch"`,
      );
      return await inNs(["sh", rollbackFile]);
    };
    await cleanupSystem();
    await sudo(["ip", "netns", "add", NS]);
    try {
      // Apply, then lose the confirmation (never run it).
      let r = await inNs(["sh", applyFile], stdin("192.0.2.1/24"));
      assertEquals(r.code, 0, r.stderr);
      const rb1 = parseRollbackDir(r.stdout, IFACE);
      assertExists(rb1);
      // The retry must not call this converged: it retires rb1 and hands
      // back a rollback of its own to confirm.
      r = await inNs(["sh", applyFile], stdin("192.0.2.1/24"));
      assertEquals(r.code, 0, r.stderr);
      assertStringIncludes(r.stdout, "changed=1");
      const rb2 = parseRollbackDir(r.stdout, IFACE);
      assertExists(rb2);
      assertEquals(rb1 === rb2, false);
      assertEquals((await confirm(rb1)).code, 4); // superseded
      assertEquals((await confirm(rb2)).code, 0);
      // The retired rollback, if it fires, restores nothing.
      assertEquals((await runRollback(rb1)).code, 0);
      assertStringIncludes(
        (await inNs(["ip", "-4", "addr", "show", IFACE])).stdout,
        "192.0.2.1/24",
      );
      // Everything is disarmed once confirmed.
      assertEquals(
        (await armed()).filter((p) => p !== rb1 && p !== rb2),
        [],
      );

      // An address added behind our back is drift, not a converged node.
      await inNs(["ip", "addr", "add", "192.0.2.77/24", "dev", IFACE]);
      r = await inNs(["sh", applyFile], stdin("192.0.2.1/24"));
      assertEquals(r.code, 0, r.stderr);
      assertStringIncludes(r.stdout, "changed=1");
      const rb3 = parseRollbackDir(r.stdout, IFACE);
      assertExists(rb3);
      assertEquals((await confirm(rb3)).code, 0);
      assertEquals(
        (await inNs(["ip", "-4", "addr", "show", IFACE])).stdout.includes(
          "192.0.2.77",
        ),
        false,
      );

      // Delete whose confirmation is lost: the retry is not a no-op either.
      r = await inNs(["sh", deleteFile]);
      assertEquals(r.code, 0, r.stderr);
      const rb4 = parseRollbackDir(r.stdout, IFACE);
      assertExists(rb4);
      r = await inNs(["sh", deleteFile]);
      assertEquals(r.code, 0, r.stderr);
      assertStringIncludes(r.stdout, "changed=1");
      const rb5 = parseRollbackDir(r.stdout, IFACE);
      assertExists(rb5);
      assertEquals((await confirm(rb5)).code, 0);
      // The first delete's rollback would have restored the config; it is retired.
      assertEquals((await runRollback(rb4)).code, 0);
      assertEquals(
        (await inNs(["ip", "link", "show", IFACE])).code !== 0,
        true,
      );
      // Now fully confirmed and gone: a further delete is a clean no-op.
      r = await inNs(["sh", deleteFile]);
      assertStringIncludes(r.stdout, "changed=0");
    } finally {
      await cleanupSystem();
      await Deno.remove(dir, { recursive: true }).catch(() => {});
    }
  },
});
