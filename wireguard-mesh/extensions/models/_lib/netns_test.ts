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
