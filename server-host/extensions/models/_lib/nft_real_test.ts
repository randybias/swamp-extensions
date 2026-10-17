// Feeds rendered rulesets to a REAL nft: `nft -c` must accept them, and applying
// one twice (as a re-apply does) must leave a table whose own JSON read-back
// matches the rendered rules. Runs `nft` directly when it is installed, else in
// a container that has it (NFT_CHECK_IMAGE, default `nft-check:local`, built
// from ubuntu:24.04 with the nftables and netbase packages); skipped when
// neither is available. The kernel only needs netlink access in its own netns.
import { assertEquals } from "jsr:@std/assert@1.0.19";
import {
  assertListingMatches,
  expectedManagedSha256,
  type FirewallRules,
  managedSha256,
  normalizeListing,
  renderRuleset,
} from "./nftables.ts";

const IMAGE = Deno.env.get("NFT_CHECK_IMAGE") ?? "nft-check:local";

async function run(
  cmd: string,
  args: string[],
  stdin: string,
): Promise<{ code: number; stdout: string; stderr: string } | null> {
  try {
    // swamp-quality-ignore deno-command
    const p = new Deno.Command(cmd, {
      args,
      stdin: "piped",
      stdout: "piped",
      stderr: "piped",
    }).spawn();
    const w = p.stdin.getWriter();
    await w.write(new TextEncoder().encode(stdin));
    await w.close();
    const o = await p.output();
    return {
      code: o.code,
      stdout: new TextDecoder().decode(o.stdout),
      stderr: new TextDecoder().decode(o.stderr),
    };
  } catch {
    return null;
  }
}

/** Runs a shell script that reads the ruleset from /tmp/r.nft (stdin). */
async function nftSh(script: string, ruleset: string) {
  const body = `cat > /tmp/r.nft; ${script}`;
  const direct = await run("nft", ["--version"], "");
  if (direct && direct.code === 0 && Deno.uid() === 0) {
    return await run("sh", ["-c", body], ruleset);
  }
  const probe = await run(
    "docker",
    [
      "run",
      "--rm",
      "--cap-add",
      "NET_ADMIN",
      "--network",
      "none",
      IMAGE,
      "nft",
      "--version",
    ],
    "",
  );
  if (!probe || probe.code !== 0) return null;
  return await run(
    "docker",
    [
      "run",
      "--rm",
      "-i",
      "--cap-add",
      "NET_ADMIN",
      "--network",
      "none",
      IMAGE,
      "sh",
      "-c",
      body,
    ],
    ruleset,
  );
}

const available = (await nftSh("true", "")) !== null;

const CASES: Record<string, FirewallRules> = {
  plain: {
    managementCidrs: ["198.51.100.0/24"],
    allowTcp: [443, 80],
    allowUdp: [53],
    defaultPolicy: "drop",
    sshPort: 22,
    allowSshFromAnywhere: false,
  },
  anywhere: {
    managementCidrs: [],
    allowTcp: [],
    allowUdp: [51820],
    defaultPolicy: "drop",
    sshPort: 2222,
    allowSshFromAnywhere: true,
  },
  ipv6: {
    managementCidrs: ["2001:db8::/32", "198.51.100.3/32"],
    allowTcp: [],
    allowUdp: [],
    defaultPolicy: "drop",
    sshPort: 22,
    allowSshFromAnywhere: false,
  },
  trusted: {
    managementCidrs: ["198.51.100.0/24"],
    allowTcp: [4222],
    allowUdp: [],
    defaultPolicy: "drop",
    sshPort: 22,
    allowSshFromAnywhere: false,
    trustedInterfaces: ["kube-bridge", "cali*", "tunl0", "vxlan.calico"],
  },
};

for (const [name, rules] of Object.entries(CASES)) {
  Deno.test({
    name:
      `real nft: ${name} is accepted by nft -c, applies twice, and reads back as rendered`,
    ignore: !available,
    sanitizeOps: false,
    sanitizeResources: false,
    fn: async () => {
      const text = renderRuleset(rules);
      const checked = await nftSh("nft -c -f /tmp/r.nft", text);
      assertEquals(checked?.code, 0, checked?.stderr);
      // Applying twice mimics a re-apply over an existing table.
      const applied = await nftSh(
        "nft -f /tmp/r.nft && nft -f /tmp/r.nft && nft -j list table inet server_host",
        text,
      );
      assertEquals(applied?.code, 0, applied?.stderr);
      assertListingMatches(rules, applied!.stdout);
      assertEquals(
        await managedSha256(normalizeListing(applied!.stdout)),
        await expectedManagedSha256(rules),
      );
    },
  });
}

Deno.test({
  name:
    "real nft: a ruleset with a bad interface name or rule is rejected by nft -c",
  ignore: !available,
  sanitizeOps: false,
  sanitizeResources: false,
  fn: async () => {
    const bad = renderRuleset(CASES.plain).replace(
      "ct state established,related accept",
      "ct state establishd accept",
    );
    const r = await nftSh("nft -c -f /tmp/r.nft", bad);
    assertEquals(r !== null && r.code !== 0, true);
  },
});
