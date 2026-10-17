// Feeds rendered rulesets to a REAL nft: `nft -c` must accept them, and applying
// one twice (as a re-apply does) must leave a table whose own JSON read-back
// matches the rendered rules. Runs in a throwaway container (NFT_CHECK_IMAGE, default `nft-check:local`, built
// from ubuntu:24.04 with the nftables and netbase packages); skipped when
// the container is unavailable. The kernel only needs netlink in its own netns.
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

/**
 * Runs a shell script in the container with the ruleset in `$R` (a mktemp file).
 * Always the container, never the host's own netns: applying the table here
 * would drop the host's traffic.
 */
async function nftSh(script: string, ruleset: string) {
  const body = `R=$(mktemp); cat > "$R"; ${script}`;
  const args = ["run", "--rm", "--cap-add", "NET_ADMIN", "--network", "none"];
  const probe = await run("docker", [...args, IMAGE, "nft", "--version"], "");
  if (!probe || probe.code !== 0) return null;
  return await run(
    "docker",
    [...args.slice(0, 2), "-i", ...args.slice(2), IMAGE, "sh", "-c", body],
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
      const checked = await nftSh('nft -c -f "$R"', text);
      assertEquals(checked?.code, 0, checked?.stderr);
      // Applying twice mimics a re-apply over an existing table.
      const applied = await nftSh(
        'nft -f "$R" && nft -f "$R" && nft -j list table inet server_host',
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
    const r = await nftSh('nft -c -f "$R"', bad);
    assertEquals(r !== null && r.code !== 0, true);
  },
});
