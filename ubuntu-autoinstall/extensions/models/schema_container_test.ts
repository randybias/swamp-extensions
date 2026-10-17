import { assert, assertEquals } from "jsr:@std/assert@1.0.19";
import { stringify } from "npm:yaml@2.9.1";
import {
  type AutoinstallInput,
  buildUserDataDocument,
  renderSeed,
} from "./_lib/render.ts";
import { seedInput, STATIC_BOND } from "./_lib/testkit.ts";

/**
 * Container validation of a rendered seed with the tools that ship on Ubuntu.
 *
 * Gated behind `AUTOINSTALL_CONTAINER=1` so the normal offline gate never
 * starts a container. Runs `cloud-init schema --config-file` on the rendered
 * user-data and `netplan generate` on the rendered network, in `ubuntu:24.04`.
 */

/** Runs a shell command in the pinned image, returning its combined output. */
async function inUbuntu(
  script: string,
  mounts: string[],
): Promise<{ code: number; out: string }> {
  const args = [
    "run",
    "--rm",
    ...mounts.flatMap((m) => ["-v", m]),
    "ubuntu:24.04",
    "bash",
    "-lc",
    script,
  ];
  const out = await new Deno.Command("docker", {
    args,
    stdout: "piped",
    stderr: "piped",
  }).output();
  const dec = new TextDecoder();
  return {
    code: out.code,
    out: dec.decode(out.stdout) + dec.decode(out.stderr),
  };
}

Deno.test({
  name: "cloud-init and netplan accept a rendered seed in ubuntu:24.04",
  ignore: Deno.env.get("AUTOINSTALL_CONTAINER") !== "1",
  fn: async () => {
    const input: AutoinstallInput = seedInput({
      storage: { layout: "lvm", sizing_policy: "scaled" },
      network: STATIC_BOND,
    });
    const seed = await renderSeed(input);
    const dir = await Deno.makeTempDir({ prefix: "autoinstall-" });
    const userData = `${dir}/user-data`;
    await Deno.writeTextFile(userData, seed.user_data);
    const networkFile = `${dir}/network.yaml`;
    const network = (buildUserDataDocument(input).autoinstall as {
      network: unknown;
    }).network;
    await Deno.writeTextFile(networkFile, stringify({ network }));
    try {
      const setup =
        "export DEBIAN_FRONTEND=noninteractive; apt-get update -qq; apt-get install -y cloud-init netplan.io";
      const schema = await inUbuntu(
        `${setup} >/dev/null 2>&1; cloud-init schema --config-file /ud.yaml`,
        [`${userData}:/ud.yaml:ro`],
      );
      assertEquals(schema.code, 0, schema.out);
      assert(schema.out.includes("Valid schema"));
      const netplan = await inUbuntu(
        `${setup} >/dev/null 2>&1; command -v netplan >/dev/null || { echo MISSING_NETPLAN; exit 3; }; mkdir -p /etc/netplan && cp /net.yaml /etc/netplan/99-autoinstall.yaml && netplan generate 2>&1`,
        [`${networkFile}:/net.yaml:ro`],
      );
      assert(!netplan.out.includes("MISSING_NETPLAN"), netplan.out);
      assert(!netplan.out.includes("Error in network definition"), netplan.out);
      assertEquals(netplan.code, 0, netplan.out);
    } finally {
      await Deno.remove(dir, { recursive: true }).catch(() => {});
    }
  },
});
