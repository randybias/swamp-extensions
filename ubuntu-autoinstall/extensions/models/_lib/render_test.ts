import { assert, assertEquals } from "jsr:@std/assert@1.0.19";
import {
  buildUserDataDocument,
  cmdlineFor,
  cmdlineForCidata,
  expandRaid1Lvm,
  type LateCommand,
  renderLateCommand,
  renderSeed,
} from "./render.ts";
import { reparseCloudConfig } from "./yaml.ts";
import { validateUserDataObject } from "./validate.ts";
import { USER_DATA_GOLDENS } from "./goldens.ts";
import {
  KEY,
  RAID10_LVM,
  SEED_NETWORKS,
  seedInput,
  STATIC_BOND,
  STORAGE_PROFILES,
} from "./testkit.ts";

for (const [profile, storage] of Object.entries(STORAGE_PROFILES)) {
  for (const [netName, network] of Object.entries(SEED_NETWORKS)) {
    Deno.test(`golden: ${profile} x ${netName}`, async () => {
      const input = seedInput({ storage, network });
      const tree = buildUserDataDocument(input);
      const seed = await renderSeed(input);
      // Byte golden.
      assertEquals(
        seed.user_data,
        USER_DATA_GOLDENS[`${profile}__${netName}`],
      );
      // The tree that produced those bytes passes the full pipeline.
      assertEquals(validateUserDataObject(tree), []);
      const parsed = reparseCloudConfig(seed.user_data);
      assertEquals(parsed.reason, undefined);
      assertEquals(parsed.value, tree);
      const ai = (parsed.value as { autoinstall: Record<string, unknown> })
        .autoinstall;
      assertEquals(ai.version, 1);
      const meta = reparseCloudConfig(seed.meta_data);
      assertEquals(
        (meta.value as Record<string, unknown>)["local-hostname"],
        "web-1",
      );
      assertEquals(seed.tree_sha256.length, 64);
    });
  }
}

Deno.test("the RAID10+LVM fixture is structurally valid", () => {
  const findings = validateUserDataObject(
    buildUserDataDocument(seedInput({ storage: RAID10_LVM })),
  );
  assertEquals(findings, []);
});

Deno.test("the raid1-lvm preset expands to ESPs, an md array, a VG and LVs", () => {
  const actions = expandRaid1Lvm({
    preset: "raid1-lvm",
    disks: ["SERIALA", "SERIALB"],
    vg_name: "vg0",
    lvs: [
      { name: "root", size: "20G", fs: "ext4", mount: "/" },
      { name: "data", size: "50G", fs: "xfs", mount: "/data" },
    ],
  });
  const ids = actions.map((a) => a.id);
  assert(ids.includes("md0") && ids.includes("vg0"));
  assertEquals(
    (actions.find((a) => a.id === "md0") as { devices: string[] }).devices,
    ["disk0-data", "disk1-data"],
  );
  assertEquals(
    actions.filter((a) => a.type === "partition" && a.flag === "boot").length,
    2,
  );
  assertEquals(
    actions.filter((a) => a.type === "disk" && a.grub_device === true).length,
    2,
  );
});

Deno.test("late commands are argv lists, never interpolated strings", () => {
  const argv: LateCommand = {
    argv: ["echo", "$(id)", "; rm -rf /"],
    in_target: true,
  };
  assertEquals(renderLateCommand(argv), [
    "curtin",
    "in-target",
    "--",
    "echo",
    "$(id)",
    "; rm -rf /",
  ]);
  assertEquals(
    renderLateCommand({ shell: "echo hi", shell_ack: true }),
    ["sh", "-c", "echo hi"],
  );
});

Deno.test("the seed is deterministic and its sums are sorted", async () => {
  const a = await renderSeed(seedInput());
  const b = await renderSeed(seedInput());
  assertEquals(a.user_data, b.user_data);
  assertEquals(a.tree_sha256, b.tree_sha256);
  assertEquals(a.files.map((f) => f.name), [
    "user-data",
    "meta-data",
    "vendor-data",
  ]);
  assert(a.user_data.includes(KEY.split(" ")[1]));
});

Deno.test("both command-line forms are correct, including the GRUB escape", () => {
  assertEquals(
    cmdlineFor("https://seed.example.com/bundles/abc123/").kernel_args,
    "autoinstall ds=nocloud-net;s=https://seed.example.com/bundles/abc123/",
  );
  assertEquals(
    cmdlineFor("https://seed.example.com/bundles/abc123/").grub_args,
    "autoinstall ds=nocloud-net\\;s=https://seed.example.com/bundles/abc123/",
  );
  assertEquals(cmdlineForCidata(), "autoinstall");
});

Deno.test("a seed URL with no trailing slash is refused by the renderer", () => {
  let threw = false;
  try {
    cmdlineFor("https://seed.example.com/bundles/abc123");
  } catch {
    threw = true;
  }
  assertEquals(threw, true);
});

Deno.test("object key order does not change the rendered bytes", async () => {
  const a = await renderSeed(
    seedInput({ locale: "en_US.UTF-8", updates: "all" }),
  );
  const b = await renderSeed(
    seedInput({ updates: "all", locale: "en_US.UTF-8" }),
  );
  assertEquals(a.user_data, b.user_data);
});

Deno.test("the network fixture is the static bond used by the goldens", () => {
  assert(STATIC_BOND.bonds.bond0.interfaces.length === 2);
});
