import { assert, assertEquals } from "jsr:@std/assert@1.0.19";
import AjvModule from "npm:ajv@8.17.1";
import addFormatsModule from "npm:ajv-formats@3.0.1";
import { buildUserDataDocument, type StorageInput } from "./_lib/render.ts";
import { seedInput } from "./_lib/testkit.ts";

/**
 * Dev-only cross-check against subiquity's own autoinstall schema, which is
 * AGPL-3.0 and deliberately not vendored. Gated behind
 * `AUTOINSTALL_SUBIQUITY=1`; the schema is downloaded into a temp dir at test
 * time and never committed.
 */

const SCHEMA_URL =
  "https://raw.githubusercontent.com/canonical/subiquity/24.04.5/autoinstall-schema.json";

type AjvInstance = {
  compile(schema: object): ((data: unknown) => boolean) & { errors?: unknown };
};

const Ajv = AjvModule as unknown as new (
  opts?: Record<string, unknown>,
) => AjvInstance;
const addFormats = addFormatsModule as unknown as (ajv: AjvInstance) => void;

const PROFILES: StorageInput[] = [
  { layout: "lvm", sizing_policy: "scaled" },
  { layout: "direct", match: { size: "largest" } },
  {
    preset: "raid1-lvm",
    disks: ["SERIALA", "SERIALB"],
    vg_name: "vg0",
    lvs: [{ name: "root", size: "20G", fs: "ext4", mount: "/" }],
  },
];

Deno.test({
  name: "the rendered autoinstall validates against subiquity's own schema",
  ignore: Deno.env.get("AUTOINSTALL_SUBIQUITY") !== "1",
  fn: async () => {
    const response = await fetch(SCHEMA_URL);
    assertEquals(response.status, 200);
    const dir = await Deno.makeTempDir({ prefix: "subiquity-" });
    const path = `${dir}/autoinstall-schema.json`;
    await Deno.writeTextFile(path, await response.text());
    try {
      const schema = JSON.parse(await Deno.readTextFile(path)) as object;
      const ajv = new Ajv({ strict: false, allErrors: true });
      addFormats(ajv);
      const validate = ajv.compile(schema);
      for (const storage of PROFILES) {
        const doc = buildUserDataDocument(seedInput({ storage })).autoinstall;
        assert(validate(doc), JSON.stringify(validate.errors));
      }
    } finally {
      await Deno.remove(dir, { recursive: true });
    }
  },
});
