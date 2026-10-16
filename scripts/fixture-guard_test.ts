import { assertEquals } from "jsr:@std/assert@1.0.13";
import { fixtureFiles, guard } from "./fixture-guard.ts";

async function ext(files: Record<string, string>): Promise<string> {
  const dir = await Deno.makeTempDir();
  for (const [p, c] of Object.entries(files)) {
    await Deno.mkdir(`${dir}/${p}`.replace(/\/[^/]+$/, ""), {
      recursive: true,
    });
    await Deno.writeTextFile(`${dir}/${p}`, c);
  }
  return dir;
}

Deno.test("selects tests and fixture dirs, skips .swamp and source", async () => {
  const d = await ext({
    "extensions/models/a.ts": "10.0.0.1",
    "extensions/models/a_test.ts": "",
    "extensions/models/fixtures/x.json": "",
    "testdata/y.txt": "",
    ".swamp/data/z_test.ts": "",
  });
  const rel = (await fixtureFiles(d)).map((f) => f.slice(d.length + 1)).sort();
  assertEquals(rel, [
    "extensions/models/a_test.ts",
    "extensions/models/fixtures/x.json",
    "testdata/y.txt",
  ]);
});

Deno.test("flags a private address in a test, honours leak-allow", async () => {
  const d = await ext({
    "extensions/models/a_test.ts": 'const h = "10.9.8.7";\nconst ok = "192.0.2.1";\n' +
      'const v = "1.2.3.4"; // leak-allow(upstream version string)\n',
  });
  assertEquals(await guard(d), ["extensions/models/a_test.ts:1 ipv4 10.9.8.7"]);
});

Deno.test("flags a real MAC in a fixture file", async () => {
  const d = await ext({
    "fixtures/lsblk.json": '{"mac": "3c:22:fb:01:02:03"}',
  });
  assertEquals(await guard(d), ["fixtures/lsblk.json:1 mac 3c:22:fb:01:02:03"]);
});

Deno.test("clean extension yields no findings", async () => {
  const d = await ext({
    "extensions/models/a_test.ts": 'const h = "198.51.100.4";',
  });
  assertEquals(await guard(d), []);
});

Deno.test("covers other test layouts and symlinked fixture dirs", async () => {
  const d = await ext({
    "src/a.test.ts": "",
    "__snapshots__/a.snap": "",
    "tests/helper.ts": "",
    "Fixture/x.json": "",
    "real/y.json": '{"ip": "8.8.4.4"}',
  });
  await Deno.symlink(`${d}/real`, `${d}/fixtures`);
  const rel = (await fixtureFiles(d)).map((f) => f.slice(d.length + 1)).sort();
  assertEquals(rel, [
    "Fixture/x.json",
    "__snapshots__/a.snap",
    "fixtures/y.json",
    "src/a.test.ts",
    "tests/helper.ts",
  ]);
  assertEquals(await guard(d), ["fixtures/y.json:1 ipv4 8.8.4.4"]);
});
