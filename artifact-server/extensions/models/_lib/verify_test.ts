import { assertEquals } from "jsr:@std/assert@1.0.19";
import { fetchScript } from "./fetch.ts";
import { parseLayout } from "./observe.ts";
import { parseVerifyOutput, verifyScript } from "./verify.ts";

const HASH = "a".repeat(64);
const OTHER = "b".repeat(64);
const TREE = "c".repeat(64);

Deno.test("parseVerifyOutput marks a matching blob ok", () => {
  const recorded = new Map([[`sha256/${HASH}/a`, HASH]]);
  const result = parseVerifyOutput(
    `BLOB\tsha256/${HASH}/a\t${HASH}\nBUNDLE\t${TREE}\t${TREE}\n`,
    recorded,
  );
  assertEquals(result.ok, [`sha256/${HASH}/a`, `bundles/${TREE}`]);
  assertEquals(result.corrupt, []);
  assertEquals([...result.seen], [`sha256/${HASH}/a`]);
});

Deno.test("parseVerifyOutput flags a tampered blob against the path hash", () => {
  const result = parseVerifyOutput(
    `BLOB\tsha256/${HASH}/a\t${OTHER}\n`,
    new Map(),
  );
  assertEquals(result.corrupt, [{
    path: `sha256/${HASH}/a`,
    expected: HASH,
    actual: OTHER,
  }]);
});

Deno.test("parseVerifyOutput flags a SHA256SUMS value that disagrees with the path", () => {
  const result = parseVerifyOutput(
    `BLOB\tsha256/${HASH}/a\t${HASH}\n`,
    new Map([[`sha256/${HASH}/a`, OTHER]]),
  );
  assertEquals(result.corrupt[0].expected, OTHER);
});

Deno.test("parseVerifyOutput flags a bundle whose tree hash changed", () => {
  const result = parseVerifyOutput(`BUNDLE\t${TREE}\t${OTHER}\n`, new Map());
  assertEquals(result.corrupt, [{
    path: `bundles/${TREE}`,
    expected: TREE,
    actual: OTHER,
  }]);
});

Deno.test("parseLayout accepts valid objects and drops an unsafe name", () => {
  const layout = parseLayout(
    [
      "##VERSION",
      "1",
      "##SUMS",
      `${HASH}  sha256/${HASH}/a`,
      "##REFS",
      `stable\tblob  ${HASH}`,
      "##BLOBS",
      `${HASH}/a\t3\t1.5`,
      `${HASH}/x\nname\t3\t1.5`,
      `${HASH}/a b\t3\t1.5`,
      "##BUNDLES",
      `${TREE}\t9\t2.5`,
      "##END",
    ].join("\n"),
  );
  assertEquals(layout.layoutVersion, 1);
  assertEquals(layout.blobs.map((b) => b.name), ["a"]);
  assertEquals(layout.bundles.map((b) => b.name), [TREE]);
  assertEquals(layout.refs, [{ name: "stable", kind: "blob", hash: HASH }]);
});

Deno.test("fetchScript is https-only, bounded and quotes the temp and URL", () => {
  const script = fetchScript(
    { url: "https://up.example.test/a.bin", max_bytes: 1024 },
    "/srv/artifacts/.fetch.x",
  );
  assertEquals(script.includes("-L --max-redirs 5 --max-filesize 1024"), true);
  assertEquals(script.includes("--proto-redir '=https'"), true);
  assertEquals(script.includes("'/srv/artifacts/.fetch.x'"), true);
  assertEquals(script.includes("'https://up.example.test/a.bin'"), true);
});

/** Runs a script through a real `sh -eu` and returns its code and stdout. */
async function runSh(
  script: string,
): Promise<{ code: number; stdout: string }> {
  const out = await new Deno.Command("sh", {
    args: ["-eu", "-c", script],
    stdout: "piped",
    stderr: "piped",
  }).output();
  return { code: out.code, stdout: new TextDecoder().decode(out.stdout) };
}

Deno.test("verifyScript ignores a newline-named directory", async () => {
  const dir = await Deno.makeTempDir();
  const root = `${dir}/root`;
  await Deno.mkdir(`${root}/sha256/${HASH}`, { recursive: true });
  await Deno.writeTextFile(`${root}/sha256/${HASH}/data`, "ok\n");
  await Deno.mkdir(`${root}/sha256/evil\n${HASH}`, { recursive: true });
  await Deno.writeTextFile(`${root}/sha256/evil\n${HASH}/data`, "bad\n");

  const result = await runSh(verifyScript(root));
  assertEquals(result.code, 0);
  assertEquals(result.stdout.includes("evil"), false);
  assertEquals(result.stdout.includes(`sha256/${HASH}/data`), true);
});
