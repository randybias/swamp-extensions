import { assertEquals } from "jsr:@std/assert@1.0.19";
import {
  regenerateSumsScript,
  removeObjectsScript,
  setRefScript,
  unsetRefScript,
} from "./ops.ts";

/** Runs a script through a real `sh -eu` and returns its exit code and stderr. */
async function sh(
  script: string,
): Promise<{ code: number; stderr: string }> {
  const out = await new Deno.Command("sh", {
    args: ["-eu", "-c", script],
    stdout: "piped",
    stderr: "piped",
  }).output();
  return {
    code: out.code,
    stderr: new TextDecoder().decode(out.stderr),
  };
}

const HASH = "a".repeat(64);

Deno.test("setRefScript names the ref file without quotes and unset removes it", async () => {
  const dir = await Deno.makeTempDir();
  const root = `${dir}/root`;
  await Deno.mkdir(`${root}/refs`, { recursive: true });

  assertEquals((await sh(setRefScript(root, "stable", "blob", HASH))).code, 0);
  // The file is exactly `stable`, not `'stable'`.
  const names = [...Deno.readDirSync(`${root}/refs`)].map((e) => e.name).sort();
  assertEquals(names, ["stable"]);
  assertEquals(
    await Deno.readTextFile(`${root}/refs/stable`),
    `blob  ${HASH}\n`,
  );

  assertEquals((await sh(unsetRefScript(root, "stable"))).code, 0);
  assertEquals([...Deno.readDirSync(`${root}/refs`)].length, 0);
});

Deno.test("removeObjectsScript refuses a planted symlinked hash directory", async () => {
  const dir = await Deno.makeTempDir();
  const root = `${dir}/root`;
  const victim = `${dir}/victim`;
  await Deno.mkdir(`${root}/sha256`, { recursive: true });
  await Deno.mkdir(victim, { recursive: true });
  await Deno.writeTextFile(`${victim}/data`, "outside\n");
  await Deno.symlink(victim, `${root}/sha256/${HASH}`);

  // The plan path is a valid blob path, but its hash directory is a symlink.
  const result = await sh(removeObjectsScript(root, [`sha256/${HASH}/data`]));
  assertEquals(result.code, 3);
  // The file outside the root is untouched.
  assertEquals(await Deno.readTextFile(`${victim}/data`), "outside\n");
});

Deno.test("removeObjectsScript removes a real blob inside the root", async () => {
  const dir = await Deno.makeTempDir();
  const root = `${dir}/root`;
  await Deno.mkdir(`${root}/sha256/${HASH}`, { recursive: true });
  await Deno.writeTextFile(`${root}/sha256/${HASH}/data`, "gone\n");
  assertEquals(
    (await sh(removeObjectsScript(root, [`sha256/${HASH}/data`]))).code,
    0,
  );
  // The emptied hash directory is removed too.
  assertEquals(
    await Deno.stat(`${root}/sha256/${HASH}`).then(() => true).catch(
      () => false,
    ),
    false,
  );
});

Deno.test("regenerateSumsScript records the path hash and skips dotfiles", async () => {
  const hasFlock = await new Deno.Command("sh", {
    args: ["-c", "command -v flock"],
  }).output().then((o) => o.code === 0).catch(() => false);
  if (!hasFlock) return; // flock is a Linux/BSD tool; skip elsewhere.

  const dir = await Deno.makeTempDir();
  const root = `${dir}/root`;
  await Deno.mkdir(`${root}/sha256/${HASH}`, { recursive: true });
  await Deno.writeTextFile(`${root}/sha256/${HASH}/data`, "content\n");
  await Deno.writeTextFile(`${root}/sha256/${HASH}/.inflight`, "temp\n");

  assertEquals((await sh(regenerateSumsScript(root))).code, 0);
  const sums = await Deno.readTextFile(`${root}/SHA256SUMS`);
  assertEquals(sums, `${HASH}  sha256/${HASH}/data\n`);
});

Deno.test("regenerateSumsScript ignores a newline-named directory", async () => {
  const hasFlock = await new Deno.Command("sh", {
    args: ["-c", "command -v flock"],
  }).output().then((o) => o.code === 0).catch(() => false);
  if (!hasFlock) return;

  const dir = await Deno.makeTempDir();
  const root = `${dir}/root`;
  await Deno.mkdir(`${root}/sha256/${HASH}`, { recursive: true });
  await Deno.writeTextFile(`${root}/sha256/${HASH}/data`, "ok\n");
  // A directory whose name begins with a newline followed by a valid hash.
  await Deno.mkdir(`${root}/sha256/evil\n${HASH}`, { recursive: true });
  await Deno.writeTextFile(`${root}/sha256/evil\n${HASH}/data`, "bad\n");

  assertEquals((await sh(regenerateSumsScript(root))).code, 0);
  const sums = await Deno.readTextFile(`${root}/SHA256SUMS`);
  assertEquals(sums, `${HASH}  sha256/${HASH}/data\n`);
  assertEquals(sums.includes("evil"), false);
});

Deno.test("regenerateSumsScript ignores a newline in a file name", async () => {
  const hasFlock = await new Deno.Command("sh", {
    args: ["-c", "command -v flock"],
  }).output().then((o) => o.code === 0).catch(() => false);
  if (!hasFlock) return;

  const dir = await Deno.makeTempDir();
  const root = `${dir}/root`;
  await Deno.mkdir(`${root}/sha256/${HASH}`, { recursive: true });
  await Deno.writeTextFile(`${root}/sha256/${HASH}/data`, "ok\n");
  // A file whose name contains a newline and a forged index line.
  await Deno.writeTextFile(
    `${root}/sha256/${HASH}/data\n${"e".repeat(64)}  injected`,
    "bad\n",
  );

  assertEquals((await sh(regenerateSumsScript(root))).code, 0);
  const sums = await Deno.readTextFile(`${root}/SHA256SUMS`);
  assertEquals(sums, `${HASH}  sha256/${HASH}/data\n`);
  assertEquals(sums.includes("injected"), false);
});

Deno.test("regenerateSumsScript skips a symlinked hash directory", async () => {
  const hasFlock = await new Deno.Command("sh", {
    args: ["-c", "command -v flock"],
  }).output().then((o) => o.code === 0).catch(() => false);
  if (!hasFlock) return;

  const dir = await Deno.makeTempDir();
  const root = `${dir}/root`;
  const other = "e".repeat(64);
  await Deno.mkdir(`${root}/sha256/${HASH}`, { recursive: true });
  await Deno.writeTextFile(`${root}/sha256/${HASH}/data`, "ok\n");
  const outside = `${dir}/outside`;
  await Deno.mkdir(outside, { recursive: true });
  await Deno.writeTextFile(`${outside}/data`, "outside\n");
  await Deno.symlink(outside, `${root}/sha256/${other}`);

  assertEquals((await sh(regenerateSumsScript(root))).code, 0);
  const sums = await Deno.readTextFile(`${root}/SHA256SUMS`);
  assertEquals(sums, `${HASH}  sha256/${HASH}/data\n`);
  assertEquals(sums.includes(other), false);
});
