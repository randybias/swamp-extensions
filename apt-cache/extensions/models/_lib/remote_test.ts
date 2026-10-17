import { assertEquals, assertRejects } from "jsr:@std/assert@1.0.19";
import { sha256Hex, type SshDeps, type SshTarget } from "./ssh.ts";
import {
  AptCacheError,
  backupPath,
  parseAptConfigDump,
  parseSsListen,
  remoteSha,
  removeOrRestoreManaged,
  writeManagedFile,
} from "./remote.ts";
import { boxFake, fakeApt, TEST_NOW } from "./test_support.ts";

const T: SshTarget = {
  host: "192.0.2.20",
  port: 22,
  user: "root",
  host_key_policy: "strict",
  host_keys: ["192.0.2.20 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeKey"],
  private_key: "PLACEHOLDER-KEY",
  connect_timeout_s: 15,
};

const PATH = "/etc/apt-cacher-ng/backends_debian";
const BACKUP = backupPath(PATH);

/** A dependency object with the in-memory box runner and a fixed clock. */
function depsOf(run: SshDeps["run"]): SshDeps {
  return { run, now: () => TEST_NOW, sleep: () => Promise.resolve() };
}

async function sha(text: string): Promise<string> {
  return await sha256Hex(new TextEncoder().encode(text));
}

Deno.test("writeManagedFile adopts a pre-existing file and backs it up once", async () => {
  const box = boxFake({ [PATH]: "original\n" });
  const first = await writeManagedFile(
    depsOf(box.fake.run),
    T,
    PATH,
    "ours\n",
    "0644",
  );
  assertEquals(first.sha256, await sha("ours\n"));
  assertEquals(first.changed, true);
  assertEquals(box.files.get(BACKUP)?.content, "original\n");
  assertEquals(box.files.get(PATH)?.content, "ours\n");
  // A second write is idempotent and must not touch the saved original.
  const second = await writeManagedFile(
    depsOf(box.fake.run),
    T,
    PATH,
    "ours\n",
    "0644",
  );
  assertEquals(second.changed, false);
  assertEquals(box.files.get(BACKUP)?.content, "original\n");
});

Deno.test("writeManagedFile backs up a pre-existing file even when its bytes equal the new ones", async () => {
  // Not the model's own: remove must give it back, not delete it.
  const same = boxFake({ [PATH]: "ours\n" });
  await writeManagedFile(depsOf(same.fake.run), T, PATH, "ours\n", "0644");
  assertEquals(same.files.get(BACKUP)?.content, "ours\n");
  const restored = await removeOrRestoreManaged(
    depsOf(same.fake.run),
    T,
    PATH,
    await sha("ours\n"),
  );
  assertEquals(restored, "restored");
  assertEquals(same.files.get(PATH)?.content, "ours\n");
});

Deno.test("writeManagedFile never backs up a generation this model wrote (recorded digest)", async () => {
  const prior = boxFake({ [PATH]: "previous\n" });
  await writeManagedFile(
    depsOf(prior.fake.run),
    T,
    PATH,
    "next\n",
    "0644",
    await sha("previous\n"),
  );
  assertEquals(prior.files.has(BACKUP), false);
});

Deno.test("remoteSha: a failing sha256sum on a present file is an error, an absent file is null", async () => {
  const run = (code: number, testCode: number): SshDeps["run"] =>
    fakeApt((command) => {
      if (command.includes("sha256sum")) return { code, stderr: "boom" };
      if (command.includes("'test'")) {
        return { code: testCode, deliberate: true };
      }
      return {};
    }).run;
  // sha256sum fails and `test -e` says the file exists: not a missing file.
  await assertRejects(
    () => remoteSha(depsOf(run(1, 0)), T, PATH),
    AptCacheError,
    "could not hash",
  );
  // sha256sum fails and `test -e` says absent: null.
  assertEquals(await remoteSha(depsOf(run(1, 1)), T, PATH), null);
});

Deno.test("removeOrRestoreManaged restores a backup when the bytes match", async () => {
  const box = boxFake({ [PATH]: "ours\n", [BACKUP]: "original\n" });
  assertEquals(
    await removeOrRestoreManaged(
      depsOf(box.fake.run),
      T,
      PATH,
      await sha("ours\n"),
    ),
    "restored",
  );
  assertEquals(box.files.get(PATH)?.content, "original\n");
  assertEquals(box.files.has(BACKUP), false);
});

Deno.test("removeOrRestoreManaged removes when there is no backup", async () => {
  const box = boxFake({ [PATH]: "ours\n" });
  assertEquals(
    await removeOrRestoreManaged(
      depsOf(box.fake.run),
      T,
      PATH,
      await sha("ours\n"),
    ),
    "removed",
  );
  assertEquals(box.files.has(PATH), false);
});

Deno.test("removeOrRestoreManaged keeps a file whose bytes changed", async () => {
  const box = boxFake({ [PATH]: "edited by hand\n" });
  assertEquals(
    await removeOrRestoreManaged(
      depsOf(box.fake.run),
      T,
      PATH,
      await sha("ours\n"),
    ),
    "kept",
  );
  assertEquals(box.files.get(PATH)?.content, "edited by hand\n");
  assertEquals(box.fake.removed.includes(PATH), false);
});

Deno.test("removeOrRestoreManaged is a no-op when the file is gone", async () => {
  const box = boxFake();
  assertEquals(
    await removeOrRestoreManaged(depsOf(box.fake.run), T, PATH, await sha("x")),
    "removed",
  );
  assertEquals(box.fake.removed.includes(PATH), false);
});

Deno.test("parseSsListen and parseAptConfigDump read real tool shapes", () => {
  assertEquals(
    parseSsListen(
      "State Recv-Q Send-Q Local Address:Port Peer Address:Port\nLISTEN 0 4096 192.0.2.20:3142 0.0.0.0:*\nLISTEN 0 4096 [::1]:3142 [::]:*\n",
    ),
    {
      listen: ["192.0.2.20", "::1"],
      ports: [3142],
      pairs: [
        { address: "192.0.2.20", port: 3142 },
        { address: "::1", port: 3142 },
      ],
    },
  );
  assertEquals(
    parseAptConfigDump(`Acquire::http::Proxy "http://192.0.2.20:3142";\n`),
    { "Acquire::http::Proxy": "http://192.0.2.20:3142" },
  );
});
