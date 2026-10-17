import { assertEquals } from "jsr:@std/assert@1.0.19";
import { sha256Hex, type SshDeps, type SshTarget } from "./ssh.ts";
import {
  backupPath,
  parseAptConfigDump,
  parseSsListen,
  removeOrRestoreManaged,
  writeManagedFile,
} from "./remote.ts";
import { boxFake, TEST_NOW } from "./test_support.ts";

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

Deno.test("writeManagedFile never backs up the model's own bytes", async () => {
  // The file already holds exactly what we are about to write.
  const same = boxFake({ [PATH]: "ours\n" });
  await writeManagedFile(depsOf(same.fake.run), T, PATH, "ours\n", "0644");
  assertEquals(same.files.has(BACKUP), false);
  // The file holds a prior generation this model wrote (recorded digest).
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
