import { assertEquals } from "jsr:@std/assert@1.0.19";
import { sha256Hex, type SshDeps, type SshTarget } from "./ssh.ts";
import {
  backupPath,
  parseAptConfigDump,
  parseSsListen,
  removeOrRestoreManaged,
  writeManagedFile,
} from "./remote.ts";
import { fakeApt, hasTok, TEST_NOW } from "./test_support.ts";

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
const SHA_A = "a".repeat(64);
const SHA_B = "b".repeat(64);

/** A dependency object with the fake runner and a fixed clock. */
function depsOf(run: SshDeps["run"]): SshDeps {
  return { run, now: () => TEST_NOW, sleep: () => Promise.resolve() };
}

async function sha(text: string): Promise<string> {
  return await sha256Hex(new TextEncoder().encode(text));
}

Deno.test("writeManagedFile backs up a pre-existing file exactly once", async () => {
  let backedUp = false;
  const fake = fakeApt((command) => {
    if (command.includes("sha256sum") && command.includes(BACKUP)) {
      return backedUp ? { code: 0, stdout: `${SHA_B}\n` } : { code: 1 };
    }
    if (command.startsWith("'sha256sum'")) return { code: 1 };
    if (command.startsWith("'cat'")) return { code: 0, stdout: "original\n" };
    if (command.startsWith("'cp' ")) {
      backedUp = true;
      return { code: 0 };
    }
    return { code: 0 };
  });
  const first = await writeManagedFile(
    depsOf(fake.run),
    T,
    PATH,
    "ours\n",
    "0644",
  );
  assertEquals(first.sha256, await sha("ours\n"));
  assertEquals(first.changed, true);
  const second = await writeManagedFile(
    depsOf(fake.run),
    T,
    PATH,
    "ours\n",
    "0644",
  );
  assertEquals(second.sha256, await sha("ours\n"));
  assertEquals(
    fake.commands.filter((c) => c.startsWith("'cp' ")).length,
    1,
    "the original was backed up more than once",
  );
});

Deno.test("writeManagedFile does not back up a file that is absent", async () => {
  const fake = fakeApt((command) => {
    if (command.startsWith("'sha256sum'")) return { code: 1 };
    if (command.startsWith("'cat'")) return { code: 1 };
    if (command.startsWith("'test' '-e'")) return { code: 1 };
    return { code: 0 };
  });
  await writeManagedFile(depsOf(fake.run), T, PATH, "ours\n", "0644");
  assertEquals(fake.commands.some((c) => c.startsWith("'cp' ")), false);
});

Deno.test("removeOrRestoreManaged restores the backup when the bytes match", async () => {
  const fake = fakeApt((command) => {
    if (command.includes("sha256sum") && command.includes(BACKUP)) {
      return { code: 0, stdout: `${SHA_B}\n` };
    }
    if (command.startsWith("'sha256sum'")) {
      return { code: 0, stdout: `${SHA_A}\n` };
    }
    return { code: 0 };
  });
  assertEquals(
    await removeOrRestoreManaged(depsOf(fake.run), T, PATH, SHA_A),
    "restored",
  );
  assertEquals(hasTok(fake, "'mv'", "-f"), true);
  assertEquals(fake.removed.includes(PATH), false);
});

Deno.test("removeOrRestoreManaged removes when there is no backup", async () => {
  const fake = fakeApt((command) => {
    if (command.includes("sha256sum") && command.includes(BACKUP)) {
      return { code: 1 };
    }
    if (command.startsWith("'sha256sum'")) {
      return { code: 0, stdout: `${SHA_A}\n` };
    }
    return { code: 0 };
  });
  assertEquals(
    await removeOrRestoreManaged(depsOf(fake.run), T, PATH, SHA_A),
    "removed",
  );
  assertEquals(fake.removed.includes(PATH), true);
});

Deno.test("removeOrRestoreManaged keeps a file whose bytes changed", async () => {
  const fake = fakeApt((command) => {
    if (command.startsWith("'sha256sum'")) {
      return { code: 0, stdout: `${SHA_B}\n` };
    }
    return { code: 0 };
  });
  assertEquals(
    await removeOrRestoreManaged(depsOf(fake.run), T, PATH, SHA_A),
    "kept",
  );
  assertEquals(fake.removed.includes(PATH), false);
  assertEquals(fake.commands.some((c) => c.startsWith("'mv'")), false);
});

Deno.test("removeOrRestoreManaged is a no-op when the file is gone", async () => {
  const fake = fakeApt((command) => {
    if (command.startsWith("'sha256sum'")) return { code: 1 };
    return { code: 0 };
  });
  assertEquals(
    await removeOrRestoreManaged(depsOf(fake.run), T, PATH, SHA_A),
    "removed",
  );
  assertEquals(fake.removed.includes(PATH), false);
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
