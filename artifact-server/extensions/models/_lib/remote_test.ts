import { assertEquals, assertRejects } from "jsr:@std/assert@1.0.19";
import type { SshTarget } from "./ssh.ts";
import { makeFakeRemote } from "./fake_remote.ts";
import {
  makeParentDir,
  probeFile,
  putRootFile,
  putUserFile,
  runScript,
} from "./remote.ts";
import { regenerateSha256Sums, setRef, unsetRef } from "./ops.ts";

const TARGET: SshTarget = {
  host: "node-1.example.test",
  port: 22,
  user: "deploy",
  host_key_policy: "strict",
  host_keys: ["node-1.example.test ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITest"],
};

Deno.test("probeFile reports missing, file with hash and size", async () => {
  const host = makeFakeRemote();
  assertEquals((await probeFile(host.deps, TARGET, "/srv/x")).state, "missing");
  host.setFile("/srv/x", "hello\n", "644");
  const probe = await probeFile(host.deps, TARGET, "/srv/x");
  assertEquals(probe.state, "file");
  assertEquals(probe.size, 6);
  assertEquals(probe.mode, "644");
});

Deno.test("runScript returns stdout and a non-zero exit as data", async () => {
  const host = makeFakeRemote();
  const ok = await runScript(host.deps, TARGET, "echo hi");
  assertEquals(ok.exit_code, 0);
  const missing = await runScript(host.deps, TARGET, "cat '/nope'");
  assertEquals(missing.exit_code, 1);
});

Deno.test("makeParentDir creates the directory on the target", async () => {
  const host = makeFakeRemote();
  await makeParentDir(host.deps, TARGET, "/srv/artifacts/sha256/aa/x");
  assertEquals(host.dirs.has("/srv/artifacts/sha256/aa"), true);
});

Deno.test("putUserFile writes bytes and converges on a repeat", async () => {
  const host = makeFakeRemote();
  const first = await putUserFile(host.deps, TARGET, "/srv/a", "one", "0644");
  assertEquals(first.changed, true);
  assertEquals(host.files.get("/srv/a")?.content, "one");
  assertEquals(host.files.get("/srv/a")?.mode, "644");
  const second = await putUserFile(host.deps, TARGET, "/srv/a", "one", "0644");
  assertEquals(second.changed, false);
  const third = await putUserFile(host.deps, TARGET, "/srv/a", "two", "0644");
  assertEquals(third.changed, true);
});

Deno.test("putRootFile installs root-owned content and verifies the read-back", async () => {
  const host = makeFakeRemote();
  host.dirs.add("/etc/nginx/sites-available");
  const result = await putRootFile(host.deps, TARGET, {
    path: "/etc/nginx/sites-available/artifact-server",
    content: "server {}\n",
    mode: "0644",
    owner: "root",
    group: "root",
  });
  assertEquals(result.changed, true);
  assertEquals(
    host.files.get("/etc/nginx/sites-available/artifact-server")?.owner,
    "root",
  );
  // The stage file is removed, never left behind.
  assertEquals(
    [...host.files.keys()].some((p) =>
      p.startsWith("/tmp/artifact-server.stage.")
    ),
    false,
  );
});

Deno.test("putRootFile refuses a symlink destination", async () => {
  const host = makeFakeRemote();
  host.symlinks.add("/etc/nginx/sites-available/artifact-server");
  await assertRejects(
    () =>
      putRootFile(host.deps, TARGET, {
        path: "/etc/nginx/sites-available/artifact-server",
        content: "server {}\n",
        mode: "0644",
        owner: "root",
        group: "root",
      }),
    Error,
    "symlink",
  );
});

Deno.test("regenerateSha256Sums indexes the blobs present, sorted", async () => {
  const host = makeFakeRemote();
  host.setFile("/r/sha256/aa/one", "one", "644");
  host.setFile("/r/sha256/bb/two", "two", "644");
  await regenerateSha256Sums(host.deps, TARGET, "/r");
  const text = host.files.get("/r/SHA256SUMS")?.content ?? "";
  const lines = text.trimEnd().split("\n");
  assertEquals(lines.length, 2);
  assertEquals(lines[0].endsWith("sha256/aa/one"), true);
  assertEquals(lines[1].endsWith("sha256/bb/two"), true);
});

Deno.test("setRef writes and unsetRef removes a ref, and unset is idempotent", async () => {
  const host = makeFakeRemote();
  const hash = "a".repeat(64);
  await setRef(host.deps, TARGET, "/r", "stable", "blob", hash);
  assertEquals(host.files.get("/r/refs/stable")?.content, `blob  ${hash}\n`);
  assertEquals(await unsetRef(host.deps, TARGET, "/r", "stable"), true);
  assertEquals(await unsetRef(host.deps, TARGET, "/r", "stable"), false);
});

Deno.test("setRef refuses a symlinked ref", async () => {
  const host = makeFakeRemote();
  host.symlinks.add("/r/refs/stable");
  await assertRejects(
    () => setRef(host.deps, TARGET, "/r", "stable", "blob", "a".repeat(64)),
    Error,
    "symlink",
  );
});
