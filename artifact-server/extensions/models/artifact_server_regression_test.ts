import { assertEquals, assertRejects } from "jsr:@std/assert@1.0.19";
import { makeFakeRemote } from "./_lib/fake_remote.ts";
import { base, modelFor, ROOT, SITE_ARGS } from "./_lib/test_support.ts";
import { SHA256SUMS_FILE } from "./_lib/layout.ts";
import { sha256Hex } from "./_lib/ssh.ts";
import {
  NGINX_DEFAULT_SITE,
  NGINX_ENABLED_PATH,
  NGINX_SITE_PATH,
  TLS_CERT_PATH,
} from "./_lib/nginx.ts";

// Regression cases for the safety review: rollback on failure, retry
// behaviour, and edge inputs that must not corrupt the host.

Deno.test("install refuses a populated root that holds no sentinel", async () => {
  const host = makeFakeRemote();
  host.setFile(`${ROOT}/not-ours.conf`, "x\n", "644", "user", "user");
  const { m, context } = modelFor(host);
  await assertRejects(
    () =>
      m.methods.install.execute(
        base({ ...SITE_ARGS, tls: { mode: "none", plaintext_ack: true } }),
        context,
      ),
    Error,
    "sentinel",
  );
  // Nothing was written and no symlink was left behind.
  assertEquals(host.files.has(NGINX_SITE_PATH), false);
  assertEquals(host.symlinks.has(NGINX_ENABLED_PATH), false);
});

Deno.test("install rollback removes the enabled link and the site on a first install", async () => {
  const host = makeFakeRemote();
  host.failNginxTest = true;
  const { m, context } = modelFor(host);
  await assertRejects(
    () =>
      m.methods.install.execute(
        base({ ...SITE_ARGS, tls: { mode: "none", plaintext_ack: true } }),
        context,
      ),
    Error,
    "rolled back",
  );
  // No dangling sites-enabled link, no site file, and no reload.
  assertEquals(host.symlinks.has(NGINX_ENABLED_PATH), false);
  assertEquals(host.files.has(NGINX_SITE_PATH), false);
  assertEquals(
    host.commands.some((c) => c.includes("argv:systemctl reload")),
    false,
  );
});

Deno.test("fetch is idempotent when the pinned object is already present", async () => {
  const host = makeFakeRemote();
  let downloads = 0;
  host.curl = () => {
    downloads++;
    return "payload";
  };
  const hash = await sha256Hex("payload");
  host.setFile(
    `${ROOT}/sha256/${hash}/p.bin`,
    "payload",
    "644",
    "user",
    "user",
  );
  const { m, context } = modelFor(host);
  const result = await m.methods.fetch.execute(
    base({
      url: "https://up.example.test/p.bin",
      filename: "p.bin",
      sha256: hash,
    }),
    context,
  );
  assertEquals((result.result as { changed: boolean }).changed, false);
  assertEquals(downloads, 0);
  assertEquals(
    host.commands.some((c) => c.includes("curl -fsS")),
    false,
  );
});

Deno.test("publish_bundle refuses duplicate file names", async () => {
  const host = makeFakeRemote();
  const { m, context } = modelFor(host);
  await assertRejects(
    () =>
      m.methods.publish_bundle.execute(
        base({
          files: [{ name: "a", content: "one" }, { name: "a", content: "two" }],
        }),
        context,
      ),
    Error,
    "unique",
  );
});

Deno.test("prune refuses a symlinked hash directory and deletes nothing", async () => {
  const host = makeFakeRemote();
  const orphan = await sha256Hex("orphan\n");
  host.setFile(
    `${ROOT}/sha256/${orphan}/data`,
    "orphan\n",
    "644",
    "user",
    "user",
  );
  // The hash directory is a symlink pointing outside the root.
  host.symlinks.add(`${ROOT}/sha256/${orphan}`);
  const { m, context } = modelFor(host);
  const plan = (await m.methods.plan_prune.execute(base(), context)).result as {
    planSha256: string;
  };
  await assertRejects(
    () =>
      m.methods.prune.execute(base({ plan_sha256: plan.planSha256 }), context),
    Error,
  );
  assertEquals(host.files.has(`${ROOT}/sha256/${orphan}/data`), true);
});

Deno.test("list drops an object whose name contains a newline", async () => {
  const host = makeFakeRemote();
  const good = await sha256Hex("good\n");
  host.setFile(
    `${ROOT}/sha256/${good}/good.txt`,
    "good\n",
    "644",
    "user",
    "user",
  );
  host.setFile(
    `${ROOT}/sha256/${good}/bad\nname`,
    "bad\n",
    "644",
    "user",
    "user",
  );
  const { m, context } = modelFor(host);
  const result = await m.methods.list.execute(base(), context);
  assertEquals((result.result as { blobs: number }).blobs, 1);
});

Deno.test("install rolls back when a credential write fails after enabling", async () => {
  const host = makeFakeRemote();
  // /etc/nginx/ssl is a file, so `install -d` for it fails.
  host.setFile("/etc/nginx/ssl", "not a directory\n", "644");
  host.failArgv = (argv) =>
    argv[0] === "install" && argv[1] === "-d" &&
    argv.includes("/etc/nginx/ssl");
  const { m, context } = modelFor(host);
  await assertRejects(
    () =>
      m.methods.install.execute(
        base({
          ...SITE_ARGS,
          tls: {
            mode: "provided",
            cert_pem: "c".repeat(64),
            key_pem: "k".repeat(64),
          },
        }),
        context,
      ),
    Error,
    "rolled back",
  );
  // Nothing was left enabled, and no certificate was written.
  assertEquals(host.symlinks.has(NGINX_ENABLED_PATH), false);
  assertEquals(host.files.has(TLS_CERT_PATH), false);
});

Deno.test("install rolls back when enabling fails after the site is enabled", async () => {
  const host = makeFakeRemote();
  host.setFile(NGINX_DEFAULT_SITE, "default\n", "644");
  host.failArgv = (argv) =>
    argv[0] === "rm" && argv.includes(NGINX_DEFAULT_SITE);
  const { m, context } = modelFor(host);
  await assertRejects(
    () =>
      m.methods.install.execute(
        base({
          ...SITE_ARGS,
          tls: { mode: "none", plaintext_ack: true },
          disable_default_site: true,
        }),
        context,
      ),
    Error,
    "rolled back",
  );
  assertEquals(host.symlinks.has(NGINX_ENABLED_PATH), false);
  assertEquals(host.files.has(NGINX_SITE_PATH), false);
});

Deno.test("install reloads even when nothing changed this run", async () => {
  const host = makeFakeRemote();
  const { m, context } = modelFor(host);
  const args = base({
    ...SITE_ARGS,
    tls: { mode: "none", plaintext_ack: true },
  });
  await m.methods.install.execute(args, context);
  host.commands.length = 0;
  const again = await m.methods.install.execute(args, context);
  assertEquals((again.result as { changed: boolean }).changed, false);
  assertEquals(
    host.commands.some((c) => c.includes("argv:systemctl reload")),
    true,
  );
});

Deno.test("install refuses to run when an existing file cannot be read for rollback", async () => {
  const host = makeFakeRemote();
  host.setFile(NGINX_SITE_PATH, "existing\n", "644");
  host.readFails.add(NGINX_SITE_PATH);
  const { m, context } = modelFor(host);
  await assertRejects(
    () =>
      m.methods.install.execute(
        base({ ...SITE_ARGS, tls: { mode: "none", plaintext_ack: true } }),
        context,
      ),
    Error,
    "could not read",
  );
  assertEquals(host.files.get(NGINX_SITE_PATH)?.content, "existing\n");
  assertEquals(host.symlinks.has(NGINX_ENABLED_PATH), false);
});

Deno.test("uninstall fails loudly when it cannot remove the site files", async () => {
  const host = makeFakeRemote();
  host.setFile(NGINX_SITE_PATH, "server {}\n", "644");
  host.failArgv = (argv) => argv[0] === "rm";
  const { m, context } = modelFor(host);
  await assertRejects(
    () => m.methods.uninstall.execute(base(), context),
    Error,
    "could not remove the site files",
  );
});

Deno.test("get fails with no site, sync succeeds", async () => {
  const host = makeFakeRemote();
  const { m, context } = modelFor(host);
  await assertRejects(
    () => m.methods.get.execute(base(), context),
    Error,
    "no artifact-server site",
  );
  const synced = await m.methods.sync.execute(base(), context);
  assertEquals(
    typeof (synced.result as { nginx_active: string }).nginx_active,
    "string",
  );
});

Deno.test("fetch repairs a stale index even when the object is present", async () => {
  const host = makeFakeRemote();
  const hash = await sha256Hex("payload");
  host.setFile(
    `${ROOT}/sha256/${hash}/p.bin`,
    "payload",
    "644",
    "user",
    "user",
  );
  host.setFile(`${ROOT}/${SHA256SUMS_FILE}`, "", "644", "user", "user");
  const { m, context } = modelFor(host);
  const result = await m.methods.fetch.execute(
    base({
      url: "https://up.example.test/p.bin",
      filename: "p.bin",
      sha256: hash,
    }),
    context,
  );
  assertEquals((result.result as { changed: boolean }).changed, false);
  assertEquals(
    host.files.get(`${ROOT}/${SHA256SUMS_FILE}`)?.content.includes(hash),
    true,
  );
});

Deno.test("install refuses when a link target cannot be read for rollback", async () => {
  const host = makeFakeRemote();
  host.setFile(NGINX_DEFAULT_SITE, "default site\n", "644");
  host.readFails.add(NGINX_DEFAULT_SITE);
  const { m, context } = modelFor(host);
  await assertRejects(
    () =>
      m.methods.install.execute(
        base({
          ...SITE_ARGS,
          tls: { mode: "none", plaintext_ack: true },
          disable_default_site: true,
        }),
        context,
      ),
    Error,
    "could not read",
  );
  assertEquals(host.files.get(NGINX_DEFAULT_SITE)?.content, "default site\n");
});

Deno.test("install reports rollback failures in the error", async () => {
  const host = makeFakeRemote();
  host.setFile("/etc/nginx/ssl", "not a directory\n", "644");
  host.failArgv = (argv) =>
    (argv[0] === "install" && argv[1] === "-d" &&
      argv.includes("/etc/nginx/ssl")) ||
    argv[0] === "rm";
  const { m, context } = modelFor(host);
  await assertRejects(
    () =>
      m.methods.install.execute(
        base({
          ...SITE_ARGS,
          tls: {
            mode: "provided",
            cert_pem: "c".repeat(64),
            key_pem: "k".repeat(64),
          },
        }),
        context,
      ),
    Error,
    "rollback errors",
  );
});
