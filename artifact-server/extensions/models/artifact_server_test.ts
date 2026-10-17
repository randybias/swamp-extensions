import { assertEquals, assertRejects } from "jsr:@std/assert@1.0.19";
import { createModelTestContext } from "jsr:@swamp-club/swamp-testing@0.20261014.55";
import { createModel } from "./artifact_server.ts";
import { makeFakeRemote } from "./_lib/fake_remote.ts";
import { sha256Hex } from "./_lib/ssh.ts";
import { BUNDLE_DIR, SHA256SUMS_FILE, treeHash } from "./_lib/layout.ts";
import { NGINX_ENABLED_PATH, NGINX_SITE_PATH } from "./_lib/nginx.ts";

const SSH = {
  host: "node-1.example.test",
  user: "deploy",
  host_key_policy: "strict" as const,
  host_keys: [
    "node-1.example.test ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestOnly",
  ],
};
const ROOT = "/srv/artifacts";
const SITE_ARGS = {
  listen: { address: "*", port: 8080 },
  server_name: "cdn.example.test",
};
const HOST = "a".repeat(64);

/** The shared argument block with defaults filled in. */
function base(overrides: Record<string, unknown> = {}) {
  return { ssh: SSH, root: ROOT, ...overrides };
}

/** Binds the model to a fake transport and returns a fresh test context. */
function modelFor(host: ReturnType<typeof makeFakeRemote>) {
  return { host, m: createModel(host.deps), ...createModelTestContext({}) };
}

Deno.test("the model type, version and empty global arguments are as specified", () => {
  const m = createModel(makeFakeRemote().deps);
  assertEquals(m.type, "@randybias/artifact-server");
  assertEquals(m.version, "2026.10.17.1");
  assertEquals(m.globalArguments.safeParse({}).success, true);
  assertEquals(m.globalArguments.safeParse({ extra: 1 }).success, false);
});

Deno.test("every method exists with a description and a schema", () => {
  const m = createModel();
  for (
    const name of [
      "render_config",
      "install",
      "upload",
      "fetch",
      "publish_bundle",
      "ref",
      "unref",
      "list",
      "verify",
      "get",
      "sync",
      "plan_prune",
      "prune",
      "uninstall",
    ]
  ) {
    const method = (m.methods as Record<
      string,
      { description: string; arguments: unknown }
    >)[name];
    assertEquals(typeof method.description, "string", name);
    assertEquals(method.description.length > 0, true, name);
    assertEquals(typeof method.arguments, "object", name);
  }
});

Deno.test("destructive methods are action kind and lead with DESTRUCTIVE", () => {
  const m = createModel();
  for (
    const name of [
      "install",
      "upload",
      "fetch",
      "ref",
      "unref",
      "prune",
      "uninstall",
      "publish_bundle",
    ]
  ) {
    assertEquals(m.methods[name].kind, "action", name);
  }
  for (const name of ["unref", "prune", "uninstall"]) {
    assertEquals(
      m.methods[name].description.startsWith("DESTRUCTIVE."),
      true,
      name,
    );
  }
  for (
    const name of [
      "render_config",
      "list",
      "verify",
      "get",
      "sync",
      "plan_prune",
    ]
  ) {
    assertEquals(
      m.methods[name].description.startsWith("READ-ONLY."),
      true,
      name,
    );
  }
});

Deno.test("the ssh block requires a pinned strict host key and rejects unknown fields", () => {
  const args = createModel().methods.install.arguments;
  assertEquals(
    args.safeParse(base({
      ...SITE_ARGS,
      tls: { mode: "none", plaintext_ack: true },
    })).success,
    true,
  );
  // Missing host_keys.
  assertEquals(
    args.safeParse({
      ssh: {
        host: "h.example.test",
        user: "deploy",
        host_key_policy: "strict",
      },
      root: ROOT,
      ...SITE_ARGS,
      tls: { mode: "none", plaintext_ack: true },
    }).success,
    false,
  );
  // Trust-on-first-use is not offered.
  assertEquals(
    args.safeParse(base({
      ssh: { ...SSH, host_key_policy: "insecure_tofu" },
      ...SITE_ARGS,
      tls: { mode: "none", plaintext_ack: true },
    })).success,
    false,
  );
  // Unknown field refused.
  assertEquals(
    args.safeParse(base({
      ...SITE_ARGS,
      tls: { mode: "none", plaintext_ack: true },
      surprise: 1,
    })).success,
    false,
  );
});

Deno.test("basic auth over plain HTTP must be acknowledged at run time", async () => {
  const { m, context } = modelFor(makeFakeRemote());
  assertEquals(
    m.methods.render_config.arguments.safeParse(
      base({ ...SITE_ARGS, tls: { mode: "none" } }),
    ).success,
    false,
  );
  const auth = base({
    ...SITE_ARGS,
    tls: { mode: "none", plaintext_ack: true },
    basic_auth: { realm: "r", users: [{ name: "u", hash: "$6$abcdefgh$xyz" }] },
  });
  assertEquals(m.methods.render_config.arguments.safeParse(auth).success, true);
  await assertRejects(
    () => m.methods.render_config.execute(auth, context),
    Error,
    "basic_auth_plaintext_ack",
  );
  const acked = { ...auth, basic_auth_plaintext_ack: true };
  const ok = await m.methods.render_config.execute(acked, context);
  assertEquals(
    typeof (ok.result as { config_sha256: string }).config_sha256,
    "string",
  );
});

Deno.test("root refuses /, relative and dot-dot paths", () => {
  const args = createModel().methods.list.arguments;
  for (
    const root of [
      "/",
      "/srv/../etc",
      "srv/artifacts",
      "/srv/./x",
      "/etc",
      "/usr",
      "/home",
      "/srv",
      "/tmp",
      "/opt",
      "/var",
    ]
  ) {
    assertEquals(args.safeParse({ ssh: SSH, root }).success, false, root);
  }
  // A two-segment path under a system directory is allowed by the grammar; the
  // install/uninstall sentinel is what protects it at run time.
  assertEquals(
    args.safeParse({ ssh: SSH, root: "/srv/artifacts" }).success,
    true,
  );
});

Deno.test("fetch.url must be https with no userinfo, quote or semicolon", () => {
  const args = createModel().methods.fetch.arguments;
  const mk = (url: string) => base({ url, filename: "a", sha256: HOST });
  assertEquals(
    args.safeParse(mk("https://up.example.test/a.bin")).success,
    true,
  );
  for (
    const url of [
      "http://up.example.test/a.bin",
      "https://user:pass@up.example.test/a.bin",
      "https://up.example.test/a;rm -rf /",
      "https://up.example.test/a`id`",
      "https://up.example.test/a b",
    ]
  ) {
    assertEquals(args.safeParse(mk(url)).success, false, url);
  }
});

Deno.test("render_config is deterministic and contains no secret", async () => {
  const { m, context, getWrittenResources } = modelFor(makeFakeRemote());
  const result = await m.methods.render_config.execute(
    base({ ...SITE_ARGS, tls: { mode: "none", plaintext_ack: true } }),
    context,
  );
  const first = (result.result as { config_sha256: string }).config_sha256;
  assertEquals(typeof first, "string");
  const written = getWrittenResources();
  assertEquals(written[0].specName, "config");
  assertEquals(
    (written[0].data as { text: string }).text.includes("autoindex off;"),
    true,
  );
  assertEquals(JSON.stringify(written[0].data).includes("password"), false);
  // Same inputs render the same bytes.
  const again = await m.methods.render_config.execute(
    base({ ...SITE_ARGS, tls: { mode: "none", plaintext_ack: true } }),
    context,
  );
  assertEquals(
    (again.result as { config_sha256: string }).config_sha256,
    first,
  );
});

Deno.test("upload refuses when the computed hash differs from the pin, changing nothing", async () => {
  const host = makeFakeRemote();
  const { m, context } = modelFor(host);
  await assertRejects(
    () =>
      m.methods.upload.execute(
        base({ filename: "a.txt", content: "hello", sha256: HOST }),
        context,
      ),
    Error,
    "does not match",
  );
  assertEquals(host.files.size, 0);
});

Deno.test("upload stores the blob and regenerates SHA256SUMS", async () => {
  const host = makeFakeRemote();
  const { m, context, getWrittenResources } = modelFor(host);
  const hash = await sha256Hex("hello");
  const result = await m.methods.upload.execute(
    base({ filename: "a.txt", content: "hello", ref: "stable" }),
    context,
  );
  const res = result.result as {
    sha256: string;
    url: string;
    changed: boolean;
  };
  assertEquals(res.sha256, hash);
  assertEquals(res.changed, true);
  assertEquals(res.url, `http://node-1.example.test/sha256/${hash}/a.txt`);
  assertEquals(
    host.files.get(`${ROOT}/sha256/${hash}/a.txt`)?.content,
    "hello",
  );
  assertEquals(
    host.files.get(`${ROOT}/${SHA256SUMS_FILE}`)?.content.includes(hash),
    true,
  );
  assertEquals(
    host.files.get(`${ROOT}/refs/stable`)?.content,
    `blob  ${hash}\n`,
  );
  assertEquals(getWrittenResources()[0].specName, "artifact");
});

Deno.test("fetch refuses a download whose hash differs from the pin and leaves no object", async () => {
  const host = makeFakeRemote();
  host.curl = () => "tampered";
  const { m, context } = modelFor(host);
  const good = await sha256Hex("expected");
  await assertRejects(
    () =>
      m.methods.fetch.execute(
        base({
          url: "https://up.example.test/a.bin",
          filename: "a.bin",
          sha256: good,
        }),
        context,
      ),
    Error,
    "does not match",
  );
  assertEquals([...host.files.keys()].some((p) => p.includes("a.bin")), false);
  assertEquals(
    [...host.files.keys()].some((p) => p.includes(".fetch.")),
    false,
  );
});

Deno.test("fetch stores a pinned download and indexes it", async () => {
  const host = makeFakeRemote();
  host.curl = () => "payload";
  const { m, context } = modelFor(host);
  const hash = await sha256Hex("payload");
  const result = await m.methods.fetch.execute(
    base({
      url: "https://up.example.test/p.bin",
      filename: "p.bin",
      sha256: hash,
    }),
    context,
  );
  assertEquals((result.result as { sha256: string }).sha256, hash);
  assertEquals(
    host.files.get(`${ROOT}/sha256/${hash}/p.bin`)?.content,
    "payload",
  );
});

Deno.test("publish_bundle writes files under the tree hash", async () => {
  const host = makeFakeRemote();
  const { m, context } = modelFor(host);
  const result = await m.methods.publish_bundle.execute(
    base({
      files: [{ name: "a", content: "one" }, { name: "b", content: "two" }],
    }),
    context,
  );
  const tree = (result.result as { tree_sha256: string }).tree_sha256;
  const expected = await treeHash(
    [
      { name: "a", sha256: await sha256Hex("one") },
      { name: "b", sha256: await sha256Hex("two") },
    ],
    (t) => sha256Hex(t),
  );
  assertEquals(tree, expected);
  assertEquals(
    host.files.get(`${ROOT}/${BUNDLE_DIR}/${tree}/a`)?.content,
    "one",
  );
  assertEquals(
    host.files.get(`${ROOT}/${BUNDLE_DIR}/${tree}/b`)?.content,
    "two",
  );
});

Deno.test("ref writes and unref removes a ref, idempotently", async () => {
  const host = makeFakeRemote();
  const { m, context } = modelFor(host);
  await m.methods.ref.execute(
    base({ ref: "stable", kind: "blob", hash: HOST }),
    context,
  );
  assertEquals(
    host.files.get(`${ROOT}/refs/stable`)?.content,
    `blob  ${HOST}\n`,
  );
  assertEquals(
    (await m.methods.unref.execute(base({ ref: "stable" }), context)).result,
    { ref: "stable", removed: true },
  );
  assertEquals(
    (await m.methods.unref.execute(base({ ref: "stable" }), context)).result,
    { ref: "stable", removed: false },
  );
});

/** Seeds a layout with one blob and one ref. */
async function seed(host: ReturnType<typeof makeFakeRemote>) {
  const body = "stored\n";
  const hash = await sha256Hex(body);
  host.setFile(`${ROOT}/.layout-version`, "1\n", "644", "user", "user");
  host.setFile(`${ROOT}/sha256/${hash}/x.txt`, body, "644", "user", "user");
  host.setFile(
    `${ROOT}/${SHA256SUMS_FILE}`,
    `${hash}  sha256/${hash}/x.txt\n`,
    "644",
    "user",
    "user",
  );
  host.setFile(`${ROOT}/refs/stable`, `blob  ${hash}\n`, "644", "user", "user");
  return hash;
}

Deno.test("list reads refs, blobs and bundles and persists a listing", async () => {
  const host = makeFakeRemote();
  await seed(host);
  const { m, context, getWrittenResources } = modelFor(host);
  const result = await m.methods.list.execute(base(), context);
  assertEquals(result.result, { refs: 1, blobs: 1, bundles: 0 });
  assertEquals(getWrittenResources()[0].specName, "listing");
});

Deno.test("verify reports ok for an intact blob and extra/missing correctly", async () => {
  const host = makeFakeRemote();
  await seed(host);
  const { m, context } = modelFor(host);
  const result = await m.methods.verify.execute(base(), context);
  assertEquals(result.result, { ok: 1, corrupt: 0, missing: 0, extra: 0 });
});

Deno.test("verify reports a corrupted blob", async () => {
  const host = makeFakeRemote();
  const hash = await seed(host);
  // Rewrite the blob so its content no longer matches its path hash.
  host.setFile(
    `${ROOT}/sha256/${hash}/x.txt`,
    "changed\n",
    "644",
    "user",
    "user",
  );
  const { m, context } = modelFor(host);
  const result = await m.methods.verify.execute(base(), context);
  assertEquals((result.result as { corrupt: number }).corrupt, 1);
});

Deno.test("get observes nginx state and the layout summary", async () => {
  const host = makeFakeRemote();
  await seed(host);
  host.setFile(NGINX_SITE_PATH, "server { listen *:8080; }\n", "644");
  const { m, context, getWrittenResources } = modelFor(host);
  const result = await m.methods.get.execute(base(), context);
  const res = result.result as {
    nginx_active: string;
    blobs: number;
    refs: number;
  };
  assertEquals(res.nginx_active, "active");
  assertEquals(res.blobs, 1);
  assertEquals(res.refs, 1);
  assertEquals(getWrittenResources()[0].specName, "server");
});

Deno.test("plan_prune leaves referenced objects and hashes the rest", async () => {
  const host = makeFakeRemote();
  const refHash = await seed(host);
  const orphan = await sha256Hex("orphan\n");
  host.setFile(
    `${ROOT}/sha256/${orphan}/y.txt`,
    "orphan\n",
    "644",
    "user",
    "user",
  );
  const { m, context, getWrittenResources } = modelFor(host);
  const result = await m.methods.plan_prune.execute(base(), context);
  const plan = result.result as {
    objects: { hash: string }[];
    planSha256: string;
  };
  assertEquals(plan.objects.map((o) => o.hash), [orphan]);
  assertEquals(plan.objects.some((o) => o.hash === refHash), false);
  assertEquals(getWrittenResources()[0].specName, "prune_plan");

  // A plan hash that does not match prunes nothing.
  await assertRejects(
    () => m.methods.prune.execute(base({ plan_sha256: HOST }), context),
    Error,
    "changed since planning",
  );
  assertEquals(
    host.files.get(`${ROOT}/sha256/${orphan}/y.txt`)?.content,
    "orphan\n",
  );

  // The matching plan deletes exactly the orphan and reindexes.
  await m.methods.prune.execute(
    base({ plan_sha256: plan.planSha256 }),
    context,
  );
  assertEquals(host.files.has(`${ROOT}/sha256/${orphan}/y.txt`), false);
  assertEquals(host.files.has(`${ROOT}/sha256/${refHash}/x.txt`), true);
});

Deno.test("install writes the site, enables it and reports the change", async () => {
  const host = makeFakeRemote();
  const { m, context, getWrittenResources } = modelFor(host);
  const result = await m.methods.install.execute(
    base({ ...SITE_ARGS, tls: { mode: "none", plaintext_ack: true } }),
    context,
  );
  assertEquals((result.result as { changed: boolean }).changed, true);
  assertEquals(
    host.files.get(NGINX_SITE_PATH)?.content.includes("autoindex off;"),
    true,
  );
  assertEquals(host.symlinks.has(NGINX_ENABLED_PATH), true);
  assertEquals(getWrittenResources()[0].specName, "config");
  // A second, identical install changes nothing.
  const again = await m.methods.install.execute(
    base({ ...SITE_ARGS, tls: { mode: "none", plaintext_ack: true } }),
    context,
  );
  assertEquals((again.result as { changed: boolean }).changed, false);
});

Deno.test("install restores the previous config and never reloads when nginx -t fails", async () => {
  const host = makeFakeRemote();
  host.setFile(NGINX_SITE_PATH, "previous\n", "644");
  host.failNginxTest = true;
  const { m, context } = modelFor(host);
  await assertRejects(
    () =>
      m.methods.install.execute(
        base({ ...SITE_ARGS, tls: { mode: "none", plaintext_ack: true } }),
        context,
      ),
    Error,
    "nginx -t failed",
  );
  assertEquals(host.files.get(NGINX_SITE_PATH)?.content, "previous\n");
  assertEquals(
    host.commands.some((c) => c.includes("argv:systemctl reload")),
    false,
  );
});

Deno.test("uninstall is a clean no-op when the site is absent", async () => {
  const host = makeFakeRemote();
  const { m, context } = modelFor(host);
  const result = await m.methods.uninstall.execute(base(), context);
  assertEquals(result.result, {
    removed: false,
    credentials_removed: 0,
    data_removed: false,
  });
});

Deno.test("uninstall removes the site and, when asked, the data root", async () => {
  const host = makeFakeRemote();
  await seed(host);
  host.setFile(NGINX_SITE_PATH, "server {}\n", "644");
  host.symlinks.add(NGINX_ENABLED_PATH);
  const { m, context } = modelFor(host);
  const result = await m.methods.uninstall.execute(
    base({ remove_data: true }),
    context,
  );
  assertEquals(result.result, {
    removed: true,
    credentials_removed: 0,
    data_removed: true,
  });
  assertEquals(host.files.has(NGINX_SITE_PATH), false);
  assertEquals(host.symlinks.has(NGINX_ENABLED_PATH), false);
  assertEquals(
    [...host.files.keys()].some((p) => p.startsWith(`${ROOT}/`)),
    false,
  );
});

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
