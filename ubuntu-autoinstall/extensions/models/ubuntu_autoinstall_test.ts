import { assert, assertEquals, assertRejects } from "jsr:@std/assert@1.0.19";
import { AutoinstallError } from "./_lib/errors.ts";
import { model, setDeps } from "./ubuntu_autoinstall.ts";
import {
  createCtx,
  fakeRemote,
  HASH,
  publishArgs,
  renderArgs,
  SERVER,
} from "./_lib/testkit.ts";
import type { SshDeps } from "./_lib/ssh.ts";

const written = (c: { getWrittenResources(): { data: unknown }[] }) =>
  c.getWrittenResources().map((r) => r.data);

Deno.test("render returns no secret and stores the bytes only as a sensitive resource", async () => {
  const c = createCtx();
  const out = await model.methods.render.execute(renderArgs(), c.context) as {
    result: Record<string, unknown>;
  };
  const dump = JSON.stringify(out.result);
  assert(!dump.includes(HASH));
  assertEquals("contents" in out.result, false);
  const resources = written(c);
  const render = resources.find((r) =>
    typeof r === "object" && r !== null && "tree_sha256" in r
  ) as Record<string, unknown>;
  const files = resources.find((r) =>
    typeof r === "object" && r !== null && "user-data" in r
  ) as Record<string, unknown>;
  assert(render !== undefined && files !== undefined);
  assert(!JSON.stringify(render).includes(HASH));
  assert(String(files["user-data"]).includes('"password":'));
});

Deno.test("validate requires the header and reports findings", async () => {
  const c = createCtx();
  const bad = await model.methods.validate.execute({
    user_data: "autoinstall:\n  version: 1\n",
  }, c.context) as { result: { valid: boolean } };
  assertEquals(bad.result.valid, false);
  const ok = await model.methods.validate.execute({
    user_data:
      `#cloud-config\nautoinstall:\n  version: 1\n  identity:\n    hostname: web-1\n    username: installer\n    password: '${HASH}'\n`,
  }, c.context) as { result: { valid: boolean } };
  assertEquals(ok.result.valid, true);
});

Deno.test("publish_http writes the bundle and ref, then is a no-op", async () => {
  const fake = fakeRemote();
  const prev = setDeps(fake.deps);
  try {
    const c = createCtx();
    const first = await model.methods.publish_http.execute(
      publishArgs(),
      c.context,
    ) as {
      result: { changed: boolean; tree_sha256: string; seed_url: string };
    };
    assertEquals(first.result.changed, true);
    const tree = first.result.tree_sha256;
    for (
      const name of ["user-data", "meta-data", "vendor-data", "SHA256SUMS"]
    ) {
      assert(fake.fs.has(`/srv/artifacts/bundles/${tree}/${name}`));
    }
    assertEquals(
      fake.fs.get("/srv/artifacts/refs/autoinstall-web-1")?.content,
      `bundle ${tree}\n`,
    );
    assert(!fake.calls.map((x) => x.args.join(" ")).join().includes(HASH));
    const second = await model.methods.publish_http.execute(
      publishArgs(),
      c.context,
    ) as {
      result: { changed: boolean };
    };
    assertEquals(second.result.changed, false);
  } finally {
    setDeps(prev);
  }
});

Deno.test("publish_http re-converges a rewritten ref and a corrupted bundle", async () => {
  const fake = fakeRemote();
  const prev = setDeps(fake.deps);
  try {
    const c = createCtx();
    const first = await model.methods.publish_http.execute(
      publishArgs(),
      c.context,
    ) as {
      result: { tree_sha256: string };
    };
    const tree = first.result.tree_sha256;
    // A missing ref is a change even when the bundle is intact.
    fake.fs.delete("/srv/artifacts/refs/autoinstall-web-1");
    const refAgain = await model.methods.publish_http.execute(
      publishArgs(),
      c.context,
    ) as {
      result: { changed: boolean };
    };
    assertEquals(refAgain.result.changed, true);
    // A corrupted bundle file is a change too.
    fake.fs.set(`/srv/artifacts/bundles/${tree}/user-data`, {
      content: "x",
      mode: "0644",
    });
    const bundleAgain = await model.methods.publish_http.execute(
      publishArgs(),
      c.context,
    ) as {
      result: { changed: boolean };
    };
    assertEquals(bundleAgain.result.changed, true);
  } finally {
    setDeps(prev);
  }
});

Deno.test("get and sync distinguish present, mismatch and not_found", async () => {
  const fake = fakeRemote();
  const prev = setDeps(fake.deps);
  try {
    const c = createCtx();
    const empty = await model.methods.get.execute(publishArgs(), c.context) as {
      result: { status: string };
    };
    assertEquals(empty.result.status, "not_found");
    const pub = await model.methods.publish_http.execute(
      publishArgs(),
      c.context,
    ) as {
      result: { tree_sha256: string };
    };
    const present = await model.methods.sync.execute(
      publishArgs(),
      c.context,
    ) as {
      result: { status: string };
    };
    assertEquals(present.result.status, "present");
    fake.fs.set(`/srv/artifacts/bundles/${pub.result.tree_sha256}/meta-data`, {
      content: "x",
      mode: "0644",
    });
    const mismatch = await model.methods.get.execute(
      publishArgs(),
      c.context,
    ) as {
      result: { status: string };
    };
    assertEquals(mismatch.result.status, "mismatch");
  } finally {
    setDeps(prev);
  }
});

Deno.test("unpublish removes the ref's bundle and is a clean no-op", async () => {
  const fake = fakeRemote();
  const prev = setDeps(fake.deps);
  try {
    const c = createCtx();
    const absent = await model.methods.unpublish.execute({
      ssh: SERVER.ssh,
      root: SERVER.root,
      hostname: "web-1",
    }, c.context) as { result: { status: string } };
    assertEquals(absent.result.status, "not_found");
    const pub = await model.methods.publish_http.execute(
      publishArgs(),
      c.context,
    ) as {
      result: { tree_sha256: string };
    };
    const gone = await model.methods.unpublish.execute({
      ssh: SERVER.ssh,
      root: SERVER.root,
      hostname: "web-1",
    }, c.context) as { result: { status: string } };
    assertEquals(gone.result.status, "deleted");
    assert(!fake.fs.has("/srv/artifacts/refs/autoinstall-web-1"));
    assert(
      !fake.fs.has(
        `/srv/artifacts/bundles/${pub.result.tree_sha256}/user-data`,
      ),
    );
  } finally {
    setDeps(prev);
  }
});

Deno.test("unpublish refuses a tree hash that names another host's bundle", async () => {
  const fake = fakeRemote();
  const prev = setDeps(fake.deps);
  try {
    const c = createCtx();
    const a = await model.methods.publish_http.execute(
      publishArgs(),
      c.context,
    ) as {
      result: { tree_sha256: string };
    };
    const b = await model.methods.publish_http.execute(
      publishArgs({
        identity: {
          hostname: "web-2",
          username: "installer",
          password_hash: HASH,
        },
      }),
      c.context,
    ) as { result: { tree_sha256: string } };
    // A's ref is present, so B's tree is a conflict and nothing is deleted.
    const e = await assertRejects(
      () =>
        model.methods.unpublish.execute({
          ssh: SERVER.ssh,
          root: SERVER.root,
          hostname: "web-1",
          tree_sha256: b.result.tree_sha256,
        }, c.context),
      AutoinstallError,
    );
    assertEquals((e as AutoinstallError).code, "conflict");
    assert(
      fake.fs.has(`/srv/artifacts/bundles/${b.result.tree_sha256}/user-data`),
    );
    assert(
      fake.fs.has(`/srv/artifacts/bundles/${a.result.tree_sha256}/user-data`),
    );
    // With no ref, a bundle that does not record the hostname is refused too.
    fake.fs.delete("/srv/artifacts/refs/autoinstall-web-1");
    const e2 = await assertRejects(
      () =>
        model.methods.unpublish.execute({
          ssh: SERVER.ssh,
          root: SERVER.root,
          hostname: "web-1",
          tree_sha256: b.result.tree_sha256,
        }, c.context),
      AutoinstallError,
    );
    assertEquals((e2 as AutoinstallError).code, "conflict");
  } finally {
    setDeps(prev);
  }
});

Deno.test("unpublish with a tree_sha256 is idempotent when the bundle is gone", async () => {
  const fake = fakeRemote();
  const prev = setDeps(fake.deps);
  try {
    const c = createCtx();
    // A bundle with no ref, then deleted by tree hash twice.
    const pub = await model.methods.publish_http.execute(
      publishArgs(),
      c.context,
    ) as {
      result: { tree_sha256: string };
    };
    fake.fs.delete("/srv/artifacts/refs/autoinstall-web-1");
    const first = await model.methods.unpublish.execute({
      ssh: SERVER.ssh,
      root: SERVER.root,
      hostname: "web-1",
      tree_sha256: pub.result.tree_sha256,
    }, c.context) as { result: { status: string } };
    assertEquals(first.result.status, "deleted");
    const again = await model.methods.unpublish.execute({
      ssh: SERVER.ssh,
      root: SERVER.root,
      hostname: "web-1",
      tree_sha256: pub.result.tree_sha256,
    }, c.context) as { result: { status: string } };
    assertEquals(again.result.status, "not_found");
  } finally {
    setDeps(prev);
  }
});

Deno.test("a transport failure is typed and leaves no state", async () => {
  const failing: SshDeps = {
    run: () => {
      throw new Error("boom");
    },
    now: () => 0,
    sleep: () => Promise.resolve(),
  };
  const prev = setDeps(failing);
  try {
    const c = createCtx();
    const e = await assertRejects(
      () => model.methods.publish_http.execute(publishArgs(), c.context),
      AutoinstallError,
    );
    assertEquals((e as AutoinstallError).code, "transport");
    assertEquals(c.getWrittenResources().length, 0);
  } finally {
    setDeps(prev);
  }
});

Deno.test("injection strings are inert data in the quoted YAML", async () => {
  const c = createCtx();
  const out = await model.methods.render.execute(
    renderArgs({
      late_commands: [{ argv: ["echo", "$(id)", "; rm -rf /", "a: b", "---"] }],
      locale: "en_US.UTF-8",
    }),
    c.context,
  ) as { result: { tree_sha256: string } };
  assertEquals(out.result.tree_sha256.length, 64);
  const files = written(c).find((r) =>
    typeof r === "object" && r !== null && "user-data" in r
  ) as Record<string, string>;
  assert(files["user-data"].includes('"$(id)"'));
  assert(files["user-data"].includes('"; rm -rf /"'));
});

Deno.test("a seed URL with userinfo or a semicolon is refused by the schema", () => {
  const userinfo = "https://u" + ":p" + "@seed.example.com/x/";
  for (const url of [userinfo, "https://seed.example.com/x;/"]) {
    assertEquals(
      model.methods.cmdline.arguments.safeParse({ seed_url: url }).success,
      false,
      url,
    );
  }
});

Deno.test("every resource name written in one method run is unique", async () => {
  const c = createCtx();
  await model.methods.render.execute(renderArgs(), c.context);
  const names = c.getWrittenResources().map((r) => r.name);
  assertEquals(new Set(names).size, names.length, names.join(","));
  assert(names.some((n) => n.endsWith("-render")));
  assert(names.some((n) => n.endsWith("-files")));

  const fake = fakeRemote();
  const prev = setDeps(fake.deps);
  try {
    const p = createCtx();
    await model.methods.publish_http.execute(publishArgs(), p.context);
    const written = p.getWrittenResources().map((r) => r.name);
    assertEquals(new Set(written).size, written.length);
  } finally {
    setDeps(prev);
  }
});
