// Runs the generated account scripts under a real POSIX shell with stub
// `getent`, `id`, `usermod` and `gpasswd`, in a scratch state directory.
import { assertEquals } from "jsr:@std/assert@1.0.19";
import { planApplyBase } from "./plans.ts";
import { STATE_DIR } from "./armed_revert.ts";

const INPUT = {
  sudo: false,
  packages: [],
  adminUser: "newops",
  authorizedKeys: [],
  sysctl: {},
  timezone: "UTC",
  previousAdmin: "oldops",
};

const script = (label: string) => {
  const step = planApplyBase(INPUT, [
    "revoke_previous",
    "admin_user",
  ]).find((s) => s.label === label)!;
  return { script: step.argv[2], args: step.argv.slice(4) };
};

async function box() {
  const dir = await Deno.makeTempDir({ prefix: "wgbase-" });
  const bin = `${dir}/bin`;
  const state = `${dir}/state`;
  await Deno.mkdir(bin);
  await Deno.mkdir(state);
  await Deno.mkdir(`${dir}/home/oldops/.ssh`, { recursive: true });
  await Deno.writeTextFile(`${dir}/home/oldops/.ssh/authorized_keys`, "k\n");
  const stub = async (n: string, body: string) => {
    await Deno.writeTextFile(`${bin}/${n}`, `#!/bin/sh\n${body}\n`);
    await Deno.chmod(`${bin}/${n}`, 0o755);
  };
  await stub("getent", `echo "$2:x:1:1::${dir}/home/$2:/bin/bash"`);
  await stub("gpasswd", `echo "$@" >> "${dir}/gpasswd.log"`);
  await stub("usermod", `echo "$@" >> "${dir}/usermod.log"`);
  // `id -u` succeeds; `id -nG` lists the groups in ${dir}/groups.
  await stub(
    "id",
    `case "$1" in -u) exit 0;; -nG) cat "${dir}/groups" 2>/dev/null;; esac`,
  );
  const run = async (s: { script: string; args: string[] }) => {
    const out = await new Deno.Command("sh", {
      args: ["-c", s.script.replaceAll(STATE_DIR, state), "sh", ...s.args],
      env: { PATH: `${bin}:/usr/bin:/bin` },
      stdout: "null",
      stderr: "null",
    }).output();
    return out.code;
  };
  const read = async (f: string) =>
    await Deno.readTextFile(`${dir}/${f}`).catch(() => null);
  const exists = (f: string) =>
    Deno.stat(f).then(() => true).catch(() => false);
  return { dir, state, run, read, exists };
}

Deno.test("revoke: removes the managed keys file, and the sudo grant only when this tool made it", async () => {
  const b = await box();
  try {
    // We granted sudo earlier: the marker is on the host.
    await Deno.writeTextFile(`${b.state}/sudo-granted-oldops`, "");
    assertEquals(
      await b.run(script("revoke previous admin account grants")),
      0,
    );
    assertEquals(
      await b.exists(`${b.dir}/home/oldops/.ssh/authorized_keys`),
      false,
    );
    assertEquals(await b.read("gpasswd.log"), "-d oldops sudo\n");
    assertEquals(await b.exists(`${b.state}/sudo-granted-oldops`), false);
    // The account itself is untouched (no userdel was ever involved).
    assertEquals(await b.exists(`${b.dir}/home/oldops`), true);
  } finally {
    await Deno.remove(b.dir, { recursive: true });
  }
});

Deno.test("revoke: a sudo membership this tool did not add is left alone", async () => {
  const b = await box();
  try {
    assertEquals(
      await b.run(script("revoke previous admin account grants")),
      0,
    );
    assertEquals(await b.read("gpasswd.log"), null);
    assertEquals(
      await b.exists(`${b.dir}/home/oldops/.ssh/authorized_keys`),
      false,
    );
  } finally {
    await Deno.remove(b.dir, { recursive: true });
  }
});

Deno.test("create: marks the sudo grant only when it added the membership", async () => {
  const b = await box();
  try {
    await Deno.writeTextFile(`${b.dir}/groups`, "newops users\n");
    assertEquals(await b.run(script("create admin user")), 0);
    assertEquals(await b.read("usermod.log"), "-aG sudo newops\n");
    assertEquals(await b.exists(`${b.state}/sudo-granted-newops`), true);
  } finally {
    await Deno.remove(b.dir, { recursive: true });
  }
  const c = await box();
  try {
    await Deno.writeTextFile(`${c.dir}/groups`, "newops sudo\n");
    assertEquals(await c.run(script("create admin user")), 0);
    assertEquals(await c.read("usermod.log"), null);
    assertEquals(await c.exists(`${c.state}/sudo-granted-newops`), false);
  } finally {
    await Deno.remove(c.dir, { recursive: true });
  }
});
