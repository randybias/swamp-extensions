// Runs the generated account scripts under a real POSIX shell with stub
// `getent`, `id`, `usermod` and `gpasswd`, in a scratch state directory.
import { assertEquals } from "jsr:@std/assert@1.0.19";
import { planApplyBase, REVOKE_SKIPPED } from "./plans.ts";
import { STATE_DIR } from "./armed_revert.ts";

const INPUT = {
  sudo: false,
  packages: [],
  adminUser: "newops",
  authorizedKeys: [],
  sysctl: {},
  timezone: "UTC",
  revoke: ["oldops"],
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
  // getent passwd USER: exit 2 when ${dir}/absent exists (no such account), 1
  // when ${dir}/getent-fails exists (an NSS or LDAP error), else an entry.
  await stub(
    "getent",
    `[ ! -e "${dir}/absent" ] || exit 2
[ ! -e "${dir}/getent-fails" ] || exit 1
echo "$2:x:1:1::${dir}/home/$2:/bin/bash"`,
  );
  // runuser -u USER -- CMD...: logs the call and runs CMD as the current user.
  await stub(
    "runuser",
    `echo "$@" >> "${dir}/runuser.log"
shift 3
exec "$@"`,
  );
  // gpasswd -d USER sudo: removes the group from the stub's group list unless
  // ${dir}/gpasswd-fails exists (a lock held, an NSS error).
  await stub(
    "gpasswd",
    `echo "$@" >> "${dir}/gpasswd.log"
[ ! -e "${dir}/gpasswd-fails" ] || exit 1
sed -i 's/ sudo//' "${dir}/groups"`,
  );
  // stat -c %U PATH: the owner is the account whose home holds the path.
  await stub(
    "stat",
    `case "$3" in */home/*/.ssh) basename "$(dirname "$3")";; *) echo root;; esac`,
  );
  await stub("usermod", `echo "$@" >> "${dir}/usermod.log"`);
  // `id -u` succeeds; `id -nG` lists the groups in ${dir}/groups.
  await stub(
    "id",
    `case "$1" in -u) exit 0;; -nG) [ ! -e "${dir}/id-fails" ] || exit 1; [ -e "${dir}/groups" ] && cat "${dir}/groups";; esac`,
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
    await Deno.writeTextFile(`${b.dir}/groups`, "oldops sudo\n");
    assertEquals(
      await b.run(script("revoke grants of oldops")),
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
      await b.run(script("revoke grants of oldops")),
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

Deno.test("revoke: a failing gpasswd keeps the marker and fails the step so a rerun retries", async () => {
  const b = await box();
  try {
    await Deno.writeTextFile(`${b.state}/sudo-granted-oldops`, "");
    await Deno.writeTextFile(`${b.dir}/groups`, "oldops sudo\n");
    await Deno.writeTextFile(`${b.dir}/gpasswd-fails`, "");
    const code = await b.run(script("revoke grants of oldops"));
    assertEquals(code !== 0 && code !== 3, true);
    assertEquals(await b.exists(`${b.state}/sudo-granted-oldops`), true);
  } finally {
    await Deno.remove(b.dir, { recursive: true });
  }
});

Deno.test("revoke: only an account that is verifiably absent counts as revoked", async () => {
  const b = await box();
  try {
    await Deno.writeTextFile(`${b.state}/sudo-granted-oldops`, "");
    await Deno.writeTextFile(`${b.dir}/absent`, "");
    assertEquals(await b.run(script("revoke grants of oldops")), 0);
    assertEquals(await b.exists(`${b.state}/sudo-granted-oldops`), false);
  } finally {
    await Deno.remove(b.dir, { recursive: true });
  }
});

Deno.test("revoke: when gpasswd AND id both fail, the step fails and the marker is kept", async () => {
  const b = await box();
  try {
    await Deno.writeTextFile(`${b.state}/sudo-granted-oldops`, "");
    await Deno.writeTextFile(`${b.dir}/groups`, "oldops sudo\n");
    await Deno.writeTextFile(`${b.dir}/gpasswd-fails`, "");
    await Deno.writeTextFile(`${b.dir}/id-fails`, "");
    const code = await b.run(script("revoke grants of oldops"));
    assertEquals(code !== 0 && code !== 3, true);
    assertEquals(await b.exists(`${b.state}/sudo-granted-oldops`), true);
  } finally {
    await Deno.remove(b.dir, { recursive: true });
  }
});

Deno.test("revoke: a failing account lookup is an error, never 'gone'", async () => {
  const b = await box();
  try {
    await Deno.writeTextFile(`${b.state}/sudo-granted-oldops`, "");
    await Deno.writeTextFile(`${b.dir}/getent-fails`, "");
    const code = await b.run(script("revoke grants of oldops"));
    assertEquals(code !== 0 && code !== 3, true);
    assertEquals(await b.exists(`${b.state}/sudo-granted-oldops`), true);
    assertEquals(await b.read("home/oldops/.ssh/authorized_keys"), "k\n");
  } finally {
    await Deno.remove(b.dir, { recursive: true });
  }
});

Deno.test("revoke: the keys file is removed as the account itself, not as root", async () => {
  const b = await box();
  try {
    assertEquals(await b.run(script("revoke grants of oldops")), 0);
    assertEquals(
      await b.read("runuser.log"),
      `-u oldops -- rm -f ${b.dir}/home/oldops/.ssh/authorized_keys\n`,
    );
  } finally {
    await Deno.remove(b.dir, { recursive: true });
  }
});

Deno.test("revoke: a symlinked ~/.ssh is left alone (exit 3) and nothing behind it is deleted", async () => {
  const b = await box();
  try {
    // oldops/.ssh points at another account's directory with live keys.
    await Deno.mkdir(`${b.dir}/home/login/.ssh`, { recursive: true });
    await Deno.writeTextFile(
      `${b.dir}/home/login/.ssh/authorized_keys`,
      "login-key\n",
    );
    await Deno.remove(`${b.dir}/home/oldops/.ssh`, { recursive: true });
    await Deno.symlink(`${b.dir}/home/login/.ssh`, `${b.dir}/home/oldops/.ssh`);
    await Deno.writeTextFile(`${b.state}/sudo-granted-oldops`, "");
    await Deno.writeTextFile(`${b.dir}/groups`, "oldops sudo\n");
    const code = await b.run(script("revoke grants of oldops"));
    assertEquals(code, REVOKE_SKIPPED);
    assertEquals(
      await b.read("home/login/.ssh/authorized_keys"),
      "login-key\n",
    );
    // The sudo part is still taken back.
    assertEquals(await b.read("gpasswd.log"), "-d oldops sudo\n");
  } finally {
    await Deno.remove(b.dir, { recursive: true });
  }
});

Deno.test("revoke: a ~/.ssh owned by someone else is left alone", async () => {
  const b = await box();
  try {
    // The stat stub reports the owner as the directory's parent name; make it differ.
    await Deno.mkdir(`${b.dir}/home/oldops/x`, { recursive: true });
    await Deno.writeTextFile(
      `${b.dir}/bin/stat`,
      "#!/bin/sh\necho someone-else\n",
    );
    const code = await b.run(script("revoke grants of oldops"));
    assertEquals(code, REVOKE_SKIPPED);
    assertEquals(await b.read("home/oldops/.ssh/authorized_keys"), "k\n");
  } finally {
    await Deno.remove(b.dir, { recursive: true });
  }
});
