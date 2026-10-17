/**
 * Managed-file ownership tests for `@randybias/apt-cache` server methods: what
 * apply_server backs up, restores, removes and restarts for, against a box
 * whose daemon only reloads on restart.
 *
 * @module
 */

import { assertEquals, assertRejects } from "jsr:@std/assert@1.0.19";
import { SECURITY_CONF_PATH } from "./apt.ts";
import { model, setDeps } from "../apt_cache.ts";
import { type Box, boxFake, type Resp, useFake } from "./test_support.ts";
import { ctx, NOW, serverArgs, SSH } from "./model_test_support.ts";
import { serverName } from "./remote.ts";
import { sha256Hex } from "./ssh.ts";

/** A responder for the host probes apply_server and remove_server need. */
function serverResponder(command: string): Resp {
  if (command.includes("is-active")) return { code: 0, stdout: "active\n" };
  if (command.includes("-ltn")) {
    return {
      code: 0,
      stdout:
        "State Recv-Q Send-Q Local Address:Port Peer Address:Port\nLISTEN 0 4096 192.0.2.20:3142 0.0.0.0:*\n",
    };
  }
  if (command.includes("dpkg-query")) {
    return { code: 0, stdout: "install ok installed\n" };
  }
  return {};
}

/**
 * A box whose daemon only picks up security.conf when it is restarted, like
 * apt-cacher-ng: an unauthenticated administrative request gets 401 while the
 * LOADED configuration holds an AdminAuth line. A change that is not followed
 * by a restart therefore leaves the old credential enforced. `openStatus` is
 * what the page answers when no credential is loaded.
 */
function daemonBox(initial: Record<string, string> = {}, openStatus = "200") {
  let loadedAuth = false;
  const restarts: number[] = [];
  const box: Box = boxFake(initial, (command) => {
    if (command.includes("'systemctl' 'restart'")) {
      restarts.push(box.fake.commands.length);
      loadedAuth = /^AdminAuth:/m.test(
        box.files.get(SECURITY_CONF_PATH)?.content ?? "",
      );
      return {};
    }
    if (command.includes("Count+Data")) {
      return { code: 0, stdout: loadedAuth ? "401" : openStatus };
    }
    return serverResponder(command);
  });
  return { box, restarts: () => restarts.length };
}

const FRAGMENT = "/etc/apt-cacher-ng/zzzz-apt-cache.conf";
const applyArgsOf = (overrides: Record<string, unknown> = {}) =>
  model.methods.apply_server.arguments.parse({
    ssh: SSH,
    ...serverArgs({ listen: ["192.0.2.20"], ...overrides }),
  });
const BACKENDS_DEBIAN = "/etc/apt-cacher-ng/backends_debian";
const BACKUP_DEBIAN = `${BACKENDS_DEBIAN}.apt-cache.bak`;

Deno.test("apply twice then remove deletes the model's files and restores the original", async () => {
  const box = boxFake(
    { [BACKENDS_DEBIAN]: "original debian mirror\n" },
    serverResponder,
  );
  useFake(box.fake);
  const c = ctx();
  const args = applyArgsOf();
  await model.methods.apply_server.execute(args, c.context);
  await model.methods.apply_server.execute(args, c.context);
  // The original was saved once, on the first apply; the second must not back
  // up the model's own output.
  assertEquals(
    box.files.get(BACKUP_DEBIAN)?.content,
    "original debian mirror\n",
  );

  const out = await model.methods.remove_server.execute(
    model.methods.remove_server.arguments.parse({
      ssh: SSH,
      confirm_host: "192.0.2.20",
      purge_cache_ack: true,
    }),
    c.context,
  );
  assertEquals(out.result.removed, true);
  assertEquals(box.files.has(FRAGMENT), false, "fragment left behind");
  assertEquals(
    box.files.get(BACKENDS_DEBIAN)?.content,
    "original debian mirror\n",
    "original backend file not restored",
  );
  assertEquals(box.files.has(BACKUP_DEBIAN), false);
});

const ADMIN_REF = { vault: "default", key: "ADMIN" };

Deno.test("dropping admin_auth_ref removes the file, restarts the daemon and the old credential is refused", async () => {
  const { box, restarts } = daemonBox();
  useFake(box.fake);
  setDeps({ resolveSecret: () => Promise.resolve("admin:s3cret") });
  const c = ctx();
  await model.methods.apply_server.execute(
    applyArgsOf({ admin_auth_ref: ADMIN_REF }),
    c.context,
  );
  assertEquals(box.files.has(SECURITY_CONF_PATH), true);
  assertEquals(restarts(), 1);
  // Only the credential changes; the fragment and backends are identical.
  const out = await model.methods.apply_server.execute(
    applyArgsOf(),
    c.context,
  );
  assertEquals(box.files.has(SECURITY_CONF_PATH), false);
  // The dropped file alone triggers the restart, so the daemon no longer
  // enforces the old credential (the verify step fails otherwise).
  assertEquals(restarts(), 2);
  assertEquals(out.result.changed, true);
  assertEquals(
    JSON.stringify(
      (c.getWrittenResources().at(-1)?.data as {
        managed_files: Record<string, string>;
      }).managed_files,
    ).includes("security.conf"),
    false,
  );
});

Deno.test("a missing restart after dropping the credential fails the apply", async () => {
  // A daemon that never reloads: the old credential stays enforced.
  const box = boxFake({}, (command) => {
    if (command.includes("Count+Data")) return { code: 0, stdout: "401" };
    return serverResponder(command);
  });
  useFake(box.fake);
  setDeps({ resolveSecret: () => Promise.resolve("admin:s3cret") });
  const c = ctx();
  await model.methods.apply_server.execute(
    applyArgsOf({ admin_auth_ref: ADMIN_REF }),
    c.context,
  );
  const e = await assertRejects(
    () => model.methods.apply_server.execute(applyArgsOf(), c.context),
    Error,
    "still enforces the dropped admin credential",
  ) as { code?: string };
  assertEquals(e.code, "verify_failed");
});

Deno.test("after dropping the credential, only HTTP 200 proves the admin page is open", async () => {
  // The restart unloads the credential, but the admin page then answers 500.
  const { box } = daemonBox({}, "500");
  useFake(box.fake);
  setDeps({ resolveSecret: () => Promise.resolve("admin:s3cret") });
  const c = ctx();
  await model.methods.apply_server.execute(
    applyArgsOf({ admin_auth_ref: ADMIN_REF }),
    c.context,
  );
  const e = await assertRejects(
    () => model.methods.apply_server.execute(applyArgsOf(), c.context),
    Error,
    "HTTP 500",
  ) as { code?: string };
  assertEquals(e.code, "verify_failed");
  // The probe must reach the local daemon, never an environment proxy.
  assertEquals(
    box.fake.commands.some((cmd) =>
      cmd.includes("Count+Data") && cmd.includes("'--noproxy' '*'")
    ),
    true,
  );
});

Deno.test("dropping only a backend key restarts the daemon", async () => {
  const { box, restarts } = daemonBox();
  useFake(box.fake);
  const c = ctx();
  await model.methods.apply_server.execute(
    applyArgsOf({
      backends: {
        debian: ["http://deb.example.test/debian/"],
        ubuntu: ["http://ubuntu.example.test/ubuntu/"],
      },
    }),
    c.context,
  );
  const before = restarts();
  await model.methods.apply_server.execute(
    applyArgsOf({ backends: { debian: ["http://deb.example.test/debian/"] } }),
    c.context,
  );
  assertEquals(restarts(), before + 1);
});

Deno.test("a restored admin file is the admin's own: nothing is assumed about its credential", async () => {
  const { box } = daemonBox({
    [SECURITY_CONF_PATH]: "AdminAuth: ops:theirs\n",
  });
  useFake(box.fake);
  setDeps({ resolveSecret: () => Promise.resolve("admin:s3cret") });
  const c = ctx();
  await model.methods.apply_server.execute(
    applyArgsOf({ admin_auth_ref: ADMIN_REF }),
    c.context,
  );
  // Dropping the ref restores the original, which still enforces its own
  // credential; the apply must not call that a failure.
  await model.methods.apply_server.execute(applyArgsOf(), c.context);
  assertEquals(
    box.files.get(SECURITY_CONF_PATH)?.content,
    "AdminAuth: ops:theirs\n",
  );
});

Deno.test("a tampered record cannot make apply remove an arbitrary path", async () => {
  const { box } = daemonBox({ "/etc/passwd": "root\n" });
  useFake(box.fake);
  const c = ctx({
    storedResources: {
      [serverName({ host: SSH.host, user: SSH.user, port: SSH.port })]: {
        target: "root@192.0.2.20:22",
        host: "192.0.2.20",
        installed: true,
        managed_files: {
          "/etc/passwd": await sha256Hex(new TextEncoder().encode("root\n")),
        },
        observed_at: new Date(NOW).toISOString(),
      },
    },
  });
  await model.methods.apply_server.execute(applyArgsOf(), c.context);
  assertEquals(box.files.get("/etc/passwd")?.content, "root\n");
  assertEquals(box.fake.removed.includes("/etc/passwd"), false);
});

// --- install: never an open proxy, lists refreshed first --------------------

/**
 * A box for install_server: the package is "absent" until the install command
 * runs, then present; `ss` reports `listeners` once it is installed.
 */
function installBox(initialListeners: string) {
  let installed = false;
  let listeners = initialListeners;
  const box: Box = boxFake({}, (command) => {
    if (command.includes("debconf-set-selections")) {
      installed = true;
      return {};
    }
    if (command.includes("-f=${Status}")) {
      return installed
        ? { code: 0, stdout: "install ok installed\n" }
        : { code: 1, stdout: "" };
    }
    if (command.includes("-f=${Version}")) {
      return { code: 0, stdout: "3.7.4-1\n" };
    }
    if (command.includes("'ss'")) {
      return {
        code: 0,
        stdout:
          `State Recv-Q Send-Q Local Address:Port Peer Address:Port\n${listeners}`,
      };
    }
    return serverResponder(command);
  });
  return { box, listen: (lines: string) => (listeners = lines) };
}

const installArgs = () =>
  model.methods.install_server.arguments.parse({ ssh: SSH });
const LOOPBACK_ONLY = "LISTEN 0 250 127.0.0.1:3142 0.0.0.0:*\n";

Deno.test("install_server refreshes the lists, then writes the loopback fragment, then installs", async () => {
  const { box } = installBox(LOOPBACK_ONLY);
  useFake(box.fake);
  const c = ctx();
  await model.methods.install_server.execute(installArgs(), c.context);
  const at = (needle: string) =>
    box.fake.commands.findIndex((cmd) => cmd.includes(needle));
  const update = at("'update'");
  const fragment = box.fake.uploads.findIndex((u) => u.path === FRAGMENT);
  const install = at("debconf-set-selections");
  assertEquals(update >= 0 && install >= 0 && fragment >= 0, true);
  // The fragment upload is a command too: find it by its script marker.
  const uploadAt = at(".ssh-host-upload");
  assertEquals(update < uploadAt && uploadAt < install, true);
  assertEquals(
    box.files.get(FRAGMENT)?.content.includes("BindAddress: 127.0.0.1"),
    true,
  );
  // The record owns the bootstrap fragment, so apply treats it as its own.
  const record = c.getWrittenResources()[0].data as {
    managed_files: Record<string, string>;
  };
  assertEquals(Object.keys(record.managed_files), [FRAGMENT]);
});

Deno.test("a wildcard listener after install stops the daemon and fails without state", async () => {
  const { box } = installBox(
    "LISTEN 0 250 0.0.0.0:3142 0.0.0.0:*\nLISTEN 0 250 [::]:3142 [::]:*\n",
  );
  useFake(box.fake);
  const c = ctx();
  const e = await assertRejects(
    () => model.methods.install_server.execute(installArgs(), c.context),
    Error,
    "listens on",
  ) as { code?: string };
  assertEquals(e.code, "open_listener");
  assertEquals(
    box.fake.commands.some((cmd) => cmd.includes("'systemctl' 'stop'")),
    true,
  );
  assertEquals(c.getWrittenResources().length, 0);
});

Deno.test("a failing apt-get update stops install before anything is written or installed", async () => {
  const box = boxFake({}, (command) => {
    if (command.includes("-f=${Status}")) return { code: 1, stdout: "" };
    if (command.includes("'update'")) {
      return {
        code: 100,
        stderr: "E: Failed to fetch http://mirror.example.test",
      };
    }
    return serverResponder(command);
  });
  useFake(box.fake);
  const c = ctx();
  await assertRejects(
    () => model.methods.install_server.execute(installArgs(), c.context),
    Error,
    "apt-get update failed (exit 100)",
  );
  assertEquals(box.files.has(FRAGMENT), false);
  assertEquals(
    box.fake.commands.some((cmd) => cmd.includes("debconf-set-selections")),
    false,
  );
  assertEquals(c.getWrittenResources().length, 0);
});

Deno.test("install, apply, remove: the bootstrap fragment is the model's own and is deleted, not 'restored'", async () => {
  const { box, listen } = installBox(LOOPBACK_ONLY);
  useFake(box.fake);
  const c = ctx();
  await model.methods.install_server.execute(installArgs(), c.context);
  listen("LISTEN 0 250 192.0.2.20:3142 0.0.0.0:*\n");
  await model.methods.apply_server.execute(applyArgsOf(), c.context);
  assertEquals(box.files.has(`${FRAGMENT}.apt-cache.bak`), false);
  const live = box.files.get(FRAGMENT)?.content ?? "";
  assertEquals(live.includes("loopback only until apply_server"), false);
  assertEquals(live.includes("192.0.2.20"), true);
  await model.methods.remove_server.execute(
    model.methods.remove_server.arguments.parse({
      ssh: SSH,
      confirm_host: "192.0.2.20",
    }),
    c.context,
  );
  assertEquals(box.files.has(FRAGMENT), false);
});
