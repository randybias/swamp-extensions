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
 * by a restart therefore leaves the old credential enforced.
 */
function daemonBox(initial: Record<string, string> = {}) {
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
      return { code: 0, stdout: loadedAuth ? "401" : "200" };
    }
    return serverResponder(command);
  });
  return { box, restarts: () => restarts.length };
}

const FRAGMENT = "/etc/apt-cacher-ng/zzzz-apt-cache.conf";
const BACKENDS_DEBIAN = "/etc/apt-cacher-ng/backends_debian";
const BACKUP_DEBIAN = `${BACKENDS_DEBIAN}.apt-cache.bak`;

Deno.test("apply twice then remove deletes the model's files and restores the original", async () => {
  const box = boxFake(
    { [BACKENDS_DEBIAN]: "original debian mirror\n" },
    serverResponder,
  );
  useFake(box.fake);
  const c = ctx();
  const args = model.methods.apply_server.arguments.parse({
    ssh: SSH,
    ...serverArgs({ listen: ["192.0.2.20"] }),
  });
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

const applyArgsOf = (overrides: Record<string, unknown> = {}) =>
  model.methods.apply_server.arguments.parse({
    ssh: SSH,
    ...serverArgs({ listen: ["192.0.2.20"], ...overrides }),
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
  let enforced = false;
  const box = boxFake({}, (command) => {
    if (command.includes("Count+Data")) {
      return { code: 0, stdout: enforced ? "401" : "200" };
    }
    return serverResponder(command);
  });
  useFake(box.fake);
  setDeps({ resolveSecret: () => Promise.resolve("admin:s3cret") });
  const c = ctx();
  enforced = true;
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
