/**
 * Server-method behaviour tests for `@randybias/apt-cache`: the schema
 * preconditions, install/render/apply/remove, the read-only get/sync/stats
 * probes, managed-file ownership, and the guarded real-acng route check.
 *
 * @module
 */

import {
  assertEquals,
  assertRejects,
  assertThrows,
} from "jsr:@std/assert@1.0.19";
import { SshError } from "./ssh.ts";
import { renderBackendFiles, renderServerFragment } from "./apt.ts";
import { model } from "../apt_cache.ts";
import { fakeApt, has, hasTok, type Resp, useFake } from "./test_support.ts";
import { ctx, SERVER, serverArgs, SSH } from "./model_test_support.ts";

// --- schema and in-method preconditions -------------------------------------

Deno.test("schema: strict host keys, required policy, sensitive refs", () => {
  assertThrows(() =>
    model.methods.get.arguments.parse({
      ssh: { ...SSH, host_key_policy: "insecure_tofu" },
    })
  );
  assertThrows(() =>
    model.methods.get.arguments.parse({ ssh: { ...SSH, host_keys: [] } })
  );
  const parsed = model.methods.get.arguments.parse({ ssh: SSH });
  assertEquals(parsed.ssh.ssh_key_ref.vault, "default");
  const refMeta = (model.methods.get.arguments.shape as unknown as {
    ssh: { shape: { ssh_key_ref: { meta: () => { sensitive?: boolean } } } };
  }).ssh.shape.ssh_key_ref.meta();
  assertEquals(refMeta.sensitive, true);
  // https_policy has no default.
  assertThrows(() =>
    model.methods.apply_server.arguments.parse({
      ssh: SSH,
      listen: ["192.0.2.20"],
    })
  );
});

Deno.test("in-method: wildcard listen and passthrough hosts are refused", async () => {
  useFake(fakeApt(() => ({})));
  for (const wild of ["0.0.0.0", "::", "::0", "[::]"]) { // leak-allow(unspecified-address spellings under test)
    await assertRejects(
      () =>
        model.methods.apply_server.execute(
          model.methods.apply_server.arguments.parse({
            ssh: SSH,
            ...serverArgs({ listen: [wild] }),
          }),
          ctx().context,
        ),
      Error,
      "listen_any_ack",
    );
  }
  await assertRejects(
    () =>
      model.methods.apply_server.execute(
        model.methods.apply_server.arguments.parse({
          ssh: SSH,
          ...serverArgs({ https_policy: "passthrough", passthrough_hosts: [] }),
        }),
        ctx().context,
      ),
    Error,
    "passthrough_hosts",
  );
});

Deno.test("in-method: the debian-security key is refused", async () => {
  useFake(fakeApt(() => ({})));
  await assertRejects(
    () =>
      model.methods.apply_server.execute(
        model.methods.apply_server.arguments.parse({
          ssh: SSH,
          ...serverArgs({
            backends: {
              "debian-security": ["http://deb.debian.org/debian-security/"],
            },
          }),
        }),
        ctx().context,
      ),
    Error,
    "debian-security",
  );
});

Deno.test("in-method: backend scheme must match the HTTPS policy", async () => {
  useFake(fakeApt(() => ({})));
  await assertRejects(
    () =>
      model.methods.apply_server.execute(
        model.methods.apply_server.arguments.parse({
          ssh: SSH,
          ...serverArgs({
            backends: { debian: ["https://deb.debian.org/debian/"] },
          }),
        }),
        ctx().context,
      ),
    Error,
    "plain http mirror",
  );
});

// --- render_server ----------------------------------------------------------

Deno.test("render_server returns the fragment and backends with sha256", async () => {
  useFake(fakeApt(() => ({})));
  const args = model.methods.render_server.arguments.parse({
    ...SERVER,
    passthrough_hosts: [],
    listen: ["192.0.2.20"],
  });
  const c = ctx();
  const out = await model.methods.render_server.execute(args, c.context);
  assertEquals(
    out.result.fragment.path,
    "/etc/apt-cacher-ng/zzzz-apt-cache.conf",
  );
  assertEquals(
    out.result.fragment.text.includes("BindAddress: 192.0.2.20"),
    true,
  );
  assertEquals(out.result.fragment.text.includes("PassThroughPattern:"), true);
  // `debian` is shadowed by the built-in Remap-debrep, so its backend file is
  // the package's built-in file, not a zzzz- file.
  assertEquals(
    out.result.backends[0].path,
    "/etc/apt-cacher-ng/backends_debian",
  );
  assertEquals(out.result.fragment.sha256.length, 64);
  assertEquals(c.getWrittenResources().length, 1);
  // The render record must not clobber the `server` spec.
  const written = c.getWrittenResources()[0].data as Record<string, unknown>;
  assertEquals("installed" in written, false);
  assertEquals(typeof written.fragment_sha256, "string");
  assertEquals(written.listen, ["192.0.2.20"]);
});

// --- install_server ---------------------------------------------------------

Deno.test("install_server preseed-no, installs and reads the version", async () => {
  const fake = fakeApt((command) => {
    if (command.includes("dpkg-query") && command.includes("-f=${Status}")) {
      return { code: 1, stdout: "" };
    }
    if (command.includes("debconf-set-selections")) return { code: 0 };
    if (command.includes("-f=${Version}")) {
      return { code: 0, stdout: "3.7.4-1\n" };
    }
    return { code: 0 };
  });
  useFake(fake);
  const c = ctx();
  const out = await model.methods.install_server.execute(
    model.methods.install_server.arguments.parse({ ssh: SSH }),
    c.context,
  );
  assertEquals(out.result, { host: "192.0.2.20", version: "3.7.4-1" });
  assertEquals(
    fake.commands.some((cmd) =>
      cmd.includes("apt-cacher-ng apt-cacher-ng/tunnelenable boolean false")
    ),
    true,
  );
  assertEquals(c.getWrittenResources()[0].data.installed, true);
});

Deno.test("install_server adopts an installed package", async () => {
  const fake = fakeApt((command) => {
    if (command.includes("-f=${Status}")) {
      return { code: 0, stdout: "install ok installed\n" };
    }
    if (command.includes("-f=${Version}")) {
      return { code: 0, stdout: "3.7.4-1\n" };
    }
    return { code: 0 };
  });
  useFake(fake);
  const out = await model.methods.install_server.execute(
    model.methods.install_server.arguments.parse({ ssh: SSH }),
    ctx().context,
  );
  assertEquals(out.result.version, "3.7.4-1");
  assertEquals(has(fake, "debconf-set-selections"), false);
});

Deno.test("install_server surfaces a sanitized apt failure, no state", async () => {
  const fake = fakeApt((command) => {
    if (command.includes("-f=${Status}")) return { code: 1, stdout: "" };
    if (command.includes("debconf-set-selections")) {
      return {
        code: 100,
        stderr: "E: Unable to locate package apt-cacher-ng\n",
      };
    }
    return { code: 0 };
  });
  useFake(fake);
  const c = ctx();
  await assertRejects(
    () =>
      model.methods.install_server.execute(
        model.methods.install_server.arguments.parse({ ssh: SSH }),
        c.context,
      ),
    Error,
    "Unable to locate package",
  );
  assertEquals(c.getWrittenResources().length, 0);
});

// --- apply_server -----------------------------------------------------------

Deno.test("apply_server writes, restarts and verifies; idempotent on re-run", async () => {
  const fake = fakeApt((command) => {
    if (command.includes("sha256sum")) return { code: 1 };
    if (command.includes("dpkg-query")) {
      return { code: 0, stdout: "install ok installed\n" };
    }
    if (command.includes("is-active")) return { code: 0, stdout: "active\n" };
    if (command.includes("-ltn")) {
      return {
        code: 0,
        stdout:
          "State Recv-Q Send-Q Local Address:Port Peer Address:Port\nLISTEN 0 4096 192.0.2.20:3142 0.0.0.0:*\n",
      };
    }
    if (command.includes("curl")) return { code: 0 };
    return { code: 0 };
  });
  useFake(fake);
  const c = ctx();
  const args = model.methods.apply_server.arguments.parse({
    ssh: SSH,
    ...serverArgs({ listen: ["192.0.2.20"], listen_any_ack: false }),
  });
  const out = await model.methods.apply_server.execute(args, c.context);
  assertEquals(out.result.changed, true);
  assertEquals(out.result.https_policy, "direct");
  assertEquals(
    fake.uploads.some((u) => u.path.endsWith("zzzz-apt-cache.conf")),
    true,
  );
  assertEquals(hasTok(fake, "systemctl", "restart"), true);
});

// --- remove_server ----------------------------------------------------------

Deno.test("remove_server no-op when absent; purges when present", async () => {
  const absent = fakeApt((command) => {
    if (command.includes("-f=${Status}")) return { code: 1, stdout: "" };
    return { code: 0 };
  });
  useFake(absent);
  const a = await model.methods.remove_server.execute(
    model.methods.remove_server.arguments.parse({
      ssh: SSH,
      confirm_host: "192.0.2.20",
    }),
    ctx().context,
  );
  assertEquals(a.result.removed, false);
  assertEquals(has(absent, "apt-get purge"), false);

  const installed = (command: string): Resp | undefined => {
    if (command.includes("-f=${Status}")) {
      return { code: 0, stdout: "install ok installed\n" };
    }
    if (command.includes("cat") && command.includes("zzzz-apt-cache.conf")) {
      return { code: 0, stdout: "CacheDir: /var/cache/apt-cacher-ng\n" };
    }
    if (command.startsWith("'test' '-L'")) return { code: 1 }; // not a symlink
    if (command.startsWith("'test' '-d'")) return { code: 0 }; // present
    return undefined;
  };

  // No ack: apt-get remove, managed files removed, cache left in place.
  const noAck = fakeApt((command) => installed(command) ?? { code: 0 });
  useFake(noAck);
  const n = await model.methods.remove_server.execute(
    model.methods.remove_server.arguments.parse({
      ssh: SSH,
      confirm_host: "192.0.2.20",
    }),
    ctx().context,
  );
  assertEquals(n.result, {
    host: "192.0.2.20",
    removed: true,
    cache_purged: false,
  });
  assertEquals(has(noAck, "apt-get remove"), true);
  assertEquals(has(noAck, "apt-get purge"), false);
  assertEquals(noAck.removed.includes("/var/cache/apt-cacher-ng"), false);

  // With ack: apt-get purge and the cache directory is deleted.
  const present = fakeApt((command) => installed(command) ?? { code: 0 });
  useFake(present);
  const p = await model.methods.remove_server.execute(
    model.methods.remove_server.arguments.parse({
      ssh: SSH,
      confirm_host: "192.0.2.20",
      purge_cache_ack: true,
    }),
    ctx().context,
  );
  assertEquals(p.result, {
    host: "192.0.2.20",
    removed: true,
    cache_purged: true,
  });
  assertEquals(has(present, "apt-get purge"), true);
  assertEquals(present.removed.includes("/var/cache/apt-cacher-ng"), true);
});

Deno.test("remove_server purges a package left in config-files", async () => {
  const fake = fakeApt((command) => {
    if (command.includes("-f=${Status}")) {
      return { code: 0, stdout: "deinstall ok config-files\n" };
    }
    if (command.includes("cat") && command.includes("zzzz-apt-cache.conf")) {
      return { code: 0, stdout: "CacheDir: /var/cache/apt-cacher-ng\n" };
    }
    if (command.startsWith("'test' '-L'")) return { code: 1 };
    if (command.startsWith("'test' '-d'")) return { code: 0 };
    return { code: 0 };
  });
  useFake(fake);
  const out = await model.methods.remove_server.execute(
    model.methods.remove_server.arguments.parse({
      ssh: SSH,
      confirm_host: "192.0.2.20",
      purge_cache_ack: true,
    }),
    ctx().context,
  );
  assertEquals(out.result, {
    host: "192.0.2.20",
    removed: true,
    cache_purged: true,
  });
  assertEquals(has(fake, "apt-get purge"), true);
  assertEquals(hasTok(fake, "systemctl", "stop"), false);
});

Deno.test("remove_server refuses a cache_dir that is not the server's", async () => {
  const fake = fakeApt((command) => {
    if (command.includes("-f=${Status}")) {
      return { code: 0, stdout: "install ok installed\n" };
    }
    if (command.includes("cat") && command.includes("zzzz-apt-cache.conf")) {
      return { code: 0, stdout: "CacheDir: /var/cache/apt-cacher-ng\n" };
    }
    return { code: 0 };
  });
  useFake(fake);
  await assertRejects(
    () =>
      model.methods.remove_server.execute(
        model.methods.remove_server.arguments.parse({
          ssh: SSH,
          confirm_host: "192.0.2.20",
          purge_cache_ack: true,
          cache_dir: "/srv/other",
        }),
        ctx().context,
      ),
    Error,
    "does not match",
  );
  assertEquals(fake.removed.includes("/srv/other"), false);
});

Deno.test("remove_server refuses a symlinked cache directory", async () => {
  const fake = fakeApt((command) => {
    if (command.includes("-f=${Status}")) {
      return { code: 0, stdout: "install ok installed\n" };
    }
    if (command.includes("cat") && command.includes("zzzz-apt-cache.conf")) {
      return { code: 0, stdout: "CacheDir: /var/cache/apt-cacher-ng\n" };
    }
    if (command.startsWith("'test' '-L'")) return { code: 0 }; // it IS a symlink
    return { code: 0 };
  });
  useFake(fake);
  await assertRejects(
    () =>
      model.methods.remove_server.execute(
        model.methods.remove_server.arguments.parse({
          ssh: SSH,
          confirm_host: "192.0.2.20",
          purge_cache_ack: true,
        }),
        ctx().context,
      ),
    Error,
    "symlink",
  );
  assertEquals(fake.removed.includes("/var/cache/apt-cacher-ng"), false);
});

Deno.test("remove_server refuses a mismatched confirm_host", async () => {
  useFake(fakeApt(() => ({})));
  await assertRejects(
    () =>
      model.methods.remove_server.execute(
        model.methods.remove_server.arguments.parse({
          ssh: SSH,
          confirm_host: "192.0.2.99",
        }),
        ctx().context,
      ),
    Error,
    "does not match",
  );
});

// --- sync -------------------------------------------------------------------

Deno.test("sync reports a widened passthrough and a missing fragment", async () => {
  const fake = fakeApt((command) => {
    if (command.includes("sha256sum")) return { code: 1 };
    if (command.includes("cat") && command.includes("zzzz-apt-cache.conf")) {
      return { code: 0, stdout: "PassThroughPattern: .*\n" };
    }
    if (command.includes("systemctl")) return { code: 0, stdout: "inactive\n" };
    if (command.includes("ss -ltn")) return { code: 1 };
    if (command.includes("du")) {
      return { code: 0, stdout: "10\t/var/cache/apt-cacher-ng\n" };
    }
    if (command.includes("df")) return { code: 0, stdout: "Avail\n100\n" };
    return { code: 0 };
  });
  useFake(fake);
  const out = await model.methods.sync.execute(
    model.methods.sync.arguments.parse({
      ssh: SSH,
      ...serverArgs({ listen: ["192.0.2.20"] }),
    }),
    ctx().context,
  );
  assertEquals(out.result.in_sync, false);
  assertEquals(
    out.result.drift.some((d) => d.startsWith("passthrough:")),
    true,
  );
});

// --- stats ------------------------------------------------------------------

Deno.test("stats reads the request log and fails closed on a bad log", async () => {
  const log = await Deno.readTextFile(
    new URL("./testdata/apt-cacher.log.txt", import.meta.url),
  );
  const fake = fakeApt((command) => {
    if (command.includes("cat")) return { code: 0, stdout: log };
    if (command.includes("-sb")) {
      return { code: 0, stdout: "3145728\t/var/cache/apt-cacher-ng\n" };
    }
    if (command.includes("--output=avail")) {
      return { code: 0, stdout: "Avail\n10485760\n" };
    }
    return { code: 0 };
  });
  // `today` = last 24h; pick now so since=1792252100 and until=1792338500.
  useFake(fake, (1792252100 + 86400) * 1000);
  const c = ctx();
  const out = await model.methods.stats.execute(
    model.methods.stats.arguments.parse({ ssh: SSH, window: "today" }),
    c.context,
  );
  assertEquals(out.result.hits, 1);
  assertEquals(out.result.misses, 1);
  assertEquals(out.result.requests, 2);
  assertEquals(out.result.bytes_from_cache, 100);
  assertEquals(out.result.bytes_upstream, 100);
  assertEquals(out.result.cache_bytes, 3145728);
  assertEquals(c.getWrittenResources().length, 1);

  const bad = fakeApt((command) => {
    if (command.includes("cat")) return { code: 0, stdout: "garbage\nmore" };
    return { code: 0 };
  });
  useFake(bad);
  const c2 = ctx();
  await assertRejects(
    () =>
      model.methods.stats.execute(
        model.methods.stats.arguments.parse({ ssh: SSH, window: "today" }),
        c2.context,
      ),
    Error,
    "unrecognised",
  );
  assertEquals(c2.getWrittenResources().length, 0);

  // A corrupt rotation exits 4, which is a distinct error from a missing log.
  const corrupt = fakeApt((command) => {
    if (command.includes("gzip -dc") || command.includes("cat")) {
      return { code: 4, stdout: "", stderr: "corrupt log" };
    }
    return { code: 0 };
  });
  useFake(corrupt);
  const failure = await assertRejects(
    () =>
      model.methods.stats.execute(
        model.methods.stats.arguments.parse({ ssh: SSH, window: "today" }),
        ctx().context,
      ),
    Error,
    "corrupt",
  ) as { code?: string };
  assertEquals(failure.code, "log_corrupt");
});

// --- transport and parsing helpers ------------------------------------------

Deno.test("a transport failure is typed and writes no state", async () => {
  const fake = fakeApt(() => ({
    code: 255,
    stderr: "Permission denied (publickey).",
  }));
  useFake(fake);
  const c = ctx();
  await assertRejects(
    () =>
      model.methods.get.execute(
        model.methods.get.arguments.parse({ ssh: SSH }),
        c.context,
      ),
    SshError,
  );
  assertEquals(c.getWrittenResources().length, 0);
});

// --- real-tool route check (docker) -----------------------------------------

const LISTEN_PL = `use IO::Socket::INET;
my ($port, $out) = @ARGV;
my $s = IO::Socket::INET->new(LocalPort=>$port, Listen=>64, Reuse=>1) or die "$port: $!";
open(my $fh, ">", $out) or die;
$fh->autoflush(1);
while (my $c = $s->accept) { print $fh "$port\\n"; close $c; }
`;

const ROUTE_RUN_SH = `#!/bin/sh
set -eu
CONF=/tmp/conf
rm -rf "$CONF" /tmp/cache /tmp/log /tmp/hit80 /tmp/hit443
mkdir -p "$CONF" /tmp/cache /tmp/log
cp -a /etc/apt-cacher-ng/. "$CONF"/
cp /w/fragment.conf "$CONF/zzzz-apt-cache.conf"
cp -f /w/backends/* "$CONF/"
printf '127.0.0.1 deb.debian.org ftp.debian.org security.debian.org cdn-fastly.deb.debian.org ports.ubuntu.com archive.ubuntu.com security.ubuntu.com\\n' >> /etc/hosts
chown -R apt-cacher-ng:apt-cacher-ng /tmp/cache /tmp/log 2>/dev/null || true
perl /w/listen.pl 80 /tmp/hit80 & L80=$!
perl /w/listen.pl 443 /tmp/hit443 & L443=$!
sleep 0.5
apt-cacher-ng -c "$CONF" LogDir=/tmp/log CacheDir=/tmp/cache >/tmp/acng.out 2>&1 & ACNG=$!
sleep 1.5
probe() {
  : > /tmp/hit80
  : > /tmp/hit443
  if [ "$1" = proxy ]; then
    curl -sS --max-time 6 -x http://127.0.0.1:3142 -o /dev/null "$2" || true
  else
    curl -sS --max-time 6 -o /dev/null "http://127.0.0.1:3142$2" || true
  fi
  sleep 0.3
  echo "$3 hit80=$(wc -l < /tmp/hit80) hit443=$(wc -l < /tmp/hit443)"
}
probe proxy "http://deb.debian.org/debian/dists/bookworm/Release" debian-proxy
probe path "/debian/dists/bookworm/Release" debian-path
probe proxy "http://ports.ubuntu.com/ubuntu-ports/dists/noble/Release" ports-proxy
probe path "/ubuntu-ports/dists/noble/Release" ports-path
kill $ACNG $L80 $L443 2>/dev/null || true
`;

async function dockerImage(name: string): Promise<boolean> {
  try {
    const out = await new Deno.Command("docker", {
      args: ["image", "inspect", name],
      stdout: "null",
      stderr: "null",
    }).output();
    return out.code === 0;
  } catch {
    return false;
  }
}

Deno.test("real acng routes https_backends over TLS for proxy- and path-style", async () => {
  if (!(await dockerImage("acng-d5:latest"))) {
    console.warn(
      "acng-d5:latest not present; skipping the real-tool route check",
    );
    return;
  }
  const backends = {
    debian: ["https://deb.debian.org/debian/"],
    "ubuntu-ports": ["https://ports.ubuntu.com/ubuntu-ports/"],
  };
  const fragment = renderServerFragment({
    listen: ["0.0.0.0"],
    port: 3142,
    https_policy: "https_backends",
    passthrough_hosts: [],
    backends,
    expire_days: 4,
    cache_dir: "/tmp/cache",
  });
  const dir = await Deno.makeTempDir({ prefix: "apt-cache-route-" });
  try {
    await Deno.writeTextFile(`${dir}/fragment.conf`, fragment);
    await Deno.mkdir(`${dir}/backends`);
    for (const file of renderBackendFiles(backends, "https")) {
      const name = file.path.split("/").pop() as string;
      await Deno.writeTextFile(`${dir}/backends/${name}`, file.text);
    }
    await Deno.writeTextFile(`${dir}/listen.pl`, LISTEN_PL);
    await Deno.writeTextFile(`${dir}/run.sh`, ROUTE_RUN_SH);
    const out = await new Deno.Command("docker", {
      args: [
        "run",
        "--rm",
        "--network",
        "none",
        "-v",
        `${dir}:/w:ro`,
        "acng-d5:latest",
        "bash",
        "/w/run.sh",
      ],
      stdout: "piped",
      stderr: "piped",
    }).output();
    const text = new TextDecoder().decode(out.stdout) +
      new TextDecoder().decode(out.stderr);
    assertEquals(out.code, 0, text);
    for (
      const label of [
        "debian-proxy",
        "debian-path",
        "ports-proxy",
        "ports-path",
      ]
    ) {
      const match = new RegExp(`${label} hit80=(\\d+) hit443=(\\d+)`).exec(
        text,
      );
      if (!match) throw new Error(`no result for ${label}:\n${text}`);
      assertEquals(Number(match[1]), 0, `${label} fetched over http (80)`);
      assertEquals(
        Number(match[2]) >= 1,
        true,
        `${label} did not use https (443)`,
      );
    }
  } finally {
    await Deno.remove(dir, { recursive: true });
  }
});
