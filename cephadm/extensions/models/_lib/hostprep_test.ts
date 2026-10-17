import { assertEquals, assertRejects } from "jsr:@std/assert@1.0.19";
import { PhaseError, SudoPolicyError, TransportError } from "./errors.ts";
import {
  busyProbeScript,
  cephadmHealth,
  classifyProbe,
  discoveryScript,
  ensureCephadm,
  ensureTimeSync,
  findingFor,
  isAptLockContention,
  parseAptSources,
  parseCephadmVersion,
  parseDpkgVersion,
  parseProbeLine,
  probeScript,
  runPackagePhase,
  sanitizeProxyLine,
  splitSections,
} from "./hostprep.ts";
import type { CommandResult, RunOptions, SshSession } from "./ssh.ts";

/** A scripted session: route sees the exact command string and throws when unrouted. */
function fakeSession(
  route: (opts: RunOptions) => CommandResult | Promise<CommandResult>,
  host = "192.0.2.10",
): { session: SshSession; calls: RunOptions[] } {
  const calls: RunOptions[] = [];
  const session: SshSession = {
    target: { host, user: "admin" },
    controlPath: null,
    run: async (opts) => {
      calls.push(opts);
      return await route(opts);
    },
    close: () =>
      Promise.resolve({ closed: false, detail: "not closed, multiplex off" }),
  };
  return { session, calls };
}

const ok = (stdout = "", code = 0, stderr = ""): CommandResult => ({
  code,
  stdout,
  stderr,
});

const deps = { now: () => 0, sleep: () => Promise.resolve(), random: () => 0 };

Deno.test("parseCephadmVersion reads the token after the word version", () => {
  assertEquals(
    parseCephadmVersion("cephadm version 19.2.1 (3f2a9c1e) squid (stable)"),
    "19.2.1",
  );
  assertEquals(parseCephadmVersion("something else"), null);
  assertEquals(parseCephadmVersion("cephadm version"), null);
});

Deno.test(
  "cephadm health compares the exact token, never a substring", // leak-allow(decision D14)
  () => {
    assertEquals(
      cephadmHealth(0, "cephadm version 19.2.1 (x) squid", "19.2.1").healthy,
      true,
    );
    assertEquals(
      cephadmHealth(0, "cephadm version 19.2.10 (x) squid", "19.2.1").healthy,
      false,
    );
    assertEquals(
      cephadmHealth(1, "cephadm version 19.2.1 (x)", "19.2.1").healthy,
      false,
    );
  },
);

Deno.test("parseDpkgVersion and apt lock detection", () => {
  assertEquals(
    parseDpkgVersion(
      "Package: chrony\nStatus: install ok installed\nVersion: 4.3-2\n",
    ),
    "4.3-2",
  );
  assertEquals(parseDpkgVersion(""), undefined);
  assertEquals(
    isAptLockContention("E: Could not get lock /var/lib/dpkg/lock-frontend"),
    true,
  );
  assertEquals(isAptLockContention("E: Unable to locate package foo"), false);
});

Deno.test("the busy probe uses fuser and pgrep and only `idle` means idle", () => {
  const script = busyProbeScript();
  assertEquals(script.includes("fuser"), true);
  assertEquals(script.includes("pgrep -x"), true);
  assertEquals(script.includes("echo idle"), true);
  assertEquals(script.includes("apt-get"), true);
});

Deno.test("V8-style URL host extraction strips userinfo and port via apt parsing", () => {
  const endpoints = parseAptSources(
    [
      "# comment",
      "deb [arch=amd64 signed-by=/k.gpg] http://deb.example.com/debian bookworm main",
      "URIs: https://u:p@mirror.test:8443/ubuntu http://archive.example.com/ubuntu",
      "deb file:/srv/repo ./",
      "",
    ].join("\n"),
  );
  assertEquals(endpoints, [
    { name: "deb.example.com", scheme: "http", origin: "apt-source" },
    { name: "mirror.test", scheme: "https", origin: "apt-source" },
    { name: "archive.example.com", scheme: "http", origin: "apt-source" },
  ]);
  assertEquals(parseAptSources("# only comments\n"), []);
});

Deno.test("apt proxy lines are stored without credentials", () => {
  assertEquals(
    sanitizeProxyLine(
      'Acquire::http::Proxy "http://user:pass@proxy.test:3128";',
    ),
    'Acquire::http::Proxy "http://proxy.test:3128";',
  );
  assertEquals(
    sanitizeProxyLine(
      'Acquire::https::Proxy "https://token@proxy.test";',
    ),
    'Acquire::https::Proxy "https://proxy.test";',
  );
});

Deno.test("section splitting discards lines under unknown markers", () => {
  const sections = splitSections(
    [
      "garbage before any marker",
      "###CEPHADM-SOURCES###",
      "deb http://deb.example.com/debian stable main",
      "###UNKNOWN###",
      "deb http://ignored.example.com/debian stable main",
      "###CEPHADM-PROXY###",
      'Acquire::http::Proxy "http://proxy.test:3128";',
      "###CEPHADM-PROBES###",
    ].join("\n"),
  );
  assertEquals(sections.sources.includes("deb.example.com"), true);
  assertEquals(sections.sources.includes("ignored.example.com"), false);
  assertEquals(sections.proxy.includes("Proxy"), true);
});

Deno.test(
  "probe lines classify resolution and reachability separately", // leak-allow(decision D16)
  () => {
    assertEquals(parseProbeLine("few|fields"), null);
    const noAddr = parseProbeLine("deb.example.com|http||||")!;
    assertEquals(classifyProbe(noAddr, "apt-source").outcome, "cannot-resolve");
    const refused = parseProbeLine("deb.example.com|http|192.0.2.10|7|000")!;
    const refusedOut = classifyProbe(refused, "apt-source");
    assertEquals(refusedOut.outcome, "cannot-reach");
    assertEquals(refusedOut.curlExit, 7);
    for (const status of ["200", "301", "403", "404", "500"]) {
      const p = parseProbeLine(
        `mirror.test|https|192.0.2.10|0|${status}`,
      )!;
      assertEquals(classifyProbe(p, "apt-source").outcome, "reached");
    }
    assertEquals(
      findingFor(classifyProbe(noAddr, "apt-source")).includes("DNS"),
      true,
    );
    assertEquals(
      findingFor(classifyProbe(refused, "apt-source")).includes("not DNS"),
      true,
    );
  },
);

Deno.test("probe and discovery scripts use no sudo and quote discovered names", () => {
  const script = probeScript([{
    name: "deb.example.com",
    scheme: "http",
    origin: "apt-source",
  }]);
  assertEquals(script.includes("getent hosts"), true);
  assertEquals(script.includes("curl"), true);
  assertEquals(script.includes("sudo"), false);
  assertEquals(script.includes("'deb.example.com'"), true);
  assertEquals(discoveryScript().includes("###CEPHADM-SOURCES###"), true);
  assertEquals(discoveryScript().includes("apt-config dump"), true);
  assertEquals(discoveryScript().includes("sudo"), false);
});

Deno.test("package phase: a ready host issues no apt call", async () => {
  const { session, calls } = fakeSession((opts) => {
    if (opts.command === "bash -s --") return ok("idle\n");
    if (opts.command.startsWith("dpkg -s ")) {
      return ok("Package: chrony\nVersion: 4.3-2\n");
    }
    throw new Error(`unexpected ${opts.command}`);
  });
  const result = await runPackagePhase(deps, session, {
    packages: ["chrony"],
    budgetMs: 0,
  });
  assertEquals(result.packages[0].alreadyPresent, true);
  assertEquals(result.packages[0].installedVersion, "4.3-2");
  assertEquals(result.evidence.installAttempts, 0);
  assertEquals(calls.some((c) => c.command.startsWith("apt-get")), false);
});

Deno.test("package phase installs only the missing packages", async () => {
  let installed = false;
  const { session, calls } = fakeSession((opts) => {
    if (opts.command === "bash -s --") return ok("idle\n");
    if (opts.command.startsWith("dpkg -s ")) {
      return installed ? ok("Version: 1\n") : ok("", 1);
    }
    if (opts.command === "apt-get update") return ok();
    if (opts.command.startsWith("apt-get install")) {
      installed = true;
      return ok();
    }
    throw new Error(`unexpected ${opts.command}`);
  });
  const result = await runPackagePhase(deps, session, {
    packages: ["chrony", "lvm2"],
    budgetMs: 0,
  });
  const install = calls.find((c) => c.command.startsWith("apt-get install"))!;
  assertEquals(install.command, "apt-get install -y 'chrony' 'lvm2'");
  assertEquals(install.sudo, true);
  assertEquals(result.evidence.installAttempts, 1);
});

Deno.test(
  "apt reports success but dpkg still misses a package: packages-absent", // leak-allow(decision D16)
  async () => {
    const { session } = fakeSession((opts) => {
      if (opts.command === "bash -s --") return ok("idle\n");
      if (opts.command.startsWith("dpkg -s ")) return ok("", 1);
      if (opts.command === "apt-get update") return ok();
      if (opts.command.startsWith("apt-get install")) return ok();
      throw new Error(`unexpected ${opts.command}`);
    });
    await assertRejects(
      () =>
        runPackagePhase(deps, session, {
          packages: ["chrony"],
          budgetMs: 60_000,
        }),
      PhaseError,
      "packages-absent",
    );
  },
);

Deno.test("apt refuses: fail fast with apt-install and zero sleeps", async () => {
  let sleeps = 0;
  const { session } = fakeSession((opts) => {
    if (opts.command === "bash -s --") return ok("idle\n");
    if (opts.command.startsWith("dpkg -s ")) return ok("", 1);
    if (opts.command === "apt-get update") return ok();
    if (opts.command.startsWith("apt-get install")) {
      return ok("", 100, "E: Unable to locate package chrony");
    }
    throw new Error(`unexpected ${opts.command}`);
  });
  await assertRejects(
    () =>
      runPackagePhase(
        {
          now: () => 0,
          sleep: () => (sleeps++, Promise.resolve()),
          random: () => 0,
        },
        session,
        { packages: ["chrony"], budgetMs: 60_000 },
      ),
    PhaseError,
    "apt-install",
  );
  assertEquals(sleeps, 0);
});

Deno.test("a lock race is treated as busy, then succeeds", async () => {
  let reads = 0;
  let installs = 0;
  const { session } = fakeSession((opts) => {
    if (opts.command === "bash -s --") {
      reads++;
      return ok(reads <= 1 ? "idle\n" : "idle\n");
    }
    if (opts.command.startsWith("dpkg -s ")) {
      return ok("", installs > 0 ? 0 : 1);
    }
    if (opts.command === "apt-get update") return ok();
    if (opts.command.startsWith("apt-get install")) {
      installs++;
      if (installs === 1) {
        return ok("", 100, "E: Could not get lock /var/lib/dpkg/lock-frontend");
      }
      return ok();
    }
    throw new Error(`unexpected ${opts.command}`);
  });
  const result = await runPackagePhase(deps, session, {
    packages: ["chrony"],
    budgetMs: 60_000,
  });
  assertEquals(result.packages[0].alreadyPresent, false);
  assertEquals(result.evidence.busyWaits, 1);
});

Deno.test(
  "a mid-session loss with no budget reports an UNKNOWN outcome", // leak-allow(decision D8)
  async () => {
    const { session } = fakeSession((opts) => {
      if (opts.command === "bash -s --") {
        throw new TransportError({
          host: "192.0.2.10",
          port: 22,
          user: "admin",
          kind: "other",
          cause: null,
          message: "session lost",
        });
      }
      throw new Error(`unexpected ${opts.command}`);
    });
    await assertRejects(
      () =>
        runPackagePhase(deps, session, { packages: ["chrony"], budgetMs: 0 }),
      PhaseError,
      "UNKNOWN",
    );
  },
);

Deno.test("ready host: ensureCephadm does not download", async () => {
  const { session, calls } = fakeSession((opts) => {
    if (opts.command.startsWith("test -x ")) return ok();
    if (opts.command.endsWith(" version")) {
      return ok("cephadm version 19.2.1 (x) squid");
    }
    throw new Error(`unexpected ${opts.command}`);
  });
  const result = await ensureCephadm(session, {
    url: "https://download.example.com/cephadm",
    version: "19.2.1",
  });
  assertEquals(result.alreadyPresent, true);
  assertEquals(result.reinstalledBroken, false);
  assertEquals(calls.some((c) => c.command.includes("curl")), false);
  assertEquals(calls[1].sudo, true);
});

Deno.test("a cephadm reporting the wrong version is reinstalled", async () => {
  let probed = 0;
  const { session, calls } = fakeSession((opts) => {
    if (opts.command.startsWith("test -x ")) return ok();
    if (opts.command.endsWith(" version")) {
      probed++;
      return ok(
        probed === 1
          ? "cephadm version 19.2.10 (x)"
          : "cephadm version 19.2.1 (x)",
      );
    }
    if (opts.command.startsWith("curl ")) return ok();
    if (opts.command.startsWith("chmod ")) return ok();
    throw new Error(`unexpected ${opts.command}`);
  });
  const result = await ensureCephadm(session, {
    url: "https://download.example.com/cephadm",
    version: "19.2.1",
  });
  assertEquals(result.reinstalledBroken, true);
  assertEquals(calls.some((c) => c.command.startsWith("curl ")), true);
});

Deno.test("a fresh install that still reports the wrong version throws", async () => {
  const { session } = fakeSession((opts) => {
    if (opts.command.startsWith("test -x ")) return ok("", 1);
    if (opts.command.startsWith("curl ")) return ok();
    if (opts.command.startsWith("chmod ")) return ok();
    if (opts.command.endsWith(" version")) {
      return ok("cephadm version 19.2.0 (x)");
    }
    throw new Error(`unexpected ${opts.command}`);
  });
  await assertRejects(
    () =>
      ensureCephadm(session, {
        url: "https://download.example.com/cephadm",
        version: "19.2.1",
      }),
    PhaseError,
    "cephadm-verify",
  );
});

Deno.test("time sync: already active does not enable; inactive enables then rechecks", async () => {
  const active = fakeSession((opts) => {
    if (opts.command.startsWith("systemctl is-active")) return ok("active\n");
    throw new Error(`unexpected ${opts.command}`);
  });
  assertEquals(await ensureTimeSync(active.session, "chrony"), {
    wasActive: true,
    active: true,
  });
  assertEquals(active.calls.some((c) => c.command.includes("enable")), false);

  let enabled = false;
  const inactive = fakeSession((opts) => {
    if (opts.command.startsWith("systemctl is-active")) {
      return ok(enabled ? "active\n" : "inactive\n");
    }
    if (opts.command.startsWith("systemctl enable")) {
      enabled = true;
      return ok();
    }
    throw new Error(`unexpected ${opts.command}`);
  });
  assertEquals(await ensureTimeSync(inactive.session, "chrony"), {
    wasActive: false,
    active: true,
  });
});

Deno.test("time sync never becoming active throws", async () => {
  const { session } = fakeSession((opts) => {
    if (opts.command.startsWith("systemctl is-active")) return ok("inactive\n");
    if (opts.command.startsWith("systemctl enable")) return ok();
    throw new Error(`unexpected ${opts.command}`);
  });
  await assertRejects(
    () => ensureTimeSync(session, "chrony"),
    PhaseError,
    "time-sync",
  );
});

Deno.test("hostprep rejects a sudo refusal even when a command allows non-zero", async () => {
  const { session } = fakeSession((opts) => {
    if (opts.command === "bash -s --") {
      throw new SudoPolicyError("passwordless sudo is required");
    }
    throw new Error(`unexpected ${opts.command}`);
  });
  await assertRejects(
    () => runPackagePhase(deps, session, { packages: ["chrony"], budgetMs: 0 }),
    SudoPolicyError,
  );
});

Deno.test("the busy phase with a budget ends at apt-busy without sleeping past it", async () => {
  let t = 0;
  const sleeps: number[] = [];
  const { session } = fakeSession((opts) => {
    if (opts.command === "bash -s --") return ok("busy\n");
    throw new Error(`unexpected ${opts.command}`);
  });
  await assertRejects(
    () =>
      runPackagePhase(
        {
          now: () => t,
          sleep: (ms) => {
            sleeps.push(ms);
            t += ms;
            return Promise.resolve();
          },
          random: () => 0,
        },
        session,
        { packages: ["chrony"], budgetMs: 10_000 },
      ),
    PhaseError,
    "apt-busy",
  );
  assertEquals(sleeps.every((s) => s <= 10_000 && s >= 1), true);
});
