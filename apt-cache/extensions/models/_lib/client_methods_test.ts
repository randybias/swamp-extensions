/**
 * Client-method behaviour tests for `@randybias/apt-cache`: configure_client,
 * client_get and unconfigure_client, including the policy, conflict, rollback
 * and vault paths.
 *
 * @module
 */

import {
  assertEquals,
  assertRejects,
  assertThrows,
} from "jsr:@std/assert@1.0.19";
import { model, setDeps } from "../apt_cache.ts";
import { boxFake, fakeApt, useFake } from "./test_support.ts";
import { CLIENT, ctx, NOW, SERVER, SSH } from "./model_test_support.ts";

Deno.test("grammar: injection in names, URLs and paths is refused", () => {
  for (
    const bad of [
      { ssh: { ...SSH, host: "192.0.2.20; id" } },
      { ssh: { ...SSH, user: "root$(id)" } },
      { proxy_url: "http://192.0.2.20:3142/; id" },
      { proxy_url: "http://user:pass@192.0.2.20:3142" },
      { proxy_url: "http://x$({touch,pwned})y:3142" },
      { proxy_url: 'http://x"y:3142' },
      { ...CLIENT, proxy_url: "https://192.0.2.20:3142" },
      { ...CLIENT, bypass_hosts: ["*.example.test"] },
      { listen: ["192.0.2.20\n0.0.0.0"] },
      { cache_dir: "/var/../etc" },
      { cache_dir: "/var" },
    ]
  ) {
    const merged = Object.assign({}, SERVER, CLIENT, bad) as Record<
      string,
      unknown
    >;
    assertThrows(() =>
      model.methods.configure_client.arguments.parse({
        ssh: SSH,
        ...merged,
      })
    );
  }
});

// --- configure_client / client_get / unconfigure_client ---------------------

Deno.test("configure_client writes and verifies the snippet", async () => {
  const fake = fakeApt((command) => {
    if (command.includes(".ssh-host-upload")) return { code: 0 };
    if (command.includes("sha256sum")) return { code: 1 };
    if (command.includes("grep -lE")) return { code: 0, stdout: "" };
    if (command.includes("apt-config")) {
      return {
        code: 0,
        stdout:
          `Acquire::http::Proxy "http://192.0.2.20:3142";\nAcquire::https::Proxy "DIRECT";\n`,
      };
    }
    return { code: 0 };
  });
  useFake(fake);
  const c = ctx();
  const out = await model.methods.configure_client.execute(
    model.methods.configure_client.arguments.parse({ ssh: SSH, ...CLIENT }),
    c.context,
  );
  assertEquals(out.result.verified, true);
  assertEquals(
    fake.uploads.some((u) => u.path.endsWith("90apt-cache-proxy")),
    true,
  );
  assertEquals(c.getWrittenResources()[0].data.present, true);
});

Deno.test("configure_client refuses a conflict without ack", async () => {
  const fake = fakeApt((command) => {
    if (command.includes("grep -lE")) {
      return { code: 0, stdout: "/etc/apt/apt.conf.d/02proxy\n" };
    }
    return { code: 0 };
  });
  useFake(fake);
  await assertRejects(
    () =>
      model.methods.configure_client.execute(
        model.methods.configure_client.arguments.parse({ ssh: SSH, ...CLIENT }),
        ctx().context,
      ),
    Error,
    "override_existing_ack",
  );
  assertEquals(
    fake.uploads.some((u) => u.path.endsWith("90apt-cache-proxy")),
    false,
  );
});

Deno.test("configure_client refuses a policy that disagrees with the server", async () => {
  const fake = fakeApt(() => ({}));
  useFake(fake);
  const c = ctx({}, {
    queryData: () =>
      Promise.resolve([{
        attributes: {
          host: "192.0.2.20",
          listen: ["192.0.2.20"],
          https_policy: "passthrough",
        },
      }]),
  });
  await assertRejects(
    () =>
      model.methods.configure_client.execute(
        model.methods.configure_client.arguments.parse({ ssh: SSH, ...CLIENT }),
        c.context,
      ),
    Error,
    "does not match the recorded server policy",
  );
});

Deno.test("configure_client rolls the snippet back on a failed verify", async () => {
  const fake = fakeApt((command) => {
    if (command.startsWith("'test' '-e'")) return { code: 1 };
    if (command.includes("cat")) return { code: 1 };
    if (command.includes("sha256sum")) return { code: 1 };
    if (command.includes("grep -lE")) return { code: 0, stdout: "" };
    if (command.includes("apt-config")) {
      return {
        code: 0,
        stdout: `Acquire::http::Proxy "http://192.0.2.9:3142";\n`,
      };
    }
    return { code: 0 };
  });
  useFake(fake);
  const c = ctx();
  await assertRejects(
    () =>
      model.methods.configure_client.execute(
        model.methods.configure_client.arguments.parse({ ssh: SSH, ...CLIENT }),
        c.context,
      ),
    Error,
    "not the proxy",
  );
  assertEquals(
    fake.removed.includes("/etc/apt/apt.conf.d/90apt-cache-proxy"),
    true,
  );
  assertEquals(c.getWrittenResources().length, 0);
});

Deno.test("configure_client fails a key mismatch even with fallback_direct", async () => {
  const fake = fakeApt((command) => {
    if (command.startsWith("'test' '-e'")) return { code: 1 };
    if (command.includes("cat")) return { code: 1 };
    if (command.includes("sha256sum")) return { code: 1 };
    if (command.includes("grep -lE")) return { code: 0, stdout: "" };
    if (command.includes("apt-config")) {
      return {
        code: 0,
        stdout: `Acquire::http::Proxy "http://192.0.2.9:3142";\n`,
      };
    }
    return { code: 0 };
  });
  useFake(fake);
  await assertRejects(
    () =>
      model.methods.configure_client.execute(
        model.methods.configure_client.arguments.parse({
          ssh: SSH,
          ...CLIENT,
          fallback_direct: true,
        }),
        ctx().context,
      ),
    Error,
    "not the proxy",
  );
});

Deno.test("configure_client restores the prior snippet on a failed re-run", async () => {
  const prior =
    '// prior snippet\nAcquire::http::Proxy "http://old.example.test:3142";\n';
  const fake = fakeApt((command) => {
    if (command.includes("cat") && command.includes("90apt-cache-proxy")) {
      return { code: 0, stdout: prior };
    }
    if (command.startsWith("'test' '-e'")) return { code: 1 };
    if (command.includes("cat")) return { code: 1 };
    if (command.includes("sha256sum")) return { code: 1 };
    if (command.includes("grep -lE")) return { code: 0, stdout: "" };
    if (command.includes("apt-config")) {
      return {
        code: 0,
        stdout: `Acquire::http::Proxy "http://192.0.2.9:3142";\n`,
      };
    }
    return { code: 0 };
  });
  useFake(fake);
  await assertRejects(
    () =>
      model.methods.configure_client.execute(
        model.methods.configure_client.arguments.parse({ ssh: SSH, ...CLIENT }),
        ctx().context,
      ),
    Error,
    "not the proxy",
  );
  assertEquals(
    fake.uploads.some((u) =>
      u.path.endsWith("90apt-cache-proxy") && u.content === prior
    ),
    true,
  );
});

Deno.test("configure_client requires an ack when the policy cannot be checked", async () => {
  const fake = fakeApt((command) => {
    if (command.includes("sha256sum")) return { code: 1 };
    if (command.includes("grep -lE")) return { code: 0, stdout: "" };
    if (command.includes("apt-config")) {
      return {
        code: 0,
        stdout:
          `Acquire::http::Proxy "http://192.0.2.20:3142";\nAcquire::https::Proxy "DIRECT";\n`,
      };
    }
    return { code: 0 };
  });
  useFake(fake);
  await assertRejects(
    () =>
      model.methods.configure_client.execute(
        model.methods.configure_client.arguments.parse({ ssh: SSH, ...CLIENT }),
        ctx({}, { queryData: undefined }).context,
      ),
    Error,
    "policy_check_ack",
  );
  const out = await model.methods.configure_client.execute(
    model.methods.configure_client.arguments.parse({
      ssh: SSH,
      ...CLIENT,
      policy_check_ack: true,
    }),
    ctx({}, { queryData: undefined }).context,
  );
  assertEquals(out.result.verified, true);
});

Deno.test("configure_client refuses when the policy query throws", async () => {
  useFake(fakeApt(() => ({})));
  await assertRejects(
    () =>
      model.methods.configure_client.execute(
        model.methods.configure_client.arguments.parse({ ssh: SSH, ...CLIENT }),
        ctx({}, {
          queryData: () => Promise.reject(new Error("query backend down")),
        }).context,
      ),
    Error,
    "could not query recorded servers",
  );
});

Deno.test("a plain-object vaultService resolves the key when none is injected", async () => {
  const fake = fakeApt((command) => {
    if (command.includes("dpkg-query") && command.includes("-f=${Status}")) {
      return { code: 1, stdout: "" };
    }
    if (command.includes("-f=${Version}")) {
      return { code: 0, stdout: "3.7.4-1\n" };
    }
    return { code: 0 };
  });
  setDeps({
    run: fake.run,
    now: () => NOW,
    sleep: () => Promise.resolve(),
    resolveSecret: undefined,
  });
  const service = {
    get: (_vault: string, _key: string) => Promise.resolve("PLACEHOLDER-KEY"),
  };
  const out = await model.methods.install_server.execute(
    model.methods.install_server.arguments.parse({ ssh: SSH }),
    ctx({}, { vaultService: service }).context,
  );
  assertEquals(out.result.version, "3.7.4-1");
});

Deno.test("client_get reports effective proxies, conflicts and force", async () => {
  const fake = fakeApt((command) => {
    if (command.includes("apt-config")) {
      return {
        code: 0,
        stdout:
          `Acquire::http::Proxy "http://192.0.2.20:3142";\nAcquire::https::Proxy "DIRECT";\n`,
      };
    }
    if (command.includes("sha256sum")) return { code: 1 };
    if (command.includes("grep -lE")) {
      return { code: 0, stdout: "/etc/apt/apt.conf.d/02proxy\n" };
    }
    return { code: 0 };
  });
  useFake(fake);
  const out = await model.methods.client_get.execute(
    model.methods.client_get.arguments.parse({ ssh: SSH }),
    ctx().context,
  );
  assertEquals(
    out.result.proxy_values!["Acquire::http::Proxy"],
    "http://192.0.2.20:3142",
  );
  assertEquals(out.result.managed_snippet_in_force, false);
  assertEquals(out.result.conflicts, ["/etc/apt/apt.conf.d/02proxy"]);
});

Deno.test("unconfigure_client removes once then no-ops", async () => {
  const box = boxFake(
    { "/etc/apt/apt.conf.d/90apt-cache-proxy": "snippet\n" },
    (command) => {
      if (command.includes("apt-config")) {
        return { code: 0, stdout: `Acquire::http::Proxy "DIRECT";\n` };
      }
      if (command.includes("grep -lE")) return { code: 0, stdout: "" };
      return {};
    },
  );
  useFake(box.fake);
  const out = await model.methods.unconfigure_client.execute(
    model.methods.unconfigure_client.arguments.parse({ ssh: SSH }),
    ctx().context,
  );
  assertEquals(out.result.removed, true);
  assertEquals(box.files.has("/etc/apt/apt.conf.d/90apt-cache-proxy"), false);

  const empty = boxFake();
  useFake(empty.fake);
  const out2 = await model.methods.unconfigure_client.execute(
    model.methods.unconfigure_client.arguments.parse({ ssh: SSH }),
    ctx().context,
  );
  assertEquals(out2.result.removed, false);
});

Deno.test("unconfigure_client surfaces a failing rm instead of reporting success", async () => {
  const SNIPPET = "/etc/apt/apt.conf.d/90apt-cache-proxy";
  const fake = fakeApt((command) => {
    if (command.includes("sha256sum")) {
      return { code: 0, stdout: `${"a".repeat(64)}  ${SNIPPET}\n` };
    }
    if (command.includes("'cat'")) return { code: 0, stdout: "snippet\n" };
    if (command.includes("'rm'")) {
      return { code: 1, stderr: "rm: cannot remove: Read-only file system" };
    }
    return {};
  });
  useFake(fake);
  const c = ctx();
  await assertRejects(
    () =>
      model.methods.unconfigure_client.execute(
        model.methods.unconfigure_client.arguments.parse({ ssh: SSH }),
        c.context,
      ),
    Error,
    "rm client snippet",
  );
  // Nothing is recorded as removed.
  assertEquals(c.getWrittenResources().length, 0);
});
