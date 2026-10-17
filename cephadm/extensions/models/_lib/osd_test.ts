import { assertEquals, assertRejects } from "jsr:@std/assert@1.0.19";
import { PhaseError, RemoteExitError } from "./errors.ts";
import { listByIdCommand } from "./resolve.ts";
import type { CommandResult, RunOptions, SshSession } from "./ssh.ts";
import {
  applyOsd,
  checkExclusions,
  entryMatchesSerial,
  extractSpecPaths,
  findLeftovers,
  osdApplyBody,
  osdSpecYaml,
  parseDeviceInventory,
  parseOsdServices,
  samePathSet,
  validateOsdMode,
} from "./osd.ts";

const deps = {
  now: () => 0,
  sleep: () => Promise.resolve(),
  random: () => 0.5,
};

/** A fake admin session that routes by the script body or the plain command. */
function adminSession(
  route: (body: string, command: string) => CommandResult,
): { session: SshSession; bodies: string[] } {
  const bodies: string[] = [];
  let dir = 0;
  let scriptBody = "";
  const session: SshSession = {
    target: { host: "192.0.2.10", user: "admin", strictHostKeyChecking: "yes" },
    controlPath: null,
    run: (opts) => {
      if (opts.command.startsWith("mktemp -d")) {
        dir++;
        return Promise.resolve({
          code: 0,
          stdout: `/tmp/cephadm-shell.ABCDE${dir}\n`,
          stderr: "",
        });
      }
      if (opts.command.startsWith("umask 022")) {
        scriptBody = opts.stdin ?? "";
        return Promise.resolve({ code: 0, stdout: "", stderr: "" });
      }
      if (opts.command.startsWith("cephadm shell")) {
        bodies.push(scriptBody);
        const r = route(scriptBody, opts.command);
        if (r.code !== 0 && !opts.allowNonZero) {
          throw new RemoteExitError(r.code, r.stdout, r.stderr, "test");
        }
        return Promise.resolve(r);
      }
      if (opts.command.startsWith("rm -rf")) {
        return Promise.resolve({ code: 0, stdout: "", stderr: "" });
      }
      return Promise.resolve({
        code: 1,
        stdout: "",
        stderr: `unrouted ${opts.command}`,
      });
    },
    close: () => Promise.resolve({ closed: false, detail: "not multiplexed" }),
  };
  return { session, bodies };
}

/** A fake target session for the serial resolver. */
function targetSession(device = "/dev/nvme0n1"): SshSession {
  return {
    target: { host: "192.0.2.50", user: "admin", strictHostKeyChecking: "yes" },
    controlPath: null,
    run: (opts: RunOptions) => {
      if (opts.command === listByIdCommand()) {
        return Promise.resolve({
          code: 0,
          stdout: "nvme-SN0001\n",
          stderr: "",
        });
      }
      if (opts.command.startsWith("readlink")) {
        return Promise.resolve({ code: 0, stdout: `${device}\n`, stderr: "" });
      }
      return Promise.resolve({ code: 1, stdout: "", stderr: "unrouted" });
    },
    close: () => Promise.resolve({ closed: false, detail: "not multiplexed" }),
  };
}

Deno.test(
  "the OSD mode rules are re-checked at run time", // leak-allow(decision D20)
  () => {
    const sel = validateOsdMode({
      targetHost: "node1",
      dataDevices: [{ serial: "SN0001" }],
    });
    assertEquals(sel.mode, "selector");
    assertEquals(sel.targetHost, "node1");
    const all = validateOsdMode({
      allAvailableDevices: true,
      excludeDevices: [{ serial: "SN0001" }],
    });
    assertEquals(all.mode, "all");
    for (
      const bad of [
        {
          allAvailableDevices: true,
          dataDevices: [{ serial: "SN0001" }],
          excludeDevices: [{ serial: "SN9" }],
        },
        {
          allAvailableDevices: true,
          excludeDevices: [{ serial: "SN9" }],
          targetHost: "node1",
        },
        { allAvailableDevices: true },
        { targetHost: "", dataDevices: [{ serial: "SN0001" }] },
        { dataDevices: [{ serial: "SN0001" }] },
        {},
      ]
    ) {
      let threw = false;
      try {
        validateOsdMode(bad);
      } catch {
        threw = true;
      }
      assertEquals(threw, true, JSON.stringify(bad));
    }
  },
);

Deno.test("device inventory parsing and matching", () => {
  const entries = parseDeviceInventory([
    {
      hostname: "node1",
      path: "/dev/sdb",
      device_id: "SN0001",
      available: true,
    },
    {
      hostname: "node2",
      path: "/dev/disk/by-id/nvme-X_SN0002",
      device_id: "",
      available: false,
    },
  ]);
  assertEquals(entries.length, 2);
  assertEquals(entries[0].available, true);
  assertEquals(entryMatchesSerial(entries[0], "SN0001"), true);
  assertEquals(entryMatchesSerial(entries[1], "SN0002"), true);
  assertEquals(entryMatchesSerial(entries[1], "SN0003"), false);
});

Deno.test("the all-available exclusion check refuses available or unknown serials", async () => {
  const unknown = adminSession(() => ({ code: 0, stdout: "[]", stderr: "" }));
  await assertRejects(
    () => checkExclusions(deps, unknown.session, [{ serial: "SN0001" }]),
    PhaseError,
    "found on no enrolled host",
  );

  const available = adminSession(() => ({
    code: 0,
    stdout:
      '[{"hostname":"node1","path":"/dev/sdb","device_id":"SN0001","available":true}]',
    stderr: "",
  }));
  await assertRejects(
    () => checkExclusions(deps, available.session, [{ serial: "SN0001" }]),
    PhaseError,
    "would be claimed",
  );

  const safe = adminSession(() => ({
    code: 0,
    stdout:
      '[{"hostname":"node1","path":"/dev/sdb","device_id":"SN0001","available":false}]',
    stderr: "",
  }));
  await checkExclusions(deps, safe.session, [{ serial: "SN0001" }]);
});

Deno.test("leftover services require the exact single-host placement", () => {
  const services = parseOsdServices([
    {
      service_name: "osd.by-serial-node1-b",
      placement: { hosts: ["node1-b"] },
    },
    { service_name: "osd.by-serial-node1-a", placement: { hosts: ["node1"] } },
    { service_name: "osd.all-available-devices" },
  ]);
  assertEquals(findLeftovers(services, "node1"), ["osd.by-serial-node1-a"]);
});

Deno.test("exported spec paths are extracted and compared as sets", () => {
  const yaml = [
    "service_type: osd",
    "spec:",
    "  data_devices:",
    "    paths:",
    "      - /dev/disk/by-id/a",
    "      - /dev/disk/by-id/b",
    "",
  ].join("\n");
  assertEquals(extractSpecPaths(yaml), [
    "/dev/disk/by-id/a",
    "/dev/disk/by-id/b",
  ]);
  assertEquals(samePathSet(["a", "b"], ["b", "a"]), true);
  assertEquals(samePathSet(["a"], ["a", "b"]), false);
});

Deno.test(
  "the applied spec nests paths under spec and never uses a host pattern", // leak-allow(decision D5)
  () => {
    const yaml = osdSpecYaml("by-serial-node1", "node1", [
      "/dev/disk/by-id/nvme-X_SN0001",
    ]);
    assertEquals(yaml.includes("service_type: osd"), true);
    assertEquals(yaml.includes("service_id: by-serial-node1"), true);
    assertEquals(yaml.includes("    - node1"), true);
    // paths must nest under data_devices, not sit beside it.
    assertEquals(
      yaml.includes(
        "spec:\n  data_devices:\n    paths:\n      - /dev/disk/by-id/nvme-X_SN0001",
      ),
      true,
    );
    assertEquals(yaml.includes("/dev/disk/by-id/nvme-X_SN0001"), true);
    assertEquals(yaml.includes("*"), false);
    const body = osdApplyBody(yaml);
    assertEquals(body.includes("<<'CEPHADM_OSD_SPEC'"), true);
    assertEquals(body.includes("trap 'rm -f \"$spec\"' EXIT"), true);
    assertEquals(body.includes('ceph orch apply -i "$spec"'), true);
  },
);

Deno.test("all-available mode applies when absent and is presence-only when present", async () => {
  const absent = adminSession((body) =>
    body.includes("orch device ls")
      ? {
        code: 0,
        stdout:
          '[{"hostname":"n","path":"/dev/sdb","device_id":"SN9","available":false}]',
        stderr: "",
      }
      : body.includes("--all-available-devices")
      ? { code: 0, stdout: "", stderr: "" }
      : { code: 0, stdout: "[]", stderr: "" }
  );
  const r1 = await applyOsd(deps, absent.session, null, {
    allAvailableDevices: true,
    excludeDevices: [{ serial: "SN9" }],
  });
  assertEquals(r1.applied, true);
  assertEquals(r1.serviceId, "all-available-devices");
  assertEquals(
    absent.bodies.some((b) => b.includes("--all-available-devices")),
    true,
  );

  const present = adminSession((body) =>
    body.includes("orch device ls")
      ? {
        code: 0,
        stdout:
          '[{"hostname":"n","path":"/dev/sdb","device_id":"SN9","available":false}]',
        stderr: "",
      }
      : body.includes("--all-available-devices")
      ? { code: 0, stdout: "", stderr: "" }
      : {
        code: 0,
        stdout: '[{"service_name":"osd.all-available-devices"}]',
        stderr: "",
      }
  );
  const r2 = await applyOsd(deps, present.session, null, {
    allAvailableDevices: true,
    excludeDevices: [{ serial: "SN9" }],
  });
  assertEquals(r2.applied, false);
  assertEquals(
    present.bodies.some((b) => b.includes("--all-available-devices")),
    false,
  );
});

Deno.test(
  "selector mode resolves before applying and converges by path set", // leak-allow(decision D21)
  async () => {
    let applied = false;
    const admin = adminSession((body) => {
      if (body.includes("orch ls --service_type osd")) {
        return { code: 0, stdout: "[]", stderr: "" };
      }
      if (body.includes("--export")) {
        return applied
          ? {
            code: 0,
            stdout:
              "spec:\n  data_devices:\n    paths:\n      - /dev/disk/by-id/nvme-SN0001\n",
            stderr: "",
          }
          : { code: 1, stdout: "", stderr: "no spec" };
      }
      if (body.includes("orch apply -i")) {
        applied = true;
        return { code: 0, stdout: "", stderr: "" };
      }
      return { code: 0, stdout: "[]", stderr: "" };
    });
    const r1 = await applyOsd(deps, admin.session, targetSession(), {
      targetHost: "node1",
      dataDevices: [{ serial: "SN0001" }],
    });
    assertEquals(r1.applied, true);
    assertEquals(r1.resolvedPaths, ["/dev/disk/by-id/nvme-SN0001"]);
    assertEquals(r1.staleServicesRemoved, []);

    const r2 = await applyOsd(deps, admin.session, targetSession(), {
      targetHost: "node1",
      dataDevices: [{ serial: "SN0001" }],
    });
    assertEquals(r2.applied, false);
  },
);

Deno.test("a resolution failure leaves the cluster untouched", async () => {
  let mutated = false;
  const admin = adminSession((body) => {
    if (body.includes("orch ls --service_type osd")) {
      return { code: 0, stdout: "[]", stderr: "" };
    }
    if (body.includes("orch rm") || body.includes("orch apply -i")) {
      mutated = true;
      return { code: 0, stdout: "", stderr: "" };
    }
    return { code: 0, stdout: "[]", stderr: "" };
  });
  const badTarget: SshSession = {
    target: { host: "192.0.2.50", user: "admin", strictHostKeyChecking: "yes" },
    controlPath: null,
    run: (opts: RunOptions) =>
      Promise.resolve(
        opts.command === listByIdCommand()
          ? { code: 0, stdout: "", stderr: "" }
          : { code: 0, stdout: "", stderr: "" },
      ),
    close: () => Promise.resolve({ closed: false, detail: "not multiplexed" }),
  };
  await assertRejects(
    () =>
      applyOsd(deps, admin.session, badTarget, {
        targetHost: "node1",
        dataDevices: [{ serial: "SN0001" }],
      }),
    PhaseError,
    "zero devices",
  );
  assertEquals(mutated, false);
});

Deno.test("a leftover service is force-removed before the apply", async () => {
  const removed: string[] = [];
  const admin = adminSession((body) => {
    if (body.includes("orch ls --service_type osd")) {
      return {
        code: 0,
        stdout:
          '[{"service_name":"osd.by-serial-node1-old","placement":{"hosts":["node1"]}}]',
        stderr: "",
      };
    }
    if (body.includes("orch rm")) {
      removed.push("old");
      return { code: 0, stdout: "", stderr: "" };
    }
    if (body.includes("--export")) {
      return { code: 1, stdout: "", stderr: "no spec" };
    }
    if (body.includes("orch apply -i")) {
      return { code: 0, stdout: "", stderr: "" };
    }
    return { code: 0, stdout: "[]", stderr: "" };
  });
  const r = await applyOsd(deps, admin.session, targetSession(), {
    targetHost: "node1",
    dataDevices: [{ serial: "SN0001" }],
  });
  assertEquals(r.staleServicesRemoved, ["osd.by-serial-node1-old"]);
  assertEquals(removed, ["old"]);
  assertEquals(r.applied, true);
  const applyAt = admin.bodies.findIndex((b) => b.includes("orch apply -i"));
  const rmAt = admin.bodies.findIndex((b) => b.includes("orch rm"));
  assertEquals(applyAt >= 0 && applyAt < rmAt, true);
});

Deno.test(
  "a failed OSD apply does not remove the stale service", // leak-allow(decision D21)
  async () => {
    let removed = false;
    const admin = adminSession((body) => {
      if (body.includes("orch ls --service_type osd")) {
        return {
          code: 0,
          stdout:
            '[{"service_name":"osd.by-serial-node1-old","placement":{"hosts":["node1"]}}]',
          stderr: "",
        };
      }
      if (body.includes("--export")) {
        return { code: 1, stdout: "", stderr: "no spec" };
      }
      if (body.includes("orch apply -i")) {
        return { code: 1, stdout: "", stderr: "apply failed" };
      }
      if (body.includes("orch rm")) {
        removed = true;
        return { code: 0, stdout: "", stderr: "" };
      }
      return { code: 0, stdout: "[]", stderr: "" };
    });
    await assertRejects(
      () =>
        applyOsd(deps, admin.session, targetSession(), {
          targetHost: "node1",
          dataDevices: [{ serial: "SN0001" }],
        }),
      PhaseError,
      "OSD apply failed",
    );
    assertEquals(removed, false);
  },
);
