import { assertEquals, assertRejects } from "jsr:@std/assert@1.0.19";
import { PhaseError, TransportError } from "./errors.ts";
import type { CommandResult, SshSession } from "./ssh.ts";
import {
  capacityReport,
  crushFailureDomain,
  nooutPredicate,
  persistVerdict,
  poolTypeOf,
  selectCrushRule,
  settle,
  verifyCsiUsers,
  verifyDisksRaw,
  verifyHealth,
  verifyHostNoout,
  verifyHostPrep,
  verifyKeyDistributed,
  verifyMgr,
  verifyMgrPlacement,
  verifyMonPlacement,
  verifyMonQuorum,
  verifyOsd,
} from "./verify.ts";

const deps = {
  now: () => 0,
  sleep: () => Promise.resolve(),
  random: () => 0.5,
};

function vSession(route: (body: string) => CommandResult): SshSession {
  let dir = 0;
  let scriptBody = "";
  return {
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
        return Promise.resolve(route(scriptBody));
      }
      if (opts.command.startsWith("rm -rf")) {
        return Promise.resolve({ code: 0, stdout: "", stderr: "" });
      }
      return Promise.resolve({ code: 1, stdout: "", stderr: "unrouted" });
    },
    close: () => Promise.resolve({ closed: false, detail: "not multiplexed" }),
  };
}

Deno.test("settle retries transport errors, stops at other errors and returns the last verdict", async () => {
  let t = 0;
  const sleeps: number[] = [];
  const wd = {
    now: () => t,
    sleep: (ms: number) => {
      sleeps.push(ms);
      t += ms;
      return Promise.resolve();
    },
    random: () => 0,
  };
  // Transport error then success.
  let reads = 0;
  const ok = await settle(wd, {
    budgetMs: 100_000,
    ceilingMs: 1600,
    read: () => {
      reads++;
      if (reads === 1) {
        return Promise.reject(
          new TransportError({
            host: "h",
            port: 22,
            user: "u",
            kind: "dropped-before-auth",
            cause: "auth",
            message: "x",
          }),
        );
      }
      return Promise.resolve(7);
    },
    pass: (v) => v === 7,
  });
  assertEquals(ok.value, 7);
  assertEquals(ok.attempts, 2);

  // Non-transport error stops at once.
  let badReads = 0;
  await assertRejects(() =>
    settle(wd, {
      budgetMs: 100_000,
      ceilingMs: 100,
      read: () => {
        badReads++;
        return Promise.reject(new Error("not json"));
      },
      pass: () => true,
    })
  );
  assertEquals(badReads, 1);

  // Single-shot transport error rethrows.
  await assertRejects(() =>
    settle(wd, {
      budgetMs: 0,
      ceilingMs: 100,
      read: () =>
        Promise.reject(
          new TransportError({
            host: "h",
            port: 22,
            user: "u",
            kind: "other",
            cause: null,
            message: "x",
          }),
        ),
      pass: () => true,
    })
  );
});

Deno.test("CRUSH rule selection and failure-domain extraction", () => {
  const rules = [
    {
      rule_id: 0,
      rule_name: "replicated_rule",
      steps: [{ op: "take", item_name: "default" }, {
        op: "chooseleaf_firstn",
        type: "host",
      }],
    },
    {
      rule_id: 7,
      rule_name: "host_rule",
      steps: [{ op: "chooseleaf_firstn", type: "rack" }],
    },
  ];
  assertEquals(
    (selectCrushRule(rules, null) as { rule_id: number }).rule_id,
    0,
  );
  assertEquals(
    (selectCrushRule(rules, "host_rule") as { rule_id: number }).rule_id,
    7,
  );
  assertEquals(selectCrushRule(rules, "missing"), null);
  assertEquals(crushFailureDomain(rules[0]), "host");
  assertEquals(crushFailureDomain(rules[1]), "rack");
});

Deno.test("mon quorum passes only when the count matches and none are out", async () => {
  const three = vSession(() => ({
    code: 0,
    stdout:
      '{"monmap":{"mons":[{"name":"a"},{"name":"b"},{"name":"c"}]},"quorum_names":["a","b","c"]}',
    stderr: "",
  }));
  const pass = await verifyMonQuorum(deps, three, { expectedMonCount: 3 });
  assertEquals(pass.pass, true);
  assertEquals(pass.actual, { monCount: 3, quorumCount: 3, outOfQuorum: [] });

  const degraded = vSession(() => ({
    code: 0,
    stdout:
      '{"monmap":{"mons":[{"name":"a"},{"name":"b"},{"name":"c"}]},"quorum_names":["a","b"]}',
    stderr: "",
  }));
  const fail = await verifyMonQuorum(deps, degraded, { expectedMonCount: 3 });
  assertEquals(fail.pass, false);
  assertEquals((fail.actual as { outOfQuorum: string[] }).outOfQuorum, ["c"]);

  const wrongCount = await verifyMonQuorum(deps, three, {
    expectedMonCount: 5,
  });
  assertEquals(wrongCount.pass, false);
});

Deno.test("mgr check requires a genuinely active mgr", async () => {
  const active = vSession(() => ({
    code: 0,
    stdout: '{"active_name":"a","standbys":["b"]}',
    stderr: "",
  }));
  assertEquals(
    (await verifyMgr(deps, active, { expectedCount: 2 })).pass,
    true,
  );

  const none = vSession(() => ({
    code: 0,
    stdout: '{"active_name":"","standbys":["a","b"]}',
    stderr: "",
  }));
  const verdict = await verifyMgr(deps, none, { expectedCount: 3 });
  assertEquals(verdict.pass, false);
  assertEquals((verdict.actual as { active: boolean }).active, false);
});

Deno.test("OSD check combines up/in and failure domain", async () => {
  const good = vSession((body) =>
    body.includes("osd stat")
      ? {
        code: 0,
        stdout: '{"num_up_osds":3,"num_in_osds":3,"num_osds":3}',
        stderr: "",
      }
      : {
        code: 0,
        stdout:
          '[{"rule_id":0,"rule_name":"replicated_rule","steps":[{"op":"chooseleaf_firstn","type":"host"}]}]',
        stderr: "",
      }
  );
  const pass = await verifyOsd(deps, good, {
    expectedUp: 3,
    expectedIn: 3,
    expectedFailureDomain: "host",
  });
  assertEquals(pass.pass, true);

  const wrongDomain = await verifyOsd(deps, good, {
    expectedUp: 3,
    expectedIn: 3,
    expectedFailureDomain: "rack",
  });
  assertEquals(wrongDomain.pass, false);
  assertEquals(
    (wrongDomain.actual as { crush: { failureDomain: string } }).crush
      .failureDomain,
    "host",
  );

  const missingRule = vSession((body) =>
    body.includes("osd stat")
      ? {
        code: 0,
        stdout: '{"num_up_osds":3,"num_in_osds":3,"num_osds":3}',
        stderr: "",
      }
      : { code: 0, stdout: "[]", stderr: "" }
  );
  const missing = await verifyOsd(deps, missingRule, {
    expectedUp: 3,
    expectedIn: 3,
    expectedFailureDomain: "host",
    crushRuleName: "nope",
  });
  assertEquals(missing.pass, false);
  assertEquals(missing.actual, {
    osd: { up: 3, in: 3, numOsds: 3 },
    crush: null,
  });
});

Deno.test("CSI user verification discards keys", async () => {
  const s = vSession(() => ({
    code: 0,
    stdout:
      '{"auth_dump":[{"entity":"client.csi-rbd","caps":{"mon":"allow r"},"key":"SECRETKEY"},{"entity":"mgr.x","caps":{},"key":"OTHER"}]}',
    stderr: "",
  }));
  const pass = await verifyCsiUsers(deps, s, ["csi-rbd"]);
  assertEquals(pass.pass, true);
  assertEquals(JSON.stringify(pass).includes("SECRETKEY"), false);
  assertEquals(JSON.stringify(pass).includes("OTHER"), false);
  const missing = await verifyCsiUsers(deps, s, ["csi-cephfs"]);
  assertEquals(missing.pass, false);
  assertEquals((missing.detail as { missing: string[] }).missing, [
    "client.csi-cephfs",
  ]);
});

Deno.test(
  "a failing verdict is recorded first, then thrown with the evidence", // leak-allow(decision D40)
  async () => {
    const written: {
      spec: string;
      name: string;
      data: Record<string, unknown>;
    }[] = [];
    const context = {
      writeResource: (
        spec: string,
        name: string,
        data: Record<string, unknown>,
      ) => {
        written.push({ spec, name, data });
        return Promise.resolve({ name });
      },
    };
    const outcome = {
      pass: false,
      expected: { a: 1 },
      actual: { a: 2 },
      detail: { why: "mismatch" },
    };
    try {
      await persistVerdict(context, deps, {
        method: "cephVerifyMgr",
        host: "192.0.2.10",
        phase: "mgr",
        key: "cephVerifyMgr-192.0.2.10", // gitleaks:allow
        outcome,
        throwOnFail: true,
      });
      throw new Error("should throw");
    } catch (e) {
      assertEquals(e instanceof PhaseError, true);
      assertEquals((e as Error).message.includes("cephadm[mgr]:"), true);
      assertEquals((e as Error).message.includes('expected={"a":1}'), true);
      assertEquals(
        (e as Error).message.includes("recordKey=cephVerifyMgr-192.0.2.10"), // gitleaks:allow
        true,
      );
    }
    assertEquals(written.length, 1);
    assertEquals(written[0].spec, "cephVerifyResult");

    // With throwOnFail false, the failing verdict is recorded and returned.
    const handle = await persistVerdict(context, deps, {
      method: "cephVerifyMgr",
      host: "192.0.2.10",
      phase: "mgr",
      key: "cephVerifyMgr-192.0.2.10", // gitleaks:allow
      outcome,
      throwOnFail: false,
    });
    assertEquals(handle.name, "cephVerifyMgr-192.0.2.10");
    assertEquals(written.length, 2);
  },
);

Deno.test(
  "health refuses missing, unknown and unnamed-warning states", // leak-allow(decision D38)
  async () => {
    const empty = vSession(() => ({ code: 0, stdout: "{}", stderr: "" }));
    assertEquals(
      (await verifyHealth(deps, empty, { wantOk: true })).actual,
      null,
    );
    assertEquals(
      (await verifyHealth(deps, empty, { wantOk: false })).actual,
      null,
    );

    const unknown = vSession(() => ({
      code: 0,
      stdout: '{"status":"HEALTH_UNKNOWN","checks":{}}',
      stderr: "",
    }));
    assertEquals(
      (await verifyHealth(deps, unknown, { wantOk: true })).pass,
      false,
    );
    assertEquals(
      (await verifyHealth(deps, unknown, { wantOk: false })).actual,
      null,
    );

    const unnamed = vSession(() => ({
      code: 0,
      stdout: '{"status":"HEALTH_WARN"}',
      stderr: "",
    }));
    assertEquals(
      (await verifyHealth(deps, unnamed, { wantOk: true })).pass,
      false,
    );

    const contradiction = vSession(() => ({
      code: 0,
      stdout: '{"status":"HEALTH_WARN","checks":{"OSD_FLAGS":{}}}',
      stderr: "",
    }));
    const verdict = await verifyHealth(deps, contradiction, {
      wantOk: false,
      allowedWarnings: ["OSD_FLAGS"],
    });
    assertEquals(verdict.pass, false);
    assertEquals(verdict.actual, null);
    assertEquals(String(verdict.detail.reason).includes("wantOk"), true);
  },
);

Deno.test("health evaluates the status and the allowlist", async () => {
  const ok = vSession(() => ({
    code: 0,
    stdout: '{"status":"health_ok","checks":{}}',
    stderr: "",
  }));
  assertEquals((await verifyHealth(deps, ok, { wantOk: true })).pass, true);

  const warn = vSession(() => ({
    code: 0,
    stdout:
      '{"status":"HEALTH_WARN","checks":{"OSD_DOWN":{"summary":{"message":"1 osd down"}}}}',
    stderr: "",
  }));
  const noAllow = await verifyHealth(deps, warn, { wantOk: true });
  assertEquals(noAllow.pass, false);
  assertEquals(noAllow.detail.activeChecks as string[], ["OSD_DOWN"]);

  const allowed = vSession(() => ({
    code: 0,
    stdout:
      '{"status":"HEALTH_WARN","checks":{"OSD_FLAGS":{"summary":{"message":"noout"}},"CEPHADM_FAILED_DAEMON":{"summary":{"message":"daemon"}}}}',
    stderr: "",
  }));
  assertEquals(
    (await verifyHealth(deps, allowed, {
      wantOk: true,
      allowedWarnings: ["OSD_FLAGS", "CEPHADM_FAILED_DAEMON"],
    })).pass,
    true,
  );
  const extra = vSession(() => ({
    code: 0,
    stdout:
      '{"status":"HEALTH_WARN","checks":{"OSD_FLAGS":{},"PG_DEGRADED":{"summary":{"message":"degraded"}}}}',
    stderr: "",
  }));
  const extraVerdict = await verifyHealth(deps, extra, {
    wantOk: true,
    allowedWarnings: ["OSD_FLAGS"],
  });
  assertEquals(extraVerdict.pass, false);
  assertEquals(extraVerdict.detail.unallowedChecks, ["PG_DEGRADED"]);

  const err = vSession(() => ({
    code: 0,
    stdout: '{"status":"HEALTH_ERR","checks":{"OSD_FLAGS":{}}}',
    stderr: "",
  }));
  assertEquals(
    (await verifyHealth(deps, err, {
      wantOk: true,
      allowedWarnings: ["OSD_FLAGS"],
    })).pass,
    false,
  );
  assertEquals((await verifyHealth(deps, err, { wantOk: false })).pass, true);
});

Deno.test(
  "the host-noout predicate reads OSD_FLAGS as an unordered set", // leak-allow(decision D46)
  () => {
    const summary = {
      checks: {
        OSD_FLAGS: { summary: { message: "host host-a has flags noout" } },
      },
    };
    assertEquals(nooutPredicate(summary, "host-a").set, true);
    const detailOnly = {
      checks: {
        OSD_FLAGS: {
          detail: [{ message: "host host-a has flags noout,noin" }],
        },
      },
    };
    assertEquals(nooutPredicate(detailOnly, "host-a").set, true);
    const reordered = {
      checks: {
        OSD_FLAGS: { summary: { message: "host host-a has flags noin,noout" } },
      },
    };
    assertEquals(nooutPredicate(reordered, "host-a").set, true);
    const prefix = {
      checks: {
        OSD_FLAGS: { summary: { message: "host host-a1 has flags noout" } },
      },
    };
    assertEquals(nooutPredicate(prefix, "host-a").set, false);
    assertEquals(nooutPredicate({ checks: {} }, "host-a").set, false);
  },
);

Deno.test("host-noout verifies the expectation in both directions", async () => {
  const set = vSession(() => ({
    code: 0,
    stdout:
      '{"checks":{"OSD_FLAGS":{"summary":{"message":"host host-a has flags noout"}}}}',
    stderr: "",
  }));
  const pass = await verifyHostNoout(deps, set, {
    hostName: "host-a",
    expectSet: true,
  });
  assertEquals(pass.pass, true);
  assertEquals(pass.subject, "host-a");
  assertEquals(pass.detail.readFrom, "checks.OSD_FLAGS");
  assertEquals(pass.detail.osdDumpConsulted, false);
  assertEquals(
    (await verifyHostNoout(deps, set, { hostName: "host-a", expectSet: false }))
      .pass,
    false,
  );

  const clear = vSession(() => ({
    code: 0,
    stdout: '{"checks":{}}',
    stderr: "",
  }));
  assertEquals(
    (await verifyHostNoout(deps, clear, {
      hostName: "host-a",
      expectSet: false,
    })).pass,
    true,
  );
  assertEquals(
    (await verifyHostNoout(deps, clear, {
      hostName: "host-a",
      expectSet: true,
    })).pass,
    false,
  );
});

/** A plain read-only session for host checks. */
function plainSession(route: (command: string) => CommandResult): SshSession {
  return {
    target: { host: "192.0.2.10", user: "admin", strictHostKeyChecking: "yes" },
    controlPath: null,
    run: (opts) => Promise.resolve(route(opts.command)),
    close: () => Promise.resolve({ closed: false, detail: "not multiplexed" }),
  };
}

Deno.test(
  "host-prep asserts packages, the exact cephadm version and time sync", // leak-allow(decision D14)
  async () => {
    const good = plainSession((command) => {
      if (command.startsWith("dpkg -s")) {
        return { code: 0, stdout: "Version: 1.2\n", stderr: "" };
      }
      if (command.startsWith("test -x")) {
        return { code: 0, stdout: "", stderr: "" };
      }
      if (command.includes("cephadm version")) {
        return {
          code: 0,
          stdout: "cephadm version 19.2.1 (x) squid (stable)",
          stderr: "",
        };
      }
      if (command.startsWith("systemctl is-active")) {
        return { code: 0, stdout: "active\n", stderr: "" };
      }
      return { code: 1, stdout: "", stderr: "unrouted" };
    });
    const pass = await verifyHostPrep(deps, good, {
      expectedPackages: ["chrony"],
      expectedCephadmVersion: "19.2.1",
      expectedTimeSyncService: "chrony",
    });
    assertEquals(pass.pass, true);
    assertEquals(
      (pass.actual as { cephadmVersion: string }).cephadmVersion,
      "19.2.1",
    );

    const short = plainSession((command) => {
      if (command.startsWith("dpkg -s")) {
        return { code: 0, stdout: "", stderr: "" };
      }
      if (command.startsWith("test -x")) {
        return { code: 0, stdout: "", stderr: "" };
      }
      if (command.includes("cephadm version")) {
        return { code: 0, stdout: "cephadm version 19.2.10 (x)", stderr: "" };
      }
      if (command.startsWith("systemctl is-active")) {
        return { code: 0, stdout: "active\n", stderr: "" };
      }
      return { code: 1, stdout: "", stderr: "unrouted" };
    });
    assertEquals(
      (await verifyHostPrep(deps, short, {
        expectedPackages: ["chrony"],
        expectedCephadmVersion: "19.2.1",
        expectedTimeSyncService: "chrony",
      })).pass,
      false,
    );

    const missing = plainSession((command) =>
      command.startsWith("systemctl is-active")
        ? { code: 3, stdout: "inactive\n", stderr: "" }
        : command.startsWith("dpkg -s")
        ? { code: 1, stdout: "", stderr: "" }
        : { code: 0, stdout: "", stderr: "" }
    );
    const verdict = await verifyHostPrep(deps, missing, {
      expectedPackages: ["chrony"],
      expectedCephadmVersion: "19.2.1",
      expectedTimeSyncService: "chrony",
    });
    assertEquals(verdict.pass, false);
    assertEquals(
      (verdict.actual as { missingPackages: string[] }).missingPackages,
      ["chrony"],
    );
    assertEquals(
      (verdict.actual as { timeSyncActive: boolean }).timeSyncActive,
      false,
    );
  },
);

Deno.test(
  "disks-raw reports signatures, children and mounts by type", // leak-allow(decision D17)
  async () => {
    const tree = JSON.stringify({
      blockdevices: [
        {
          name: "nvme0n1",
          path: "/dev/nvme0n1",
          type: "disk",
          fstype: null,
          mountpoint: null,
        },
        {
          name: "nvme1n1",
          path: "/dev/nvme1n1",
          type: "disk",
          fstype: "ext4",
          mountpoint: null,
          children: [{
            name: "nvme1n1p1",
            path: "/dev/nvme1n1p1",
            type: "part",
            mountpoint: "/data",
          }],
        },
      ],
    });
    const resolver = (device: string) =>
      plainSession((command) => {
        if (command.startsWith("lsblk")) {
          return { code: 0, stdout: tree, stderr: "" };
        }
        if (command.startsWith("readlink")) {
          return { code: 0, stdout: `${device}\n`, stderr: "" };
        }
        if (command.includes("basename")) {
          return { code: 0, stdout: "nvme-SN0001\n", stderr: "" };
        }
        return { code: 1, stdout: "", stderr: "unrouted" };
      });
    const raw = await verifyDisksRaw(deps, resolver("/dev/nvme0n1"), [{
      serial: "SN0001",
    }]);
    assertEquals(raw.pass, true);
    const dirty = await verifyDisksRaw(deps, resolver("/dev/nvme1n1"), [{
      serial: "SN0001",
    }]);
    assertEquals(dirty.pass, false);
    assertEquals(dirty.detail.mounted as string[], ["SN0001"]);
    const observed =
      (dirty.detail.perDevice as { children: { type: string }[] }[])[0];
    assertEquals(observed.children[0].type, "part");
  },
);

Deno.test("key distribution reports present, absent, unreadable and unreachable", async () => {
  const outcomes = new Map<string, number | TransportError>([
    ["a", 0],
    ["b", 1],
    ["c", 2],
  ]);
  const result = await verifyKeyDistributed(deps, {
    hosts: ["a", "b", "c"],
    port: 22,
    cephPubKey:
      "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExampleExampleExampleExampleExample",
    makeSession: (host) => {
      const outcome = outcomes.get(host)!;
      if (outcome instanceof TransportError) return Promise.reject(outcome);
      return Promise.resolve(plainSession(() => ({
        code: outcome as number,
        stdout: "",
        stderr: "denied",
      })));
    },
  });
  assertEquals(result.outcome.pass, false);
  assertEquals(result.outcome.detail.absentOn as string[], ["b"]);
  assertEquals(result.outcome.detail.unreadableOn as string[], ["c"]);

  const unreachable = await verifyKeyDistributed(deps, {
    hosts: ["x"],
    port: 22,
    cephPubKey:
      "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExampleExampleExampleExampleExample",
    makeSession: () =>
      Promise.reject(
        new TransportError({
          host: "x",
          port: 22,
          user: "u",
          kind: "other",
          cause: null,
          message: "unreachable",
        }),
      ),
  });
  assertEquals(unreachable.unreachable.length, 1);
  assertEquals(unreachable.outcome.detail.unreachableOn as string[], ["x"]);
});

Deno.test("pool type mapping is explicit, never guessed", () => {
  assertEquals(poolTypeOf(1), "replicated");
  assertEquals(poolTypeOf(3), "erasure");
  assertEquals(poolTypeOf(2), "unknown");
  assertEquals(poolTypeOf(undefined), "unknown");
  assertEquals(poolTypeOf("3"), "unknown");
});

Deno.test(
  "capacity joins both reads, computes margins and flags at-risk EC pools", // leak-allow(decision D35)
  async () => {
    const df = JSON.stringify({
      stats: {
        total_bytes: 100,
        total_avail_bytes: 50,
        total_used_bytes: 50,
        total_used_raw_ratio: 0.5,
        num_osds: 3,
      },
      pools: [
        {
          name: "rep",
          id: 1,
          stats: {
            stored: 10,
            bytes_used: 10,
            percent_used: 0.1,
            max_avail: 40,
            objects: 5,
          },
        },
        {
          name: "ec",
          id: 2,
          stats: {
            stored: 20,
            bytes_used: 20,
            percent_used: 0.2,
            max_avail: 30,
            objects: 7,
          },
        },
      ],
    });
    const detail = JSON.stringify([
      {
        pool_name: "rep",
        pool: 1,
        type: 1,
        size: 3,
        min_size: 2,
        pg_num: 32,
        erasure_code_profile: "",
      },
      {
        pool_name: "ec",
        pool: 2,
        type: 3,
        size: 5,
        min_size: 4,
        pg_num: 128,
        erasure_code_profile: "ec_k3_m2_host",
      },
    ]);
    const s = vSession((body) =>
      body.includes("osd pool ls detail")
        ? { code: 0, stdout: detail, stderr: "" }
        : { code: 0, stdout: df, stderr: "" }
    );
    const report = await capacityReport(deps, s);
    assertEquals(report.poolCount, 2);
    assertEquals(report.partialCount, 0);
    const ec = report.pools.find((p) => p.name === "ec")!;
    assertEquals(ec.poolType, "erasure");
    assertEquals([
      ec.size,
      ec.minSize,
      ec.minSizeMargin,
      ec.pgNum,
      ec.ecProfile,
    ], [5, 4, 1, 128, "ec_k3_m2_host"]);
    assertEquals(ec.storedBytes, 20);
    const rep = report.pools.find((p) => p.name === "rep")!;
    assertEquals([rep.size, rep.minSize, rep.minSizeMargin, rep.ecProfile], [
      3,
      2,
      1,
      null,
    ]);
    assertEquals(report.atRiskPools, ["ec"]);
    assertEquals(report.unjudgedPools, []);
    assertEquals(report.cluster.numOsds, 3);
  },
);

Deno.test("capacity marks partial pools and unjudged EC pools", async () => {
  const df = JSON.stringify({
    stats: {},
    pools: [{ name: "extra", id: 9, stats: { stored: 1 } }],
  });
  const detail = JSON.stringify([
    {
      pool_name: "ec",
      pool: 2,
      type: 3,
      size: 6,
      pg_num: 64,
      erasure_code_profile: "ec_k3_m2_host",
    },
  ]);
  const s = vSession((body) =>
    body.includes("osd pool ls detail")
      ? { code: 0, stdout: detail, stderr: "" }
      : { code: 0, stdout: df, stderr: "" }
  );
  const report = await capacityReport(deps, s);
  assertEquals(report.poolCount, 2);
  assertEquals(report.partialCount, 2);
  const extra = report.pools.find((p) => p.name === "extra")!;
  assertEquals(extra.partial, true);
  assertEquals(extra.size, null);
  assertEquals(extra.storedBytes, 1);
  // EC with no min_size -> unjudged, never silently omitted.
  assertEquals(report.atRiskPools, []);
  assertEquals(report.unjudgedPools, ["ec"]);
  assertEquals(report.cluster.totalBytes, null);
});

Deno.test("capacity throws on a cluster with no pools", async () => {
  const s = vSession((body) =>
    body.includes("osd pool ls detail")
      ? { code: 0, stdout: "[]", stderr: "" }
      : { code: 0, stdout: '{"stats":{},"pools":[]}', stderr: "" }
  );
  await assertRejects(() => capacityReport(deps, s), PhaseError, "no pools");
});

Deno.test(
  "mon placement judges quorum, mapping and majority over monmap entries", // leak-allow(decision D42)
  async () => {
    const mk = (quorum: string, ps: string, hosts: string) =>
      vSession((body) => {
        if (body.includes("quorum_status")) {
          return { code: 0, stdout: quorum, stderr: "" };
        }
        if (body.includes("orch ps")) {
          return { code: 0, stdout: ps, stderr: "" };
        }
        if (body.includes("orch host ls")) {
          return { code: 0, stdout: hosts, stderr: "" };
        }
        return { code: 0, stdout: "[]", stderr: "" };
      });
    const quorum =
      '{"monmap":{"mons":[{"name":"a"},{"name":"b"},{"name":"c"},{"name":"d"},{"name":"e"}]},"quorum_names":["a","b","c","d","e"]}';
    const ps = JSON.stringify(
      ["a", "b", "c", "d", "e"].map((h) => ({
        daemon_type: "mon",
        daemon_id: h,
        hostname: h,
      })),
    );
    const hosts = JSON.stringify(
      ["a", "b", "c", "d", "e"].map((h) => ({ hostname: h, status: "" })),
    );
    assertEquals(
      (await verifyMonPlacement(deps, mk(quorum, ps, hosts), [
        "a",
        "b",
        "c",
        "d",
        "e",
      ])).pass,
      true,
    );
    const shrunk = await verifyMonPlacement(deps, mk(quorum, ps, hosts), [
      "a",
      "b",
    ]);
    assertEquals(shrunk.pass, false);
    assertEquals(
      (shrunk.actual as { majorityKept: boolean }).majorityKept,
      false,
    );
    const unknown = await verifyMonPlacement(deps, mk(quorum, ps, hosts), [
      "a",
      "b",
      "c",
      "d",
      "e",
      "z",
    ]);
    assertEquals(unknown.detail.unknownPlacementHosts as string[], ["z"]);
  },
);

Deno.test("mon placement fails closed on an unmapped or out-of-quorum mon", async () => {
  const quorum =
    '{"monmap":{"mons":[{"name":"mon1"},{"name":"node-a"}]},"quorum_names":["mon1","node-a"]}';
  const ps = JSON.stringify([{
    daemon_type: "mon",
    daemon_id: "mon1",
    hostname: "node-x",
  }]);
  const hosts = JSON.stringify([{ hostname: "node-x", status: "" }, {
    hostname: "node-a",
    status: "",
  }]);
  const s = vSession((body) =>
    body.includes("quorum_status")
      ? { code: 0, stdout: quorum, stderr: "" }
      : body.includes("orch ps")
      ? { code: 0, stdout: ps, stderr: "" }
      : { code: 0, stdout: hosts, stderr: "" }
  );
  const verdict = await verifyMonPlacement(deps, s, ["node-x", "node-a"]);
  assertEquals(verdict.pass, false);
  assertEquals(verdict.detail.unmappedMons as string[], ["node-a"]);
});

Deno.test("mgr placement reports a collision with an active MDS", async () => {
  const mgr = '{"active_name":"mgr1"}';
  const fs =
    '{"filesystems":[{"mdsmap":{"fs_name":"cephfs","info":{"0":{"name":"mds1","state":"up:active"},"1":{"name":"mds2","state":"up:standby-replay"}}}}]}';
  const ps = JSON.stringify([
    { daemon_type: "mgr", daemon_id: "mgr1", hostname: "node-mgr" },
    { daemon_type: "mds", daemon_id: "mds1", hostname: "node-mds" },
    { daemon_type: "mds", daemon_id: "mds2", hostname: "node-standby" },
  ]);
  const hosts = JSON.stringify(
    ["node-mgr", "node-mds", "node-standby"].map((h) => ({
      hostname: h,
      status: "",
    })),
  );
  const mk = () =>
    vSession((body) => {
      if (body.includes("mgr dump")) {
        return { code: 0, stdout: mgr, stderr: "" };
      }
      if (body.includes("fs dump")) return { code: 0, stdout: fs, stderr: "" };
      if (body.includes("orch ps")) return { code: 0, stdout: ps, stderr: "" };
      return { code: 0, stdout: hosts, stderr: "" };
    });
  const collision = await verifyMgrPlacement(deps, mk(), ["node-mds"]);
  assertEquals(collision.pass, false);
  assertEquals(
    (collision.actual as { besideActiveMds: string[] }).besideActiveMds,
    ["node-mds"],
  );
  // Naming only the standby-replay host passes; no filesystems passes.
  assertEquals(
    (await verifyMgrPlacement(deps, mk(), ["node-standby"])).pass,
    true,
  );
  const none = vSession((body) => {
    if (body.includes("mgr dump")) {
      return { code: 0, stdout: '{"active_name":"mgr1"}', stderr: "" };
    }
    if (body.includes("fs dump")) {
      return { code: 0, stdout: '{"filesystems":[]}', stderr: "" };
    }
    if (body.includes("orch ps")) return { code: 0, stdout: ps, stderr: "" };
    return { code: 0, stdout: hosts, stderr: "" };
  });
  assertEquals((await verifyMgrPlacement(deps, none, ["node-mgr"])).pass, true);
});
