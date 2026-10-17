import { assertEquals, assertRejects } from "jsr:@std/assert@1.0.19";
import { PhaseError, TransportError } from "./errors.ts";
import type { CommandResult, SshSession } from "./ssh.ts";
import {
  crushFailureDomain,
  persistVerdict,
  selectCrushRule,
  settle,
  verifyCsiUsers,
  verifyMgr,
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
    target: { host: "192.0.2.10", user: "admin" },
    controlPath: null,
    run: (opts) => {
      if (opts.command === "mktemp -d") {
        dir++;
        return Promise.resolve({
          code: 0,
          stdout: `/tmp/tmp.${dir}\n`,
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
