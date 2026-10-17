import { assertEquals, assertRejects } from "jsr:@std/assert@1.0.19";
import { PhaseError } from "./errors.ts";
import type { CommandResult, SshSession } from "./ssh.ts";
import {
  capPairs,
  createCsiUser,
  createFs,
  createPool,
  deleteFs,
  fetchCsiKey,
  getConnBundle,
  parseAuthEntities,
  profileMatches,
  removeOsds,
  ruleMatches,
} from "./dataplane.ts";

const deps = {
  now: () => 0,
  sleep: () => Promise.resolve(),
  random: () => 0.5,
};

function dpSession(
  route: (body: string) => CommandResult,
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
        return Promise.resolve(route(scriptBody));
      }
      if (opts.command.startsWith("rm -rf")) {
        return Promise.resolve({ code: 0, stdout: "", stderr: "" });
      }
      return Promise.resolve({ code: 1, stdout: "", stderr: "unrouted" });
    },
    close: () => Promise.resolve({ closed: false, detail: "not multiplexed" }),
  };
  return { session, bodies };
}

Deno.test("pool rule and profile matchers compare structure, not names", () => {
  assertEquals(
    ruleMatches(
      { steps: [{ item_name: "default" }, { type: "host" }] },
      "host",
    ),
    true,
  );
  assertEquals(
    ruleMatches({ steps: [{ item_name: "other" }, { type: "host" }] }, "host"),
    false,
  );
  assertEquals(
    profileMatches(
      { k: "4", m: "2", "crush-failure-domain": "host" },
      4,
      2,
      "host",
    ),
    true,
  );
  assertEquals(
    profileMatches(
      { k: "3", m: "2", "crush-failure-domain": "host" },
      4,
      2,
      "host",
    ),
    false,
  );
  assertEquals(
    profileMatches(
      { k: 4, m: 2, "crush-failure-domain": "host", "crush-root": "other" },
      4,
      2,
      "host",
    ),
    false,
  );
});

Deno.test("auth entities parse from both shapes", () => {
  const bare = parseAuthEntities([
    { entity: "client.csi-rbd", caps: { mon: "allow r" }, key: "SECRET" },
  ]);
  assertEquals(bare.length, 1);
  assertEquals(bare[0].caps.mon, "allow r");
  const wrapped = parseAuthEntities({
    auth_dump: [{ entity: "client.x", caps: { osd: "allow rw" } }],
  });
  assertEquals(wrapped[0].entity, "client.x");
  assertEquals(wrapped[0].caps.osd, "allow rw");
});

Deno.test("cap pairs are ordered and include mds only when given", () => {
  assertEquals(capPairs({ mon: "a", mgr: "b", osd: "c" }), [["mon", "a"], [
    "mgr",
    "b",
  ], ["osd", "c"]]);
  assertEquals(capPairs({ mon: "a", mgr: "b", osd: "c", mds: "d" }), [
    ["mon", "a"],
    ["mgr", "b"],
    ["osd", "c"],
    ["mds", "d"],
  ]);
});

Deno.test("a new replicated pool creates the rule, pool, size and application in order", async () => {
  const s = dpSession((body) => {
    if (body.includes("osd pool ls detail")) {
      return { code: 0, stdout: "[]", stderr: "" };
    }
    if (body.includes("osd crush rule ls")) {
      return { code: 0, stdout: "[]", stderr: "" };
    }
    if (body.includes("create-replicated")) {
      return { code: 0, stdout: "", stderr: "" };
    }
    if (body.includes("osd pool create")) {
      return { code: 0, stdout: "", stderr: "" };
    }
    if (body.includes("osd pool set")) {
      return { code: 0, stdout: "", stderr: "" };
    }
    if (body.includes("application enable")) {
      return { code: 0, stdout: "", stderr: "" };
    }
    if (body.includes("rbd pool init")) {
      return { code: 0, stdout: "", stderr: "" };
    }
    return { code: 0, stdout: "[]", stderr: "" };
  });
  const record = await createPool(deps, s.session, {
    name: "rbd",
    scheme: "replicated",
    size: 3,
    application: "rbd",
    failureDomain: "host",
  });
  assertEquals(record.existed, false);
  assertEquals(record.crushRule, "host_rule");
  assertEquals(record.changed, [
    "crushRule:host_rule",
    "created",
    "size:3",
    "application:rbd",
  ]);
  assertEquals(s.bodies.some((b) => b.includes("rbd pool init")), true);
});

Deno.test("an existing matching pool changes nothing and is not re-created", async () => {
  const s = dpSession((body) => {
    if (body.includes("osd pool ls detail")) {
      return {
        code: 0,
        stdout:
          '[{"pool_name":"rbd","type":1,"size":3,"crush_rule":7,"application_metadata":{"rbd":{}}}]',
        stderr: "",
      };
    }
    if (body.includes("osd crush rule dump")) {
      return {
        code: 0,
        stdout:
          '{"rule_id":7,"steps":[{"item_name":"default"},{"type":"host"}]}',
        stderr: "",
      };
    }
    if (body.includes("rbd pool init")) {
      return { code: 0, stdout: "", stderr: "" };
    }
    return { code: 0, stdout: "", stderr: "" };
  });
  const record = await createPool(deps, s.session, {
    name: "rbd",
    scheme: "replicated",
    size: 3,
    application: "rbd",
    failureDomain: "host",
  });
  assertEquals(record.existed, true);
  assertEquals(record.changed, []);
  assertEquals(s.bodies.some((b) => b.includes("osd pool create")), false);
});

Deno.test("a mismatched existing pool is refused before any change", async () => {
  const s = dpSession((body) =>
    body.includes("osd pool ls detail")
      ? {
        code: 0,
        stdout:
          '[{"pool_name":"p","type":3,"erasure_code_profile":"ec_k2_m1_host"}]',
        stderr: "",
      }
      : { code: 0, stdout: "", stderr: "" }
  );
  await assertRejects(
    () =>
      createPool(deps, s.session, {
        name: "p",
        scheme: "replicated",
        size: 2,
        application: "rbd",
        failureDomain: "host",
      }),
    PhaseError,
    "different scheme",
  );
  assertEquals(s.bodies.some((b) => b.includes("osd pool create")), false);
});

Deno.test("replicated with a missing size is refused after the read, before any change", async () => {
  const s = dpSession(() => ({ code: 0, stdout: "[]", stderr: "" }));
  await assertRejects(
    () =>
      createPool(deps, s.session, {
        name: "p",
        scheme: "replicated",
        size: null,
        application: "rbd",
        failureDomain: "host",
      }),
    PhaseError,
    "size is required",
  );
});

Deno.test("a new EC pool sets its profile and never a size", async () => {
  const s = dpSession((body) => {
    if (body.includes("osd pool ls detail")) {
      return { code: 0, stdout: "[]", stderr: "" };
    }
    if (body.includes("erasure-code-profile ls")) {
      return { code: 0, stdout: "[]", stderr: "" };
    }
    return { code: 0, stdout: "", stderr: "" };
  });
  const record = await createPool(deps, s.session, {
    name: "ec",
    scheme: "erasure",
    erasureProfile: { k: 4, m: 2 },
    application: "rgw",
    failureDomain: "host",
  });
  assertEquals(record.erasureCodeProfile, "ec_k4_m2_host");
  assertEquals(
    record.changed.includes("erasureCodeProfile:ec_k4_m2_host"),
    true,
  );
  assertEquals(record.size, undefined);
  assertEquals(s.bodies.some((b) => b.includes("osd pool set")), false);
  assertEquals(s.bodies.some((b) => b.includes("rbd pool init")), false);
});

Deno.test("filesystem creation takes the create, adopt or existing path", async () => {
  // Existing volume: only fs ls and the MDS apply.
  const existing = dpSession((body) => {
    if (body.includes("fs ls")) {
      return { code: 0, stdout: '[{"name":"cephfs"}]', stderr: "" };
    }
    if (body.includes("orch ls --service_name 'mds.cephfs'")) {
      return { code: 0, stdout: "[]", stderr: "" };
    }
    if (body.includes("orch apply mds")) {
      return { code: 0, stdout: "", stderr: "" };
    }
    return { code: 0, stdout: "[]", stderr: "" };
  });
  const r1 = await createFs(deps, existing.session, {
    name: "cephfs",
    placement: ["b", "a"],
  });
  assertEquals(r1.existed, true);
  assertEquals(r1.creationPath, "already existed");
  assertEquals(r1.mdsHosts, ["a", "b"]);
  assertEquals(
    existing.bodies.some((b) => b.includes("fs volume create")),
    false,
  );

  // Fresh: fs volume create.
  const fresh = dpSession((body) => {
    if (body.includes("fs ls")) return { code: 0, stdout: "[]", stderr: "" };
    if (body.includes("osd pool ls")) {
      return { code: 0, stdout: "[]", stderr: "" };
    }
    if (body.includes("fs volume create")) {
      return { code: 0, stdout: "", stderr: "" };
    }
    return { code: 0, stdout: "[]", stderr: "" };
  });
  const r2 = await createFs(deps, fresh.session, {
    name: "cephfs",
    placement: ["a"],
  });
  assertEquals(r2.creationPath, "fs volume create");
});

Deno.test("adopting an EC data pool requires ec_overwrites", async () => {
  const s = dpSession((body) => {
    if (body.includes("fs ls")) return { code: 0, stdout: "[]", stderr: "" };
    if (body === body && body.includes("osd pool ls detail")) {
      return {
        code: 0,
        stdout:
          '[{"pool_name":"cephfs.cephfs.data","erasure_code_profile":"ec_k2_m1_host","flags_names":"ec_overwrites"}]',
        stderr: "",
      };
    }
    if (body.includes("osd pool ls")) {
      return {
        code: 0,
        stdout: '["cephfs.cephfs.meta","cephfs.cephfs.data"]',
        stderr: "",
      };
    }
    if (body.includes("fs new")) return { code: 0, stdout: "", stderr: "" };
    return { code: 0, stdout: "[]", stderr: "" };
  });
  const r = await createFs(deps, s.session, {
    name: "cephfs",
    placement: ["a"],
  });
  assertEquals(r.creationPath, "fs new (adopted pools)");
  assertEquals(s.bodies.some((b) => b.includes("--force")), true);

  const bad = dpSession((body) => {
    if (body.includes("fs ls")) return { code: 0, stdout: "[]", stderr: "" };
    if (body.includes("osd pool ls detail")) {
      return {
        code: 0,
        stdout:
          '[{"pool_name":"cephfs.cephfs.data","erasure_code_profile":"ec_k2_m1_host","flags_names":""}]',
        stderr: "",
      };
    }
    if (body.includes("osd pool ls")) {
      return {
        code: 0,
        stdout: '["cephfs.cephfs.meta","cephfs.cephfs.data"]',
        stderr: "",
      };
    }
    return { code: 0, stdout: "[]", stderr: "" };
  });
  await assertRejects(
    () => createFs(deps, bad.session, { name: "cephfs", placement: ["a"] }),
    PhaseError,
    "allow_ec_overwrites",
  );
});

Deno.test("CSI user creation runs every command, discards the key and refuses reserved names", async () => {
  const s = dpSession((body) => {
    if (body.includes("auth get-or-create")) {
      return {
        code: 0,
        stdout: "[client.csi-rbd]\n\tkey = SECRETKEY\n",
        stderr: "",
      };
    }
    if (body.includes("auth caps")) return { code: 0, stdout: "", stderr: "" };
    if (body.includes("auth get ")) {
      return {
        code: 0,
        stdout:
          '[{"entity":"client.csi-rbd","caps":{"mon":"allow r","mgr":"allow r","osd":"allow rw"},"key":"SECRETKEY"}]',
        stderr: "",
      };
    }
    return { code: 0, stdout: "", stderr: "" };
  });
  const record = await createCsiUser(deps, s.session, {
    name: "csi-rbd",
    caps: { mon: "allow r", mgr: "allow r", osd: "allow rw" },
  });
  assertEquals(record, {
    name: "csi-rbd",
    caps: { mon: "allow r", mgr: "allow r", osd: "allow rw" },
  });
  assertEquals(JSON.stringify(record).includes("SECRETKEY"), false);
  assertEquals(s.bodies.some((b) => b.includes("auth caps")), true);

  await assertRejects(
    () =>
      createCsiUser(deps, s.session, {
        name: "admin",
        caps: { mon: "allow r", mgr: "allow r", osd: "allow r" },
      }),
    PhaseError,
    "reserved entity",
  );
  await assertRejects(
    () =>
      createCsiUser(deps, s.session, {
        name: "bootstrap-osd",
        caps: { mon: "allow r", mgr: "allow r", osd: "allow r" },
      }),
    PhaseError,
    "reserved entity",
  );
});

Deno.test("the connection bundle keeps only v2 endpoints and csi entities", async () => {
  const s = dpSession((body) => {
    if (body.includes("mon dump")) {
      return {
        code: 0,
        stdout:
          '{"fsid":"f","mons":[{"public_addrs":{"addrvec":[{"type":"v2","addr":"192.0.2.10:3300"},{"type":"v1","addr":"192.0.2.10:6789"}]}},{"public_addrs":{"addrvec":[{"type":"v2","addr":"198.51.100.9:3300"}]}}]}',
        stderr: "",
      };
    }
    if (body.includes("osd pool ls")) {
      return { code: 0, stdout: '["a","b"]', stderr: "" };
    }
    if (body.includes("fs ls")) {
      return { code: 0, stdout: '[{"name":"cephfs"}]', stderr: "" };
    }
    if (body.includes("auth ls")) {
      return {
        code: 0,
        stdout:
          '{"auth_dump":[{"entity":"client.admin"},{"entity":"client.bootstrap-osd"},{"entity":"client.csi-rbd"},{"entity":"client.csi-cephfs"},{"entity":"mgr.x"}]}',
        stderr: "",
      };
    }
    return { code: 0, stdout: "[]", stderr: "" };
  });
  const bundle = await getConnBundle(deps, s.session);
  assertEquals(bundle.monEndpoints, ["192.0.2.10:3300", "198.51.100.9:3300"]);
  assertEquals(bundle.csiUserNames, ["csi-cephfs", "csi-rbd"]);
  assertEquals(bundle.fsid, "f");
});

Deno.test("fetching a key validates a single base64 line and withholds stdout on failure", async () => {
  const good = dpSession(() => ({ code: 0, stdout: "AQAAAA==\n", stderr: "" }));
  assertEquals(await fetchCsiKey(deps, good.session, "csi-rbd"), {
    userName: "csi-rbd",
    key: "AQAAAA==",
  });
  const bad = dpSession(() => ({
    code: 0,
    stdout: "warning: not a key\n",
    stderr: "",
  }));
  try {
    await fetchCsiKey(deps, bad.session, "csi-rbd");
    throw new Error("should throw");
  } catch (e) {
    assertEquals((e as Error).message.includes("not a key"), false);
  }
});

Deno.test("OSD removal outs before removing, zaps by default and skips absent ids", async () => {
  let call = 0;
  const s = dpSession((body) => {
    if (body.includes("osd tree")) {
      call++;
      return call === 1
        ? { code: 0, stdout: '{"nodes":[{"id":3,"type":"osd"}]}', stderr: "" }
        : { code: 0, stdout: '{"nodes":[]}', stderr: "" };
    }
    if (body.includes("health detail")) {
      return { code: 0, stdout: '{"status":"HEALTH_OK"}', stderr: "" };
    }
    if (body.includes("ok-to-stop")) {
      return { code: 0, stdout: "presumed safe", stderr: "" };
    }
    return { code: 0, stdout: "", stderr: "" };
  });
  const record = await removeOsds(deps, s.session, { osdIds: [3] });
  assertEquals(record.removed, [3]);
  assertEquals(record.skippedAbsent, []);
  const outAt = s.bodies.findIndex((b) => b.includes("osd out 3"));
  const rmAt = s.bodies.findIndex((b) => b.includes("orch osd rm 3 --zap"));
  assertEquals(outAt >= 0 && outAt < rmAt, true);

  const absent = dpSession(() => ({
    code: 0,
    stdout: '{"nodes":[]}',
    stderr: "",
  }));
  const r2 = await removeOsds(deps, absent.session, { osdIds: [9] });
  assertEquals(r2.removed, []);
  assertEquals(r2.skippedAbsent, [9]);
  assertEquals(absent.bodies.some((b) => b.includes("osd out")), false);
});

Deno.test("deleting a filesystem confirms, polls MDS removal and restores the gate", async () => {
  const mismatch = dpSession(() => {
    throw new Error("should not be called");
  });
  let calls = 0;
  await assertRejects(
    () => deleteFs(deps, mismatch.session, { fsName: "a", confirmFsName: "b" }),
    PhaseError,
    "does not match",
  );
  assertEquals(mismatch.bodies.length, 0);

  let poolReads = 0;
  const s = dpSession((body) => {
    if (body.includes("fs status")) {
      return {
        code: 0,
        stdout: '{"clients":[{"fs":"cephfs","clients":0}]}',
        stderr: "",
      };
    }
    if (body.includes("fs ls")) {
      calls++;
      return {
        code: 0,
        stdout: calls === 1
          ? '[{"name":"cephfs","metadata_pool":"cephfs.cephfs.meta","data_pools":["cephfs.cephfs.data"]}]'
          : "[]",
        stderr: "",
      };
    }
    if (body.includes("osd pool ls")) {
      poolReads++;
      return {
        code: 0,
        stdout: poolReads === 1
          ? '["cephfs.cephfs.meta","cephfs.cephfs.data",".mgr"]'
          : '[".mgr"]',
        stderr: "",
      };
    }
    if (body.includes("orch rm")) return { code: 0, stdout: "", stderr: "" };
    if (body.includes("orch ls")) {
      return { code: 0, stdout: "No services reported", stderr: "" };
    }
    if (body.includes("fs volume rm")) {
      return { code: 0, stdout: "", stderr: "" };
    }
    return { code: 0, stdout: "", stderr: "" };
  });
  const record = await deleteFs(deps, s.session, {
    fsName: "cephfs",
    confirmFsName: "cephfs",
  });
  assertEquals(record.deleted, true);
  assertEquals(record.gateRestored, true);
  assertEquals(record.mdsServiceRemoved, true);
  const on = s.bodies.findIndex((b) =>
    b.includes("mon_allow_pool_delete true")
  );
  const off = s.bodies.findIndex((b) =>
    b.includes("mon_allow_pool_delete false")
  );
  assertEquals(on >= 0 && on < off, true);
  assertEquals(
    s.bodies.some((b) => b.includes("--yes-i-really-mean-it")),
    true,
  );
});

Deno.test(
  "an existing pool whose rule structure or EC profile content drifted is refused", // leak-allow(decision D31)
  async () => {
    // Same rule id, but the rule chooses the wrong failure domain.
    const ruleDrift = dpSession((body) => {
      if (body.includes("osd pool ls detail")) {
        return {
          code: 0,
          stdout:
            '[{"pool_name":"p","type":1,"size":3,"crush_rule":7,"application_metadata":{"rbd":{}}}]',
          stderr: "",
        };
      }
      if (body.includes("osd crush rule dump")) {
        return {
          code: 0,
          stdout:
            '{"rule_id":7,"steps":[{"item_name":"default"},{"type":"rack"}]}',
          stderr: "",
        };
      }
      return { code: 0, stdout: "", stderr: "" };
    });
    await assertRejects(
      () =>
        createPool(deps, ruleDrift.session, {
          name: "p",
          scheme: "replicated",
          size: 3,
          application: "rbd",
          failureDomain: "host",
        }),
      PhaseError,
      "different CRUSH rule",
    );

    // Same profile name, different content.
    const profileDrift = dpSession((body) => {
      if (body.includes("osd pool ls detail")) {
        return {
          code: 0,
          stdout:
            '[{"pool_name":"p","type":3,"erasure_code_profile":"ec_k4_m2_host"}]',
          stderr: "",
        };
      }
      if (body.includes("erasure-code-profile get")) {
        return {
          code: 0,
          stdout: '{"k":"4","m":"3","crush-failure-domain":"host"}',
          stderr: "",
        };
      }
      return { code: 0, stdout: "", stderr: "" };
    });
    await assertRejects(
      () =>
        createPool(deps, profileDrift.session, {
          name: "p",
          scheme: "erasure",
          erasureProfile: { k: 4, m: 2 },
          application: "rgw",
          failureDomain: "host",
        }),
      PhaseError,
      "EC profile does not match",
    );
  },
);

Deno.test("the pool-delete gate is reset even when turning it on fails", async () => {
  let fsLs = 0;
  const s = dpSession((body) => {
    if (body.includes("fs status")) {
      return {
        code: 0,
        stdout: '{"clients":[{"fs":"cephfs","clients":0}]}',
        stderr: "",
      };
    }
    if (body.includes("fs ls")) {
      fsLs++;
      return {
        code: 0,
        stdout: fsLs === 1
          ? '[{"name":"cephfs","metadata_pool":"cephfs.cephfs.meta","data_pools":["cephfs.cephfs.data"]}]'
          : "[]",
        stderr: "",
      };
    }
    if (body.includes("osd pool ls")) {
      return {
        code: 0,
        stdout: '["cephfs.cephfs.meta","cephfs.cephfs.data",".mgr"]',
        stderr: "",
      };
    }
    if (body.includes("orch ls")) {
      return { code: 0, stdout: "No services reported", stderr: "" };
    }
    // The gate-on call fails after it may have run.
    if (body.includes("mon_allow_pool_delete true")) {
      return { code: 1, stdout: "", stderr: "session lost" };
    }
    return { code: 0, stdout: "", stderr: "" };
  });
  await assertRejects(() =>
    deleteFs(deps, s.session, { fsName: "cephfs", confirmFsName: "cephfs" })
  );
  assertEquals(
    s.bodies.some((b) => b.includes("mon_allow_pool_delete false")),
    true,
  );
  assertEquals(
    s.bodies.some((b) => b.includes("--yes-i-really-mean-it")),
    false,
    "the volume was never removed",
  );
});

Deno.test("OSD removal refuses by itself on HEALTH_ERR", async () => {
  const s = dpSession((body) => {
    if (body.includes("osd tree")) {
      return {
        code: 0,
        stdout: '{"nodes":[{"id":3,"type":"osd"}]}',
        stderr: "",
      };
    }
    if (body.includes("health detail")) {
      return { code: 0, stdout: '{"status":"HEALTH_ERR"}', stderr: "" };
    }
    return { code: 0, stdout: "", stderr: "" };
  });
  await assertRejects(
    () => removeOsds(deps, s.session, { osdIds: [3] }),
    PhaseError,
    "HEALTH_ERR",
  );
  assertEquals(s.bodies.some((b) => b.includes("osd out")), false);
  assertEquals(s.bodies.some((b) => b.includes("orch osd rm")), false);
});

Deno.test("OSD removal refuses by itself when ok-to-stop rejects the set", async () => {
  const s = dpSession((body) => {
    if (body.includes("osd tree")) {
      return {
        code: 0,
        stdout: '{"nodes":[{"id":3,"type":"osd"},{"id":5,"type":"osd"}]}',
        stderr: "",
      };
    }
    if (body.includes("health detail")) {
      return { code: 0, stdout: '{"status":"HEALTH_OK"}', stderr: "" };
    }
    if (body.includes("ok-to-stop")) {
      return {
        code: 1,
        stdout: "",
        stderr: "OSDs 3,5 are not safe to stop together",
      };
    }
    return { code: 0, stdout: "", stderr: "" };
  });
  await assertRejects(
    () => removeOsds(deps, s.session, { osdIds: [3, 5] }),
    PhaseError,
    "refuses to stop",
  );
  assertEquals(s.bodies.some((b) => b.includes("osd out")), false);
  assertEquals(s.bodies.some((b) => b.includes("orch osd rm")), false);
});

Deno.test("OSD removal proceeds for an in-service OSD gated only by ok-to-stop", async () => {
  // `osd safe-to-destroy` would return EBUSY here; ok-to-stop passes and the
  // orchestrator performs the drain.
  let tree = 0;
  const s = dpSession((body) => {
    if (body.includes("osd tree")) {
      tree++;
      return {
        code: 0,
        stdout: tree === 1
          ? '{"nodes":[{"id":3,"type":"osd"}]}'
          : '{"nodes":[]}',
        stderr: "",
      };
    }
    if (body.includes("health detail")) {
      return { code: 0, stdout: '{"status":"HEALTH_OK"}', stderr: "" };
    }
    if (body.includes("ok-to-stop")) {
      return { code: 0, stdout: "presumed safe", stderr: "" };
    }
    return { code: 0, stdout: "", stderr: "" };
  });
  const record = await removeOsds(deps, s.session, { osdIds: [3] });
  assertEquals(record.removed, [3]);
  const okAt = s.bodies.findIndex((b) => b.includes("ok-to-stop 3"));
  const outAt = s.bodies.findIndex((b) => b.includes("osd out 3"));
  assertEquals(okAt >= 0 && okAt < outAt, true);
});

Deno.test("OSD removal fails closed when health cannot be judged", async () => {
  const s = dpSession((body) => {
    if (body.includes("osd tree")) {
      return {
        code: 0,
        stdout: '{"nodes":[{"id":3,"type":"osd"}]}',
        stderr: "",
      };
    }
    // Missing status.
    if (body.includes("health detail")) {
      return { code: 0, stdout: "{}", stderr: "" };
    }
    return { code: 0, stdout: "", stderr: "" };
  });
  await assertRejects(
    () => removeOsds(deps, s.session, { osdIds: [3] }),
    PhaseError,
    "not HEALTH_OK or HEALTH_WARN",
  );
  assertEquals(s.bodies.some((b) => b.includes("osd out")), false);
});

Deno.test("filesystem deletion fails closed when the client count is unreadable", async () => {
  for (
    const stdout of [
      '{"clients":[{"fs":"other","clients":0}]}',
      '{"clients":[{"fs":"cephfs","clients":"two"}]}',
      "{}",
    ]
  ) {
    const s = dpSession((body) => {
      if (body.includes("fs status")) return { code: 0, stdout, stderr: "" };
      if (body.includes("fs ls")) {
        return {
          code: 0,
          stdout:
            '[{"name":"cephfs","metadata_pool":"cephfs.cephfs.meta","data_pools":["cephfs.cephfs.data"]}]',
          stderr: "",
        };
      }
      return { code: 0, stdout: "", stderr: "" };
    });
    await assertRejects(
      () =>
        deleteFs(deps, s.session, {
          fsName: "cephfs",
          confirmFsName: "cephfs",
        }),
      PhaseError,
      "could not read the filesystem client count",
    );
    assertEquals(s.bodies.some((b) => b.includes("orch rm")), false);
  }
});

Deno.test("filesystem deletion refuses by itself while clients are connected", async () => {
  const s = dpSession((body) => {
    if (body.includes("fs status")) {
      return {
        code: 0,
        stdout: '{"clients":[{"fs":"cephfs","clients":2}]}',
        stderr: "",
      };
    }
    if (body.includes("fs ls")) {
      return {
        code: 0,
        stdout:
          '[{"name":"cephfs","metadata_pool":"cephfs.cephfs.meta","data_pools":["cephfs.cephfs.data"]}]',
        stderr: "",
      };
    }
    return { code: 0, stdout: "", stderr: "" };
  });
  await assertRejects(
    () =>
      deleteFs(deps, s.session, { fsName: "cephfs", confirmFsName: "cephfs" }),
    PhaseError,
    "in use by clients",
  );
  assertEquals(s.bodies.some((b) => b.includes("orch rm")), false);
  assertEquals(s.bodies.some((b) => b.includes("fs volume rm")), false);
});
