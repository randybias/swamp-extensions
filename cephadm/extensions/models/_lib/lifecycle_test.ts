import { assertEquals, assertRejects } from "jsr:@std/assert@1.0.19";
import { PhaseError, TransportError } from "./errors.ts";
import type { CommandResult, RunOptions, SshSession } from "./ssh.ts";
import {
  applyPlacement,
  bootstrapCluster,
  bootstrapCompound,
  bootstrapConfPath,
  distributeKeyToHost,
  distributeRecordKey,
  evaluateMonQuorum,
  hostAdd,
  ipInCidr,
  keyNeedle,
  normalisePlacementHost,
  parsePlacement,
  placementConverged,
  probeCephadmLs,
  readCephPubKey,
  validateCephPubKey,
} from "./lifecycle.ts";

const KEY =
  "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExampleExampleExampleExampleExample";
const deps = {
  now: () => 0,
  sleep: () => Promise.resolve(),
  random: () => 0.5,
};

type CephHandler = (args: string) => CommandResult;

/** A fake session that understands both plain commands and cephadm-shell scripts. */
function cephSession(
  handler: CephHandler,
  plain?: (opts: RunOptions) => CommandResult | undefined,
): { session: SshSession; calls: RunOptions[]; cephArgs: string[] } {
  const calls: RunOptions[] = [];
  const cephArgs: string[] = [];
  let dir = 0;
  let scriptBody = "";
  const session: SshSession = {
    target: { host: "192.0.2.10", user: "admin", strictHostKeyChecking: "yes" },
    controlPath: null,
    run: (opts) => {
      calls.push(opts);
      const special = plain?.(opts);
      if (special) return Promise.resolve(special);
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
        const line = scriptBody.split("\n")[2] ?? "";
        const args = line.replace(/^ceph /, "").replace(/ -f json$/, "");
        cephArgs.push(args);
        return Promise.resolve(handler(args));
      }
      if (opts.command.startsWith("rm -rf")) {
        return Promise.resolve({ code: 0, stdout: "", stderr: "" });
      }
      // Host-level cephadm commands (probe, cat ceph.pub, sh -c) fall through.
      cephArgs.push(opts.command);
      return Promise.resolve(handler(opts.command));
    },
    close: () => Promise.resolve({ closed: false, detail: "not multiplexed" }),
  };
  return { session, calls, cephArgs };
}

Deno.test("IPv4 containment is checked against the network block", () => {
  assertEquals(ipInCidr("192.0.2.10", "192.0.2.0/24"), true);
  assertEquals(ipInCidr("198.51.100.9", "192.0.2.0/24"), false);
  assertEquals(ipInCidr("not-an-ip", "192.0.2.0/24"), false);
  assertEquals(ipInCidr("192.0.2.10", "garbage"), false);
});

Deno.test("bootstrap config paths are unique and private", () => {
  let n = 0;
  const random = () => {
    n++;
    return (n % 16) / 16;
  };
  const a = bootstrapConfPath(random);
  const b = bootstrapConfPath(random);
  assertEquals(a === b, false);
  assertEquals(a.startsWith("/tmp/cephadm-bootstrap-"), true);
  assertEquals(a.endsWith(".conf"), true);
});

Deno.test(
  "the bootstrap compound sets public_network through -c and no flag", // leak-allow(decision D23)
  () => {
    const compound = bootstrapCompound({
      conf: "/tmp/cephadm-bootstrap-abc.conf",
      publicNet: "192.0.2.0/24",
      clusterNet: "198.51.100.0/24",
      cephImage: "registry.example.com/ceph/ceph:v19.2.3",
      monIp: "192.0.2.10",
      sshUser: "admin",
    });
    assertEquals(compound.includes("[global]"), true);
    assertEquals(compound.includes("public_network = %s"), true);
    assertEquals(compound.includes("'192.0.2.0/24'"), true);
    assertEquals(compound.includes("--public-network"), false);
    assertEquals(compound.includes("--mon-ip '192.0.2.10'"), true);
    assertEquals(
      compound.includes("--image 'registry.example.com/ceph/ceph:v19.2.3'"),
      true,
    );
    assertEquals(compound.includes("--skip-monitoring-stack"), true);
  },
);

Deno.test("the cephadm ls probe has three outcomes and never passes -f", async () => {
  const none = cephSession(() => ({ code: 0, stdout: "[]", stderr: "" }));
  assertEquals(await probeCephadmLs(none.session), { outcome: "none" });
  assertEquals(none.calls[0].command.includes("cephadm ls"), true);
  assertEquals(none.calls[0].command.includes("-f"), false);

  const found = cephSession(() => ({
    code: 0,
    stdout: '[{"fsid":"3f2a9c1e-5b7d-4e8f-9a0b-1c2d3e4f5a6b"}]',
    stderr: "",
  }));
  assertEquals(await probeCephadmLs(found.session), {
    outcome: "found",
    fsid: "3f2a9c1e-5b7d-4e8f-9a0b-1c2d3e4f5a6b",
  });

  const nonzero = cephSession(() => ({ code: 3, stdout: "", stderr: "boom" }));
  assertEquals((await probeCephadmLs(nonzero.session)).outcome, "unknown");
  const bad = cephSession(() => ({ code: 0, stdout: "not json", stderr: "" }));
  assertEquals((await probeCephadmLs(bad.session)).outcome, "unknown");
  const object = cephSession(() => ({ code: 0, stdout: "{}", stderr: "" }));
  assertEquals((await probeCephadmLs(object.session)).outcome, "unknown");
});

Deno.test("ceph.pub must be a single valid public key", async () => {
  const good = cephSession(
    () => ({ code: 0, stdout: `${KEY}\n`, stderr: "" }),
    (opts) =>
      opts.command.startsWith("cat /etc/ceph/ceph.pub")
        ? { code: 0, stdout: `${KEY}\n`, stderr: "" }
        : undefined,
  );
  assertEquals(await readCephPubKey(good.session), KEY);
  assertEquals(validateCephPubKey(KEY), KEY);
  try {
    validateCephPubKey('command="x" ' + KEY);
    throw new Error("should throw");
  } catch (e) {
    assertEquals(e instanceof PhaseError, true);
  }
});

Deno.test(
  "bootstrap creates a cluster, recovers from a lost session, and never re-probes a non-zero exit", // leak-allow(decision D22)
  async () => {
    let probes = 0;
    const ok = cephSession((args) => {
      if (args === "fsid") return { code: 0, stdout: "fsid", stderr: "" };
      return { code: 0, stdout: "[]", stderr: "" };
    }, (opts) => {
      if (opts.command === "cephadm ls") {
        probes++;
        return {
          code: 0,
          stdout: probes === 1 ? "[]" : '[{"fsid":"abc"}]',
          stderr: "",
        };
      }
      if (opts.command.startsWith("sh -c")) {
        return { code: 0, stdout: "", stderr: "" };
      }
      if (opts.command.startsWith("cat /etc/ceph/ceph.pub")) {
        return { code: 0, stdout: `${KEY}\n`, stderr: "" };
      }
      return undefined;
    });
    const result = await bootstrapCluster(deps, ok.session, {
      host: "192.0.2.10",
      monIp: "192.0.2.10",
      publicNet: "192.0.2.0/24",
      clusterNet: "198.51.100.0/24",
      cephImage: "registry.example.com/ceph/ceph:v19.2.3",
      sshUser: "admin",
      timeoutMs: 900_000,
    });
    assertEquals(result.bootstrapped, true);
    assertEquals(result.recoveredAfterTransportError, false);
    assertEquals(result.fsid, "abc");

    // Existing cluster: no bootstrap command.
    const existing = cephSession(
      () => ({ code: 0, stdout: "", stderr: "" }),
      (opts) => {
        if (opts.command === "cephadm ls") {
          return {
            code: 0,
            stdout: '[{"fsid":"abc"}]',
            stderr: "",
          };
        }
        if (opts.command.startsWith("cat /etc/ceph/ceph.pub")) {
          return {
            code: 0,
            stdout: `${KEY}\n`,
            stderr: "",
          };
        }
        return undefined;
      },
    );
    const adopted = await bootstrapCluster(deps, existing.session, {
      host: "192.0.2.10",
      monIp: "192.0.2.10",
      publicNet: "192.0.2.0/24",
      clusterNet: "198.51.100.0/24",
      cephImage: "registry.example.com/ceph/ceph:v19.2.3",
      sshUser: "admin",
      timeoutMs: 900_000,
    });
    assertEquals(adopted.bootstrapped, false);
    assertEquals(
      existing.calls.some((c) => c.command.startsWith("sh -c")),
      false,
    );

    // A non-zero bootstrap exit fails and does not recover.
    const failed = cephSession(
      () => ({ code: 0, stdout: "", stderr: "" }),
      (opts) => {
        if (opts.command === "cephadm ls") {
          return {
            code: 0,
            stdout: "[]",
            stderr: "",
          };
        }
        if (opts.command.startsWith("sh -c")) {
          return {
            code: 1,
            stdout: "",
            stderr: "bootstrap error",
          };
        }
        return undefined;
      },
    );
    await assertRejects(
      () =>
        bootstrapCluster(deps, failed.session, {
          host: "192.0.2.10",
          monIp: "192.0.2.10",
          publicNet: "192.0.2.0/24",
          clusterNet: "198.51.100.0/24",
          cephImage: "registry.example.com/ceph/ceph:v19.2.3",
          sshUser: "admin",
          timeoutMs: 900_000,
        }),
      PhaseError,
      "bootstrap failed",
    );
  },
);

Deno.test("a bootstrap transport failure recovers only when a re-probe finds the cluster", async () => {
  let probes = 0;
  const recovered = cephSession(
    () => ({ code: 0, stdout: "", stderr: "" }),
    (opts) => {
      if (opts.command === "cephadm ls") {
        probes++;
        return {
          code: 0,
          stdout: probes === 1 ? "[]" : '[{"fsid":"abc"}]',
          stderr: "",
        };
      }
      if (opts.command.startsWith("sh -c")) {
        throw new TransportError({
          host: "192.0.2.10",
          port: 22,
          user: "admin",
          kind: "aborted",
          cause: null,
          message: "killed",
        });
      }
      if (opts.command.startsWith("cat /etc/ceph/ceph.pub")) {
        return {
          code: 0,
          stdout: `${KEY}\n`,
          stderr: "",
        };
      }
      return undefined;
    },
  );
  const result = await bootstrapCluster(deps, recovered.session, {
    host: "192.0.2.10",
    monIp: "192.0.2.10",
    publicNet: "192.0.2.0/24",
    clusterNet: "198.51.100.0/24",
    cephImage: "registry.example.com/ceph/ceph:v19.2.3",
    sshUser: "admin",
    timeoutMs: 900_000,
  });
  assertEquals(result.recoveredAfterTransportError, true);

  let probes2 = 0;
  const lost = cephSession(
    () => ({ code: 0, stdout: "", stderr: "" }),
    (opts) => {
      if (opts.command === "cephadm ls") {
        probes2++;
        return { code: 0, stdout: probes2 === 1 ? "[]" : "[]", stderr: "" };
      }
      if (opts.command.startsWith("sh -c")) {
        throw new TransportError({
          host: "192.0.2.10",
          port: 22,
          user: "admin",
          kind: "other",
          cause: null,
          message: "lost",
        });
      }
      return undefined;
    },
  );
  await assertRejects(
    () =>
      bootstrapCluster(deps, lost.session, {
        host: "192.0.2.10",
        monIp: "192.0.2.10",
        publicNet: "192.0.2.0/24",
        clusterNet: "198.51.100.0/24",
        cephImage: "registry.example.com/ceph/ceph:v19.2.3",
        sshUser: "admin",
        timeoutMs: 900_000,
      }),
    TransportError,
  );
});

Deno.test("the verification needle is 40 characters from the key body", () => {
  const needle = keyNeedle(KEY);
  assertEquals(needle.length, 40);
  assertEquals(KEY.includes(needle), true);
  assertEquals(needle.includes("ssh-ed25519"), false);
  try {
    keyNeedle("ssh-ed25519 AAAA short");
    throw new Error("should throw");
  } catch (e) {
    assertEquals(e instanceof PhaseError, true);
  }
});

Deno.test("key distribution backs up, appends, verifies and is idempotent", async () => {
  const absent = cephSession(
    () => ({ code: 0, stdout: "", stderr: "" }),
    (opts) => {
      if (opts.command.includes("mkdir -p")) {
        return {
          code: 0,
          stdout: "",
          stderr: "",
        };
      }
      if (opts.command.startsWith("grep -Fqx")) {
        return {
          code: 1,
          stdout: "",
          stderr: "",
        };
      }
      if (opts.command.startsWith("cat >>")) {
        return {
          code: 0,
          stdout: "",
          stderr: "",
        };
      }
      if (opts.command.startsWith("grep -Fq ")) {
        return {
          code: 0,
          stdout: "",
          stderr: "",
        };
      }
      return undefined;
    },
  );
  const out = await distributeKeyToHost(
    deps,
    absent.session,
    KEY,
    "192.0.2.10",
    22,
  );
  assertEquals(out.alreadyPresent, false);
  assertEquals(out.verified, true);
  assertEquals(
    absent.calls.some((c) =>
      c.command.includes('cat >> "$HOME/.ssh/authorized_keys"')
    ),
    true,
  );
  // No truncating redirect to authorized_keys, only the append above.
  assertEquals(
    absent.calls.every((c) =>
      !/[^>]>\s*"\$HOME\/\.ssh\/authorized_keys"/.test(c.command)
    ),
    true,
  );

  const present = cephSession(
    () => ({ code: 0, stdout: "", stderr: "" }),
    (opts) => {
      if (opts.command.includes("mkdir -p")) {
        return {
          code: 0,
          stdout: "",
          stderr: "",
        };
      }
      if (opts.command.startsWith("grep -Fqx")) {
        return {
          code: 0,
          stdout: "",
          stderr: "",
        };
      }
      if (opts.command.startsWith("grep -Fq ")) {
        return {
          code: 0,
          stdout: "",
          stderr: "",
        };
      }
      return undefined;
    },
  );
  const out2 = await distributeKeyToHost(
    deps,
    present.session,
    KEY,
    "192.0.2.10",
    22,
  );
  assertEquals(out2.alreadyPresent, true);
  assertEquals(out2.verified, true);
  assertEquals(
    present.calls.some((c) => c.command.startsWith("cat >>")),
    false,
  );
});

Deno.test("the distribute record key is the sorted host:port list", () => {
  assertEquals(
    distributeRecordKey([{ host: "b", port: 22 }, { host: "a", port: 2202 }]),
    "cephDistributeKey-a:2202,b:22",
  );
});

Deno.test("host add gates on fsid, is idempotent and reads back", async () => {
  let added = false;
  const session = cephSession((args) => {
    if (args === "fsid") {
      return {
        code: 0,
        stdout: "3f2a9c1e-5b7d-4e8f-9a0b-1c2d3e4f5a6b",
        stderr: "",
      };
    }
    if (args === "orch host ls") {
      return {
        code: 0,
        stdout: added ? '[{"hostname":"node1","addr":"192.0.2.10"}]' : "[]",
        stderr: "",
      };
    }
    if (args.startsWith("orch host add")) {
      added = true;
      return { code: 0, stdout: "", stderr: "" };
    }
    return { code: 1, stdout: "", stderr: "unrouted" };
  });
  const result = await hostAdd(deps, session.session, {
    fsid: "3F2A9C1E-5B7D-4E8F-9A0B-1C2D3E4F5A6B",
    host: "node1",
    addr: "192.0.2.10",
  });
  assertEquals(result.added, true);
  assertEquals(session.cephArgs[0], "fsid");

  const mismatch = cephSession((args) =>
    args === "fsid"
      ? { code: 0, stdout: "other-fsid", stderr: "" }
      : { code: 0, stdout: "[]", stderr: "" }
  );
  await assertRejects(
    () =>
      hostAdd(deps, mismatch.session, {
        fsid: "expected",
        host: "node1",
        addr: "192.0.2.10",
      }),
    PhaseError,
    "possibly-wrong cluster",
  );
  assertEquals(mismatch.cephArgs.length, 1);

  const conflict = cephSession((args) => {
    if (args === "fsid") return { code: 0, stdout: "fsid", stderr: "" };
    if (args === "orch host ls") {
      return {
        code: 0,
        stdout: '[{"hostname":"node1","addr":"198.51.100.5"}]',
        stderr: "",
      };
    }
    return { code: 0, stdout: "", stderr: "" };
  });
  await assertRejects(
    () =>
      hostAdd(deps, conflict.session, {
        fsid: "fsid",
        host: "node1",
        addr: "192.0.2.10",
      }),
    PhaseError,
    "different address",
  );
});

Deno.test("placement hosts are normalised and convergence is set equality", () => {
  assertEquals(normalisePlacementHost("node-a:192.0.2.0/24"), "node-a");
  assertEquals(normalisePlacementHost("node-a=mon1"), "node-a");
  assertEquals(normalisePlacementHost("node-a:192.0.2.0/24=mon1"), "node-a");
  assertEquals(
    parsePlacement([{ placement: { hosts: ["a:net", "b=name"] } }]),
    {
      hosts: ["a", "b"],
      count: null,
    },
  );
  assertEquals(
    parsePlacement([{ placement: { hosts: ["a"], count: 3 } }])?.count,
    3,
  );
  assertEquals(parsePlacement({}), null);
  assertEquals(parsePlacement([]), null);
  assertEquals(
    placementConverged({ hosts: ["b", "a"], count: null }, ["a", "b"]),
    true,
  );
  assertEquals(
    placementConverged({ hosts: ["a", "b"], count: 3 }, ["a", "b"]),
    false,
  );
  assertEquals(placementConverged({ hosts: [], count: null }, ["a"]), false);
});

Deno.test("applying a placement replaces a count spec and is idempotent", async () => {
  const converged = cephSession((args) =>
    args === "orch ls --service_name 'mgr'"
      ? { code: 0, stdout: '[{"placement":{"hosts":["node-a"]}}]', stderr: "" }
      : { code: 0, stdout: "", stderr: "" }
  );
  const r1 = await applyPlacement(deps, converged.session, {
    serviceName: "mgr",
    applyArgs: "mgr",
    requested: ["node-a"],
    phase: "cephApplyMgr",
  });
  assertEquals(r1.applied, false);
  assertEquals(
    converged.cephArgs.some((a) => a.startsWith("orch apply")),
    false,
  );

  const count = cephSession((args) =>
    args === "orch ls --service_name 'mgr'"
      ? { code: 0, stdout: '[{"placement":{"count":3}}]', stderr: "" }
      : { code: 0, stdout: "", stderr: "" }
  );
  const r2 = await applyPlacement(deps, count.session, {
    serviceName: "mgr",
    applyArgs: "mgr",
    requested: ["node-a", "node-b"],
    phase: "cephApplyMgr",
  });
  assertEquals(r2.applied, true);
  assertEquals(r2.replacedCountSpec, true);
  assertEquals(r2.previousCount, 3);
  assertEquals(
    count.cephArgs.some((a) =>
      a === "orch apply mgr --placement='node-a,node-b'"
    ),
    true,
  );
});

Deno.test(
  "mon quorum majority is computed over monmap entries", // leak-allow(decision D42)
  () => {
    const dump = { mons: [{ name: "a" }, { name: "b" }, { name: "c" }] };
    const status = { quorum_names: ["a", "b", "c"] };
    assertEquals(evaluateMonQuorum(dump, status, ["a", "b"]), {
      evaluated: true,
      pass: true,
      kept: 2,
      current: 3,
    });
    assertEquals(evaluateMonQuorum(dump, status, ["a"]).pass, false);
    assertEquals(evaluateMonQuorum({}, status, ["a"]).pass, null);
  },
);
