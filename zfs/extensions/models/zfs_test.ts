import {
  assertEquals,
  assertRejects,
  assertThrows,
} from "jsr:@std/assert@1.0.19";
import { createModelTestContext } from "jsr:@swamp-club/swamp-testing@0.20261014.55";
import {
  type CommandResult,
  type CommandRunner,
  SshError,
} from "./_lib/ssh.ts";
import { instanceKey } from "./_lib/zfs.ts";
import { createModel, type ZfsDeps } from "./zfs.ts";

const HOST = "192.0.2.10";
const PORT = 22;
const USER = "root";
const IDENTITY = { host: HOST, port: PORT, user: USER };

const SSH = {
  host: HOST,
  port: PORT,
  user: USER,
  host_key_policy: "insecure_tofu" as const,
  private_key: "PLACEHOLDER-PRIVATE-KEY-NOT-REAL",
};

const LSBLK = JSON.stringify({
  blockdevices: [
    {
      name: "sda",
      path: "/dev/sda",
      type: "disk",
      children: [{
        name: "sda1",
        path: "/dev/sda1",
        type: "part",
        pkname: "sda",
        mountpoint: "/",
        fstype: "ext4",
        uuid: "ROOT-UUID",
      }],
    },
    { name: "sdb", path: "/dev/sdb", type: "disk" },
  ],
});

const MOUNTS = "/dev/sda1 / ext4 rw,relatime 0 0\nproc /proc proc rw 0 0\n";
const FSTAB = "UUID=ROOT-UUID / ext4 defaults 0 1\n";
const MDSTAT = "Personalities : [raid1]\nunused devices: <none>\n";
const SWAPS = "Filename Type Size Used Priority\n";

const POOL_ROW = "tank\t10G\t1G\t9G\tONLINE\t777\n";
const POOL_STATUS = [
  "  pool: tank",
  " state: ONLINE",
  "config:",
  "",
  "\tNAME        STATE     READ WRITE CKSUM",
  "\ttank        ONLINE       0     0     0",
  "\t  /dev/sdb  ONLINE       0     0     0",
  "",
  "errors: No known data errors",
].join("\n");
const DATASET_ROW = "tank/data\tfilesystem\t1G\t9G\t1G\t/tank/data\n";
const SNAP_A = "tank/data@a\t0\t1G\t1700000100\n";
const SNAP_B = "tank/data@b\t0\t1G\t1700000200\n";

/** A confirmed-absent zfs target. */
const ABSENT = { code: 1, stdout: "dataset does not exist\n" };
/** The documented "no pools" result of `zpool`. */
const NO_POOLS = { code: 1, stdout: "no pools available\n" };

// The transport quotes every argv word, so these exact fragments identify a
// command without colliding with a differently-shaped one.
const P = {
  poolProbe: "'zpool' 'list' '-H' '-o' 'name'",
  poolList: "'zpool' 'list' '-H' '-p'",
  poolStatus: "'zpool' 'status' '-P'",
  poolStatusTank: "'zpool' 'status' '-P' 'tank'",
  poolCreate: "'zpool' 'create'",
  dsProbe: "'zfs' 'list' '-H' '-o' 'name'",
  dsCreate: "'zfs' 'create'",
  dsGet: "'zfs' 'get'",
  dsSet: "'zfs' 'set'",
  datasetsList: "'zfs' 'list' '-H' '-p' '-r' '-t' 'filesystem,volume'",
  zvolProbe: "'zfs' 'list' '-H' '-p' '-t' 'volume'",
  snapProbe: "'zfs' 'list' '-H' '-t' 'snapshot' '-o' 'name'",
  snapCreate: "'zfs' 'snapshot'",
  snapshotsList: "'zfs' 'list' '-H' '-p' '-r' '-t' 'snapshot'",
  clone: "'zfs' 'clone'",
  rollback: "'zfs' 'rollback'",
  destroy: "'zfs' 'destroy'",
  origin: "'origin'",
  lsblk: "'lsblk'",
  readlink: "'readlink'",
  mounts: "'/proc/mounts'",
  fstab: "'/etc/fstab'",
  mdstat: "'/proc/mdstat'",
  swaps: "'/proc/swaps'",
};

interface RouteResult {
  code?: number;
  stdout?: string;
  stderr?: string;
}

type Route = (remote: string) => RouteResult | undefined;

const has = (remote: string, fragment: string): boolean =>
  remote.includes(fragment);

function makeRunner(route: Route): CommandRunner {
  return (cmd, args) => {
    let result: CommandResult = { code: 0, stdout: "", stderr: "" };
    if (cmd === "ssh-agent") {
      result = {
        code: 0,
        stdout:
          "SSH_AUTH_SOCK=/tmp/fake-agent.sock; export SSH_AUTH_SOCK;\nSSH_AGENT_PID=99; export SSH_AGENT_PID;\n",
        stderr: "",
      };
    } else if (cmd === "ssh-add") {
      result = { code: 0, stdout: "", stderr: "" };
    } else if (cmd === "ssh") {
      const remote = args[args.length - 1];
      const out = route(remote) ?? {};
      result = {
        code: out.code ?? 0,
        stdout: out.stdout ?? "",
        stderr: out.stderr ?? "",
      };
    }
    return Promise.resolve(result);
  };
}

function deps(route: Route): ZfsDeps {
  return {
    ssh: {
      run: makeRunner(route),
      now: () => 0,
      sleep: () => Promise.resolve(),
    },
    now: () => Date.UTC(2026, 9, 17, 12, 0, 0),
  };
}

function model(route: Route) {
  return createModel(deps(route));
}

/** Facts shared by every create_pool guard call; the pool does not exist. */
function guardRoute(
  readlinkTarget: string,
  overrides: Route = () => undefined,
) {
  return (remote: string): RouteResult | undefined => {
    if (has(remote, P.poolProbe)) return NO_POOLS;
    if (has(remote, P.lsblk)) return { code: 0, stdout: LSBLK };
    if (has(remote, P.mounts)) return { code: 0, stdout: MOUNTS };
    if (has(remote, P.fstab)) return { code: 0, stdout: FSTAB };
    if (has(remote, P.mdstat)) return { code: 0, stdout: MDSTAT };
    if (has(remote, P.swaps)) return { code: 0, stdout: SWAPS };
    if (has(remote, P.poolStatus)) {
      return { code: 1, stdout: "no pools available\n" };
    }
    if (has(remote, P.readlink)) {
      return { code: 0, stdout: `${readlinkTarget}\n` };
    }
    return overrides(remote);
  };
}

Deno.test("create_pool refuses a vdev in the boot family", async () => {
  const commands: string[] = [];
  const zfs = model((remote) => {
    commands.push(remote);
    return guardRoute("/dev/sda")(remote);
  });
  const args = zfs.methods.create_pool.arguments.parse({
    ssh: SSH,
    pool: "tank",
    vdevs: ["/dev/disk/by-id/wwn-boot"],
  });
  const { context, getWrittenResources } = createModelTestContext();
  await assertRejects(
    () => zfs.methods.create_pool.execute(args, context),
    Error,
    "protected device set",
  );
  assertEquals(commands.some((c) => has(c, P.poolCreate)), false);
  assertEquals(getWrittenResources().length, 0);
});

Deno.test("create_pool creates a pool on a spare disk", async () => {
  const commands: string[] = [];
  const zfs = model((remote) => {
    commands.push(remote);
    if (has(remote, P.poolStatusTank)) return { code: 0, stdout: POOL_STATUS };
    const guard = guardRoute("/dev/sdb")(remote);
    if (guard) return guard;
    if (has(remote, P.poolCreate)) return { code: 0 };
    if (has(remote, P.poolList)) return { code: 0, stdout: POOL_ROW };
    return { code: 0 };
  });
  const args = zfs.methods.create_pool.arguments.parse({
    ssh: SSH,
    pool: "tank",
    vdevs: ["/dev/disk/by-id/wwn-spare"],
    properties: { ashift: 12 },
  });
  const { context } = createModelTestContext();
  const out = await zfs.methods.create_pool.execute(args, context);
  assertEquals(out.result.pool, "tank");
  assertEquals(out.result.guid, "777");
  assertEquals(out.result.changed, true);
  assertEquals(
    commands.some((c) => has(c, P.poolCreate) && c.includes("ashift=12")),
    true,
  );
});

Deno.test("create_pool is a no-op when the pool has the same vdevs", async () => {
  const commands: string[] = [];
  const zfs = model((remote) => {
    commands.push(remote);
    if (has(remote, P.poolProbe)) return { code: 0, stdout: "tank\n" };
    if (has(remote, P.readlink)) return { code: 0, stdout: "/dev/sdb\n" };
    if (has(remote, P.poolStatusTank)) return { code: 0, stdout: POOL_STATUS };
    if (has(remote, P.poolList)) return { code: 0, stdout: POOL_ROW };
    return { code: 0 };
  });
  const args = zfs.methods.create_pool.arguments.parse({
    ssh: SSH,
    pool: "tank",
    vdevs: ["/dev/disk/by-id/wwn-spare"],
  });
  const { context } = createModelTestContext();
  const out = await zfs.methods.create_pool.execute(args, context);
  assertEquals(out.result.changed, false);
  assertEquals(commands.some((c) => has(c, P.poolCreate)), false);
  assertEquals(commands.some((c) => has(c, P.lsblk)), false);
});

Deno.test("create_pool refuses an existing pool with a different vdev set", async () => {
  const zfs = model((remote) => {
    if (has(remote, P.poolProbe)) return { code: 0, stdout: "tank\n" };
    if (has(remote, P.readlink)) {
      return remote.includes("wwn-other")
        ? { code: 0, stdout: "/dev/sdc\n" }
        : { code: 0, stdout: "/dev/sdb\n" };
    }
    if (has(remote, P.poolStatusTank)) return { code: 0, stdout: POOL_STATUS };
    if (has(remote, P.poolList)) return { code: 0, stdout: POOL_ROW };
    return { code: 0 };
  });
  const args = zfs.methods.create_pool.arguments.parse({
    ssh: SSH,
    pool: "tank",
    vdevs: ["/dev/disk/by-id/wwn-other"],
  });
  const { context } = createModelTestContext();
  await assertRejects(
    () => zfs.methods.create_pool.execute(args, context),
    Error,
    "different vdev set",
  );
});

Deno.test("create_dataset creates then only applies the diff", async () => {
  const commands: string[] = [];
  let created = false;
  const zfs = model((remote) => {
    commands.push(remote);
    if (has(remote, P.dsProbe)) {
      return created ? { code: 0, stdout: "tank/data\n" } : ABSENT;
    }
    if (has(remote, P.dsCreate)) {
      created = true;
      return { code: 0 };
    }
    if (has(remote, P.dsGet)) {
      return { code: 0, stdout: "compression\tzstd\nquota\t10G\n" };
    }
    if (has(remote, P.datasetsList)) return { code: 0, stdout: DATASET_ROW };
    return { code: 0 };
  });
  const args = zfs.methods.create_dataset.arguments.parse({
    ssh: SSH,
    name: "tank/data",
    properties: { compression: "zstd", quota: "10G" },
  });
  const { context } = createModelTestContext();
  const first = await zfs.methods.create_dataset.execute(args, context);
  assertEquals(first.result.properties_changed, ["compression", "quota"]);
  commands.length = 0;
  const second = await zfs.methods.create_dataset.execute(args, context);
  assertEquals(second.result.properties_changed, []);
  assertEquals(commands.some((c) => has(c, P.dsSet)), false);
});

Deno.test("create_dataset sets only the changed property", async () => {
  const commands: string[] = [];
  const zfs = model((remote) => {
    commands.push(remote);
    if (has(remote, P.dsProbe)) return { code: 0, stdout: "tank/data\n" };
    if (has(remote, P.dsGet)) {
      return { code: 0, stdout: "compression\tzstd\nquota\t10G\n" };
    }
    if (has(remote, P.datasetsList)) return { code: 0, stdout: DATASET_ROW };
    return { code: 0 };
  });
  const args = zfs.methods.create_dataset.arguments.parse({
    ssh: SSH,
    name: "tank/data",
    properties: { compression: "lz4", quota: "10G" },
  });
  const { context } = createModelTestContext();
  const out = await zfs.methods.create_dataset.execute(args, context);
  assertEquals(out.result.properties_changed, ["compression"]);
  assertEquals(
    commands.some((c) => has(c, P.dsSet) && c.includes("compression=lz4")),
    true,
  );
});

Deno.test("create_zvol builds a sparse volume", async () => {
  const commands: string[] = [];
  const zfs = model((remote) => {
    commands.push(remote);
    if (has(remote, P.zvolProbe)) return ABSENT;
    if (has(remote, P.dsCreate) && remote.includes("'-s'")) return { code: 0 };
    if (has(remote, P.datasetsList)) {
      return { code: 0, stdout: "tank/vol\tvolume\t0\t9G\t10G\t-\n" };
    }
    return { code: 0 };
  });
  const args = zfs.methods.create_zvol.arguments.parse({
    ssh: SSH,
    name: "tank/vol",
    volsize: "10G",
  });
  const { context } = createModelTestContext();
  const out = await zfs.methods.create_zvol.execute(args, context);
  assertEquals(out.result, { name: "tank/vol", volsize: "10G", sparse: true });
  const create = commands.find((c) => has(c, P.dsCreate) && c.includes("'-s'"));
  assertEquals(create?.includes("'-V' '10G'"), true);
});

Deno.test("create_zvol refuses a different existing size", async () => {
  const zfs = model((remote) => {
    if (has(remote, P.zvolProbe)) return { code: 0, stdout: "tank/vol\t20G\n" };
    return { code: 0 };
  });
  const args = zfs.methods.create_zvol.arguments.parse({
    ssh: SSH,
    name: "tank/vol",
    volsize: "10G",
  });
  const { context } = createModelTestContext();
  await assertRejects(
    () => zfs.methods.create_zvol.execute(args, context),
    Error,
    "exists with volsize",
  );
});

Deno.test("snapshot creates once and is then a no-op", async () => {
  const commands: string[] = [];
  let exists = false;
  const zfs = model((remote) => {
    commands.push(remote);
    if (has(remote, P.dsProbe)) {
      return exists ? { code: 0, stdout: "tank/data@a\n" } : ABSENT;
    }
    if (has(remote, P.snapCreate)) {
      exists = true;
      return { code: 0 };
    }
    if (has(remote, P.snapshotsList)) return { code: 0, stdout: SNAP_A };
    return { code: 0 };
  });
  const args = zfs.methods.snapshot.arguments.parse({
    ssh: SSH,
    name: "tank/data",
    tag: "a",
  });
  const { context } = createModelTestContext();
  const first = await zfs.methods.snapshot.execute(args, context);
  assertEquals(first.result, { name: "tank/data@a", created: true });
  commands.length = 0;
  const second = await zfs.methods.snapshot.execute(args, context);
  assertEquals(second.result.created, false);
  assertEquals(commands.some((c) => has(c, P.snapCreate)), false);
});

Deno.test("clone creates once and then converges on origin", async () => {
  const commands: string[] = [];
  let cloned = false;
  const zfs = model((remote) => {
    commands.push(remote);
    if (has(remote, P.dsGet) && has(remote, P.origin)) {
      return { code: 0, stdout: "tank/data@a\n" };
    }
    if (has(remote, P.dsProbe)) {
      if (remote.includes("tank/data@a")) {
        return { code: 0, stdout: "tank/data@a\n" };
      }
      return cloned ? { code: 0, stdout: "tank/clone\n" } : ABSENT;
    }
    if (has(remote, P.clone)) {
      cloned = true;
      return { code: 0 };
    }
    if (has(remote, P.datasetsList)) {
      return {
        code: 0,
        stdout: "tank/clone\tfilesystem\t0\t9G\t0\t/tank/clone\n",
      };
    }
    return { code: 0 };
  });
  const args = zfs.methods.clone.arguments.parse({
    ssh: SSH,
    name: "tank/data",
    tag: "a",
    target: "tank/clone",
  });
  const { context } = createModelTestContext();
  const first = await zfs.methods.clone.execute(args, context);
  assertEquals(first.result, { source: "tank/data@a", target: "tank/clone" });
  commands.length = 0;
  await zfs.methods.clone.execute(args, context);
  assertEquals(commands.some((c) => has(c, P.clone)), false);
});

Deno.test("rollback refuses later snapshots without an acknowledgement", async () => {
  const commands: string[] = [];
  const zfs = model((remote) => {
    commands.push(remote);
    if (has(remote, P.snapshotsList)) {
      return { code: 0, stdout: `${SNAP_A}${SNAP_B}` };
    }
    return { code: 0 };
  });
  const args = zfs.methods.rollback.arguments.parse({
    ssh: SSH,
    name: "tank/data",
    tag: "a",
  });
  const { context } = createModelTestContext();
  await assertRejects(
    () => zfs.methods.rollback.execute(args, context),
    Error,
    "later snapshot",
  );
  assertEquals(commands.some((c) => has(c, P.rollback)), false);
});

Deno.test("rollback with the acknowledgement destroys later snapshots", async () => {
  const commands: string[] = [];
  const zfs = model((remote) => {
    commands.push(remote);
    if (has(remote, P.snapshotsList)) {
      return { code: 0, stdout: `${SNAP_A}${SNAP_B}` };
    }
    if (has(remote, P.rollback)) return { code: 0 };
    return { code: 0 };
  });
  const args = zfs.methods.rollback.arguments.parse({
    ssh: SSH,
    name: "tank/data",
    tag: "a",
    destroy_later_snapshots: true,
  });
  const { context } = createModelTestContext();
  const out = await zfs.methods.rollback.execute(args, context);
  assertEquals(out.result.destroyed_snapshots, 1);
  assertEquals(
    commands.some((c) => has(c, P.rollback) && c.includes("'-r'")),
    true,
  );
});

Deno.test("destroy is a clean no-op on an absent target", async () => {
  const commands: string[] = [];
  const zfs = model((remote) => {
    commands.push(remote);
    if (has(remote, P.dsProbe)) return ABSENT;
    return { code: 0 };
  });
  const args = zfs.methods.destroy.arguments.parse({
    ssh: SSH,
    target: "tank/gone",
  });
  const { context } = createModelTestContext();
  const out = await zfs.methods.destroy.execute(args, context);
  assertEquals(out.result, { target: "tank/gone", destroyed: false });
  assertEquals(commands.some((c) => has(c, P.destroy)), false);
});

Deno.test("a transport failure is typed and writes no state", async () => {
  const zfs = model(() => ({
    code: 255,
    stderr: "Permission denied (publickey).",
  }));
  const args = zfs.methods.create_dataset.arguments.parse({
    ssh: SSH,
    name: "tank/data",
    properties: { compression: "zstd" },
  });
  const { context, getWrittenResources } = createModelTestContext();
  await assertRejects(
    () => zfs.methods.create_dataset.execute(args, context),
    SshError,
    "authentication failed",
  );
  assertEquals(getWrittenResources().length, 0);
});

Deno.test("the grammar rejects injection on every remote-bound input", () => {
  const zfs = model(() => undefined);
  const base = { ssh: SSH, pool: "tank", vdevs: ["/dev/sdb"] };
  const bad = [
    { pool: "tank; rm -rf /" },
    { pool: "tank`id`" },
    { vdevs: ["/dev/sdb; rm -rf /"] },
    { vdevs: ["/dev/../etc/passwd"] },
  ];
  for (const override of bad) {
    assertThrows(
      () => zfs.methods.create_pool.arguments.parse({ ...base, ...override }),
      Error,
      undefined,
      JSON.stringify(override),
    );
  }
  assertThrows(
    () =>
      zfs.methods.create_dataset.arguments.parse({
        ssh: SSH,
        name: "tank/data",
        properties: { "Bad-Name": "x" },
      }),
    Error,
  );
  assertThrows(
    () =>
      zfs.methods.snapshot.arguments.parse({
        ssh: SSH,
        name: "tank/data",
        tag: "bad tag",
      }),
    Error,
  );
});

Deno.test("strict host-key policy requires a pinned key", () => {
  const zfs = model(() => undefined);
  assertThrows(
    () =>
      zfs.methods.create_pool.arguments.parse({
        ssh: { ...SSH, host_key_policy: "strict" },
        pool: "tank",
        vdevs: ["/dev/sdb"],
      }),
    Error,
    undefined,
    "strict requires a non-empty host_keys",
  );
});

Deno.test("create_zvol is a no-op when the existing size matches in bytes", async () => {
  const commands: string[] = [];
  const zfs = model((remote) => {
    commands.push(remote);
    if (has(remote, P.zvolProbe)) {
      return { code: 0, stdout: "tank/vol\t10737418240\n" };
    }
    if (has(remote, P.datasetsList)) {
      return { code: 0, stdout: "tank/vol\tvolume\t0\t9G\t10G\t-\n" };
    }
    return { code: 0 };
  });
  const args = zfs.methods.create_zvol.arguments.parse({
    ssh: SSH,
    name: "tank/vol",
    volsize: "10G",
  });
  const { context } = createModelTestContext();
  const out = await zfs.methods.create_zvol.execute(args, context);
  assertEquals(out.result.volsize, "10G");
  assertEquals(commands.some((c) => has(c, P.dsCreate)), false);
});

Deno.test("create_pool refuses when the fact probe itself fails", async () => {
  const zfs = model((remote) => {
    if (has(remote, P.poolProbe)) return NO_POOLS;
    if (has(remote, P.lsblk)) return { code: 0, stdout: LSBLK };
    if (has(remote, P.mounts)) return { code: 0, stdout: MOUNTS };
    if (has(remote, P.swaps)) return { code: 0, stdout: SWAPS };
    // `cat` fails, then `test -e` fails with exit 2 (a probe failure), which
    // must not be read as a confirmed-absent file.
    if (has(remote, "'test'")) return { code: 2 };
    if (has(remote, P.fstab)) return { code: 1, stderr: "I/O error" };
    return { code: 0 };
  });
  const args = zfs.methods.create_pool.arguments.parse({
    ssh: SSH,
    pool: "tank",
    vdevs: ["/dev/sdb"],
  });
  const { context } = createModelTestContext();
  await assertRejects(
    () => zfs.methods.create_pool.execute(args, context),
    Error,
    "could not confirm whether /etc/fstab exists",
  );
});

Deno.test("create_pool refuses when a safety fact cannot be read", async () => {
  const commands: string[] = [];
  const zfs = model((remote) => {
    commands.push(remote);
    if (has(remote, P.poolProbe)) return NO_POOLS;
    if (has(remote, P.lsblk)) return { code: 0, stdout: LSBLK };
    if (has(remote, P.mounts)) {
      return { code: 1, stderr: "permission denied" };
    }
    return { code: 0 };
  });
  const args = zfs.methods.create_pool.arguments.parse({
    ssh: SSH,
    pool: "tank",
    vdevs: ["/dev/sdb"],
  });
  const { context } = createModelTestContext();
  await assertRejects(
    () => zfs.methods.create_pool.execute(args, context),
    Error,
    "refusing to create a pool",
  );
  assertEquals(commands.some((c) => has(c, P.poolCreate)), false);
});

Deno.test("get refuses when no pool is named and the host has none", async () => {
  const zfs = model((remote) => {
    if (has(remote, P.poolProbe)) return NO_POOLS;
    return { code: 0 };
  });
  const args = zfs.methods.get.arguments.parse({ ssh: SSH });
  const { context } = createModelTestContext();
  await assertRejects(
    () => zfs.methods.get.execute(args, context),
    Error,
    "no pool specified",
  );
});

Deno.test("get reports live pool state", async () => {
  const zfs = model((remote) => {
    if (has(remote, P.poolStatusTank)) return { code: 0, stdout: POOL_STATUS };
    if (has(remote, P.poolList)) return { code: 0, stdout: POOL_ROW };
    if (has(remote, P.datasetsList)) return { code: 0, stdout: DATASET_ROW };
    if (has(remote, P.snapshotsList)) {
      return { code: 0, stdout: `${SNAP_A}${SNAP_B}` };
    }
    return { code: 0 };
  });
  const args = zfs.methods.get.arguments.parse({ ssh: SSH, pool: "tank" });
  const { context, getWrittenResources } = createModelTestContext();
  const out = await zfs.methods.get.execute(args, context);
  assertEquals(out.result.pool_state?.name, "tank");
  assertEquals(out.result.pool_state?.vdevs, ["/dev/sdb"]);
  assertEquals(out.result.datasets[0].name, "tank/data");
  assertEquals(out.result.snapshots.length, 2);
  assertEquals(getWrittenResources().length, 1);
});

Deno.test("sync compares recorded state with the host", async () => {
  const zfs = model((remote) => {
    if (has(remote, P.poolStatusTank)) return { code: 0, stdout: POOL_STATUS };
    if (has(remote, P.poolList)) return { code: 0, stdout: POOL_ROW };
    return { code: 0, stdout: "" };
  });
  const key = instanceKey(IDENTITY, "tank");
  const { context } = createModelTestContext({
    storedResources: {
      [key]: {
        host: HOST,
        port: PORT,
        user: USER,
        kind: "pool",
        name: "tank",
        pool: "tank",
        observed_at: "2026-10-17T00:00:00.000Z",
        pool_state: {
          name: "tank",
          health: "DEGRADED",
          size: "10G",
          alloc: "1G",
          free: "9G",
          guid: "777",
          vdevs: ["/dev/sdb"],
        },
        datasets: [],
        snapshots: [],
      },
    },
  });
  const args = zfs.methods.sync.arguments.parse({ ssh: SSH, pool: "tank" });
  const out = await zfs.methods.sync.execute(args, context);
  assertEquals(out.result.in_sync, false);
  assertEquals(
    out.result.diffs.some((diff) => diff.includes("pool health")),
    true,
  );
});
