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
import { DeviceGuardError } from "./_lib/safety.ts";
import { instanceKey } from "./_lib/zfs.ts";
import { createModel, SystemPoolError, type ZfsDeps } from "./zfs.ts";

const HOST = "192.0.2.10";
const PORT = 22;
const USER = "root";
const IDENTITY = { host: HOST, port: PORT, user: USER };

const SSH = {
  host: HOST,
  port: PORT,
  user: USER,
  host_key_policy: "strict" as const,
  host_keys: [`${HOST} ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeKeyForTests`],
  private_key: "PLACEHOLDER-PRIVATE-KEY-NOT-REAL",
};

const LSBLK = JSON.stringify({
  blockdevices: [
    {
      name: "sda",
      path: "/dev/sda",
      pkname: null,
      type: "disk",
      fstype: null,
      uuid: null,
      partuuid: null,
      parttype: null,
      label: null,
      mountpoints: [null],
      children: [{
        name: "sda1",
        path: "/dev/sda1",
        pkname: "sda",
        type: "part",
        fstype: "ext4",
        uuid: "ROOT-UUID",
        partuuid: null,
        parttype: "0x83",
        label: null,
        mountpoints: ["/"],
      }],
    },
    {
      name: "sdb",
      path: "/dev/sdb",
      pkname: null,
      type: "disk",
      fstype: null,
      uuid: null,
      partuuid: null,
      parttype: null,
      label: null,
      mountpoints: [null],
    },
  ],
});
const ZERO_SECTOR = Array.from({ length: 512 }, () => "00").join(" ");
const FINDMNT = JSON.stringify({
  filesystems: [{ target: "/", source: "/dev/sda1", fstype: "ext4" }],
});
const FSTAB = "UUID=ROOT-UUID / ext4 defaults 0 1\n";
const MDSTAT = "Personalities :\nunused devices: <none>\n";
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
  poolDestroy: "'zpool' 'destroy'",
  poolExport: "'zpool' 'export'",
  poolDescendants:
    "'zfs' 'list' '-H' '-r' '-o' 'name' '-t' 'filesystem,volume,snapshot'",
  poolVolumes: "'zfs' 'list' '-H' '-r' '-t' 'volume' '-o' 'name'",
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
  lsblk: "lsblk -J -b -o",
  readlink: "'readlink'",
  fstab: "/etc/fstab",
  mdstat: "/proc/mdstat",
  swaps: "/proc/swaps",
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

/** Raw probe outputs for one synthetic host. */
interface GuardFixture {
  lsblk?: string;
  findmnt?: string;
  fstab?: string;
  swaps?: string;
  mdstat?: string;
  links?: string;
  blkid?: string;
  zpool?: string;
  pvs?: string;
  mdExamine?: Record<string, RouteResult>;
}

/** Serves the shared guard's probes from a fixture; `zpool` defaults to none. */
function guardProbeRoute(fixture: GuardFixture = {}): Route {
  return (remote) => {
    if (has(remote, P.poolProbe)) return NO_POOLS;
    if (has(remote, "lsblk -J -b -o")) {
      return { code: 0, stdout: fixture.lsblk ?? LSBLK };
    }
    if (has(remote, "find /dev")) {
      return { code: 0, stdout: fixture.links ?? "" };
    }
    if (has(remote, "blkid")) {
      return {
        code: 0,
        stdout: fixture.blkid ??
          '/dev/sdz9: UUID="99999999-0000-0000-0000-000000000000" TYPE="ext4"\n',
      };
    }
    if (has(remote, "findmnt -J")) {
      return { code: 0, stdout: fixture.findmnt ?? FINDMNT };
    }
    if (has(remote, "/etc/fstab")) {
      return { code: 0, stdout: fixture.fstab ?? FSTAB };
    }
    if (has(remote, "/proc/swaps")) {
      return { code: 0, stdout: fixture.swaps ?? SWAPS };
    }
    if (has(remote, "/proc/mdstat")) {
      return { code: 0, stdout: fixture.mdstat ?? MDSTAT };
    }
    if (has(remote, "mdadm --examine")) {
      for (const key of Object.keys(fixture.mdExamine ?? {})) {
        if (has(remote, key)) return fixture.mdExamine![key];
      }
      return {
        code: 1,
        stderr: "mdadm: No md superblock detected on /dev/x.\n",
      };
    }
    if (has(remote, "zpool status -P")) {
      return { code: 0, stdout: fixture.zpool ?? "no pools available\n" };
    }
    if (has(remote, "pvs --noheadings")) {
      return { code: 0, stdout: fixture.pvs ?? "" };
    }
    if (has(remote, "test -d /sys/firmware/efi")) {
      return { code: 1, stdout: "" };
    }
    if (has(remote, "efibootmgr -v")) return { code: 127, stdout: "" };
    if (has(remote, "dd if=")) return { code: 0, stdout: ZERO_SECTOR };
    return undefined;
  };
}

/** A guard route plus a successful `zpool create`/read for the spare path. */
function fullCreateRoute(fixture: GuardFixture = {}): Route {
  const guard = guardProbeRoute(fixture);
  return (remote) => {
    if (has(remote, P.poolProbe)) return NO_POOLS;
    if (has(remote, P.poolStatusTank)) return { code: 0, stdout: POOL_STATUS };
    if (has(remote, P.poolList)) return { code: 0, stdout: POOL_ROW };
    if (has(remote, P.poolCreate)) return { code: 0 };
    return guard(remote);
  };
}

Deno.test("create_pool refuses a vdev in the boot family", async () => {
  const commands: string[] = [];
  const zfs = model((remote) => {
    commands.push(remote);
    return guardProbeRoute({
      links: "/dev/disk/by-id/wwn-boot /dev/sda\n",
    })(remote);
  });
  const args = zfs.methods.create_pool.arguments.parse({
    ssh: SSH,
    pool: "tank",
    vdevs: ["/dev/disk/by-id/wwn-boot"],
  });
  const { context, getWrittenResources } = createModelTestContext();
  const error = await assertRejects(
    () => zfs.methods.create_pool.execute(args, context),
    DeviceGuardError,
  );
  assertEquals(error.code, "boot-protected");
  assertEquals(error.message.includes("/dev/sda"), true);
  assertEquals(commands.some((c) => has(c, P.poolCreate)), false);
  assertEquals(getWrittenResources().length, 0);
});

Deno.test("create_pool creates a pool on a spare disk", async () => {
  const commands: string[] = [];
  const zfs = model((remote) => {
    commands.push(remote);
    if (has(remote, P.poolStatusTank)) return { code: 0, stdout: POOL_STATUS };
    const guard = guardProbeRoute({
      links: "/dev/disk/by-id/wwn-spare /dev/sdb\n",
    })(remote);
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

/** A compact lsblk device spec for the guard fixtures. */
interface DevSpec {
  name: string;
  type: string;
  fstype?: string;
  uuid?: string;
  parttype?: string | null;
  label?: string;
  mounts?: string[];
  path?: string;
  children?: DevSpec[];
}

function devRow(d: DevSpec): Record<string, unknown> {
  const path = d.path ??
    (d.type === "lvm" || d.type === "crypt"
      ? `/dev/mapper/${d.name}`
      : `/dev/${d.name}`);
  return {
    name: d.name,
    path,
    pkname: null,
    type: d.type,
    fstype: d.fstype ?? null,
    uuid: d.uuid ?? null,
    partuuid: null,
    parttype: d.parttype ?? (d.type === "part" ? "0x83" : null),
    label: d.label ?? null,
    mountpoints: d.mounts ?? [null],
    ...(d.children ? { children: d.children.map(devRow) } : {}),
  };
}

function lsblkJson(...devs: DevSpec[]): string {
  return JSON.stringify({ blockdevices: devs.map(devRow) });
}

/** A `findmnt -J` body. */
function findmntJson(
  ...mounts: { target: string; source: string; fstype: string }[]
): string {
  return JSON.stringify({ filesystems: mounts });
}

const MD_ARRAY_UUID = "7a0d6e3f:11112222:33334444:55556666";
const MD_EXAMINE =
  `/dev/x:\n          Magic : a92b4efc\n        Version : 1.2\n     Array UUID : ${MD_ARRAY_UUID}\n           Name : host:0\n`;

Deno.test("create_pool refuses a root-on-ZFS disk named by-id", async () => {
  const zfs = model(guardProbeRoute({
    lsblk: lsblkJson(
      {
        name: "sda",
        type: "disk",
        children: [
          {
            name: "sda1",
            type: "part",
            fstype: "vfat",
            uuid: "ABCD-1234",
            mounts: ["/boot/efi"],
          },
          { name: "sda3", type: "part", fstype: "zfs_member", label: "rpool" },
        ],
      },
      {
        name: "sdb",
        type: "disk",
        children: [{
          name: "sdb3",
          type: "part",
          fstype: "zfs_member",
          label: "rpool",
        }],
      },
      { name: "sdc", type: "disk" },
    ),
    findmnt: findmntJson(
      { target: "/", source: "rpool/ROOT/debian", fstype: "zfs" },
      { target: "/boot/efi", source: "/dev/sda1", fstype: "vfat" },
    ),
    fstab: "UUID=ABCD-1234 /boot/efi vfat umask=0077 0 1\n",
    links: "/dev/disk/by-id/ata-A-part3 /dev/sda3\n" +
      "/dev/disk/by-id/ata-B-part3 /dev/sdb3\n",
    zpool: "  pool: rpool\n state: ONLINE\nconfig:\n\n" +
      "\tNAME  STATE\n\trpool ONLINE\n\t  mirror-0  ONLINE\n" +
      "\t    /dev/disk/by-id/ata-A-part3  ONLINE\n" +
      "\t    /dev/disk/by-id/ata-B-part3  ONLINE\n\n" +
      "errors: No known data errors\n",
  }));
  const args = zfs.methods.create_pool.arguments.parse({
    ssh: SSH,
    pool: "tank",
    vdevs: ["/dev/disk/by-id/ata-A-part3"],
  });
  const { context } = createModelTestContext();
  const error = await assertRejects(
    () => zfs.methods.create_pool.execute(args, context),
    DeviceGuardError,
  );
  assertEquals(error.code, "boot-protected");
});

Deno.test("create_pool refuses a disk named only by an fstab UUID", async () => {
  const zfs = model(guardProbeRoute({
    lsblk: lsblkJson(
      {
        name: "sda",
        type: "disk",
        children: [{
          name: "sda1",
          type: "part",
          fstype: "ext4",
          mounts: ["/"],
        }],
      },
      {
        name: "sdb",
        type: "disk",
        children: [{
          name: "sdb1",
          type: "part",
          fstype: "ext4",
          uuid: "22222222-3333-4444-5555-666666666666",
        }],
      },
      { name: "sdc", type: "disk" },
    ),
    findmnt: findmntJson({
      target: "/",
      source: "/dev/sda1",
      fstype: "ext4",
    }),
    fstab: "/dev/sda1 / ext4 defaults 0 1\n" +
      "UUID=22222222-3333-4444-5555-666666666666 /var/lib/data ext4 noauto 0 2\n",
  }));
  const args = zfs.methods.create_pool.arguments.parse({
    ssh: SSH,
    pool: "tank",
    vdevs: ["/dev/sdb"],
  });
  const { context } = createModelTestContext();
  const error = await assertRejects(
    () => zfs.methods.create_pool.execute(args, context),
    DeviceGuardError,
  );
  assertEquals(error.code, "boot-protected");
});

Deno.test("create_pool refuses either parent of a multi-parent LV", async () => {
  const spanning: DevSpec = {
    name: "vg1-data",
    type: "lvm",
    fstype: "xfs",
    mounts: ["/srv"],
  };
  const route = fullCreateRoute({
    lsblk: lsblkJson(
      {
        name: "sda",
        type: "disk",
        children: [{
          name: "sda1",
          type: "part",
          fstype: "ext4",
          mounts: ["/"],
        }],
      },
      {
        name: "sdb",
        type: "disk",
        fstype: "LVM2_member",
        children: [spanning],
      },
      {
        name: "sdc",
        type: "disk",
        fstype: "LVM2_member",
        children: [spanning],
      },
      { name: "sdd", type: "disk" },
    ),
    findmnt: findmntJson(
      { target: "/", source: "/dev/sda1", fstype: "ext4" },
      { target: "/srv", source: "/dev/mapper/vg1-data", fstype: "xfs" },
    ),
    fstab: "/dev/sda1 / ext4 defaults 0 1\n",
    links: "/dev/mapper/vg1-data /dev/dm-3\n",
    pvs: "  /dev/sdb  vg1\n  /dev/sdc  vg1\n",
  });
  for (const vdev of ["/dev/sdb", "/dev/sdc"]) {
    const error = await assertRejects(
      () =>
        model(route).methods.create_pool.execute(
          model(route).methods.create_pool.arguments.parse({
            ssh: SSH,
            pool: "tank",
            vdevs: [vdev],
          }),
          createModelTestContext().context,
        ),
      DeviceGuardError,
      vdev,
    );
    assertEquals(error.code, "boot-protected", vdev);
  }
  const args = model(route).methods.create_pool.arguments.parse({
    ssh: SSH,
    pool: "tank",
    vdevs: ["/dev/sdd"],
  });
  await model(route).methods.create_pool.execute(
    args,
    createModelTestContext().context,
  );
});

Deno.test("create_pool refuses a faulty md member with combined flags", async () => {
  const route = fullCreateRoute({
    lsblk: lsblkJson(
      {
        name: "sda",
        type: "disk",
        children: [{
          name: "sda1",
          type: "part",
          fstype: "linux_raid_member",
          children: [{
            name: "md0",
            type: "raid1",
            fstype: "ext4",
            mounts: ["/"],
          }],
        }],
      },
      {
        name: "sdc",
        type: "disk",
        children: [{ name: "sdc1", type: "part", fstype: "linux_raid_member" }],
      },
      { name: "sdd", type: "disk" },
    ),
    findmnt: findmntJson({
      target: "/",
      source: "/dev/md0",
      fstype: "ext4",
    }),
    fstab: "",
    mdstat: "md0 : active raid1 sdc1[2](W)(F) sda1[0]\n",
    mdExamine: {
      "/dev/sda1": { code: 0, stdout: MD_EXAMINE },
      "/dev/sdc1": { code: 0, stdout: MD_EXAMINE },
    },
  });
  const error = await assertRejects(
    () =>
      model(route).methods.create_pool.execute(
        model(route).methods.create_pool.arguments.parse({
          ssh: SSH,
          pool: "tank",
          vdevs: ["/dev/sdc"],
        }),
        createModelTestContext().context,
      ),
    DeviceGuardError,
  );
  assertEquals(error.code, "boot-protected");
  const args = model(route).methods.create_pool.arguments.parse({
    ssh: SSH,
    pool: "tank",
    vdevs: ["/dev/sdd"],
  });
  await model(route).methods.create_pool.execute(
    args,
    createModelTestContext().context,
  );
});

Deno.test("create_pool allows a free sibling of a root md member", async () => {
  const arrayUuid = MD_ARRAY_UUID.replaceAll(":", "-");
  const member = (n: string): DevSpec => ({
    name: `${n}1`,
    type: "part",
    fstype: "linux_raid_member",
    uuid: arrayUuid,
    children: [{ name: "md0", type: "raid1", fstype: "ext4", mounts: ["/"] }],
  });
  const free = (n: string): DevSpec => ({ name: `${n}2`, type: "part" });
  const route = fullCreateRoute({
    lsblk: lsblkJson(
      { name: "sda", type: "disk", children: [member("sda"), free("sda")] },
      { name: "sdb", type: "disk", children: [member("sdb"), free("sdb")] },
    ),
    findmnt: findmntJson({ target: "/", source: "/dev/md0", fstype: "ext4" }),
    fstab: "/dev/md0 / ext4 defaults 0 1\n",
    mdstat: "md0 : active raid1 sdb1[1] sda1[0]\n",
    links: "/dev/disk/by-id/ata-EXAMPLE_A-part2 /dev/sda2\n" +
      "/dev/disk/by-id/ata-EXAMPLE_B-part2 /dev/sdb2\n",
    blkid: `/dev/sda1: UUID="${arrayUuid}" TYPE="linux_raid_member"\n` +
      `/dev/sdb1: UUID="${arrayUuid}" TYPE="linux_raid_member"\n` +
      `/dev/md0: UUID="11111111-2222-3333-4444-555555555555" TYPE="ext4"\n`,
    mdExamine: {
      "/dev/sda1": { code: 0, stdout: MD_EXAMINE },
      "/dev/sdb1": { code: 0, stdout: MD_EXAMINE },
    },
  });
  // A whole disk carries a root md member partition, so it is refused.
  for (const vdev of ["/dev/sda", "/dev/sdb"]) {
    const error = await assertRejects(
      () =>
        model(route).methods.create_pool.execute(
          model(route).methods.create_pool.arguments.parse({
            ssh: SSH,
            pool: "tank",
            vdevs: [vdev],
          }),
          createModelTestContext().context,
        ),
      DeviceGuardError,
      vdev,
    );
    assertEquals(error.code, "boot-protected", vdev);
  }
  // A new free sibling partition is allowed, plain and by-id.
  for (
    const vdev of [
      "/dev/sda2",
      "/dev/sdb2",
      "/dev/disk/by-id/ata-EXAMPLE_A-part2",
    ]
  ) {
    const args = model(route).methods.create_pool.arguments.parse({
      ssh: SSH,
      pool: "tank",
      vdevs: [vdev],
    });
    await model(route).methods.create_pool.execute(
      args,
      createModelTestContext().context,
    );
  }
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

Deno.test("host-key policy is strict-only and host_keys is required", () => {
  const zfs = model(() => undefined);
  // No pinned keys.
  assertThrows(() =>
    zfs.methods.create_pool.arguments.parse({
      ssh: { ...SSH, host_keys: [] },
      pool: "tank",
      vdevs: ["/dev/sdb"],
    })
  );
  // Trust-on-first-use is not offered.
  assertThrows(() =>
    zfs.methods.create_pool.arguments.parse({
      ssh: { ...SSH, host_key_policy: "insecure_tofu" },
      pool: "tank",
      vdevs: ["/dev/sdb"],
    })
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
    if (has(remote, "/etc/fstab")) return { code: 2, stderr: "I/O error" };
    return guardProbeRoute()(remote);
  });
  const args = zfs.methods.create_pool.arguments.parse({
    ssh: SSH,
    pool: "tank",
    vdevs: ["/dev/sdb"],
  });
  const { context } = createModelTestContext();
  const error = await assertRejects(
    () => zfs.methods.create_pool.execute(args, context),
    DeviceGuardError,
  );
  assertEquals(error.code, "boot-unverifiable");
});

Deno.test("create_pool refuses when a safety fact cannot be read", async () => {
  const commands: string[] = [];
  const zfs = model((remote) => {
    commands.push(remote);
    if (has(remote, "lsblk -J -b -o")) {
      return { code: 1, stderr: "lsblk: failed" };
    }
    return guardProbeRoute()(remote);
  });
  const args = zfs.methods.create_pool.arguments.parse({
    ssh: SSH,
    pool: "tank",
    vdevs: ["/dev/sdb"],
  });
  const { context } = createModelTestContext();
  await assertRejects(
    () => zfs.methods.create_pool.execute(args, context),
    DeviceGuardError,
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

Deno.test("destroy_pool refuses children without an ack, then destroys with one", async () => {
  const base = (remote: string): RouteResult | undefined => {
    if (has(remote, P.poolProbe)) return { code: 0, stdout: "tank\n" };
    if (has(remote, P.poolDescendants)) {
      return { code: 0, stdout: "tank\ntank/data\ntank/data@a\n" };
    }
    return guardProbeRoute()(remote);
  };
  const refuses = model((remote) => {
    if (has(remote, P.poolDestroy)) return { code: 0 };
    return base(remote);
  });
  const error = await assertRejects(
    () =>
      refuses.methods.destroy_pool.execute(
        refuses.methods.destroy_pool.arguments.parse({
          ssh: SSH,
          pool: "tank",
          recursive: false,
        }),
        createModelTestContext().context,
      ),
    Error,
    "set recursive",
  );
  assertEquals(error.message.includes("2 dataset"), true);

  const commands: string[] = [];
  const recursive = model((remote) => {
    commands.push(remote);
    if (has(remote, P.poolDestroy)) return { code: 0 };
    return base(remote);
  });
  const out = await recursive.methods.destroy_pool.execute(
    recursive.methods.destroy_pool.arguments.parse({
      ssh: SSH,
      pool: "tank",
      recursive: true,
    }),
    createModelTestContext().context,
  ) as { result: { destroyed: boolean } };
  assertEquals(out.result.destroyed, true);
  assertEquals(
    commands.some((c) => has(c, "'zpool' 'destroy' '-f' 'tank'")),
    true,
  );
});

Deno.test("destroy_pool and export_pool are clean no-ops on an absent pool", async () => {
  const m = model(guardProbeRoute());
  const destroyed = await m.methods.destroy_pool.execute(
    m.methods.destroy_pool.arguments.parse({ ssh: SSH, pool: "tank" }),
    createModelTestContext().context,
  ) as { result: { destroyed: boolean } };
  assertEquals(destroyed.result.destroyed, false);
  const exported = await m.methods.export_pool.execute(
    m.methods.export_pool.arguments.parse({ ssh: SSH, pool: "tank" }),
    createModelTestContext().context,
  ) as { result: { exported: boolean } };
  assertEquals(exported.result.exported, false);
});

Deno.test("export_pool is not forced by default and forces when asked", async () => {
  const commands: string[] = [];
  const m = model((remote) => {
    commands.push(remote);
    if (has(remote, P.poolProbe)) return { code: 0, stdout: "tank\n" };
    if (has(remote, P.poolExport)) return { code: 0 };
    return guardProbeRoute()(remote);
  });
  const plain = await m.methods.export_pool.execute(
    m.methods.export_pool.arguments.parse({ ssh: SSH, pool: "tank" }),
    createModelTestContext().context,
  ) as { result: { exported: boolean } };
  assertEquals(plain.result.exported, true);
  assertEquals(commands.some((c) => has(c, "'zpool' 'export' 'tank'")), true);
  assertEquals(
    commands.some((c) => has(c, "'zpool' 'export' '-f' 'tank'")),
    false,
  );

  const forced = await m.methods.export_pool.execute(
    m.methods.export_pool.arguments.parse({
      ssh: SSH,
      pool: "tank",
      force: true,
    }),
    createModelTestContext().context,
  ) as { result: { exported: boolean } };
  assertEquals(forced.result.exported, true);
  assertEquals(
    commands.some((c) => has(c, "'zpool' 'export' '-f' 'tank'")),
    true,
  );
});

Deno.test("a zpool failure surfaces the sanitized stderr reason", async () => {
  const m = model((remote) => {
    if (has(remote, P.poolCreate)) {
      return {
        code: 1,
        stderr:
          "cannot create 'tank': one or more devices is currently unavailable\n",
      };
    }
    return fullCreateRoute()(remote);
  });
  const error = await assertRejects(
    () =>
      m.methods.create_pool.execute(
        m.methods.create_pool.arguments.parse({
          ssh: SSH,
          pool: "tank",
          vdevs: ["/dev/sdb"],
        }),
        createModelTestContext().context,
      ),
    Error,
    "one or more devices is currently unavailable",
  );
  assertEquals(error.message.includes("failed (exit 1)"), true);
});

/** A route that makes `tank` look like a system pool via the given mounts. */
function systemPoolRoute(
  mount: { target: string; source: string } | {
    target: string;
    source: string;
  }[],
  opts: {
    bootfs?: string;
    findmntCode?: number;
    zvols?: string[];
    devices?: Record<string, string>;
    swaps?: string[];
    readlinkCode?: number;
    lsblkCode?: number;
    ancestors?: Record<string, string[]>;
  } = {},
): Route {
  const mounts = Array.isArray(mount) ? mount : [mount];
  const findmnt = JSON.stringify({ filesystems: mounts });
  return (remote) => {
    if (has(remote, P.poolProbe)) return { code: 0, stdout: "tank\n" };
    if (has(remote, "'zpool' 'get'")) {
      return { code: 0, stdout: `${opts.bootfs ?? "-"}\n` };
    }
    if (has(remote, "findmnt -J")) {
      return { code: opts.findmntCode ?? 0, stdout: findmnt };
    }
    if (has(remote, "/proc/swaps")) {
      const swaps = opts.swaps ?? [];
      const body = [
        "Filename Type Size Used Priority",
        ...swaps.map((d) => `${d} partition 0 0 -2`),
      ].join("\n");
      return { code: 0, stdout: `${body}\n` };
    }
    if (has(remote, P.poolVolumes)) {
      const zvols = opts.zvols ?? [];
      return { code: 0, stdout: zvols.length ? `${zvols.join("\n")}\n` : "" };
    }
    if (has(remote, "readlink")) {
      if (opts.readlinkCode !== undefined) {
        return { code: opts.readlinkCode, stdout: "", stderr: "no such file" };
      }
      const link = /'readlink' '-f' '([^']+)'/.exec(remote)?.[1] ?? "";
      const name = link.replace("/dev/zvol/", "");
      return { code: 0, stdout: `${opts.devices?.[name] ?? link}\n` };
    }
    if (has(remote, "'lsblk' '-s'")) {
      if (opts.lsblkCode !== undefined) {
        return { code: opts.lsblkCode, stdout: "", stderr: "lsblk error" };
      }
      const dev =
        /'lsblk' '-s' '-n' '-o' 'PATH,TYPE' '([^']+)'/.exec(remote)?.[1] ?? "";
      const ancestors = opts.ancestors?.[dev] ?? [dev];
      return {
        code: 0,
        stdout: ancestors.map((p) => `${p} disk`).join("\n") + "\n",
      };
    }
    if (has(remote, P.poolDescendants)) {
      return { code: 0, stdout: "tank\ntank/data\n" };
    }
    if (has(remote, P.poolDestroy)) return { code: 0 };
    if (has(remote, P.poolExport)) return { code: 0 };
    return guardProbeRoute()(remote);
  };
}

Deno.test("destroy_pool refuses a system pool regardless of recursive", async () => {
  const cases: Route[] = [
    // A dataset at / or /boot.
    systemPoolRoute({ target: "/", source: "tank/ROOT/ubuntu" }),
    systemPoolRoute({ target: "/boot", source: "tank/BOOT/ubuntu" }),
    // A system mount backed by a zvol, as mount(8) reports it: /dev/zd0.
    systemPoolRoute({ target: "/var", source: "/dev/zd0" }, {
      zvols: ["tank/var"],
      devices: { "tank/var": "/dev/zd0" },
    }),
    // A partitioned zvol: /dev/zd0p1.
    systemPoolRoute({ target: "/boot", source: "/dev/zd0p1" }, {
      zvols: ["tank/var"],
      devices: { "tank/var": "/dev/zd0" },
    }),
    // A bind mount of the pool root onto /var.
    systemPoolRoute({ target: "/var", source: "tank[/var]" }),
    // bootfs set.
    systemPoolRoute({ target: "/", source: "/dev/sda1" }, {
      bootfs: "tank/ROOT/ubuntu",
    }),
    // A zvol active as swap, reported as /dev/zd16.
    systemPoolRoute({ target: "/", source: "/dev/sda1" }, {
      zvols: ["tank/swap"],
      devices: { "tank/swap": "/dev/zd16" },
      swaps: ["/dev/zd16"],
    }),
    // dm-crypt on a zvol: the mount source is /dev/dm-0, whose ancestry
    // includes /dev/zd0.
    systemPoolRoute({ target: "/", source: "/dev/dm-0" }, {
      zvols: ["tank/root"],
      devices: { "tank/root": "/dev/zd0" },
      ancestors: { "/dev/dm-0": ["/dev/dm-0", "/dev/zd0"] },
    }),
    // A nested bind-mount suffix is stripped from the first '['.
    systemPoolRoute({ target: "/var", source: "tank[/a[b]]" }),
  ];
  for (const route of cases) {
    const m = model(route);
    await assertRejects(
      () =>
        m.methods.destroy_pool.execute(
          m.methods.destroy_pool.arguments.parse({
            ssh: SSH,
            pool: "tank",
            recursive: true,
          }),
          createModelTestContext().context,
        ),
      SystemPoolError,
    );
  }
});

Deno.test("a failing system-pool probe fails closed", async () => {
  const failingFindmnt = model(
    systemPoolRoute({ target: "/", source: "/dev/sda1" }, { findmntCode: 1 }),
  );
  await assertRejects(
    () =>
      failingFindmnt.methods.destroy_pool.execute(
        failingFindmnt.methods.destroy_pool.arguments.parse({
          ssh: SSH,
          pool: "tank",
          recursive: true,
        }),
        createModelTestContext().context,
      ),
    SystemPoolError,
    "could not read mounts",
  );
  // A zvol that cannot be resolved to its device also fails closed.
  const failingReadlink = model(
    systemPoolRoute({ target: "/", source: "/dev/sda1" }, {
      zvols: ["tank/var"],
      readlinkCode: 1,
    }),
  );
  await assertRejects(
    () =>
      failingReadlink.methods.destroy_pool.execute(
        failingReadlink.methods.destroy_pool.arguments.parse({
          ssh: SSH,
          pool: "tank",
          recursive: true,
        }),
        createModelTestContext().context,
      ),
    SystemPoolError,
    "did not resolve to a /dev/zdN device",
  );
});

Deno.test("export_pool refuses a system pool too", async () => {
  const m = model(
    systemPoolRoute(
      { target: "/boot", source: "tank/BOOT/ubuntu" },
    ),
  );
  await assertRejects(
    () =>
      m.methods.export_pool.execute(
        m.methods.export_pool.arguments.parse({ ssh: SSH, pool: "tank" }),
        createModelTestContext().context,
      ),
    SystemPoolError,
  );
});

Deno.test("destroy_pool refuses without recursive when system checks pass", async () => {
  const m = model(systemPoolRoute({ target: "/", source: "/dev/sda1" }));
  await assertRejects(
    () =>
      m.methods.destroy_pool.execute(
        m.methods.destroy_pool.arguments.parse({
          ssh: SSH,
          pool: "tank",
          recursive: false,
        }),
        createModelTestContext().context,
      ),
    Error,
    "set recursive",
  );
});

Deno.test("a failing ancestry probe fails closed; a stacked swap is refused", async () => {
  const failing = model(
    systemPoolRoute({ target: "/", source: "/dev/dm-0" }, {
      zvols: ["tank/root"],
      devices: { "tank/root": "/dev/zd0" },
      lsblkCode: 1,
    }),
  );
  await assertRejects(
    () =>
      failing.methods.export_pool.execute(
        failing.methods.export_pool.arguments.parse({ ssh: SSH, pool: "tank" }),
        createModelTestContext().context,
      ),
    SystemPoolError,
    "ancestry",
  );

  const swap = model(
    systemPoolRoute({ target: "/", source: "/dev/sda1" }, {
      zvols: ["tank/swap"],
      devices: { "tank/swap": "/dev/zd16" },
      swaps: ["/dev/dm-1"],
      ancestors: { "/dev/dm-1": ["/dev/dm-1", "/dev/zd16"] },
    }),
  );
  await assertRejects(
    () =>
      swap.methods.export_pool.execute(
        swap.methods.export_pool.arguments.parse({ ssh: SSH, pool: "tank" }),
        createModelTestContext().context,
      ),
    SystemPoolError,
    "stacked on zvol",
  );
});
