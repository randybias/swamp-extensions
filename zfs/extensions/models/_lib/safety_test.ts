import { assertEquals, assertRejects } from "jsr:@std/assert@1.0.19";
import {
  type CommandResult,
  type CommandRunner,
  exec,
  type ExecResult,
  type SshDeps,
  type SshTarget,
} from "./ssh.ts";
import {
  assessProtected,
  collectProbes,
  DeviceGuardError,
  isSudoRefusal,
} from "./safety.ts";

const TARGET: SshTarget = {
  host: "192.0.2.10",
  port: 22,
  user: "root",
  host_key_policy: "insecure_tofu",
  private_key: "PLACEHOLDER-KEY",
  connect_timeout_s: 15,
};

interface Route {
  (
    remote: string,
  ): { code?: number; stdout?: string; stderr?: string } | undefined;
}

const has = (remote: string, fragment: string): boolean =>
  remote.includes(fragment);

/** A fake transport spawner that records the remote command of each ssh call. */
function fakeDeps(route: Route): { deps: SshDeps; remotes: string[] } {
  const remotes: string[] = [];
  const run: CommandRunner = (cmd, args) => {
    let result: CommandResult = { code: 0, stdout: "", stderr: "" };
    if (cmd === "ssh-agent") {
      result = {
        code: 0,
        stdout:
          "SSH_AUTH_SOCK=/tmp/a.sock; export SSH_AUTH_SOCK;\nSSH_AGENT_PID=9; export SSH_AGENT_PID;\n",
        stderr: "",
      };
    } else if (cmd === "ssh-add") {
      result = { code: 0, stdout: "", stderr: "" };
    } else if (cmd === "ssh") {
      const remote = args[args.length - 1];
      remotes.push(remote);
      const out = route(remote) ?? {};
      result = {
        code: out.code ?? 0,
        stdout: out.stdout ?? "",
        stderr: out.stderr ?? "",
      };
    }
    return Promise.resolve(result);
  };
  return {
    deps: { run, now: () => 0, sleep: () => Promise.resolve() },
    remotes,
  };
}

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
      label: null,
      mountpoints: [null],
    },
  ],
});
const FINDMNT = JSON.stringify({
  filesystems: [{ target: "/", source: "/dev/sda1", fstype: "ext4" }],
});

/** A plain host route; every probe answers. */
function plainRoute(overrides: Route = () => undefined): Route {
  return (remote) => {
    if (has(remote, "lsblk -J -b -o")) return { code: 0, stdout: LSBLK };
    if (has(remote, "find /dev")) return { code: 0, stdout: "" };
    if (has(remote, "blkid")) return { code: 127, stdout: "" };
    if (has(remote, "findmnt -J")) return { code: 0, stdout: FINDMNT };
    if (has(remote, "/etc/fstab")) {
      return { code: 0, stdout: "UUID=ROOT-UUID / ext4 defaults 0 1\n" };
    }
    if (has(remote, "/proc/swaps")) {
      return { code: 0, stdout: "Filename Type Size Used Priority\n" };
    }
    if (has(remote, "/proc/mdstat")) {
      return { code: 0, stdout: "Personalities :\nunused devices: <none>\n" };
    }
    if (has(remote, "mdadm --examine")) {
      return {
        code: 1,
        stderr: "mdadm: No md superblock detected on /dev/x.\n",
      };
    }
    if (has(remote, "zpool status -P")) {
      return { code: 0, stdout: "no pools available\n" };
    }
    if (has(remote, "pvs --noheadings")) return { code: 127, stdout: "" };
    return overrides(remote);
  };
}

Deno.test("isSudoRefusal recognises sudo's password and tty refusals", () => {
  assertEquals(isSudoRefusal("sudo: a password is required"), true);
  assertEquals(
    isSudoRefusal("sudo: no tty present and no askpass program"),
    true,
  );
  assertEquals(isSudoRefusal("must have a tty to run sudo"), true);
  assertEquals(isSudoRefusal("lsblk: command not found"), false);
});

Deno.test("collectProbes reads every probe and runs device probes as root", async () => {
  const { deps, remotes } = fakeDeps(plainRoute());
  const probes = await collectProbes(deps, TARGET, ["/dev/sdb"]);
  assertEquals(probes.lsblk.code, 0);
  assertEquals(probes.findmnt.stdout, FINDMNT);
  assertEquals(probes.fstab, {
    state: "ok",
    text: "UUID=ROOT-UUID / ext4 defaults 0 1\n",
  });
  assertEquals(probes.zpool.code, 0);
  assertEquals(probes.pvs.code, 127);
  // lsblk, blkid, zpool, pvs and mdadm run under `sudo -n --`; links and
  // findmnt do not.
  for (
    const fragment of [
      "lsblk -J -b -o",
      "zpool status -P",
      "pvs --noheadings",
    ]
  ) {
    const remote = remotes.find((r) => has(r, fragment)) as string;
    assertEquals(has(remote, "'sudo' '-n' '--'"), true, fragment);
  }
  const links = remotes.find((r) => has(r, "find /dev")) as string;
  assertEquals(has(links, "'sudo'"), false);
  const findmnt = remotes.find((r) => has(r, "findmnt -J")) as string;
  assertEquals(has(findmnt, "'sudo'"), false);
});

Deno.test("a sudo refusal is a typed unverifiable error", async () => {
  const { deps } = fakeDeps((remote) =>
    has(remote, "lsblk -J -b -o")
      ? { code: 1, stderr: "sudo: a password is required\n" }
      : plainRoute()(remote)
  );
  const error = await assertRejects(
    () => collectProbes(deps, TARGET, ["/dev/sdb"]),
    DeviceGuardError,
  );
  assertEquals(error.code, "boot-unverifiable");
});

Deno.test("assessProtected allows a spare disk and refuses the boot disk", async () => {
  const { deps } = fakeDeps(plainRoute());
  const set = await assessProtected(deps, TARGET, ["/dev/sdb"]);
  assertEquals(set.devices["/dev/sda1"] !== undefined, true);
  const error = await assertRejects(
    () => assessProtected(deps, TARGET, ["/dev/sda"]),
    DeviceGuardError,
  );
  assertEquals(error.code, "boot-protected");
  assertEquals(error.message.includes("/dev/sda"), true);
});

Deno.test("assessProtected refuses when a file probe is unreadable", async () => {
  const { deps } = fakeDeps((remote) =>
    has(remote, "/etc/fstab")
      ? { code: 2, stderr: "I/O error" }
      : plainRoute()(remote)
  );
  const error = await assertRejects(
    () => assessProtected(deps, TARGET, ["/dev/sdb"]),
    DeviceGuardError,
  );
  assertEquals(error.code, "boot-unverifiable");
});

Deno.test("exec still surfaces the vendored transport's exit code", async () => {
  const { deps } = fakeDeps(() => ({ code: 3, stdout: "x" }));
  const result: ExecResult = await exec(deps, TARGET, ["true"]);
  assertEquals(result.exit_code, 3);
});
