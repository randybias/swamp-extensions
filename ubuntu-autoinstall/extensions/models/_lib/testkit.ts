/**
 * Shared fixtures and a fake remote for the autoinstall tests.
 *
 * The fake implements the remote side of the vendored transport (an in-memory
 * filesystem behind the `ssh` command) so the model's publish path is exercised
 * without a host, in one place rather than in every test.
 *
 * @module
 */

import { createModelTestContext } from "jsr:@swamp-club/swamp-testing@0.20261014.55";
import { type CommandRunner, sha256Hex, type SshDeps } from "./ssh.ts";
import type { AutoinstallInput, StorageInput } from "./render.ts";

/** A placeholder crypt(3) SHA-512 hash (never a real one): 86-char hash part. */
export const HASH = "$6$abcdefgh$" + "a".repeat(86);
/** A synthetic ed25519 public key line. */
export const KEY =
  "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeKeyForTestsPlaceholder000000000000 user@example.com";
/** A synthetic pinned host-key line. */
export const HOSTKEY =
  "192.0.2.10 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeHostKeyForTests000";

/** A strict SSH target, as the schemas carry it. */
export const SSH_TARGET = {
  host: "192.0.2.10",
  port: 22,
  user: "root",
  host_key_policy: "strict" as const,
  host_keys: [HOSTKEY],
};

/** The seed server block used by publish/get/sync tests. */
export const SERVER = {
  ssh: SSH_TARGET,
  root: "/srv/artifacts",
  url_base: "https://seed.example.com",
};

/** A valid pure-renderer input. */
export function seedInput(
  over: Partial<AutoinstallInput> = {},
): AutoinstallInput {
  return {
    identity: { hostname: "web-1", username: "installer", password_hash: HASH },
    ssh: { install_server: true, authorized_keys: [KEY], allow_pw: false },
    ...over,
  };
}

/** A valid `render`/`publish_http` argument object. */
export function renderArgs(over: Record<string, unknown> = {}) {
  return {
    identity: {
      hostname: "web-1",
      username: "installer",
      password_hash: HASH,
    },
    ssh: { install_server: true, authorized_keys: [KEY] },
    storage: { layout: "lvm" as const },
    ...over,
  };
}

/** A valid `publish_http` argument object. */
export function publishArgs(over: Record<string, unknown> = {}) {
  return { ...renderArgs(over), server: SERVER };
}

/** A model test context with a stable definition name. */
export function createCtx(
  options: { storedResources?: Record<string, Record<string, unknown>> } = {},
) {
  return createModelTestContext({
    globalArgs: {},
    definition: { name: "test-autoinstall" },
    ...options,
  });
}

/** A call the fake runner recorded. */
export interface RemoteCall {
  /** The `ssh` argv, last element the remote command. */
  args: string[];
  /** The bytes piped to the remote command, decoded. */
  stdin?: string;
}

/** An in-memory remote filesystem, the fake transport and the calls it saw. */
export interface FakeRemote {
  /** Path to `{content, mode}`. */
  fs: Map<string, { content: string; mode: string }>;
  /** Every `ssh` invocation. */
  calls: RemoteCall[];
  /** Dependency set to inject with `setDeps`. */
  deps: SshDeps;
}

const decode = (v: string | Uint8Array | undefined): string | undefined =>
  v === undefined
    ? undefined
    : typeof v === "string"
    ? v
    : new TextDecoder().decode(v);

/**
 * Fakes the remote side of the transport: an in-memory filesystem that answers
 * the upload probe and write, `sha256sum`, `cat`, `mkdir` and `rm -rf`.
 */
export function fakeRemote(): FakeRemote {
  const fs = new Map<string, { content: string; mode: string }>();
  const calls: RemoteCall[] = [];
  const run: CommandRunner = async (cmd, args, options = {}) => {
    if (cmd === "ssh-agent") {
      return {
        code: 0,
        stdout:
          "SSH_AUTH_SOCK=/tmp/a.sock; export SSH_AUTH_SOCK;\nSSH_AGENT_PID=1; export SSH_AGENT_PID;\n",
        stderr: "",
      };
    }
    if (cmd === "ssh-add") return { code: 0, stdout: "", stderr: "" };
    if (cmd !== "ssh") return { code: 0, stdout: "", stderr: "" };
    const remote = args[args.length - 1];
    const stdin = decode(options.stdin);
    calls.push({ args, stdin });
    const answer = await answerRemote(fs, remote, stdin);
    return { ...answer, stderr: answer.stderr ?? "" };
  };
  return {
    fs,
    calls,
    deps: { run, now: () => 0, sleep: () => Promise.resolve() },
  };
}

async function answerRemote(
  fs: FakeRemote["fs"],
  remote: string,
  stdin: string | undefined,
): Promise<{ code: number; stdout: string; stderr?: string }> {
  if (remote.includes("SYMLINK") && remote.includes("MISSING")) {
    const file = /f='([^']+)'/.exec(remote)?.[1] ?? "";
    const cur = fs.get(file);
    if (!cur) return { code: 0, stdout: "MISSING\n" };
    return { code: 0, stdout: `${await sha256Hex(cur.content)} ${cur.mode}\n` };
  }
  if (remote.includes("mktemp") && remote.includes("mv -T")) {
    const file = /f='([^']+)'/.exec(remote)?.[1] ?? "";
    const mode = /chmod '([0-7]+)'/.exec(remote)?.[1] ?? "0600";
    fs.set(file, { content: stdin ?? "", mode });
    return { code: 0, stdout: `${await sha256Hex(stdin ?? "")} ${mode}\n` };
  }
  if (remote.startsWith("'stat'")) {
    const path = /'stat' '-c' '%F' '--' '([^']+)'/.exec(remote)?.[1] ?? "";
    return fs.has(path) ? { code: 0, stdout: "regular file\n" } : {
      code: 1,
      stdout: "",
      stderr: `stat: cannot statx '${path}': No such file or directory`,
    };
  }
  if (remote.startsWith("'sha256sum'")) {
    const file = /'sha256sum' '--' '([^']+)'/.exec(remote)?.[1] ?? "";
    const cur = fs.get(file);
    if (!cur) {
      return { code: 1, stdout: "", stderr: "No such file or directory" };
    }
    return { code: 0, stdout: `${await sha256Hex(cur.content)}  ${file}\n` };
  }
  if (remote.startsWith("'cat'")) {
    const file = /'cat' '--' '([^']+)'/.exec(remote)?.[1] ?? "";
    const cur = fs.get(file);
    if (!cur) {
      return { code: 1, stdout: "", stderr: "No such file or directory" };
    }
    return { code: 0, stdout: cur.content };
  }
  if (remote.startsWith("'mkdir'")) return { code: 0, stdout: "" };
  if (remote.startsWith("'rm'")) {
    const path = /'rm' '-rf' '--' '([^']+)'/.exec(remote)?.[1] ?? "";
    for (const key of [...fs.keys()]) {
      if (key === path || key.startsWith(`${path}/`)) fs.delete(key);
    }
    return { code: 0, stdout: "" };
  }
  return { code: 0, stdout: "" };
}

/** A static netplan bond shared by the golden and container tests. */
export const STATIC_BOND = {
  version: 2,
  ethernets: {
    eno1: { match: { macaddress: "02:00:00:00:00:01" }, dhcp4: false },
    eno2: { match: { macaddress: "02:00:00:00:00:02" }, dhcp4: false },
  },
  bonds: {
    bond0: {
      interfaces: ["eno1", "eno2"],
      addresses: ["192.0.2.10/24"],
      routes: [{ to: "default", via: "192.0.2.1" }],
      nameservers: { addresses: ["192.0.2.53"] },
      parameters: { mode: "active-backup" },
    },
  },
};

/** Explicit RAID10 + LVM: one ESP on the grub disk, an md array, a VG and an LV. */
export const RAID10_LVM: StorageInput = {
  config: [
    { type: "disk", id: "diska", serial: "SERIALA", grub_device: true },
    { type: "disk", id: "diskb", serial: "SERIALB" },
    { type: "disk", id: "diskc", serial: "SERIALC" },
    { type: "disk", id: "diskd", serial: "SERIALD" },
    {
      type: "partition",
      id: "espa",
      device: "diska",
      size: 536870912,
      flag: "boot",
    },
    { type: "partition", id: "dat-a", device: "diska", size: -1 },
    { type: "partition", id: "dat-b", device: "diskb", size: -1 },
    { type: "partition", id: "dat-c", device: "diskc", size: -1 },
    { type: "partition", id: "dat-d", device: "diskd", size: -1 },
    { type: "format", id: "espafmt", volume: "espa", fstype: "fat32" },
    { type: "mount", id: "espamnt", device: "espafmt", path: "/boot/efi" },
    {
      type: "raid",
      id: "md0",
      raidlevel: 10,
      devices: ["dat-a", "dat-b", "dat-c", "dat-d"],
      spare_devices: [],
    },
    { type: "lvm_volgroup", id: "vg0", name: "vg0", devices: ["md0"] },
    { type: "lvm_partition", id: "lv-root", name: "root", volgroup: "vg0" },
    { type: "format", id: "fmt-root", volume: "lv-root", fstype: "ext4" },
    { type: "mount", id: "mnt-root", device: "fmt-root", path: "/" },
  ],
};

/** The four storage profiles the golden matrix covers. */
export const STORAGE_PROFILES: Record<string, StorageInput> = {
  lvm: { layout: "lvm", sizing_policy: "scaled" },
  direct: { layout: "direct", match: { size: "largest" } },
  "raid1-lvm": {
    preset: "raid1-lvm",
    disks: ["SERIALA", "SERIALB"],
    vg_name: "vg0",
    lvs: [{ name: "root", size: "20G", fs: "ext4", mount: "/" }],
  },
  "raid10-lvm": RAID10_LVM,
};

/** The two networks the golden matrix covers. */
export const SEED_NETWORKS: Record<
  string,
  Record<string, unknown> | undefined
> = {
  dhcp: undefined,
  bond: STATIC_BOND,
};
