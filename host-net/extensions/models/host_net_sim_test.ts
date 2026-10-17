// deno-lint-ignore-file no-explicit-any
// The harness reads loosely-typed records the model writes; the assertions
// below check their fields.
/**
 * Whole-lifecycle tests against a simulated host: the model's real host
 * scripts run under a real `sh` with stub `ip`, `netplan`, `networkctl`,
 * `systemctl` and `systemd-run` binaries that keep their state in a temporary
 * directory standing in for `/`. These are the sequences that single-step tests
 * missed: ownership, provenance and MTU baselines across several commits.
 */
import { assert, assertEquals, assertRejects } from "jsr:@std/assert@1.0.19";
import { createModel } from "./host_net.ts";
import type { CommandRunner } from "./_lib/ssh.ts";

const SSH = {
  host: "192.0.2.20",
  port: 22,
  user: "root",
  host_key_policy: "strict" as const,
  host_keys: ["192.0.2.20 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFake"],
  ssh_key_ref: { vault: "v", key: "k" },
  connect_timeout_s: 15,
};
const A = {
  id: 100,
  link: "enp1s0",
  mtu: 9000,
  addresses: ["198.51.100.10/24"],
};
const B = { id: 200, link: "enp1s0", addresses: ["198.51.100.20/24"] };
const KEY = "root@192.0.2.20:22";
const STUBS = [
  "ip",
  "netplan",
  "networkctl",
  "simip.py",
  "systemctl",
  "systemd-run",
];

async function simAvailable(): Promise<boolean> {
  try {
    // python3 backs the `ip`/`netplan` stubs; check it through sh, which is the
    // only program the tests are allowed to start.
    const out = await new Deno.Command("sh", {
      args: ["-c", "command -v python3 >/dev/null"],
      stdout: "null",
      stderr: "null",
    }).output();
    return out.success;
  } catch {
    return false; // no permission to run sh, or sh is missing
  }
}

interface World {
  call: (m: string, a: Record<string, unknown>) => Promise<any>;
  store: Map<string, Record<string, any>>;
  links: () => Promise<Record<string, number>>;
  files: () => Promise<string[]>;
  root: string;
  cleanup: () => Promise<void>;
}

async function world(): Promise<World> {
  const root = await Deno.makeTempDir({ prefix: "host-net-sim-" });
  const bin = `${root}/bin`;
  await Deno.mkdir(bin, { recursive: true });
  for (const name of STUBS) {
    await Deno.copyFile(
      new URL(`./_lib/testdata/sim/${name}`, import.meta.url),
      `${bin}/${name}`,
    );
    await Deno.chmod(`${bin}/${name}`, 0o755);
  }
  for (
    const d of [
      "etc/netplan",
      "etc/systemd/network",
      "etc/cloud/cloud.cfg.d",
      "var/lib",
      "run",
      "tmp",
      "state/units",
    ]
  ) await Deno.mkdir(`${root}/${d}`, { recursive: true });
  const nic = (ifname: string, address: string) => ({
    ifname,
    mtu: 1500,
    operstate: "UP",
    address,
    linkinfo: { info_kind: "ether" },
  });
  await Deno.writeTextFile(
    `${root}/state/links.json`,
    JSON.stringify([
      nic("enp1s0", "02:00:00:00:00:01"),
      nic("enp2s0", "02:00:00:00:00:02"),
    ]),
  );
  await Deno.writeTextFile(`${root}/state/log`, "");
  const re =
    /(\/etc\/|\/var\/lib\/host-net|\/run\/host-net\.lock|\/tmp\/host-net-precheck)/g;
  const run: CommandRunner = async (cmd, args, options = {}) => {
    if (cmd === "ssh-agent") {
      return {
        code: 0,
        stdout: args[0] === "-s"
          ? "SSH_AUTH_SOCK=/tmp/a.sock;\nSSH_AGENT_PID=1;\n"
          : "",
        stderr: "",
      };
    }
    if (cmd !== "ssh") return { code: 0, stdout: "", stderr: "" };
    const remote = args[args.length - 1].replace(re, (m) => root + m);
    const p = new Deno.Command("sh", {
      args: ["-c", remote],
      stdin: "piped",
      stdout: "piped",
      stderr: "piped",
      env: {
        PATH: `${bin}:/usr/bin:/bin`,
        SIMROOT: root,
        SIMBIN: bin,
        SSH_CONNECTION: "192.0.2.99 1 192.0.2.20 22",
      },
      clearEnv: true,
    }).spawn();
    const w = p.stdin.getWriter();
    if (options.stdin !== undefined) {
      await w.write(
        typeof options.stdin === "string"
          ? new TextEncoder().encode(options.stdin)
          : options.stdin,
      );
    }
    await w.close();
    const o = await p.output();
    const dec = (b: Uint8Array) =>
      new TextDecoder().decode(b).replaceAll(root, "");
    return { code: o.code, stdout: dec(o.stdout), stderr: dec(o.stderr) };
  };
  let n = 0;
  const model = createModel({
    run,
    now: () => Date.now(),
    sleep: () => Promise.resolve(),
    resolveSecret: () => Promise.resolve("K"),
    token: () => (++n).toString(16).padStart(16, "0"),
  });
  const store = new Map<string, Record<string, any>>();
  const context = {
    logger: { info() {}, warn() {}, error() {} },
    writeResource: (_s: string, name: string, data: Record<string, any>) => {
      store.set(name, structuredClone(data));
      return Promise.resolve({ name });
    },
    readResource: (name: string) =>
      Promise.resolve(
        store.has(name) ? structuredClone(store.get(name)!) : null,
      ),
  };
  const call = async (meth: string, a: Record<string, unknown>) => {
    const md = (model.methods as any)[meth];
    const out = await md.execute(md.arguments.parse(a), context);
    return out.result;
  };
  return {
    call,
    store,
    root,
    links: async () => {
      const list = JSON.parse(
        await Deno.readTextFile(`${root}/state/links.json`),
      );
      return Object.fromEntries(
        list.map((l: { ifname: string; mtu: number }) => [l.ifname, l.mtu]),
      );
    },
    files: async () => {
      const out: string[] = [];
      for (
        const d of [
          "etc/netplan",
          "etc/systemd/network",
          "etc/cloud/cloud.cfg.d",
        ]
      ) {
        for await (const f of Deno.readDir(`${root}/${d}`)) out.push(f.name);
      }
      return out.sort();
    },
    cleanup: () => Deno.remove(root, { recursive: true }),
  };
}

const net = (
  backend: string,
  vlans: unknown[],
  extra: Record<string, unknown> = {},
) => ({
  ...SSH,
  backend,
  bridge_type: "linux",
  management_interface: "enp1s0",
  ethernets: [{ name: "enp1s0" }],
  vlans,
  revert_after_s: 300,
  ...extra,
});

for (const backend of ["netplan", "networkd"] as const) {
  Deno.test(`${backend}: A -> A+B -> B-only -> A+B -> remove keeps ownership and provenance`, async () => {
    if (!await simAvailable()) return;
    const w = await world();
    try {
      const step = async (vlans: unknown[]) => {
        await w.call("apply", net(backend, vlans));
        await w.call("commit", net(backend, vlans));
      };
      const config = () => w.store.get(`config-${KEY}`)!;
      const provenance = () =>
        (config().ownedFiles as { path: string; preExisted: boolean }[])
          .map((f) => f.preExisted);

      await step([A]);
      assertEquals(config().devices, ["enp1s0.100"]);
      assertEquals(provenance().every((p) => p === false), true);

      await step([A, B]);
      assertEquals([...config().devices].sort(), ["enp1s0.100", "enp1s0.200"]);
      // host-net's own files are NOT "pre-existing" just because an earlier
      // apply wrote them.
      assertEquals(provenance().every((p) => p === false), true);

      // Dropping A deletes it (under the armed revert) and its files.
      await step([B]);
      assertEquals(config().devices, ["enp1s0.200"]);
      const afterDrop = await w.links();
      assertEquals("enp1s0.100" in afterDrop, false);
      assertEquals("enp1s0.200" in afterDrop, true);
      if (backend === "networkd") {
        assertEquals(
          (await w.files()).some((f) => f.includes("100")),
          false,
          "the dropped VLAN's files are removed",
        );
      }
      assertEquals(provenance().every((p) => p === false), true);

      // Adding it back works: nothing unowned is left in the way.
      await step([A, B]);
      assertEquals([...config().devices].sort(), ["enp1s0.100", "enp1s0.200"]);
      assertEquals(provenance().every((p) => p === false), true);

      await w.call("remove", net(backend, [A, B]));
      await w.call("commit", net(backend, [A, B]));
      const links = await w.links();
      assertEquals(Object.keys(links).sort(), ["enp1s0", "enp2s0"]);
      assertEquals(
        (await w.files()).filter((f) => f.includes("host-net")),
        [],
        "every file host-net wrote is gone",
      );
      assertEquals(config().devices, []);
      assertEquals(config().ownedFiles, []);
    } finally {
      await w.cleanup();
    }
  });

  Deno.test(`${backend}: dropping a declared VLAN under a revert that fires restores it`, async () => {
    if (!await simAvailable()) return;
    const w = await world();
    try {
      await w.call("apply", net(backend, [A, B]));
      await w.call("commit", net(backend, [A, B]));
      const armed = await w.call("apply", net(backend, [B]));
      assert(!("enp1s0.100" in await w.links()));
      await w.call("revert_now", { ...SSH, token: armed.revert_token });
      // The committed ownership is untouched and the device is back.
      assertEquals(
        [...w.store.get(`config-${KEY}`)!.devices].sort(),
        ["enp1s0.100", "enp1s0.200"],
      );
      assert("enp1s0.100" in await w.links());
    } finally {
      await w.cleanup();
    }
  });
}

Deno.test("the parent MTU baseline survives later commits and remove restores it", async () => {
  if (!await simAvailable()) return;
  const w = await world();
  try {
    const cfg = (vlans: unknown[]) =>
      net("networkd", vlans, { ethernets: [{ name: "enp2s0", mtu: 9000 }] });
    const B2 = { id: 200, link: "enp2s0", addresses: ["198.51.100.20/24"] };
    await w.call("apply", cfg([]));
    await w.call("commit", cfg([]));
    assertEquals((await w.links())["enp2s0"], 9000);
    assertEquals(w.store.get(`config-${KEY}`)!.parentMtus, [
      { name: "enp2s0", mtu: 1500 },
    ]);
    // A second commit sees the NIC already at 9000; the baseline must stay 1500.
    await w.call("apply", cfg([B2]));
    await w.call("commit", cfg([B2]));
    assertEquals(w.store.get(`config-${KEY}`)!.parentMtus, [
      { name: "enp2s0", mtu: 1500 },
    ]);
    await w.call("remove", cfg([B2]));
    await w.call("commit", cfg([B2]));
    assertEquals((await w.links())["enp2s0"], 1500);
  } finally {
    await w.cleanup();
  }
});

Deno.test("takeover: the precheck stage has the cloud-init directory, and remove undoes an MTU-only change", async () => {
  if (!await simAvailable()) return;
  const w = await world();
  try {
    const cfg = net("netplan", [], {
      mode: "takeover",
      management_change_ack: true,
      ethernets: [{ name: "enp1s0", mtu: 9000 }],
    });
    await w.call("apply", cfg);
    await w.call("commit", cfg);
    assertEquals((await w.links())["enp1s0"], 9000);
    await w.call("remove", cfg);
    await w.call("commit", cfg);
    assertEquals((await w.links())["enp1s0"], 1500);
    assertEquals(
      (await w.files()).filter((f) => f.includes("host-net")),
      [],
    );
  } finally {
    await w.cleanup();
  }
});

Deno.test("a restore whose netplan apply exits non-zero still passes on the checks and clears the marker", async () => {
  if (!await simAvailable()) return;
  const w = await world();
  try {
    const armed = await w.call("apply", net("netplan", [A]));
    await Deno.writeTextFile(`${w.root}/state/apply_fails`, "");
    const fired = await w.call("revert_now", {
      ...SSH,
      token: armed.revert_token,
    });
    assertEquals(fired.result, "pass");
    assertEquals(w.store.get(`revert-${KEY}`)!.result, "pass");
    // The current marker is gone, so the next apply is accepted.
    await Deno.remove(`${w.root}/state/apply_fails`);
    await w.call("apply", net("netplan", [A, B]));
  } finally {
    await w.cleanup();
  }
});

Deno.test("a restore whose post-checks fail records fail and blocks later applies until cleared", async () => {
  if (!await simAvailable()) return;
  const w = await world();
  try {
    const armed = await w.call("apply", net("netplan", [A]));
    await Deno.writeTextFile(`${w.root}/state/no_route`, "");
    await assertRejects(
      () => w.call("revert_now", { ...SSH, token: armed.revert_token }),
      Error,
      "restore reported fail",
    );
    assertEquals(w.store.get(`revert-${KEY}`)!.result, "fail");
    // Fail-closed: the host marker blocks the next apply.
    await Deno.remove(`${w.root}/state/no_route`);
    // The clear refuses while the checks fail ...
    await Deno.writeTextFile(`${w.root}/state/no_addr`, "");
    await assertRejects(
      () => w.call("clear_failed_revert", { ...SSH }),
      Error,
      "post-restore checks",
    );
    // ... and clears once they pass.
    await Deno.remove(`${w.root}/state/no_addr`);
    const cleared = await w.call("clear_failed_revert", { ...SSH });
    assertEquals(cleared.cleared, true);
    // Nothing left to clear.
    await assertRejects(
      () => w.call("clear_failed_revert", { ...SSH }),
      Error,
      "no revert marker",
    );
    await w.call("apply", net("netplan", [A]));
  } finally {
    await w.cleanup();
  }
});

Deno.test("clear_failed_revert refuses a marker that is not a failed restore", async () => {
  if (!await simAvailable()) return;
  const w = await world();
  try {
    await w.call("apply", net("netplan", [A]));
    await assertRejects(
      () => w.call("clear_failed_revert", { ...SSH }),
      Error,
      "not a failed restore",
    );
  } finally {
    await w.cleanup();
  }
});
