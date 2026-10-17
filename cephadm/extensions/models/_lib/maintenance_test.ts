import {
  assertEquals,
  assertRejects,
  assertThrows,
} from "jsr:@std/assert@1.0.19";
import { PhaseError } from "./errors.ts";
import type { CommandResult, RunOptions, SshSession } from "./ssh.ts";
import {
  cephadmResidue,
  classifyCheckHost,
  classifyFsid,
  enterMaintenance,
  floorPollBudget,
  HOST_MARKERS,
  hostOsdIds,
  lvmResidue,
  nooutClear,
  parseHostState,
  parseOkToStopDaemons,
  parseOsdActivate,
  splitHostSections,
  stripCephadmBanner,
  wholeHostResidue,
} from "./maintenance.ts";

const deps = {
  now: () => 0,
  sleep: () => Promise.resolve(),
  random: () => 0.5,
};

const FSID = "0b1d4c6e-3f2a-4e8b-9c7d-1a2b3c4d5e6f";

/** Builds host-observation stdout from sections. */
function observation(opts: {
  systemctl?: boolean;
  lvm?: boolean;
  fsids?: string[];
  units?: string[];
  unitFiles?: string[];
  vgs?: string[];
  lvs?: string[];
  mdstat?: string[];
  omit?: string[];
} = {}): string {
  const m = HOST_MARKERS;
  const omit = new Set(opts.omit ?? []);
  const lines: string[] = [];
  if (opts.systemctl) lines.push(m.systemctl);
  if (opts.lvm) lines.push(m.lvm);
  const section = (key: keyof typeof HOST_MARKERS, content: string[]) => {
    if (omit.has(key)) return;
    lines.push(m[key], ...content);
  };
  section("fsid", opts.fsids ?? []);
  section("units", opts.units ?? []);
  section("unitFiles", opts.unitFiles ?? []);
  section("vgs", opts.vgs ?? []);
  section("lvs", opts.lvs ?? []);
  section("mdstat", opts.mdstat ?? []);
  return lines.join("\n");
}

/** A session routing both plain host commands and cephadm-shell scripts. */
function mSession(
  route: (body: string, command: string) => CommandResult,
): SshSession {
  let dir = 0;
  let scriptBody = "";
  return {
    target: { host: "192.0.2.10", user: "admin", strictHostKeyChecking: "yes" },
    controlPath: null,
    run: (opts: RunOptions) => {
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
        return Promise.resolve(route(scriptBody, opts.command));
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
}

Deno.test("the host observation splits sections and discards unknown markers", () => {
  const stdout = observation({
    systemctl: true,
    lvm: true,
    fsids: [FSID, "crash"],
    units: ["ceph-abc@mon.h.test loaded active running"],
    unitFiles: ["ceph.target enabled"],
    vgs: ["ceph-abc"],
    lvs: ["ceph-abc/osd-block-1"],
    mdstat: ["md0 : active raid1 sda1[0] sdb1[1]", "unused"],
  });
  const sections = splitHostSections(stdout);
  assertEquals(sections.fsid, [FSID, "crash"]);
  assertEquals(sections.units.length, 1);
  // A presence marker files nothing under the previous section.
  assertEquals(sections.units.includes(HOST_MARKERS.lvm), false);
});

Deno.test(
  "derived host state classifies fsids, units, LVM and md", // leak-allow(decision D17)
  () => {
    const stdout = observation({
      systemctl: true,
      lvm: true,
      fsids: [FSID, "crash", "not-a-uuid"],
      units: [
        `ceph-${FSID}@mon.node1.test loaded active running`,
        "ceph.target loaded active active",
      ],
      unitFiles: ["ceph-crash.service enabled"],
      vgs: ["ceph-abc", "vg-other"],
      lvs: ["ceph-abc/osd-block-1", "vg-other/root"],
      mdstat: ["md0 : active raid1 sda1[0] sdb1[1]"],
    });
    const state = parseHostState("192.0.2.10", stdout);
    assertEquals(state.fsids, [FSID]);
    assertEquals(state.clusterUnits, [`ceph-${FSID}@mon.node1.test`]);
    assertEquals(state.cephVolumeGroups, ["ceph-abc"]);
    assertEquals(state.cephLogicalVolumes, ["ceph-abc/osd-block-1"]);
    assertEquals(state.mdArrays, ["md0"]);
    assertEquals(state.toolsSeen, { systemctl: true, lvm: true, mdstat: true });
  },
);

Deno.test(
  "a missing section marker fails closed, never reading clean", // leak-allow(decision D7)
  () => {
    const stdout = observation({
      systemctl: true,
      lvm: true,
      omit: ["mdstat"],
    });
    assertThrows(
      () => parseHostState("192.0.2.10", stdout),
      PhaseError,
      "not observed",
    );
    assertThrows(() => parseHostState("192.0.2.10", ""), PhaseError);
  },
);

Deno.test(
  "residue refuses when a tool was not observed", // leak-allow(decision D13)
  () => {
    const noSystemctl = parseHostState(
      "h",
      observation({ lvm: true, fsids: [FSID] }),
    );
    assertThrows(() => cephadmResidue(noSystemctl), PhaseError, "not observed");
    const noLvm = parseHostState(
      "h",
      observation({ systemctl: true, vgs: ["ceph-abc"] }),
    );
    assertThrows(() => lvmResidue(noLvm), PhaseError, "not observed");
  },
);

Deno.test("fsid classification refuses a foreign cluster and splits planes", () => {
  const foreign = parseHostState(
    "h",
    observation({
      systemctl: true,
      lvm: true,
      fsids: [FSID, "11111111-2222-3333-4444-555555555555"],
    }),
  );
  assertEquals(classifyFsid(foreign, FSID), "refuse");

  const clean = parseHostState(
    "h",
    observation({ systemctl: true, lvm: true }),
  );
  assertEquals(classifyFsid(clean, FSID), "no-op");

  const stranded = parseHostState(
    "h",
    observation({
      systemctl: true,
      lvm: true,
      vgs: ["ceph-abc"],
      lvs: ["ceph-abc/lv"],
    }),
  );
  assertEquals(classifyFsid(stranded, FSID), "stranded");

  const purge = parseHostState(
    "h",
    observation({
      systemctl: true,
      lvm: true,
      fsids: [FSID],
      units: [`ceph-${FSID}@mon.h.test`],
    }),
  );
  assertEquals(classifyFsid(purge, FSID), "purge");
  // A named fsid in uppercase still matches case-insensitively.
  assertEquals(classifyFsid(purge, FSID.toUpperCase()), "purge");
  // Units with a UUID but no directory still purge.
  assertEquals(wholeHostResidue(purge).length >= 2, true);
});

Deno.test("ok-to-stop output parses daemons from every line shape", () => {
  const text = [
    "Inferring fsid 00000000-0000-0000-0000-000000000000",
    "It is presumed safe to stop host node1. Note the following:",
    "It appears safe to stop osd.3",
    "osd.4,osd.5 are safe to restart",
    "It is presumed safe to stop ['mds.node1']",
    "- osd.6",
  ].join("\n");
  assertEquals(parseOkToStopDaemons(text), [
    "osd.3",
    "osd.4",
    "osd.5",
    "mds.node1",
    "osd.6",
  ]);
  assertEquals(
    stripCephadmBanner(
      "Inferring fsid x\nUsing ceph image with id 'abc'\nALERT: not safe",
    ),
    "ALERT: not safe",
  );
});

Deno.test("check-host classification is ok only on the healthy phrase", () => {
  assertEquals(classifyCheckHost("Host looks OK"), {
    ok: true,
    detail: "Host looks OK",
  });
  assertEquals(classifyCheckHost("no container engine found").ok, false);
  assertEquals(classifyCheckHost("").ok, false);
});

Deno.test("host OSD ids traverse intermediate nodes and terminate on cycles", () => {
  const tree = {
    nodes: [
      { id: -1, name: "default", type: "root", children: [-2] },
      { id: -2, name: "host-a", type: "host", children: [-3] },
      { id: -3, name: "chassis1", type: "chassis", children: [3, 5] },
      { id: 3, name: "osd.3", type: "osd", status: "up" },
      { id: 5, name: "osd.5", type: "osd", status: "down" },
    ],
  };
  assertEquals(hostOsdIds(tree, "host-a"), [3, 5]);
  // A cyclic tree still terminates.
  const cyclic = {
    nodes: [{ id: -2, name: "host-a", type: "host", children: [-2, 3] }, {
      id: 3,
      name: "osd.3",
      type: "osd",
    }],
  };
  assertEquals(hostOsdIds(cyclic, "host-a"), [3]);
});

Deno.test("osd activate parses ids and the already-created marker", () => {
  assertEquals(parseOsdActivate("Created osd(s) 0,1,2"), {
    activated: [0, 1, 2],
    alreadyPresent: false,
  });
  assertEquals(parseOsdActivate("Created osd(s) 4, 7"), {
    activated: [4, 7],
    alreadyPresent: false,
  });
  assertEquals(
    parseOsdActivate("Created no osd(s) (already created?)"),
    { activated: [], alreadyPresent: true },
  );
  assertThrows(
    () => parseOsdActivate("Created osd(s) a,b"),
    PhaseError,
    "unexpected output",
  );
  assertThrows(
    () => parseOsdActivate("Created no osd(s)"),
    PhaseError,
    "unexpected output",
  );
});

Deno.test("the maintenance poll floor only ever raises the budget", () => {
  assertEquals(floorPollBudget(0), 300_000);
  assertEquals(floorPollBudget(30_000), 300_000);
  // With a logger, a raise is reported.
  const warns: string[] = [];
  assertEquals(
    floorPollBudget(30_000, { info: () => {}, warn: () => warns.push("x") }),
    300_000,
  );
  assertEquals(warns.length, 1);
  assertEquals(floorPollBudget(900_000), 900_000);
});

Deno.test("noout-clear refuses an unknown host, a maintenance host and down OSDs", async () => {
  const hosts = (status: string) =>
    JSON.stringify([{ hostname: "node1", status }]);
  const noout = JSON.stringify({
    checks: {
      OSD_FLAGS: { summary: { message: "host node1 has flags noout" } },
    },
  });
  const tree = JSON.stringify({
    nodes: [
      { id: -2, name: "node1", type: "host", children: [3] },
      { id: 3, name: "osd.3", type: "osd", status: "down" },
    ],
  });
  const s = mSession((body, command) => {
    if (command === "bash -s --") {
      return { code: 0, stdout: hosts("ok"), stderr: "" };
    }
    if (body.includes("orch host ls")) {
      return { code: 0, stdout: hosts("maintenance"), stderr: "" };
    }
    if (body.includes("health detail")) {
      return { code: 0, stdout: noout, stderr: "" };
    }
    if (body.includes("osd tree")) return { code: 0, stdout: tree, stderr: "" };
    return { code: 0, stdout: "[]", stderr: "" };
  });
  await assertRejects(
    () => nooutClear(deps, s, { host: "192.0.2.10", hostName: "node1" }),
    PhaseError,
    "in maintenance",
  );
});

Deno.test(
  "a failed LVM section is not read as a clean host", // leak-allow(decision D13)
  () => {
    const stdout =
      observation({ systemctl: true, lvm: true, vgs: ["ceph-abc"] }) +
      "\n" + "#__cephadm_status_vgs__1";
    const state = parseHostState("h", stdout);
    assertEquals(state.sectionFailures.includes("vgs"), true);
    assertThrows(() => lvmResidue(state), PhaseError, "not observed");
  },
);

Deno.test(
  "maintenance enter reads real OSD counts, not zeros", // leak-allow(decision D45)
  async () => {
    const hosts = JSON.stringify([{
      hostname: "node1",
      status: "maintenance",
    }]);
    const health = JSON.stringify({
      checks: {
        OSD_FLAGS: { summary: { message: "host node1 has flags noout" } },
      },
    });
    const osd = JSON.stringify({ num_up_osds: 0, num_in_osds: 3, num_osds: 3 });
    const s = mSession((body) => {
      if (body.includes("orch host ls")) {
        return { code: 0, stdout: hosts, stderr: "" };
      }
      if (body.includes("health detail")) {
        return { code: 0, stdout: health, stderr: "" };
      }
      if (body.includes("osd stat")) {
        return { code: 0, stdout: osd, stderr: "" };
      }
      return { code: 0, stdout: "[]", stderr: "" };
    });
    const record = await enterMaintenance(deps, s, {
      host: "192.0.2.10",
      hostName: "node1",
      osdCount: 3,
    });
    assertEquals(record.numUpOsds, 0);
    assertEquals(record.numInOsds, 3);
    assertEquals(record.didIssueCommand, false);
    assertEquals(record.hostOsdsDown, true);
  },
);
