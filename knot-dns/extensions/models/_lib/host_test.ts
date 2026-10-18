/**
 * Runs the real host scripts, under dash `sh -eu`, against real knotd, kdig,
 * ss and Knot Resolver inside a throwaway container. Skipped when docker or
 * the image is absent. Build the image from the Knot 3.6.1 + Resolver 6.5 base
 * with `iproute2 psmisc procps` added (ss, pkill) and name it with
 * KNOT_BOX_IMAGE (default knot-check:b3).
 */

import {
  assert,
  assertEquals,
  assertStringIncludes,
} from "jsr:@std/assert@1.0.19";
import {
  applyResolverScript,
  applyZoneScript,
  observeScript,
  portCheckScript,
  removeZoneScript,
  restoreZoneScript,
  stagedListen,
  zonePaths,
} from "./scripts.ts";
import { renderResolverYaml, ResolverSchema } from "./resolver.ts";
import { listenFragment } from "./listen.ts";
import {
  renderZoneConfig,
  renderZoneFile,
  SoaSchema,
  type ZoneRecord,
} from "./zone.ts";

const IMAGE = Deno.env.get("KNOT_BOX_IMAGE") ?? "knot-check:b3";

async function boxAvailable(): Promise<boolean> {
  try {
    const r = await new Deno.Command("docker", {
      args: ["image", "inspect", IMAGE],
      stdout: "null",
      stderr: "null",
    }).output();
    return r.code === 0;
  } catch {
    return false;
  }
}

const available = await boxAvailable();

/** True when the image ships Knot Resolver (the distro image does not). */
async function hasResolver(): Promise<boolean> {
  if (!available) return false;
  const r = await new Deno.Command("docker", {
    args: ["run", "--rm", IMAGE, "sh", "-c", "command -v knot-resolver"],
    stdout: "null",
    stderr: "null",
  }).output();
  return r.code === 0;
}

const resolverAvailable = await hasResolver();

/**
 * Container prelude: zone directories, the stock Knot config plus the managed
 * include, and a systemctl stand-in that restarts knotd and the resolver the
 * way the units would (the image has no init system).
 */
const PRELUDE = String.raw`
mkdir -p /run/knot /var/lib/knot/zones /etc/knot/knot.conf.d /run/knot-resolver /var/cache/knot-resolver /etc/knot-resolver
chown knot:knot /run/knot /var/lib/knot /var/lib/knot/zones
chown knot-resolver:knot-resolver /run/knot-resolver /var/cache/knot-resolver 2>/dev/null || true
echo 'include: /etc/knot/knot.conf.d/*.conf' >> /etc/knot/knot.conf
cat > /usr/local/bin/systemctl <<'SC'
#!/bin/bash
# Daemons must not inherit the caller's flock descriptor (systemd would not
# pass it on), or the lock would stay held after the script exits.
for fd in 3 4 5 6 7 8 9; do eval "exec $fd>&-"; done
cmd=$1; shift
unit=
for a in "$@"; do case "$a" in --*) ;; *) unit=$a ;; esac; done
case "$cmd:$unit" in
  restart:knot|start:knot)
    pkill -x knotd 2>/dev/null; while pgrep -x knotd >/dev/null; do sleep 0.1; done
    knotd -d; sleep 1 ;;
  reload:knot-resolver|restart:knot-resolver|start:knot-resolver)
    pkill -f /usr/bin/knot-resolver 2>/dev/null; pkill kresd 2>/dev/null; sleep 1
    (knot-resolver -c /etc/knot-resolver/config.yaml >/tmp/kr.log 2>&1 &) ;;
  *) exit 0 ;;
esac
SC
chmod +x /usr/local/bin/systemctl
`;

interface StepResult {
  rc: number;
  out: string;
  err: string;
}

/** Shell that writes `content` to `path` through a quoted heredoc. */
function put(path: string, content: string): string {
  return `cat > '${path}' <<'KNOT_EOF'\n${content}\nKNOT_EOF`;
}

/**
 * Runs `setup` then each named step script with `sh -eu` in one fresh
 * container, returning every step's exit code and output.
 */
async function box(
  setup: string,
  steps: [string, string][],
): Promise<Record<string, StepResult>> {
  const body = [PRELUDE, setup];
  for (const [name, script] of steps) {
    body.push(
      put(`/tmp/step_${name}.sh`, script),
      `if sh -eu /tmp/step_${name}.sh >/tmp/${name}.out 2>/tmp/${name}.err; then rc=0; else rc=$?; fi`,
      `echo "@@STEP ${name} $rc"; sed 's/^/O:/' /tmp/${name}.out; sed 's/^/E:/' /tmp/${name}.err`,
    );
  }
  const run = await new Deno.Command("docker", {
    args: [
      "run",
      "--rm",
      "-i",
      "--cap-add",
      "SYS_PTRACE",
      IMAGE,
      "bash",
      "-c",
      body.join("\n"),
    ],
    stdout: "piped",
    stderr: "piped",
  }).output();
  const text = new TextDecoder().decode(run.stdout);
  const results: Record<string, StepResult> = {};
  let current: StepResult | undefined;
  for (const line of text.split("\n")) {
    const m = line.match(/^@@STEP (\S+) (\d+)$/);
    if (m) {
      current = { rc: Number(m[2]), out: "", err: "" };
      results[m[1]] = current;
    } else if (current && line.startsWith("O:")) {
      current.out += `${line.slice(2)}\n`;
    } else if (current && line.startsWith("E:")) {
      current.err += `${line.slice(2)}\n`;
    }
  }
  return results;
}

const APEX = "example.com.";
const SOA = SoaSchema.parse({
  primary_ns: "ns1.example.com.",
  contact: "hostmaster.example.com.",
  refresh: 7200,
  retry: 3600,
  expire: 1209600,
  minimum: 3600,
});

/** One zone fixture; `rev` changes the content so a new apply has work to do. */
function zoneFixture(rev: number, notify: string[]) {
  const records: ZoneRecord[] = [
    { name: "@", type: "NS", data: "ns1.example.com." },
    { name: "ns1", type: "A", data: "192.0.2.53" },
    { name: "rev", type: "TXT", data: [`r${rev}`] },
  ];
  return {
    file: renderZoneFile(APEX, SOA, records).trimEnd(),
    fragment: renderZoneConfig({
      apex: APEX,
      file: zonePaths(APEX).zoneFile,
      signed: false,
      dnssec: { algorithm: "ecdsap256sha256", nsec3: false },
      notifySecondaries: notify,
      allowTransfer: [],
      tsigKeyNames: [],
    }).trimEnd(),
  };
}

/** Writes the staged files for one apply of the example zone. */
function stage(
  run: string,
  listens: string[],
  opts: { rev?: number; notify?: string[] } = {},
): string {
  const p = zonePaths(APEX, run);
  const { file, fragment } = zoneFixture(opts.rev ?? 1, opts.notify ?? []);
  return [
    put(stagedListen(run), listenFragment(listens).trimEnd()),
    put(p.stagedZone, file),
    put(p.stagedFragment, fragment),
    `: > '${p.stagedTsig}'`,
  ].join("\n");
}

const kdig = (port: number) =>
  `kdig +retry=0 +time=2 -p ${port} @127.0.0.1 ${APEX} SOA | grep -c 'status: NOERROR' || true`;

Deno.test({
  name: "portCheck: knotd's own socket passes, a foreign one is PORT_BUSY",
  ignore: !available,
  fn: async () => {
    const r = await box(
      [
        put(
          "/etc/knot/knot.conf.d/40-managed-listen.conf",
          listenFragment(["127.0.0.1@5353"]).trimEnd(),
        ),
        "knotd -d; sleep 1",
        `perl -MIO::Socket::INET -e '$s=IO::Socket::INET->new(Listen=>1,LocalAddr=>"127.0.0.1",LocalPort=>5454) or die; sleep 60' &`,
        "sleep 1",
      ].join("\n"),
      [
        ["own", portCheckScript(["127.0.0.1@5353"])],
        ["foreign", portCheckScript(["127.0.0.1@5454"])],
        ["free", portCheckScript(["127.0.0.1@5555"])],
      ],
    );
    assertEquals(r.own.rc, 0, r.own.err);
    assertEquals(r.foreign.rc, 9);
    assertStringIncludes(r.foreign.err, "PORT_BUSY 127.0.0.1:5454");
    assertEquals(r.free.rc, 0, r.free.err);
  },
});

Deno.test({
  name:
    "apply: a listen change restarts knotd and is answered; no-op and shrink",
  ignore: !available,
  fn: async () => {
    const l1 = ["127.0.0.1@5353"];
    const l2 = ["127.0.0.1@5454"];
    const r = await box("", [
      ["stage1", stage("a1", l1)],
      ["apply1", applyZoneScript({ apex: APEX, run: "a1", listens: l1 })],
      ["q1", kdig(5353)],
      ["stage2", stage("a2", l1)],
      ["apply2", applyZoneScript({ apex: APEX, run: "a2", listens: l1 })],
      [
        "leftovers",
        "ls -A /var/lib/knot/zones /etc/knot/knot.conf.d | grep '[.]staged' || true",
      ],
      ["stage3", stage("a3", l2, { rev: 2 })],
      ["apply3", applyZoneScript({ apex: APEX, run: "a3", listens: l2 })],
      ["q3new", kdig(5454)],
      ["q3old", kdig(5353)],
    ]);
    assertEquals(r.apply1.rc, 0, r.apply1.err);
    assertStringIncludes(r.apply1.out, "changed=yes");
    assertEquals(r.q1.out.trim(), "1");
    assertEquals(r.apply2.rc, 0, r.apply2.err);
    assertStringIncludes(r.apply2.out, "changed=no");
    assertEquals(r.leftovers.out.trim(), "", "unconsumed staged files remain");
    assertEquals(r.apply3.rc, 0, r.apply3.err);
    assertEquals(r.q3new.out.trim(), "1");
    assertEquals(r.q3old.out.trim(), "0", "the old listener must be gone");
  },
});

Deno.test({
  name: "apply: an unreachable NOTIFY secondary does not fail the reload",
  ignore: !available,
  fn: async () => {
    const l = ["127.0.0.1@5353"];
    const notify = ["192.0.2.99@53"];
    const r = await box("", [
      ["s1", stage("n1", l, { notify })],
      ["a1", applyZoneScript({ apex: APEX, run: "n1", listens: l })],
      ["s2", stage("n2", l, { notify, rev: 2 })],
      ["a2", applyZoneScript({ apex: APEX, run: "n2", listens: l })],
      ["txt", `kdig +retry=0 -p 5353 @127.0.0.1 rev.example.com. TXT +short`],
    ]);
    assertEquals(r.a1.rc, 0, r.a1.err);
    assertEquals(r.a2.rc, 0, r.a2.err);
    assertStringIncludes(r.txt.out, "r2");
  },
});

Deno.test({
  name: "apply: an ownership failure restores the previous files",
  ignore: !available,
  fn: async () => {
    const l = ["127.0.0.1@5353"];
    const failing = "#!/bin/sh\nexit 1";
    const r = await box(
      [
        put("/usr/local/bin/chown", failing),
        put("/usr/local/bin/chgrp", failing),
        "chmod +x /usr/local/bin/chown /usr/local/bin/chgrp",
      ].join("\n"),
      [
        ["s", stage("c1", l)],
        ["a", applyZoneScript({ apex: APEX, run: "c1", listens: l })],
        [
          "left",
          `ls /var/lib/knot/zones /etc/knot/knot.conf.d | tr '\\n' ' '`,
        ],
      ],
    );
    assertEquals(r.a.rc, 10);
    assertStringIncludes(r.a.err, "CHOWN_FAILED");
    assert(!r.left.out.includes("example.com.zone "), r.left.out);
    assert(!r.left.out.includes("40-managed-listen.conf"), r.left.out);
  },
});

Deno.test({
  name: "apply: a failing rollback reload keeps the backup and says so",
  ignore: !available,
  fn: async () => {
    const l1 = ["127.0.0.1@5353"];
    const l2 = ["127.0.0.1@5454"];
    // From the second apply on, every restart fails, so the first failure
    // and the rollback both fail.
    const brokenRestart =
      '#!/bin/sh\n[ -e /tmp/broken ] && exit 1\nexec /usr/bin/systemctl.real "$@"';
    const r = await box("", [
      ["s1", stage("r1", l1)],
      ["a1", applyZoneScript({ apex: APEX, run: "r1", listens: l1 })],
      [
        "break",
        [
          "mv /usr/local/bin/systemctl /usr/bin/systemctl.real",
          put("/usr/local/bin/systemctl", brokenRestart),
          "chmod +x /usr/local/bin/systemctl /usr/bin/systemctl.real; touch /tmp/broken",
        ].join("\n"),
      ],
      ["s2", stage("r2", l2, { rev: 2 })],
      ["a2", applyZoneScript({ apex: APEX, run: "r2", listens: l2 })],
    ]);
    assertEquals(r.a1.rc, 0, r.a1.err);
    assertEquals(r.a2.rc, 13);
    assertStringIncludes(r.a2.err, "RESTORE_RELOAD_FAILED backup=");
  },
});

Deno.test({
  name: "remove: the shared listen fragment shrinks and knotd rebinds",
  ignore: !available,
  fn: async () => {
    const l = ["127.0.0.1@5353"];
    const r = await box("", [
      ["s1", stage("m1", l)],
      ["a1", applyZoneScript({ apex: APEX, run: "m1", listens: l })],
      ["sr", put(stagedListen("m2"), "")],
      [
        "rm",
        removeZoneScript({
          apex: APEX,
          run: "m2",
          purgeKeysAck: false,
          unsigned: true,
        }),
      ],
      ["bound", `ss -lntuH | grep -c ':5353 ' || true`],
    ]);
    assertEquals(r.rm.rc, 0, r.rm.err);
    assertStringIncludes(r.rm.out, "removed=yes");
    assertEquals(r.bound.out.trim(), "0");
  },
});

Deno.test({
  name: "remove: purge_keys_ack removes the zone's KASP keys",
  ignore: !available,
  fn: async () => {
    const l = ["127.0.0.1@5353"];
    const run = "p1";
    const p = zonePaths(APEX, run);
    const { file } = zoneFixture(1, []);
    const signed = renderZoneConfig({
      apex: APEX,
      file: zonePaths(APEX).zoneFile,
      signed: true,
      dnssec: { algorithm: "ecdsap256sha256", nsec3: false },
      notifySecondaries: [],
      allowTransfer: [],
      tsigKeyNames: [],
    }).trimEnd();
    const stageSigned = [
      put(stagedListen(run), listenFragment(l).trimEnd()),
      put(p.stagedZone, file),
      put(p.stagedFragment, signed),
      `: > '${p.stagedTsig}'`,
    ].join("\n");
    const r = await box("", [
      ["stage", stageSigned],
      ["apply", applyZoneScript({ apex: APEX, run, listens: l })],
      [
        "keys_before",
        'for i in 1 2 3 4 5 6 7 8 9 10; do n=$(keymgr example.com. list 2>/dev/null | wc -l); [ "$n" -ge 2 ] && break; sleep 1; done; echo "$n"',
      ],
      ["stage_remove", put(stagedListen("p2"), "")],
      [
        "remove",
        removeZoneScript({
          apex: APEX,
          run: "p2",
          purgeKeysAck: true,
          unsigned: true,
        }),
      ],
      ["keys_after", "keymgr example.com. list 2>/dev/null | wc -l"],
      ["zones_left", "keymgr -l 2>/dev/null | grep -c '^example.com' || true"],
    ]);
    assertEquals(r.apply.rc, 0, r.apply.err);
    assert(Number(r.keys_before.out.trim()) >= 2, r.keys_before.out);
    assertEquals(r.remove.rc, 0, r.remove.err);
    assertStringIncludes(r.remove.out, "removed=yes");
    assertEquals(r.keys_after.out.trim(), "0");
    assertEquals(r.zones_left.out.trim(), "0");
  },
});

Deno.test({
  name: "restore: undoing a listen change restarts knotd on the old address",
  ignore: !available,
  fn: async () => {
    const l1 = ["127.0.0.1@5353"];
    const l2 = ["127.0.0.1@5454"];
    // The apply's backup directory is random; pin it under a known name.
    const pinned = "mkdir -p /tmp/bk; export TMPDIR=/tmp/bk\n";
    const r = await box("", [
      ["s1", stage("u1", l1)],
      ["a1", applyZoneScript({ apex: APEX, run: "u1", listens: l1 })],
      ["s2", stage("u2", l2, { rev: 2 })],
      ["a2", pinned + applyZoneScript({ apex: APEX, run: "u2", listens: l2 })],
      ["pin", "mv /tmp/bk/tmp.* /tmp/bk/b2"],
      ["restore", restoreZoneScript({ apex: APEX, backup: "/tmp/bk/b2" })],
      ["old", kdig(5353)],
      ["new", kdig(5454)],
    ]);
    assertEquals(r.restore.rc, 0, r.restore.err);
    assertEquals(r.old.out.trim(), "1");
    assertEquals(r.new.out.trim(), "0");
  },
});

Deno.test({
  name: "observe: a down knotd is PROBE_FAILED, not an empty serial",
  ignore: !available,
  fn: async () => {
    const l = ["127.0.0.1@5353"];
    const r = await box("", [
      ["s", stage("o1", l)],
      ["a", applyZoneScript({ apex: APEX, run: "o1", listens: l })],
      ["up", observeScript([APEX])],
      ["stop", "pkill -x knotd; sleep 1"],
      ["down", observeScript([APEX])],
    ]);
    assertEquals(r.up.rc, 0, r.up.err);
    assertStringIncludes(r.up.out, "KEY_BEGIN");
    assertEquals(r.down.rc, 11);
    assertStringIncludes(r.down.err, "PROBE_FAILED");
  },
});

/** Staging for a resolver forwarding example.com. to a local knotd. */
function resolverBox(dnssec: boolean): { setup: string; yaml: string } {
  const yaml = renderResolverYaml(ResolverSchema.parse({
    listen: ["127.0.0.1@5454"],
    forwards: [{
      subtree: APEX,
      servers: ["127.0.0.2"],
      dnssec,
    }],
  }));
  const p = zonePaths(APEX);
  const fixture = zoneFixture(1, []);
  const setup = [
    put(
      "/etc/knot/knot.conf.d/40-managed-listen.conf",
      listenFragment(["127.0.0.2@53"]).trimEnd(),
    ),
    put(p.zoneFile, fixture.file),
    put(p.fragment, fixture.fragment),
    "chown -R knot:knot /var/lib/knot/zones; knotd -d; sleep 1",
    put("/etc/knot-resolver/.config.yaml.staged", yaml.trimEnd()),
  ].join("\n");
  return { setup, yaml };
}

const resolverApply = applyResolverScript({
  liveYaml: "/etc/knot-resolver/config.yaml",
  packageBackup: "/etc/knot-resolver/config.yaml.package",
  stagedYaml: "/etc/knot-resolver/.config.yaml.staged",
  testListen: "127.0.0.1@5454",
  testName: APEX,
});

Deno.test({
  name: "resolver: a non-validating forward to a private zone answers",
  ignore: !resolverAvailable,
  fn: async () => {
    const { setup } = resolverBox(false);
    const r = await box(setup, [["apply", resolverApply]]);
    assertEquals(r.apply.rc, 0, r.apply.err);
    assertStringIncludes(r.apply.out, "changed=yes");
  },
});

Deno.test({
  name: "resolver: a SERVFAIL reply fails the apply and restores the config",
  ignore: !resolverAvailable,
  fn: async () => {
    // dnssec: true against an unsigned private zone cannot validate.
    const { setup } = resolverBox(true);
    const r = await box(setup, [["apply", resolverApply]]);
    assertEquals(r.apply.rc, 7);
    assertStringIncludes(r.apply.err, "TEST_QUERY_FAILED");
  },
});
