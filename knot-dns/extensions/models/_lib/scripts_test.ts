import { installScript, VENDOR_KEY_FINGERPRINT } from "./install.ts";
import { assert, assertEquals } from "jsr:@std/assert@1.0.19";
import {
  applyResolverScript,
  applyZoneScript,
  discoverZonesScript,
  getDsScript,
  kskSubmittedScript,
  observeScript,
  parseKeyValues,
  portCheckScript,
  removeResolverScript,
  removeZoneScript,
  resolverObserveScript,
  restoreZoneScript,
  zonePaths,
} from "./scripts.ts";
import { shq } from "./fragments.ts";

/** Runs `sh -n` over a script; returns a non-zero code on a syntax error. */
async function shSyntax(script: string): Promise<number> {
  const cmd = new Deno.Command("sh", {
    args: ["-n"],
    stdin: "piped",
    stdout: "null",
    stderr: "piped",
  });
  const child = cmd.spawn();
  const writer = child.stdin.getWriter();
  await writer.write(new TextEncoder().encode(script));
  await writer.close();
  return (await child.output()).code;
}

const APPLY = {
  apex: "example.com.",
  run: "r1",
  listens: ["127.0.0.1@5353"],
};
const REMOVE = {
  apex: "example.com.",
  run: "r1",
  purgeKeysAck: false,
  unsigned: false,
};

const SCRIPTS: [string, string][] = [
  ["install", installScript({ resolver: true })],
  [
    "apply_zone",
    applyZoneScript(APPLY),
  ],
  [
    "remove_zone",
    removeZoneScript(REMOVE),
  ],
  ["get_ds", getDsScript("example.com.")],
  ["discover", discoverZonesScript()],
  ["observe", observeScript(["example.com."])],
  [
    "apply_resolver",
    applyResolverScript({
      liveYaml: "/etc/knot-resolver/config.yaml",
      packageBackup: "/etc/knot-resolver/config.yaml.package",
      stagedYaml: "/etc/knot-resolver/.config.yaml.staged",
      testListen: "127.0.0.1",
      testName: ".",
    }),
  ],
  [
    "remove_resolver",
    removeResolverScript({
      liveYaml: "/etc/knot-resolver/config.yaml",
      packageBackup: "/etc/knot-resolver/config.yaml.package",
    }),
  ],
  ["observe_resolver", resolverObserveScript()],
];

Deno.test("every host script is valid sh syntax", async () => {
  for (const [name, script] of SCRIPTS) {
    assertEquals(await shSyntax(script), 0, name);
  }
});

Deno.test("port check strips an ss scope and reports the owner", () => {
  const s = portCheckScript(["127.0.0.53:53"]);
  // `ss` prints `127.0.0.53%lo:53`; the scope must not defeat the comparison.
  assert(s.includes('sub(/%.*$/, "", addr)'));
  assert(s.includes('owner="?"'));
  assert(s.includes("PORT_BUSY ${waddr}:${wport} ${foreign}"));
  // The authoritative precheck allows knotd; the resolver precheck allows the
  // resolver's own process and never knotd.
  assert(s.includes("own_list='knotd'"));
  assert(s.includes("owner==O[i]"));
  const resolver = portCheckScript(["127.0.0.3:53"], [
    "kresd",
    "knot-resolver",
  ]);
  assert(resolver.includes("own_list='kresd,knot-resolver'"));
  assert(!resolver.includes("own_list='knotd'"));
});

Deno.test("ksk_submitted treats a missing ready key as already done", () => {
  const s = kskSubmittedScript("example.com.");
  assert(s.includes("no key ready for submission"));
  assert(s.includes("submitted=already"));
  assert(s.includes("ZONE_ABSENT"));
});

Deno.test("zone paths and quoting are stable", () => {
  const p = zonePaths("example.com.");
  assertEquals(p.zoneFile, "/var/lib/knot/zones/example.com.zone");
  assertEquals(p.fragment, "/etc/knot/knot.conf.d/50-managed-example.com.conf");
  assertEquals(shq("a'b"), "'a'\\''b'");
});

Deno.test("apply script validates before swapping and rolls back on reload failure", () => {
  const script = applyZoneScript(APPLY);
  assert(script.includes("kzonecheck"));
  assert(script.includes("knotc -c"));
  assert(script.includes("conf-check"));
  assert(script.includes("zone-reload"));
  assert(script.indexOf("kzonecheck") < script.indexOf('mv "$zst" "$z"'));
  assert(script.includes("RELOAD_FAILED"));
  assert(script.includes("flock -x /run/knot-dns.lock"));
});

Deno.test("remove script refuses a signed zone without an ack", () => {
  const script = removeZoneScript(REMOVE);
  assert(script.includes("[ 1 = 1 ]"));
  const acked = removeZoneScript({
    ...REMOVE,
    unsigned: true,
  });
  assert(acked.includes("[ 0 = 1 ]"));
});

Deno.test("remove without purge_keys_ack keeps the journal and KASP keys", () => {
  const script = removeZoneScript(REMOVE);
  assert(!script.includes("zone-purge"));
  assert(!script.includes("keymgr"));
});

Deno.test("remove with purge_keys_ack purges zone data and KASP keys", async () => {
  const acked = removeZoneScript({
    ...REMOVE,
    purgeKeysAck: true,
    unsigned: true,
  });
  // -f is required: without it `knotc zone-purge` refuses and does nothing.
  assert(acked.includes('knotc -f zone-purge "$apex"'));
  assert(acked.includes('keymgr "$apex" delete "$id"'));
  // A failed list must fail the purge, not read as "no keys".
  assert(acked.includes('ids=$(keymgr "$apex" list 2>/dev/null) || return 1'));
  // Key ids are hex; a remote-derived token is grammar-checked before a tool.
  assert(acked.includes('case "$id" in *[!0-9a-fA-F]*) return 1 ;; esac'));
  // delete must not inherit the list pipe as stdin.
  assert(acked.includes("</dev/null"));
  // After the zone is gone, a failed key purge removes the backup and fails.
  assert(
    acked.includes('purge_keys || { rm -rf "${b:?}"; echo PURGE_KEYS_FAILED'),
  );
  // A reload failure after the irreversible purge says so.
  assert(acked.includes("RELOAD_FAILED_KEYS_PURGED"));
  // The zone data purge runs while the zone is still configured (before the
  // fragment is removed), and the key purge retries on a present=no re-run.
  assert(
    acked.indexOf("zone-purge") < acked.indexOf('rm -f "$z" "$f" "$t"'),
  );
  assertEquals(await shSyntax(acked), 0);
});

Deno.test("resolver apply script validates with kresctl before swapping", () => {
  const script = applyResolverScript({
    liveYaml: "/etc/knot-resolver/config.yaml",
    packageBackup: "/etc/knot-resolver/config.yaml.package",
    stagedYaml: "/etc/knot-resolver/.config.yaml.staged",
    testListen: "127.0.0.1",
    testName: ".",
  });
  assert(script.includes("kresctl validate"));
  assert(
    script.indexOf("kresctl validate") < script.indexOf('mv "$st" "$live"'),
  );
  assert(script.includes("TEST_QUERY_FAILED"));
});

Deno.test("apply script never uses the blocking zone-reload", () => {
  // A blocking zone-reload waits on NOTIFY retries to an unreachable
  // secondary; the script polls zone-status instead (see host_test.ts).
  const script = applyZoneScript(APPLY);
  assert(!script.includes("-b zone-reload"));
  assert(script.includes("wait_loaded"));
});

Deno.test("restore script restores every file and reloads", () => {
  const s = restoreZoneScript({ apex: "example.com.", backup: "/tmp/b" });
  assert(s.includes("NO_BACKUP"));
  assert(s.includes("reload_knot"));
  assert(s.includes("flock -x /run/knot-dns.lock"));
});

Deno.test("resolver apply tests the query before discarding the backup", () => {
  const script = applyResolverScript({
    liveYaml: "/etc/knot-resolver/config.yaml",
    packageBackup: "/etc/knot-resolver/config.yaml.package",
    stagedYaml: "/etc/knot-resolver/.config.yaml.staged",
    testListen: "127.0.0.1",
    testName: ".",
  });
  assert(script.includes("kresctl validate"));
  assert(script.includes("TEST_QUERY_FAILED"));
  assert(script.includes('mv "$b" "$live"'));
  assert(script.indexOf("kdig") < script.indexOf("TEST_QUERY_FAILED"));
});

Deno.test("parseKeyValues reads simple output", () => {
  assertEquals(
    parseKeyValues("noise\nchanged=yes\nserial=123\n"),
    { changed: "yes", serial: "123" },
  );
});

Deno.test("install brings every tool the model runs, from the archive, and verifies them", async () => {
  const plain = installScript({ resolver: false });
  // kzonecheck ships in knot-dnssecutils, not in knot or knot-dnsutils.
  assert(plain.includes("knot knot-dnsutils knot-dnssecutils"));
  assert(plain.includes('echo "TOOL_MISSING $t" >&2; exit 127'));
  assert(plain.includes("UNEXPECTED_VERSION knot"));
  assert(
    !plain.includes("pkg.labs.nic.cz"),
    "no vendor repo without a resolver",
  );
  assertEquals(await shSyntax(plain), 0);
  const withResolver = installScript({ resolver: true });
  // The vendor key is checked against a pinned fingerprint before it is trusted.
  assert(withResolver.includes(VENDOR_KEY_FINGERPRINT));
  assert(
    withResolver.indexOf("KEY_MISMATCH") <
      withResolver.indexOf("install -m 0644"),
    "the fingerprint check precedes trusting the key",
  );
  // The repository is pinned below the archive so knot is not upgraded.
  assert(withResolver.includes("Pin-Priority: 100"));
  assert(withResolver.includes("knot-resolver6"));
  assert(!withResolver.includes("|| apt-get install -y -qq knot-resolver"));
  assert(withResolver.includes('echo "kresd_version=$rv"'));
  assertEquals(await shSyntax(withResolver), 0);
});
