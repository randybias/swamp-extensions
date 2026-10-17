import { assert, assertEquals } from "jsr:@std/assert@1.0.19";
import {
  applyResolverScript,
  applyZoneScript,
  discoverZonesScript,
  getDsScript,
  installScript,
  observeScript,
  parseKeyValues,
  removeResolverScript,
  removeZoneScript,
  resolverObserveScript,
  shq,
  zonePaths,
} from "./scripts.ts";

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

const SCRIPTS: [string, string][] = [
  ["install", installScript({ resolver: true })],
  ["apply_zone", applyZoneScript({ apex: "example.com.", signed: true })],
  [
    "remove_zone",
    removeZoneScript({
      apex: "example.com.",
      purgeKeysAck: false,
      unsigned: false,
    }),
  ],
  ["get_ds", getDsScript("example.com.")],
  ["discover", discoverZonesScript()],
  ["observe", observeScript(["example.com."])],
  [
    "apply_resolver",
    applyResolverScript({
      liveYaml: "/etc/knot-resolver/config.yaml",
      stagedYaml: "/etc/knot-resolver/.config.yaml.staged",
      testListen: "127.0.0.1",
      testName: ".",
    }),
  ],
  ["remove_resolver", removeResolverScript()],
  ["observe_resolver", resolverObserveScript()],
];

Deno.test("every host script is valid sh syntax", async () => {
  for (const [name, script] of SCRIPTS) {
    assertEquals(await shSyntax(script), 0, name);
  }
});

Deno.test("zone paths and quoting are stable", () => {
  const p = zonePaths("example.com.");
  assertEquals(p.zoneFile, "/var/lib/knot/zones/example.com.zone");
  assertEquals(p.fragment, "/etc/knot/knot.conf.d/50-managed-example.com.conf");
  assertEquals(shq("a'b"), "'a'\\''b'");
});

Deno.test("apply script validates before swapping and rolls back on reload failure", () => {
  const script = applyZoneScript({ apex: "example.com.", signed: false });
  assert(script.includes("kzonecheck"));
  assert(script.includes("knotc -c"));
  assert(script.includes("conf-check"));
  assert(script.includes("zone-reload"));
  assert(script.indexOf("kzonecheck") < script.indexOf('mv "$zst" "$z"'));
  assert(script.includes("RELOAD_FAILED"));
  assert(script.includes("flock -x /run/knot-dns.lock"));
});

Deno.test("remove script refuses a signed zone without an ack", () => {
  const script = removeZoneScript({
    apex: "example.com.",
    purgeKeysAck: false,
    unsigned: false,
  });
  assert(script.includes("[ 1 = 1 ]"));
  const acked = removeZoneScript({
    apex: "example.com.",
    purgeKeysAck: true,
    unsigned: true,
  });
  assert(acked.includes("[ 0 = 1 ]"));
  assert(acked.includes("keymgr"));
});

Deno.test("resolver apply script validates with kresctl before swapping", () => {
  const script = applyResolverScript({
    liveYaml: "/etc/knot-resolver/config.yaml",
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

Deno.test("parseKeyValues reads simple output", () => {
  assertEquals(
    parseKeyValues("noise\nchanged=yes\nserial=123\n"),
    { changed: "yes", serial: "123" },
  );
});
