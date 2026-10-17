import { assertEquals } from "jsr:@std/assert@1.0.19";
import { renderZoneConfig, renderZoneFile, SoaSchema } from "./zone.ts";
import { renderResolverYaml, ResolverSchema } from "./resolver.ts";

/** True when a tool is on PATH; these tests skip when it is not. */
async function have(tool: string): Promise<boolean> {
  const r = await new Deno.Command("sh", {
    args: ["-c", `command -v ${tool} >/dev/null 2>&1`],
    stdout: "null",
    stderr: "null",
  }).output();
  return r.code === 0;
}

const SOA = SoaSchema.parse({
  primary_ns: "ns1.example.com.",
  contact: "hostmaster.example.com.",
  refresh: 7200,
  retry: 3600,
  expire: 1209600,
  minimum: 3600,
});

const RECORDS = [
  { name: "@", type: "NS", data: "ns1.example.com." },
  { name: "ns1", type: "A", data: "192.0.2.53" },
  { name: "ns1", type: "AAAA", data: "2001:db8::53" },
  { name: "www", type: "A", data: "192.0.2.10" },
  {
    name: "mail",
    type: "MX",
    data: { preference: 10, exchange: "mx.example.com." },
  },
  { name: "@", type: "TXT", data: ["hello world"] },
  {
    name: "_sip._tcp",
    type: "SRV",
    data: { priority: 0, weight: 5, port: 5060, target: "sip.example.com." },
  },
  { name: "sub", type: "NS", data: "ns1.sub.example.com." },
  { name: "ns1.sub", type: "A", data: "192.0.2.54" },
  {
    name: "alias",
    type: "CNAME",
    data: "www.example.com.",
  },
];

async function run(
  cmd: string,
  args: string[],
): Promise<{ code: number; stderr: string }> {
  const out = await new Deno.Command(cmd, {
    args,
    stdout: "null",
    stderr: "piped",
  }).output();
  return { code: out.code, stderr: new TextDecoder().decode(out.stderr) };
}

Deno.test("the rendered zone passes the real kzonecheck when installed", async () => {
  if (!(await have("kzonecheck"))) return;
  const dir = await Deno.makeTempDir();
  const file = `${dir}/example.com.zone`;
  await Deno.writeTextFile(
    file,
    renderZoneFile("example.com.", SOA, RECORDS as never),
  );
  const r = await run("kzonecheck", ["-o", "example.com.", file]);
  assertEquals(r.code, 0, r.stderr);
});

Deno.test("the rendered config passes the real knotc conf-check when installed", async () => {
  if (!(await have("knotc"))) return;
  const dir = await Deno.makeTempDir();
  const fragment = renderZoneConfig({
    apex: "example.com.",
    file: `${dir}/example.com.zone`,
    signed: true,
    dnssec: { algorithm: "ecdsap256sha256", nsec3: false },
    notifySecondaries: ["192.0.2.2@53"],
    allowTransfer: ["192.0.2.3"],
    tsigKeyNames: ["xfer"],
  });
  const conf =
    `server:\n  listen: ["192.0.2.53@53"]\nkey:\n  - id: xfer\n    algorithm: hmac-sha256\n    secret: "${
      ["cGxh", "Y2Vob2xkZXI="].join("")
    }"\n` + fragment;
  const path = `${dir}/knot.conf`;
  await Deno.writeTextFile(path, conf);
  const r = await run("knotc", ["-c", path, "conf-check"]);
  assertEquals(r.code, 0, r.stderr);
});

Deno.test("the rendered resolver yaml passes the real kresctl validate when installed", async () => {
  if (!(await have("kresctl"))) return;
  const dir = await Deno.makeTempDir();
  const path = `${dir}/config.yaml`;
  await Deno.writeTextFile(
    path,
    renderResolverYaml(ResolverSchema.parse({
      listen: ["127.0.0.1@53"],
      cache_size_mb: 256,
      forwards: [{
        subtree: "internal.example.",
        servers: ["192.0.2.53"],
      }],
    })),
  );
  const r = await run("kresctl", ["validate", path]);
  assertEquals(r.code, 0, r.stderr);
});
