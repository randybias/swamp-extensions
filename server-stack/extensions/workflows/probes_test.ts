/**
 * Runs the workflow's own probe scripts, extracted from the YAML, against a
 * real NATS server in docker (skipped when docker or the image is absent) and
 * against closed and black-holed ports for the mesh wait.
 */

import {
  assert,
  assertEquals,
  assertStringIncludes,
} from "jsr:@std/assert@1.0.19";
import { parse, stringify } from "jsr:@std/yaml@1.0.9";

interface Step {
  name: string;
  task: { inputs?: { run?: string } };
}

const NATS_IMAGE = Deno.env.get("NATS_IMAGE") ?? "nats:2.10-alpine";

async function script(job: string, step: string): Promise<string> {
  const text = await Deno.readTextFile(
    new URL("./server-stack-provision-host/workflow.yaml", import.meta.url),
  );
  const doc = parse(text) as { jobs: { name: string; steps: Step[] }[] };
  const run = doc.jobs.find((j) => j.name === job)?.steps.find((s) =>
    s.name === step
  )?.task.inputs?.run;
  assert(run, `${job}/${step} has a run script`);
  return run;
}

async function bash(
  run: string,
  env: Record<string, string>,
): Promise<{ code: number; out: string }> {
  const r = await new Deno.Command("bash", {
    args: ["-c", run],
    env,
    stdout: "piped",
    stderr: "piped",
  }).output();
  return { code: r.code, out: new TextDecoder().decode(r.stdout) };
}

async function docker(...args: string[]): Promise<number> {
  try {
    return (await new Deno.Command("docker", {
      args,
      stdout: "null",
      stderr: "null",
    }).output()).code;
  } catch {
    return 1;
  }
}

const haveNats = await docker("image", "inspect", NATS_IMAGE) === 0;
const haveHelm = await new Deno.Command("helm", {
  args: ["version", "--short"],
  stdout: "null",
  stderr: "null",
}).output().then((r) => r.code === 0, () => false);

/** Starts a NATS server on a loopback port; returns its stop function. */
async function nats(
  port: number,
  serverArgs: string[],
  dockerArgs: string[] = [],
): Promise<() => Promise<void>> {
  // Unique per start, so a parallel run cannot remove this container.
  const name = `probe-nats-${port}-${crypto.randomUUID().slice(0, 8)}`;
  const code = await docker(
    "run",
    "-d",
    "--rm",
    "--name",
    name,
    "-p",
    `127.0.0.1:${port}:4222`,
    ...dockerArgs,
    NATS_IMAGE,
    ...serverArgs,
  );
  assertEquals(code, 0);
  await new Promise((r) => setTimeout(r, 1500));
  return async () => {
    await docker("rm", "-f", name);
  };
}

const target = (port: number) => ({
  PATH: Deno.env.get("PATH") ?? "",
  NATS_HOST: "127.0.0.1",
  NATS_PORT: String(port),
});

Deno.test({
  name:
    "the unauthenticated probe is unchanged and passes against a plain server",
  ignore: !haveNats,
  fn: async () => {
    const stop = await nats(14223, []);
    try {
      const r = await bash(await script("verify", "probe-nats"), target(14223));
      assertEquals(r.code, 0);
      assertStringIncludes(r.out, "INFO {");
      assertStringIncludes(r.out, "+OK");
    } finally {
      await stop();
    }
  },
});

Deno.test({
  name:
    "the auth probe passes with the right token, even one with quotes and backslashes, and shows anonymous refused",
  ignore: !haveNats,
  fn: async () => {
    const token = 'tok"en\\x';
    const stop = await nats(14224, ["--auth", token]);
    try {
      const run = await script("verify", "probe-nats-auth");
      const ok = await bash(run, { ...target(14224), NATS_TOKEN: token });
      assertStringIncludes(ok.out, '"auth_required":true');
      assertStringIncludes(ok.out, "\n+OK");
      assertStringIncludes(
        ok.out,
        "unauthenticated: -ERR 'Authorization Violation'",
      );
      const bad = await bash(run, { ...target(14224), NATS_TOKEN: "wrong" });
      assertEquals(bad.out.includes("\n+OK"), false);
    } finally {
      await stop();
    }
  },
});

Deno.test("the mesh wait gives up quietly at its bound, and answers at once when the port is open", async () => {
  const run = await script("host", "wait-mesh");
  const base = { PATH: Deno.env.get("PATH") ?? "", WAIT: "4" };
  const started = Date.now();
  for (const host of ["127.0.0.1", "192.0.2.1"]) {
    const r = await bash(run, { ...base, HOST: host, PORT: "14999" });
    assertEquals(r.code, 0);
    assertStringIncludes(r.out, "no answer from");
  }
  assert(Date.now() - started < 20_000, "each wait stays near its bound");
  const listener = Deno.listen({ hostname: "127.0.0.1", port: 14998 });
  try {
    const r = await bash(run, { ...base, HOST: "127.0.0.1", PORT: "14998" });
    assertStringIncludes(r.out, "answered 127.0.0.1:14998");
  } finally {
    listener.close();
  }
});

/** The values block of the README's NATS authentication section. */
async function readmeValues(): Promise<unknown> {
  const readme = await Deno.readTextFile(
    new URL("../../README.md", import.meta.url),
  );
  const section = readme.slice(readme.indexOf("## NATS authentication"));
  const block = section.match(/```yaml\n([\s\S]*?)```/)?.[1];
  assert(block, "README has a values block");
  return (parse(block) as { nats_chart: { values: unknown } }).nats_chart
    .values;
}

const REPO = "https://nats-io.github.io/k8s/helm/charts/";

Deno.test({
  name:
    "the documented token reference renders unquoted and NATS expands it from the environment",
  ignore: !haveNats || !haveHelm,
  fn: async () => {
    const dir = await Deno.makeTempDir();
    try {
      const values = `${dir}/values.yaml`;
      await Deno.writeTextFile(
        values,
        stringify(await readmeValues() as Record<string, unknown>),
      );
      const rendered = await new Deno.Command("helm", {
        args: [
          "template",
          "nats",
          "nats",
          "--repo",
          REPO,
          "--version",
          "2.15.1",
          "-f",
          values,
        ],
        stdout: "piped",
        stderr: "null",
      }).output();
      assertEquals(rendered.code, 0, "helm template renders the chart");
      const stanza = new TextDecoder().decode(rendered.stdout).match(
        /"authorization": \{[^}]*\}/,
      )?.[0];
      assert(stanza, "the chart renders an authorization stanza");
      assertStringIncludes(stanza, '"token": $NATS_TOKEN');
      await Deno.writeTextFile(`${dir}/nats.conf`, `{ ${stanza} }\n`);
      await Deno.chmod(`${dir}/nats.conf`, 0o644);
      const token = crypto.randomUUID();
      const stop = await nats(
        14225,
        ["-c", "/etc/nats/nats.conf"],
        [
          "-v",
          `${dir}/nats.conf:/etc/nats/nats.conf:ro`,
          "-e",
          `NATS_TOKEN=${token}`,
        ],
      );
      try {
        const run = await script("verify", "probe-nats-auth");
        const ok = await bash(run, { ...target(14225), NATS_TOKEN: token });
        assertStringIncludes(ok.out, "\n+OK");
        assertStringIncludes(ok.out, "Authorization Violation");
        const literal = await bash(run, {
          ...target(14225),
          NATS_TOKEN: "$NATS_TOKEN",
        });
        assertEquals(literal.out.includes("\n+OK"), false);
      } finally {
        await stop();
      }
    } finally {
      await Deno.remove(dir, { recursive: true });
    }
  },
});

Deno.test("the token shape check accepts a generated token and rejects anything that could break the manifest", async () => {
  const run = await script("cluster", "check-nats-token");
  const verdict = async (token: string) =>
    (await bash(run, { PATH: Deno.env.get("PATH") ?? "", NATS_TOKEN: token }))
      .code;
  assertEquals(await verdict("0123456789abcdef0123456789abcdef"), 0);
  for (
    const bad of [
      "short",
      'has"quote0123456789',
      "new\nline0123456789abcdef",
      "back\\slash0123456789abc",
      "x".repeat(257),
    ]
  ) {
    assertEquals(await verdict(bad), 1, JSON.stringify(bad));
  }
});
