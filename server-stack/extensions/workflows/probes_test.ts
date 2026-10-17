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

/** Runs docker and returns its trimmed stdout (empty on any failure). */
async function dockerOut(...args: string[]): Promise<string> {
  try {
    const r = await new Deno.Command("docker", {
      args,
      stdout: "piped",
      stderr: "piped",
    }).output();
    const text = new TextDecoder();
    // `docker logs` replays the container's stderr on its own stderr.
    return r.code === 0
      ? `${text.decode(r.stdout)}${
        args[0] === "logs" ? text.decode(r.stderr) : ""
      }`.trim()
      : "";
  } catch {
    return "";
  }
}

/** True once the server on `port` has sent its INFO line (within 2 s). */
async function answersInfo(port: number): Promise<boolean> {
  let conn: Deno.Conn | undefined;
  try {
    conn = await Deno.connect({ hostname: "127.0.0.1", port });
    // A peer that accepts and never writes (docker's proxy before the server
    // is up) would block read() forever; closing the connection ends it.
    const timer = setTimeout(() => conn?.close(), 2000);
    try {
      const buf = new Uint8Array(16);
      const n = await conn.read(buf);
      return n !== null &&
        new TextDecoder().decode(buf.subarray(0, n)).startsWith("INFO");
    } finally {
      clearTimeout(timer);
    }
  } catch {
    return false; // refused, reset, or closed by the timer
  } finally {
    try {
      conn?.close();
    } catch { /* already closed */ }
  }
}

/**
 * Starts a NATS server and returns its port and stop function. Docker picks
 * the host port (a fixed one collides with a parallel run), and the server is
 * waited for until it sends INFO (the published port accepts connections
 * before the server inside is listening, so a fixed sleep is a race).
 */
async function nats(
  serverArgs: string[],
  dockerArgs: string[] = [],
): Promise<{ port: number; stop: () => Promise<void> }> {
  const name = `probe-nats-${crypto.randomUUID().slice(0, 8)}`;
  const code = await docker(
    "run",
    "-d",
    "--name",
    name,
    "-p",
    // host port left empty: docker picks a free one
    "127.0.0.1::4222", // leak-allow(docker -p host-ip::container-port, empty host port)
    ...dockerArgs,
    NATS_IMAGE,
    ...serverArgs,
  );
  assertEquals(code, 0);
  const stop = async () => {
    await docker("rm", "-f", name);
  };
  try {
    // The mapping can lag `docker run -d` under load, so it is polled too.
    let port = 0;
    for (let i = 0; i < 100 && !port; i++) {
      const mapped = await dockerOut("port", name, "4222/tcp");
      port = Number(mapped.split("\n")[0].split(":").pop()) || 0;
      if (!port) await new Promise((r) => setTimeout(r, 100));
    }
    assert(
      port > 0,
      `docker published a port for ${name}: ${await dockerOut(
        "inspect",
        "-f",
        "{{.State.Status}} exit={{.State.ExitCode}} {{.State.Error}}",
        name,
      )} / ${await dockerOut("logs", name)}`,
    );
    for (let i = 0; i < 100 && !await answersInfo(port); i++) {
      await new Promise((r) => setTimeout(r, 100));
    }
    assert(await answersInfo(port), "NATS answers INFO within 10 s");
    return { port, stop };
  } catch (err) {
    await stop();
    throw err;
  }
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
    const { port, stop } = await nats([]);
    try {
      const r = await bash(await script("verify", "probe-nats"), target(port));
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
    const { port, stop } = await nats(["--auth", token]);
    try {
      const run = await script("verify", "probe-nats-auth");
      const ok = await bash(run, { ...target(port), NATS_TOKEN: token });
      assertStringIncludes(ok.out, '"auth_required":true');
      assertStringIncludes(ok.out, "\n+OK");
      assertStringIncludes(
        ok.out,
        "unauthenticated: -ERR 'Authorization Violation'",
      );
      const bad = await bash(run, { ...target(port), NATS_TOKEN: "wrong" });
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
  // A port nothing listens on: bind an ephemeral one and release it.
  const probe = Deno.listen({ hostname: "127.0.0.1", port: 0 });
  const closed = (probe.addr as Deno.NetAddr).port;
  probe.close();
  for (const host of ["127.0.0.1", "192.0.2.1"]) {
    const r = await bash(run, { ...base, HOST: host, PORT: String(closed) });
    assertEquals(r.code, 0);
    assertStringIncludes(r.out, "no answer from");
  }
  assert(Date.now() - started < 20_000, "each wait stays near its bound");
  const listener = Deno.listen({ hostname: "127.0.0.1", port: 0 });
  const open = (listener.addr as Deno.NetAddr).port;
  try {
    const r = await bash(run, {
      ...base,
      HOST: "127.0.0.1",
      PORT: String(open),
    });
    assertStringIncludes(r.out, `answered 127.0.0.1:${open}`);
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
          "https://nats-io.github.io/k8s/helm/charts/",
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
      const token = `k${crypto.randomUUID()}`;
      const { port, stop } = await nats(
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
        const ok = await bash(run, { ...target(port), NATS_TOKEN: token });
        assertStringIncludes(ok.out, "\n+OK");
        assertStringIncludes(ok.out, "Authorization Violation");
        const literal = await bash(run, {
          ...target(port),
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
  assertEquals(await verdict("k0123456789abcdef0123456789abcdef"), 0);
  for (
    const bad of [
      // NATS reads these as numbers or dates and fails to start.
      "0123456789abcdef0123456789abcdef",
      "6e50123456789abcdef",
      "2026-10-17T00:00:00Z-abc",
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
