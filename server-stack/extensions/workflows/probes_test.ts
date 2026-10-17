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
import { parse } from "jsr:@std/yaml@1.0.9";

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

/** Starts a NATS server on a loopback port; returns its stop function. */
async function nats(
  port: number,
  authToken?: string,
): Promise<() => Promise<void>> {
  const name = `probe-nats-${port}`;
  await docker("rm", "-f", name);
  const code = await docker(
    "run",
    "-d",
    "--rm",
    "--name",
    name,
    "-p",
    `127.0.0.1:${port}:4222`,
    NATS_IMAGE,
    ...(authToken ? ["--auth", authToken] : []),
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
    const stop = await nats(14223);
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
    const stop = await nats(14224, token);
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
