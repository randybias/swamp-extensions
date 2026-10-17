/**
 * Tests for the cephadm session layer: TOFU pin learning and persistence.
 *
 * @module
 */

import { assertEquals } from "jsr:@std/assert@1.0.19";
import {
  openSession,
  type SessionContext,
  type Spawner,
  type SshDeps,
  toTarget,
} from "./ssh_session.ts";

const encoder = new TextEncoder();
const BLOB = "AAAAC3NzaC1lZDI1NTE5AAAAIFakeKey";

function fakeSpawner(
  handler: (
    cmd: string,
    command: string,
  ) => { code: number; stdout: string; stderr: string },
): { spawn: Spawner; scans: () => number } {
  let scans = 0;
  const spawn: Spawner = (cmd, args) => {
    const command = args.at(-1) ?? "";
    if (cmd === "ssh-keyscan") scans++;
    return {
      stdin: new WritableStream<Uint8Array>({
        write() {},
        close() {},
      }),
      output: () => {
        const r = handler(cmd, command);
        return Promise.resolve({
          code: r.code,
          stdout: encoder.encode(r.stdout),
          stderr: encoder.encode(r.stderr),
        });
      },
      kill: () => {},
    };
  };
  return { spawn, scans: () => scans };
}

function storeContext(): {
  context: SessionContext;
  written: { specName: string; name: string; data: Record<string, unknown> }[];
} {
  const store = new Map<string, Record<string, unknown>>();
  const written: {
    specName: string;
    name: string;
    data: Record<string, unknown>;
  }[] = [];
  return {
    written,
    context: {
      readResource: (name) => Promise.resolve(store.get(name) ?? null),
      writeResource: (specName, name, data) => {
        written.push({ specName, name, data });
        store.set(name, data);
        return Promise.resolve({});
      },
    },
  };
}

const REQUEST = {
  host: "192.0.2.10",
  sshUser: "admin",
  port: null,
  keyPath: null,
  privateKey: null,
  host_key_policy: "insecure_tofu" as const,
  host_keys: null,
};

Deno.test("openSession learns and persists pins on first insecure_tofu use", async () => {
  const fake = fakeSpawner((cmd, command) =>
    cmd === "ssh-keyscan"
      ? { code: 0, stdout: `${command} ssh-ed25519 ${BLOB}\n`, stderr: "" }
      : { code: 0, stdout: "ok", stderr: "" }
  );
  const deps: SshDeps = {
    spawn: fake.spawn,
    now: () => 0,
    sleep: () => Promise.resolve(),
  };
  const { context, written } = storeContext();
  const session = await openSession(deps, toTarget(REQUEST), context);
  const res = await session.run({ command: "true" });
  assertEquals(res.stdout, "ok");
  assertEquals(fake.scans(), 1);
  assertEquals(written.length, 1);
  assertEquals(written[0].specName, "hostkeys");
  assertEquals(written[0].name, "hostkeys-192.0.2.10-22");
  const pins = written[0].data.host_keys as string[];
  assertEquals(pins[0].startsWith("192.0.2.10 "), true);
  // A recorded pin is re-verified, never re-learned.
  const session2 = await openSession(deps, toTarget(REQUEST), context);
  await session2.run({ command: "true" });
  assertEquals(fake.scans(), 1, "the stored pin is reused");
});

Deno.test("toTarget requires a host-key policy", () => {
  let threw = false;
  try {
    toTarget({ ...REQUEST, host_key_policy: undefined as never });
  } catch {
    threw = true;
  }
  assertEquals(threw, true);
});

Deno.test("openSession refuses a bare pin before any connection", async () => {
  const fake = fakeSpawner(() => ({ code: 0, stdout: "", stderr: "" }));
  const deps: SshDeps = {
    spawn: fake.spawn,
    now: () => 0,
    sleep: () => Promise.resolve(),
  };
  const { context } = storeContext();
  let message = "";
  try {
    await openSession(
      deps,
      toTarget({
        ...REQUEST,
        host_key_policy: "strict",
        host_keys: [`ssh-ed25519 ${BLOB}`],
      }),
      context,
    );
  } catch (e) {
    message = (e as Error).message;
  }
  assertEquals(message.includes("must name its host"), true);
  assertEquals(fake.scans(), 0);
});
