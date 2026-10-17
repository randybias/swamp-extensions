import { assertEquals, assertStringIncludes } from "jsr:@std/assert@1.0.19";
import {
  DEADLINE_EXITS,
  type RemoteCall,
  renderRemote,
  renderScript,
  runRemote,
  withSudo,
} from "./remote.ts";
import { SshTarget } from "./ssh.ts";
import { fakeHost } from "./test_support.ts";

const TARGET: SshTarget = {
  host: "192.0.2.10",
  port: 22,
  user: "root",
  host_key_policy: "strict",
  host_keys: [
    "192.0.2.10 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeKeyMaterialForTests",
  ],
  private_key: "fake",
  connect_timeout_s: 15,
};

/** Runs the exact stdin the transport sends, through a local `sh -s`. */
async function runLocally(
  call: RemoteCall,
): Promise<{ code: number; stdout: string }> {
  const { stdin } = renderRemote({ ...call, sudo: false });
  const child = new Deno.Command("sh", {
    args: ["-s"],
    stdin: "piped",
    stdout: "piped",
    stderr: "null",
  }).spawn();
  const w = child.stdin.getWriter();
  await w.write(new TextEncoder().encode(stdin));
  await w.close();
  const out = await child.output();
  return { code: out.code, stdout: new TextDecoder().decode(out.stdout) };
}

Deno.test("withSudo: prefixes only when asked", () => {
  assertEquals(withSudo(true, ["sh", "-s"]), ["sudo", "-n", "sh", "-s"]);
  assertEquals(withSudo(false, ["sh", "-s"]), ["sh", "-s"]);
});

Deno.test("renderRemote: only `sh -s` is on the command line; the script and its deadline are stdin", () => {
  const r = renderRemote({
    sudo: true,
    script: "echo hi\n",
    args: ["a b", "c'd"],
    deadlineS: 40,
  });
  assertEquals(r.argv, ["sudo", "-n", "sh", "-s"]);
  assertEquals(r.stdin.startsWith("set -eu\ntimeout -k 5 40 sh -c "), true);
  assertEquals(r.stdin.endsWith("; exit $?"), true);
  assertEquals(r.timeoutMs, 65_000);
  assertEquals(JSON.stringify(r.argv).includes("echo"), false);
});

Deno.test("renderScript: caller values are quoted positional parameters, data is base64, the prologue is the canonical one", () => {
  const s = renderScript({
    sudo: false,
    script: 'printf %s "$1"\n',
    args: ["x; rm -rf /", "$(id)"],
    data: new TextEncoder().encode("secret-free bytes\n"),
    deadlineS: 5,
    lock: { path: "/var/lib/server-host/revert.lock", waitSec: 7 },
    umask: "077",
  });
  assertStringIncludes(s, "set -eu\numask 077\n");
  assertStringIncludes(s, "set -- 'x; rm -rf /' '$(id)'");
  assertStringIncludes(s, "flock -w 7 9");
  assertStringIncludes(s, "base64 -d");
  assertEquals(s.includes("secret-free bytes"), false);
  assertStringIncludes(s, "trap bw_cleanup EXIT");
});

Deno.test("a rendered call runs under dash: arguments stay literal and data round-trips", async () => {
  const evil = "a; echo pwned $(echo no) `echo no` \"q\" 'r'";
  const { code, stdout } = await runLocally({
    sudo: false,
    script: 'printf \'%s|\' "$1" "$2"; bw_data\n',
    args: [evil, "two words"],
    data: new TextEncoder().encode("line1\nline2\n"),
    deadlineS: 20,
  });
  assertEquals(code, 0);
  assertEquals(stdout, `${evil}|two words|line1\nline2\n`);
});

Deno.test("a call that outlives its deadline ends as 124, not as a killed shell", async () => {
  const { code } = await runLocally({
    sudo: false,
    script: "sleep 30\n",
    deadlineS: 1,
  });
  assertEquals(DEADLINE_EXITS.includes(code), true, String(code));
});

Deno.test("the cleanup trap runs on the deadline", async () => {
  const dir = await Deno.makeTempDir({ prefix: "wgremote-" });
  try {
    const { code } = await runLocally({
      sudo: false,
      script: `touch '${dir}/tmp'\nsleep 30\n`,
      deadlineS: 1,
      cleanup: `rm -f '${dir}/tmp'`,
    });
    assertEquals(DEADLINE_EXITS.includes(code), true);
    assertEquals(
      await Deno.stat(`${dir}/tmp`).then(() => true, () => false),
      false,
    );
  } finally {
    await Deno.remove(dir, { recursive: true });
  }
});

Deno.test("runRemote: sends the stdin script through the transport and returns the host's answer", async () => {
  const host = fakeHost(() => ({ code: 7, stdout: "out" }));
  const res = await runRemote(host.deps, TARGET, {
    sudo: true,
    script: "true\n",
    deadlineS: 10,
  });
  assertEquals([res.exit_code, res.stdout], [7, "out"]);
  const [call] = host.sshCalls();
  assertEquals(call.timeoutMs, 35_000);
  assertEquals(host.scripts()[0].includes("true"), true);
});
