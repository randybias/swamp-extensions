import { assertEquals, assertRejects } from "jsr:@std/assert@1.0.19";
import { AutoinstallError } from "./errors.ts";
import { compareRemoteFile } from "./publish.ts";
import type { CommandRunner, SshDeps } from "./ssh.ts";

const TARGET = {
  host: "192.0.2.10",
  port: 22,
  user: "root",
  host_key_policy: "strict" as const,
  host_keys: ["192.0.2.10 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeHostKey000"],
};

function deps(
  answer: (
    remote: string,
  ) => { code: number; stdout?: string; stderr?: string },
): SshDeps {
  const run: CommandRunner = (cmd, args) => {
    if (cmd !== "ssh") {
      return Promise.resolve({ code: 0, stdout: "", stderr: "" });
    }
    const r = answer(args[args.length - 1]);
    return Promise.resolve({
      code: r.code,
      stdout: r.stdout ?? "",
      stderr: r.stderr ?? "",
    });
  };
  return { run, now: () => 0, sleep: () => Promise.resolve() };
}

Deno.test("an absent file reads as absent, not a transport failure", async () => {
  const d = deps(() => ({
    code: 1,
    stderr: "stat: cannot statx '/x': No such file or directory",
  }));
  assertEquals(await compareRemoteFile(d, TARGET, "/x", "y"), "absent");
});

Deno.test("an unreadable parent is a transport failure, not absence", async () => {
  const d = deps(() => ({
    code: 1,
    stderr: "stat: cannot statx '/x/y': Permission denied",
  }));
  const e = await assertRejects(
    () => compareRemoteFile(d, TARGET, "/x/y", "z"),
    AutoinstallError,
  );
  assertEquals((e as AutoinstallError).code, "transport");
});

Deno.test("a present but wrong file is 'wrong', not absent", async () => {
  const d = deps((remote) =>
    remote.startsWith("'stat'")
      ? { code: 0, stdout: "regular file\n" }
      : { code: 0, stdout: `${"a".repeat(64)}  /x\n` }
  );
  assertEquals(await compareRemoteFile(d, TARGET, "/x", "different"), "wrong");
});
