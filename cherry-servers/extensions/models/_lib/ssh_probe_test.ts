import {
  assertEquals,
  assertRejects,
  assertThrows,
} from "jsr:@std/assert@1.0.19";
import {
  assertHost,
  assertMarkerPath,
  assertUser,
  checkHostKeys,
  checkMarker,
  type CommandRunner,
  fingerprints,
  keysForHost,
  parseBanner,
  parseHostKeys,
  ProbeConfigError,
  scanHostKeys,
} from "./ssh_probe.ts";

const KEY = { type: "ssh-ed25519", key: "AAAAC3NzaC1lZDI1NTE5AAAAIFakeKeyOne" };
const OTHER = {
  type: "ssh-ed25519",
  key: "AAAAC3NzaC1lZDI1NTE5AAAAIFakeKeyTwo",
};

Deno.test("parseBanner accepts an SSH banner and rejects anything else", () => {
  assertEquals(
    parseBanner("SSH-2.0-OpenSSH_9.6p1 Ubuntu\r\n"),
    "SSH-2.0-OpenSSH_9.6p1 Ubuntu",
  );
  assertEquals(parseBanner("HTTP/1.1 400 Bad Request"), null);
  assertEquals(parseBanner(""), null);
});

Deno.test("parseHostKeys reads keyscan and bare key lines, skipping comments", () => {
  const keys = parseHostKeys(
    `# 192.0.2.10:22 SSH-2.0-OpenSSH\n192.0.2.10 ${KEY.type} ${KEY.key}\n${OTHER.type} ${OTHER.key}\n`,
  );
  assertEquals(keys, [{ host: "192.0.2.10", ...KEY }, OTHER]);
});

Deno.test("checkHostKeys strict passes on match and fails on mismatch", () => {
  checkHostKeys([KEY], "strict", [KEY, OTHER]);
  assertThrows(
    () => checkHostKeys([OTHER], "strict", [KEY]),
    Error,
    "mismatch",
  );
  assertThrows(() => checkHostKeys([KEY], "strict", []), Error, "known_hosts");
  assertThrows(() => checkHostKeys([], "strict", [KEY]), Error, "no host keys");
});

Deno.test("checkHostKeys accept-new and insecure never throw", () => {
  checkHostKeys([OTHER], "accept-new", [KEY]);
  checkHostKeys([], "insecure");
});

Deno.test("input grammars reject injection attempts", () => {
  for (const bad of ["a;b", "$(id)", "host name", "a`b`", "-oProxyCommand=x"]) {
    assertThrows(() => assertHost(bad));
  }
  for (const bad of ["root;id", "Root", "-l", "a b"]) {
    assertThrows(() => assertUser(bad));
  }
  for (
    const bad of [
      "relative/path",
      "/tmp/x'; rm -rf /",
      "/a/../etc/passwd",
      "/a b",
      "/$(id)",
    ]
  ) {
    assertThrows(() => assertMarkerPath(bad));
  }
  assertHost("192.0.2.10");
  assertHost("server-1.example.com");
  assertHost("2001:db8::1");
  assertUser("root");
  assertMarkerPath("/var/lib/cloud/instance/boot-finished");
});

Deno.test("scanHostKeys passes the port and host as separate arguments", async () => {
  let seen: string[] = [];
  const run: CommandRunner = (_cmd, args) => {
    seen = args;
    return Promise.resolve({
      code: 0,
      stdout: `192.0.2.10 ${KEY.type} ${KEY.key}\n`,
      stderr: "",
    });
  };
  assertEquals(await scanHostKeys(run, "192.0.2.10", 2222), [
    { host: "192.0.2.10", ...KEY },
  ]);
  assertEquals(seen, ["-T", "5", "-p", "2222", "192.0.2.10"]);
});

Deno.test("fingerprints parses ssh-keygen output", async () => {
  const run: CommandRunner = () =>
    Promise.resolve({
      code: 0,
      stdout: "256 SHA256:abcDEF123 no comment (ED25519)\n",
      stderr: "",
    });
  assertEquals(await fingerprints(run, [KEY]), [
    { type: KEY.type, sha256: "SHA256:abcDEF123" },
  ]);
});

/** Scripted runner for the marker check. */
function markerRunner(sshCode: number) {
  const calls: { cmd: string; args: string[]; stdin?: string }[] = [];
  const run: CommandRunner = (cmd, args, options) => {
    calls.push({ cmd, args, stdin: options?.stdin });
    if (cmd === "ssh-agent" && args[0] === "-s") {
      return Promise.resolve({
        code: 0,
        stdout:
          "SSH_AUTH_SOCK=/tmp/agent.test; export SSH_AUTH_SOCK;\nSSH_AGENT_PID=4242; export SSH_AGENT_PID;\n",
        stderr: "",
      });
    }
    if (cmd === "ssh") {
      return Promise.resolve({ code: sshCode, stdout: "", stderr: "" });
    }
    return Promise.resolve({ code: 0, stdout: "", stderr: "" });
  };
  return { run, calls };
}

const MARKER_OPTS = {
  host: "192.0.2.10",
  port: 22,
  user: "root",
  privateKey: "PRIVATE-KEY-PLACEHOLDER",
  hostKeys: [KEY],
  markerPath: "/var/lib/cloud/instance/boot-finished",
};

Deno.test("checkMarker sends the key over stdin, never in argv, and kills the agent", async () => {
  const { run, calls } = markerRunner(0);
  assertEquals(await checkMarker(run, MARKER_OPTS), true);
  const add = calls.find((c) => c.cmd === "ssh-add");
  assertEquals(add?.stdin, "PRIVATE-KEY-PLACEHOLDER\n");
  for (const c of calls) {
    assertEquals(c.args.join(" ").includes("PRIVATE-KEY-PLACEHOLDER"), false);
  }
  const ssh = calls.find((c) => c.cmd === "ssh");
  assertEquals(ssh?.args.includes("StrictHostKeyChecking=yes"), true);
  // The operator's ssh config and default keys never take part.
  assertEquals(ssh?.args.slice(0, 2), ["-F", "/dev/null"]);
  assertEquals(ssh?.args.includes("IdentityFile=none"), true);
  assertEquals(ssh?.args.includes("IdentityAgent=/tmp/agent.test"), true);
  assertEquals(
    ssh?.args.at(-1),
    "test -e '/var/lib/cloud/instance/boot-finished'",
  );
  assertEquals(calls.at(-1)?.args, ["-k"]);
});

Deno.test("checkMarker returns false when the marker is absent", async () => {
  const { run } = markerRunner(1);
  assertEquals(await checkMarker(run, MARKER_OPTS), false);
});

Deno.test("checkMarker throws on connection or auth failure", async () => {
  const { run, calls } = markerRunner(255);
  await assertRejects(() => checkMarker(run, MARKER_OPTS), Error, "exit 255");
  assertEquals(calls.at(-1)?.args, ["-k"]);
});

Deno.test("checkMarker refuses to run without pinned host keys", async () => {
  const { run } = markerRunner(0);
  await assertRejects(
    () => checkMarker(run, { ...MARKER_OPTS, hostKeys: [] }),
    Error,
    "pinned host keys",
  );
});

Deno.test("keysForHost honours the known_hosts host field and port", () => {
  const keys = parseHostKeys(
    `192.0.2.10,server.example.com ${KEY.type} ${KEY.key}\n` +
      `[192.0.2.10]:2222 ${OTHER.type} ${OTHER.key}\n` +
      `198.51.100.7 ${OTHER.type} ${OTHER.key}\n` +
      `${OTHER.type} ${OTHER.key}\n`,
  );
  assertEquals(keysForHost(keys, "192.0.2.10", 22).map((k) => k.key), [
    KEY.key,
    OTHER.key,
  ]);
  assertEquals(keysForHost(keys, "192.0.2.10", 2222).length, 2);
  assertEquals(
    keysForHost(keys, "203.0.113.9", 22).every((k) => k.host === undefined),
    true,
  );
});

Deno.test("checkMarker treats a rejected private key as non-retryable", async () => {
  const { run: base } = markerRunner(0);
  const calls: string[][] = [];
  const run: CommandRunner = (cmd, args, options) => {
    calls.push([cmd, ...args]);
    if (cmd === "ssh-add") {
      return Promise.resolve({ code: 1, stdout: "", stderr: "bad key" });
    }
    return base(cmd, args, options);
  };
  await assertRejects(
    () => checkMarker(run, MARKER_OPTS),
    ProbeConfigError,
    "rejected the private key",
  );
  assertEquals(calls.at(-1), ["ssh-agent", "-k"]);
});

Deno.test("invalid probe input raises ProbeConfigError", () => {
  assertThrows(() => assertUser("root;id"), ProbeConfigError);
  assertThrows(() => assertMarkerPath("/tmp/$(id)"), ProbeConfigError);
  assertThrows(() => assertHost("-oProxyCommand=x"), ProbeConfigError);
});
