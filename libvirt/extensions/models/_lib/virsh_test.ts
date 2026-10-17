import { assertEquals, assertThrows } from "jsr:@std/assert@1.0.19";
import {
  consoleArgv,
  isBenign,
  isNotFound,
  LibvirtError,
  virshArgv,
  xmlTempPath,
} from "./virsh.ts";

Deno.test("virshArgv: the URI is always selected with -c", () => {
  assertEquals(virshArgv("qemu:///system", ["net-info", "default"]), [
    "virsh",
    "-c",
    "qemu:///system",
    "net-info",
    "default",
  ]);
});

Deno.test("consoleArgv: one quoted command and a timeout-to-zero wrapper", () => {
  const argv = consoleArgv("qemu:///system", "node-a", 15);
  assertEquals(argv[0], "sh");
  assertEquals(argv[1], "-c");
  const script = argv[2];
  assertEquals(
    script.includes("'timeout' '-s' 'KILL' '15' 'script' '-qec' "),
    true,
  );
  // `script -qec` must receive exactly one argument: the whole quoted command.
  assertEquals(script.includes("virsh"), true);
  assertEquals(script.includes("qemu:///system"), true);
  assertEquals(script.includes("'/dev/null'"), true);
  assertEquals(script.includes("[ $rc -eq 124 ]"), true);
  assertEquals(
    script.includes("[ $rc -eq 137 ] && [ $((end - start)) -ge 14 ]"),
    true,
  );
  assertEquals(script.includes("--timeout"), false);
  assertEquals(
    consoleArgv("qemu:///system", "node-a", 5, "serial0")[2]
      .includes("serial0"),
    true,
  );
});

Deno.test({
  name: "consoleArgv: a timed-out capture exits 0 with the partial output",
  ignore: Deno.build.os === "windows",
  fn: async () => {
    const dir = await Deno.makeTempDir({ prefix: "libvirt-console-timeout-" });
    try {
      const virsh = `${dir}/virsh`;
      await Deno.writeTextFile(virsh, "#!/bin/sh\nprintf 'hi'\nsleep 30\n");
      await Deno.chmod(virsh, 0o755);
      const argv = consoleArgv("qemu:///system", "node-a", 1);
      const out = await new Deno.Command(argv[0], {
        args: argv.slice(1),
        env: { PATH: `${dir}:${Deno.env.get("PATH") ?? ""}` },
        stdout: "piped",
        stderr: "piped",
      }).output();
      assertEquals(out.code, 0);
      assertEquals(new TextDecoder().decode(out.stdout).includes("hi"), true);
    } finally {
      await Deno.remove(dir, { recursive: true });
    }
  },
});

Deno.test({
  name: "consoleArgv: a virsh failure propagates its exit",
  ignore: Deno.build.os === "windows",
  fn: async () => {
    const dir = await Deno.makeTempDir({ prefix: "libvirt-console-fail-" });
    try {
      const virsh = `${dir}/virsh`;
      await Deno.writeTextFile(virsh, "#!/bin/sh\nprintf 'nope'\nexit 1\n");
      await Deno.chmod(virsh, 0o755);
      const argv = consoleArgv("qemu:///system", "node-a", 5);
      const out = await new Deno.Command(argv[0], {
        args: argv.slice(1),
        env: { PATH: `${dir}:${Deno.env.get("PATH") ?? ""}` },
        stdout: "piped",
        stderr: "piped",
      }).output();
      assertEquals(out.code !== 0, true);
    } finally {
      await Deno.remove(dir, { recursive: true });
    }
  },
});

Deno.test("xmlTempPath: reject a token that could escape /tmp", () => {
  assertEquals(
    xmlTempPath("0000000000000000"),
    "/tmp/randybias-libvirt-0000000000000000.xml",
  );
  for (const bad of ["../etc/passwd", "ABCDEF12", "abc", "0123;id"]) {
    assertThrows(() => xmlTempPath(bad), LibvirtError);
  }
});

Deno.test("isNotFound: only an explicit not-found is absence", () => {
  const res = (stderr: string) => ({ exit_code: 1, stdout: "", stderr });
  assertEquals(
    isNotFound(res("error: failed to get network 'x'"), "network"),
    true,
  );
  assertEquals(isNotFound(res("error: Network not found"), "network"), true);
  assertEquals(
    isNotFound(res("error: failed to get domain 'x'"), "domain"),
    true,
  );
  assertEquals(
    isNotFound(res("error: Storage volume not found"), "volume"),
    true,
  );
  // A hard error must not read as absence.
  assertEquals(
    isNotFound(res("error: failed to connect to the hypervisor"), "network"),
    false,
  );
  assertEquals(isNotFound(res("Permission denied"), "domain"), false);
  assertEquals(
    isNotFound({ exit_code: 0, stdout: "", stderr: "" }, "volume"),
    false,
  );
});

Deno.test("isBenign: matches the already-in-state errors only", () => {
  const res = (stderr: string, exit_code = 1) => ({
    exit_code,
    stdout: "",
    stderr,
  });
  assertEquals(
    isBenign(res("domain is already running"), [/already running/i]),
    true,
  );
  assertEquals(isBenign(res("permission denied"), [/already running/i]), false);
  assertEquals(
    isBenign({ exit_code: 0, stdout: "", stderr: "" }, [/whatever/]),
    true,
  );
});
