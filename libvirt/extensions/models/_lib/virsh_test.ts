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

Deno.test("consoleArgv: pty wrapper with a real kill bound, no --timeout", () => {
  const argv = consoleArgv("qemu:///system", "node-a", 15);
  assertEquals(argv.slice(0, 6), [
    "timeout",
    "-s",
    "KILL",
    "15",
    "script",
    "-qec",
  ]);
  assertEquals(argv.at(-1), "/dev/null");
  const joined = argv.join(" ");
  assertEquals(joined.includes("--timeout"), false);
  assertEquals(joined.includes("'console' 'node-a' '--force'"), true);
  assertEquals(joined.includes("'virsh' '-c' 'qemu:///system'"), true);
  assertEquals(
    consoleArgv("qemu:///system", "node-a", 5, "serial0").join(" ")
      .includes("'--devname' 'serial0'"),
    true,
  );
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
