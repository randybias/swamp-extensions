import { assertEquals, assertThrows } from "jsr:@std/assert@1.0.19";
import {
  consoleArgv,
  isBenign,
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

Deno.test("consoleArgv: forced attach with a hard timeout", () => {
  assertEquals(consoleArgv("qemu:///system", "node-a", 15), [
    "virsh",
    "-c",
    "qemu:///system",
    "console",
    "node-a",
    "--force",
    "--timeout",
    "15",
  ]);
  assertEquals(
    consoleArgv("qemu:///system", "node-a", 5, "serial0").slice(-2),
    [
      "--devname",
      "serial0",
    ],
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
