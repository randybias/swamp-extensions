import { assert, assertEquals } from "jsr:@std/assert@1.0.19";
import {
  checkNoPlaintextSecrets,
  checkNumbers,
  checkStorageGraph,
  checkUserDataHeader,
  roundTripGuard,
  validateUserDataObject,
  validateUserDataText,
} from "./validate.ts";
import { emitCloudConfig } from "./yaml.ts";
import { HASH } from "./testkit.ts";

const valid = {
  autoinstall: {
    version: 1,
    identity: {
      hostname: "web-1",
      username: "installer",
      password: HASH,
    },
    ssh: { "install-server": true, "authorized-keys": [], "allow-pw": false },
  },
};

const pointer = (doc: unknown, p: string) =>
  validateUserDataObject(doc).find((f) => f.pointer === p);

Deno.test("a well-formed document has no findings", () => {
  assertEquals(validateUserDataObject(valid), []);
});

Deno.test("the autoinstall structure rejects an unknown key and a bad version", () => {
  assert(
    pointer(
      { autoinstall: { ...valid.autoinstall, identiy: {} } },
      "/autoinstall/identiy",
    ),
  );
  assert(
    pointer(
      { autoinstall: { ...valid.autoinstall, version: 2 } },
      "/autoinstall/version",
    ),
  );
  assert(pointer({ ...valid, extra: 1 }, "/extra"));
});

Deno.test("the storage graph rejects a dangling ref, two / mounts and a bootless grub disk", () => {
  const dangling = checkStorageGraph({
    config: [{ type: "format", id: "fmt0", volume: "missing", fstype: "ext4" }],
  });
  assert(dangling.some((f) => f.message.includes("does not resolve")));
  const both = checkStorageGraph({
    config: [
      { type: "disk", id: "disk0", grub_device: true, serial: "S0" },
      { type: "partition", id: "p0", device: "disk0", size: -1 },
      { type: "format", id: "f0", volume: "p0", fstype: "ext4" },
      { type: "mount", id: "m0", device: "f0", path: "/" },
      { type: "format", id: "f1", volume: "p0", fstype: "ext4" },
      { type: "mount", id: "m1", device: "f1", path: "/" },
    ],
  });
  assert(both.some((f) => f.message.includes("exactly one mount at /")));
  assert(both.some((f) => f.message.includes("grub device without a boot")));
});

Deno.test("a LUKS passphrase is refused", () => {
  assert(
    pointer(
      {
        autoinstall: {
          ...valid.autoinstall,
          storage: { layout: { name: "lvm", password: "placeholder" } },
        },
      },
      "/autoinstall/storage/layout/password",
    ),
  );
});

Deno.test("non-integer numbers are refused", () => {
  assert(checkNumbers({ n: 1e21 }).some((f) => f.pointer === "/n"));
  assert(checkNumbers({ n: 1.5 }).length === 1);
  assertEquals(checkNumbers({ n: 42 }), []);
});

Deno.test("plaintext secrets in first-boot user-data are refused", () => {
  assert(
    checkNoPlaintextSecrets({ chpasswd: { list: "u:p" } }).length === 1,
  );
  assert(
    checkNoPlaintextSecrets({ users: [{ plain_text_passwd: "x" }] }).length ===
      1,
  );
  assert(
    checkNoPlaintextSecrets({ ssh_keys: { rsa_private: "-----BEGIN" } })
      .length === 1,
  );
  assertEquals(checkNoPlaintextSecrets({ users: [{ name: "u" }] }), []);
});

Deno.test("validate requires the #cloud-config first line and refuses jinja", () => {
  assertEquals(checkUserDataHeader("#cloud-config\n"), []);
  assert(checkUserDataHeader("autoinstall:\n  version: 1\n").length === 1);
  assert(
    checkUserDataHeader("#cloud-config\n## template: jinja\n").length === 1,
  );
  assertEquals(validateUserDataText(emitCloudConfig(valid)), []);
  assert(validateUserDataText("a: 1\na: 2\n").length > 0);
});

Deno.test("the round-trip guard catches a divergent tree", () => {
  const tree = { autoinstall: { version: 1, flag: "on" } };
  assertEquals(roundTripGuard(emitCloudConfig(tree), tree), []);
  assert(
    roundTripGuard(emitCloudConfig(tree), {
      autoinstall: { version: 1, flag: "off" },
    }).length > 0,
  );
});

Deno.test("a plaintext password in first-boot user-data is refused; a hash is allowed", () => {
  assert(checkNoPlaintextSecrets({ password: "plaintextpw" }).length === 1);
  assertEquals(
    checkNoPlaintextSecrets({ password: HASH }),
    [],
  );
  const findings = validateUserDataObject({
    autoinstall: {
      ...valid.autoinstall,
      "user-data": { password: "plaintextpw" },
    },
  });
  assert(
    findings.some((f) => f.pointer === "/autoinstall/user-data/password"),
  );
});

Deno.test("a cloud-config problem under user-data is pointed at user-data", () => {
  const findings = validateUserDataObject({
    autoinstall: {
      ...valid.autoinstall,
      "user-data": { "not-a-cloud-init-key": true },
    },
  });
  assert(
    findings.every((f) => !f.pointer.startsWith("/autoinstall/not-a")),
  );
  assert(
    findings.some((f) => f.pointer.startsWith("/autoinstall/user-data")),
  );
});
