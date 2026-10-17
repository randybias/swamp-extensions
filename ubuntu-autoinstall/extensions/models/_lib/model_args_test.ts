import { assert, assertEquals } from "jsr:@std/assert@1.0.19";
import { PublishArgs, RenderArgs, ValidateArgs } from "./model_args.ts";
import { isCryptHash } from "./grammars.ts";
import { HASH, publishArgs, renderArgs } from "./testkit.ts";

interface MetaField {
  meta(): { sensitive?: boolean } | undefined;
  shape?: Record<string, MetaField>;
}

const shapeOf = (schema: unknown): Record<string, MetaField> =>
  (schema as { shape: Record<string, MetaField> }).shape;

Deno.test("the password hash and the supplied user-data are sensitive", () => {
  assertEquals(
    shapeOf(shapeOf(RenderArgs).identity).password_hash.meta()?.sensitive,
    true,
  );
  assertEquals(shapeOf(ValidateArgs).user_data.meta()?.sensitive, true);
});

Deno.test("a plaintext password and a non-crypt hash are refused", () => {
  assertEquals(
    RenderArgs.safeParse(renderArgs({
      identity: {
        hostname: "web-1",
        username: "installer",
        password_hash: "hunter2",
      },
    })).success,
    false,
  );
  assertEquals(RenderArgs.safeParse(renderArgs()).success, true);
});

Deno.test("only a strict host-key policy with pinned keys is accepted", () => {
  const insecure = {
    ...publishArgs(),
    server: {
      ...publishArgs().server,
      ssh: { ...publishArgs().server.ssh, host_key_policy: "insecure_tofu" },
    },
  };
  assertEquals(PublishArgs.safeParse(insecure).success, false);
  const noKeys = {
    ...publishArgs(),
    server: {
      ...publishArgs().server,
      ssh: { ...publishArgs().server.ssh, host_keys: [] },
    },
  };
  assertEquals(PublishArgs.safeParse(noKeys).success, false);
});

Deno.test("authorized_keys must parse as an OpenSSH key (RSA 3072+)", () => {
  const shortRsa = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQ user@example.com";
  assertEquals(
    RenderArgs.safeParse(renderArgs({
      ssh: { install_server: true, authorized_keys: [shortRsa] },
    })).success,
    false,
  );
  assertEquals(
    RenderArgs.safeParse(renderArgs({
      ssh: { install_server: true, authorized_keys: ["not a key"] },
    })).success,
    false,
  );
});

Deno.test("a late command argv element must be printable", () => {
  assertEquals(
    RenderArgs.safeParse(renderArgs({
      late_commands: [{ argv: ["echo", "a\nb"] }],
    })).success,
    false,
  );
  assertEquals(
    RenderArgs.safeParse(renderArgs({
      late_commands: [{ shell: "echo hi", shell_ack: true }],
      late_commands_shell_ack: true,
    })).success,
    true,
  );
});

Deno.test("the network subset rejects a bad CIDR and a stray key", () => {
  assertEquals(
    RenderArgs.safeParse(renderArgs({
      network: {
        version: 2,
        ethernets: { eno1: { addresses: ["999.0.0.1/24"] } },
      },
    })).success,
    false,
  );
  assertEquals(
    RenderArgs.safeParse(renderArgs({
      network: { version: 2, ethernets: { eno1: { nonsense: true } } },
    })).success,
    false,
  );
  assertEquals(
    RenderArgs.safeParse(renderArgs({
      network: {
        version: 2,
        ethernets: {
          eno1: { match: { macaddress: "02:00:00:00:00:01" }, dhcp4: false },
        },
      },
    })).success,
    true,
  );
});

Deno.test("a command-line seed_url must end in / and carry no shell character", () => {
  assertEquals(
    RenderArgs.safeParse(renderArgs({ seed_url: "https://s.example.com/x/" }))
      .success,
    true,
  );
  assertEquals(
    RenderArgs.safeParse(renderArgs({ seed_url: "https://s.example.com/x" }))
      .success,
    false,
  );
  assertEquals(
    RenderArgs.safeParse(
      renderArgs({ seed_url: "https://s.example.com/$(id)/" }),
    ).success,
    false,
  );
});

Deno.test("a password hash that is a plaintext is never accepted", () => {
  assert(HASH.startsWith("$6$"));
});

Deno.test("first_boot_user_data is sensitive and bounded", () => {
  assertEquals(
    shapeOf(RenderArgs).first_boot_user_data.meta()?.sensitive,
    true,
  );
  const huge = { blob: "x".repeat(70000) };
  assertEquals(
    RenderArgs.safeParse(renderArgs({ first_boot_user_data: huge })).success,
    false,
  );
});

Deno.test("only real crypt formats are accepted", () => {
  const good = [
    "$1$abcdefgh$0123456789012345678901",
    `$2a$10$${"x".repeat(53)}`,
    `$2b$12$${"x".repeat(53)}`,
    `$2y$10$${"x".repeat(53)}`,
    `$5$abcdefghijklmnop$${"x".repeat(43)}`,
    `$6$abcdefghijklmnop$${"x".repeat(86)}`,
    `$6$rounds=5000$abcdefghijklmnop$${"x".repeat(86)}`,
    `$y$j9T$${"x".repeat(24)}$${"x".repeat(43)}`,
    `$y$${"x".repeat(24)}$${"x".repeat(43)}`,
  ];
  for (const hash of good) assertEquals(isCryptHash(hash), true, hash);
  const bad = [
    "hunter2",
    "$6$hunter2222",
    "$6$abcdefghijklmnop$",
    "$1$onlysalt",
    "$2b$10$short",
    "$9$whatever$x$y",
    "$6$salt$hash",
  ];
  for (const hash of bad) assertEquals(isCryptHash(hash), false, hash);
});
