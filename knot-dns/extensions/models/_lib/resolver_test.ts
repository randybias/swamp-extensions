import { assert, assertEquals } from "jsr:@std/assert@1.0.19";
import {
  CidrSchema,
  ForwardSchema,
  ListenAddressSchema,
  pickTestQuery,
  renderResolverYaml,
  ResolverSchema,
  splitListen,
} from "./resolver.ts";

Deno.test("listen and CIDR grammars", () => {
  assertEquals(ListenAddressSchema.safeParse("127.0.0.1@53").success, true);
  assertEquals(ListenAddressSchema.safeParse("2001:db8::1").success, true);
  assertEquals(ListenAddressSchema.safeParse("not-an-address").success, false);
  assertEquals(ListenAddressSchema.safeParse("127.0.0.1@0").success, false);
  assertEquals(CidrSchema.safeParse("192.0.2.0/24").success, true);
  assertEquals(CidrSchema.safeParse("192.0.2.0/33").success, false);
  assertEquals(splitListen("127.0.0.1@5353"), {
    host: "127.0.0.1",
    port: 5353,
  });
  assertEquals(splitListen("127.0.0.1"), { host: "127.0.0.1", port: 53 });
});

Deno.test("an authoritative upstream cannot use TLS", () => {
  assertEquals(
    ForwardSchema.safeParse({
      subtree: "internal.example.",
      servers: ["192.0.2.53"],
      authoritative: true,
      transport: "tls",
    }).success,
    false,
  );
});

Deno.test("golden resolver config.yaml", () => {
  const input = ResolverSchema.parse({
    listen: ["127.0.0.1@53"],
    cache_size_mb: 256,
    forwards: [
      {
        subtree: "internal.example.",
        servers: ["192.0.2.53"],
        authoritative: false,
      },
      {
        subtree: ".",
        servers: ["203.0.113.53"],
        transport: "tls",
        tls_hostname: "dns.example",
        dnssec: true,
      },
    ],
    allow_query_from: ["127.0.0.0/8", "2001:db8::/32"],
  });
  assertEquals(
    renderResolverYaml(input),
    [
      "---",
      "network:",
      "  listen:",
      '    - interface: "127.0.0.1"',
      "      port: 53",
      "cache:",
      "  size-max: 256M",
      "forward:",
      '  - subtree: "internal.example."',
      "    servers:",
      '      - address: "192.0.2.53"',
      "    options:",
      "      dnssec: false",
      '  - subtree: "."',
      "    servers:",
      '      - address: "203.0.113.53"',
      "        transport: tls",
      '        hostname: "dns.example"',
      "    options:",
      "      dnssec: true",
      "views:",
      "  - subnets:",
      '      - "127.0.0.0/8"',
      '      - "2001:db8::/32"',
      "    answer: allow",
      "  - subnets:",
      '      - "0.0.0.0/0"',
      '      - "::/0"',
      "    answer: refused",
      "",
    ].join("\n"),
  );
});

Deno.test("resolver YAML escapes scalar content", () => {
  const input = ResolverSchema.parse({
    listen: ["127.0.0.1@53"],
    forwards: [{
      subtree: "example.test.",
      servers: ["192.0.2.1"],
    }],
  });
  const yaml = renderResolverYaml(input);
  assert(yaml.includes('subtree: "example.test."'));
});

Deno.test("the self-test asks a name the forwarded upstream actually serves", () => {
  const input = (forwards: unknown[], test_name?: string) =>
    ResolverSchema.parse({
      listen: ["127.0.0.3@53"],
      forwards,
      ...(test_name ? { test_name } : {}),
    });
  const fwd = (subtree: string) => ({
    subtree,
    servers: ["127.0.0.1"],
    authoritative: true,
  });
  // The parent is forwarded, only children are served: ask a served child.
  assertEquals(
    pickTestQuery(input([fwd("example.test.")]), [
      "a.example.test.",
      "b.example.test.",
    ]),
    "a.example.test.",
  );
  // The forwarded subtree is itself served: ask it, even if a child is listed first.
  assertEquals(
    pickTestQuery(input([fwd("a.example.test.")]), [
      "x.a.example.test.",
      "a.example.test.",
    ]),
    "a.example.test.",
  );
  // The caller's name always wins.
  assertEquals(
    pickTestQuery(input([fwd("example.test.")], "www.a.example.test."), [
      "a.example.test.",
    ]),
    "www.a.example.test.",
  );
  // Nothing served overlaps (an external forward): the subtree, as before.
  assertEquals(
    pickTestQuery(input([fwd("corp.example.")]), ["a.example.test."]),
    "corp.example.",
  );
  // No forwards at all: the root.
  assertEquals(pickTestQuery(input([]), ["a.example.test."]), ".");
  // A name outside the subtree is not mistaken for a child.
  assertEquals(
    pickTestQuery(input([fwd("example.test.")]), ["badexample.test."]),
    "example.test.",
  );
});
