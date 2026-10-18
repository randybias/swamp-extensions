import { assert, assertEquals } from "jsr:@std/assert@1.0.19";
import {
  cidrContains,
  CidrSchema,
  effectiveAllowQueryFrom,
  ForwardSchema,
  ListenAddressSchema,
  pickTestListen,
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

Deno.test("CIDR containment covers both families and /0", () => {
  assert(cidrContains("127.0.0.0/8", "127.0.0.1"));
  assert(!cidrContains("203.0.113.0/24", "127.0.0.1"));
  assert(cidrContains("192.0.2.10/32", "192.0.2.10"));
  assert(!cidrContains("192.0.2.10/32", "192.0.2.11"));
  assert(cidrContains("2001:db8::/32", "2001:db8::1"));
  assert(!cidrContains("2001:db8:1::/48", "2001:db8:2::1"));
  assert(!cidrContains("2001:db8::/32", "192.0.2.1"));
  assert(cidrContains("::1/128", "::1"));
  assert(cidrContains("0.0.0.0/0", "203.0.113.7"));
});

Deno.test("the default access list covers loopback and the listen addresses", () => {
  const input = ResolverSchema.parse({
    listen: ["127.0.0.1@53", "192.0.2.10@53"],
  });
  const allow = effectiveAllowQueryFrom(input);
  assert(allow.includes("127.0.0.0/8"));
  assert(allow.includes("192.0.2.10/32"));
  // An explicit list is used verbatim.
  const explicit = ResolverSchema.parse({
    listen: ["192.0.2.10@53"],
    allow_query_from: ["192.0.2.0/24"],
  });
  assertEquals(effectiveAllowQueryFrom(explicit), ["192.0.2.0/24"]);
});

Deno.test("the self-test picks a listen address the access list permits", () => {
  // The first listen is excluded; the second is permitted.
  const picksSecond = ResolverSchema.parse({
    listen: ["127.0.0.1@53", "192.0.2.10@53"],
    allow_query_from: ["192.0.2.0/24"],
  });
  assertEquals(pickTestListen(picksSecond), "192.0.2.10@53");
  // Default: loopback is permitted.
  assertEquals(
    pickTestListen(ResolverSchema.parse({ listen: ["127.0.0.1@5353"] })),
    "127.0.0.1@5353",
  );
  // A wildcard is probed on loopback.
  assertEquals(
    pickTestListen(ResolverSchema.parse({ listen: ["0.0.0.0@5353"] })),
    "0.0.0.0@5353",
  );
  // An explicit list excluding every listen returns null (the caller refuses).
  assertEquals(
    pickTestListen(ResolverSchema.parse({
      listen: ["192.0.2.10@53"],
      allow_query_from: ["203.0.113.0/24"],
    })),
    null,
  );
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
