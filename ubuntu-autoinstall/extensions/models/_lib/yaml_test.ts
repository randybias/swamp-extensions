import { assert, assertEquals } from "jsr:@std/assert@1.0.19";
import {
  CLOUD_CONFIG_HEADER,
  deepEqual,
  emitCloudConfig,
  emitYamlBody,
  reparseCloudConfig,
  sanitizeScalars,
} from "./yaml.ts";

Deno.test("the header is fixed and every string is quoted", () => {
  const out = emitCloudConfig({
    autoinstall: { hostname: "on", mode: "0644", time: "22:22" },
  });
  assert(out.startsWith(CLOUD_CONFIG_HEADER));
  assert(out.includes('"hostname": "on"'));
  assert(out.includes('"mode": "0644"'));
  assert(out.includes('"time": "22:22"'));
});

Deno.test("keys are sorted and the output is deterministic", () => {
  const a = emitCloudConfig({ b: 1, a: 2, c: { z: 1, y: 2 } });
  const b = emitCloudConfig({ c: { y: 2, z: 1 }, a: 2, b: 1 });
  assertEquals(a, b);
  assert(a.indexOf('"a":') < a.indexOf('"b":'));
  assert(a.indexOf('"y":') < a.indexOf('"z":'));
});

Deno.test("the YAML 1.1 round-trip preserves quoted scalars", () => {
  const tree = {
    autoinstall: {
      version: 1,
      identity: { hostname: "on", password: "$6$abc$def" },
      nested: { "yes": "no", n: "1e3", tilde: "~" },
    },
  };
  const parsed = reparseCloudConfig(emitCloudConfig(tree));
  assertEquals(parsed.reason, undefined);
  assert(deepEqual(tree, parsed.value));
});

Deno.test("the YAML 1.1 traps are caught by the emitter's quoting", () => {
  // Without quoting, YAML 1.1 reads these as a bool, an octal and a base-60.
  const raw = reparseCloudConfig("a: on\nb: 0644\nc: 22:22\n");
  assertEquals(raw.reason, undefined);
  assertEquals(raw.value, { a: true, b: 420, c: 1342 });
  // Quoted, they stay strings and round-trip.
  const tree = { a: "on", b: "0644", c: "22:22" };
  const parsed = reparseCloudConfig(emitCloudConfig(tree));
  assert(deepEqual(tree, parsed.value));
});

Deno.test("duplicate keys, merge keys, anchors, aliases and tags are refused", () => {
  assert(reparseCloudConfig("a: 1\na: 2\n").reason !== undefined);
  assert(reparseCloudConfig("base: &b {x: 1}\ny: *b\n").reason !== undefined);
  assert(reparseCloudConfig("y:\n  <<: {x: 1}\n").reason !== undefined);
  assert(reparseCloudConfig("y: !!str 1\n").reason !== undefined);
  assert(reparseCloudConfig("y: !custom 1\n").reason !== undefined);
});

Deno.test("deepEqual is structural and order independent", () => {
  assert(deepEqual({ a: 1, b: [1, { c: 2 }] }, { b: [1, { c: 2 }], a: 1 }));
  assertEquals(deepEqual({ a: 1 }, { a: "1" }), false);
  assertEquals(deepEqual([1, 2], [2, 1]), false);
});

Deno.test("a non-integer number is emitted as a quoted string", () => {
  // `1e21` emitted unquoted is read as a string by PyYAML but a number here.
  const body = emitYamlBody({ exponent: 1e21, fraction: 1.5 });
  assert(body.includes('"1e+21"'));
  assert(body.includes('"1.5"'));
  assertEquals(sanitizeScalars({ a: 1e21, b: [2, 3] }), {
    a: "1e+21",
    b: [2, 3],
  });
});

Deno.test("the YAML 1.1 trap corpus is caught or round-trips", () => {
  // Norway, octal, sexagesimal, null and exponent: all become other types
  // unquoted, and stay strings quoted.
  const parsed = reparseCloudConfig(
    "norway: no\noctal: 0644\nsexagesimal: 22:22\nnil: ~\nexp: 1e3\n",
  );
  assertEquals(parsed.value, {
    norway: false,
    octal: 420,
    sexagesimal: 1342,
    nil: null,
    exp: 1000,
  });
  const tree = {
    norway: "no",
    octal: "0644",
    sexagesimal: "22:22",
    nil: "~",
    exp: "1e3",
    merged: { a: 1 },
  };
  const quoted = reparseCloudConfig(emitYamlBody(tree));
  assertEquals(quoted.reason, undefined);
  assert(deepEqual(quoted.value, tree));
});
