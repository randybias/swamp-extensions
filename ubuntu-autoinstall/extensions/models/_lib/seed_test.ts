import { assert, assertEquals } from "jsr:@std/assert@1.0.19";
import {
  BUNDLE_FILES,
  bundleDir,
  bundleSums,
  bundleUrl,
  isRootPath,
  isSeedUrl,
  isSeedUrlBase,
  refLine,
  refPath,
} from "./seed.ts";
import type { RenderedFile } from "./render.ts";

const files: RenderedFile[] = [
  { name: "user-data", sha256: "a".repeat(64), bytes: 10 },
  { name: "meta-data", sha256: "b".repeat(64), bytes: 20 },
  { name: "vendor-data", sha256: "c".repeat(64), bytes: 5 },
];

Deno.test("bundle paths follow the artifact-server layout", () => {
  assertEquals(
    bundleDir("/srv/artifacts", "abc"),
    "/srv/artifacts/bundles/abc",
  );
  assertEquals(
    refPath("/srv/artifacts", "web-1"),
    "/srv/artifacts/refs/autoinstall-web-1",
  );
  assertEquals(refLine("abc"), "bundle abc\n");
  assertEquals(
    bundleUrl("https://seed.example.com/", "abc"),
    "https://seed.example.com/bundles/abc/",
  );
  assertEquals([...BUNDLE_FILES], [
    "user-data",
    "meta-data",
    "vendor-data",
    "SHA256SUMS",
  ]);
});

Deno.test("SHA256SUMS is sorted by name in checksum format", () => {
  assertEquals(
    bundleSums(files),
    [
      `${"b".repeat(64)}  meta-data`,
      `${"a".repeat(64)}  user-data`,
      `${"c".repeat(64)}  vendor-data`,
      "",
    ].join("\n"),
  );
});

Deno.test("root paths must be absolute and free of traversal", () => {
  assertEquals(isRootPath("/srv/artifacts"), true);
  assertEquals(isRootPath("/"), false);
  assertEquals(isRootPath("srv/artifacts"), false);
  assertEquals(isRootPath("/srv/../etc"), false);
  assertEquals(isRootPath("/srv//etc"), false);
});

Deno.test("a seed URL base allows only safe characters", () => {
  assertEquals(isSeedUrlBase("https://seed.example.com"), true);
  assertEquals(isSeedUrlBase("http://192.0.2.1:8080/path"), true);
  assertEquals(isSeedUrlBase("https://seed.example.com/a%20b"), true);
  const bad = [
    "https://user%3Apass%40seed.example.com",
    "https://seed.example.com?a=1",
    "https://seed.example.com#frag",
    "ftp://seed.example.com",
    'https://seed.example.com"; rm -rf /',
    "https://seed.example.com/$(id)",
    "https://seed.example.com/a`b",
    "https://seed.example.com/{a}",
    "https://seed.example.com;x",
    "https://seed.example.com/a\\b",
  ];
  for (const u of bad) assertEquals(isSeedUrlBase(u), false, u);
});

Deno.test("a command-line seed URL must end in a slash", () => {
  assertEquals(isSeedUrl("https://seed.example.com/bundles/abc/"), true);
  assertEquals(isSeedUrl("https://seed.example.com/bundles/abc"), false);
  assert(isSeedUrl("https://seed.example.com;x/") === false);
});
