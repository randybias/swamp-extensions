import { assertEquals, assertThrows } from "jsr:@std/assert@1.0.19";
import {
  AptConfigError,
  assertCacheDir,
  assertPassthroughHost,
  escapeRegex,
  isBackendUrl,
  parseCacheBytes,
  parseFsFree,
  parseProxyUrl,
  parseReportPage,
  renderBackendFile,
  renderClientSnippet,
  renderDetectScript,
  renderPassthroughPattern,
  renderSecurityConf,
  renderServerFragment,
} from "./apt.ts";

async function golden(name: string): Promise<string> {
  return await Deno.readTextFile(
    new URL(`./testdata/${name}`, import.meta.url),
  );
}

Deno.test("parseProxyUrl accepts http host:port and rejects the rest", () => {
  assertEquals(
    parseProxyUrl("http://192.0.2.10:3142").url,
    "http://192.0.2.10:3142",
  );
  assertEquals(
    parseProxyUrl("http://cache.example.test:3142").host,
    "cache.example.test",
  );
  assertEquals(
    parseProxyUrl("http://[2001:db8::10]:3142").address,
    "2001:db8::10",
  );
  for (
    const bad of [
      "https://192.0.2.10:3142",
      "http://user:pass@192.0.2.10:3142",
      "http://192.0.2.10",
      "http://192.0.2.10:3142/path",
      "http://192.0.2.10:3142?x=1",
    ]
  ) {
    assertThrows(() => parseProxyUrl(bad), AptConfigError, undefined, bad);
  }
});

Deno.test("passthrough hosts reject wildcards, IP literals and case", () => {
  assertPassthroughHost("archive.example.test");
  assertPassthroughHost("security.example.test");
  for (
    const bad of [
      "*.example.test",
      "192.0.2.10",
      "2001:db8::1",
      "Bad.Example.test",
      "",
    ]
  ) {
    assertThrows(
      () => assertPassthroughHost(bad),
      AptConfigError,
      undefined,
      bad,
    );
  }
});

Deno.test("backend URLs reject credentials, query and a wrong scheme", () => {
  assertEquals(isBackendUrl("http://deb.debian.org/debian/", "http"), true);
  assertEquals(isBackendUrl("https://deb.debian.org/debian/", "https"), true);
  assertEquals(isBackendUrl("https://deb.debian.org/debian/", "http"), false);
  assertEquals(
    isBackendUrl("http://user:pass@mirror.test/debian/", "http"),
    false,
  );
  assertEquals(isBackendUrl("http://mirror.test/debian/?x=1", "http"), false);
  assertEquals(isBackendUrl("http://mirror.test/debian/#frag", "http"), false);
  assertEquals(isBackendUrl("http://mirror.test:8080/debian/", "http"), false);
});

Deno.test("escapeRegex neutralizes metacharacters", () => {
  assertEquals(escapeRegex("a.b"), "a\\.b");
  assertEquals(escapeRegex("a+b*c?"), "a\\+b\\*c\\?");
  assertEquals(escapeRegex(".*"), "\\.\\*");
});

Deno.test("passthrough pattern is anchored, escaped and never .*", () => {
  const pattern = renderPassthroughPattern([
    "archive.example.test",
    "security.example.test",
  ]);
  assertEquals(
    pattern,
    "^(archive\\.example\\.test|security\\.example\\.test)(:443)?$",
  );
  assertEquals(pattern.includes(".*"), false);
  assertThrows(() => renderPassthroughPattern([]), AptConfigError);
  assertThrows(() => renderPassthroughPattern([".*"]), AptConfigError);
});

Deno.test("server fragment goldens per HTTPS policy", async () => {
  assertEquals(
    renderServerFragment({
      listen: ["192.0.2.10"],
      port: 3142,
      https_policy: "direct",
      passthrough_hosts: [],
      backends: {
        debian: ["http://deb.debian.org/debian/"],
        ubuntu: ["http://archive.ubuntu.com/ubuntu/"],
      },
      expire_days: 4,
      cache_dir: "/var/cache/apt-cacher-ng",
    }),
    await golden("server-direct.golden.txt"),
  );
  assertEquals(
    renderServerFragment({
      listen: ["192.0.2.10", "2001:db8::10"],
      port: 3142,
      https_policy: "passthrough",
      passthrough_hosts: ["security.example.test", "archive.example.test"],
      backends: { debian: ["http://deb.debian.org/debian/"] },
      expire_days: 7,
      cache_dir: "/var/cache/apt-cacher-ng",
    }),
    await golden("server-passthrough.golden.txt"),
  );
  assertEquals(
    renderServerFragment({
      listen: ["192.0.2.10"],
      port: 3142,
      https_policy: "https_backends",
      passthrough_hosts: [],
      backends: { debian: ["https://deb.debian.org/debian/"] },
      expire_days: 4,
      cache_dir: "/var/cache/apt-cacher-ng",
    }),
    await golden("server-https-backends.golden.txt"),
  );
});

Deno.test("backend file golden and scheme enforcement", async () => {
  assertEquals(
    renderBackendFile(
      ["http://deb.debian.org/debian/", "http://mirror2.example.test/debian/"],
      "http",
    ),
    await golden("backend-debian.golden.txt"),
  );
  assertThrows(
    () => renderBackendFile(["https://deb.debian.org/debian/"], "http"),
    AptConfigError,
  );
  assertThrows(() => renderBackendFile([], "http"), AptConfigError);
});

Deno.test("client snippet goldens per policy", async () => {
  assertEquals(
    renderClientSnippet({
      proxy_url: "http://192.0.2.10:3142",
      https_policy: "passthrough",
      bypass_hosts: ["archive.example.test"],
      fallback_direct: true,
    }),
    await golden("client-passthrough.golden.txt"),
  );
  assertEquals(
    renderClientSnippet({
      proxy_url: "http://192.0.2.10:3142",
      https_policy: "direct",
      bypass_hosts: [],
      fallback_direct: false,
    }),
    await golden("client-direct.golden.txt"),
  );
});

Deno.test("detect script golden is valid sh and falls back per connect", async () => {
  const script = renderDetectScript("http://192.0.2.10:3142");
  assertEquals(script, await golden("detect.golden.sh"));
  const dir = await Deno.makeTempDir({ prefix: "apt-cache-detect-" });
  try {
    const path = `${dir}/detect.sh`;
    await Deno.writeTextFile(path, script);
    const syntax = await new Deno.Command("sh", { args: ["-n", path] })
      .output();
    assertEquals(syntax.code, 0);
    const run = async (exit: number): Promise<string> => {
      const stub = `${dir}/timeout`;
      await Deno.writeTextFile(stub, `#!/bin/sh\nexit ${exit}\n`);
      await Deno.chmod(stub, 0o755);
      const out = await new Deno.Command("sh", {
        args: [path],
        env: { PATH: `${dir}:${Deno.env.get("PATH") ?? ""}` },
        stdout: "piped",
        stderr: "piped",
      }).output();
      return new TextDecoder().decode(out.stdout).trim();
    };
    assertEquals(await run(0), "http://192.0.2.10:3142");
    assertEquals(await run(1), "DIRECT");
  } finally {
    await Deno.remove(dir, { recursive: true });
  }
});

Deno.test("security.conf renders only a valid user:password", () => {
  assertEquals(renderSecurityConf("admin:s3cret"), "AdminAuth: admin:s3cret\n");
  assertThrows(() => renderSecurityConf("nocolon"), AptConfigError);
  assertThrows(() => renderSecurityConf("a:b\ninjected"), AptConfigError);
});

Deno.test("report page parser reads the requested window and fails closed", async () => {
  const html = await Deno.readTextFile(
    new URL("./testdata/report-page.txt", import.meta.url),
  );
  assertEquals(parseReportPage(html, "today"), {
    requests: 15,
    hits: 12,
    misses: 3,
    bytes_from_cache: 1048576,
    bytes_upstream: 2097152,
  });
  assertEquals(parseReportPage(html, "7 days").requests, 50);
  assertThrows(() => parseReportPage(html, "last year"), AptConfigError);
  assertThrows(() => parseReportPage("", "today"), AptConfigError);
});

Deno.test("cache size and free space parsers", () => {
  assertEquals(parseCacheBytes("1234567\t/var/cache/apt-cacher-ng\n"), 1234567);
  assertEquals(parseFsFree("Avail\n10485760\n"), 10485760);
  assertThrows(() => parseCacheBytes("nope"), AptConfigError);
});

Deno.test("cache directory grammar rejects traversal and relative paths", () => {
  assertCacheDir("/var/cache/apt-cacher-ng");
  assertThrows(() => assertCacheDir("relative/dir"), AptConfigError);
  assertThrows(() => assertCacheDir("/var/../etc"), AptConfigError);
  assertThrows(() => assertCacheDir("/var/cache/"), AptConfigError);
});
