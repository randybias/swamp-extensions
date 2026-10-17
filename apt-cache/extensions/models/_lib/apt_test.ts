import { assertEquals, assertThrows } from "jsr:@std/assert@1.0.19";
import {
  AptConfigError,
  assertCacheDir,
  assertPassthroughHost,
  escapeRegex,
  expectedProxyKeys,
  isBackendUrl,
  isWildcardAddress,
  parseAptCacherLog,
  parseCacheBytes,
  parseFsFree,
  parseProxyUrl,
  proxyValuesOf,
  renderBackendFile,
  renderClientSnippet,
  renderDetectScript,
  renderPassthroughPattern,
  renderSecurityConf,
  renderServerFragment,
  windowToSeconds,
} from "./apt.ts";

async function golden(name: string): Promise<string> {
  return await Deno.readTextFile(
    new URL(`./testdata/${name}`, import.meta.url),
  );
}

async function hasTool(name: string): Promise<boolean> {
  try {
    const out = await new Deno.Command("sh", {
      args: ["-c", `command -v ${name}`],
      stdout: "null",
      stderr: "null",
    }).output();
    return out.code === 0;
  } catch {
    return false;
  }
}

/** Parses `apt-config dump` lines into a flat `Key "value";` record. */
function dumpToRecord(text: string): Record<string, string> {
  const out: Record<string, string> = {};
  for (const raw of text.split(/\r?\n/)) {
    const match = /^([A-Za-z0-9_:.-]+)\s+"(.*)";\s*$/.exec(raw.trim());
    if (match) out[match[1]] = match[2];
  }
  return out;
}

Deno.test("parseProxyUrl enforces the raw grammar before URL parsing", () => {
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
      "http://x$({touch,pwned})y:3142",
      'http://x"y:3142',
      "http://x{y}:3142",
      "http://x,y:3142",
      "http://x&y:3142",
      "http://x`y:3142",
      "http://Upper.Example.test:3142",
      "http://[not-an-ip]:3142",
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

Deno.test("backend URLs are an exact grammar, not WHATWG leniency", () => {
  assertEquals(isBackendUrl("http://deb.debian.org/debian/", "http"), true);
  assertEquals(isBackendUrl("https://deb.debian.org/debian/", "https"), true);
  assertEquals(isBackendUrl("http://deb.debian.org", "http"), true);
  assertEquals(isBackendUrl("http://127.0.0.1/debian/", "http"), true);
  assertEquals(isBackendUrl("https://deb.debian.org/debian/", "http"), false);
  for (
    const bad of [
      "http://user:pass@mirror.test/debian/",
      "http://mirror.test/debian/?x=1",
      "http://mirror.test/debian/#frag",
      "http://mirror.test/debian/#",
      "http://mirror.test/debian/;rm",
      "http://mirror.test:8080/debian/",
      "http://mirror.test:80/debian/",
      "http://Upper.test/debian/",
      "http://mirror.test/debian/ extra",
    ]
  ) {
    assertEquals(isBackendUrl(bad, "http"), false, bad);
  }
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
  const direct = renderServerFragment({
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
  });
  assertEquals(direct, await golden("server-direct.golden.txt"));
  // The URL pattern comes first and the file backend after the `;`. Verified
  // against real apt-cacher-ng 3.7.4: the buggy order returns 503 for
  // /ubuntu-ports/dists/.../Release, this order returns 200.
  assertEquals(
    direct.includes(
      "Remap-debian: /debian ; file:zzzz-apt-cache-backend-debian",
    ),
    true,
  );
  assertEquals(
    direct.includes(
      "Remap-ubuntu: /ubuntu ; file:zzzz-apt-cache-backend-ubuntu",
    ),
    true,
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

Deno.test("expectedProxyKeys mirrors the snippet", () => {
  assertEquals(
    expectedProxyKeys({
      proxy_url: "http://192.0.2.10:3142",
      https_policy: "passthrough",
      bypass_hosts: ["archive.example.test"],
      fallback_direct: true,
    }),
    {
      "Acquire::http::Proxy": "http://192.0.2.10:3142",
      "Acquire::https::Proxy": "http://192.0.2.10:3142",
      "Acquire::http::Proxy::archive.example.test": "DIRECT",
      "Acquire::http::Proxy-Auto-Detect":
        "/usr/local/lib/apt-cache/proxy-detect",
    },
  );
});

Deno.test("detect script golden is valid sh and falls back per connect", async () => {
  const script = renderDetectScript("http://192.0.2.10:3142");
  assertEquals(script, await golden("detect.golden.sh"));
  const dir = await Deno.makeTempDir({ prefix: "apt-cache-detect-" });
  try {
    const path = `${dir}/detect.sh`;
    await Deno.writeTextFile(path, script);
    // `-eu` catches unbound variables an `-n` syntax check misses.
    for (const flags of [["-n"], ["-eu"]]) {
      const syntax = await new Deno.Command("sh", { args: [...flags, path] })
        .output();
      assertEquals(syntax.code, 0, flags.join(" "));
    }
    const run = async (exit: number): Promise<string> => {
      const stub = `${dir}/timeout`;
      await Deno.writeTextFile(stub, `#!/bin/sh\nexit ${exit}\n`);
      await Deno.chmod(stub, 0o755);
      const out = await new Deno.Command("sh", {
        args: ["-eu", path],
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

Deno.test("apt-config accepts the rendered snippet and reports every key", async () => {
  if (!(await hasTool("apt-config"))) {
    console.warn("apt-config not present; skipping the real-tool check");
    return;
  }
  const dir = await Deno.makeTempDir({ prefix: "apt-cache-aptconfig-" });
  try {
    const input = {
      proxy_url: "http://192.0.2.20:3142",
      https_policy: "passthrough" as const,
      bypass_hosts: ["archive.example.test"],
      fallback_direct: true,
    };
    const file = `${dir}/snippet.conf`;
    await Deno.writeTextFile(file, renderClientSnippet(input));
    const out = await new Deno.Command("apt-config", {
      args: ["-c", file, "dump"],
      stdout: "piped",
      stderr: "piped",
    }).output();
    assertEquals(out.code, 0);
    const values = dumpToRecord(new TextDecoder().decode(out.stdout));
    for (const [key, value] of Object.entries(expectedProxyKeys(input))) {
      assertEquals(values[key], value, key);
    }
  } finally {
    await Deno.remove(dir, { recursive: true });
  }
});

Deno.test("apt-cacher log parser matches the report's log analysis", async () => {
  const log = await Deno.readTextFile(
    new URL("./testdata/apt-cacher.log.txt", import.meta.url),
  );
  assertEquals(parseAptCacherLog(log, 1792252100, 1792252300), {
    requests: 2,
    hits: 1,
    misses: 1,
    bytes_from_cache: 100,
    bytes_upstream: 100,
  });
  assertEquals(parseAptCacherLog("", 0, 1), {
    requests: 0,
    hits: 0,
    misses: 0,
    bytes_from_cache: 0,
    bytes_upstream: 0,
  });
  assertThrows(
    () => parseAptCacherLog("garbage\nmore garbage\n1|I|2", 0, 10),
    AptConfigError,
    "unrecognised",
  );
});

Deno.test("windowToSeconds accepts today and <n> days", () => {
  assertEquals(windowToSeconds("today"), 86400);
  assertEquals(windowToSeconds("7 days"), 604800);
  assertEquals(windowToSeconds("3 days"), 259200);
  assertThrows(() => windowToSeconds("last year"), AptConfigError);
  assertThrows(() => windowToSeconds("0 days"), AptConfigError);
});

Deno.test("cache size and free space parsers", () => {
  assertEquals(parseCacheBytes("1234567\t/var/cache/apt-cacher-ng\n"), 1234567);
  assertEquals(parseFsFree("Avail\n10485760\n"), 10485760);
  assertThrows(() => parseCacheBytes("nope"), AptConfigError);
});

Deno.test("cache directory grammar rejects traversal, shallow and relative paths", () => {
  assertCacheDir("/var/cache/apt-cacher-ng");
  assertCacheDir("/srv/cache");
  assertThrows(() => assertCacheDir("relative/dir"), AptConfigError);
  assertThrows(() => assertCacheDir("/var/../etc"), AptConfigError);
  assertThrows(() => assertCacheDir("/var/cache/"), AptConfigError);
  assertThrows(() => assertCacheDir("/var"), AptConfigError);
  assertThrows(() => assertCacheDir("/"), AptConfigError);
});

Deno.test("wildcard bind detection normalizes every IPv6 spelling", () => {
  // spellings of the unspecified address under test
  for (const wild of ["0.0.0.0", "::", "::0", "0:0:0:0:0:0:0:0", "[::]"]) { // leak-allow(unspecified-address spellings under test)
    assertEquals(isWildcardAddress(wild), true, wild);
  }
  for (const not of ["192.0.2.1", "::1", "2001:db8::1", "127.0.0.1"]) {
    assertEquals(isWildcardAddress(not), false, not);
  }
});

Deno.test("proxyValuesOf keeps proxy keys and strips userinfo", () => {
  assertEquals(
    proxyValuesOf({
      "Acquire::http::Proxy": "http://user:pw@192.0.2.10:3142",
      "Acquire::https::Proxy": "DIRECT",
      "Acquire::http::Proxy::archive.example.test": "DIRECT",
      "Acquire::http::Proxy-Auto-Detect":
        "/usr/local/lib/apt-cache/proxy-detect",
      "APT::Install-Recommends": "1",
      "APT::Acquire::http::Proxy": "ignored",
    }),
    {
      "Acquire::http::Proxy": "http://192.0.2.10:3142",
      "Acquire::https::Proxy": "DIRECT",
      "Acquire::http::Proxy::archive.example.test": "DIRECT",
    },
  );
});
