import { assertEquals } from "jsr:@std/assert@1.0.19";
import {
  hasUrlCredentials,
  HOST_RE,
  isCidr,
  isSafeFilename,
  MANIFEST_PATH_RE,
  MODE_RE,
  NAME_RE,
  normalizeManifestPath,
  REMOTE_PATH_RE,
  SAFE_FILENAME_RE,
  SAFE_URL_RE,
  USER_RE,
} from "./grammar.ts";

Deno.test("HOST_RE accepts names and IP literals, rejects injection", () => {
  assertEquals(HOST_RE.test("k0s.example.com"), true);
  assertEquals(HOST_RE.test("192.0.2.10"), true);
  assertEquals(HOST_RE.test("2001:db8::1"), true);
  assertEquals(HOST_RE.test("192.0.2.10; rm -rf /"), false);
  assertEquals(HOST_RE.test("host name"), false);
});

Deno.test("USER_RE and NAME_RE enforce their grammars", () => {
  assertEquals(USER_RE.test("root"), true);
  assertEquals(USER_RE.test("_svc-1"), true);
  assertEquals(USER_RE.test("root; rm -rf /"), false);
  assertEquals(NAME_RE.test("example-stack"), true);
  assertEquals(NAME_RE.test("Bad_Name"), false);
});

Deno.test("path grammars reject traversal and injection", () => {
  assertEquals(REMOTE_PATH_RE.test("/etc/k0s/k0s.yaml"), true);
  assertEquals(REMOTE_PATH_RE.test("/etc/../passwd"), true); // `..` handled separately
  assertEquals(REMOTE_PATH_RE.test("relative/path"), false);
  assertEquals(REMOTE_PATH_RE.test("/etc/x; rm -rf /"), false);
  assertEquals(MANIFEST_PATH_RE.test("sub/configmap.yaml"), true);
  assertEquals(MANIFEST_PATH_RE.test("../escape"), true);
  assertEquals(MANIFEST_PATH_RE.test("/absolute"), false);
  assertEquals(MODE_RE.test("0644"), true);
  assertEquals(MODE_RE.test("silly"), false);
  assertEquals(SAFE_FILENAME_RE.test("configmap.yaml"), true);
  assertEquals(SAFE_FILENAME_RE.test("a/b"), false);
});

Deno.test("isSafeFilename rejects dot segments", () => {
  assertEquals(isSafeFilename("configmap.yaml"), true);
  assertEquals(isSafeFilename("."), false);
  assertEquals(isSafeFilename(".."), false);
  assertEquals(isSafeFilename("../escape"), false);
});

Deno.test("normalizeManifestPath collapses dot and empty segments", () => {
  assertEquals(normalizeManifestPath("./a//b/./c.yaml"), "a/b/c.yaml");
  assertEquals(normalizeManifestPath("a.yaml"), "a.yaml");
  assertEquals(normalizeManifestPath("./a.yaml"), "a.yaml");
});

Deno.test("SAFE_URL_RE and hasUrlCredentials gate HTTPS URLs", () => {
  assertEquals(SAFE_URL_RE.test("https://charts.example.com/stable"), true);
  assertEquals(SAFE_URL_RE.test("https://example.com/k0s; rm -rf /"), false);
  assertEquals(SAFE_URL_RE.test("http://example.com"), false);
  assertEquals(
    hasUrlCredentials("https://user:pass@example.com/k0s"),
    true,
  );
  assertEquals(hasUrlCredentials("https://example.com/k0s"), false);
  assertEquals(hasUrlCredentials("not a url"), true);
});

Deno.test("isCidr validates IPv4 and IPv6 prefixes", () => {
  assertEquals(isCidr("192.0.2.0/24"), true);
  assertEquals(isCidr("2001:db8::/32"), true);
  assertEquals(isCidr("192.0.2.0/33"), false);
  assertEquals(isCidr("300.0.0.0/24"), false);
  assertEquals(isCidr("192.0.2.0"), false);
});
