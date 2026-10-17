import { assertEquals, assertStringIncludes } from "jsr:@std/assert@1.0.19";
import {
  HTPASSWD_PATH,
  listenAddress,
  renderSite,
  TLS_CERT_PATH,
  TLS_KEY_PATH,
} from "./nginx.ts";

const BASE = {
  root: "/srv/artifacts",
  listen: { address: "*", port: 8080 },
  serverName: "cdn.example.test",
  tlsProvided: false,
  basicAuth: false,
  basicAuthRealm: "",
};

Deno.test("listenAddress brackets IPv6 and passes * and IPv4 through", () => {
  assertEquals(listenAddress("*"), "*");
  assertEquals(listenAddress("192.0.2.10"), "192.0.2.10");
  assertEquals(listenAddress("2001:db8::1"), "[2001:db8::1]");
});

Deno.test("renderSite is deterministic and denies dotfiles and refs", () => {
  const a = renderSite(BASE);
  const b = renderSite({ ...BASE });
  assertEquals(a, b);
  assertStringIncludes(a, "listen *:8080;");
  assertStringIncludes(a, "server_name 'cdn.example.test';");
  assertStringIncludes(a, "root '/srv/artifacts';");
  assertStringIncludes(a, "autoindex off;");
  assertStringIncludes(a, "disable_symlinks on;");
  assertStringIncludes(a, "location ~ /\\. {");
  assertStringIncludes(a, "location ^~ /refs/ {");
  assertStringIncludes(a, "deny all;");
  // TLS and auth are absent unless asked for.
  assertEquals(a.includes("ssl_certificate"), false);
  assertEquals(a.includes("auth_basic"), false);
  assertEquals(a.endsWith("}\n"), true);
});

Deno.test("renderSite adds TLS files only for provided TLS", () => {
  const text = renderSite({ ...BASE, tlsProvided: true });
  assertStringIncludes(text, "listen *:8080 ssl;");
  assertStringIncludes(text, `ssl_certificate '${TLS_CERT_PATH}';`);
  assertStringIncludes(text, `ssl_certificate_key '${TLS_KEY_PATH}';`);
});

Deno.test("renderSite adds basic auth with the realm and htpasswd path", () => {
  const text = renderSite({
    ...BASE,
    basicAuth: true,
    basicAuthRealm: "artifacts",
  });
  assertStringIncludes(text, "auth_basic 'artifacts';");
  assertStringIncludes(text, `auth_basic_user_file '${HTPASSWD_PATH}';`);
});

Deno.test("renderSite denies dotfiles inside the immutable directories too", () => {
  const text = renderSite(BASE);
  // The immutable locations must not use ^~, which would skip the dotfile
  // regex and serve in-flight .ssh-host-upload.* temp files.
  assertEquals(text.includes("^~ /sha256/"), false);
  assertEquals(text.includes("^~ /bundles/"), false);
  const sha = text.slice(
    text.indexOf("location /sha256/"),
    text.indexOf("location /bundles/"),
  );
  assertEquals(sha.includes("location ~ /\\. {"), true);
  assertEquals(sha.includes("deny all;"), true);
  const bundles = text.slice(text.indexOf("location /bundles/"));
  assertEquals(bundles.includes("location ~ /\\. {"), true);
  assertEquals(bundles.includes("deny all;"), true);
});

Deno.test("renderSite quotes a root with no shell metacharacters untouched", () => {
  const text = renderSite({ ...BASE, root: "/srv/a b/c" });
  assertStringIncludes(text, "root '/srv/a b/c';");
});
