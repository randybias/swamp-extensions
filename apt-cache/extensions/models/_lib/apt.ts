/**
 * Pure Apt-Cacher NG helpers: input grammars, deterministic renderers for the
 * managed server fragment, backend files and client apt snippet, and parsers
 * for the report page the model reads over the server's loopback.
 *
 * Nothing here spawns a process or opens a socket, so the module is exercised
 * offline. The model in `apt_cache.ts` is a thin orchestration layer over these
 * functions plus the vendored SSH transport.
 *
 * @module
 */

/** An input that fails its allowlist grammar or a cross-field rule. */
export class AptConfigError extends Error {
  /** Creates a configuration error safe to show a caller. */
  constructor(message: string) {
    super(message);
    this.name = "AptConfigError";
  }
}

/** HTTPS handling policy. Required; there is no default. */
export type HttpsPolicy = "direct" | "passthrough" | "https_backends";

/**
 * The package's built-in safe passthrough default. Rendered for `direct` and
 * `https_backends` so an earlier `.*` (the debconf tunnel prompt) cannot stay
 * in force.
 */
export const DEFAULT_PASSTHROUGH_PATTERN =
  "^(bugs\\.debian\\.org|changelogs\\.ubuntu\\.com):443$";

/** Every accepted HTTPS policy, in table order. */
export const HTTPS_POLICIES = [
  "direct",
  "passthrough",
  "https_backends",
] as const;

/** Distribution keys a backend map may name. */
export const DISTRO_KEYS = [
  "debian",
  "ubuntu",
  "ubuntu-ports",
  "debian-security",
] as const;

/** Grammar for a backend map key. */
export const DISTRO_KEY_RE = /^(debian|ubuntu|ubuntu-ports|debian-security)$/;

/** Absolute path of the managed server fragment; sorts after acng.conf and the debconf file. */
export const FRAGMENT_PATH = "/etc/apt-cacher-ng/zzzz-apt-cache.conf";
/** Directory holding the managed fragment and backend files. */
export const ACNG_CONF_DIR = "/etc/apt-cacher-ng";
/** Absolute path of the client apt snippet. */
export const CLIENT_SNIPPET_PATH = "/etc/apt/apt.conf.d/90apt-cache-proxy";
/** Absolute path of the client auto-detect script. */
export const DETECT_PATH = "/usr/local/lib/apt-cache/proxy-detect";
/** Absolute path of the server's admin credential file. */
export const SECURITY_CONF_PATH = "/etc/apt-cacher-ng/security.conf";
/** Default cache directory (the package default). */
export const DEFAULT_CACHE_DIR = "/var/cache/apt-cacher-ng";
/** Default listen port. */
export const DEFAULT_PORT = 3142;
/** Iface name of the managed backend file for a distribution key. */
export function managedBackendName(key: string): string {
  return `zzzz-apt-cache-backend-${key}`;
}

/** Absolute path of the managed backend file for a distribution key. */
export function managedBackendPath(key: string): string {
  return `${ACNG_CONF_DIR}/${managedBackendName(key)}`;
}

/** DNS-1123 hostname, lower case, one or more labels. */
export const PASSTHROUGH_HOST_RE =
  /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$/;

/** Dotted-quad IPv4 literal. */
const IPV4_RE =
  /^(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$/;

/** Absolute cache directory path. */
const CACHE_DIR_RE = /^\/[A-Za-z0-9._/-]{1,255}$/;

/** True for a dotted-quad IPv4 literal. */
export function isIpv4(s: string): boolean {
  return IPV4_RE.test(s);
}

/** True for a bracketed or bare IPv6 literal. */
export function isIpv6(s: string): boolean {
  const v = s.startsWith("[") && s.endsWith("]") ? s.slice(1, -1) : s;
  if (!v.includes(":")) return false;
  try {
    new URL(`http://[${v}]/`);
    return true;
  } catch {
    return false;
  }
}

/** Throws unless `host` is a lower-case DNS name and not an IP literal. */
export function assertPassthroughHost(host: string): void {
  if (
    !PASSTHROUGH_HOST_RE.test(host) || host.includes("*") ||
    isIpv4(host) || isIpv6(host)
  ) {
    throw new AptConfigError(
      `Not a valid passthrough hostname: ${JSON.stringify(host)}`,
    );
  }
}

/** Throws unless `path` is an absolute cache directory with no `..`. */
export function assertCacheDir(path: string): void {
  if (
    !CACHE_DIR_RE.test(path) || path.endsWith("/") ||
    path.split("/").includes("..")
  ) {
    throw new AptConfigError(`Not a valid cache directory: ${path}`);
  }
}

/** A parsed `http://<host>:<port>` proxy URL. */
export interface ProxyUrl {
  /** Host as written, without brackets for IPv6. */
  address: string;
  /** Host exactly as written (bracketed for IPv6). */
  host: string;
  /** TCP port. */
  port: number;
  /** Canonical `http://host:port` form. */
  url: string;
}

/** Parses a proxy URL: `http://` only, no userinfo, explicit port. */
export function parseProxyUrl(url: string): ProxyUrl {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    throw new AptConfigError(`Not a valid proxy URL: ${url}`);
  }
  if (parsed.protocol !== "http:") {
    throw new AptConfigError("The proxy URL must use http://");
  }
  if (parsed.username !== "" || parsed.password !== "") {
    throw new AptConfigError("The proxy URL must not carry credentials");
  }
  if (parsed.port === "") {
    throw new AptConfigError("The proxy URL must name a port");
  }
  const port = Number(parsed.port);
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new AptConfigError(`Not a valid proxy port: ${parsed.port}`);
  }
  if (parsed.pathname !== "/" || parsed.search !== "" || parsed.hash !== "") {
    throw new AptConfigError("The proxy URL must be a bare host and port");
  }
  const rawHost = parsed.hostname;
  const host = rawHost.startsWith("[") && rawHost.endsWith("]")
    ? rawHost.slice(1, -1)
    : rawHost;
  const hostField = isIpv6(host) ? `[${host}]` : host;
  return {
    address: host,
    host: hostField,
    port,
    url: `http://${hostField}:${port}`,
  };
}

/** True when `s` is an accepted backend mirror base URL. */
export function isBackendUrl(s: string, scheme: "http" | "https"): boolean {
  let parsed: URL;
  try {
    parsed = new URL(s);
  } catch {
    return false;
  }
  if (`${scheme}:` !== parsed.protocol) return false;
  if (parsed.username !== "" || parsed.password !== "") return false;
  if (parsed.search !== "" || parsed.hash !== "" || parsed.host === "") {
    return false;
  }
  if (parsed.hostname.includes("*") || parsed.port !== "") {
    return false;
  }
  if (!parsed.pathname.startsWith("/")) return false;
  return !/\s/.test(s);
}

/** Throws unless `s` is a backend mirror base URL for `scheme`. */
export function assertBackendUrl(s: string, scheme: "http" | "https"): void {
  if (!isBackendUrl(s, scheme)) {
    throw new AptConfigError(
      `Not a valid ${scheme} backend URL: ${JSON.stringify(s)}`,
    );
  }
}

/** Escapes every regular-expression metacharacter in `value`. */
export function escapeRegex(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/**
 * Renders the anchored passthrough pattern `^(host1|host2)(:443)?$` with every
 * host escaped. Wildcards and raw `.*` are impossible: hosts pass
 * {@link assertPassthroughHost} and are escaped before joining.
 */
export function renderPassthroughPattern(hosts: string[]): string {
  if (hosts.length === 0) {
    throw new AptConfigError("passthrough requires at least one host");
  }
  const escaped = [...new Set(hosts)].map((host) => {
    assertPassthroughHost(host);
    return escapeRegex(host);
  }).sort();
  return `^(${escaped.join("|")})(:443)?$`;
}

/** Everything the server fragment renderer needs. */
export interface ServerRenderInput {
  /** Listen addresses; one `BindAddress` line holds all of them. */
  listen: string[];
  /** TCP port. */
  port: number;
  /** HTTPS handling policy. */
  https_policy: HttpsPolicy;
  /** Hosts allowed to tunnel when the policy is `passthrough`. */
  passthrough_hosts: string[];
  /** Distribution key to mirror base URLs. */
  backends: Record<string, string[]>;
  /** `ExThreshold` in days. */
  expire_days: number;
  /** Cache directory. */
  cache_dir: string;
}

/**
 * Renders the single managed fragment under `/etc/apt-cacher-ng/`. Apt-Cacher
 * NG reads every `*.conf` in that directory, so the package's own `acng.conf`
 * is never edited.
 */
export function renderServerFragment(input: ServerRenderInput): string {
  if (input.listen.length === 0) {
    throw new AptConfigError("listen must name at least one address");
  }
  if (
    !Number.isInteger(input.port) || input.port < 1024 || input.port > 65535
  ) {
    throw new AptConfigError(`Not a valid port: ${input.port}`);
  }
  assertCacheDir(input.cache_dir);
  const lines = [
    "# Managed by @randybias/apt-cache. Do not edit; re-applied by the model.",
    `BindAddress: ${input.listen.join(" ")}`,
    `Port: ${input.port}`,
    `CacheDir: ${input.cache_dir}`,
    `ExThreshold: ${input.expire_days}`,
  ];
  // Always render PassThroughPattern: our fragment sorts after acng.conf, so
  // omitting it would leave any earlier `.*` (the debconf tunnel prompt)
  // in force. For direct and https_backends this is the documented built-in
  // default, which is safe; for passthrough it is the caller's allowlist.
  const pattern = input.https_policy === "passthrough"
    ? renderPassthroughPattern(input.passthrough_hosts)
    : DEFAULT_PASSTHROUGH_PATTERN;
  lines.push(`PassThroughPattern: ${pattern}`);
  const scheme = input.https_policy === "https_backends" ? "https" : "http";
  for (const key of Object.keys(input.backends).sort()) {
    const urls = input.backends[key];
    if (urls.length === 0) {
      throw new AptConfigError(`Backend ${key} names no mirror`);
    }
    for (const url of urls) assertBackendUrl(url, scheme);
    lines.push(`Remap-${key}: file:${managedBackendName(key)} /${key}`);
  }
  return lines.join("\n") + "\n";
}

/** Renders one managed backend file: one mirror base URL per line. */
export function renderBackendFile(
  urls: string[],
  scheme: "http" | "https",
): string {
  if (urls.length === 0) throw new AptConfigError("A backend file needs a URL");
  for (const url of urls) assertBackendUrl(url, scheme);
  return urls.join("\n") + "\n";
}

/** Everything the client snippet renderer needs. */
export interface ClientRenderInput {
  /** Canonical `http://host:port` proxy URL. */
  proxy_url: string;
  /** HTTPS handling policy. */
  https_policy: HttpsPolicy;
  /** Hosts that go DIRECT. */
  bypass_hosts: string[];
  /** Whether to render the auto-detect script reference. */
  fallback_direct: boolean;
}

/**
 * Renders the client apt snippet. `passthrough` points HTTPS at the cache;
 * `direct` and `https_backends` send HTTPS DIRECT and proxy only HTTP.
 */
export function renderClientSnippet(input: ClientRenderInput): string {
  const proxy = parseProxyUrl(input.proxy_url);
  const lines = [
    "// Managed by @randybias/apt-cache. Do not edit; re-applied by the model.",
    `Acquire::http::Proxy "${proxy.url}";`,
  ];
  const httpsValue = input.https_policy === "passthrough"
    ? proxy.url
    : "DIRECT";
  lines.push(`Acquire::https::Proxy "${httpsValue}";`);
  for (const host of [...new Set(input.bypass_hosts)].sort()) {
    assertPassthroughHost(host);
    lines.push(`Acquire::http::Proxy::${host} "DIRECT";`);
  }
  if (input.fallback_direct) {
    lines.push(`Acquire::http::Proxy-Auto-Detect "${DETECT_PATH}";`);
  }
  return lines.join("\n") + "\n";
}

/**
 * Renders the static auto-detect script. It is tiny and runs as root on every
 * apt invocation, so it contains only a fixed `timeout`/`bash` probe and the
 * validated URL. A successful TCP connect prints the proxy; anything else
 * prints DIRECT.
 */
export function renderDetectScript(proxy_url: string): string {
  const proxy = parseProxyUrl(proxy_url);
  return [
    "#!/bin/sh",
    "# Managed by @randybias/apt-cache. Static and tiny; runs as root.",
    "# Prints the proxy URL when a TCP connect succeeds within 2s, else DIRECT.",
    `if timeout 2 bash -c 'exec 3<>/dev/tcp/${proxy.address}/${proxy.port}' 2>/dev/null; then`,
    `  printf '%s\\n' '${proxy.url}'`,
    "else",
    "  printf '%s\\n' 'DIRECT'",
    "fi",
    "",
  ].join("\n");
}

/** Renders the server's `security.conf` body for an admin user and password. */
export function renderSecurityConf(auth: string): string {
  const match = /^([A-Za-z0-9._-]{1,64}):(.{1,128})$/.exec(auth);
  if (!match || /[\r\n]/.test(auth)) {
    throw new AptConfigError(
      "admin_auth_ref must hold user:password without control characters",
    );
  }
  return `AdminAuth: ${auth}\n`;
}

/** The summary `stats` returns. */
export interface StatsTotals {
  /** Request hits. */
  requests: number;
  /** Request hits. */
  hits: number;
  /** Request misses. */
  misses: number;
  /** Bytes served from cache. */
  bytes_from_cache: number;
  /** Bytes fetched upstream. */
  bytes_upstream: number;
}

function decodeEntities(text: string): string {
  return text
    .replace(/&amp;/g, "&")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    .replace(/&nbsp;/g, " ");
}

/** Splits an HTML table into rows of cell text, with tags removed. */
export function parseHtmlRows(html: string): string[][] {
  const rows: string[][] = [];
  for (const rowMatch of html.matchAll(/<tr\b[^>]*>([\s\S]*?)<\/tr>/gi)) {
    const cells: string[] = [];
    for (
      const cellMatch of rowMatch[1].matchAll(
        /<t[dh]\b[^>]*>([\s\S]*?)<\/t[dh]>/gi,
      )
    ) {
      cells.push(
        decodeEntities(cellMatch[1].replace(/<[^>]*>/g, " ")).replace(
          /\s+/g,
          " ",
        ).trim(),
      );
    }
    if (cells.length > 0) rows.push(cells);
  }
  return rows;
}

function firstInteger(text: string): number | undefined {
  const match = /(\d[\d,]*)/.exec(text);
  if (!match) return undefined;
  const n = Number(match[1].replaceAll(",", ""));
  return Number.isFinite(n) ? n : undefined;
}

/**
 * Parses the Apt-Cacher NG report page's log-analysis row whose period label
 * contains `window` (case-insensitive). Throws rather than guessing when no
 * row matches, so `stats` fails closed on an unrecognised page.
 */
export function parseReportPage(html: string, window: string): StatsTotals {
  const rows = parseHtmlRows(html);
  if (rows.length === 0) {
    throw new AptConfigError("the report page held no tables");
  }
  const wanted = window.trim().toLowerCase();
  for (const row of rows) {
    const label = row[0].trim().toLowerCase();
    if (
      label === "" || label === "period" ||
      label.includes("cache efficiency") || label === "requests" ||
      label === "hits" || label === "misses" || label === "total" ||
      label === "data"
    ) {
      continue;
    }
    const numbers = row.slice(1).map(firstInteger).filter(
      (n): n is number => n !== undefined,
    );
    if (numbers.length < 6) continue;
    if (wanted === "" || label.includes(wanted)) {
      return {
        requests: numbers[2],
        hits: numbers[0],
        misses: numbers[1],
        bytes_from_cache: numbers[3],
        bytes_upstream: numbers[4],
      };
    }
  }
  throw new AptConfigError(
    `the report page had no log-analysis row for window ${
      JSON.stringify(window)
    }`,
  );
}

/** Parses the byte count from `du -sb <dir>`. */
export function parseCacheBytes(stdout: string): number {
  const n = firstInteger(stdout);
  if (n === undefined) {
    throw new AptConfigError("could not read the cache directory size");
  }
  return n;
}

/** Parses the available bytes from `df -B1 --output=avail <dir>`. */
export function parseFsFree(stdout: string): number {
  const lines = stdout.split(/\r?\n/).map((l) => l.trim()).filter((l) =>
    l !== ""
  );
  const last = lines[lines.length - 1];
  if (last === undefined) {
    throw new AptConfigError("could not read filesystem free space");
  }
  const n = firstInteger(last);
  if (n === undefined) {
    throw new AptConfigError("could not parse filesystem free space");
  }
  return n;
}
