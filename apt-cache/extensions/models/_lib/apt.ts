/**
 * Pure Apt-Cacher NG helpers: input grammars, deterministic renderers for the
 * managed server fragment, backend files and client apt snippet, and parsers
 * for the request log the model reads over SSH.
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
/** Directory holding the client auto-detect script. */
export const DETECT_DIR = "/usr/local/lib/apt-cache";
/** Absolute path of the client auto-detect script. */
export const DETECT_PATH = `${DETECT_DIR}/proxy-detect`;
/** Absolute path of the server's admin credential file. */
export const SECURITY_CONF_PATH = "/etc/apt-cacher-ng/security.conf";
/** Absolute path of the request log `stats` reads. */
export const APT_CACHER_LOG_PATH = "/var/log/apt-cacher-ng/apt-cacher.log";
/** Default cache directory (the package default). */
export const DEFAULT_CACHE_DIR = "/var/cache/apt-cacher-ng";
/** Default listen port. */
export const DEFAULT_PORT = 3142;
/** Iface name of the managed backend file for a distribution key. */
export function managedBackendName(key: string): string {
  return `zzzz-apt-cache-backend-${key}`;
}

/** Absolute path of a managed backend file for a distribution key. */
export function managedBackendPath(key: string): string {
  return `${ACNG_CONF_DIR}/${managedBackendName(key)}`;
}

/**
 * The package's built-in backend file that a key's built-in remap reads, or
 * null when the key needs its own `Remap-` line. `Remap-debrep` and
 * `Remap-uburep` already claim the proxy-style and path-style prefixes for
 * `debian` and `ubuntu`; overwriting the file they read is the only way to
 * change those routes (`acng.conf` cannot be edited and a second `Remap-` for
 * the same key only appends).
 */
export function backendFileFor(key: string): string | null {
  switch (key) {
    case "debian":
      return `${ACNG_CONF_DIR}/backends_debian`;
    case "ubuntu":
      return `${ACNG_CONF_DIR}/backends_ubuntu`;
    default:
      return null;
  }
}

/**
 * The URL prefixes a key's own `Remap-` line matches. A path prefix serves
 * transparent/path-style requests; a `host/path` prefix serves the
 * proxy-style requests `configure_client` produces (apt sends
 * `GET http://ports.ubuntu.com/ubuntu-ports/...` to the proxy).
 */
export function remapPrefixes(key: string): string[] {
  switch (key) {
    case "ubuntu-ports":
      return ["/ubuntu-ports", "ports.ubuntu.com/ubuntu-ports"];
    default:
      return [`/${key}`];
  }
}

/** One rendered backend file. */
export interface RenderedBackend {
  /** Distribution key. */
  key: string;
  /** Absolute remote path (built-in file for shadowed keys, else the managed file). */
  path: string;
  /** File body: one mirror base URL per line. */
  text: string;
}

/** Renders every backend file, choosing the path a key's remap reads. */
export function renderBackendFiles(
  backends: Record<string, string[]>,
  scheme: "http" | "https",
): RenderedBackend[] {
  return Object.keys(backends).sort().map((key) => ({
    key,
    path: backendFileFor(key) ?? managedBackendPath(key),
    text: renderBackendFile(backends[key], scheme),
  }));
}

/** DNS-1123 hostname, lower case, one or more labels. */
export const PASSTHROUGH_HOST_RE =
  /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$/;

/** Dotted-quad IPv4 literal. */
const IPV4_RE =
  /^(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$/;

/** Absolute cache directory path; at least two components. */
const CACHE_DIR_RE = /^\/[A-Za-z0-9._/-]{1,255}$/;

/**
 * Top-level directories that must never be a cache directory, because
 * `remove_server` may `rm -rf` it. `var`, `srv`, `opt`, `data`, `media`,
 * `mnt` and `tmp` are allowed.
 */
const FORBIDDEN_CACHE_ROOTS = new Set([
  "bin",
  "boot",
  "dev",
  "etc",
  "home",
  "lib",
  "lib32",
  "lib64",
  "proc",
  "root",
  "run",
  "sbin",
  "sys",
  "usr",
]);

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

/**
 * True when `address` is a wildcard bind: IPv4 `0.0.0.0` or the IPv6
 * unspecified address in any spelling (`::`, `::0`, `0:0:0:0:0:0:0:0`,
 * bracketed or bare).
 */
export function isWildcardAddress(address: string): boolean {
  const v = address.startsWith("[") && address.endsWith("]")
    ? address.slice(1, -1)
    : address;
  if (v === "0.0.0.0") return true;
  if (!v.includes(":")) return false;
  try {
    return new URL(`http://[${v}]/`).hostname === "[::]";
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

/**
 * Throws unless `path` is an absolute cache directory with at least two
 * components, no `..` and no trailing slash. The two-component floor keeps a
 * later `rm -rf` from ever naming a top-level directory.
 */
export function assertCacheDir(path: string): void {
  const parts = path.split("/").filter((part) => part !== "");
  if (
    !CACHE_DIR_RE.test(path) || path.endsWith("/") || path.includes("//") ||
    parts.includes(".") || parts.includes("..") || parts.length < 2 ||
    FORBIDDEN_CACHE_ROOTS.has(parts[0])
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

/** Bracketed IPv6 or a DNS/IPv4 label, followed by an explicit port. */
const PROXY_URL_RE =
  /^http:\/\/(\[[0-9A-Fa-f:.]+\]|[A-Za-z0-9.-]+):([0-9]{1,5})$/;

/**
 * Parses a proxy URL with the spec grammar
 * `http://<ipv4|[ipv6]|dns-1123 fqdn>:<port>` against the raw string, before
 * any WHATWG leniency. `new URL` alone accepts host characters such as
 * `$ ( ) { } , ; & \` "`, which would reach the auto-detect script and the apt
 * snippet.
 */
export function parseProxyUrl(url: string): ProxyUrl {
  const match = PROXY_URL_RE.exec(url);
  if (!match) {
    throw new AptConfigError(`Not a valid proxy URL: ${url}`);
  }
  const port = Number(match[2]);
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new AptConfigError(`Not a valid proxy port: ${match[2]}`);
  }
  const rawHost = match[1];
  let address: string;
  if (rawHost.startsWith("[")) {
    address = rawHost.slice(1, -1);
    if (!isIpv6(address)) {
      throw new AptConfigError(`Not a valid proxy host: ${rawHost}`);
    }
  } else if (isIpv4(rawHost)) {
    address = rawHost;
  } else if (PASSTHROUGH_HOST_RE.test(rawHost) && !rawHost.includes("*")) {
    address = rawHost;
  } else {
    throw new AptConfigError(`Not a valid proxy host: ${rawHost}`);
  }
  const hostField = isIpv6(address) ? `[${address}]` : address;
  return {
    address,
    host: hostField,
    port,
    url: `http://${hostField}:${port}`,
  };
}

/** A DNS-1123 host label sequence, lower case. */
const BACKEND_HOST_RE = PASSTHROUGH_HOST_RE;
/** A mirror path: `/`-separated segments from a conservative allowlist. */
const BACKEND_PATH_RE = /^(?:\/[A-Za-z0-9._~+@:%-]*)*$/;

/**
 * True when `s` is an accepted backend mirror base URL: the exact `scheme`,
 * a lower-case DNS name or IPv4 literal (no userinfo, no port, no wildcard)
 * and a conservative path. `new URL` alone accepts a trailing `#`, `;` or an
 * explicit `:80`, so the raw string is checked instead.
 */
export function isBackendUrl(s: string, scheme: "http" | "https"): boolean {
  const prefix = `${scheme}://`;
  if (!s.startsWith(prefix)) return false;
  const rest = s.slice(prefix.length);
  const slash = rest.indexOf("/");
  const host = slash === -1 ? rest : rest.slice(0, slash);
  const path = slash === -1 ? "" : rest.slice(slash);
  if (host === "" || (host.includes(":") && !isIpv4(host))) return false;
  if (!isIpv4(host) && !BACKEND_HOST_RE.test(host)) return false;
  if (path !== "" && !BACKEND_PATH_RE.test(path)) return false;
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
    // `debian` and `ubuntu` are served by the package's built-in Remap-debrep
    // and Remap-uburep, whose backend files the model manages. A second
    // Remap- line for the same key only appends to that repo (the built-in
    // prefixes are added first and win ties), so it cannot change the route.
    if (backendFileFor(key) !== null) continue;
    // The URL pattern comes first and the `file:` backend second, after the
    // `;` separator. Putting the backend in the pattern slot makes acng never
    // match the mirror (a `/ubuntu-ports` request then returns 503).
    lines.push(
      `Remap-${key}: ${remapPrefixes(key).join(" ")} ; file:${
        managedBackendName(key)
      }`,
    );
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
 * The `Acquire::*` keys and exact values the snippet sets, for a read-back
 * check. Derived from the same inputs as the snippet.
 */
export function expectedProxyKeys(
  input: ClientRenderInput,
): Record<string, string> {
  const proxy = parseProxyUrl(input.proxy_url);
  const keys: Record<string, string> = {
    "Acquire::http::Proxy": proxy.url,
    "Acquire::https::Proxy": input.https_policy === "passthrough"
      ? proxy.url
      : "DIRECT",
  };
  for (const host of [...new Set(input.bypass_hosts)].sort()) {
    assertPassthroughHost(host);
    keys[`Acquire::http::Proxy::${host}`] = "DIRECT";
  }
  if (input.fallback_direct) {
    keys["Acquire::http::Proxy-Auto-Detect"] = DETECT_PATH;
  }
  return keys;
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

/** Single-quotes `value` as one POSIX shell word. */
function shQuote(value: string): string {
  if (value === "") return "''";
  return `'${value.replace(/'/g, "'\\''")}'`;
}

/**
 * Renders the static auto-detect script. It is tiny and runs as root on every
 * apt invocation, so it contains only a fixed `timeout`/`bash` probe and the
 * validated URL. The address is passed as an argv word to `bash -c`, never
 * interpolated into the command text, and the printed URL is quoted as data.
 * A successful TCP connect prints the proxy; anything else prints DIRECT.
 */
export function renderDetectScript(proxy_url: string): string {
  const proxy = parseProxyUrl(proxy_url);
  return [
    "#!/bin/sh",
    "# Managed by @randybias/apt-cache. Static and tiny; runs as root.",
    "# Prints the proxy URL when a TCP connect succeeds within 2s, else DIRECT.",
    `if timeout 2 bash -c 'exec 3<>/dev/tcp/"$1"/"$2"' _ ${
      shQuote(proxy.address)
    } ${shQuote(String(proxy.port))} 2>/dev/null; then`,
    `  printf '%s\\n' ${shQuote(proxy.url)}`,
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
  /** Total requests (`max(I, O)`), the report's "Total". */
  requests: number;
  /** Requests served without going upstream (`max(I, O) - I`). */
  hits: number;
  /** Requests that fetched upstream (`I` lines). */
  misses: number;
  /** Bytes served from cache (`max(byteIn, byteOut) - byteIn`). */
  bytes_from_cache: number;
  /** Bytes fetched upstream (`I` lines). */
  bytes_upstream: number;
}

/** Seconds in a day. */
const DAY_SECONDS = 86400;

/**
 * Converts a `stats` window label to a duration in seconds. Accepts `today`
 * (24 h) and `<n> days` (1–90); throws otherwise.
 */
export function windowToSeconds(window: string): number {
  const w = window.trim().toLowerCase();
  if (w === "today" || w === "day" || w === "1 day") return DAY_SECONDS;
  if (w === "week" || w === "7 days") return 7 * DAY_SECONDS;
  const match = /^(\d{1,3})\s*days?$/.exec(w);
  if (match) {
    const n = Number(match[1]);
    if (n >= 1 && n <= 90) return n * DAY_SECONDS;
  }
  throw new AptConfigError(
    `Unrecognised window ${JSON.stringify(window)}; use "today" or "<n> days"`,
  );
}

/**
 * Parses rows of the apt-cacher request log (`<time>|I|<bytes>`,
 * `<time>|O|<bytes>`, `<time>|E|<bytes>`, and free-form `misc` rows) and
 * returns the report-equivalent totals for `[since, until]` (unix seconds).
 * The mapping is `reqMax = max(I, O)` / `dataMax = max(byteIn, byteOut)` from
 * upstream `GetStats`, so it matches the maintenance page without invoking the
 * page's `Count Data` action. Fails closed when more than half the rows are
 * unrecognisable.
 */
export function parseAptCacherLog(
  text: string,
  since: number,
  until: number,
): StatsTotals {
  let reqIn = 0, reqOut = 0, byteIn = 0, byteOut = 0;
  let recognised = 0, total = 0;
  for (const raw of text.split(/\r?\n/)) {
    if (raw === "") continue;
    total++;
    const tokens = raw.split("|");
    if (tokens.length < 3 || !/^\d+$/.test(tokens[0])) continue;
    const type = tokens[1];
    // Only the documented row types count as recognised: I (fetch upstream),
    // O (serve), E (serve error), and the misc rows M and X. An unknown typed
    // row (e.g. `1|Z|100`) must not defeat the fail-closed check.
    if (
      type !== "I" && type !== "O" && type !== "E" && type !== "M" &&
      type !== "X"
    ) continue;
    if (
      (type === "I" || type === "O" || type === "E") &&
      !/^\d+$/.test(tokens[2])
    ) continue;
    recognised++;
    const when = Number(tokens[0]);
    if (when < since || when > until) continue;
    const bytes = Number(tokens[2]);
    if (type === "I") {
      byteIn += bytes;
      reqIn++;
    } else if (type === "O") {
      byteOut += bytes;
      reqOut++;
    }
  }
  if (total > 0 && (total - recognised) * 2 > total) {
    throw new AptConfigError(
      "the apt-cacher log had too many unrecognised lines; refusing to guess",
    );
  }
  const reqMax = Math.max(reqIn, reqOut);
  const dataMax = Math.max(byteIn, byteOut);
  return {
    requests: reqMax,
    hits: reqMax - reqIn,
    misses: reqIn,
    bytes_from_cache: dataMax - byteIn,
    bytes_upstream: byteIn,
  };
}

/**
 * Drops the userinfo from any `<scheme>://` value, for every scheme (socks5h,
 * http, ...) and up to the LAST `@` before the first `/`. `DIRECT`, `auto` and
 * other non-URL values pass through unchanged.
 */
export function redactProxyValue(value: string): string {
  const match = /^([A-Za-z][A-Za-z0-9+.-]*:\/\/)([^/]*)(.*)$/.exec(value);
  if (!match) return value;
  const [, scheme, authority, rest] = match;
  const at = authority.lastIndexOf("@");
  if (at === -1) return value;
  return `${scheme}${authority.slice(at + 1)}${rest}`;
}

/**
 * Keeps only the effective `Acquire::(http|https)::Proxy` and
 * `...::Proxy::<host>` keys from an `apt-config dump`, and strips any userinfo
 * so a pre-existing credential is never persisted. Auto-detect and unrelated
 * apt keys are dropped.
 */
export function proxyValuesOf(
  values: Record<string, string>,
): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [key, value] of Object.entries(values)) {
    if (/^Acquire::(http|https)::Proxy(::[A-Za-z0-9._-]+)?$/.test(key)) {
      out[key] = redactProxyValue(value);
    }
  }
  return out;
}

/**
 * Renders the `sh -c` body that prints apt-cacher's current log plus its
 * rotated logs, so a multi-day window is not silently truncated by logrotate
 * (`size 10M`, `rotate 7`, `delaycompress`). Exits 3 when no log file exists.
 */
export function renderLogReadScript(logPath: string): string {
  const l = shQuote(logPath);
  return [
    `L=${l}`,
    "read_any=0",
    `for f in "$L" "$L.1" "$L".*.gz; do`,
    '  [ -f "$f" ] || continue',
    "  read_any=1",
    '  case "$f" in',
    '    *.gz) gzip -dc "$f" 2>/dev/null || zcat "$f" 2>/dev/null ;;',
    '    *) cat "$f" ;;',
    "  esac",
    "done",
    '[ "$read_any" = 1 ] || { echo "no apt-cacher log found" >&2; exit 3; }',
  ].join("\n");
}

/** Parses the byte count from `du -sb <dir>`. */
export function parseCacheBytes(stdout: string): number {
  const match = /(\d[\d,]*)/.exec(stdout);
  if (!match) {
    throw new AptConfigError("could not read the cache directory size");
  }
  const n = Number(match[1].replaceAll(",", ""));
  if (!Number.isFinite(n)) {
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
  const match = /(\d[\d,]*)/.exec(last);
  if (!match) {
    throw new AptConfigError("could not parse filesystem free space");
  }
  const n = Number(match[1].replaceAll(",", ""));
  if (!Number.isFinite(n)) {
    throw new AptConfigError("could not parse filesystem free space");
  }
  return n;
}
