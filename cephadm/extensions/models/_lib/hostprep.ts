/**
 * Host-preparation logic: the package phase, the cephadm install and time-sync
 * steps, and the package-source pre-flight.
 *
 * The package verdict comes from dpkg, never from the install command's exit
 * status, because a session killed by its own timeout reported an install
 * failed while dpkg finished it seconds later. A busy host is never installed
 * over, and a session lost mid-install is never re-sent blindly. The
 * package-source check measures resolution and reachability separately, so
 * "did not resolve" and "did not answer" lead to different systems.
 *
 * @module
 */

import { fail, SudoPolicyError, TransportError } from "./errors.ts";
import type { SshSession } from "./ssh_session.ts";
import {
  assertCephadmVersion,
  assertHttpUrl,
  HOSTNAME_RE,
  quote,
  redactUrl,
} from "./validate.ts";

/** Shared dependencies for waits and jitter. */
export interface PrepDeps {
  /** Current time in milliseconds. */
  now: () => number;
  /** Sleeps for the given milliseconds. */
  sleep: (ms: number) => Promise<void>;
  /** Random value in [0, 1). */
  random: () => number;
}

/** Default per-command budget for host preparation, in milliseconds. */
export const HOSTPREP_BUDGET_MS = 15 * 60 * 1000;
/** The floor for any command run inside cephadm shell, in milliseconds. */
export const CEPHADM_SHELL_FLOOR_MS = 5 * 60 * 1000;
/** The fixed install path for the cephadm binary. */
export const CEPHADM_PATH = "/usr/local/sbin/cephadm";

/** Per-package presence evidence. */
export interface PackageEvidence {
  /** Package name. */
  name: string;
  /** Whether the first idle read found it present. */
  alreadyPresent: boolean;
  /** `dpkg -s` Version field, when observed. */
  installedVersion?: string;
}

/** Evidence from the package phase, so a green run does not hide a retried one. */
export interface PackagePhaseEvidence {
  /** Install commands sent, re-sends included. */
  installAttempts: number;
  /** Transport failures seen. */
  transportFailures: number;
  /** Failures dropped during authentication. */
  droppedPreauth: number;
  /** Failures proving the command never started. */
  preSessionFailures: number;
  /** Times the host was busy. */
  busyWaits: number;
  /** State reads made. */
  entries: number;
  /** Total wall time of the phase. */
  elapsedMs: number;
  /** Packages confirmed present only after a session had failed. */
  confirmedAfterTransportFailure: boolean;
}

/** Outcome of the package phase. */
export interface PackagePhaseResult {
  /** Per-package evidence, in request order. */
  packages: PackageEvidence[];
  /** Phase evidence. */
  evidence: PackagePhaseEvidence;
}

/** The script a busy probe runs under sudo; only the exact output `idle` means idle. */
export function busyProbeScript(): string {
  return [
    'holders=""',
    "if command -v fuser >/dev/null 2>&1; then",
    '  holders="$(fuser /var/lib/dpkg/lock-frontend /var/lib/dpkg/lock 2>/dev/null || true)"',
    "fi",
    'if [ -n "$holders" ]; then echo busy; exit 0; fi',
    "for proc in apt apt-get dpkg unattended-upgr; do",
    '  if pgrep -x "$proc" >/dev/null 2>&1; then echo busy; exit 0; fi',
    "done",
    "echo idle",
  ].join("\n");
}

/** Parses the `Version:` field out of `dpkg -s` output. */
export function parseDpkgVersion(stdout: string): string | undefined {
  for (const line of stdout.split("\n")) {
    if (line.startsWith("Version:")) {
      return line.slice("Version:".length).trim() || undefined;
    }
  }
  return undefined;
}

/** Extracts the version token after the word `version` from `cephadm version` output. */
export function parseCephadmVersion(stdout: string): string | null {
  const words = stdout.trim().split(/\s+/);
  const at = words.indexOf("version");
  if (at < 0 || at + 1 >= words.length) return null;
  const token = words[at + 1];
  return token === "" ? null : token;
}

/** True when stderr indicates another apt holds the dpkg lock. */
export function isAptLockContention(stderr: string): boolean {
  const l = stderr.toLowerCase();
  return l.includes("could not get lock") || l.includes("lock-frontend") ||
    l.includes("is held by process") ||
    l.includes("unable to acquire the dpkg frontend lock") ||
    l.includes("unable to lock the administration directory");
}

type Logger = { warn: (m: string, p?: Record<string, unknown>) => void };

/** The capped exponential wait between package-phase entries, clamped to what is left. */
export function hostprepBackoff(
  n: number,
  remainingMs: number,
  random: () => number,
): number {
  const raw = Math.min(30_000, 3000 * 2 ** n) + Math.floor(random() * 3000);
  return Math.min(Math.max(1, remainingMs), raw);
}

/**
 * Runs the package phase. Returns evidence when every requested package is
 * confirmed present by dpkg; throws a phase-attributed error otherwise, naming
 * the last blocking cause.
 */
export async function runPackagePhase(
  deps: PrepDeps,
  session: SshSession,
  opts: { packages: string[]; budgetMs: number },
  log?: Logger,
): Promise<PackagePhaseResult> {
  const requested = opts.packages;
  const budget = Math.max(0, opts.budgetMs);
  const started = deps.now();
  const deadline = started + budget;
  const maxEntries = budget > 0 ? Math.ceil(budget / 3000) + 2 : 3;
  const evidence: PackagePhaseEvidence = {
    installAttempts: 0,
    transportFailures: 0,
    droppedPreauth: 0,
    preSessionFailures: 0,
    busyWaits: 0,
    entries: 0,
    elapsedMs: 0,
    confirmedAfterTransportFailure: false,
  };
  const alreadyPresent = new Map<string, boolean>();
  const versions = new Map<string, string>();
  let sawFirstIdle = false;
  let anyTransportFailure = false;
  let lastCause: "busy" | "pre-session" | "mid-session" | null = null;
  let lastCauseText = "";
  let freeEntries = 0;
  let awaitingVerdict: string[] | null = null;
  let n = 0;

  const finish = (): PackagePhaseResult => {
    evidence.elapsedMs = deps.now() - started;
    return {
      packages: requested.map((name) => ({
        name,
        alreadyPresent: alreadyPresent.get(name) ?? false,
        ...(versions.has(name) ? { installedVersion: versions.get(name) } : {}),
      })),
      evidence,
    };
  };

  const recordTransport = (e: TransportError): void => {
    evidence.transportFailures++;
    anyTransportFailure = true;
    // A lost session means the last install's verdict is not trustworthy.
    awaitingVerdict = null;
    if (e.kind === "dropped-before-auth") evidence.droppedPreauth++;
    if (e.preSession) {
      evidence.preSessionFailures++;
      lastCause = "pre-session";
      lastCauseText = e.sessionCause ?? "dropped during authentication";
    } else {
      lastCause = "mid-session";
      lastCauseText = "session lost after it may have started";
    }
  };

  // Reads the host once: busy probe under sudo, then dpkg for each pending package.
  type StateRead =
    | { kind: "busy" }
    | { kind: "transport"; error: TransportError }
    | {
      kind: "idle";
      present: Map<string, boolean>;
      versions: Map<string, string>;
    };
  const readState = async (): Promise<StateRead> => {
    evidence.entries++;
    try {
      const busy = await session.run({
        command: "bash -s --",
        stdin: busyProbeScript(),
        sudo: true,
        allowNonZero: true,
      });
      if (busy.stdout.trim() !== "idle") return { kind: "busy" };
      const present = new Map<string, boolean>();
      const found = new Map<string, string>();
      for (const name of requested) {
        const r = await session.run({
          command: `dpkg -s ${quote(name)}`,
          allowNonZero: true,
        });
        const isPresent = r.code === 0;
        present.set(name, isPresent);
        if (isPresent) {
          const v = parseDpkgVersion(r.stdout);
          if (v !== undefined) found.set(name, v);
        }
      }
      return { kind: "idle", present, versions: found };
    } catch (e) {
      if (e instanceof TransportError) return { kind: "transport", error: e };
      throw e;
    }
  };

  const isMidSession = (c: typeof lastCause): boolean => c === "mid-session";

  const giveUp = (): never => {
    const noBudget = budget === 0
      ? " (no retry budget was given, so nothing was retried)"
      : "";
    if (lastCause === "busy") {
      fail(
        "hostprep.apt-busy",
        `apt/dpkg still running after ${evidence.elapsedMs}ms of ${budget}ms; nothing was installed over it${noBudget}`,
        {
          transportFailures: evidence.transportFailures,
        },
      );
    }
    if (lastCause === "pre-session") {
      if (
        evidence.transportFailures > 0 &&
        evidence.droppedPreauth === evidence.transportFailures
      ) {
        fail(
          "hostprep.ssh-pre-session",
          `every session was dropped during authentication (${lastCauseText}); look at sshd (MaxStartups under concurrent fan-out) rather than apt or the mirror${noBudget}`,
          { transportFailures: evidence.transportFailures },
        );
      }
      fail(
        "hostprep.ssh-pre-session",
        `the install never started (${lastCauseText})${noBudget}`,
        {
          transportFailures: evidence.transportFailures,
        },
      );
    }
    fail(
      "hostprep.packages-absent",
      `still absent (confirmed by re-reading dpkg) and the last session MAY HAVE RUN${noBudget}`,
      { entries: evidence.entries },
    );
  };

  for (;;) {
    const free = freeEntries > 0;
    if (free) freeEntries--;
    if (
      evidence.entries >= maxEntries ||
      (!free && budget > 0 && deps.now() >= deadline)
    ) {
      // One extra verdict read after a mid-session loss, then give up.
      break;
    }
    const state = await readState();
    if (state.kind === "transport") {
      recordTransport(state.error);
      if (budget === 0) break;
      const wait = hostprepBackoff(n, deadline - deps.now(), deps.random);
      if (deps.now() + wait > deadline) break;
      await deps.sleep(wait);
      n++;
      continue;
    }
    if (state.kind === "busy") {
      evidence.busyWaits++;
      lastCause = "busy";
      if (budget === 0) break;
      const wait = hostprepBackoff(n, deadline - deps.now(), deps.random);
      if (deps.now() + wait > deadline) break;
      await deps.sleep(wait);
      n++;
      continue;
    }
    // Idle read: it is the first verdict for alreadyPresent.
    if (!sawFirstIdle) {
      sawFirstIdle = true;
      for (const name of requested) {
        alreadyPresent.set(name, state.present.get(name) ?? false);
      }
    }
    // apt exited 0 but dpkg still shows a package missing: do not loop.
    if (awaitingVerdict !== null) {
      const stillAbsent = awaitingVerdict.filter((name) =>
        !(state.present.get(name) ?? false)
      );
      if (stillAbsent.length > 0) {
        fail(
          "hostprep.packages-absent",
          "apt reported success but dpkg does not show the requested packages",
          { packages: stillAbsent },
        );
      }
      awaitingVerdict = null;
    }
    const missing = requested.filter((name) =>
      !(state.present.get(name) ?? false)
    );
    if (missing.length === 0) {
      for (const [k, v] of state.versions) versions.set(k, v);
      if (anyTransportFailure) evidence.confirmedAfterTransportFailure = true;
      return finish();
    }
    for (const [k, v] of state.versions) versions.set(k, v);
    // Some missing and the host is idle: update and install only the missing.
    try {
      const upd = await session.run({
        command: "apt-get update",
        sudo: true,
        allowNonZero: true,
      });
      if (upd.code !== 0 && !isAptLockContention(upd.stderr)) {
        return aptFailure("apt-get update", missing, upd.code, upd.stderr);
      }
      if (upd.code !== 0 && isAptLockContention(upd.stderr)) {
        evidence.busyWaits++;
        lastCause = "busy";
        if (budget === 0) break;
        n++;
        continue;
      }
      const install = await session.run({
        command: `apt-get install -y ${missing.map(quote).join(" ")}`,
        sudo: true,
        allowNonZero: true,
      });
      evidence.installAttempts++;
      if (install.code !== 0) {
        if (isAptLockContention(install.stderr)) {
          evidence.busyWaits++;
          lastCause = "busy";
          if (budget === 0) break;
          n++;
          continue;
        }
        return aptFailure(
          "apt-get install",
          missing,
          install.code,
          install.stderr,
        );
      }
      awaitingVerdict = missing;
    } catch (e) {
      if (e instanceof TransportError) {
        recordTransport(e);
        if (budget === 0) break;
        n++;
        continue;
      }
      if (e instanceof SudoPolicyError) throw e;
      throw e;
    }
    // Re-enter once, without sleeping; that read is the verdict.
    freeEntries++;
    continue;
  }

  // Budget or iteration bound reached, or no budget: one final verdict read.
  {
    const state = await readState();
    if (state.kind === "idle") {
      const missing = requested.filter((name) =>
        !(state.present.get(name) ?? false)
      );
      if (missing.length === 0) {
        for (const [k, v] of state.versions) versions.set(k, v);
        if (!sawFirstIdle) {
          for (const name of requested) alreadyPresent.set(name, true);
        }
        if (anyTransportFailure) evidence.confirmedAfterTransportFailure = true;
        log?.warn("Packages confirmed present only after a session had failed");
        return finish();
      }
    } else if (state.kind === "transport") {
      recordTransport(state.error);
      if (isMidSession(lastCause)) {
        fail(
          "hostprep.packages-absent",
          "outcome UNKNOWN, not a confirmed absence; nothing was re-sent; re-run (idempotent) to re-read dpkg" +
            (budget === 0
              ? " (no retry budget was given, so nothing was retried)"
              : ""),
          { entries: evidence.entries },
        );
      }
    }
  }
  return giveUp();

  function aptFailure(
    what: string,
    missing: string[],
    code: number,
    stderr: string,
  ): never {
    fail(
      "hostprep.apt-install",
      `${what} exited ${code}; this is not a connectivity problem`,
      {
        requested: requested.length,
        stillAbsent: missing,
        installedDespiteFailure: requested.length - missing.length,
        stderr: stderr.slice(0, 500),
      },
    );
  }
}

/** Parses `cephadm version` output into a health verdict against the pinned version. */
export function cephadmHealth(
  code: number,
  stdout: string,
  pinned: string,
): { healthy: boolean; token: string | null } {
  const token = code === 0 ? parseCephadmVersion(stdout) : null;
  return { healthy: token !== null && token === pinned, token };
}

/** Reads a target's cephadm version under sudo (the one probe both methods share). */
export async function probeCephadmVersion(
  session: SshSession,
  pinned: string,
): Promise<
  {
    healthy: boolean;
    token: string | null;
    code: number;
    stdout: string;
    stderr: string;
  }
> {
  const r = await session.run({
    command: `${CEPHADM_PATH} version`,
    sudo: true,
    allowNonZero: true,
  });
  const { healthy, token } = cephadmHealth(r.code, r.stdout, pinned);
  return { healthy, token, code: r.code, stdout: r.stdout, stderr: r.stderr };
}

/**
 * The remote script that downloads cephadm. The URL reaches curl only as a
 * config read from a here-document, never as an argument.
 */
export function curlDownloadScript(url: string): string {
  const breaksConfig = [...url].some((c) => {
    const code = c.charCodeAt(0);
    return code < 0x20 || code === 0x7f || c === '"' || c === "\\";
  });
  if (breaksConfig) {
    fail("validate", "invalid cephadmUrl", { field: "cephadmUrl" });
  }
  return [
    `curl --fail --silent --show-error -o ${CEPHADM_PATH} -K - <<'CEPHADM_URL_CONFIG'`,
    `url = "${url}"`,
    "CEPHADM_URL_CONFIG",
    "",
  ].join("\n");
}

/** Ensures the pinned cephadm binary is present and healthy, returning its evidence. */
export async function ensureCephadm(
  session: SshSession,
  opts: { url: string; version: string },
): Promise<
  {
    alreadyPresent: boolean;
    version: string | null;
    reinstalledBroken: boolean;
  }
> {
  assertHttpUrl("cephadmUrl", opts.url);
  assertCephadmVersion("cephadmVersion", opts.version);
  const present = await session.run({
    command: `test -x ${CEPHADM_PATH}`,
    allowNonZero: true,
  });
  let reinstalledBroken = false;
  let alreadyPresent = present.code === 0;
  if (present.code === 0) {
    const probe = await probeCephadmVersion(session, opts.version);
    if (probe.healthy) {
      return {
        alreadyPresent: true,
        version: probe.token,
        reinstalledBroken: false,
      };
    }
    reinstalledBroken = true;
    alreadyPresent = false;
  }
  // The URL travels on stdin twice over: the script itself, and inside it the
  // URL goes to curl as a config on curl's own stdin (`-K -`), so a query token
  // is on no command line, neither the ssh argv nor the remote curl's.
  const curl = await session.run({
    command: "bash -s --",
    stdin: curlDownloadScript(opts.url),
    sudo: true,
    allowNonZero: true,
  });
  if (curl.code !== 0) {
    fail("hostprep.cephadm-install", "download failed", {
      url: redactUrl(opts.url),
      cause: curl.stderr.slice(0, 300),
    });
  }
  const chmod = await session.run({
    command: `chmod +x ${CEPHADM_PATH}`,
    sudo: true,
    allowNonZero: true,
  });
  if (chmod.code !== 0) {
    fail("hostprep.cephadm-install", "chmod failed", {
      url: redactUrl(opts.url),
      cause: chmod.stderr.slice(0, 300),
    });
  }
  const recheck = await probeCephadmVersion(session, opts.version);
  if (!recheck.healthy) {
    fail(
      "hostprep.cephadm-verify",
      "the installed cephadm does not report the pinned version",
      {
        expected: opts.version,
        actual: recheck.token ?? "none",
      },
    );
  }
  return { alreadyPresent, version: recheck.token, reinstalledBroken };
}

/** Ensures a time-sync service is active, returning its evidence. */
export async function ensureTimeSync(
  session: SshSession,
  unit: string,
): Promise<{ wasActive: boolean; active: boolean }> {
  const status = async (): Promise<boolean> => {
    const r = await session.run({
      command: `systemctl is-active ${quote(unit)}`,
      allowNonZero: true,
    });
    return r.stdout.trim() === "active";
  };
  if (await status()) return { wasActive: true, active: true };
  await session.run({
    command: `systemctl enable --now ${quote(unit)}`,
    sudo: true,
    allowNonZero: true,
  });
  if (await status()) return { wasActive: false, active: true };
  fail("hostprep.time-sync", "the time-sync service is still not active", {
    service: unit,
  });
}

// ---------------------------------------------------------------------------
// Package-source pre-flight
// ---------------------------------------------------------------------------

/** One apt mirror or URL host to probe. */
export interface Endpoint {
  /** DNS name. */
  name: string;
  /** `http` or `https`. */
  scheme: string;
  /** Where it came from. */
  origin: "apt-source" | "cephadm-url";
}

/** One probed endpoint's measured outcome. */
export interface EndpointOutcome {
  /** DNS name. */
  name: string;
  /** `http` or `https`. */
  scheme: string;
  /** Where it came from. */
  origin: "apt-source" | "cephadm-url";
  /** Verdict. */
  outcome: "reached" | "cannot-resolve" | "cannot-reach";
  /** Addresses returned by getent; empty exactly when `cannot-resolve`. */
  addresses: string[];
  /** HTTP status when observed. */
  httpStatus?: string;
  /** curl's exit code when it failed. */
  curlExit?: number;
}

/** Adds an http(s) URL's scheme and hostname to `out`, deduplicated and in order. */
function addUrl(out: Endpoint[], raw: string): void {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    return;
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") return;
  const name = url.hostname.toLowerCase();
  // A discovered name is host-file content and is treated as untrusted.
  if (name === "" || !HOSTNAME_RE.test(name)) return;
  const scheme = url.protocol.slice(0, -1);
  if (out.some((e) => e.name === name && e.scheme === scheme)) return;
  out.push({ name, scheme, origin: "apt-source" });
}

/** Strips credentials from one apt proxy configuration line before storing it. */
export function sanitizeProxyLine(line: string): string {
  return line
    // Remove userinfo from any URL, quoted or not.
    .replace(/([A-Za-z][A-Za-z0-9+.-]*:\/\/)[^@\s"]*@/g, "$1")
    // Redact a value assigned to a secret-shaped key, quoted or bare.
    .replace(
      /(password|passwd|secret|token|user)[ \t]*=[ \t]*("[^"]*"|'[^']*'|\S+)/gi,
      "$1=<redacted>",
    )
    // Belt and braces: any remaining `user:pass@` inside a URL.
    .replace(/([A-Za-z][A-Za-z0-9+.-]*:\/\/)[^\s"]*:(\S+)@/g, "$1<redacted>@");
}

/** Parses apt sources in both one-line and deb822 formats. */
export function parseAptSources(text: string): Endpoint[] {
  const out: Endpoint[] = [];
  for (const rawLine of text.split("\n")) {
    const line = rawLine.trim();
    if (line === "" || line.startsWith("#")) continue;
    const uris = line.match(/^URIs:\s*(.+)$/i);
    if (uris) {
      for (const uri of uris[1].trim().split(/\s+/)) addUrl(out, uri);
      continue;
    }
    const oneLine = line.match(/^deb(?:-src)?\s+(?:\[[^\]]*\]\s+)?(\S+)/);
    if (oneLine) addUrl(out, oneLine[1]);
  }
  return out;
}

/** The name of the discovery markers the probe script uses. */
export const SECTION_MARKERS = {
  sources: "###CEPHADM-SOURCES###",
  proxy: "###CEPHADM-PROXY###",
  probes: "###CEPHADM-PROBES###",
} as const;

/** The discovery script: apt sources, proxy lines, and an empty probe section. */
export function discoveryScript(): string {
  return [
    `echo '${SECTION_MARKERS.sources}'`,
    "cat /etc/apt/sources.list /etc/apt/sources.list.d/*.list /etc/apt/sources.list.d/*.sources 2>/dev/null || true",
    `echo '${SECTION_MARKERS.proxy}'`,
    "apt-config dump 2>/dev/null | grep -i proxy || true",
    `echo '${SECTION_MARKERS.probes}'`,
  ].join("\n");
}

/** Splits discovery output into sections; lines under an unknown marker are discarded. */
export function splitSections(
  stdout: string,
): { sources: string; proxy: string } {
  const sources: string[] = [];
  const proxy: string[] = [];
  let current: "sources" | "proxy" | "other" = "other";
  for (const line of stdout.split("\n")) {
    if (line.trim() === SECTION_MARKERS.sources) {
      current = "sources";
      continue;
    }
    if (line.trim() === SECTION_MARKERS.proxy) {
      current = "proxy";
      continue;
    }
    if (line.trim() === SECTION_MARKERS.probes) {
      current = "other";
      continue;
    }
    // A marker we do not know starts a section we discard, rather than
    // filing its lines under the previous section.
    if (line.trim().startsWith("###")) {
      current = "other";
      continue;
    }
    if (current === "sources") sources.push(line);
    else if (current === "proxy") proxy.push(line);
  }
  return { sources: sources.join("\n"), proxy: proxy.join("\n") };
}

/** The default port for a scheme, used when stripping a URL host. */
export function hostOfUrl(
  raw: string,
): { name: string; scheme: string } | null {
  try {
    const url = new URL(raw);
    if (url.protocol !== "http:" && url.protocol !== "https:") return null;
    if (url.hostname === "") return null;
    return {
      name: url.hostname.toLowerCase(),
      scheme: url.protocol.slice(0, -1),
    };
  } catch {
    return null;
  }
}

/** The probe script for a set of endpoints; sends no sudo and mutates nothing. */
export function probeScript(endpoints: Endpoint[]): string {
  const lines: string[] = [];
  for (const e of endpoints) {
    // Defense in depth: never assemble a script from a name that is not a host.
    if (
      !HOSTNAME_RE.test(e.name) || (e.scheme !== "http" && e.scheme !== "https")
    ) continue;
    lines.push(`name=${quote(e.name)}`);
    lines.push(`scheme=${quote(e.scheme)}`);
    lines.push(
      'addrs="$(getent hosts "$name" 2>/dev/null | awk \'{print $1}\' | paste -sd, -)"',
    );
    lines.push('if [ -z "$addrs" ]; then');
    lines.push('  printf \'%s|%s|||\\n\' "$name" "$scheme"');
    lines.push("else");
    lines.push("  code=0");
    lines.push(
      '  status="$(curl -sS -o /dev/null -w \'%{http_code}\' --max-time 10 -I "$scheme://$name/" 2>/dev/null)" || code=$?',
    );
    lines.push(
      '  printf \'%s|%s|%s|%s|%s\\n\' "$name" "$scheme" "$addrs" "$code" "$status"',
    );
    lines.push("fi");
  }
  return lines.join("\n");
}

/** Parses one probe line; malformed lines (fewer than four fields) yield null. */
export function parseProbeLine(
  line: string,
): {
  name: string;
  scheme: string;
  addresses: string[];
  curlExit: string;
  httpStatus: string;
} | null {
  const fields = line.split("|");
  if (fields.length < 4) return null;
  const [name, scheme, addrField, curlExit, httpStatus = ""] = fields;
  if (name === "" || scheme === "") return null;
  const addresses = addrField.split(",").map((a) => a.trim()).filter((a) =>
    a !== ""
  );
  return { name, scheme, addresses, curlExit, httpStatus };
}

/** Classifies a probe line into an outcome. */
export function classifyProbe(
  parsed: NonNullable<ReturnType<typeof parseProbeLine>>,
  origin: "apt-source" | "cephadm-url",
): EndpointOutcome {
  if (parsed.addresses.length === 0) {
    return {
      name: parsed.name,
      scheme: parsed.scheme,
      origin,
      outcome: "cannot-resolve",
      addresses: [],
    };
  }
  const failed = parsed.curlExit !== "" && parsed.curlExit !== "0";
  const noStatus = parsed.httpStatus === "" || parsed.httpStatus === "000";
  if (failed || noStatus) {
    return {
      name: parsed.name,
      scheme: parsed.scheme,
      origin,
      outcome: "cannot-reach",
      addresses: parsed.addresses,
      ...(parsed.curlExit !== "" ? { curlExit: Number(parsed.curlExit) } : {}),
    };
  }
  return {
    name: parsed.name,
    scheme: parsed.scheme,
    origin,
    outcome: "reached",
    addresses: parsed.addresses,
    httpStatus: parsed.httpStatus,
  };
}

/** Builds the human finding for a non-reached endpoint. */
export function findingFor(outcome: EndpointOutcome): string {
  if (outcome.outcome === "cannot-resolve") {
    return `${outcome.name} (${outcome.scheme}): DNS on the target did not resolve it; check the resolver, stub or search domain, not the mirror`;
  }
  return `${outcome.name} (${outcome.scheme}): resolved to ${
    outcome.addresses.join(", ")
  } but nothing answered; check routing, firewall or the mirror itself, not DNS${
    outcome.curlExit !== undefined ? ` (curl exit ${outcome.curlExit})` : ""
  }`;
}

/** Runtime re-validation of the cephadm URL against both allowed schemes. */
export function cephadmUrlHost(url: string): Endpoint {
  assertHttpUrl("cephadmUrl", url);
  const parsed = hostOfUrl(url);
  if (parsed === null) {
    fail("validate", "invalid cephadmUrl", { field: "cephadmUrl" });
  }
  return { name: parsed.name, scheme: parsed.scheme, origin: "cephadm-url" };
}
