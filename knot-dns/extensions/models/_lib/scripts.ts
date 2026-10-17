/**
 * Host-side shell scripts for the Knot DNS model and the parsers for what
 * they print.
 *
 * Every script is a single `sh -c` command whose text contains only fixed
 * paths and values that were validated by the schemas. A script prints
 * `key=value` lines (and, where needed, a delimited record dump) that the
 * model parses. The apply script validates, backs up, swaps and reloads under
 * `flock`, and keeps the backup until the caller verifies the served records;
 * on any failure it restores the previous files before failing.
 *
 * @module
 */

import type { DiffEntry } from "./zone.ts";
import { parseZoneRead } from "./parse.ts";
import {
  OWN_ALL_FN,
  QUERY_OK_FN,
  RESTART_KNOT_FN,
  shq,
  underLock,
  WAIT_LOADED_FN,
} from "./fragments.ts";

/** Fixed on-host paths. */
const KNOT_CONF = "/etc/knot/knot.conf";
const KNOT_CONF_DIR = "/etc/knot/knot.conf.d";
const ZONE_DIR = "/var/lib/knot/zones";
const INCLUDE_LINE = `include: ${KNOT_CONF_DIR}/*.conf`;
/** Host-global authoritative listen fragment. */
const LISTEN_FRAGMENT = `${KNOT_CONF_DIR}/40-managed-listen.conf`;
/** Staged host-global listen fragment for one run (names never collide). */
export function stagedListen(run: string): string {
  return `${KNOT_CONF_DIR}/.40-managed-listen.${runToken(run)}.conf.staged`;
}

/** Restricts a run id to a filesystem-safe token. */
function runToken(run: string): string {
  if (!/^[A-Za-z0-9]{1,32}$/.test(run)) throw new Error("invalid run id");
  return run;
}
/** Lock shared by every zone-modifying script. */
const KNOT_LOCK = "/run/knot-dns.lock";

/** Makes a filesystem-safe token from an apex. */
function apexToken(apex: string): string {
  return apex.replace(/\.$/, "").replace(/[^A-Za-z0-9.-]/g, "_");
}

/** The live paths for one zone; staged names carry the run id when given. */
export function zonePaths(apex: string, run?: string) {
  const token = apexToken(apex);
  const r = run === undefined ? "" : `.${runToken(run)}`;
  return {
    zoneFile: `${ZONE_DIR}/${token}.zone`,
    fragment: `${KNOT_CONF_DIR}/50-managed-${token}.conf`,
    tsigFragment: `${KNOT_CONF_DIR}/10-managed-tsig-${token}.conf`,
    stagedZone: `${ZONE_DIR}/.${token}.zone${r}.staged`,
    stagedFragment: `${KNOT_CONF_DIR}/.50-managed-${token}${r}.conf.staged`,
    stagedTsig: `${KNOT_CONF_DIR}/.10-managed-tsig-${token}${r}.conf.staged`,
  };
}

/** Parses `key=value` lines into a record. */
export function parseKeyValues(text: string): Record<string, string> {
  const out: Record<string, string> = {};
  for (const line of text.split("\n")) {
    const eq = line.indexOf("=");
    if (eq <= 0) continue;
    const key = line.slice(0, eq).trim();
    if (!/^[a-z_]+$/.test(key)) continue;
    out[key] = line.slice(eq + 1);
  }
  return out;
}

/** Restores a file from the backup directory, or removes it. */
function restoreLine(backupVar: string, path: string): string {
  return `if [ -f "${backupVar}" ]; then mv "${backupVar}" ${path}; else rm -f ${path}; fi`;
}

/**
 * Precheck that each requested listen address/port is free or held by Knot.
 * `ss -H` drops the header; `-p` adds the owning process, which is how a
 * socket already held by knotd is told apart from a foreign one. A socket
 * whose owner cannot be seen counts as foreign, so an unprivileged probe
 * fails closed.
 */
export function portCheckScript(listens: string[]): string {
  const wants = listens.map(shq).join(" ");
  return [
    "set -eu",
    "rc=0",
    `for want in ${wants}; do`,
    "  waddr=${want%@*}; wport=${want#*@}",
    '  [ "$want" = "$waddr" ] && wport=53',
    "  ss=$(ss -lntupH) || { echo PROBE_FAILED >&2; exit 11; }",
    '  foreign=$(printf \'%s\\n\' "$ss" | awk -v a="$waddr" -v p="$wport" \'',
    '    { loc=$5; n=split(loc, x, ":"); port=x[n]; addr=loc; sub(":" port "$", "", addr);',
    '      gsub(/[][]/, "", addr)',
    '      if (port==p && (addr==a || addr=="0.0.0.0" || addr=="*" || addr=="::" || a=="0.0.0.0" || a=="::") && $0 !~ /users:\\(\\("knotd"/) print addr ":" port }\')',
    '  if [ -n "$foreign" ]; then echo "PORT_BUSY ${waddr}:${wport}" >&2; rc=1; fi',
    "done",
    '[ "$rc" = 0 ] || exit 9',
  ].join("\n");
}

/** Variables, helper functions and rollback shared by the zone mutators. */
function zoneHead(
  opts: { apex: string; run: string; reloadZone: boolean },
): string[] {
  const p = zonePaths(opts.apex, opts.run);
  return [
    "set -eu",
    `apex=${shq(opts.apex)}`,
    `z=${shq(p.zoneFile)}; zst=${shq(p.stagedZone)}`,
    `f=${shq(p.fragment)}; fst=${shq(p.stagedFragment)}`,
    `t=${shq(p.tsigFragment)}; tst=${shq(p.stagedTsig)}`,
    `l=${shq(LISTEN_FRAGMENT)}; lst=${shq(stagedListen(opts.run))}`,
    `zc=${shq(KNOT_CONF)}`,
    `reload_zone=${opts.reloadZone ? "yes" : "no"}`,
    "listen_changed=no",
    // Staged names are per-run, so whatever the run did not consume is removed
    // rather than left to accumulate.
    "cleanup() {",
    '  rm -f "$zst" "$fst" "$tst" "$lst"',
    '  if [ -n "${tmp:-}" ]; then rm -rf "${tmp:?}"; fi',
    "}",
    "trap cleanup EXIT",
    OWN_ALL_FN,
    RESTART_KNOT_FN,
    WAIT_LOADED_FN,
    // Listen changes need a restart; everything else a reload.
    "reload_knot() {",
    '  if [ "$listen_changed" = yes ]; then restart_knot; return; fi',
    "  knotc reload || return 1",
    '  [ "$reload_zone" = no ] && return 0',
    '  knotc zone-reload "$apex" && wait_loaded "$apex"',
    "}",
    // Puts the backup back and reloads. When the reload itself fails the
    // backup is kept so the operator can restore by hand.
    "rollback() {",
    `  ${restoreLine('"$b/z"', '"$z"')}`,
    `  ${restoreLine('"$b/f"', '"$f"')}`,
    `  ${restoreLine('"$b/t"', '"$t"')}`,
    `  ${restoreLine('"$b/l"', '"$l"')}`,
    '  if reload_knot; then rm -rf "${b:?}"; echo "$1" >&2; exit "$2"; fi',
    '  echo "$1 RESTORE_RELOAD_FAILED backup=$b" >&2; exit 13',
    "}",
    // Sets listen_changed when the live listen fragment must differ from the
    // staged one (a staged empty file means "no listen fragment").
    "listen_diff() {",
    '  want_listen=no; [ -s "$lst" ] && want_listen=yes',
    '  if [ "$want_listen" = yes ]; then',
    '    if [ ! -f "$l" ] || ! cmp -s "$l" "$lst"; then listen_changed=yes; fi',
    '  elif [ -f "$l" ]; then listen_changed=yes; fi',
    "}",
  ];
}

/** Copies the live config plus staged fragments into a throwaway conf dir. */
const CONF_CHECK_LINES = [
  "tmp=$(mktemp -d)",
  'mkdir -p "$tmp/conf.d"',
  `sed "s#${KNOT_CONF_DIR}/\\\\*\\\\.conf#$tmp/conf.d/*.conf#" "$zc" > "$tmp/knot.conf"`,
  `for g in ${KNOT_CONF_DIR}/*.conf; do [ -e "$g" ] || continue; [ "$g" = "$f" ] && continue; [ "$g" = "$t" ] && continue; [ "$g" = "$l" ] && continue; cp "$g" "$tmp/conf.d/"; done`,
  'cp "$fst" "$tmp/conf.d/50-managed-zones.conf"',
  'if [ -s "$tst" ]; then cp "$tst" "$tmp/conf.d/10-managed-tsig.conf"; fi',
  'if [ "$want_listen" = yes ]; then cp "$lst" "$tmp/conf.d/40-managed-listen.conf"; fi',
  `knotc -c "$tmp/knot.conf" conf-check || { echo CONFCHECK_FAILED >&2; exit 4; }`,
];

/** Copies each live file into the backup dir `$b`, ignoring absent ones. */
const BACKUP_LINES = [
  "b=$(mktemp -d)",
  'cp -a "$z" "$b/z" 2>/dev/null || true',
  'cp -a "$f" "$b/f" 2>/dev/null || true',
  'cp -a "$t" "$b/t" 2>/dev/null || true',
  'cp -a "$l" "$b/l" 2>/dev/null || true',
];

/**
 * Script that validates, backs up, swaps, reloads and dumps one zone (and the
 * host-global listen fragment and the per-zone TSIG fragment) under flock. The
 * backup directory is kept until the caller verifies the served records. A
 * changed listen fragment restarts knotd and every listen address is then
 * queried for the zone; any failure restores the previous files.
 */
export function applyZoneScript(
  opts: { apex: string; run: string; listens: string[] },
): string {
  const inner = [
    ...zoneHead({ apex: opts.apex, run: opts.run, reloadZone: true }),
    QUERY_OK_FN,
    `listens=${shq(opts.listens.join(" "))}`,
    `[ -f "$zc" ] || { echo INCLUDE_MISSING >&2; exit 3; }`,
    `grep -qF ${
      shq(INCLUDE_LINE)
    } "$zc" || { echo INCLUDE_MISSING >&2; exit 3; }`,
    `[ -f "$zst" ] || { echo STAGE_MISSING >&2; exit 3; }`,
    `[ -f "$fst" ] || { echo STAGE_MISSING >&2; exit 3; }`,
    `command -v kdig >/dev/null 2>&1 || { echo KDIG_MISSING >&2; exit 3; }`,
    `command -v kzonecheck >/dev/null 2>&1 || { echo KZONECHECK_MISSING >&2; exit 3; }`,
    `kzonecheck -o "$apex" "$zst" || { echo KZONECHECK_FAILED >&2; exit 4; }`,
    "listen_diff",
    ...CONF_CHECK_LINES,
    "changed=$listen_changed",
    `if [ ! -f "$z" ] || ! cmp -s "$z" "$zst"; then changed=yes; fi`,
    `if [ ! -f "$f" ] || ! cmp -s "$f" "$fst"; then changed=yes; fi`,
    'if [ -s "$tst" ]; then if [ ! -f "$t" ] || ! cmp -s "$t" "$tst"; then changed=yes; fi; elif [ -f "$t" ]; then changed=yes; fi',
    ...BACKUP_LINES,
    'if [ "$changed" = yes ]; then',
    '  mv "$zst" "$z"; mv "$fst" "$f"',
    '  if [ -s "$tst" ]; then mv "$tst" "$t"; else rm -f "$t" "$tst"; fi',
    '  if [ "$want_listen" = yes ]; then mv "$lst" "$l"; else rm -f "$l" "$lst"; fi',
    '  own_all "$z" "$f" "$l" "$t" || rollback CHOWN_FAILED 10',
    "  reload_knot || rollback RELOAD_FAILED 5",
    "fi",
    "for want in $listens; do",
    '  query_ok "$want" "$apex" SOA NOERROR && continue',
    '  if [ "$changed" = yes ]; then rollback VERIFY_QUERY_FAILED 14; fi',
    '  rm -rf "${b:?}"; echo VERIFY_QUERY_FAILED >&2; exit 14',
    "done",
    'echo "backup=$b"',
    'echo "changed=$changed"',
    "serial=$(knotc zone-status \"$apex\" 2>/dev/null | sed -n 's/.*serial: *\\([0-9]*\\).*/\\1/p' | head -1) || serial=",
    'echo "serial=${serial:-}"',
    "echo ZONE_READ_BEGIN",
    `knotc zone-read "$apex" 2>/dev/null || true`,
    "echo ZONE_READ_END",
  ].join("\n");
  return underLock(KNOT_LOCK, inner);
}

/** Restores the files a failed apply kept in `backup`, then reloads. */
export function restoreZoneScript(
  opts: { apex: string; backup: string },
): string {
  const inner = [
    ...zoneHead({ apex: opts.apex, run: "restore", reloadZone: true }),
    `b=${shq(opts.backup)}`,
    `[ -d "$b" ] || { echo NO_BACKUP >&2; exit 3; }`,
    // A restore that brings back a different listen fragment needs a restart.
    'if [ -f "$b/l" ]; then',
    '  if [ ! -f "$l" ] || ! cmp -s "$l" "$b/l"; then listen_changed=yes; fi',
    'elif [ -f "$l" ]; then listen_changed=yes; fi',
    `${restoreLine('"$b/z"', '"$z"')}`,
    `${restoreLine('"$b/f"', '"$f"')}`,
    `${restoreLine('"$b/t"', '"$t"')}`,
    `${restoreLine('"$b/l"', '"$l"')}`,
    'own_all "$z" "$f" "$l" "$t" || { echo CHOWN_FAILED >&2; exit 10; }',
    "reload_knot || { echo RESTORE_RELOAD_FAILED >&2; exit 13; }",
    'rm -rf "${b:?}"',
    "echo restored=yes",
  ].join("\n");
  return underLock(KNOT_LOCK, inner);
}

/** Removes a backup directory kept by a successful apply. */
export function finalizeZoneScript(backup: string): string {
  return `set -eu\nrm -rf ${shq(backup)}\necho discarded=yes`;
}

/**
 * Script that removes one zone's file, fragment and TSIG fragment and moves
 * the host-global listen fragment to the staged one (what the remaining zones
 * still need), restarting knotd when that changes.
 */
export function removeZoneScript(opts: {
  apex: string;
  run: string;
  purgeKeysAck: boolean;
  unsigned: boolean;
}): string {
  const purge = opts.purgeKeysAck
    ? `knotc zone-purge "$apex" 2>/dev/null || true`
    : "true";
  const inner = [
    ...zoneHead({ apex: opts.apex, run: opts.run, reloadZone: false }),
    "present=no",
    '[ -f "$f" ] && present=yes',
    `if [ "$present" = no ]; then echo "removed=no"; exit 0; fi`,
    'if [ -f "$z" ]; then',
    `  signed=$(grep -c 'dnssec-signing: on' "$f" 2>/dev/null || true)`,
    `  if [ "$signed" != "0" ] && [ ${
      opts.unsigned ? "0" : "1"
    } = 1 ]; then echo DNSSEC_UNSIGN_ACK_REQUIRED >&2; exit 6; fi`,
    "fi",
    "listen_diff",
    ...BACKUP_LINES,
    'rm -f "$z" "$f" "$t"',
    'if [ "$want_listen" = yes ]; then mv "$lst" "$l"; else rm -f "$l" "$lst"; fi',
    'own_all "$l" || rollback CHOWN_FAILED 10',
    "reload_knot || rollback RELOAD_FAILED 5",
    'rm -rf "${b:?}"',
    purge,
    'echo "removed=yes"',
  ].join("\n");
  return underLock(KNOT_LOCK, inner);
}

/** Script that prints the DS records for a zone. */
export function getDsScript(apex: string): string {
  return [
    "set -eu",
    "echo DS_BEGIN",
    `keymgr ${shq(apex)} ds 2>/dev/null || true`,
    "echo DS_END",
  ].join("\n");
}

/** Script that tells Knot the KSK's DS is at the parent. */
export function kskSubmittedScript(apex: string): string {
  return [
    "set -eu",
    `[ -f ${
      shq(zonePaths(apex).fragment)
    } ] || { echo ZONE_ABSENT >&2; exit 3; }`,
    `knotc -b zone-ksk-submitted ${shq(apex)} >/dev/null`,
    "echo submitted=yes",
  ].join("\n");
}

/**
 * Script that validates, swaps and reloads the resolver configuration, then
 * asks the resolver itself (on its listen port) for `testName`. kdig exits 0
 * on SERVFAIL, so the reply's rcode is checked; NXDOMAIN is accepted because
 * a private forward zone may legitimately have no SOA at the apex.
 */
export function applyResolverScript(opts: {
  liveYaml: string;
  packageBackup: string;
  stagedYaml: string;
  testListen: string;
  testName: string;
}): string {
  const restore = [
    '[ -s "$b" ] && mv "$b" "$live" || rm -f "$live"',
    "systemctl restart knot-resolver 2>/dev/null || true",
    'rm -f "$b"',
  ].join("; ");
  const inner = [
    "set -eu",
    QUERY_OK_FN,
    `live=${shq(opts.liveYaml)}; st=${shq(opts.stagedYaml)}`,
    `pkg=${shq(opts.packageBackup)}`,
    // The staged file is removed on every exit: a failed run leaves nothing.
    `trap 'rm -f "$st"' EXIT`,
    `[ -f "$st" ] || { echo STAGE_MISSING >&2; exit 3; }`,
    `command -v kdig >/dev/null 2>&1 || { echo KDIG_MISSING >&2; exit 3; }`,
    `command -v kresctl >/dev/null 2>&1 || { echo KRESCTL_MISSING >&2; exit 3; }`,
    `kresctl validate "$st" || { echo KRESCTL_FAILED >&2; exit 4; }`,
    `if [ -f "$live" ] && [ ! -f "$pkg" ]; then cp -a "$live" "$pkg"; fi`,
    "changed=yes",
    `if [ -f "$live" ] && cmp -s "$live" "$st"; then changed=no; fi`,
    "b=$(mktemp)",
    'cp -a "$live" "$b" 2>/dev/null || true',
    // install leaves the service disabled so it cannot fight knotd for the
    // package's default listen address.
    "systemctl enable knot-resolver >/dev/null 2>&1 || true",
    'if [ "$changed" = yes ]; then',
    '  mv "$st" "$live"',
    "  if ! systemctl reload knot-resolver 2>/dev/null && ! systemctl restart knot-resolver 2>/dev/null; then",
    `    ${restore}; echo RELOAD_FAILED >&2; exit 5`,
    "  fi",
    "fi",
    `if ! query_ok ${shq(opts.testListen)} ${
      shq(opts.testName)
    } SOA NOERROR NXDOMAIN; then`,
    `  ${restore}; echo TEST_QUERY_FAILED >&2; exit 7`,
    "fi",
    'rm -f "$b"',
    'echo "changed=$changed"',
  ].join("\n");
  return underLock("/run/knot-resolver.lock", inner);
}

/** Script that stops the resolver and restores the package configuration. */
export function removeResolverScript(opts: {
  liveYaml: string;
  packageBackup: string;
}): string {
  return [
    "set -eu",
    `live=${shq(opts.liveYaml)}; pkg=${shq(opts.packageBackup)}`,
    "if ! command -v kresctl >/dev/null 2>&1 && [ ! -f \"$live\" ]; then echo 'removed=no'; exit 0; fi",
    "if ! systemctl disable --now knot-resolver 2>/dev/null; then echo STOP_FAILED >&2; exit 8; fi",
    'if [ -f "$pkg" ]; then mv "$pkg" "$live"; else rm -f "$live"; fi',
    "echo 'removed=yes'",
  ].join("\n");
}

/** Script that lists the apex of every model-managed zone fragment. */
export function discoverZonesScript(): string {
  return [
    "set -eu",
    `for f in ${KNOT_CONF_DIR}/50-managed-*.conf; do`,
    '  [ -e "$f" ] || continue',
    "  sed -n 's/^ *- *domain: *//p' \"$f\" | head -1",
    "done",
  ].join("\n");
}

/** Script that reports the resolver service and listen configuration. */
export function resolverObserveScript(): string {
  return [
    "set -eu",
    "active=$(systemctl is-active knot-resolver 2>/dev/null || true)",
    'echo "active=$active"',
    "echo RESOLVER_BEGIN",
    "cat /etc/knot-resolver/config.yaml 2>/dev/null || true",
    "echo RESOLVER_END",
  ].join("\n");
}

/**
 * Captures a probe's output and fails the script when the probe itself fails;
 * testing a downstream `head`/`awk` would hide the producer's failure.
 */
function probe(variable: string, command: string): string {
  return `${variable}=$(${command}) || { echo PROBE_FAILED >&2; exit 11; }`;
}

/** Script that dumps every managed zone's served records and status under flock. */
export function observeScript(apexes: string[]): string {
  const inner = [
    "set -eu",
    ...apexes.flatMap((apex) => {
      const p = zonePaths(apex);
      return [
        `echo ${shq(`ZONE ${apex}`)}`,
        `if [ -f ${shq(p.fragment)} ]; then`,
        `  ${probe("status", `knotc zone-status ${shq(apex)} 2>/dev/null`)}`,
        `  serial=$(printf '%s\\n' "$status" | sed -n 's/.*serial: *\\([0-9]*\\).*/\\1/p' | head -1)`,
        `  sha=`,
        `  if [ -f ${shq(p.zoneFile)} ]; then`,
        `    ${probe("sum", `sha256sum ${shq(p.zoneFile)}`)}`,
        `    sha=\${sum%% *}`,
        `  fi`,
        `  echo "serial=\${serial:-}"`,
        `  echo "file_sha=\${sha:-}"`,
        `  echo KEY_BEGIN`,
        `  keymgr ${shq(apex)} list 2>/dev/null || true`,
        `  echo KEY_END`,
        `  echo ZONE_READ_BEGIN`,
        `  knotc zone-read ${shq(apex)} 2>/dev/null || true`,
        `  echo ZONE_READ_END`,
        `else echo "missing=yes"; fi`,
      ];
    }),
  ].join("\n");
  return underLock(KNOT_LOCK, inner);
}

/** Extracts the text between two marker lines. */
export function between(text: string, begin: string, end: string): string {
  const b = text.indexOf(begin);
  if (b === -1) return "";
  const e = text.indexOf(end, b + begin.length);
  if (e === -1) return "";
  return text.slice(b + begin.length, e).replace(/^\n/, "");
}

/** Parses a `zone-read` dump (all types) into canonical tuples. */
export function parseServed(text: string, apex: string): DiffEntry[] {
  return parseZoneRead(
    between(text, "ZONE_READ_BEGIN", "ZONE_READ_END"),
    apex,
  );
}
