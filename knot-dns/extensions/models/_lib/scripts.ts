/**
 * Host-side shell scripts for the Knot DNS model and the parsers for what
 * they print.
 *
 * Every script is a single `sh -c` command whose text contains only fixed
 * paths and values that were validated by the schemas, so no untrusted text is
 * interpolated. A script prints `key=value` lines (and, where needed, a
 * delimited record dump) that the model parses. On a reload error the previous
 * files are restored before the script fails; on a verify mismatch the caller
 * runs {@link restoreZoneScript} with the backup directory the apply script
 * printed, so nothing new is left live.
 *
 * @module
 */

import type { DiffEntry } from "./zone.ts";
import { parseZoneRead } from "./parse.ts";

/** Fixed on-host paths. */
export const KNOT_CONF = "/etc/knot/knot.conf";
export const KNOT_CONF_DIR = "/etc/knot/knot.conf.d";
export const ZONE_DIR = "/var/lib/knot/zones";
export const INCLUDE_LINE = `include: ${KNOT_CONF_DIR}/*.conf`;

/** Makes a filesystem-safe token from an apex. */
export function apexToken(apex: string): string {
  return apex.replace(/\.$/, "").replace(/[^A-Za-z0-9.-]/g, "_");
}

/** The live paths for one zone. */
export function zonePaths(apex: string) {
  const token = apexToken(apex);
  return {
    zoneFile: `${ZONE_DIR}/${token}.zone`,
    fragment: `${KNOT_CONF_DIR}/50-managed-${token}.conf`,
    tsigFragment: `${KNOT_CONF_DIR}/10-managed-tsig-${token}.conf`,
    stagedZone: `${ZONE_DIR}/.${token}.zone.staged`,
    stagedFragment: `${KNOT_CONF_DIR}/.50-managed-${token}.conf.staged`,
    stagedTsig: `${KNOT_CONF_DIR}/.10-managed-tsig-${token}.conf.staged`,
  };
}

/** POSIX single-quotes a value for a script literal. */
export function shq(value: string): string {
  return `'${value.replace(/'/g, `'\\''`)}'`;
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

/** Script that installs Knot (and optionally Knot Resolver 6) and the include. */
export function installScript(opts: { resolver: boolean }): string {
  const lines = [
    "set -eu",
    "export DEBIAN_FRONTEND=noninteractive",
    "if ! command -v knotc >/dev/null 2>&1; then apt-get update -qq; apt-get install -y -qq knot; fi",
    `mkdir -p ${shq(KNOT_CONF_DIR)} ${shq(ZONE_DIR)}`,
    "command -v chown >/dev/null 2>&1 && chown knot:knot /var/lib/knot/zones 2>/dev/null || true",
    `touch ${shq(KNOT_CONF)}`,
    `if ! grep -qF ${shq(INCLUDE_LINE)} ${
      shq(KNOT_CONF)
    }; then printf '%s\\n' ${shq(INCLUDE_LINE)} >> ${shq(KNOT_CONF)}; fi`,
  ];
  if (opts.resolver) {
    lines.push(
      "if ! command -v kresctl >/dev/null 2>&1; then",
      "  apt-get install -y -qq knot-resolver6 || apt-get install -y -qq knot-resolver",
      "fi",
      "mkdir -p /etc/knot-resolver",
      "systemctl enable --now knot-resolver 2>/dev/null || true",
    );
  }
  lines.push(
    "systemctl enable --now knot 2>/dev/null || true",
    "kv=$(knotc --version 2>/dev/null | head -1 || true)",
    'echo "knot_version=$kv"',
    "rv=$(command -v kresd >/dev/null 2>&1 && kresd --version 2>/dev/null | head -1 || true)",
    'echo "kresd_version=$rv"',
  );
  return lines.join("\n");
}

/** Grants the Knot user read access to a model-managed file. */
const CHGRP =
  'chown root:knot "$1" 2>/dev/null || chgrp knot "$1" 2>/dev/null || true';

/**
 * Script that validates, backs up, swaps, reloads and dumps one zone under
 * flock. The backup directory is kept until the caller verifies the served
 * records; it is printed as `backup=<dir>`.
 */
export function applyZoneScript(opts: {
  apex: string;
  signed: boolean;
  hasTsig: boolean;
}): string {
  const p = zonePaths(opts.apex);
  const dcheck = opts.signed ? " -d on" : "";
  const inner = [
    "set -eu",
    `apex=${shq(opts.apex)}`,
    `z=${shq(p.zoneFile)}; zst=${shq(p.stagedZone)}`,
    `f=${shq(p.fragment)}; fst=${shq(p.stagedFragment)}`,
    `t=${shq(p.tsigFragment)}; tst=${shq(p.stagedTsig)}`,
    `zc=${shq(KNOT_CONF)}`,
    `[ -f "$zc" ] || { echo INCLUDE_MISSING >&2; exit 3; }`,
    `grep -qF ${
      shq(INCLUDE_LINE)
    } "$zc" || { echo INCLUDE_MISSING >&2; exit 3; }`,
    `[ -f "$zst" ] || { echo STAGE_MISSING >&2; exit 3; }`,
    `[ -f "$fst" ] || { echo STAGE_MISSING >&2; exit 3; }`,
    `kzonecheck${dcheck} -o "$apex" "$zst" || { echo KZONECHECK_FAILED >&2; exit 4; }`,
    "tmp=$(mktemp -d); trap 'rm -rf \"$tmp\"' EXIT",
    'mkdir -p "$tmp/conf.d"',
    `sed "s#${KNOT_CONF_DIR}/\\\\*\\\\.conf#$tmp/conf.d/*.conf#" "$zc" > "$tmp/knot.conf"`,
    `for g in ${KNOT_CONF_DIR}/*.conf; do [ -e "$g" ] || continue; [ "$g" = "$f" ] && continue; [ "$g" = "$t" ] && continue; cp "$g" "$tmp/conf.d/"; done`,
    'cp "$fst" "$tmp/conf.d/50-managed-zones.conf"',
    `if [ -f "$tst" ]; then cp "$tst" "$tmp/conf.d/10-managed-tsig.conf"; fi`,
    `knotc -c "$tmp/knot.conf" conf-check || { echo CONFCHECK_FAILED >&2; exit 4; }`,
    "changed=yes",
    `if [ -f "$z" ] && cmp -s "$z" "$zst" && [ -f "$f" ] && cmp -s "$f" "$fst"; then changed=no; fi`,
    "b=$(mktemp -d)",
    'cp -a "$z" "$b/z" 2>/dev/null || true',
    'cp -a "$f" "$b/f" 2>/dev/null || true',
    'cp -a "$t" "$b/t" 2>/dev/null || true',
    'if [ "$changed" = yes ]; then',
    '  mv "$zst" "$z"; mv "$fst" "$f"',
    `  if [ -f "$tst" ]; then mv "$tst" "$t"; fi`,
    `  for x in "$z" "$f"; do ${CHGRP}; done`,
    `  [ -f "$t" ] && chown root:knot "$t" 2>/dev/null || true`,
    '  if ! knotc -b reload || ! knotc -b zone-reload "$apex"; then',
    '    [ -f "$b/z" ] && mv "$b/z" "$z" || rm -f "$z"',
    '    [ -f "$b/f" ] && mv "$b/f" "$f" || rm -f "$f"',
    '    [ -f "$b/t" ] && mv "$b/t" "$t" || rm -f "$t"',
    "    knotc -b reload 2>/dev/null || true",
    '    rm -rf "$b"; echo RELOAD_FAILED >&2; exit 5',
    "  fi",
    "fi",
    'echo "backup=$b"',
    'echo "changed=$changed"',
    "serial=$(knotc zone-status \"$apex\" 2>/dev/null | sed -n 's/.*serial: *\\([0-9]*\\).*/\\1/p' | head -1)",
    'echo "serial=${serial:-}"',
    "echo ZONE_READ_BEGIN",
    `knotc zone-read "$apex" 2>/dev/null || true`,
    "echo ZONE_READ_END",
  ].join("\n");
  return [
    "set -eu",
    `flock -x /run/knot-dns.lock sh -c ${shq(inner)}`,
  ].join("\n");
}

/** Restores the files a failed apply kept in `backup`, then reloads. */
export function restoreZoneScript(
  opts: { apex: string; backup: string },
): string {
  const p = zonePaths(opts.apex);
  const inner = [
    "set -eu",
    `b=${shq(opts.backup)}`,
    `z=${shq(p.zoneFile)}; f=${shq(p.fragment)}; t=${shq(p.tsigFragment)}`,
    `[ -d "$b" ] || { echo NO_BACKUP >&2; exit 3; }`,
    'if [ -f "$b/z" ]; then mv "$b/z" "$z"; else rm -f "$z"; fi',
    'if [ -f "$b/f" ]; then mv "$b/f" "$f"; else rm -f "$f"; fi',
    'if [ -f "$b/t" ]; then mv "$b/t" "$t"; else rm -f "$t"; fi',
    `for x in "$z" "$f"; do ${CHGRP}; done`,
    "knotc -b reload 2>/dev/null || true",
    'rm -rf "$b"',
    "echo restored=yes",
  ].join("\n");
  return ["set -eu", `flock -x /run/knot-dns.lock sh -c ${shq(inner)}`].join(
    "\n",
  );
}

/** Removes a backup directory kept by a successful apply. */
export function finalizeZoneScript(backup: string): string {
  return `set -eu\nrm -rf ${shq(backup)}\necho discarded=yes`;
}

/** Script that removes one zone's file and fragment. */
export function removeZoneScript(opts: {
  apex: string;
  purgeKeysAck: boolean;
  unsigned: boolean;
}): string {
  const p = zonePaths(opts.apex);
  const purge = opts.purgeKeysAck
    ? `knotc zone-purge ${shq(opts.apex)} 2>/dev/null || true`
    : "true";
  return [
    "set -eu",
    `apex=${shq(opts.apex)}`,
    `z=${shq(p.zoneFile)}; f=${shq(p.fragment)}; t=${shq(p.tsigFragment)}`,
    "present=no",
    '[ -f "$f" ] && present=yes',
    `if [ "$present" = no ]; then echo "removed=no"; exit 0; fi`,
    'if [ -f "$z" ]; then',
    `  signed=$(grep -c 'dnssec-signing: on' "$f" 2>/dev/null || true)`,
    `  if [ "$signed" != "0" ] && [ ${
      opts.unsigned ? "0" : "1"
    } = 1 ]; then echo DNSSEC_UNSIGN_ACK_REQUIRED >&2; exit 6; fi`,
    "fi",
    'b=$(mktemp -d); cp -a "$z" "$b/z" 2>/dev/null || true; cp -a "$f" "$b/f"',
    'rm -f "$z" "$f" "$t"',
    "if ! knotc -b reload 2>/dev/null; then",
    '  cp -a "$b/z" "$z" 2>/dev/null || true; cp -a "$b/f" "$f"',
    '  knotc -b reload 2>/dev/null || true; rm -rf "$b"; echo RELOAD_FAILED >&2; exit 5',
    "fi",
    'rm -rf "$b"',
    purge,
    'echo "removed=yes"',
  ].join("\n");
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

/** Script that reports the DNSSEC key state of a zone. */
export function keyStateScript(apex: string): string {
  return [
    "set -eu",
    "echo KEY_BEGIN",
    `keymgr ${shq(apex)} list 2>/dev/null || true`,
    "echo KEY_END",
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

/** Script that validates, swaps and reloads the resolver configuration. */
export function applyResolverScript(opts: {
  liveYaml: string;
  packageBackup: string;
  stagedYaml: string;
  testListen: string;
  testName: string;
}): string {
  const inner = [
    "set -eu",
    `live=${shq(opts.liveYaml)}; st=${shq(opts.stagedYaml)}`,
    `pkg=${shq(opts.packageBackup)}`,
    `[ -f "$st" ] || { echo STAGE_MISSING >&2; exit 3; }`,
    `kresctl validate "$st" || { echo KRESCTL_FAILED >&2; exit 4; }`,
    `if [ -f "$live" ] && [ ! -f "$pkg" ]; then cp -a "$live" "$pkg"; fi`,
    "changed=yes",
    `if [ -f "$live" ] && cmp -s "$live" "$st"; then changed=no; fi`,
    "b=$(mktemp)",
    'cp -a "$live" "$b" 2>/dev/null || true',
    'if [ "$changed" = yes ]; then',
    '  mv "$st" "$live"',
    "  if ! systemctl reload knot-resolver 2>/dev/null && ! systemctl restart knot-resolver 2>/dev/null; then",
    '    [ -s "$b" ] && mv "$b" "$live" || rm -f "$live"',
    '    systemctl restart knot-resolver 2>/dev/null || true; rm -f "$b"; echo RELOAD_FAILED >&2; exit 5',
    "  fi",
    "fi",
    `if ! kdig +time=3 +tries=1 @${shq(opts.testListen)} ${
      shq(opts.testName)
    } SOA >/dev/null 2>&1; then`,
    '  [ -s "$b" ] && mv "$b" "$live" || rm -f "$live"',
    '  systemctl restart knot-resolver 2>/dev/null || true; rm -f "$b"; echo TEST_QUERY_FAILED >&2; exit 7',
    "fi",
    'rm -f "$b"',
    'echo "changed=$changed"',
  ].join("\n");
  return [
    "set -eu",
    `flock -x /run/knot-resolver.lock sh -c ${shq(inner)}`,
  ].join("\n");
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

/** Script that dumps every managed zone's served records and status under flock. */
export function observeScript(apexes: string[]): string {
  const inner = [
    "set -eu",
    ...apexes.flatMap((apex) => [
      `echo ${shq(`ZONE ${apex}`)}`,
      `if [ -f ${shq(zonePaths(apex).fragment)} ]; then`,
      `  serial=$(knotc zone-status ${
        shq(apex)
      } 2>/dev/null | sed -n 's/.*serial: *\\([0-9]*\\).*/\\1/p' | head -1)`,
      `  sha=$(sha256sum ${
        shq(zonePaths(apex).zoneFile)
      } 2>/dev/null | awk '{print $1}')`,
      `  echo "serial=\${serial:-}"`,
      `  echo "file_sha=\${sha:-}"`,
      `  echo KEY_BEGIN`,
      `  keymgr ${shq(apex)} list 2>/dev/null || true`,
      `  echo KEY_END`,
      `  echo ZONE_READ_BEGIN`,
      `  knotc zone-read ${shq(apex)} 2>/dev/null || true`,
      `  echo ZONE_READ_END`,
      `else echo "missing=yes"; fi`,
    ]),
  ].join("\n");
  return [
    "set -eu",
    `flock -x /run/knot-dns.lock sh -c ${shq(inner)}`,
  ].join("\n");
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
