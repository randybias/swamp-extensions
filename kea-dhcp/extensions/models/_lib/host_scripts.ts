/**
 * The host-side shell bodies and the paths they act on.
 *
 * Every remote string is assembled here with `posixQuote`, so there is one
 * quoting helper and one place to audit. The scripts are pure string builders;
 * the model uploads them and the tests exercise them under `sh -eu`.
 *
 * @module
 */

import { posixQuote } from "./ssh.ts";

/** The Kea DHCPv4 config file. */
export const CONFIG_PATH = "/etc/kea/kea-dhcp4.conf";
/** The directory that holds the revert records and markers. */
export const REVERT_ROOT = "/var/lib/kea-dhcp-revert";
/** The packaged systemd service. */
export const SERVICE = "kea-dhcp4-server";
/** The package's original config, captured once by `install`. */
export const ORIGINAL_CONFIG = `${REVERT_ROOT}/original.conf`;
/** The shared lock that serializes a commit against the revert timer. */
const REVERT_LOCK = "/run/kea-dhcp-revert.lock";

/** The transient systemd unit name for an armed revert. */
export function timerName(token: string): string {
  return `kea-dhcp-revert-${token}`;
}

/** Prints the interface that carries the SSH session, or UNKNOWN. */
export function managementScript(): string {
  return [
    "set -- $SSH_CONNECTION",
    "peer=$1",
    'if [ -z "$peer" ]; then printf %s UNKNOWN; exit 0; fi',
    'iface=$(ip -o route get "$peer" 2>/dev/null | awk \'{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}\')',
    'if [ -z "$iface" ]; then',
    '  iface=$(ip -o -4 addr show 2>/dev/null | awk -v a="$peer" \'{split($4,x,"/"); if(x[1]==a){print $2; exit}}\')',
    "fi",
    'printf %s "$iface"',
  ].join("\n");
}

/** Prints the group the Kea service runs as. */
export function groupScript(): string {
  return [
    `u=$(systemctl show -p User --value ${SERVICE} 2>/dev/null || true)`,
    'if [ -z "$u" ]; then u=root; fi',
    'if [ "$u" = root ]; then g=root; else g=$(id -gn "$u" 2>/dev/null || true); fi',
    'if [ -z "$g" ]; then g=$(stat -c %G /var/lib/kea 2>/dev/null || true); fi',
    'printf %s "$g"',
  ].join("\n");
}

/**
 * Validates a lease_cmds hook path. Loading a hook runs its code as root during
 * `kea-dhcp4 -t`, so the path must be the packaged library, root-owned and not
 * group/world writable, inside the discovered hooks directory.
 */
export function hookLibraryScript(path: string): string {
  return [
    `p=${posixQuote(path)}`,
    '[ -f "$p" ] || { printf %s missing; exit 0; }',
    '[ -L "$p" ] && { printf %s symlink; exit 0; }',
    'owner=$(stat -c %U "$p" 2>/dev/null || true); [ "$owner" = root ] || { printf %s "owner=$owner"; exit 0; }',
    'w=$(find "$p" -maxdepth 0 -perm /022 2>/dev/null || true); [ -z "$w" ] || { printf %s writable; exit 0; }',
    "libs=$(dpkg -L kea-common kea-dhcp4-server 2>/dev/null | grep -m1 '/hooks/.*\\.so$' || true)",
    'if [ -z "$libs" ]; then libs=$(find /usr/lib -maxdepth 6 -path "*/kea/hooks/libdhcp_*.so" 2>/dev/null | head -n1); fi',
    'if [ -z "$libs" ]; then printf %s no-hooks-dir; exit 0; fi',
    'hooks=$(dirname "$libs")',
    'case "$(readlink -f "$p")" in "$hooks"/*) ;; *) printf %s "outside=$hooks"; exit 0;; esac',
    "printf %s ok",
  ].join("\n");
}

/**
 * Claims the revert under the lock: refuse-active and snapshot together, and
 * record the service's prior enabled state. Exits 9 when a revert is armed.
 */
export function claimScript(dir: string, activeJson: string): string {
  return [
    "set -e",
    `exec 9>${posixQuote(REVERT_LOCK)}`,
    "flock -w 30 9 || exit 8",
    `if [ -f ${posixQuote(`${REVERT_ROOT}/active.json`)} ]; then exit 9; fi`,
    `mkdir -p ${posixQuote(dir)}`,
    `chmod 700 ${posixQuote(dir)}`,
    `if [ -f ${posixQuote(CONFIG_PATH)} ]; then cp -a ${
      posixQuote(CONFIG_PATH)
    } ${posixQuote(`${dir}/previous.conf`)}; fi`,
    `en=$(systemctl is-enabled ${SERVICE} 2>/dev/null || true)`,
    `printf '{"enabled":"%s"}\\n' "$en" > ${posixQuote(`${dir}/prior.json`)}`,
    `printf '%s\\n' ${posixQuote(activeJson)} > ${
      posixQuote(`${REVERT_ROOT}/active.json`)
    }`,
  ].join("\n");
}

/** Sets the service group and atomically installs a staged file. */
export function installFileScript(staged: string, group: string): string {
  return [
    "set -e",
    `chgrp ${posixQuote(group)} ${posixQuote(staged)}`,
    `chmod 0640 ${posixQuote(staged)}`,
    `mv -T ${posixQuote(staged)} ${posixQuote(CONFIG_PATH)}`,
  ].join("\n");
}

/**
 * The commit critical section. Under the revert lock it stops the timer,
 * re-checks that no restore fired or started, re-checks the armed file sha,
 * writes the `committed` marker and clears the active marker.
 */
export function commitScript(
  dir: string,
  token: string,
  armedSha: string,
): string {
  const timer = timerName(token);
  return [
    "set -u",
    `exec 9>${posixQuote(REVERT_LOCK)}`,
    "flock -w 30 9 || { printf %s lock-failed; exit 0; }",
    `if [ -f ${
      posixQuote(`${dir}/fired.json`)
    } ]; then printf %s fired; exit 0; fi`,
    `systemctl stop ${timer}.timer >/dev/null 2>&1 || true`,
    `if [ -f ${
      posixQuote(`${dir}/fired.json`)
    } ]; then printf %s fired; exit 0; fi`,
    `if systemctl is-active --quiet ${timer}.service; then printf %s service-active; exit 0; fi`,
    `if systemctl is-active --quiet ${timer}.timer; then printf %s timer-active; exit 0; fi`,
    `got=$(sha256sum ${
      posixQuote(CONFIG_PATH)
    } 2>/dev/null | awk '{print $1}')`,
    `if [ "$got" != ${
      posixQuote(armedSha)
    } ]; then printf %s drifted; exit 0; fi`,
    `printf committed > ${posixQuote(`${dir}/committed`)}`,
    `rm -f ${posixQuote(`${REVERT_ROOT}/active.json`)}`,
    "printf %s committed",
  ].join("\n");
}

/**
 * The restore body the timer runs.
 *
 * It restores the previous file, returns the service to its prior running and
 * enabled state, judges pass/fail from the post-state (file sha, service and
 * enabled state, socket answer) and records it in fired.json. It takes the same
 * lock as a commit and exits without reverting when a `committed` marker
 * exists, so a commit and a revert can never both act. It always clears
 * active.json; a failed restore leaves a recovery note beside it.
 */
export function restoreScript(
  token: string,
  socket: string,
  priorActive: boolean,
  priorEnabled: boolean,
): string {
  const dir = posixQuote(`${REVERT_ROOT}/${token}`);
  return [
    "#!/bin/sh",
    "set -u",
    `d=${dir}`,
    `f=${posixQuote(CONFIG_PATH)}`,
    `a=${posixQuote(`${REVERT_ROOT}/active.json`)}`,
    `s=${posixQuote(socket)}`,
    `svc=${SERVICE}`,
    "result=pass",
    'detail=""',
    "finish() {",
    `  printf '{"token":"%s","fired_at":"%s","result":"%s","detail":"%s"}\\n' ${
      posixQuote(token)
    } "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$result" "$detail" > "$d/fired.json"`,
    '  if [ "$result" != pass ]; then',
    '    printf \'Restore failed (%s). The previous config is %s/previous.conf; recovery: inspect %s, restore previous.conf by hand if needed, then run systemctl restart %s.\\n\' "$detail" "$d" "$f" "$svc" > "$d/recovery.txt"',
    "  fi",
    '  rm -f "$a"',
    "  exit 0",
    "}",
    `exec 9>${posixQuote(REVERT_LOCK)}`,
    "if ! flock -w 30 9; then result=fail; detail=lock; finish; fi",
    'if [ -f "$d/committed" ] || [ ! -f "$a" ]; then exit 0; fi',
    'if [ -f "$d/previous.conf" ]; then',
    '  cp -a "$d/previous.conf" "$f" 2>/dev/null || { result=fail; detail="$detail restore-copy"; }',
    "else",
    '  rm -f "$f" 2>/dev/null || { result=fail; detail="$detail remove-config"; }',
    "fi",
    'if [ -f "$d/previous.conf" ]; then',
    `  want=$(sha256sum "$d/previous.conf" 2>/dev/null | awk '{print $1}')`,
    `  got=$(sha256sum "$f" 2>/dev/null | awk '{print $1}')`,
    '  [ "$want" = "$got" ] || { result=fail; detail="$detail file-sha"; }',
    "fi",
    `if [ ${priorActive ? "1" : "0"} = 1 ]; then`,
    '  if command -v socat >/dev/null 2>&1 && [ -f "$d/restore-request.json" ]; then',
    '    ans=$(socat -t 10 - UNIX-CONNECT:"$s" < "$d/restore-request.json" 2>/dev/null || true)',
    `    printf %s "$ans" | grep -Eq '"result": *0' || systemctl restart "$svc" >/dev/null 2>&1 || true`,
    "  else",
    '    systemctl restart "$svc" >/dev/null 2>&1 || true',
    "  fi",
    '  systemctl is-active --quiet "$svc" || { result=fail; detail="$detail service-inactive"; }',
    '  if [ "$result" = pass ] && [ -f "$d/hash-request.json" ] && command -v socat >/dev/null 2>&1; then',
    '    ans=$(socat -t 10 - UNIX-CONNECT:"$s" < "$d/hash-request.json" 2>/dev/null || true)',
    `    printf %s "$ans" | grep -Eq '"result": *0' || { result=fail; detail="$detail socket-no-answer"; }`,
    "  fi",
    "else",
    '  systemctl stop "$svc" >/dev/null 2>&1 || true',
    '  systemctl is-active --quiet "$svc" && { result=fail; detail="$detail service-still-active"; }',
    "fi",
    `if [ ${priorEnabled ? "1" : "0"} = 1 ]; then`,
    '  systemctl enable "$svc" >/dev/null 2>&1 || true',
    "else",
    '  systemctl disable "$svc" >/dev/null 2>&1 || true',
    "fi",
    'cur=$(systemctl is-enabled "$svc" 2>/dev/null || true)',
    `if [ ${priorEnabled ? "1" : "0"} = 1 ]; then`,
    '  [ "$cur" = enabled ] || { result=fail; detail="$detail enable-state"; }',
    "else",
    '  [ "$cur" = disabled ] || { result=fail; detail="$detail disable-state"; }',
    "fi",
    "finish",
  ].join("\n") + "\n";
}
