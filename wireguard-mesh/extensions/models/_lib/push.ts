/**
 * Push half: applies a rendered config to one node through the canonical
 * vendored SSH transport (`_lib/ssh.ts`). Every value that reaches the remote
 * shell is validated against a grammar and quoted, and each script is a fixed
 * template; the private key and the config travel in an uploaded temp file
 * piped into the script, never on argv. An ssh exit 255 is the transport's
 * typed `SshError`, and supplied host-key pins that do not apply to the host
 * are refused rather than silently accepted.
 *
 * @module
 */

import { IFACE_RE } from "./render.ts";
import {
  buildKnownHosts,
  exec,
  type ExecResult,
  type HostKeyInfo,
  SshConfigError,
  type SshDeps,
  SshError,
  type SshTarget as CanonicalTarget,
  upload,
  waitConnection,
} from "./ssh.ts";

/** Result of running a command. */
export interface CommandResult {
  /** Exit code. */
  code: number;
  /** Captured standard output. */
  stdout: string;
  /** Captured standard error. */
  stderr: string;
}

/**
 * Result of a transport call. `known_hosts` carries the ssh-keyscan-format
 * lines learned on a first trust-on-first-use contact, so the caller can pin
 * them.
 */
export interface TransportResult extends CommandResult {
  /** Host keys learned on this call, when it was a first `insecure_tofu` run. */
  known_hosts?: string;
}

/** Runs a fixed shell script on the node, with `stdin` piped to it. */
export type Transport = (
  script: string,
  stdin?: string,
) => Promise<TransportResult>;

/** SSH target block; the host-key policy is never a silent default. */
export interface SshTarget {
  /** Host name or IP literal. */
  host: string;
  /** SSH user. */
  user: string;
  /** SSH port. */
  port: number;
  /** Host-key policy. */
  host_key_policy: "strict" | "insecure_tofu";
  /** Pinned ssh-keyscan-format lines; required for strict. */
  host_keys: string[];
  /** Private key text, loaded into a short-lived ssh-agent over stdin. */
  private_key?: string;
  /** Connection timeout in seconds. */
  connect_timeout_s?: number;
  /** Cap in bytes on captured output. */
  max_output_bytes?: number;
}

/** A transport failure: unreachable host, rejected auth or host key. */
export class TransportError extends Error {
  /** Why the transport failed. */
  readonly reason: "unreachable" | "auth" | "host-key" | "remote";
  /** Creates the error. */
  constructor(reason: TransportError["reason"], message: string) {
    super(message);
    this.name = "TransportError";
    this.reason = reason;
  }
}

function canonicalTarget(t: SshTarget): CanonicalTarget {
  if (t.host_key_policy === "strict" && t.host_keys.length === 0) {
    throw new TransportError(
      "host-key",
      "host_key_policy strict requires pinned host_keys",
    );
  }
  return {
    host: t.host,
    port: t.port,
    user: t.user,
    host_key_policy: t.host_key_policy,
    ...(t.host_keys.length > 0 ? { host_keys: t.host_keys } : {}),
    ...(t.private_key !== undefined ? { private_key: t.private_key } : {}),
    connect_timeout_s: t.connect_timeout_s ?? 15,
    ...(t.max_output_bytes !== undefined
      ? { max_output_bytes: t.max_output_bytes }
      : {}),
  };
}

/** Maps a canonical transport error to the model's typed transport error. */
function toTransportError(e: unknown): TransportError {
  if (e instanceof SshError) {
    return new TransportError("unreachable", e.message);
  }
  if (e instanceof SshConfigError) {
    return new TransportError("host-key", e.message);
  }
  if (e instanceof TransportError) return e;
  return new TransportError("remote", (e as Error).message);
}

/** ssh-keyscan-format lines for learned keys, with a port-aware host field. */
function knownHostsLines(
  host: string,
  port: number,
  keys: HostKeyInfo[],
): string {
  return buildKnownHosts(host, port, keys);
}

/**
 * Builds the ssh-backed transport on the canonical `_lib/ssh.ts`. A first
 * `insecure_tofu` call with no pins learns the host keys (returned in
 * `known_hosts`, `[host]:port` for a non-default port) and pins them for the
 * rest of the operation; `stdin` is written to a private `mktemp -d` directory
 * and the script unlinks it as soon as it is opened on fd 3, so the key and
 * config are never at rest and never on argv. An ssh exit 255 is the canonical
 * typed `SshError`, rethrown here as a `TransportError`.
 */
export function sshTransport(t: SshTarget, deps: SshDeps): Transport {
  const target = canonicalTarget(t);
  return async (script, stdin) => {
    let learnedLines: string | undefined;
    if (
      target.host_key_policy === "insecure_tofu" &&
      (target.host_keys?.length ?? 0) === 0
    ) {
      let waited;
      try {
        waited = await waitConnection(deps, target, {
          timeout_s: target.connect_timeout_s,
        });
      } catch (e) {
        throw toTransportError(e);
      }
      if (!waited.reachable || waited.host_keys.length === 0) {
        throw new TransportError("unreachable", "the node did not answer SSH");
      }
      learnedLines = knownHostsLines(t.host, t.port, waited.host_keys);
      target.host_keys = learnedLines.split("\n").filter((l) => l !== "");
    }
    let dir: string | undefined;
    let tmp: string | undefined;
    let result: TransportResult | undefined;
    let failure: TransportError | undefined;
    try {
      if (stdin !== undefined) {
        let made: ExecResult;
        try {
          made = await exec(deps, target, [
            "mktemp",
            "-d",
            "-p",
            "/tmp",
            "wgmesh.XXXXXXXX",
          ]);
        } catch (e) {
          throw toTransportError(e);
        }
        if (made.exit_code !== 0) {
          throw new TransportError(
            "remote",
            "could not create a private temp directory on the node",
          );
        }
        dir = made.stdout.trim();
        if (!/^\/tmp\/wgmesh\.[A-Za-z0-9]{6,}$/.test(dir)) {
          throw new TransportError(
            "remote",
            "mktemp returned an unexpected path",
          );
        }
        tmp = `${dir}/stdin`;
        try {
          await upload(deps, target, {
            path: tmp,
            content: stdin,
            mode: "0600",
          });
        } catch (e) {
          throw toTransportError(e);
        }
      }
      const body = tmp === undefined || dir === undefined ? script : [
        "umask 077",
        // Open the file, then unlink it before the script runs, so the key is
        // never at rest even if the script cuts the SSH path.
        `exec 3<'${tmp}' && rm -f -- '${tmp}'`,
        `trap 'rm -f -- "${tmp}"; rmdir -- "${dir}" 2>/dev/null || true' EXIT HUP INT TERM`,
        "{",
        script,
        "} <&3",
      ].join("\n");
      let res: ExecResult;
      try {
        res = await exec(deps, target, ["sh", "-c", body]);
      } catch (e) {
        throw toTransportError(e);
      }
      result = {
        code: res.exit_code,
        stdout: res.stdout,
        stderr: res.stderr,
        ...(learnedLines !== undefined ? { known_hosts: learnedLines } : {}),
      };
    } catch (e) {
      failure = e instanceof TransportError ? e : toTransportError(e);
    }
    let cleanupFailure: TransportError | undefined;
    if (tmp !== undefined) {
      let cleaned: ExecResult | undefined;
      try {
        cleaned = await exec(deps, target, [
          "sh",
          "-c",
          `rm -f -- '${tmp}'; rmdir -- '${dir}' 2>/dev/null || true`,
        ]);
      } catch {
        cleaned = undefined;
      }
      if (cleaned === undefined || cleaned.exit_code !== 0) {
        cleanupFailure = new TransportError(
          "remote",
          `the remote temp file ${tmp} may still hold the key; remove it by hand`,
        );
      }
    }
    if (cleanupFailure !== undefined) throw cleanupFailure;
    if (failure !== undefined) throw failure;
    return result!;
  };
}

/** Hex SHA-256 of text. */
export async function sha256Hex(text: string): Promise<string> {
  const d = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(text),
  );
  return [...new Uint8Array(d)].map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

/** Throws unless `name` is a valid interface name. */
export function assertIface(name: string): void {
  if (!IFACE_RE.test(name)) throw new Error(`Invalid interface name: ${name}`);
}

const KEY_TYPE_RE = /^[a-z0-9@.-]{1,40}$/;
const KEY_B64_RE = /^[A-Za-z0-9+/=]{1,2048}$/;
const HOST_FIELD_RE = /^[A-Za-z0-9.,:_\[\]-]{1,512}$/;

/**
 * True for an ssh-keyscan line: an optional host field (a hostname, an IP, a
 * comma list, or `[host]:port`), a key type and a base64 payload. Any other
 * token count is rejected.
 */
export function isHostKeyLine(value: string): boolean {
  const parts = value.trim().split(/\s+/);
  if (parts.length === 2) {
    return KEY_TYPE_RE.test(parts[0]) && KEY_B64_RE.test(parts[1]);
  }
  if (parts.length === 3) {
    return HOST_FIELD_RE.test(parts[0]) && KEY_TYPE_RE.test(parts[1]) &&
      KEY_B64_RE.test(parts[2]);
  }
  return false;
}

/** A host key parsed from a known_hosts or ssh-keyscan line. */
export interface HostKeyPair {
  /** Key algorithm, e.g. `ssh-ed25519`. */
  type: string;
  /** Base64 public key blob. */
  key: string;
}

/** Parses known_hosts / ssh-keyscan text into unique `{type, key}` pairs. */
export function parseKnownHosts(text: string): HostKeyPair[] {
  const seen = new Set<string>();
  const out: HostKeyPair[] = [];
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (line === "" || line.startsWith("#")) continue;
    const parts = line.split(/\s+/);
    const bare = /^(ssh-|ecdsa-|sk-)/.test(parts[0]);
    const type = bare ? parts[0] : parts[1];
    const key = bare ? parts[1] : parts[2];
    if (!type || !key) continue;
    const id = `${type} ${key}`;
    if (seen.has(id)) continue;
    seen.add(id);
    out.push({ type, key });
  }
  return out;
}

/**
 * Remote-shell lines that restore the saved config and key into place, tearing
 * down whatever interface is live first, and bring the interface back up when
 * it was up before. They are tolerant; the caller checks the interface
 * afterwards. Expects `$rb`, `$d`, `$i` and `$up`.
 */
function restoreLines(): string[] {
  return [
    'if ip link show "$i" >/dev/null 2>&1; then',
    '  if [ -e "$d/$i.conf" ]; then wg-quick down "$i" >/dev/null 2>&1 || ip link delete "$i" >/dev/null 2>&1 || true; else ip link delete "$i" >/dev/null 2>&1 || true; fi',
    "fi",
    'if [ -e "$rb/$i.conf" ]; then cp -p "$rb/$i.conf" "$d/$i.conf"; else rm -f "$d/$i.conf"; fi',
    'if [ -e "$rb/$i.key" ]; then cp -p "$rb/$i.key" "$d/$i.key"; else rm -f "$d/$i.key"; fi',
    'if [ "$up" = 1 ] && [ -e "$d/$i.conf" ]; then wg-quick up "$i" >/dev/null 2>&1 || true; fi',
  ];
}

/** Shell lines only reached after `$epoch` is set: back up both files. */
function backupLines(): string[] {
  return [
    'rb=$(mktemp -d "$d/.$i.rollback.XXXXXX")',
    'echo "$epoch" > "$rb/epoch"',
    'if [ -e "$d/$i.conf" ]; then cp -p "$d/$i.conf" "$rb/$i.conf"; fi',
    'if [ -e "$d/$i.key" ]; then cp -p "$d/$i.key" "$rb/$i.key"; fi',
  ];
}

/**
 * Writes and launches a detached rollback for generation `$epoch`. It takes the
 * same lock as a mutation, then restores only if it is still that generation
 * and has not been disarmed, so an expired rollback can never overwrite a later
 * successful apply. Callers return the directory for a fresh-connection
 * confirmation to disarm.
 */
function launchRollbackLines(windowSeconds: number): string[] {
  const rollback = [
    'sleep "$1"',
    "shift",
    "rb=$1; d=$2; i=$3; up=$4; epoch=$5",
    "if command -v flock >/dev/null 2>&1; then",
    '  exec 9>"$d/.$i.lock"',
    "  flock -w 60 9 || exit 1",
    "fi",
    'if [ ! -e "$rb/epoch" ]; then exit 0; fi',
    'if [ -e "$rb/disarm" ]; then rm -rf "$rb"; exit 0; fi',
    'if [ "$(cat "$d/.$i.epoch" 2>/dev/null || echo stale)" != "$epoch" ]; then rm -rf "$rb"; exit 0; fi',
    ...restoreLines(),
    'rm -rf "$rb"',
  ].join("\n");
  return [
    "cat > \"$rb/rollback.sh\" <<'ROLLBACK'",
    rollback,
    "ROLLBACK",
    "if command -v setsid >/dev/null 2>&1; then",
    `  setsid sh "$rb/rollback.sh" ${windowSeconds} "$rb" "$d" "$i" "$up" "$epoch" </dev/null >/dev/null 2>&1 9>&- &`,
    "else",
    `  nohup sh "$rb/rollback.sh" ${windowSeconds} "$rb" "$d" "$i" "$up" "$epoch" </dev/null >/dev/null 2>&1 9>&- &`,
    "fi",
  ];
}

/** Shell lines only reached after `$d` and `$i` are set: bump the generation. */
function bumpEpochLines(): string[] {
  return [
    'epoch=$(cat "$d/.$i.epoch" 2>/dev/null || echo 0)',
    "epoch=$((epoch + 1))",
    'echo "$epoch" > "$d/.$i.epoch"',
  ];
}

/** Takes an advisory remote lock around a change, when `flock` is present. */
function lockLines(): string[] {
  return [
    // Every change is confirmed under the lock, so a node without flock is
    // refused before anything is touched.
    'if ! command -v flock >/dev/null 2>&1; then echo "flock is required" >&2; exit 75; fi',
    'exec 9>"$d/.$i.lock"',
    'if ! flock -w 60 9; then echo "another run holds the $i lock" >&2; exit 75; fi',
  ];
}

/**
 * Shell function `pending_rb`: succeeds when an earlier change on `$i` is
 * still waiting for its confirmation (a rollback directory of the current
 * generation that has not been disarmed). A run that finds one must not report
 * a no-op: it starts a new generation, which retires the old rollback, and goes
 * through confirmation itself.
 */
function pendingRbLines(): string[] {
  return [
    "pending_rb() {",
    '  cur=$(cat "$d/.$i.epoch" 2>/dev/null || echo none)',
    '  for p in "$d"/.$i.rollback.*; do',
    '    [ -d "$p" ] && [ -e "$p/epoch" ] && [ ! -e "$p/disarm" ] || continue',
    '    if [ "$(cat "$p/epoch")" = "$cur" ]; then return 0; fi',
    "  done",
    "  return 1",
    "}",
  ];
}

/** Shell function `route_sig FILE`: a stable signature of routed prefixes. */
function routeSigLines(): string[] {
  return [
    "route_sig() {",
    "  sed -n 's/^Address *= *//p; s/^AllowedIPs *= *//p' \"$1\" 2>/dev/null | tr ',' '\\n' | tr -d ' ' | sort | tr '\\n' ','",
    "}",
  ];
}

/**
 * Shell function `route_check`: sets `route_ok=0` unless every desired
 * `AllowedIPs` is routed through the interface. `ip route get` sees both
 * wg-quick's explicit routes and the connected route for the node's address.
 */
function routeCheckLines(): string[] {
  return [
    "route_check() {",
    "  route_ok=1",
    "  for p in $(sed -n 's/^AllowedIPs *= *//p' \"$d/$i.conf\" | tr ',' ' '); do",
    '    case "$p" in',
    "      0.0.0.0/0|::/0)",
    '        if ! ip route show table all 2>/dev/null | grep -q "default dev $i"; then route_ok=0; fi',
    "        ;;",
    '      *:*) if ! ip -6 route get "${p%/*}" 2>/dev/null | grep -q "dev $i"; then route_ok=0; fi ;;',
    '      *) if ! ip -4 route get "${p%/*}" 2>/dev/null | grep -q "dev $i"; then route_ok=0; fi ;;',
    "    esac",
    "  done",
    "}",
  ];
}

/**
 * Shell function `addr_check FILE`: sets `addr_ok=1` only when the live
 * interface carries exactly the `Address` entries of FILE. A missing address and
 * an extra global one both count; link-local addresses are ignored.
 */
function addrCheckLines(): string[] {
  return [
    "addr_check() {",
    "  addr_ok=1",
    "  want=0",
    "  for a in $(sed -n 's/^Address *= *//p' \"$1\" | tr ',' ' '); do",
    "    want=$((want + 1))",
    '    if ! ip -o addr show dev "$i" 2>/dev/null | grep -qF " $a "; then addr_ok=0; fi',
    "  done",
    '  have=$(ip -o addr show dev "$i" scope global 2>/dev/null | wc -l)',
    '  if [ "$have" -ne "$want" ]; then addr_ok=0; fi',
    "}",
  ];
}

/** Seconds the remote rollback waits before restoring a changed interface. */
export const APPLY_ROLLBACK_SECONDS = 120;

/**
 * Remote script for `apply`. Stdin: the private key on the first line, then
 * the config. Backs up both durable files, stages both at mode 0600, commits
 * both as one guarded step, and restores both (and the previous live config)
 * on any failure. A change to `Address` OR to routed `AllowedIPs` recreates the
 * interface, because `wg syncconf` does not update wg-quick's routes. A no-op
 * is reported only after live peers and addresses are proven to match. On
 * success it leaves a detached rollback armed and prints `rb=<dir>` for a fresh
 * connection to disarm; prints `changed=0|1`.
 */
export function applyScript(iface: string): string {
  assertIface(iface);
  return [
    "set -eu",
    "umask 077",
    `d=/etc/wireguard`,
    `i='${iface}'`,
    'mkdir -p "$d"',
    ...lockLines(),
    "IFS= read -r key",
    'case "$key" in ""|*[!A-Za-z0-9+/=]*) echo "bad key on stdin" >&2; exit 64;; esac',
    'stage=$(mktemp -d "$d/.$i.stage.XXXXXX")',
    'cleanup() { rm -rf "$stage"; }',
    "trap cleanup EXIT",
    'cfg="$stage/$i.conf"',
    'kf="$stage/$i.key"',
    'cat > "$cfg"',
    'printf "%s\\n" "$key" > "$kf"',
    'chmod 600 "$cfg" "$kf"',
    "up=0",
    'if ip link show "$i" >/dev/null 2>&1; then up=1; fi',
    "restore_previous() {",
    ...restoreLines(),
    '  if [ "$up" = 1 ] && ! ip link show "$i" >/dev/null 2>&1; then',
    '    echo "rollback could not restore interface $i" >&2; return 1;',
    "  fi",
    "  return 0",
    "}",
    // Restores the saved state and, only when that worked, disarms the rollback.
    'fail_restore() { if restore_previous; then touch "$rb/disarm"; fi; exit 1; }',
    // Arms a detached rollback. `$1` = 1 starts a new generation, which retires
    // any earlier unconfirmed rollback; 0 reuses the current one.
    "arm_rollback() {",
    '  [ -e "$d/.$i.epoch" ] || echo 0 > "$d/.$i.epoch"',
    '  epoch=$(cat "$d/.$i.epoch" 2>/dev/null || echo 0)',
    '  if [ "$1" = 1 ]; then epoch=$((epoch + 1)); echo "$epoch" > "$d/.$i.epoch"; fi',
    ...backupLines(),
    ...launchRollbackLines(APPLY_ROLLBACK_SECONDS),
    "}",
    // Peers, endpoints, allowed IPs, keepalive and listen port; no counters.
    "live_sig() {",
    '  wg show "$i" dump 2>/dev/null | { IFS= read -r first || true; printf "%s\\n" "$first" | cut -f2,3,4; cut -f1,3,4,8 | sort; }',
    "}",
    ...addrCheckLines(),
    ...pendingRbLines(),
    "changed=0",
    "if pending_rb; then changed=1; fi",
    'if ! cmp -s "$cfg" "$d/$i.conf"; then changed=1; fi',
    'if ! cmp -s "$kf" "$d/$i.key"; then changed=1; fi',
    'if [ "$up" = 0 ]; then changed=1; fi',
    "live_drift=0",
    'if [ "$up" = 1 ] && [ "$changed" = 0 ]; then',
    '  addr_check "$cfg"',
    '  if [ "$addr_ok" = 0 ]; then',
    "    live_drift=1",
    "  else",
    // The probe re-syncs the live interface, which is a live change: arm first.
    "    arm_rollback 0",
    '    wg-quick strip "$cfg" > "$stage/desired.wg"',
    "    before=$(live_sig)",
    '    if ! wg syncconf "$i" "$stage/desired.wg"; then fail_restore; fi',
    '    if ! wg set "$i" private-key "$d/$i.key"; then fail_restore; fi',
    "    after=$(live_sig)",
    '    if [ "$before" != "$after" ]; then live_drift=1; fi',
    '    touch "$rb/disarm"',
    "  fi",
    "fi",
    'if [ "$changed" = 0 ] && [ "$live_drift" = 0 ]; then echo "changed=0"; exit 0; fi',
    "arm_rollback 1",
    ...routeSigLines(),
    'old_routes=$(route_sig "$d/$i.conf")',
    'if ! { mv "$kf" "$d/$i.key" && mv "$cfg" "$d/$i.conf"; }; then fail_restore; fi',
    'new_routes=$(route_sig "$d/$i.conf")',
    'addr_check "$d/$i.conf"',
    'if [ "$up" = 1 ] && [ "$addr_ok" = 1 ] && [ "$old_routes" = "$new_routes" ]; then',
    '  wg-quick strip "$d/$i.conf" > "$stage/committed.wg"',
    '  if ! wg syncconf "$i" "$stage/committed.wg"; then fail_restore; fi',
    '  if ! wg set "$i" private-key "$d/$i.key"; then fail_restore; fi',
    "else",
    '  if [ "$up" = 1 ]; then wg-quick down "$i" || ip link delete "$i"; fi',
    '  if ! wg-quick up "$i"; then fail_restore; fi',
    "fi",
    'if ! ip link show "$i" >/dev/null 2>&1; then fail_restore; fi',
    ...routeCheckLines(),
    "route_check",
    'if [ "$route_ok" = 0 ]; then fail_restore; fi',
    'echo "changed=1"',
    'echo "rb=$rb"',
  ].join("\n");
}

/** Remote script for `get`; prints `wg show <iface> dump`. */
export function getScript(iface: string): string {
  assertIface(iface);
  return `set -eu; wg show '${iface}' dump`;
}

/**
 * Remote script for `delete`. Brings the interface down and removes the config
 * and key, arming a detached rollback first; on success it leaves the rollback
 * armed and prints `rb=<dir>` so a fresh connection can confirm reachability
 * and disarm it. Prints `changed=0|1`; a node already down and gone is a clean
 * no-op.
 */
export function deleteScript(iface: string, rollbackSeconds: number): string {
  assertIface(iface);
  if (!Number.isInteger(rollbackSeconds) || rollbackSeconds < 1) {
    throw new Error(`Invalid rollback window: ${rollbackSeconds}`);
  }
  return [
    "set -eu",
    "umask 077",
    `d=/etc/wireguard`,
    `i='${iface}'`,
    'mkdir -p "$d"',
    ...lockLines(),
    ...pendingRbLines(),
    "changed=0",
    "if pending_rb; then changed=1; fi",
    'if ip link show "$i" >/dev/null 2>&1; then changed=1; fi',
    'if [ -e "$d/$i.conf" ]; then changed=1; fi',
    'if [ -e "$d/$i.key" ]; then changed=1; fi',
    'if [ "$changed" = 0 ]; then echo "changed=0"; exit 0; fi',
    "up=0",
    'if ip link show "$i" >/dev/null 2>&1; then up=1; fi',
    ...bumpEpochLines(),
    ...backupLines(),
    ...launchRollbackLines(rollbackSeconds),
    // wg-quick cannot take down an interface whose config is missing or corrupt.
    'if ip link show "$i" >/dev/null 2>&1; then wg-quick down "$i" >/dev/null 2>&1 || ip link delete "$i" || true; fi',
    'rm -f "$d/$i.conf" "$d/$i.key"',
    'if ip link show "$i" >/dev/null 2>&1; then echo "interface $i is still up" >&2; exit 1; fi',
    'if [ -e "$d/$i.conf" ]; then echo "config $i.conf still present" >&2; exit 1; fi',
    'if [ -e "$d/$i.key" ]; then echo "key $i.key still present" >&2; exit 1; fi',
    'echo "changed=1"',
    'echo "rb=$rb"',
  ].join("\n");
}

/** Exit codes of {@link confirmScript} when there is nothing to confirm. */
export const CONFIRM_REFUSED = {
  /** The rollback already ran (or never existed): the old state is back. */
  gone: 3,
  /** A newer generation has superseded this one. */
  superseded: 4,
  /** The lock could not be taken. */
  busy: 75,
} as const;

/**
 * Remote script for a FRESH management connection after a successful `apply`
 * or `delete`: reaching the node at all proves the path survived. Under the
 * same lock the rollback takes, it requires the rollback directory to still
 * exist with the CURRENT generation and only then disarms it. If the rollback
 * already ran, was superseded, or the lock is busy, it fails, so the caller
 * never records a change the node has already undone.
 */
export function confirmScript(iface: string, rollbackDir: string): string {
  assertIface(iface);
  if (
    !new RegExp(
      `^/etc/wireguard/\\.${iface}\\.rollback\\.[A-Za-z0-9]+$`,
    ).test(rollbackDir)
  ) {
    throw new Error(`Invalid rollback directory: ${rollbackDir}`);
  }
  return [
    "set -eu",
    `d=/etc/wireguard`,
    `i='${iface}'`,
    `rb='${rollbackDir}'`,
    ...confirmLockLines(),
    `if [ ! -e "$rb/epoch" ]; then echo "no pending rollback; it already ran" >&2; exit ${CONFIRM_REFUSED.gone}; fi`,
    `if [ "$(cat "$rb/epoch")" != "$(cat "$d/.$i.epoch" 2>/dev/null || echo none)" ]; then echo "a newer change superseded this one" >&2; exit ${CONFIRM_REFUSED.superseded}; fi`,
    'touch "$rb/disarm"',
    'echo "confirmed"',
  ].join("\n");
}

/** Lock lines for confirm: the lock is required, so no `flock` is an error. */
function confirmLockLines(): string[] {
  return [
    'if ! command -v flock >/dev/null 2>&1; then echo "flock is required to confirm" >&2; exit 75; fi',
    'exec 9>"$d/.$i.lock"',
    `if ! flock -w 30 9; then echo "another run holds the $i lock" >&2; exit ${CONFIRM_REFUSED.busy}; fi`,
  ];
}

/** Extracts and validates the rollback directory a mutation script printed. */
export function parseRollbackDir(
  stdout: string,
  iface: string,
): string | undefined {
  const m = /^rb=(.+)$/m.exec(stdout);
  if (!m) return undefined;
  const dir = m[1].trim();
  const re = new RegExp(
    `^/etc/wireguard/\\.${iface}\\.rollback\\.[A-Za-z0-9]+$`,
  );
  return re.test(dir) ? dir : undefined;
}

/** One peer parsed from `wg show <iface> dump`. */
export interface LivePeer {
  /** Peer public key. */
  public_key: string;
  /** Peer endpoint, if known. */
  endpoint?: string;
  /** Allowed IPs. */
  allowed_ips: string[];
  /** Unix time of the latest handshake; 0 when none. */
  latest_handshake: number;
}

/**
 * Parses `wg show <iface> dump`. The first line describes the interface and
 * holds its private key; it is dropped, so no interface key material is
 * returned or persisted. Only peer public keys remain.
 */
export function parseDump(text: string): LivePeer[] {
  const rows = text.split("\n").filter((l) => l.length > 0).slice(1);
  return rows.map((l) => {
    const f = l.split("\t");
    return {
      public_key: f[0],
      ...(f[2] && f[2] !== "(none)" ? { endpoint: f[2] } : {}),
      allowed_ips: f[3] && f[3] !== "(none)" ? f[3].split(",") : [],
      latest_handshake: Number(f[4] ?? 0) || 0,
    };
  }).sort((a, b) => (a.public_key < b.public_key ? -1 : 1));
}
