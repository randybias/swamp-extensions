/**
 * POSIX `sh` fragments shared by the host scripts. Each fragment is plain
 * text for a script that already runs under `set -eu` in dash.
 *
 * @module
 */

/** POSIX single-quotes a value for a script literal. */
export function shq(value: string): string {
  return `'${value.replace(/'/g, `'\\''`)}'`;
}

/** Runs `inner` under an exclusive flock so concurrent runs serialize. */
export function underLock(lock: string, inner: string): string {
  return ["set -eu", `flock -x ${lock} sh -c ${shq(inner)}`].join("\n");
}

/**
 * Defines `own_all`, which grants the Knot user read access to every managed
 * file that exists and fails when any chown/chgrp fails. Callers roll back on
 * failure instead of exiting with new files already swapped in.
 */
export const OWN_ALL_FN = [
  "own_all() {",
  '  for x in "$@"; do',
  '    [ -f "$x" ] || continue',
  '    chown root:knot "$x" 2>/dev/null || chgrp knot "$x" 2>/dev/null || return 1',
  "  done",
  "}",
].join("\n");

/**
 * Defines `restart_knot`. Knot applies `server.listen` changes only on a
 * restart, never on a reload, so a listen change must go through here.
 */
export const RESTART_KNOT_FN = [
  "restart_knot() {",
  "  systemctl restart knot || return 1",
  "  n=0",
  "  until knotc status >/dev/null 2>&1; do",
  '    n=$((n+1)); [ "$n" -lt 15 ] || return 1; sleep 1',
  "  done",
  "}",
].join("\n");

/**
 * Defines `wait_loaded APEX`, which polls until a requested zone reload has
 * been applied. A non-blocking `zone-reload` is used because the blocking form
 * can wait on outgoing NOTIFY retries to an unreachable secondary.
 */
export const WAIT_LOADED_FN = [
  "wait_loaded() {",
  "  n=0",
  "  while :; do",
  '    st=$(knotc zone-status "$1") || return 1',
  '    case "$st" in *"load: pending"*) ;; *) return 0 ;; esac',
  '    n=$((n+1)); [ "$n" -lt 40 ] || return 1; sleep 1',
  "  done",
  "}",
].join("\n");

/**
 * Defines `query_ok ADDR[@PORT] NAME TYPE ACCEPT...`, which asks the real
 * server and succeeds only when the reply's rcode is one of ACCEPT. kdig
 * exits 0 on SERVFAIL and REFUSED, so the status line is what is checked.
 * Wildcard listen addresses are queried on loopback.
 */
export const QUERY_OK_FN = [
  "query_ok() {",
  "  want=$1; name=$2; qtype=$3; shift 3",
  "  addr=${want%@*}; port=${want#*@}",
  '  [ "$want" = "$addr" ] && port=53',
  '  case "$addr" in 0.0.0.0) addr=127.0.0.1 ;; ::) addr=::1 ;; esac',
  "  n=0",
  "  while :; do",
  '    out=$(kdig +retry=0 +time=2 -p "$port" "@$addr" "$name" "$qtype" 2>/dev/null) || out=',
  '    for rc in "$@"; do',
  '      case "$out" in *"status: $rc"*) return 0 ;; esac',
  "    done",
  '    n=$((n+1)); [ "$n" -lt 10 ] || { echo "QUERY_FAILED $addr:$port" >&2; return 1; }',
  "    sleep 1",
  "  done",
  "}",
].join("\n");
