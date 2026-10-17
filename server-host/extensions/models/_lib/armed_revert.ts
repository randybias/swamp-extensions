/**
 * The armed-revert protocol: a host-side dead-man's switch built before any
 * dangerous firewall change, and cancelled only by an explicit commit.
 *
 * The switch is a `systemd-run --on-active` transient timer, owned by PID 1,
 * that runs a small restore script after `revert_after_s`. Because the timer
 * lives on the host, it fires even when the SSH session that armed it has
 * died, so an operator who locks themselves out recovers without console
 * access. This module renders the scripts and argv; it never runs anything.
 *
 * @module
 */

import { TABLE } from "./nftables.ts";
import type { RemoteCall } from "./remote.ts";
import { HostConfigError } from "./validate.ts";

/** Remote directory holding snapshots and revert scripts. */
export const STATE_DIR = "/var/lib/server-host";
/** Seconds past a revert's expiry during which a not-yet-running restore is waited for. */
export const FIRING_GRACE_S = 120;
/** Grammar of a revert token; the token is embedded in remote paths and units. */
export const TOKEN_RE = /^[0-9a-f]{16,64}$/;

/** The remote path of the nftables snapshot for `token`. */
export function snapshotPath(token: string): string {
  assertToken(token);
  return `${STATE_DIR}/revert-${token}.nft`;
}

/** The remote path of the revert script for `token`. */
export function scriptPath(token: string): string {
  assertToken(token);
  return `${STATE_DIR}/revert-${token}.sh`;
}

/** The host-side lock serializing arm, apply, restore and cancel. */
export const LOCK_PATH = `${STATE_DIR}/revert.lock`;
/** The host-side record of the one current revert: `<token> <expiry epoch> <managed sha256>`. */
export const CURRENT_PATH = `${STATE_DIR}/current`;

/** The base name of the transient timer unit for `token`. */
export function unitName(token: string): string {
  assertToken(token);
  return `server-host-revert-${token}`;
}

function assertToken(token: string): void {
  if (!TOKEN_RE.test(token)) {
    throw new HostConfigError("Not a revert token");
  }
}

/** Seconds a script waits for the host lock before it reports the host busy. */
export const LOCK_WAIT_S = 20;
/** Seconds an arm or cancel may run on the host. */
const CHANGE_DEADLINE_S = 60;
/** Seconds the guarded apply may run, kept under the shortest revert (60 s). */
export const APPLY_DEADLINE_S = 30;
/** Seconds a read-only probe may run on the host. */
export const PROBE_DEADLINE_S = 30;
/** Seconds the revert script waits for the lock before it restores anyway. */
const RESTORE_LOCK_WAIT_S = 120;

const LOCK = { path: LOCK_PATH, waitSec: LOCK_WAIT_S } as const;

/** Shell helper: true when a unit is active or on its way in or out of it. */
const BUSY_FN = `busy() {
  case "$(systemctl is-active "$1" 2>/dev/null || true)" in
    active|activating|deactivating|reloading) return 0 ;;
  esac
  return 1
}
`;

/**
 * The restore script the timer runs. It holds the host lock for its whole run,
 * so an apply or a replacement arm can never interleave with it. It restores
 * only while it is still the CURRENT revert and its snapshot exists: a
 * superseded or already-cancelled revert does nothing, so a late restore can
 * never overwrite newer rules. The restore is ONE `nft -f -` transaction
 * (`add table` and `delete table` of the managed table plus its snapshot; no other table is read, flushed or restored).
 */
export function renderRevertScript(token: string): string {
  const snap = snapshotPath(token);
  const self = scriptPath(token);
  return `#!/bin/sh
# Armed revert for @randybias/server-host. Generated; do not edit.
set -eu
exec 9>"${LOCK_PATH}"
# Every holder of the lock is bounded by its own deadline, so a lock still held
# after the wait belongs to a wedged process; restoring matters more than
# excluding it.
flock -w ${RESTORE_LOCK_WAIT_S} 9 || echo "lock wait expired; restoring anyway" >&2
snap="${snap}"
ctok=
if [ -f "${CURRENT_PATH}" ]; then read ctok _ < "${CURRENT_PATH}" || true; fi
if [ "$ctok" != '${token}' ] || [ ! -f "$snap" ]; then
  rm -f "$snap" "${self}"
  exit 0
fi
{
  echo 'add table inet ${TABLE}'
  echo 'delete table inet ${TABLE}'
  if [ -s "$snap" ]; then cat "$snap"; fi
} | nft -f -
rm -f "$snap" "${self}" "${CURRENT_PATH}"
`;
}

/**
 * The call that arms the dead-man's switch, all under the host lock: refuse
 * (exit 75) while any earlier revert's timer OR service is active, or its
 * artifacts remain within {@link FIRING_GRACE_S} of its expiry; otherwise
 * clear the dead revert's leftovers, snapshot the ruleset, record this token
 * as current, and start the transient `--on-active` timer. The snapshot is
 * taken here, under the lock, so it cannot predate another change. A lock that
 * stays busy past {@link LOCK_WAIT_S} also exits 75, so a wedged holder cannot
 * hang the arm.
 */
export function armCall(
  token: string,
  revertAfterS: number,
  sudo: boolean,
  managedSha256: string,
): RemoteCall {
  if (!/^[0-9a-f]{64}$/.test(managedSha256)) {
    throw new HostConfigError("managed table hash must be 64 lowercase hex");
  }
  if (
    !Number.isInteger(revertAfterS) || revertAfterS < 60 || revertAfterS > 1800
  ) {
    throw new HostConfigError("revert_after_s must be 60-1800");
  }
  const unit = unitName(token);
  return {
    sudo,
    deadlineS: CHANGE_DEADLINE_S,
    lock: LOCK,
    umask: "077",
    script: `${BUSY_FN}cur="${CURRENT_PATH}"
if [ -f "$cur" ]; then
  otok=; oexp=0
  read otok oexp _ < "$cur" || true
  case "$otok" in ""|*[!0-9a-f]*) otok= ;; esac
  case "$oexp" in ""|*[!0-9]*) oexp=0 ;; esac
  if [ -n "$otok" ] && [ "$otok" != '${token}' ]; then
    ou="server-host-revert-$otok"
    if busy "$ou.timer" || busy "$ou.service"; then
      echo "an earlier revert is still active" >&2
      exit 75
    fi
    if [ -f "${STATE_DIR}/revert-$otok.nft" ] && [ "$(date +%s)" -lt $((oexp + ${FIRING_GRACE_S})) ]; then
      echo "an earlier revert has not finished firing" >&2
      exit 75
    fi
    rm -f "${STATE_DIR}/revert-$otok.nft" "${STATE_DIR}/revert-$otok.sh"
  fi
fi
snap="${snapshotPath(token)}"
: > "$snap"
tables=$(nft list tables)
if printf '%s\\n' "$tables" | grep -qx 'table inet ${TABLE}'; then nft list table inet ${TABLE} > "$snap"; fi
printf '%s %s %s\\n' '${token}' "$(( $(date +%s) + ${revertAfterS} ))" '${managedSha256}' > "$cur.tmp"
mv -f "$cur.tmp" "$cur"
if ! systemd-run --on-active=${revertAfterS}s --unit=${unit} --collect --description='server-host armed revert' --quiet '${
      scriptPath(token)
    }'; then
  rm -f "$cur" "${snapshotPath(token)}"
  exit 1
fi
`,
  };
}

/** Exit codes of {@link guardedApplyCall} when the revert no longer guards the change. */
export const APPLY_REFUSED = {
  /** The revert is not the current one (superseded). */
  superseded: 70,
  /** The restore already ran, or the snapshot is gone. */
  restored: 71,
  /** The revert has expired. */
  expired: 72,
  /** The timer is no longer active. */
  timerGone: 73,
} as const;

/**
 * The call that applies the ruleset `rules`, under the host lock and only
 * while this token's revert still guards the change: it is the current revert,
 * its snapshot exists, it has not expired and its timer is active. Because the
 * restore holds the same lock, the apply either completes before the restore
 * starts or is refused after it; the two can never interleave.
 */
export function guardedApplyCall(
  token: string,
  sudo: boolean,
  rules: Uint8Array,
): RemoteCall {
  const unit = unitName(token);
  return {
    sudo,
    data: rules,
    deadlineS: APPLY_DEADLINE_S,
    lock: { path: LOCK_PATH, waitSec: 10 },
    script: `[ -f "${CURRENT_PATH}" ] || exit ${APPLY_REFUSED.superseded}
ctok=; cexp=0
read ctok cexp _ < "${CURRENT_PATH}" || true
[ "$ctok" = '${token}' ] || exit ${APPLY_REFUSED.superseded}
[ -f "${snapshotPath(token)}" ] || exit ${APPLY_REFUSED.restored}
case "$cexp" in ""|*[!0-9]*) exit ${APPLY_REFUSED.expired} ;; esac
[ "$(date +%s)" -lt "$cexp" ] || exit ${APPLY_REFUSED.expired}
[ "$(systemctl is-active '${unit}.timer' || true)" = active ] || exit ${APPLY_REFUSED.timerGone}
bw_data | nft -f -
`,
  };
}

function cancelCall(token: string, sudo: boolean, requireActive: boolean) {
  const unit = unitName(token);
  const call: RemoteCall = {
    sudo,
    deadlineS: CHANGE_DEADLINE_S,
    lock: LOCK,
    script: `unit='${unit}'
${
      requireActive
        ? `state=$(systemctl is-active "$unit.timer" || true)
if [ "$state" != "active" ]; then
  echo "revert timer $unit is not active" >&2
  exit 1
fi
systemctl stop "$unit.timer"
`
        : `systemctl stop "$unit.timer" 2>/dev/null || true
`
    }systemctl stop "$unit.service" 2>/dev/null || true
ctok=
if [ -f "${CURRENT_PATH}" ]; then read ctok _ < "${CURRENT_PATH}" || true; fi
if [ "$ctok" = '${token}' ]; then rm -f "${CURRENT_PATH}"; fi
rm -f '${snapshotPath(token)}' '${scriptPath(token)}'
`,
  };
  return call;
}

/**
 * The call that confirms the change: under the host lock it FAILS unless the
 * timer is still active, stops the timer and service, and removes the files
 * and the current marker. A non-zero exit means no commit may be recorded.
 */
export function commitCall(token: string, sudo: boolean): RemoteCall {
  return cancelCall(token, sudo, true);
}

/**
 * The call that abandons a revert after a change that definitely did not
 * happen: like commit, but tolerant, so it succeeds when the timer is already
 * gone. Idempotent.
 */
export function disarmCall(token: string, sudo: boolean): RemoteCall {
  return cancelCall(token, sudo, false);
}

/** The READ-ONLY call that prints the host's current-revert marker, if any. */
export function markerCall(sudo: boolean): RemoteCall {
  return {
    sudo,
    deadlineS: PROBE_DEADLINE_S,
    // Empty only when the marker is absent; any read error exits non-zero.
    script: `if [ -e "${CURRENT_PATH}" ]; then cat "${CURRENT_PATH}"; fi
`,
  };
}

/**
 * Parses the marker `<token> <expiry epoch> [<managed table sha256>]`; null
 * when absent or malformed.
 */
export function parseMarker(
  stdout: string,
): { token: string; expires_at_s: number; managed_sha256?: string } | null {
  const m = /^([0-9a-f]{16,64}) ([0-9]{1,12})(?: ([0-9a-f]{64}))?\s*$/.exec(
    stdout,
  );
  return m && TOKEN_RE.test(m[1])
    ? {
      token: m[1],
      expires_at_s: Number(m[2]),
      ...(m[3] ? { managed_sha256: m[3] } : {}),
    }
    : null;
}

/** The READ-ONLY call that reports whether the revert timer is still armed. */
export function probeCall(token: string, sudo: boolean): RemoteCall {
  return {
    sudo,
    deadlineS: PROBE_DEADLINE_S,
    script: `systemctl is-active '${unitName(token)}.timer'
`,
  };
}

/** True when `systemctl is-active` reported `active` for a timer. */
export function isTimerActive(stdout: string): boolean {
  return stdout.trim() === "active";
}
