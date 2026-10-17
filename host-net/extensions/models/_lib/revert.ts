/**
 * The host-side armed-revert artifacts, adapted from the server-host hardened
 * pattern: one host script decides under a `flock -w` whether an earlier revert
 * is still live, snapshots exactly the owned files this change may replace,
 * writes a per-token restore script and a current-revert marker, and only then
 * activates the transient timer. The restore is token-guarded, removes only
 * created devices, restores exactly the owned files and records its outcome;
 * a failure keeps the marker for an operator and never reboots.
 *
 * @module
 */

import { assertIface, TOKEN_RE } from "./validate.ts";

/** The host state directory. */
export const STATE_DIR = "/var/lib/host-net";
/** The host lock every mutating step shares. */
export const LOCK_PATH = "/run/host-net.lock";
/** The current-revert marker line file. */
export const CURRENT_PATH = `${STATE_DIR}/current`;

/** The directory that holds one revert. */
export function revertDir(token: string): string {
  if (!TOKEN_RE.test(token)) throw new Error("invalid revert token");
  return `${STATE_DIR}/revert/${token}`;
}

/** The per-token restore script. */
export function restorePath(token: string): string {
  return `${revertDir(token)}/restore.sh`;
}

/** The per-token staging directory for config files. */
export function stagedDir(token: string): string {
  return `${revertDir(token)}/staged`;
}

/** The systemd unit name for a token. */
export function unitName(token: string): string {
  return `host-net-revert-${token}`;
}

/** Everything the restore and arm scripts need to know. */
export interface RevertContext {
  /** 16-hex token. */
  token: string;
  /** Config backend. */
  backend: "netplan" | "networkd";
  /** Bridge implementation. */
  bridgeType: "linux" | "ovs";
  /** Virtual devices this change creates. */
  created: string[];
  /** Subset of `created` that are OVS bridges, deleted with `ovs-vsctl`. */
  createdBridges: string[];
  /** The managed files this change owns and may replace. */
  ownedFiles: string[];
  /** Parent interfaces whose MTU this change raises, with the pre-change value. */
  parentMtus: { name: string; mtu: number }[];
}

/** The marker written at arm time. */
export interface RevertMarker {
  /** Token. */
  token: string;
  /** Expiry, epoch seconds. */
  expires_at: number;
  /** SHA-256 of the rendered config identity. */
  armed_sha256: string;
  /** SHA-256 over the managed file contents only. */
  content_sha256: string;
  /** `apply` or `remove`. */
  operation: string;
  /** Devices this change created. */
  created: string[];
  /** `pending`, `pass` or `fail`. */
  result: "pending" | "pass" | "fail";
  /** Fire time, epoch seconds, or null. */
  fired_at: number | null;
}

function shq(value: string): string {
  return `'${value.replace(/'/g, `'\\''`)}'`;
}

/** Renders the marker JSON. */
export function renderMarker(marker: RevertMarker): string {
  if (!TOKEN_RE.test(marker.token)) throw new Error("invalid revert token");
  return JSON.stringify(marker) + "\n";
}

/** The shell list of owned files, for a `for` loop. */
function ownedList(ctx: RevertContext): string {
  return ctx.ownedFiles.map(shq).join(" ");
}

/**
 * Shell (inside the arm script) that records the management path the SSH
 * session actually uses: the peer address, and the device, gateway and source
 * address `ip route get <peer>` picks for it, with the source's prefix length.
 * It refuses (exit 77) when it cannot, or when the checks it writes do not pass
 * against the state as it is now, so no change is ever made that could not be
 * judged afterwards. Works for IPv4 and IPv6 alike.
 */
function recordPathScript(): string {
  return String.raw`ssh_conn="$(printenv SSH_CONNECTION || true)"
peer="$(printf '%s' "$ssh_conn" | cut -d' ' -f1)"
local_ip="$(printf '%s' "$ssh_conn" | cut -d' ' -f3)"
case "$peer$local_ip" in ""|*[!0-9A-Fa-f:.]*) echo 'host-net: cannot determine the management peer' >&2; rm -rf "$DIR"; exit 77 ;; esac
[ -n "$peer" ] && [ -n "$local_ip" ] || { echo 'host-net: cannot determine the management peer' >&2; rm -rf "$DIR"; exit 77; }
rg="$(ip -j route get "$peer" from "$local_ip" 2>/dev/null | tr -d ' ' || true)"
pick() { printf '%s' "$rg" | sed -n "s/.*\"$1\":\"\([^\"]*\)\".*/\1/p" | head -n 1; }
pdev="$(pick dev)"; pgw="$(pick gateway)"; psrc="$(pick prefsrc)"
ppl="$(ip -j addr show dev "$pdev" 2>/dev/null | tr -d ' ' | sed -n "s/.*\"local\":\"$psrc\",\"prefixlen\":\([0-9]*\).*/\1/p" | head -n 1)"
case "$pdev" in ""|*[!A-Za-z0-9._@:-]*) pdev= ;; esac
case "$pgw$psrc" in *[!0-9A-Fa-f:.]*) pdev= ;; esac
case "$ppl" in ""|*[!0-9]*) pdev= ;; esac
[ -n "$pdev" ] && [ -n "$psrc" ] || { echo 'host-net: cannot record the management path' >&2; rm -rf "$DIR"; exit 77; }
{
  printf "PEER='%s'\nLOCAL='%s'\nDEV='%s'\nGW='%s'\nSRC='%s'\nPL='%s'\n" "$peer" "$local_ip" "$pdev" "$pgw" "$psrc" "$ppl"
  cat <<'HOST_NET_CHECKS'
` + POST_CHECKS_BODY + String.raw`
HOST_NET_CHECKS
} > "$DIR/checks.sh"
( CHECK=fail; . "$DIR/checks.sh"; [ "$CHECK" = pass ] ) || { echo 'host-net: the management path does not pass its own checks now' >&2; rm -rf "$DIR"; exit 77; }`;
}

/**
 * The checks proper, run on the host with the PEER/DEV/GW/SRC/PL values the
 * arm script wrote above them. CHECK=pass only when the path to the SSH peer
 * leaves through the same device, via the same gateway, from the same source
 * address, that source is still configured with the same prefix length, and
 * the route is not marked dead or linkdown.
 */
const POST_CHECKS_BODY = String.raw`CHECK=fail
now="$(ip -j route get "$PEER" from "$LOCAL" 2>/dev/null | tr -d ' ' || true)"
pick() { printf '%s' "$now" | sed -n "s/.*\"$1\":\"\([^\"]*\)\".*/\1/p" | head -n 1; }
case "$now" in ""|*'"linkdown"'*|*'"dead"'*) ;; *)
  if [ "$(pick dev)" = "$DEV" ] && [ "$(pick gateway)" = "$GW" ] && [ "$(pick prefsrc)" = "$SRC" ]; then
    addrs="$(ip -j addr show dev "$DEV" 2>/dev/null | tr -d ' ' || true)"
    case "$addrs" in *"\"local\":\"$SRC\",\"prefixlen\":$PL,"*) CHECK=pass ;; esac
  fi ;;
esac`;

/** Reads a recorded checks file into CHECK without trusting it: anything but a clean pass is fail. */
const RUN_CHECKS = String
  .raw`CHECK="$( ( CHECK=fail; . "$DIR/checks.sh"; printf '%s' "$CHECK" ) 2>/dev/null || true )"
[ "$CHECK" = pass ] || CHECK=fail`;

/**
 * Renders the per-token restore script. It exits non-zero unless invoked with
 * its own token, is a no-op when superseded, deletes only created devices
 * (bridges first), restores the parent MTUs and exactly the owned files from
 * the manifest, and records its outcome under a trap so a mid-restore failure
 * still writes `fail`. The apply command's exit status is advisory (a cloud-init
 * netplan that matches a renamed NIC by MAC can exit non-zero on a host that is
 * in fact restored): it is logged, and pass or fail rests on the post-restore
 * checks alone. The current marker is cleared only on success.
 */
export function renderRestoreScript(ctx: RevertContext): string {
  if (!TOKEN_RE.test(ctx.token)) throw new Error("invalid revert token");
  for (const name of [...ctx.created, ...ctx.createdBridges]) {
    assertIface(name, "created device");
  }
  const dir = revertDir(ctx.token);
  const bridges = ctx.createdBridges.map(shq).join(" ");
  const others = ctx.created.filter((n) => !ctx.createdBridges.includes(n))
    .map(shq).join(" ");
  const parentLines = ctx.parentMtus
    .map((p) => `ip link set dev ${shq(p.name)} mtu ${p.mtu}`)
    .join("\n");
  const applyCmd = ctx.backend === "netplan"
    ? "netplan apply"
    : "networkctl reload && networkctl reconfigure";
  const ovsDelete = ctx.bridgeType === "ovs" && ctx.createdBridges.length > 0
    ? `for br in ${bridges}; do ovs-vsctl --if-exists del-br "$br" >/dev/null 2>&1 || true; done`
    : "";
  return `#!/bin/sh
# host-net restore, token ${ctx.token}. Generated; do not edit.
set -eu
TOKEN=${shq(ctx.token)}
DIR=${shq(dir)}
SNAP="$DIR/snapshot"
MARKER="$DIR/marker.json"
RESULT=fail
write_result() {
  now="$(date +%s)"
  tmp="$MARKER.tmp"
  printf '{"token":"%s","result":"%s","fired_at":%s}\\n' "$TOKEN" "$RESULT" "$now" > "$tmp" 2>/dev/null && mv -f "$tmp" "$MARKER" || true
}
[ "\${1-}" = "$TOKEN" ] || { echo 'host-net: wrong token' >&2; exit 64; }
exec 9>"${LOCK_PATH}"
flock -w 30 9 || { echo 'host-net: lock busy' >&2; exit 75; }
cur=
if [ -f "${CURRENT_PATH}" ]; then read cur _ < "${CURRENT_PATH}" || true; fi
if [ "$cur" != "$TOKEN" ]; then
  rm -rf "$DIR"
  exit 0
fi
# Only a restore that is really running records an outcome: a refused call
# (wrong token, busy lock, stale token) must never touch the marker.
trap 'RESULT=fail; write_result' EXIT
# 1. delete only the devices this change created (bridge before its ports).
for dev in ${bridges} ${others}; do ip link delete dev "$dev" 2>/dev/null || true; done
${ovsDelete}
# 2. restore exactly the owned files recorded in the manifest. A copy failure
#    must abort the restore (set -e does not catch an AND-list failure).
if [ -f "$DIR/owned.txt" ]; then
  while IFS="$(printf '\\t')" read -r p state; do
    [ -n "$p" ] || continue
    b="$(basename "$p")"
    if [ "$state" = present ] && [ -f "$SNAP/$b" ]; then
      cp -a "$SNAP/$b" "$p.host-net-new" && mv -f "$p.host-net-new" "$p" || exit 1
    else
      rm -f "$p"
    fi
  done < "$DIR/owned.txt"
fi
# 3. restore the parent MTUs this change raised, after the files.
${parentLines}
# 4. apply the restored configuration. Its exit status is advisory.
applyrc=0
${applyCmd} || applyrc=$?
if [ "$applyrc" -ne 0 ]; then
  msg="host-net: restore: apply exited $applyrc; judging by the post-restore checks"
  echo "$msg" >&2
  logger -t host-net "$msg" 2>/dev/null || true
fi
# 5. record the outcome; pass needs the recorded management path to hold again.
${RUN_CHECKS}
RESULT=$CHECK
write_result
if [ "$RESULT" = pass ]; then rm -f "${CURRENT_PATH}"; fi
trap - EXIT
exit 0
`;
}

/** Arguments for {@link renderArmScript}. */
export interface ArmOptions {
  /** Seconds until the timer fires. */
  revertAfterS: number;
  /** The rendered config identity. */
  armedSha256: string;
  /** SHA-256 over the managed file contents only. */
  contentSha256: string;
  /** `apply` or `remove`. */
  operation: "apply" | "remove";
}

/**
 * Renders the arm script. Under `flock -w 30` it refuses (exit 76) while an
 * earlier revert timer or service is active, within the firing grace, or left a
 * `fail` marker for an operator; otherwise it removes a dead revert's
 * leftovers, snapshots exactly the owned files (with a present/absent
 * manifest), writes the per-token restore script and the marker, and activates
 * the timer. A failed `systemd-run` rolls its own files back and exits 1.
 */
export function renderArmScript(ctx: RevertContext, opts: ArmOptions): string {
  if (!TOKEN_RE.test(ctx.token)) throw new Error("invalid revert token");
  if (!/^[0-9a-f]{64}$/.test(opts.armedSha256)) {
    throw new Error("armed sha must be 64 hex");
  }
  if (!Number.isInteger(opts.revertAfterS) || opts.revertAfterS < 60) {
    throw new Error("revert_after_s out of range");
  }
  const dir = revertDir(ctx.token);
  const unit = unitName(ctx.token);
  const self = restorePath(ctx.token);
  const marker = renderMarker({
    token: ctx.token,
    expires_at: 0,
    armed_sha256: opts.armedSha256,
    content_sha256: opts.contentSha256,
    operation: opts.operation,
    created: ctx.created,
    result: "pending",
    fired_at: null,
  }).trim().replace(/'/g, `'\\''`);
  return `set -eu
umask 077
mkdir -p "${STATE_DIR}"
exec 9>"${LOCK_PATH}"
flock -w 30 9 || { echo 'host-net: lock busy' >&2; exit 75; }
cur="${CURRENT_PATH}"
if [ -f "$cur" ]; then
  otok=; oexp=0
  read otok oexp _ < "$cur" || true
  case "$otok" in ""|*[!0-9a-f]*) otok= ;; esac
  case "$oexp" in ""|*[!0-9]*) oexp=0 ;; esac
  if [ -n "$otok" ] && [ "$otok" != ${shq(ctx.token)} ]; then
    ou="${unitName(ctx.token).replace(ctx.token, "$otok")}"
    state=$(systemctl is-active "$ou.timer" || true)
    sstate=$(systemctl is-active "$ou.service" || true)
    if [ "$state" = active ] || [ "$sstate" = active ]; then
      echo "an earlier revert is still active" >&2
      exit 76
    fi
    if [ "$(date +%s)" -lt $((oexp + 120)) ]; then
      echo "an earlier revert has not finished firing" >&2
      exit 76
    fi
    if [ -f "${STATE_DIR}/revert/$otok/marker.json" ] && grep -q '"result":"fail"' "${STATE_DIR}/revert/$otok/marker.json"; then
      echo "an earlier revert failed and needs clearing" >&2
      exit 76
    fi
    rm -rf "${STATE_DIR}/revert/$otok"
  fi
fi
DIR=${shq(dir)}
SNAP="$DIR/snapshot"
rm -rf "$DIR"
mkdir -p "$SNAP" "$DIR/staged"
: > "$DIR/owned.txt"
for p in ${ownedList(ctx)}; do
  b="$(basename "$p")"
  if [ -f "$p" ]; then cp -a "$p" "$SNAP/$b"; printf '%s\\tpresent\\n' "$p" >> "$DIR/owned.txt"; else printf '%s\\tabsent\\n' "$p" >> "$DIR/owned.txt"; fi
done
printf '%s\\n' '${marker}' > "$DIR/marker.json"
${recordPathScript()}
cat > ${shq(self)} <<'HOST_NET_RESTORE'
${renderRestoreScript(ctx)}HOST_NET_RESTORE
chmod 700 ${shq(self)}
now=$(date +%s)
printf '%s %s %s\\n' ${shq(ctx.token)} "$((now + ${opts.revertAfterS}))" ${
    shq(opts.armedSha256)
  } > "$cur.tmp"
mv -f "$cur.tmp" "$cur"
if ! systemd-run --unit=${unit} --on-active=${opts.revertAfterS} --timer-property=AccuracySec=1s ${
    shq(self)
  } ${shq(ctx.token)}; then
  rm -f "$cur" "$DIR/marker.json" ${shq(self)}
  exit 1
fi
`;
}

/**
 * Renders the disarm script. With `requireActive` it fails unless this token's
 * timer is active at cancel time (commit); otherwise it is tolerant (abandon).
 * Either way it stops the timer and any service and removes this token's files.
 */
export function renderDisarmScript(
  token: string,
  requireActive: boolean,
): string {
  const unit = unitName(token);
  const active = requireActive
    ? `state=$(systemctl is-active "${unit}.timer" || true)
if [ "$state" != active ]; then
  echo "revert timer ${unit} is not active" >&2
  exit 1
fi
systemctl stop "${unit}.timer"
`
    : `systemctl stop "${unit}.timer" 2>/dev/null || true
`;
  return `set -eu
exec 9>"${LOCK_PATH}"
flock -w 30 9 || { echo 'host-net: lock busy' >&2; exit 75; }
${active}systemctl stop "${unit}.service" 2>/dev/null || true
cur=
if [ -f "${CURRENT_PATH}" ]; then read cur _ < "${CURRENT_PATH}" || true; fi
if [ "$cur" = ${shq(token)} ]; then rm -f "${CURRENT_PATH}"; fi
rm -rf ${shq(revertDir(token))}
`;
}

/** The READ-ONLY script that prints the current marker line, if any. */
export function renderMarkerReadScript(): string {
  return `if [ -e "${CURRENT_PATH}" ]; then cat "${CURRENT_PATH}"; fi`;
}

/** The READ-ONLY script that prints the current revert's marker JSON, if any. */
export function renderMarkerJsonReadScript(token: string): string {
  const marker = `${revertDir(token)}/marker.json`;
  return `if [ -e ${shq(marker)} ]; then cat ${shq(marker)}; fi`;
}

/**
 * Renders the operator's clear script. Under the host lock it removes the
 * current revert's state (stopping its leftover timer) only when that revert's
 * marker says `fail` and the post-restore checks pass right now.
 * Exit codes: 10 nothing to clear, 3 marker is not fail, 5 checks fail (the host
 * still needs hands), 75 lock busy.
 */
export function renderClearFailedScript(): string {
  return `set -eu
exec 9>"${LOCK_PATH}"
flock -w 30 9 || { echo 'host-net: lock busy' >&2; exit 75; }
cur=
if [ -f "${CURRENT_PATH}" ]; then read cur _ < "${CURRENT_PATH}" || true; fi
case "$cur" in ""|*[!0-9a-f]*) echo 'no revert marker to clear' >&2; exit 10 ;; esac
[ "\${#cur}" -eq 16 ] || { echo 'no revert marker to clear' >&2; exit 10; }
dir="${STATE_DIR}/revert/$cur"
if [ ! -f "$dir/marker.json" ] || ! tr -d ' ' < "$dir/marker.json" | grep -q '"result":"fail"'; then
  echo 'the revert marker is not a failed restore' >&2
  exit 3
fi
unit="host-net-revert-$cur"
# The checks recorded at arm time (the management path). A missing, empty or
# corrupt file is a failed check, never a different exit code.
DIR="$dir"
${RUN_CHECKS}
if [ "$CHECK" != pass ]; then
  echo 'the post-restore checks still fail; fix the host first' >&2
  exit 5
fi
# Holding the lock means no restore is running; a leftover timer would only
# re-run a restore the host no longer needs.
systemctl stop "$unit.timer" 2>/dev/null || true
systemctl stop "$unit.service" 2>/dev/null || true
rm -f "${CURRENT_PATH}"
rm -rf "$dir"
printf 'cleared %s\\n' "$cur"
`;
}
