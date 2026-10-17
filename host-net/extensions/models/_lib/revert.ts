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
 * Renders the per-token restore script. It exits non-zero unless invoked with
 * its own token, is a no-op when superseded, deletes only created devices
 * (bridges first), restores the parent MTUs and exactly the owned files from
 * the manifest, and records its outcome under a trap so a mid-restore failure
 * still writes `fail`. The current marker is cleared only on success.
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
trap 'RESULT=fail; write_result' EXIT
[ "\${1-}" = "$TOKEN" ] || { echo 'host-net: wrong token' >&2; exit 64; }
exec 9>"${LOCK_PATH}"
flock -w 30 9 || { echo 'host-net: lock busy' >&2; exit 75; }
cur=
if [ -f "${CURRENT_PATH}" ]; then read cur _ < "${CURRENT_PATH}" || true; fi
if [ "$cur" != "$TOKEN" ]; then
  rm -rf "$DIR"
  trap - EXIT
  exit 0
fi
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
# 4. apply the restored configuration.
${applyCmd}
# 5. record the outcome; only a non-empty default route is a pass.
route="$(ip -j route show default 2>/dev/null || true)"
case "$route" in ""|"[]") ;; *) RESULT=pass ;; esac
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
