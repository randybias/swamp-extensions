/**
 * The host-side armed-revert artifacts, adapted from the server-host hardened
 * pattern: one host script decides under a `flock` whether an earlier revert is
 * still live, snapshots only what this change owns, writes a per-token restore
 * script and a current-revert marker, and only then activates the transient
 * timer. The restore is token-guarded, removes only created devices, restores
 * only owned files and records its outcome; a failure leaves the marker for an
 * operator and never reboots.
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
  /** Virtual devices this change creates (bridge first is applied in restore). */
  created: string[];
  /** Subset of `created` that are OVS bridges. */
  createdBridges: string[];
  /** The managed files this change owns (the restore restores only these). */
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
  /** Devices this change created. */
  created: string[];
  /** `pending`, `pass` or `fail`. */
  result: "pending" | "pass" | "fail";
  /** Fire time, epoch seconds, or null. */
  fired_at: number | null;
}

function shellQuote(value: string): string {
  return `'${value.replace(/'/g, `'\\''`)}'`;
}

/** Renders the marker JSON. */
export function renderMarker(marker: RevertMarker): string {
  if (!TOKEN_RE.test(marker.token)) throw new Error("invalid revert token");
  return JSON.stringify(marker) + "\n";
}

function ownedFileRestore(ctx: RevertContext): string {
  if (ctx.backend === "netplan") {
    const files = ctx.ownedFiles.map(shellQuote).join(" ");
    return [
      `for f in ${files}; do`,
      `  b="$(basename "$f")"`,
      `  if [ -f "$SNAP/$b" ]; then cp -a "$SNAP/$b" "$f.host-net-new" && mv -f "$f.host-net-new" "$f"; else rm -f "$f"; fi`,
      `done`,
    ].join("\n");
  }
  return [
    `for f in /etc/systemd/network/90-host-net-*; do [ -e "$f" ] || continue; b="$(basename "$f")"; if [ ! -f "$SNAP/$b" ]; then rm -f "$f"; fi; done`,
    `cp -a "$SNAP/." /etc/systemd/network/ 2>/dev/null || true`,
  ].join("\n");
}

/**
 * Renders the per-token restore script. It exits non-zero unless invoked with
 * its own token, is a no-op when superseded, deletes only created devices
 * (bridges first), restores parent MTUs and only owned files, and records its
 * outcome in the marker under a trap so a mid-restore failure still writes
 * `fail`.
 */
export function renderRestoreScript(ctx: RevertContext): string {
  if (!TOKEN_RE.test(ctx.token)) throw new Error("invalid revert token");
  for (const name of [...ctx.created, ...ctx.createdBridges]) {
    assertIface(name, "created device");
  }
  const dir = revertDir(ctx.token);
  const bridges = ctx.createdBridges.map(shellQuote).join(" ");
  const others = ctx.created.filter((n) => !ctx.createdBridges.includes(n))
    .map(shellQuote).join(" ");
  const parentLines = ctx.parentMtus
    .map((p) => `ip link set dev ${shellQuote(p.name)} mtu ${p.mtu}`)
    .join("\n");
  const applyCmd = ctx.backend === "netplan"
    ? "netplan apply"
    : "networkctl reload && networkctl reconfigure";
  return `#!/bin/sh
# host-net restore, token ${ctx.token}. Generated; do not edit.
set -eu
TOKEN=${shellQuote(ctx.token)}
DIR=${shellQuote(dir)}
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
flock 9
cur=
if [ -f "${CURRENT_PATH}" ]; then read cur _ < "${CURRENT_PATH}" || true; fi
if [ "$cur" != "$TOKEN" ]; then
  rm -rf "$DIR"
  trap - EXIT
  exit 0
fi
# 1. delete only the devices this change created (bridge before its ports).
for dev in ${bridges} ${others}; do ip link delete dev "$dev" 2>/dev/null || true; done
${
    ctx.bridgeType === "ovs" && ctx.createdBridges.length > 0
      ? `for br in ${bridges}; do ovs-vsctl --if-exists del-br "$br" >/dev/null 2>&1 || true; done`
      : ""
  }
# 2. restore the parent MTUs this change raised.
${parentLines}
# 3. restore only the owned files from the snapshot.
${ownedFileRestore(ctx)}
# 4. apply the restored configuration.
${applyCmd}
# 5. record the outcome; a non-empty default route means the path is back.
if [ -n "$(ip -j route show default 2>/dev/null || true)" ]; then RESULT=pass; fi
write_result
rm -f "${CURRENT_PATH}"
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
}

/**
 * Renders the arm script: under the lock it refuses while any earlier revert
 * timer or service is active (or within the firing grace), removes a dead
 * revert's leftovers, snapshots only the owned files, writes the per-token
 * restore script and the current marker, and activates the timer. If the timer
 * fails to start it rolls its own marker and snapshot back and exits non-zero.
 */
export function renderArmScript(
  ctx: RevertContext,
  opts: ArmOptions,
): string {
  if (!TOKEN_RE.test(ctx.token)) throw new Error("invalid revert token");
  if (!/^[0-9a-f]{64}$/.test(opts.armedSha256)) {
    throw new Error("armed sha must be 64 hex");
  }
  if (!Number.isInteger(opts.revertAfterS) || opts.revertAfterS < 60) {
    throw new Error("revert_after_s out of range");
  }
  const dir = revertDir(ctx.token);
  const unit = unitName(ctx.token);
  const marker = renderMarker({
    token: ctx.token,
    expires_at: 0,
    armed_sha256: opts.armedSha256,
    content_sha256: opts.contentSha256,
    created: ctx.created,
    result: "pending",
    fired_at: null,
  }).trim();
  const restore = renderRestoreScript(ctx);
  return `set -eu
umask 077
mkdir -p "${STATE_DIR}"
exec 9>"${LOCK_PATH}"
flock 9
cur="${CURRENT_PATH}"
if [ -f "$cur" ]; then
  otok=; oexp=0
  read otok oexp _ < "$cur" || true
  case "$otok" in ""|*[!0-9a-f]*) otok= ;; esac
  case "$oexp" in ""|*[!0-9]*) oexp=0 ;; esac
  if [ -n "$otok" ] && [ "$otok" != ${shellQuote(ctx.token)} ]; then
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
    rm -rf "${STATE_DIR}/revert/$otok"
  fi
fi
DIR=${shellQuote(dir)}
SNAP="$DIR/snapshot"
mkdir -p "$SNAP"
if [ -d /etc/netplan ]; then cp -a /etc/netplan/. "$SNAP/" 2>/dev/null || true; fi
if [ -d /etc/systemd/network ]; then for f in /etc/systemd/network/90-host-net-*; do [ -e "$f" ] || continue; cp -a "$f" "$SNAP/"; done; fi
ip -d -j link > "$DIR/live-link.json"
printf '%s\\n' '${marker.replace(/'/g, `'\\''`)}' > "$DIR/marker.json"
cat > "${shellQuote(restorePath(ctx.token))}" <<'HOST_NET_RESTORE'
${restore}HOST_NET_RESTORE
chmod 700 "${shellQuote(restorePath(ctx.token))}"
now=$(date +%s)
printf '%s %s %s\\n' ${
    shellQuote(ctx.token)
  } "$((now + ${opts.revertAfterS}))" ${
    shellQuote(opts.armedSha256)
  } > "$cur.tmp"
mv -f "$cur.tmp" "$cur"
if ! systemd-run --unit=${unit} --on-active=${opts.revertAfterS} --timer-property=AccuracySec=1s "${
    shellQuote(restorePath(ctx.token))
  }" ${shellQuote(ctx.token)}; then
  rm -f "$cur" "$DIR/marker.json" "${shellQuote(restorePath(ctx.token))}"
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
flock 9
${active}systemctl stop "${unit}.service" 2>/dev/null || true
cur=
if [ -f "${CURRENT_PATH}" ]; then read cur _ < "${CURRENT_PATH}" || true; fi
if [ "$cur" = ${shellQuote(token)} ]; then rm -f "${CURRENT_PATH}"; fi
rm -rf ${shellQuote(revertDir(token))}
`;
}

/** The READ-ONLY script that prints the current marker line, if any. */
export function renderMarkerReadScript(): string {
  return `if [ -e "${CURRENT_PATH}" ]; then cat "${CURRENT_PATH}"; fi`;
}
