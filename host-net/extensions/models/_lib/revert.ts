/**
 * The host-side armed-revert artifacts: the marker, the restore script and the
 * systemd-run arm/commit commands. The restore removes only the virtual devices
 * this change created and restores the managed config files from the snapshot;
 * it never flushes the OVS database or touches devices it did not create.
 *
 * @module
 */

import { assertIface, TOKEN_RE } from "./validate.ts";

/** Everything the restore needs to know. */
export interface RevertContext {
  /** 16-hex token. */
  token: string;
  /** Config backend. */
  backend: "netplan" | "networkd";
  /** Bridge implementation. */
  bridgeType: "linux" | "ovs";
  /** Every virtual device this change created. */
  created: string[];
  /** Subset of `created` that are OVS bridges. */
  createdBridges: string[];
  /** Managed config file paths. */
  managedFiles: string[];
}

/** The host directory that holds one revert. */
export function revertDir(token: string): string {
  if (!TOKEN_RE.test(token)) throw new Error("invalid revert token");
  return `/var/lib/host-net/revert/${token}`;
}

/** The marker document, kept as JSON for `get`/`sync` to read. */
export interface RevertMarker {
  /** Token. */
  token: string;
  /** Arm time, epoch seconds. */
  armed_at: number;
  /** Expiry time, epoch seconds. */
  expires_at: number;
  /** SHA-256 of the armed config. */
  armed_sha256: string;
  /** Devices this change created. */
  created: string[];
  /** `pending`, `pass` or `fail`. */
  result: "pending" | "pass" | "fail";
  /** Fire time, epoch seconds, or null. */
  fired_at: number | null;
}

/** Renders the marker JSON. */
export function renderMarker(marker: RevertMarker): string {
  if (!TOKEN_RE.test(marker.token)) throw new Error("invalid revert token");
  return JSON.stringify(marker, null, 2) + "\n";
}

function shellQuote(value: string): string {
  return `'${value.replace(/'/g, `'\\''`)}'`;
}

/**
 * Renders the restore script. The script is a no-op unless its token is still
 * the current marker, lowers MTUs child-first, deletes only created devices,
 * restores the managed files from the snapshot and records its result.
 */
export function renderRestoreScript(ctx: RevertContext): string {
  if (!TOKEN_RE.test(ctx.token)) throw new Error("invalid revert token");
  for (const name of ctx.created) assertIface(name, "created device");
  for (const name of ctx.createdBridges) assertIface(name, "created bridge");
  const dir = revertDir(ctx.token);
  const createdArray = ctx.created.map(shellQuote).join(" ");
  const ovsArray = ctx.createdBridges.map(shellQuote).join(" ");
  const lowerOrder = [...ctx.created].reverse();
  const lines: string[] = [
    "#!/bin/sh",
    "# host-net restore; token-guarded, removes only what this change created.",
    "set -eu",
    `TOKEN=${shellQuote(ctx.token)}`,
    "DIR=" + shellQuote(dir),
    `LOCK=/run/host-net.lock`,
    'exec 9>"$LOCK"',
    "flock -n 9 || { echo 'host-net: lock busy' >&2; exit 75; }",
    `CURRENT="$(cat /var/lib/host-net/current 2>/dev/null || true)"`,
    `[ "$CURRENT" = "$TOKEN" ] || { echo 'host-net: superseded' >&2; exit 0; }`,
    `MARKER="$DIR/marker.json"`,
    `SNAP="$DIR/snapshot"`,
    "",
    "# 1. lower MTUs on created devices (child-first) before their parents run.",
  ];
  // Emit explicit lower steps in reverse creation order.
  for (const name of lowerOrder) {
    lines.push(
      `ip link set dev ${shellQuote(name)} mtu 1500 2>/dev/null || true`,
    );
  }
  lines.push(
    "",
    "# 2. delete only the devices this change created.",
    `for dev in ${createdArray}; do`,
    '  ip link delete dev "$dev" 2>/dev/null || true',
    "done",
  );
  if (ctx.bridgeType === "ovs" && ctx.createdBridges.length > 0) {
    lines.push(
      `for br in ${ovsArray}; do`,
      '  ovs-vsctl --if-exists del-br "$br" >/dev/null 2>&1 || true',
      "done",
    );
  }
  lines.push(
    "",
    "# 3. restore the managed config from the snapshot.",
  );
  if (ctx.backend === "netplan") {
    lines.push(
      `rm -rf /etc/netplan.host-net-new`,
      `cp -a "$SNAP/netplan" /etc/netplan.host-net-new`,
      `rm -rf /etc/netplan`,
      `mv /etc/netplan.host-net-new /etc/netplan`,
    );
  } else {
    lines.push(
      `for f in /etc/systemd/network/90-host-net-*; do [ -e "$f" ] && rm -f "$f"; done`,
      `cp -a "$SNAP/networkd/." /etc/systemd/network/ 2>/dev/null || true`,
    );
  }
  if (
    ctx.managedFiles.includes(
      "/etc/cloud/cloud.cfg.d/99-disable-network-config.cfg",
    )
  ) {
    lines.push(
      `if [ -e "$SNAP/cloud-init.cfg" ]; then cp -a "$SNAP/cloud-init.cfg" /etc/cloud/cloud.cfg.d/99-disable-network-config.cfg; else rm -f /etc/cloud/cloud.cfg.d/99-disable-network-config.cfg; fi`,
    );
  }
  const applyCmd = ctx.backend === "netplan"
    ? "netplan apply"
    : "networkctl reload && networkctl reconfigure";
  lines.push(
    "",
    "# 4. apply the restored configuration.",
    `${applyCmd}`,
    "",
    "# 5. record the outcome in the marker; never reboot.",
    `RESULT=fail`,
    `if ip -j route show default >/dev/null 2>&1; then RESULT=pass; fi`,
    `now="$(date +%s)"`,
    `sed -i "s/\\"result\\": *\\"[a-z]*\\"/\\"result\\": \\"$RESULT\\"/; s/\\"fired_at\\": *[0-9]*/\\"fired_at\\": $now/" "$MARKER"`,
    `rm -f /var/lib/host-net/current`,
    `exit 0`,
    "",
  );
  return lines.join("\n");
}
