/**
 * Phase planning and execution: turns validated inputs into an ordered stream
 * of remote steps, then runs that stream through the SSH transport.
 *
 * Every step is an `exec` of a fixed argv. Caller values travel as separate
 * argv words, on stdin, or inside a fixed script that reads them as positional
 * parameters, so nothing is interpolated into a shell string. File writes go
 * through a sudo-wrapped `sh -c` that reads the content on stdin, creates the
 * parent directory, writes a same-directory temp file and `mv`s it into place
 * atomically, so they work for a non-root login and are idempotent by content.
 *
 * The firewall and lockdown plans write the revert script (kind `stage`) and
 * then activate the timer (kind `arm`) before they apply (kind `apply`).
 * {@link assertArmedBeforeApply} proves that the timer activation, not merely
 * the upload, precedes the change.
 *
 * @module
 */

import { exec, type ExecResult, type SshDeps, type Target } from "./ssh.ts";
import {
  isTimerActive,
  parseMarker,
  renderArmArgv,
  renderCommitArgv,
  renderDisarmArgv,
  renderGuardedApplyArgv,
  renderMarkerArgv,
  renderProbeArgv,
  renderRevertScript,
  scriptPath,
  STATE_DIR,
  withSudo,
} from "./armed_revert.ts";
import { listingSha256, managedSha256, normalizeListing } from "./nftables.ts";
import { HostConfigError } from "./validate.ts";

/** The risk class of a step, used to assert ordering. */
export type StepKind =
  | "stage"
  | "arm"
  | "precheck"
  | "apply"
  | "verify"
  | "cleanup"
  | "base";

/** One remote action in a plan. */
export interface Step {
  /** Risk class of the step. */
  kind: StepKind;
  /** Human-readable label. */
  label: string;
  /** The remote argv; each element reaches the host as one word. */
  argv: string[];
  /** Content delivered on stdin, if any. */
  stdin?: Uint8Array;
  /** When true, a remote exit outside `okExit` stops the plan. */
  check?: boolean;
  /** Exit codes that count as success for a checked step; default `[0]`. */
  okExit?: number[];
  /** Per-step transport timeout in seconds; defaults to {@link STEP_TIMEOUT_S}. */
  timeoutS?: number;
}

/** A step after execution, with its result summarised for logging and tests. */
export interface EmittedStep {
  /** Risk class of the step. */
  kind: StepKind;
  /** Human-readable label. */
  label: string;
  /** The remote argv. */
  argv: string[];
  /** The remote exit code. */
  exit_code: number;
}

const enc = new TextEncoder();

/** Default per-step timeout. */
export const STEP_TIMEOUT_S = 600;
/** Timeout of the guarded apply, kept well under the shortest revert (60 s). */
export const APPLY_TIMEOUT_S = 30;

/**
 * True when the timer-activation step (`arm`) precedes the first mutating
 * `apply` step in `steps`. A `stage` step (writing the revert script) does not
 * count: the invariant is that the timer is armed, not merely prepared.
 */
export function isArmedBeforeApply(steps: Step[]): boolean {
  const arm = steps.findIndex((s) => s.kind === "arm");
  const apply = steps.findIndex((s) => s.kind === "apply");
  return arm >= 0 && apply >= 0 && arm < apply;
}

/** Throws unless the plan arms a revert before it applies a change. */
export function assertArmedBeforeApply(steps: Step[]): void {
  if (!isArmedBeforeApply(steps)) {
    throw new Error("Plan violates the armed-revert invariant");
  }
}

const PKG_SCRIPT = `set -e
for p in "$@"; do
  if dpkg-query -W -f='\${Status}' "$p" 2>/dev/null | grep -q "install ok installed"; then
    continue
  fi
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq
  apt-get install -y --no-install-recommends "$p"
  printf 'changed %s\\n' "$p"
done
`;

const USER_SCRIPT = `set -e
if ! id -u "$1" >/dev/null 2>&1; then
  useradd -m -s /bin/bash "$1"
  printf 'created %s\\n' "$1"
fi
if ! id -nG "$1" | tr ' ' '\\n' | grep -qx sudo; then
  if usermod -aG sudo "$1" 2>/dev/null; then
    install -d -m 0755 "${STATE_DIR}"
    : > "${STATE_DIR}/sudo-granted-$1"
  fi
fi
`;

/**
 * Takes back what an earlier run granted a previous managed account: the
 * managed authorized_keys file, and the sudo membership only if this tool added
 * it (a marker on the host records that). The account itself stays.
 *
 * Exit 0: revoked. Exit 3: the keys file was left alone because `~/.ssh` is a
 * symlink or not the account's own directory (removing through it could delete
 * another account's keys); the sudo part is still done. Any other non-zero
 * exit: the sudo membership could not be removed, and the marker is kept so a
 * rerun retries.
 */
export const REVOKE_SKIPPED = 3;
const REVOKE_SCRIPT = `set -e
user=$1
rc=0
home=$(getent passwd "$user" | cut -d: -f6 || true)
if [ -n "$home" ]; then
  d="$home/.ssh"
  if [ -L "$d" ] || [ ! -d "$d" ] || [ "$(stat -c %U "$d")" != "$user" ]; then
    if [ -e "$d" ] || [ -L "$d" ]; then
      echo "left $d alone: not the account's own directory" >&2
      rc=${REVOKE_SKIPPED}
    fi
  else
    rm -f "$d/authorized_keys"
  fi
fi
m="${STATE_DIR}/sudo-granted-$user"
if [ -e "$m" ]; then
  gpasswd -d "$user" sudo >/dev/null 2>&1 || true
  if id -nG "$user" 2>/dev/null | tr ' ' '\\n' | grep -qx sudo; then
    echo "could not remove $user from sudo" >&2
    exit 1
  fi
  rm -f "$m"
fi
exit $rc
`;

const KEYS_SCRIPT = `set -e
user=$1
home=$(getent passwd "$user" | cut -d: -f6)
[ -n "$home" ] || { printf 'no home directory for %s\\n' "$user" >&2; exit 1; }
install -d -m 700 "$home/.ssh"
chown "$user" "$home/.ssh" 2>/dev/null || true
tmp=$(mktemp "$home/.ssh/authorized_keys.XXXXXX")
cat > "$tmp"
chmod 600 "$tmp"
chown "$user" "$tmp" 2>/dev/null || true
if [ -f "$home/.ssh/authorized_keys" ] && cmp -s "$tmp" "$home/.ssh/authorized_keys"; then
  rm -f "$tmp"
else
  mv -f "$tmp" "$home/.ssh/authorized_keys"
  printf 'updated authorized_keys\\n'
fi
`;

/** Inputs to the base phase. All strings are already grammar-validated. */
export interface BaseInput {
  /** Wrap privileged commands in `sudo -n`. */
  sudo: boolean;
  /** Packages to ensure installed. */
  packages: string[];
  /** Administrative account to ensure exists. */
  adminUser: string;
  /** Public keys to authorize for the account, verbatim lines. */
  authorizedKeys: string[];
  /** Sysctl keys and values to write. */
  sysctl: Record<string, string>;
  /** Time zone to set. */
  timezone: string;
  /** Previous managed accounts whose grants are revoked first. */
  revoke?: string[];
}

/** Renders the managed sysctl drop-in with sorted keys. */
export function renderSysctlConf(sysctl: Record<string, string>): string {
  const keys = Object.keys(sysctl).sort();
  return `# Managed by @randybias/server-host. Generated; do not edit.\n${
    keys.map((k) => `${k} = ${sysctl[k]}`).join("\n")
  }\n`;
}

/** Renders the fixed journald hardening drop-in. */
export function renderJournaldConf(): string {
  return `# Managed by @randybias/server-host. Generated; do not edit.\n[Journal]\nStorage=persistent\nCompress=yes\nSystemMaxUse=200M\nForwardToSyslog=no\n`;
}

/**
 * A sudo-wrapped step that writes `content` to an absolute path on stdin. The
 * parent directory is created, the temp file lives in the destination
 * directory, and `mv` replaces the destination atomically. `path` and `mode`
 * are constants chosen by this module, never a caller value.
 */
export function writeFileStep(
  kind: StepKind,
  label: string,
  path: string,
  content: Uint8Array,
  mode: string,
  sudo: boolean,
): Step {
  const script = `set -e
dir=$(dirname "${path}")
install -d -m 0755 "$dir"
tmp=$(mktemp "${path}.XXXXXX")
cat > "$tmp"
chmod ${mode} "$tmp"
if [ -f "${path}" ] && cmp -s "$tmp" "${path}"; then
  chmod ${mode} "${path}"
  rm -f "$tmp"
  exit 0
fi
mv -f "$tmp" "${path}"
`;
  return {
    kind,
    label,
    argv: withSudo(sudo, ["sh", "-c", script]),
    stdin: content,
    check: true,
  };
}

/**
 * Builds the base-phase step stream for exactly the components named in
 * `changed`. An unchanged re-run passes an empty list and emits no steps, so
 * nothing is installed, restarted or reset.
 */
export function planApplyBase(
  input: BaseInput,
  changed: readonly string[],
): Step[] {
  const steps: Step[] = [];
  const want = (name: string) => changed.includes(name);
  if (want("revoke_previous")) {
    for (const user of input.revoke ?? []) {
      steps.push({
        kind: "base",
        label: `revoke grants of ${user}`,
        argv: withSudo(input.sudo, ["sh", "-c", REVOKE_SCRIPT, "sh", user]),
        // 0 = revoked, 3 = keys left alone (the caller reads it); anything else
        // stops the plan before the new account is granted anything.
        check: true,
        okExit: [0, REVOKE_SKIPPED],
      });
    }
  }
  if (want("packages") && input.packages.length > 0) {
    steps.push({
      kind: "base",
      label: "install packages",
      argv: withSudo(input.sudo, [
        "sh",
        "-c",
        PKG_SCRIPT,
        "sh",
        ...input.packages,
      ]),
      check: true,
    });
  }
  if (want("admin_user")) {
    steps.push({
      kind: "base",
      label: "create admin user",
      argv: withSudo(input.sudo, [
        "sh",
        "-c",
        USER_SCRIPT,
        "sh",
        input.adminUser,
      ]),
      check: true,
    });
  }
  if (want("authorized_keys")) {
    steps.push({
      kind: "base",
      label: "authorize admin keys",
      argv: withSudo(input.sudo, [
        "sh",
        "-c",
        KEYS_SCRIPT,
        "sh",
        input.adminUser,
      ]),
      stdin: enc.encode(
        input.authorizedKeys.length > 0
          ? `${input.authorizedKeys.join("\n")}\n`
          : "",
      ),
      check: true,
    });
  }
  if (want("sysctl")) {
    steps.push(
      writeFileStep(
        "base",
        "write sysctl drop-in",
        "/etc/sysctl.d/99-server-host.conf",
        enc.encode(renderSysctlConf(input.sysctl)),
        "0644",
        input.sudo,
      ),
    );
    steps.push({
      kind: "base",
      label: "apply sysctl",
      argv: withSudo(input.sudo, ["sysctl", "--system"]),
      check: true,
    });
  }
  if (want("journald")) {
    steps.push(
      writeFileStep(
        "base",
        "write journald drop-in",
        "/etc/systemd/journald.conf.d/99-server-host.conf",
        enc.encode(renderJournaldConf()),
        "0644",
        input.sudo,
      ),
    );
    steps.push({
      kind: "base",
      label: "restart journald",
      argv: withSudo(input.sudo, ["systemctl", "restart", "systemd-journald"]),
      check: true,
    });
  }
  if (want("timezone")) {
    steps.push({
      kind: "base",
      label: "set time zone",
      argv: withSudo(input.sudo, [
        "timedatectl",
        "set-timezone",
        input.timezone,
      ]),
      check: true,
    });
  }
  if (want("time_sync")) {
    steps.push({
      kind: "base",
      label: "enable time sync",
      argv: withSudo(input.sudo, ["timedatectl", "set-ntp", "true"]),
      check: true,
    });
  }
  return steps;
}

/** Options shared by the two reverting firewall plans. */
export interface FirewallChangeInput {
  /** Random token embedded in the revert unit and file names. */
  token: string;
  /** Seconds until the host reverts itself. */
  revertAfterS: number;
  /** Wrap privileged commands in `sudo -n`. */
  sudo: boolean;
  /** Rendered nftables script to apply. */
  rulesText: string;
  /** SHA-256 of the managed table the apply installs; recorded on the host. */
  managedSha256: string;
}

/**
 * Builds the ordered firewall-change stream: `nft -c` syntax check (no side
 * effects, so it runs before anything is armed), write the revert script
 * (stage), arm (which snapshots and starts the timer under the host lock),
 * apply under the same lock only while the revert still guards the change,
 * then read the table back.
 */
export function planFirewallChange(input: FirewallChangeInput): Step[] {
  const rules = enc.encode(input.rulesText);
  const steps: Step[] = [
    {
      kind: "precheck",
      label: "nft syntax check",
      argv: withSudo(input.sudo, ["nft", "-c", "-f", "-"]),
      stdin: rules,
      check: true,
    },
    writeFileStep(
      "stage",
      "write revert script",
      scriptPath(input.token),
      enc.encode(renderRevertScript(input.token)),
      "0700",
      input.sudo,
    ),
    {
      kind: "arm",
      label: "arm revert timer",
      argv: renderArmArgv(
        input.token,
        input.revertAfterS,
        input.sudo,
        input.managedSha256,
      ),
      check: true,
    },
    {
      kind: "apply",
      label: "apply ruleset",
      argv: renderGuardedApplyArgv(input.token, input.sudo),
      stdin: rules,
      check: true,
      timeoutS: APPLY_TIMEOUT_S,
    },
    {
      kind: "verify",
      label: "read table back",
      argv: withSudo(input.sudo, [
        "nft",
        "-j",
        "list",
        "table",
        "inet",
        "server_host",
      ]),
      check: true,
    },
  ];
  assertArmedBeforeApply(steps);
  return steps;
}

/** Builds the ordered stream that cancels an armed revert. */
export function planCommit(token: string, sudo: boolean): Step[] {
  return [{
    kind: "cleanup",
    label: "cancel revert timer",
    argv: renderCommitArgv(token, sudo),
    check: true,
  }];
}

/**
 * The step that abandons a revert after a change that definitely did not
 * happen. Tolerant and idempotent; see {@link renderDisarmArgv}.
 */
export function planDisarm(token: string, sudo: boolean): Step[] {
  return [{
    kind: "cleanup",
    label: "disarm revert timer",
    argv: renderDisarmArgv(token, sudo),
    check: true,
  }];
}

/** Inputs to the READ-ONLY probe. */
export interface ReadInput {
  /** Wrap privileged commands in `sudo -n`. */
  sudo: boolean;
  /** The revert token to check, when the caller recorded one. */
  token?: string;
}

/** The READ-ONLY result of probing a host's current firewall state. */
export interface ProbeResult {
  /** SHA-256 of the full `nft -j list ruleset` output without handles. */
  ruleset_sha256: string;
  /** SHA-256 of the canonical managed table. */
  managed_sha256: string;
  /** True when the managed table is present. */
  managed_table: boolean;
  /** True when the revert timer (the recorded one, else the host's) is active. */
  armed: boolean;
  /** Token of the revert the host itself records as current, if any. */
  current_token?: string;
  /** ISO-8601 expiry of that revert, if any. */
  current_expires_at?: string;
  /** Managed-table hash the host recorded for that revert, if any. */
  current_managed_sha256?: string;
  /** ISO-8601 time of the probe. */
  observed_at: string;
}

/**
 * Runs READ-ONLY probes and returns the host's current firewall state. A probe
 * that fails or is truncated throws {@link HostOpsError}; a caller must not
 * persist an observation it did not obtain.
 */
export async function probeState(
  deps: SshDeps,
  target: Target,
  input: ReadInput,
): Promise<ProbeResult> {
  const listed = await exec(
    deps,
    target,
    withSudo(input.sudo, ["nft", "-j", "list", "ruleset"]),
    { timeoutS: 60 },
  );
  if (listed.exit_code !== 0) {
    throw new HostOpsError(
      `nft -j list ruleset on ${target.host} failed with exit code ${listed.exit_code}; refusing to record firewall state`,
    );
  }
  if (listed.truncated) {
    throw new HostOpsError(
      `nft -j list ruleset on ${target.host} output was truncated; refusing to record firewall state`,
    );
  }
  let table;
  try {
    table = normalizeListing(listed.stdout);
  } catch {
    throw new HostOpsError(
      `nft -j list ruleset on ${target.host} did not return JSON; refusing to record firewall state`,
    );
  }
  const managed = table !== null;
  const marked = await exec(
    deps,
    target,
    renderMarkerArgv(input.sudo),
    { timeoutS: 30 },
  );
  if (marked.exit_code !== 0) {
    throw new HostOpsError(
      `Reading the revert marker on ${target.host} failed with exit code ${marked.exit_code}; refusing to record firewall state`,
    );
  }
  if (marked.truncated) {
    throw new HostOpsError(
      `The revert marker on ${target.host} was truncated; refusing to record firewall state`,
    );
  }
  const marker = parseMarker(marked.stdout);
  if (marker === null && marked.stdout.trim() !== "") {
    throw new HostOpsError(
      `The revert marker on ${target.host} is not readable; refusing to record firewall state`,
    );
  }
  const token = input.token ?? marker?.token;
  let armed = false;
  if (token) {
    const probe = await exec(
      deps,
      target,
      renderProbeArgv(token, input.sudo),
      { timeoutS: 30 },
    );
    if (probe.exit_code === 0) {
      armed = isTimerActive(probe.stdout);
    } else if (probe.exit_code === 3 || probe.exit_code === 4) {
      armed = false;
    } else {
      throw new HostOpsError(
        `Revert timer probe on ${target.host} failed with exit code ${probe.exit_code}; refusing to record firewall state`,
      );
    }
  }
  return {
    ruleset_sha256: await listingSha256(listed.stdout),
    managed_sha256: await managedSha256(table),
    managed_table: managed,
    armed,
    ...(marker
      ? {
        current_token: marker.token,
        current_expires_at: new Date(marker.expires_at_s * 1000).toISOString(),
        ...(marker.managed_sha256
          ? { current_managed_sha256: marker.managed_sha256 }
          : {}),
      }
      : {}),
    observed_at: new Date(deps.now()).toISOString(),
  };
}

/**
 * Runs `steps` through the transport in order and returns what was emitted. A
 * step marked `check` throws {@link HostOpsError} on a non-zero remote exit,
 * so a failed `nft -c` pre-check stops the plan before anything is armed.
 * `after` runs once each step has succeeded, before the next one starts; the
 * model uses it to persist the armed revert before the change is applied.
 */
export async function executePlan(
  deps: SshDeps,
  target: Target,
  steps: Step[],
  after?: (step: Step, result: ExecResult) => Promise<void>,
): Promise<EmittedStep[]> {
  const emitted: EmittedStep[] = [];
  for (const step of steps) {
    const res = await exec(deps, target, step.argv, {
      stdin: step.stdin,
      timeoutS: step.timeoutS ?? STEP_TIMEOUT_S,
    });
    if (step.check && !(step.okExit ?? [0]).includes(res.exit_code)) {
      throw new HostOpsError(
        `Remote step "${step.label}" failed with exit code ${res.exit_code}`,
        step.kind,
        res.exit_code,
      );
    }
    emitted.push({
      kind: step.kind,
      label: step.label,
      argv: step.argv,
      exit_code: res.exit_code,
    });
    if (after) await after(step, res);
  }
  return emitted;
}

/** A remote step failed or a plan violated an invariant. */
export class HostOpsError extends Error {
  /** The kind of step that failed, when the failure was a remote exit. */
  readonly stepKind?: StepKind;
  /** The remote exit code, when the failure was a remote exit. */
  readonly exitCode?: number;
  /** Creates a host-operations error. */
  constructor(message: string, stepKind?: StepKind, exitCode?: number) {
    super(message);
    this.name = "HostOpsError";
    this.stepKind = stepKind;
    this.exitCode = exitCode;
  }
}

/** Re-exported so callers depend on one error family for host operations. */
export { HostConfigError, STATE_DIR };
