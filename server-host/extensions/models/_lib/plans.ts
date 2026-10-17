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

import { exec, type SshDeps, type Target } from "./ssh.ts";
import {
  renderArmArgv,
  renderCommitArgv,
  renderProbeArgv,
  renderRevertScript,
  renderSnapshotArgv,
  scriptPath,
  STATE_DIR,
  withSudo,
} from "./armed_revert.ts";
import { managedTableSha256, rulesetSha256 } from "./nftables.ts";
import { HostConfigError } from "./validate.ts";

/** The risk class of a step, used to assert ordering. */
export type StepKind =
  | "snapshot"
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
  /** When true, a non-zero remote exit stops the plan. */
  check?: boolean;
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
usermod -aG sudo "$1" 2>/dev/null || true
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
}

/**
 * Builds the ordered firewall-change stream: snapshot, write the revert script
 * (stage), activate the timer (arm), pre-check with `nft -c`, apply with
 * `nft -f`, then read the table back. The timer activation always precedes the
 * apply step.
 */
export function planFirewallChange(input: FirewallChangeInput): Step[] {
  const rules = enc.encode(input.rulesText);
  const steps: Step[] = [
    {
      kind: "snapshot",
      label: "snapshot ruleset",
      argv: renderSnapshotArgv(input.token, input.sudo),
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
      argv: renderArmArgv(input.token, input.revertAfterS, input.sudo),
      check: true,
    },
    {
      kind: "precheck",
      label: "nft syntax check",
      argv: withSudo(input.sudo, ["nft", "-c", "-f", "-"]),
      stdin: rules,
      check: true,
    },
    {
      kind: "apply",
      label: "apply ruleset",
      argv: withSudo(input.sudo, ["nft", "-f", "-"]),
      stdin: rules,
      check: true,
    },
    {
      kind: "verify",
      label: "read table back",
      argv: withSudo(input.sudo, [
        "nft",
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

/** Inputs to the READ-ONLY probe. */
export interface ReadInput {
  /** Wrap privileged commands in `sudo -n`. */
  sudo: boolean;
  /** The revert token to check, when the caller recorded one. */
  token?: string;
}

/** The READ-ONLY result of probing a host's current firewall state. */
export interface ProbeResult {
  /** SHA-256 of the full `nft list ruleset` output. */
  ruleset_sha256: string;
  /** SHA-256 of the canonical managed table. */
  managed_sha256: string;
  /** True when the managed table is present. */
  managed_table: boolean;
  /** True when a recorded revert timer is still active. */
  armed: boolean;
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
    withSudo(input.sudo, ["nft", "list", "ruleset"]),
    { timeoutS: 60 },
  );
  if (listed.exit_code !== 0) {
    throw new HostOpsError(
      `nft list ruleset on ${target.host} failed with exit code ${listed.exit_code}; refusing to record firewall state`,
    );
  }
  if (listed.truncated) {
    throw new HostOpsError(
      `nft list ruleset on ${target.host} output was truncated; refusing to record firewall state`,
    );
  }
  const managed = listed.stdout.includes("table inet server_host");
  let armed = false;
  if (input.token) {
    const probe = await exec(
      deps,
      target,
      renderProbeArgv(input.token, input.sudo),
      { timeoutS: 30 },
    );
    if (probe.exit_code === 0) {
      armed = probe.stdout.trim() === "active";
    } else if (probe.exit_code === 3 || probe.exit_code === 4) {
      armed = false;
    } else {
      throw new HostOpsError(
        `Revert timer probe on ${target.host} failed with exit code ${probe.exit_code}; refusing to record firewall state`,
      );
    }
  }
  return {
    ruleset_sha256: await rulesetSha256(listed.stdout),
    managed_sha256: await managedTableSha256(listed.stdout),
    managed_table: managed,
    armed,
    observed_at: new Date(deps.now()).toISOString(),
  };
}

/**
 * Runs `steps` through the transport in order and returns what was emitted. A
 * step marked `check` throws {@link HostOpsError} on a non-zero remote exit,
 * so a failed `nft -c` pre-check stops the plan before the apply step.
 */
export async function executePlan(
  deps: SshDeps,
  target: Target,
  steps: Step[],
): Promise<EmittedStep[]> {
  const emitted: EmittedStep[] = [];
  for (const step of steps) {
    const res = await exec(deps, target, step.argv, {
      stdin: step.stdin,
      timeoutS: 600,
    });
    if (step.check && res.exit_code !== 0) {
      throw new HostOpsError(
        `Remote step "${step.label}" failed with exit code ${res.exit_code}`,
      );
    }
    emitted.push({
      kind: step.kind,
      label: step.label,
      argv: step.argv,
      exit_code: res.exit_code,
    });
  }
  return emitted;
}

/** A remote step failed or a plan violated an invariant. */
export class HostOpsError extends Error {
  /** Creates a host-operations error. */
  constructor(message: string) {
    super(message);
    this.name = "HostOpsError";
  }
}

/** Re-exported so callers depend on one error family for host operations. */
export { HostConfigError, STATE_DIR };
