/**
 * The install script: Knot DNS and its tools from the distribution archive,
 * and optionally Knot Resolver 6 from the CZ.NIC Labs package repository.
 *
 * Knot Resolver 6 is not in the Ubuntu 24.04 archive (it has 5.7, which has no
 * `kresctl`), so the vendor repository is added with a pinned signing-key
 * fingerprint. That repository also carries a newer Knot DNS; it is pinned at
 * apt priority 100 so Knot DNS stays at the archive version and only
 * knot-resolver6 and its own (differently versioned) libraries come from it.
 *
 * @module
 */

import { shq } from "./fragments.ts";

/** Fixed on-host paths. */
const KNOT_CONF = "/etc/knot/knot.conf";
const KNOT_CONF_DIR = "/etc/knot/knot.conf.d";
const ZONE_DIR = "/var/lib/knot/zones";
const INCLUDE_LINE = `include: ${KNOT_CONF_DIR}/*.conf`;

/** Where the vendor publishes its signing key and packages. */
const VENDOR_KEY_URL = "https://pkg.labs.nic.cz/gpg";
const VENDOR_REPO_URL = "https://pkg.labs.nic.cz/knot-resolver";
const VENDOR_KEYRING = "/usr/share/keyrings/cznic-labs-pkg.gpg";
const VENDOR_LIST = "/etc/apt/sources.list.d/cznic-labs-knot-resolver.list";
const VENDOR_PREFS = "/etc/apt/preferences.d/cznic-labs-knot-resolver";

/**
 * The primary-key fingerprint of the "CZ.NIC Labs Packaging" key, read from
 * https://pkg.labs.nic.cz/gpg on 2026-10-17, in gpg's grouped display form, and
 * confirmed against keys.openpgp.org and https://pkg.labs.nic.cz/doc. A key
 * whose fingerprint differs is refused before it is trusted.
 */
const VENDOR_KEY_FINGERPRINT_GROUPED =
  "9C71 D59C D4CE 8BD2 966A 7A3E AB6A 3031 2401 9B64";

/** The same fingerprint without spaces, as `gpg --with-colons` prints it. */
export const VENDOR_KEY_FINGERPRINT = VENDOR_KEY_FINGERPRINT_GROUPED.split(" ")
  .join("");

/** Major versions the model is written against. */
const EXPECTED_KNOT_MAJOR = 3;
const EXPECTED_RESOLVER_MAJOR = 6;

/** Installs the distribution packages that ship every tool the model runs. */
const DISTRO_INSTALL = [
  "for t in knotc knotd kdig kzonecheck keymgr; do",
  '  command -v "$t" >/dev/null 2>&1 || need_distro=1',
  "done",
  'if [ "${need_distro:-0}" = 1 ]; then',
  "  apt-get update -qq",
  "  apt-get install -y -qq knot knot-dnsutils knot-dnssecutils",
  "fi",
];

/** Adds the vendor repository after verifying its key, then installs. */
const RESOLVER_INSTALL = [
  "if ! command -v kresctl >/dev/null 2>&1; then",
  "  apt-get install -y -qq ca-certificates curl gnupg",
  "  . /etc/os-release",
  '  case "${VERSION_CODENAME:-}" in ""|*[!a-z]*) echo UNSUPPORTED_OS >&2; exit 14 ;; esac',
  "  key=$(mktemp)",
  `  curl -fsS --max-time 60 -o "$key" ${
    shq(VENDOR_KEY_URL)
  } || { echo KEY_FETCH_FAILED >&2; exit 12; }`,
  // The first fpr line of --with-colons output is the primary key's.
  `  fpr=$(gpg --show-keys --with-colons "$key" | awk -F: '/^fpr:/ {print $10; exit}')`,
  `  [ "$fpr" = ${
    shq(VENDOR_KEY_FINGERPRINT)
  } ] || { echo KEY_MISMATCH >&2; rm -f "$key"; exit 12; }`,
  `  install -m 0644 "$key" ${shq(VENDOR_KEYRING)}; rm -f "$key"`,
  `  printf '%s\\n' "deb [signed-by=${VENDOR_KEYRING}] ${VENDOR_REPO_URL} $VERSION_CODENAME main" > ${
    shq(VENDOR_LIST)
  }`,
  // Priority 100: never preferred over the archive for a package both have.
  `  printf 'Package: *\\nPin: origin pkg.labs.nic.cz\\nPin-Priority: 100\\n' > ${
    shq(VENDOR_PREFS)
  }`,
  "  apt-get update -qq",
  "  apt-get install -y -qq knot-resolver6",
  "fi",
  "mkdir -p /etc/knot-resolver",
  // The package's own config listens on 127.0.0.1:53, which knotd may hold.
  // Leave the service stopped; apply_resolver enables and starts it with the
  // configuration it renders.
  "systemctl disable --now knot-resolver >/dev/null 2>&1 || true",
  // The package's own start may have failed on that address; clear the
  // failed state so the stopped service reads inactive.
  "systemctl reset-failed knot-resolver >/dev/null 2>&1 || true",
];

/** Fails unless the tools exist and are the major versions expected. */
function verifyLines(resolver: boolean): string[] {
  const lines = [
    "major() { printf '%s\\n' \"$1\" | grep -oE '[0-9]+\\.[0-9]+(\\.[0-9]+)?' | head -1 | cut -d. -f1; }",
    "for t in knotc kdig kzonecheck keymgr; do",
    '  command -v "$t" >/dev/null 2>&1 || { echo "TOOL_MISSING $t" >&2; exit 127; }',
    "done",
    "kv=$(knotc --version 2>&1 | head -1)",
    `[ "$(major "$kv")" = ${EXPECTED_KNOT_MAJOR} ] || { echo "UNEXPECTED_VERSION knot $kv" >&2; exit 13; }`,
  ];
  if (resolver) {
    lines.push(
      'for t in kresctl kresd; do command -v "$t" >/dev/null 2>&1 || { echo "TOOL_MISSING $t" >&2; exit 127; }; done',
      "rv=$(kresd --version 2>&1 | head -1)",
      `[ "$(major "$rv")" = ${EXPECTED_RESOLVER_MAJOR} ] || { echo "UNEXPECTED_VERSION knot-resolver $rv" >&2; exit 13; }`,
    );
  }
  return lines;
}

/** Script that installs Knot (and optionally Knot Resolver 6) and the include. */
export function installScript(opts: { resolver: boolean }): string {
  return [
    "set -eu",
    "export DEBIAN_FRONTEND=noninteractive",
    ...DISTRO_INSTALL,
    ...(opts.resolver ? RESOLVER_INSTALL : []),
    `mkdir -p ${shq(KNOT_CONF_DIR)} ${shq(ZONE_DIR)}`,
    "command -v chown >/dev/null 2>&1 && chown knot:knot /var/lib/knot/zones 2>/dev/null || true",
    `touch ${shq(KNOT_CONF)}`,
    `if ! grep -qF ${shq(INCLUDE_LINE)} ${
      shq(KNOT_CONF)
    }; then printf '%s\\n' ${shq(INCLUDE_LINE)} >> ${shq(KNOT_CONF)}; fi`,
    "systemctl enable --now knot 2>/dev/null || true",
    ...verifyLines(opts.resolver),
    'echo "knot_version=$kv"',
    ...(opts.resolver ? ['echo "kresd_version=$rv"'] : []),
  ].join("\n");
}
