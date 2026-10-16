#!/usr/bin/env bash
# Tests for gates.sh verdict functions and argument handling.
set -u
here="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=lib/verdicts.sh
source "$here/lib/verdicts.sh"
td="$here/testdata"
fail=0
expect() { # expect <want-rc> <desc> <cmd...>
  local want=$1 desc=$2
  shift 2
  "$@" >/dev/null 2>&1
  local rc=$?
  if [[ $rc == "$want" ]]; then echo "ok   $desc"; else
    echo "FAIL $desc (want $want got $rc)"
    fail=1
  fi
}
expect 0 "quality ok (private)" verdict_quality "$td/quality-ok.json" private
expect 0 "quality: public, repository provisional" verdict_quality "$td/quality-ok.json" public
jq '.factors |= map(if .id == "repository-verified" then .status = "missing" else . end)' \
  "$td/quality-ok.json" >"$td/../../.q-norepo.json"
expect 1 "quality: public, repository missing" verdict_quality "$td/../../.q-norepo.json" public
expect 0 "quality: private, repository missing is exempt" verdict_quality "$td/../../.q-norepo.json" private
rm -f "$td/../../.q-norepo.json"
expect 1 "quality missing factor" verdict_quality "$td/quality-missing.json"
expect 2 "quality with no output" verdict_quality "$td/empty.json"
expect 2 "quality auth error object" verdict_quality "$td/swamp-noauth.err.json"
expect 0 "dry ok stable" verdict_dry "$td/dry-ok.json" stable
expect 2 "dry no credentials (not-run check)" verdict_dry "$td/dry-noauth.json" beta
expect 2 "dry auth error object" verdict_dry "$td/swamp-noauth.err.json" beta
expect 2 "dry no output" verdict_dry "$td/empty.json" beta
expect 1 "dry version already exists" verdict_dry "$td/dry-version-exists.json" beta
expect 1 "dry review report missing" verdict_dry "$td/dry-review-missing.json" beta
expect 0 "dimension issue on beta" verdict_dry "$td/dry-review-issue.json" beta
expect 1 "dimension issue on stable" verdict_dry "$td/dry-review-issue.json" stable
expect 2 "bad ext name: leading dash" bash "$here/gates.sh" "--evil"
expect 2 "bad ext name: double dash" bash "$here/gates.sh" "a--b"
expect 2 "bad ext name: path" bash "$here/gates.sh" "../x"
expect 2 "bad ext name: space" bash "$here/gates.sh" "a b"
expect 2 "dir without manifest" bash "$here/gates.sh" "scripts"
expect 2 "quality with no factors" verdict_quality "$td/quality-nofactors.json"
expect 2 "dry missing registry checks" verdict_dry "$td/dry-partial.json" beta
expect 0 "dry missing warnings field means none (beta)" verdict_dry "$td/dry-nowarnings.json" beta
expect 0 "dry missing warnings field means none (stable)" verdict_dry "$td/dry-nowarnings.json" stable
expect 2 "dry warnings field of the wrong type" verdict_dry "$td/dry-badwarnings.json" beta
printf '{"code": "auth_gate_blocked"}' >"$td/../../.gates-test.err"
expect 2 "swamp exit: no credentials" swamp_exit 1 "$td/../../.gates-test.err"
expect 1 "swamp exit: other failure" swamp_exit 3 /dev/null
expect 0 "swamp exit: ok" swamp_exit 0 /dev/null
rm -f "$td/../../.gates-test.err"
jq '.registryChecks |= map(if .name == "version-exists" then .status = "failed" else . end)' \
  "$td/dry-ok.json" >"$td/../../.dry-published.json"
h=$(jq -r .contentHash "$td/dry-ok.json")
expect 0 "published version, hash unchanged" verdict_dry "$td/../../.dry-published.json" beta "$h"
expect 1 "published version, hash changed" verdict_dry "$td/../../.dry-published.json" beta "0000"
expect 1 "published version not recorded" verdict_dry "$td/../../.dry-published.json" beta
rm -f "$td/../../.dry-published.json"
exit "$fail"
