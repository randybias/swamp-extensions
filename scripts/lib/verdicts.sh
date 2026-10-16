#!/usr/bin/env bash
# Verdicts over swamp JSON output. Each returns 0 pass, 1 fail, 2 could not run.
# Output that is empty, an error object, or missing the fields a verdict needs
# is "could not run" (2), never a pass. Sourced by gates.sh and gates_test.sh.

judgeable() { # <json-file>
  [[ -s $1 ]] && jq -e 'type == "object" and (has("error") | not)' "$1" >/dev/null 2>&1
}

verdict_quality() { # <quality.json> [visibility]
  # repository-verified is decided by the registry on publish, so locally it is at best
  # "provisional". Private: exempt entirely. Public: it must at least be provisional.
  local private=1
  [[ ${2:-private} == private ]] || private=0
  judgeable "$1" || return 2
  jq -e '(.allPassed | type == "boolean") and (.factors | type == "array") and
    ([.factors[].id] | contains(["has-readme", "description", "has-license", "dependency-trust"]))
    and all(.factors[]; .status | type == "string")' "$1" >/dev/null 2>&1 || return 2
  jq -e --argjson private "$private" '
    [.factors[] | select(
      if .id == "repository-verified" then
        ($private == 0 and (.status | IN("earned", "provisional") | not))
      else .status != "earned" end)] | length == 0' \
    "$1" >/dev/null || return 1
}

verdict_dry() { # <dry-run.json> <channel> [published-hash]
  # published-hash: the contentHash release.yaml records for this version, when it is
  # already published. Then a version-exists failure passes only if the hash is unchanged.
  local j=$1 channel=$2 published=${3:-}
  judgeable "$j" || return 2
  # swamp omits unresolvedWarnings when there are none; absent means [], any other type is unjudgeable.
  jq -e '((.unresolvedWarnings // []) | type == "array") and (.registryChecks | type == "array") and
    ([.registryChecks[].name] |
      contains(["authentication", "reserved-collective", "collective-membership", "version-exists"]))' \
    "$j" >/dev/null 2>&1 || return 2
  jq -e '[.registryChecks[] | select(.status == "not-run")] | length == 0' "$j" >/dev/null || return 2
  if [[ -n $published ]]; then
    jq -e --arg h "$published" '.contentHash == $h' "$j" >/dev/null || return 1
    jq -e '[.registryChecks[] | select(.status != "passed" and .name != "version-exists")]
      | length == 0' "$j" >/dev/null || return 1
  else
    jq -e '[.registryChecks[] | select(.status != "passed")] | length == 0' "$j" >/dev/null || return 1
  fi
  jq -e '[(.unresolvedWarnings // [])[] | select(.ruleId != "adversarial-review-dimension-issue")]
    | length == 0' "$j" >/dev/null || return 1
  if [[ $channel != beta ]]; then
    jq -e '(.unresolvedWarnings // []) | length == 0' "$j" >/dev/null || return 1
  fi
  return 0
}

# Classify a swamp command's exit: 0 ok, 2 no credentials, 1 any other failure.
swamp_exit() { # <rc> <stderr-file>
  (($1 == 0)) && return 0
  grep -q '"code": *"auth_gate_blocked"' "$2" 2>/dev/null && return 2
  return 1
}
