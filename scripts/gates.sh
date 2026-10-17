#!/usr/bin/env bash
# Run every gate for one extension directory, in increasing-risk order.
# Gates 4 and 5 also scan every tracked file in the repo, whatever the extension.
# Usage: scripts/gates.sh [--offline] <extension-dir>
#        scripts/gates.sh --tree   (gates 4 and 5 on the whole tracked tree only)
# Exit: 0 all passed, 1 a gate failed, 2 a gate could not run, 3 incomplete (--offline).
set -uo pipefail

# shellcheck source=lib/verdicts.sh
source "$(dirname "$0")/lib/verdicts.sh"

root="$(cd "$(dirname "$0")/.." && pwd)"
offline=0
tree=0
[[ ${1:-} == --offline ]] && { offline=1; shift; }
[[ ${1:-} == --tree ]] && { tree=1; shift; }
ext=${1:-}
if ((tree)); then
  if [[ -n $ext ]]; then
    echo "usage: gates.sh --tree  (takes no extension)" >&2
    exit 2
  fi
elif ! [[ $ext =~ ^[a-z0-9]+(-[a-z0-9]+)*$ ]] || [[ ! -f $root/$ext/manifest.yaml ]]; then
  echo "usage: gates.sh [--offline] <extension-dir>  (a top-level dir holding manifest.yaml)" >&2
  echo "       gates.sh --tree" >&2
  exit 2
fi
for t in deno swamp jq yq gitleaks git; do
  command -v "$t" >/dev/null || { echo "NOT RUN  tool missing: $t" >&2; exit 2; }
done

cd "$root" || exit 2
out="$root/.gates/${ext:-_tree}"
mkdir -p "$out"
worst=0
note() { # <rc> <n> <name> [detail]
  local rc=$1 tag
  case $rc in 0 | 1 | 2 | 3) ;; *) rc=1 ;; esac # any other exit status is a failure
  case $rc in 0) tag=PASS ;; 1) tag=FAIL ;; 2) tag="NOT RUN" ;; 3) tag=SKIP ;; esac
  printf '%-8s %s %-14s %s\n' "$tag" "$2" "$3" "${4:-}"
  if ((rc == 1)); then worst=1
  elif ((rc == 2 && worst != 1)); then worst=2
  elif ((rc == 3 && worst == 0)); then worst=3
  fi
}
in_ext() { (cd "$ext" && "$@"); }
worse() { # <rc> <rc>: a failure beats could-not-run beats pass
  if (($1 == 1 || $2 == 1)); then echo 1
  elif (($1 == 2 || $2 == 2)); then echo 2
  else echo 0
  fi
}

# 4 leak scan: the extension (tracked and untracked files), then every tracked file in the repo
gate_leaks() {
  local rc=0
  : >"$out/leaks.txt"
  if [[ -n $ext ]]; then
    deno run --allow-read --allow-env --allow-run=git scripts/leak-scan.ts "$ext" \
      >>"$out/leaks.txt" 2>&1
    rc=$?
  fi
  deno run --allow-read --allow-env --allow-run=git scripts/leak-scan.ts --tree . \
    >>"$out/leaks.txt" 2>&1
  rc=$(worse "$rc" $?)
  note $rc 4 "leak scan" "$( ((rc)) && head -5 "$out/leaks.txt" | tr '\n' ';')"
}

# Copy every tracked file (as in the working tree) into a temp dir and gitleaks it, so
# untracked drafts are never scanned. Exit 0 clean, 1 findings, 2 cannot run.
gitleaks_tree() {
  local tmp rc
  tmp=$(mktemp -d) || return 2
  git ls-files -z --cached | while IFS= read -r -d '' f; do
    [[ -f $f || -L $f ]] && printf '%s\0' "$f"
  done | tar --null -T - -cf - | tar -xf - -C "$tmp" || {
    rm -rf "$tmp"
    return 2
  }
  echo "== tracked tree" >>"$out/gitleaks.txt"
  gitleaks dir "$tmp" --redact --no-banner >>"$out/gitleaks.txt" 2>&1
  rc=$?
  rm -rf "$tmp"
  ((rc == 0)) || rc=1
  return $rc
}

# 5 gitleaks: the extension dir, the whole tracked tree, then full history
gate_gitleaks() {
  local rc=0
  : >"$out/gitleaks.txt"
  if [[ -n $ext ]]; then
    gitleaks dir "$ext" --redact --no-banner >>"$out/gitleaks.txt" 2>&1 || rc=1
  fi
  gitleaks_tree
  rc=$(worse "$rc" $?)
  echo "== history" >>"$out/gitleaks.txt"
  gitleaks git . --redact --no-banner >>"$out/gitleaks.txt" 2>&1 || rc=$(worse "$rc" 1)
  note $rc 5 gitleaks "$( ((rc)) && echo "log: .gates/${ext:-_tree}/gitleaks.txt")"
}

if ((tree)); then
  gate_leaks
  gate_gitleaks
  exit $worst
fi

channel=$(yq -r ".\"$ext\".channel // \"\"" release.yaml)
if [[ $channel != beta && $channel != stable ]]; then
  note 1 0 release "no beta/stable channel for $ext in release.yaml"
  exit 1
fi
version=$(yq -r .version "$ext/manifest.yaml")
# contentHash recorded when this version was published (empty if never published)
published=$(yq -r ".\"$ext\".published.\"$version\" // \"\"" release.yaml)

# 0 consistency: model versions, packaged files
bad=""
while read -r m; do
  [[ -n $m ]] || continue
  grep -qE "^[[:space:]]*version: \"${version//./\\.}\"," "$ext/extensions/models/$m" 2>/dev/null ||
    bad+=" $m"
done < <(yq -r '.models[]?' "$ext/manifest.yaml")
yq -e '(.additionalFiles | any_c(. == "README.md")) and (.additionalFiles | any_c(. == "LICENSE.txt"))
  and ((.additionalFiles | any_c(. == "LOGBOOK.md")) | not)' "$ext/manifest.yaml" >/dev/null 2>&1 ||
  bad+=" additionalFiles"
rc=0
[[ -z $bad ]] || rc=1
note $rc 0 consistency "${bad:+mismatch:$bad}"

# 1 deno
models=()
while read -r m; do [[ -n $m ]] && models+=("extensions/models/$m"); done \
  < <(yq -r '.models[]?' "$ext/manifest.yaml")
{
  in_ext deno fmt --check && in_ext deno lint && in_ext deno check "${models[@]}" &&
    in_ext deno task test
} >"$out/deno.log" 2>&1
rc=$?
((rc == 0)) || rc=1
note $rc 1 deno "log: .gates/$ext/deno.log"

# 2 swamp fmt: the command must exit 0 AND report passed
in_ext swamp extension fmt manifest.yaml --check --json >"$out/fmt.json" 2>"$out/fmt.err"
swamp_exit $? "$out/fmt.err"
rc=$?
if ((rc == 0)); then
  if ! judgeable "$out/fmt.json"; then rc=2
  elif ! jq -e '.status == "passed"' "$out/fmt.json" >/dev/null; then rc=1
  fi
fi
note $rc 2 "swamp fmt"

# 3 quality: the command must exit 0 AND the verdict pass
in_ext swamp extension quality manifest.yaml --json >"$out/quality.json" 2>"$out/quality.err"
swamp_exit $? "$out/quality.err"
rc=$?
if ((rc == 0)); then
  verdict_quality "$out/quality.json" "$(yq -r '.visibility // "public"' "$ext/manifest.yaml")"
  rc=$?
fi
note $rc 3 quality

gate_leaks
gate_gitleaks

# 6 fixture guard
deno run --allow-read scripts/fixture-guard.ts "$ext" >"$out/fixtures.txt" 2>&1
rc=$?
note $rc 6 "fixture guard" "$( ((rc)) && head -5 "$out/fixtures.txt" | tr '\n' ';')"

# 7 + 8 dry run and adversarial review
if ((offline)); then
  note 3 7 "dry run" "--offline"
  note 3 8 review "--offline"
else
  dry() {
    in_ext swamp extension push manifest.yaml --dry-run --json \
      >"$out/dry-run.json" 2>"$out/dry-run.err"
    dry_rc=$?
  }
  dry_rc=0
  dry
  hash=$(jq -r '.contentHash // empty' "$out/dry-run.json" 2>/dev/null)
  report="reviews/$ext/$hash.json"
  target=$(jq -r '[.unresolvedWarnings[]? | select(.ruleId == "adversarial-review-report")
    | .file][0] // empty' "$out/dry-run.json" 2>/dev/null)
  local_only=0
  if [[ -n $hash && -f $report ]]; then
    # Always judge the committed report, even when swamp's temp dir already has one.
    if [[ -z $target ]]; then
      name=$(yq -r .name "$ext/manifest.yaml" | tr -d '@' | tr '/' '_')
      target="${TMPDIR:-/tmp}"
      target="${target%/}/swamp-extension-review/_${name}-${hash}.json"
    fi
    mkdir -p "$(dirname "$target")" && cp "$report" "$target" && dry
  elif [[ -n $hash && ! -f $report && -z $target ]]; then
    local_only=1
  fi
  verdict_dry "$out/dry-run.json" "$channel" "$published"
  rc=$?
  # A non-zero exit can never pass, whatever the JSON says.
  # The one exception: an already-published version whose hash matches release.yaml,
  # where version-exists is the only failed check (verdict_dry has already proved both).
  if ((rc == 0 && dry_rc != 0)) && [[ -n $published ]] &&
    jq -e '[.registryChecks[] | select(.status != "passed") | .name] == ["version-exists"]' \
      "$out/dry-run.json" >/dev/null; then
    dry_rc=0
  fi
  if ((rc == 0 && dry_rc != 0)); then
    swamp_exit "$dry_rc" "$out/dry-run.err"
    rc=$?
  fi
  detail="contentHash ${hash:-none}"
  if [[ -n $published && -n $hash && $hash != "$published" ]]; then
    detail="$version is published with ${published:0:12}; packaged files changed, bump the version"
  elif [[ -n $published ]]; then
    detail="$detail (already published, unchanged)"
  fi
  note $rc 7 "dry run" "$detail"
  if ((local_only)); then
    note 1 8 review "report is only in swamp's temp dir; commit it as $report"
  elif [[ -z $hash ]]; then
    note 2 8 review "no contentHash, so no report to check"
  elif [[ -f $report ]]; then
    note $rc 8 review "$report"
  else
    note 1 8 review "missing $report"
  fi
fi

exit $worst
