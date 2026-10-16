#!/usr/bin/env bash
# List extension dirs touched between two commits; all of them if shared files changed.
# Usage: changed-extensions.sh <base> <head>
set -euo pipefail
base=$1 head=$2
root="$(cd "$(dirname "$0")/.." && pwd)"
all() {
  for m in "$root"/*/manifest.yaml; do
    if [[ -f $m ]]; then basename "$(dirname "$m")"; fi
  done
}
if ! git -C "$root" cat-file -e "$base^{commit}" 2>/dev/null; then all; exit 0; fi
changed=$(git -C "$root" diff --name-only "$base" "$head")
if grep -qE '^(scripts/|release\.yaml$|CONVENTIONS\.md$)' <<<"$changed"; then all; exit 0; fi
cut -d/ -f1 <<<"$changed" | sort -u | while read -r d; do
  if [[ -n $d && -f $root/$d/manifest.yaml ]]; then echo "$d"; fi
done
true
