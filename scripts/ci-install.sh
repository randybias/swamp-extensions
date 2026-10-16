#!/usr/bin/env bash
# Install the pinned CI toolchain (swamp, gitleaks, yq) into ~/.local/bin on a Linux x86_64 runner.
set -euo pipefail
SWAMP_VERSION=20261013.025835.0-sha.1b6f0c59
GITLEAKS_VERSION=8.30.1
YQ_VERSION=v4.47.2
bin="$HOME/.local/bin"
mkdir -p "$bin"
curl -fsSL https://swamp.club/install.sh | sh -s -- -V "$SWAMP_VERSION" -d "$bin"
curl -fsSL "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz" |
  tar -xz -C "$bin" gitleaks
curl -fsSL -o "$bin/yq" "https://github.com/mikefarah/yq/releases/download/${YQ_VERSION}/yq_linux_amd64"
chmod +x "$bin/yq"
echo "$bin" >>"${GITHUB_PATH:-/dev/null}"
