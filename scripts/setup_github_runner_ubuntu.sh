#!/usr/bin/env bash
#
# Setup a self-hosted GitHub Actions runner on an Ubuntu Server VM for the
# homelab-cyber-range repo. Designed for situations where copy/pasting into
# a Proxmox console is painful — fetch this script with curl and run it.
#
# Usage:
#   ./setup_github_runner_ubuntu.sh <RUNNER_TOKEN>
#   RUNNER_TOKEN=xxxx ./setup_github_runner_ubuntu.sh
#
# Optional env vars:
#   RUNNER_NAME   defaults to "<hostname>-homelab-runner"
#
# Get the runner token from:
#   GitHub repo > Settings > Actions > Runners > New self-hosted runner
#
set -euo pipefail

REPO_URL="https://github.com/gideon930-linux/homelab-cyber-range"
RUNNER_DIR="${HOME}/actions-runner"
RUNNER_TOKEN="${1:-${RUNNER_TOKEN:-}}"
RUNNER_NAME="${RUNNER_NAME:-$(hostname)-homelab-runner}"

usage() {
  cat <<EOF
Usage: $0 <RUNNER_TOKEN>
   or: RUNNER_TOKEN=xxxx $0

Required:
  RUNNER_TOKEN   Registration token from:
                 ${REPO_URL}/settings/actions/runners/new

Optional env vars:
  RUNNER_NAME    Runner display name (default: $(hostname)-homelab-runner)

Example:
  $0 AAABBBCCCDDDEEE
EOF
}

if [[ -z "${RUNNER_TOKEN}" ]]; then
  echo "Error: RUNNER_TOKEN is required." >&2
  echo >&2
  usage >&2
  exit 1
fi

echo "==> Installing dependencies via apt"
sudo apt-get update
sudo apt-get install -y curl tar git nmap jq python3

echo "==> Preparing runner directory at ${RUNNER_DIR}"
mkdir -p "${RUNNER_DIR}"
cd "${RUNNER_DIR}"

echo "==> Looking up latest GitHub Actions runner release"
LATEST_JSON="$(curl -fsSL https://api.github.com/repos/actions/runner/releases/latest)"
RUNNER_VERSION="$(echo "${LATEST_JSON}" | jq -r '.tag_name' | sed 's/^v//')"
if [[ -z "${RUNNER_VERSION}" || "${RUNNER_VERSION}" == "null" ]]; then
  echo "Error: could not determine latest runner version from GitHub API." >&2
  exit 1
fi
RUNNER_TARBALL="actions-runner-linux-x64-${RUNNER_VERSION}.tar.gz"
RUNNER_URL="https://github.com/actions/runner/releases/download/v${RUNNER_VERSION}/${RUNNER_TARBALL}"
echo "    Latest version: v${RUNNER_VERSION}"

if [[ ! -f "${RUNNER_TARBALL}" ]]; then
  echo "==> Downloading ${RUNNER_TARBALL}"
  curl -fL -o "${RUNNER_TARBALL}" "${RUNNER_URL}"
fi

echo "==> Extracting runner"
tar xzf "${RUNNER_TARBALL}"

echo "==> Configuring runner for ${REPO_URL} as '${RUNNER_NAME}'"
./config.sh \
  --unattended \
  --url "${REPO_URL}" \
  --token "${RUNNER_TOKEN}" \
  --name "${RUNNER_NAME}" \
  --replace

echo "==> Installing runner as a system service"
sudo ./svc.sh install

echo "==> Starting runner service"
sudo ./svc.sh start

echo
echo "Runner '${RUNNER_NAME}' is installed and running."
echo "Verify at: ${REPO_URL}/settings/actions/runners"
