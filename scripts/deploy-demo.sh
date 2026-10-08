#!/usr/bin/env bash
# Deploy RTM to the shared demo server (see the rtm-demo-server skill).
#
# Syncs this repo to ~/rtm-demo on the box and (re)builds the "rtm" compose
# project — web (live API mode) on :8090 and the Go API on :8091. Scoped to the
# "rtm" project only; never touches the other (Hank) containers on the box.
#
# Auth: set RTM_DEMO_IDENTITY for an explicit SSH key, use an already configured
# default key, or set RTM_DEMO_PASSWORD for sshpass. Never commit credentials.
#
#   RTM_DEMO_IDENTITY=~/.ssh/example_ed25519 ./scripts/deploy-demo.sh
#   RTM_DEMO_PASSWORD=... ./scripts/deploy-demo.sh
set -euo pipefail

TARGET="${RTM_DEMO_TARGET:-hankdemoserver}"
PUBLIC_HOST="${RTM_DEMO_PUBLIC_HOST:-192.168.86.139}"
REMOTE_DIR="${RTM_DEMO_DIR:-rtm-demo}"
PROJECT="rtm"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Build one ssh/rsync transport so sync, Compose, and health checks authenticate
# the same way. An explicit identity uses the pre-verified known_hosts entry.
if [[ -n "${RTM_DEMO_IDENTITY:-}" ]]; then
  if [[ ! -f "$RTM_DEMO_IDENTITY" ]]; then
    echo "RTM_DEMO_IDENTITY does not name a readable file" >&2
    exit 1
  fi
  SSH_BASE=(ssh -i "$RTM_DEMO_IDENTITY" -o IdentitiesOnly=yes -o BatchMode=yes -o StrictHostKeyChecking=yes -o ConnectTimeout=15)
elif [[ -n "${RTM_DEMO_PASSWORD:-}" ]]; then
  export SSHPASS="$RTM_DEMO_PASSWORD"
  SSH_BASE=(sshpass -e ssh -o StrictHostKeyChecking=yes -o ConnectTimeout=15)
else
  SSH_BASE=(ssh -o BatchMode=yes -o StrictHostKeyChecking=yes -o ConnectTimeout=15)
fi

echo "→ Syncing repo to ${TARGET}:${REMOTE_DIR}/"
rsync -az --delete \
  --exclude 'node_modules' --exclude 'dist' --exclude '.git' \
  --exclude 'backend/bin' --exclude '.DS_Store' --exclude '*.local' --exclude '.env' \
  --exclude 'secrets' \
  -e "${SSH_BASE[*]}" \
  "${REPO_ROOT}/" "${TARGET}:${REMOTE_DIR}/"

echo "→ Building & starting the '${PROJECT}' stack"
"${SSH_BASE[@]}" "${TARGET}" \
  "cd ~/${REMOTE_DIR} && docker compose -p ${PROJECT} -f docker-compose.demo.yml up --build -d"

echo "→ Health check"
"${SSH_BASE[@]}" "${TARGET}" '
  curl -fsS -o /dev/null -w "  web  http://HOST:8090  HTTP %{http_code}\n" http://localhost:8090/ &&
  curl -fsS -o /dev/null -w "  api  http://HOST:8091  HTTP %{http_code}\n" http://localhost:8091/api/v1/version'

echo "✓ RTM demo live: http://${PUBLIC_HOST}:8090  (API: http://${PUBLIC_HOST}:8091/api/v1)"
