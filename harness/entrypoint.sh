#!/usr/bin/env bash
# Starts the OpenCode server and the AI Cyber Shield gateway inside the container.
set -euo pipefail

if [[ -z "${SHIELD_TOKEN:-}" || -z "${OPENCODE_SERVER_PASSWORD:-}" ]]; then
  echo "SHIELD_TOKEN and OPENCODE_SERVER_PASSWORD must be set (run start.ps1, or copy .env.example to .env)." >&2
  exit 1
fi

# Model used by the agents. Empty means OpenCode picks its own default.
export SHIELD_MODEL="${SHIELD_MODEL:-}"

mkdir -p /workspace/data/captures /workspace/data/reports

cd /workspace
opencode serve --hostname 0.0.0.0 --port 4096 &
OPENCODE_PID=$!

python3 -m uvicorn app:app --app-dir /opt/shield/gateway --host 0.0.0.0 --port 7878 --no-access-log &
GATEWAY_PID=$!

trap 'kill $OPENCODE_PID $GATEWAY_PID 2>/dev/null || true' TERM INT
# Exit (and let Docker restart us) if either process dies.
wait -n $OPENCODE_PID $GATEWAY_PID
EXIT=$?
kill $OPENCODE_PID $GATEWAY_PID 2>/dev/null || true
exit $EXIT
