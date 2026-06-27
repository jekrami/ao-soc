#!/usr/bin/env bash
# =============================================================================
# stop-demo.sh — Stop AO-SOC demo processes started by start-demo.sh
# =============================================================================
#
# Reads PIDs from scripts/.demo-pids and sends SIGTERM, then SIGKILL if needed.
# Falls back to killing listeners on ports 8500, 4317, 5173 via lsof/fuser.
#
# Usage:
#   ./scripts/stop-demo.sh
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PID_FILE="$SCRIPT_DIR/.demo-pids"
DEMO_PORTS=(8500 4317 5173)

kill_pid() {
  local pid="$1"
  local label="$2"
  if [[ -z "$pid" ]] || [[ "$pid" -le 0 ]]; then
    return 0
  fi
  if kill -0 "$pid" 2>/dev/null; then
    echo "  Stopping $label (PID $pid)..."
    kill "$pid" 2>/dev/null || true
    sleep 1
    kill -9 "$pid" 2>/dev/null || true
  fi
}

kill_port() {
  local port="$1"
  if command -v lsof >/dev/null 2>&1; then
    local pids
    pids=$(lsof -ti ":$port" 2>/dev/null || true)
    if [[ -n "$pids" ]]; then
      echo "  Stopping listeners on port $port..."
      # shellcheck disable=SC2086
      kill $pids 2>/dev/null || true
      sleep 1
      # shellcheck disable=SC2086
      kill -9 $pids 2>/dev/null || true
    fi
  elif command -v fuser >/dev/null 2>&1; then
    fuser -k "${port}/tcp" 2>/dev/null || true
  fi
}

echo "Stopping AO-SOC demo stack..."

if [[ -f "$PID_FILE" ]]; then
  # PID file lines: name=pid
  while IFS='=' read -r name pid; do
    [[ -z "$name" ]] && continue
    kill_pid "$pid" "$name"
  done <"$PID_FILE"
  rm -f "$PID_FILE"
else
  echo "  No PID file; cleaning ports ${DEMO_PORTS[*]}."
fi

for port in "${DEMO_PORTS[@]}"; do
  kill_port "$port"
done

echo "Done."
