#!/usr/bin/env bash
# =============================================================================
# start-demo.sh — Prepare and launch the full AO-SOC demo stack (Linux/macOS)
# =============================================================================
#
# One-shot demo bootstrap for local recordings and smoke tests (no Ollama, no Splunk).
#
# What this script does:
#   1. Verifies python3 and node/npm are available
#   2. Installs orchestrator Python deps and backend/frontend npm packages
#      (unless --skip-install)
#   3. Starts broker (uvicorn :8500), UI API (:4317), dashboard (:5173) in background
#   4. Loads demo alerts:
#        - Default: batch seed via seed_demo_alert.py (12 alerts)
#        - With --live: real-time trickle via simulate_alerts.py
#
# Usage:
#   chmod +x scripts/start-demo.sh
#   ./scripts/start-demo.sh
#   ./scripts/start-demo.sh --live
#   ./scripts/start-demo.sh --skip-install --count 8
#
# Stop:
#   ./scripts/stop-demo.sh
#
# Logs: scripts/logs/{broker,api,frontend,simulator}.log
# =============================================================================

set -euo pipefail

# --- Defaults (override with flags) ---
LIVE=0
COUNT=12
SEED=42
SKIP_INSTALL=0
SIM_INTERVAL=10
SIM_DURATION=120

# --- Parse arguments ---
while [[ $# -gt 0 ]]; do
  case "$1" in
    --live)          LIVE=1; shift ;;
    --count)         COUNT="$2"; shift 2 ;;
    --seed)          SEED="$2"; shift 2 ;;
    --skip-install)  SKIP_INSTALL=1; shift ;;
    --sim-interval)  SIM_INTERVAL="$2"; shift 2 ;;
    --sim-duration)  SIM_DURATION="$2"; shift 2 ;;
    -h|--help)
      sed -n '1,30p' "$0"
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      exit 1
      ;;
  esac
done

# --- Paths ---
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
ORCHESTRATOR_DIR="$REPO_ROOT/orchestrator"
BACKEND_DIR="$REPO_ROOT/backend"
FRONTEND_DIR="$REPO_ROOT/frontend"
LOG_DIR="$SCRIPT_DIR/logs"
PID_FILE="$SCRIPT_DIR/.demo-pids"

BROKER_URL="http://127.0.0.1:8500"
API_URL="http://127.0.0.1:4317"
DASHBOARD_URL="http://localhost:5173"

mkdir -p "$LOG_DIR"

# --- Helpers ---

step() {
  echo ""
  echo "==> $*"
}

need_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "ERROR: '$1' not found on PATH." >&2
    exit 1
  fi
}

# Prefer python3 on Linux; fall back to python
PYTHON=""
if command -v python3 >/dev/null 2>&1; then
  PYTHON=python3
elif command -v python >/dev/null 2>&1; then
  PYTHON=python
else
  echo "ERROR: python3/python not found. Install Python 3.11+." >&2
  exit 1
fi

wait_http() {
  local url="$1"
  local label="${2:-$url}"
  local timeout="${3:-90}"
  local elapsed=0
  while [[ $elapsed -lt $timeout ]]; do
    if curl -sf "$url" >/dev/null 2>&1; then
      echo "    OK: $label"
      return 0
    fi
    sleep 2
    elapsed=$((elapsed + 2))
  done
  echo "ERROR: Timed out waiting for $label ($url)" >&2
  exit 1
}

start_bg() {
  local name="$1"
  local workdir="$2"
  shift 2
  local logfile="$LOG_DIR/${name}.log"
  echo "    Starting $name (log: $logfile)"
  (
    cd "$workdir"
    exec "$@"
  ) >>"$logfile" 2>&1 &
  local pid=$!
  echo "${name}=${pid}" >>"$PID_FILE"
  echo "$pid"
}

# Remind user to stop on Ctrl+C in this terminal (child services keep running)
cleanup_hint() {
  echo ""
  echo "Interrupted. Demo services may still be running — use: ./scripts/stop-demo.sh"
}
trap cleanup_hint INT TERM

# --- 1. Prerequisites ---

step "Checking prerequisites"
need_cmd node
need_cmd npm
need_cmd curl
echo "    $("$PYTHON" --version), node $(node -v)"

# --- 2. Install dependencies ---

if [[ $SKIP_INSTALL -eq 0 ]]; then
  step "Installing dependencies (use --skip-install to skip)"
  echo "    pip install -r orchestrator/requirements.txt"
  (cd "$ORCHESTRATOR_DIR" && "$PYTHON" -m pip install -r requirements.txt)
  for dir in "$BACKEND_DIR" "$FRONTEND_DIR"; do
    echo "    npm install in $dir"
    (cd "$dir" && npm install)
  done
else
  echo "    Skipping install (--skip-install)"
fi

# Fresh PID file
: >"$PID_FILE"

# --- 3. Start broker ---

step "Starting Aegis-Link broker on port 8500"
export BROKER_PORT=8500
start_bg broker "$ORCHESTRATOR_DIR" \
  "$PYTHON" -m uvicorn soc_orchestrator:app --host 0.0.0.0 --port 8500
sleep 3
wait_http "$BROKER_URL/health" "Broker /health"

# --- 4. Start UI API ---

step "Starting Express UI API on port 4317"
export BROKER_URL="$BROKER_URL"
start_bg api "$BACKEND_DIR" npm start
sleep 2
wait_http "$API_URL/api/health" "UI API /api/health"

# --- 5. Start dashboard ---

step "Starting Vite dashboard on port 5173"
start_bg frontend "$FRONTEND_DIR" npm run dev
sleep 4

# --- 6. Demo data ---

if [[ $LIVE -eq 1 ]]; then
  step "Starting live alert simulation (${SIM_INTERVAL}s interval, ${SIM_DURATION}s duration)"
  start_bg simulator "$ORCHESTRATOR_DIR" \
    "$PYTHON" simulate_alerts.py \
      --interval "$SIM_INTERVAL" \
      --duration "$SIM_DURATION" \
      --seed "$SEED"
else
  step "Seeding $COUNT demo alerts (batch mode, resets prior demo data)"
  (cd "$ORCHESTRATOR_DIR" && "$PYTHON" seed_demo_alert.py --count "$COUNT" --seed "$SEED")
fi

# --- Done ---

echo ""
echo "========================================"
echo " AO-SOC demo stack is running"
echo "========================================"
echo ""
echo "  Dashboard:     $DASHBOARD_URL"
echo "  Live alerts:   $DASHBOARD_URL/alerts"
echo "  Broker health: $BROKER_URL/health"
echo "  UI API:        $API_URL/api/summary"
echo ""
if [[ $LIVE -eq 1 ]]; then
  echo "  Mode:          Live simulation"
else
  echo "  Mode:          Batch seed ($COUNT alerts)"
fi
echo "  Logs:          $LOG_DIR/"
echo "  Stop all:      ./scripts/stop-demo.sh"
echo ""
echo "  Mock incidents are hidden while the broker is up (LIVE posture)."
echo ""
