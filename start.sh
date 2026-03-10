#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────
#  Security Analysis Platform – Start Script
#  Launches the FastAPI backend (which also serves the frontend)
# ─────────────────────────────────────────────────────────────────────────
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

HOST="${HOST:-0.0.0.0}"
PORT="${PORT:-8000}"
WORKERS="${WORKERS:-1}"
RELOAD="${RELOAD:-true}"

echo "╔════════════════════════════════════════════════════════════╗"
echo "║     Security Analysis Platform                            ║"
echo "║     API + Frontend                                        ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""
echo "  Backend API:  http://${HOST}:${PORT}/api"
echo "  Frontend UI:  http://${HOST}:${PORT}/"
echo "  API Docs:     http://${HOST}:${PORT}/docs"
echo ""

# Ensure data directories exist
mkdir -p data/uploads data/reports

# Install FastAPI deps if needed
pip show fastapi >/dev/null 2>&1 || pip install "fastapi>=0.109.0" "uvicorn[standard]>=0.27.0" "python-multipart>=0.0.6"

if [ "$RELOAD" = "true" ]; then
  echo "  Mode: Development (auto-reload)"
  echo ""
  exec uvicorn api.main:app --host "$HOST" --port "$PORT" --reload
else
  echo "  Mode: Production (${WORKERS} workers)"
  echo ""
  exec uvicorn api.main:app --host "$HOST" --port "$PORT" --workers "$WORKERS"
fi
