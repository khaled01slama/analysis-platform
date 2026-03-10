#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════
#  Security Analysis Platform – Docker Entrypoint
#  Validates all components then launches the requested command.
# ═══════════════════════════════════════════════════════════════════════
set -e

# ── Resolve python binary (prefer python3) ─────────────────────
PYTHON=$(command -v python3 2>/dev/null || command -v python 2>/dev/null || echo python)

# ── Colours ─────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'

banner() {
    echo ""
    echo -e "${CYAN}╔════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║      Security Analysis Platform  (Docker)                     ║${NC}"
    echo -e "${CYAN}╚════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
}

check_ok()   { echo -e "  ${GREEN}✔${NC} $1"; }
check_warn() { echo -e "  ${YELLOW}⚠${NC} $1"; }
check_fail() { echo -e "  ${RED}✗${NC} $1"; }

# ── Resolve APP_ROOT (works both inside Docker and on the host) ────
if [ -d /app ] && [ -w /app ]; then
    APP_ROOT="/app"
else
    APP_ROOT="$(cd "$(dirname "$0")" && pwd)"
fi

# ── Ensure data directories ────────────────────────────────────────
mkdir -p "$APP_ROOT/data/uploads" "$APP_ROOT/data/reports"

# ── Work from APP_ROOT so local Python imports resolve ─────────────
cd "$APP_ROOT"

# ── Component checks ───────────────────────────────────────────────
banner
echo -e "${CYAN}Component check${NC}"
echo "───────────────────────────────────────────────────"

# 1) Python & FastAPI
if $PYTHON -c "import fastapi" 2>/dev/null; then
    check_ok "FastAPI API server"
else
    check_fail "FastAPI not installed"
fi

# 2) SBOM Analyzer
if $PYTHON -c "from sbom_analyzer.analyzer import SBOMAnalyzer" 2>/dev/null; then
    check_ok "SBOM Analyzer"
else
    check_warn "SBOM Analyzer (import failed – non-critical)"
fi

# 3) Correlation Engine
if $PYTHON -c "from correlation_engine.correlation_engine import CorrelationEngine" 2>/dev/null; then
    check_ok "Correlation Engine"
else
    check_warn "Correlation Engine (import failed – non-critical)"
fi

# 4) Security Assistant (LLM)
if $PYTHON -c "from security_assistant.security_assistant_core import LangGraphSecurityAgent" 2>/dev/null; then
    check_ok "Security Assistant (LangGraph)"
else
    check_warn "Security Assistant (not available – check GROQ_API_KEY)"
fi

# 5) Vanir
if [ -d "$VANIR_PATH" ]; then
    if [ -f "$VANIR_PATH/detector_runner" ] || [ -f "$VANIR_PATH/detector_runner.zip" ]; then
        check_ok "Vanir detector_runner (Bazel build)"
    else
        check_warn "Vanir directory exists but detector_runner binary not found"
        check_warn "  → You can still use Vanir's Python modules directly"
    fi
else
    check_warn "Vanir not found at $VANIR_PATH"
fi

# 6) Joern
if command -v joern &>/dev/null; then
    JOERN_VER=$(joern --version 2>/dev/null || echo "unknown")
    check_ok "Joern CLI ($JOERN_VER)"
elif command -v joern-parse &>/dev/null; then
    check_ok "Joern (joern-parse available)"
else
    check_warn "Joern CLI not in PATH (dead-code analysis unavailable)"
fi

# 7) Java (needed by Joern & Vanir)
if java -version 2>&1 | head -1 | grep -q "version"; then
    JAVA_VER=$(java -version 2>&1 | head -1)
    check_ok "Java runtime – $JAVA_VER"
else
    check_warn "Java not found (Joern & Vanir Bazel builds require JRE)"
fi

# 8) Frontend
if [ -f "$APP_ROOT/frontend/index.html" ]; then
    check_ok "Frontend (static SPA)"
else
    check_warn "Frontend files missing"
fi

echo "───────────────────────────────────────────────────"
echo ""

# ── Environment summary ────────────────────────────────────────────
echo -e "${CYAN}Environment${NC}"
echo "  GROQ_API_KEY  = ${GROQ_API_KEY:+set (***${GROQ_API_KEY: -4})}${GROQ_API_KEY:-NOT SET}"
echo "  GROQ_MODEL    = ${GROQ_MODEL:-llama-3.1-8b-instant}"
echo "  VANIR_PATH    = ${VANIR_PATH:-/opt/vanir}"
echo "  JOERN_HOME    = ${JOERN_HOME:-/opt/joern}"
echo "  HOST:PORT     = ${HOST:-0.0.0.0}:${PORT:-8000}"
echo "  WORKERS       = ${WORKERS:-1}"
echo ""

# ── Execute command ─────────────────────────────────────────────────
case "${1:-serve}" in
    serve)
        echo -e "${GREEN}▶ Starting FastAPI server …${NC}"
        echo "  API:      http://${HOST:-0.0.0.0}:${PORT:-8000}/api"
        echo "  Frontend: http://${HOST:-0.0.0.0}:${PORT:-8000}/"
        echo "  Docs:     http://${HOST:-0.0.0.0}:${PORT:-8000}/docs"
        echo ""
        exec $PYTHON -m uvicorn api.main:app \
            --host "${HOST:-0.0.0.0}" \
            --port "${PORT:-8000}" \
            --workers "${WORKERS:-1}" \
            --log-level info
        ;;

    dev)
        echo -e "${GREEN}▶ Starting FastAPI server (dev + auto-reload) …${NC}"
        exec $PYTHON -m uvicorn api.main:app \
            --host "${HOST:-0.0.0.0}" \
            --port "${PORT:-8000}" \
            --reload \
            --log-level debug
        ;;

    joern-analyze)
        # Usage: docker compose run app joern-analyze /path/to/project ProjectName [output.json]
        shift
        echo -e "${GREEN}▶ Running Joern dead-code analysis …${NC}"
        exec bash "$APP_ROOT/detection_script/find_non_called_methods.sh" "$@"
        ;;

    vanir-scan)
        # Usage: docker compose run app vanir-scan /path/to/target
        shift
        echo -e "${GREEN}▶ Running Vanir patch detection …${NC}"
        if [ -f "$VANIR_PATH/detector_runner" ]; then
            exec "$VANIR_PATH/detector_runner" "$@"
        elif [ -f "$VANIR_PATH/detector_runner.zip" ]; then
            exec $PYTHON "$VANIR_PATH/detector_runner.zip" "$@"
        else
            echo -e "${RED}detector_runner not found – running via Python source${NC}"
            exec $PYTHON -m vanir.vanir.vanir.detector_runner "$@"
        fi
        ;;

    healthcheck)
        $PYTHON -c "import urllib.request; urllib.request.urlopen('http://localhost:${PORT:-8000}/api/health')"
        ;;

    shell)
        exec /bin/bash
        ;;

    *)
        exec "$@"
        ;;
esac
