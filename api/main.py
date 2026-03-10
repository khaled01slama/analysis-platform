"""
FastAPI Application – Security Analysis Platform

Thin hub that wires routers, middleware, lifespan, and static-file serving.
All endpoint logic lives in api/routes/*.py.
"""

import sys
import logging
from pathlib import Path
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles

# ── Ensure project root is importable ───────────────────────────────────
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

# ── Logging ─────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
logger = logging.getLogger("api")

# ── Probe optional heavy modules once at import time ────────────────────
import api.deps as deps  # noqa: E402  (after sys.path fix)

from correlation_engine.db_integration import AnalysisDatabase  # noqa: E402

try:
    from security_assistant.security_assistant_core import LangGraphSecurityAgent  # noqa: F401
    deps.SECURITY_AGENT_AVAILABLE = True
except Exception as e:
    logger.warning(f"Security agent not available: {e}")

try:
    from security_assistant.web_search import VulnerabilitySearchEngine
    deps.SEARCH_ENGINE_AVAILABLE = True
except Exception as e:
    logger.warning(f"Search engine not available: {e}")


# ── Lifespan ────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup / shutdown lifecycle."""
    deps.db = AnalysisDatabase()
    if deps.SEARCH_ENGINE_AVAILABLE:
        deps.search_engine = VulnerabilitySearchEngine()
    logger.info("API started – database & modules ready")
    yield
    logger.info("API shutting down")


# ── App factory ─────────────────────────────────────────────────────────

app = FastAPI(
    title="Security Analysis Platform API",
    description=(
        "Unified REST API for SBOM analysis, vulnerability correlation, "
        "and AI-powered security assistance."
    ),
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Register routers ────────────────────────────────────────────────────
from api.routes.sbom import router as sbom_router          # noqa: E402
from api.routes.correlation import router as correlation_router  # noqa: E402
from api.routes.security import router as security_router   # noqa: E402
from api.routes.dashboard import router as dashboard_router  # noqa: E402

app.include_router(sbom_router)
app.include_router(correlation_router)
app.include_router(security_router)
app.include_router(dashboard_router)


# ── Lightweight top-level endpoints ─────────────────────────────────────

from datetime import datetime  # noqa: E402

@app.get("/api/health")
async def health():
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "modules": {
            "sbom_analyzer": True,
            "correlation_engine": True,
            "security_agent": deps.SECURITY_AGENT_AVAILABLE,
            "search_engine": deps.SEARCH_ENGINE_AVAILABLE,
        },
    }


@app.get("/api/info")
async def info():
    return {
        "name": "Security Analysis Platform",
        "version": "1.0.0",
        "description": (
            "Unified platform for SBOM analysis, vulnerability correlation "
            "& AI security assistance"
        ),
        "endpoints": {
            "sbom": "/api/sbom/*",
            "correlation": "/api/correlation/*",
            "security": "/api/security/*",
            "dashboard": "/api/dashboard/*",
            "history": "/api/history/*",
        },
    }


@app.get("/api/jobs")
async def list_jobs():
    """List all active/recent analysis jobs."""
    return {
        jid: {
            "status": j["status"],
            "progress": j["progress"],
            "message": j["message"],
            "filename": j.get("filename", ""),
            "created_at": j.get("created_at", ""),
        }
        for jid, j in deps.analysis_jobs.items()
    }


# ── Serve frontend SPA ─────────────────────────────────────────────────

FRONTEND_DIR = PROJECT_ROOT / "frontend"
if FRONTEND_DIR.exists():
    app.mount(
        "/static",
        StaticFiles(directory=str(FRONTEND_DIR / "static")),
        name="static",
    )

    @app.get("/", response_class=HTMLResponse)
    async def serve_frontend():
        return HTMLResponse(
            content=(FRONTEND_DIR / "index.html").read_text(),
            status_code=200,
        )
