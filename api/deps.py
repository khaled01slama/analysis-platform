"""
Shared application state & dependencies.

Every route module imports from here instead of reaching into main.py globals.
"""

import logging
from pathlib import Path
from typing import Optional, Dict, Any

logger = logging.getLogger("api")

# ── Resolved paths ──────────────────────────────────────────────────────
PROJECT_ROOT = Path(__file__).resolve().parent.parent
UPLOAD_DIR = PROJECT_ROOT / "data" / "uploads"
REPORT_DIR = PROJECT_ROOT / "data" / "reports"
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
REPORT_DIR.mkdir(parents=True, exist_ok=True)

# ── Runtime singletons (populated by lifespan in main.py) ──────────────
db: Optional[Any] = None                       # AnalysisDatabase instance
search_engine: Optional[Any] = None            # VulnerabilitySearchEngine instance

SECURITY_AGENT_AVAILABLE: bool = False
SEARCH_ENGINE_AVAILABLE: bool = False

# In-memory job tracker for async SBOM analyses
analysis_jobs: Dict[str, Dict[str, Any]] = {}
