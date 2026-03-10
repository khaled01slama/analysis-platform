"""
Pydantic request / response schemas used across the API.
"""

from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field


# ── SBOM ────────────────────────────────────────────────────────────────

class SBOMUploadResponse(BaseModel):
    job_id: str
    filename: str
    status: str
    message: str


class AnalysisStatusResponse(BaseModel):
    job_id: str
    status: str  # pending | running | completed | failed
    progress: float = 0.0
    message: str = ""
    result: Optional[Dict[str, Any]] = None


# ── Correlation ─────────────────────────────────────────────────────────

class CorrelationRequest(BaseModel):
    vanir_data: Optional[Dict[str, Any]] = Field(
        None, description="Vanir JSON output (or upload file)"
    )
    joern_data: Optional[Any] = Field(
        None, description="Joern JSON output (or upload file)"
    )
    repo_path: Optional[str] = Field(
        None, description="Path to repository for live scan"
    )


class CorrelationResponse(BaseModel):
    analysis_id: Optional[int] = None
    timestamp: str
    summary: Dict[str, Any]
    correlations: List[Dict[str, Any]]
    recommendations: List[Dict[str, Any]]


# ── Security Assistant ──────────────────────────────────────────────────

class SecurityQueryRequest(BaseModel):
    query: str = Field(..., description="Security question or CVE ID")
    context: Optional[Dict[str, Any]] = None


class SecurityQueryResponse(BaseModel):
    answer: str
    sources: List[Dict[str, Any]] = []
    confidence: float = 0.0


class VulnSearchRequest(BaseModel):
    query: str
    limit: int = 10


# ── Dashboard ───────────────────────────────────────────────────────────

class DashboardSummary(BaseModel):
    total_analyses: int = 0
    total_vulnerabilities: int = 0
    severity_breakdown: Dict[str, int] = {}
    recent_analyses: List[Dict[str, Any]] = []
    risk_distribution: Dict[str, int] = {}
