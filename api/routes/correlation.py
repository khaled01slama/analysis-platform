"""
Vulnerability correlation endpoints – JSON payload or file upload.
"""

import json
from typing import Dict, Any

from fastapi import APIRouter, UploadFile, File, BackgroundTasks

from api.deps import logger, db
from api.models import CorrelationRequest, CorrelationResponse

from correlation_engine.correlation_engine import (
    CorrelationEngine, VanirParser, JoernParser, ReportGenerator,
)

router = APIRouter(prefix="/api/correlation", tags=["Correlation"])


@router.post("/analyze", response_model=CorrelationResponse)
async def correlation_analyze(req: CorrelationRequest):
    """Run vulnerability correlation from Vanir + Joern JSON payloads."""
    vanir_data = req.vanir_data or {"vulnerabilities": [], "missing_patches": []}
    joern_data = req.joern_data or []

    vulnerabilities = VanirParser.parse(vanir_data)
    unused_functions = JoernParser.parse(joern_data)

    engine = CorrelationEngine()
    correlations = engine.correlate(vulnerabilities, unused_functions)

    gen = ReportGenerator()
    report = gen.generate_analysis_report(correlations)

    aid = None
    if db:
        aid = db.create_analysis(req.repo_path or "api-upload", "correlation")
        db.update_analysis_status(aid, "completed")

    return CorrelationResponse(
        analysis_id=aid,
        timestamp=report["timestamp"],
        summary=report["analysis_summary"],
        correlations=report["correlations"],
        recommendations=report["recommendations"],
    )


@router.post("/upload")
async def correlation_upload(
    vanir_file: UploadFile = File(None),
    joern_file: UploadFile = File(None),
):
    """Upload Vanir and/or Joern result files for correlation."""
    vanir_data: Dict[str, Any] = {"vulnerabilities": [], "missing_patches": []}
    joern_data: Any = []

    if vanir_file:
        content = await vanir_file.read()
        vanir_data = json.loads(content)
    if joern_file:
        content = await joern_file.read()
        joern_data = json.loads(content)

    vulnerabilities = VanirParser.parse(vanir_data)
    unused_functions = JoernParser.parse(joern_data)

    engine = CorrelationEngine()
    correlations = engine.correlate(vulnerabilities, unused_functions)

    gen = ReportGenerator()
    report = gen.generate_analysis_report(correlations)

    return {
        "timestamp": report["timestamp"],
        "summary": report["analysis_summary"],
        "correlations": report["correlations"],
        "recommendations": report["recommendations"],
    }
