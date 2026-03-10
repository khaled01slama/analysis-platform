"""
SBOM analysis endpoints – upload, status, report download.
"""

import json
import uuid
import shutil
from datetime import datetime

from fastapi import APIRouter, UploadFile, File, HTTPException, BackgroundTasks
from fastapi.responses import FileResponse

from api.deps import (
    logger, UPLOAD_DIR, REPORT_DIR,
    db, analysis_jobs,
)
from api.models import SBOMUploadResponse, AnalysisStatusResponse

from sbom_analyzer.analyzer import SBOMAnalyzer
from sbom_analyzer.converter import convert_spdx_to_json

router = APIRouter(prefix="/api/sbom", tags=["SBOM Analysis"])


# ── Background worker ───────────────────────────────────────────────────

def _run_sbom_analysis(job_id: str, file_path: str) -> None:
    """Background worker for SBOM analysis."""
    try:
        analysis_jobs[job_id]["status"] = "running"
        analysis_jobs[job_id]["progress"] = 0.1
        analysis_jobs[job_id]["message"] = "Starting analysis…"

        def progress_cb(val, msg):
            analysis_jobs[job_id]["progress"] = val
            analysis_jobs[job_id]["message"] = msg

        # Convert SPDX → JSON if needed
        target = file_path
        if file_path.lower().endswith(".spdx"):
            analysis_jobs[job_id]["message"] = "Converting SPDX to JSON…"
            target = convert_spdx_to_json(file_path)

        analyzer = SBOMAnalyzer(target, progress_callback=progress_cb)
        report = analyzer.generate_report()

        if report:
            report_path = str(REPORT_DIR / f"sbom_{job_id}.json")
            with open(report_path, "w") as f:
                json.dump(report, f, indent=2)

            if db:
                aid = db.create_analysis(file_path, "sbom_only")
                db.update_analysis_status(aid, "completed")

            analysis_jobs[job_id].update(
                status="completed", progress=1.0,
                message="Analysis complete", result=report,
            )
        else:
            analysis_jobs[job_id]["status"] = "failed"
            analysis_jobs[job_id]["message"] = "SBOM analysis returned no results"

    except Exception as exc:
        logger.exception("SBOM analysis failed")
        analysis_jobs[job_id]["status"] = "failed"
        analysis_jobs[job_id]["message"] = str(exc)


# ── Endpoints ───────────────────────────────────────────────────────────

@router.post("/upload", response_model=SBOMUploadResponse)
async def upload_sbom(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
):
    """Upload an SBOM file (SPDX or JSON) and start vulnerability analysis."""
    if not file.filename:
        raise HTTPException(400, "No file provided")

    job_id = str(uuid.uuid4())[:8]
    dest = UPLOAD_DIR / f"{job_id}_{file.filename}"

    with open(dest, "wb") as f:
        shutil.copyfileobj(file.file, f)

    analysis_jobs[job_id] = {
        "status": "pending",
        "progress": 0.0,
        "message": "Queued",
        "result": None,
        "filename": file.filename,
        "created_at": datetime.now().isoformat(),
    }

    background_tasks.add_task(_run_sbom_analysis, job_id, str(dest))

    return SBOMUploadResponse(
        job_id=job_id,
        filename=file.filename,
        status="pending",
        message="SBOM uploaded – analysis starting",
    )


@router.get("/status/{job_id}", response_model=AnalysisStatusResponse)
async def sbom_status(job_id: str):
    """Check the status of an SBOM analysis job."""
    job = analysis_jobs.get(job_id)
    if not job:
        raise HTTPException(404, "Job not found")
    return AnalysisStatusResponse(
        job_id=job_id,
        status=job["status"],
        progress=job["progress"],
        message=job["message"],
        result=job.get("result"),
    )


@router.get("/report/{job_id}")
async def sbom_report(job_id: str):
    """Download the SBOM analysis report JSON."""
    path = REPORT_DIR / f"sbom_{job_id}.json"
    if not path.exists():
        raise HTTPException(404, "Report not found")
    return FileResponse(
        str(path),
        media_type="application/json",
        filename=f"sbom_report_{job_id}.json",
    )
