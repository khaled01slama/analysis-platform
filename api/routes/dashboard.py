"""
Dashboard aggregation & analysis history endpoints.
"""

import json
import sqlite3
from typing import Optional, List, Any, Dict

from fastapi import APIRouter, HTTPException, Query

from api.deps import logger, db
from api.models import DashboardSummary

router = APIRouter(tags=["Dashboard & History"])


# ══════════════════════════════════════════════════════════════════════════
#  Dashboard
# ══════════════════════════════════════════════════════════════════════════

@router.get("/api/dashboard/summary", response_model=DashboardSummary)
async def dashboard_summary():
    """Aggregate statistics for the frontend dashboard."""
    if not db:
        return DashboardSummary()

    try:
        conn = sqlite3.connect(db.db_path)
        cur = conn.cursor()

        cur.execute("SELECT COUNT(*) FROM analysis")
        total_analyses = cur.fetchone()[0]

        cur.execute("""
            SELECT COALESCE(SUM(critical_count),0), COALESCE(SUM(high_count),0),
                   COALESCE(SUM(medium_count),0), COALESCE(SUM(low_count),0)
            FROM vanir_results
        """)
        row = cur.fetchone()
        severity = {
            "Critical": row[0], "High": row[1],
            "Medium": row[2], "Low": row[3],
        }
        total_vulns = sum(severity.values())

        cur.execute("""
            SELECT id, timestamp, repo_path, analysis_type, status, duration_seconds
            FROM analysis ORDER BY id DESC LIMIT 10
        """)
        recent = [
            {
                "id": r[0], "timestamp": r[1], "repo_path": r[2],
                "analysis_type": r[3], "status": r[4], "duration": r[5],
            }
            for r in cur.fetchall()
        ]

        cur.execute("""
            SELECT COALESCE(SUM(high_risk_count),0),
                   COALESCE(SUM(medium_risk_count),0),
                   COALESCE(SUM(low_risk_count),0)
            FROM correlation_results
        """)
        risk_row = cur.fetchone()
        risk_dist = {"High": risk_row[0], "Medium": risk_row[1], "Low": risk_row[2]}

        conn.close()

        return DashboardSummary(
            total_analyses=total_analyses,
            total_vulnerabilities=total_vulns,
            severity_breakdown=severity,
            recent_analyses=recent,
            risk_distribution=risk_dist,
        )
    except Exception as e:
        logger.error(f"Dashboard summary error: {e}")
        return DashboardSummary()


# ══════════════════════════════════════════════════════════════════════════
#  History
# ══════════════════════════════════════════════════════════════════════════

@router.get("/api/history/analyses")
async def list_analyses(
    limit: int = Query(20, ge=1, le=100),
    offset: int = Query(0, ge=0),
    analysis_type: Optional[str] = None,
    status: Optional[str] = None,
):
    """List analysis history with pagination and filtering."""
    if not db:
        return {"analyses": [], "total": 0}

    conn = sqlite3.connect(db.db_path)
    cur = conn.cursor()

    where_clauses: List[str] = []
    params: List[Any] = []
    if analysis_type:
        where_clauses.append("analysis_type = ?")
        params.append(analysis_type)
    if status:
        where_clauses.append("status = ?")
        params.append(status)

    where_sql = (" WHERE " + " AND ".join(where_clauses)) if where_clauses else ""

    cur.execute(f"SELECT COUNT(*) FROM analysis{where_sql}", params)
    total = cur.fetchone()[0]

    cur.execute(
        f"SELECT id, timestamp, repo_path, analysis_type, status, duration_seconds "
        f"FROM analysis{where_sql} ORDER BY id DESC LIMIT ? OFFSET ?",
        params + [limit, offset],
    )
    rows = cur.fetchall()
    conn.close()

    return {
        "analyses": [
            {
                "id": r[0], "timestamp": r[1], "repo_path": r[2],
                "analysis_type": r[3], "status": r[4], "duration": r[5],
            }
            for r in rows
        ],
        "total": total,
        "limit": limit,
        "offset": offset,
    }


@router.get("/api/history/analysis/{analysis_id}")
async def get_analysis_detail(analysis_id: int):
    """Get detailed results for a specific analysis."""
    if not db:
        raise HTTPException(503, "Database not available")

    conn = sqlite3.connect(db.db_path)
    cur = conn.cursor()

    cur.execute("SELECT * FROM analysis WHERE id = ?", (analysis_id,))
    analysis = cur.fetchone()
    if not analysis:
        conn.close()
        raise HTTPException(404, "Analysis not found")

    result: Dict[str, Any] = {
        "id": analysis[0],
        "timestamp": analysis[1],
        "repo_path": analysis[2],
        "analysis_type": analysis[3],
        "status": analysis[4],
        "duration": analysis[5],
    }

    # Vanir
    cur.execute("SELECT * FROM vanir_results WHERE analysis_id = ?", (analysis_id,))
    vanir = cur.fetchone()
    if vanir:
        result["vanir"] = {
            "vulnerability_count": vanir[2],
            "critical": vanir[3], "high": vanir[4],
            "medium": vanir[5], "low": vanir[6],
            "patch_links": json.loads(vanir[7]) if vanir[7] else [],
            "cve_ids": json.loads(vanir[8]) if vanir[8] else [],
        }

    # Joern
    cur.execute("SELECT * FROM joern_results WHERE analysis_id = ?", (analysis_id,))
    joern = cur.fetchone()
    if joern:
        result["joern"] = {"unused_functions_count": joern[2]}

    # Correlation
    cur.execute("SELECT * FROM correlation_results WHERE analysis_id = ?", (analysis_id,))
    corr = cur.fetchone()
    if corr:
        result["correlation"] = {
            "high_risk": corr[4], "medium_risk": corr[5], "low_risk": corr[6],
        }

    # SBOM
    cur.execute("SELECT * FROM sbom_results WHERE analysis_id = ?", (analysis_id,))
    sbom = cur.fetchone()
    if sbom:
        result["sbom"] = {
            "package_count": sbom[2], "vulnerability_count": sbom[3],
            "critical": sbom[4], "high": sbom[5],
            "medium": sbom[6], "low": sbom[7],
        }

    conn.close()
    return result
