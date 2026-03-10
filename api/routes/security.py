"""
Security assistant endpoints – AI queries & vulnerability search.
"""

import re

from fastapi import APIRouter, HTTPException

from api.deps import (
    logger, search_engine,
    SECURITY_AGENT_AVAILABLE, SEARCH_ENGINE_AVAILABLE,
)
from api.models import SecurityQueryRequest, SecurityQueryResponse, VulnSearchRequest

router = APIRouter(prefix="/api/security", tags=["Security Assistant"])


@router.post("/query", response_model=SecurityQueryResponse)
async def security_query(req: SecurityQueryRequest):
    """Ask the AI security assistant a question or search for CVE info."""

    # 1. Try web search first for CVE / vulnerability queries
    if search_engine and (
        "CVE" in req.query.upper()
        or "vulnerability" in req.query.lower()
    ):
        results = search_engine.search_vulnerabilities(req.query, limit=5)
        if results:
            answer_parts = []
            for r in results:
                answer_parts.append(
                    f"**{r.get('title', 'N/A')}** ({r.get('source', '')})\n"
                    f"{r.get('snippet', '')}\n{r.get('url', '')}"
                )
            return SecurityQueryResponse(
                answer="\n\n".join(answer_parts),
                sources=results,
                confidence=0.85,
            )

    # 2. Fall back to LangGraph security agent
    if SECURITY_AGENT_AVAILABLE:
        try:
            from security_assistant.security_assistant_core import LangGraphSecurityAgent

            agent = LangGraphSecurityAgent()
            result_text = agent.run(req.query, context=req.context or {})
            return SecurityQueryResponse(
                answer=result_text,
                sources=[],
                confidence=0.7,
            )
        except Exception as e:
            logger.warning(f"Security agent failed: {e}")

    return SecurityQueryResponse(
        answer=(
            "Security assistant is not available. "
            "Please ensure GROQ_API_KEY is set in .env and dependencies are installed."
        ),
        sources=[],
        confidence=0.0,
    )


@router.post("/search")
async def vulnerability_search(req: VulnSearchRequest):
    """Search for vulnerability information (NVD, OSV)."""
    if not search_engine:
        raise HTTPException(503, "Search engine not available")
    results = search_engine.search_vulnerabilities(req.query, limit=req.limit)
    return {"query": req.query, "results": results, "count": len(results)}
