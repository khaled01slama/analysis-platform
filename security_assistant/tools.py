"""
Tool implementations available to the LangGraph security agent.
"""

import re
import json
import sqlite3
import logging
from datetime import datetime
from pathlib import Path
from collections import Counter
from typing import List

from security_assistant.models import SecurityReport
from security_assistant.memory import PersistentMemory
from security_assistant.llm import create_llm

logger = logging.getLogger("security_assistant.tools")


class SecurityAgentTools:
    """Toolbox consumed by the LangGraph agent nodes."""

    def __init__(self, memory: PersistentMemory, web_search=None):
        self.memory = memory

        # Web-search helpers (optional)
        try:
            try:
                from security_assistant.web_search import (
                    VulnerabilitySearchEngine,
                    SearchEnabledAssistant,
                )
            except ImportError:
                from web_search import VulnerabilitySearchEngine, SearchEnabledAssistant

            self.web_search = VulnerabilitySearchEngine()
            self.search_assistant = SearchEnabledAssistant() if SearchEnabledAssistant else None
        except ImportError:
            logger.warning("Web search components not available")
            self.web_search = None
            self.search_assistant = None

        self.vulnerability_search = self.web_search

        self.workspace = Path("./agent_workspace")
        self.workspace.mkdir(exist_ok=True)

        logger.info("SecurityAgentTools initialised")

    # ── Database query via LLM-generated SQL ────────────────────────────
    def query_analysis_database(self, prompt: str) -> str:
        try:
            import sqlparse
        except ImportError:
            return (
                "Database querying requires the sqlparse package. "
                "Install it with: pip install sqlparse"
            )

        allowed_tables = [
            "analysis", "vanir_results", "joern_results", "correlation_results",
            "sbom_results", "vulnerabilities", "analysis_meta",
            "security_agent_memory", "agent_state",
            "reports", "insights", "search_cache",
        ]

        try:
            llm = getattr(self, "llm", None)
            if llm is None and hasattr(self.memory, "llm"):
                llm = self.memory.llm
            if llm is None:
                llm = create_llm(temperature=0.1)

            system_prompt = (
                "You are a security data assistant. Transform the following "
                "natural language request into a safe SQL SELECT query. "
                "Only use the following tables: {}. "
                "Do not generate UPDATE, DELETE, INSERT, or DROP statements. "
                "Return only the SQL query, nothing else."
            ).format(", ".join(allowed_tables))

            from langchain_core.messages import SystemMessage, HumanMessage

            llm_response = llm.invoke([
                SystemMessage(content=system_prompt),
                HumanMessage(content=prompt),
            ])
            sql = (
                llm_response.content.strip()
                if hasattr(llm_response, "content")
                else str(llm_response).strip()
            )

            parsed = sqlparse.parse(sql)
            if not parsed or parsed[0].get_type() != "SELECT":
                return "Sorry, only SELECT queries are allowed."
            if not any(t in sql for t in allowed_tables):
                return "Query references unsupported table."

            conn = sqlite3.connect(self.memory.db_path)
            cur = conn.cursor()
            cur.execute(sql)
            rows = cur.fetchall()
            columns = [d[0] for d in cur.description]
            conn.close()

            if not rows:
                return "No results found."

            lines = ["Here are the results for your request:", ""]
            lines.append(" | ".join(columns))
            for row in rows:
                lines.append(" | ".join(str(c) for c in row))
            lines.append("")
            lines.append(f"Total results: {len(rows)}")
            return "\n".join(lines)

        except Exception as exc:
            return f"Query failed: {exc}"

    # ── Vulnerability search ────────────────────────────────────────────
    def search_vulnerabilities(self, query: str) -> str:
        try:
            if not self.vulnerability_search:
                return "Vulnerability search engine is not available."
            results = self.vulnerability_search.search_vulnerabilities(query)
            if not results:
                return f"No results found for query: {query}"

            parts: list[str] = []
            for r in results[:10]:
                parts.append(
                    f"**{r.get('title', 'Unknown')}**\n"
                    f"Source: {r.get('source', 'Unknown')}\n"
                    f"URL: {r.get('url', 'N/A')}\n"
                    f"Snippet: {r.get('snippet', 'No description')}\n---"
                )
            return "\n".join(parts)
        except Exception as exc:
            return f"Search failed: {exc}"

    def enhanced_cve_search(self, cve_id: str) -> str:
        try:
            if not self.search_assistant:
                if self.web_search:
                    results = self.web_search.search_vulnerabilities(cve_id)
                    if results:
                        lines = [f"**CVE Analysis: {cve_id}**"]
                        for r in results[:3]:
                            lines.append(f"- {r.get('title', 'Unknown')}")
                            lines.append(f"  Source: {r.get('source', 'Unknown')}")
                            lines.append(f"  Summary: {r.get('snippet', '')[:200]}...")
                            lines.append("")
                        return "\n".join(lines)
                return f"No search results found for {cve_id}"

            results = self.search_assistant.search_enhanced_cve(cve_id)
            if not results:
                return f"No enhanced results found for {cve_id}"

            lines = [f"**Enhanced CVE Analysis: {cve_id}**"]
            if isinstance(results, dict):
                for key in ("summary", "severity", "cvss_score", "remediation"):
                    if key in results:
                        lines.append(f"{key.replace('_', ' ').title()}: {results[key]}")
                if "references" in results:
                    lines.append(f"References: {len(results['references'])} found")
            return "\n".join(lines)
        except Exception as exc:
            return f"Enhanced CVE search failed: {exc}"

    # ── Report analysis ─────────────────────────────────────────────────
    def analyze_previous_reports(self, target: str = None, days_back: int = 30) -> str:
        try:
            reports = self.memory.get_reports(target=target, days_back=days_back)
            if not reports:
                return "No previous reports found for analysis."

            severity_counts: dict = {}
            cve_trends: list = []
            recommendations: list = []
            for r in reports:
                severity_counts[r.severity] = severity_counts.get(r.severity, 0) + 1
                cve_trends.extend(r.related_cves)
                recommendations.extend(r.recommendations)

            lines = [
                f"**Report Analysis Summary ({len(reports)} reports)**",
                f"Severity distribution: {severity_counts}",
                f"Most common CVEs: {self._most_common(cve_trends)}",
                f"Recurring recommendations: {self._most_common(recommendations)}",
            ]
            insight = "\n".join(lines)
            self.memory.store_insight(
                insight, "report_analysis", 0.8, [r.id for r in reports]
            )
            return insight
        except Exception as exc:
            return f"Report analysis failed: {exc}"

    # ── Recommendation generation ───────────────────────────────────────
    def generate_action_recommendations(self, context: str) -> str:
        try:
            insights = self.memory.get_insights(category="report_analysis")
            recent = self.memory.get_reports(days_back=7)

            parts: list[str] = []
            if insights:
                parts.append("## Historical Analysis Insights:")
                for i in insights[:2]:
                    parts.append(f"- {i['content']}")

            if recent:
                pending = [r for r in recent if r.remediation_status == "pending"]
                high = [r for r in recent if r.severity in ("HIGH", "CRITICAL")]
                parts.append("## Recent Activity Analysis:")
                if pending:
                    parts.append(f"- {len(pending)} vulnerabilities need immediate remediation")
                if high:
                    parts.append(f"- {len(high)} high-severity issues require priority attention")

            if "vulnerability" in context.lower():
                parts += [
                    "## Vulnerability Management:",
                    "- Prioritize patching based on exploitability and business impact",
                    "- Implement vulnerability scanning automation",
                ]
            if "correlation" in context.lower():
                parts += [
                    "## Correlation Analysis:",
                    "- Review correlation patterns for threat actor attribution",
                    "- Validate correlation results to reduce false positives",
                ]

            parts += [
                "## Immediate Actions:",
                "- Update threat intelligence feeds",
                "- Review and validate security controls",
                "- Conduct risk assessment of identified issues",
            ]
            return "\n".join(parts)
        except Exception as exc:
            return f"Recommendation generation failed: {exc}"

    # ── Report creation ─────────────────────────────────────────────────
    def create_security_report(
        self,
        title: str,
        content: str,
        target: str,
        severity: str,
        report_type: str = "assessment",
    ) -> str:
        try:
            report_id = f"RPT-{datetime.now().strftime('%Y%m%d%H%M%S')}"
            report = SecurityReport(
                id=report_id,
                title=title,
                content=content,
                report_type=report_type,
                target=target,
                timestamp=datetime.now(),
                severity=severity,
                recommendations=self._extract_recommendations(content),
                tags=[report_type, severity.lower(), target],
                related_cves=self._extract_cves(content),
            )
            self.memory.store_report(report)
            return f"Report created successfully: {report_id}"
        except Exception as exc:
            return f"Report creation failed: {exc}"

    # ── Private helpers ─────────────────────────────────────────────────
    @staticmethod
    def _most_common(items: List[str], top_n: int = 3) -> List[str]:
        return [item for item, _ in Counter(items).most_common(top_n)]

    @staticmethod
    def _extract_recommendations(content: str) -> List[str]:
        patterns = [
            r"(?:recommend|suggest|should|must|need to)\s+(.+?)(?:\.|$)",
            r"(?:action|step|fix|patch|update)\s*:\s*(.+?)(?:\.|$)",
            r"(?:immediately|urgent|critical)\s+(.+?)(?:\.|$)",
        ]
        recs: list[str] = []
        for p in patterns:
            recs.extend(re.findall(p, content, re.IGNORECASE | re.MULTILINE))
        return recs[:10]

    @staticmethod
    def _extract_cves(content: str) -> List[str]:
        return list(set(re.findall(r"CVE-\d{4}-\d{4,}", content)))
