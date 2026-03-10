"""
Persistent memory layer – SQLite-backed storage for reports, insights
and search-result caches.
"""

import json
import sqlite3
import logging
from datetime import datetime
from typing import Dict, List, Optional

from security_assistant.models import SecurityReport

logger = logging.getLogger("security_assistant.memory")


class PersistentMemory:
    """Lightweight SQLite store used by the security agent."""

    def __init__(self, db_path: str):
        self.db_path = db_path
        self._init_tables()

    # ── Schema ──────────────────────────────────────────────────────────
    def _init_tables(self):
        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()

        cur.execute("""
            CREATE TABLE IF NOT EXISTS reports (
                id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                content TEXT NOT NULL,
                report_type TEXT NOT NULL,
                target TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                severity TEXT NOT NULL,
                recommendations TEXT NOT NULL,
                tags TEXT NOT NULL,
                related_cves TEXT NOT NULL,
                remediation_status TEXT DEFAULT 'pending'
            )
        """)

        cur.execute("""
            CREATE TABLE IF NOT EXISTS insights (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                content TEXT NOT NULL,
                category TEXT NOT NULL,
                confidence REAL NOT NULL,
                timestamp TEXT NOT NULL,
                related_reports TEXT
            )
        """)

        cur.execute("""
            CREATE TABLE IF NOT EXISTS search_cache (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                query_hash TEXT UNIQUE NOT NULL,
                query TEXT NOT NULL,
                results TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                timestamp TEXT NOT NULL
            )
        """)

        conn.commit()
        conn.close()

    # ── Reports ─────────────────────────────────────────────────────────
    def get_reports(
        self,
        target: Optional[str] = None,
        report_type: Optional[str] = None,
        days_back: int = 30,
    ) -> List[SecurityReport]:
        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()

        query = (
            "SELECT * FROM reports "
            "WHERE timestamp > datetime('now', '-{} days')".format(days_back)
        )
        params: list = []

        if target:
            query += " AND target = ?"
            params.append(target)
        if report_type:
            query += " AND report_type = ?"
            params.append(report_type)

        query += " ORDER BY timestamp DESC"
        cur.execute(query, params)
        rows = cur.fetchall()
        conn.close()

        reports: List[SecurityReport] = []
        for row in rows:
            data = {
                "id": row[0],
                "title": row[1],
                "content": row[2],
                "report_type": row[3],
                "target": row[4],
                "timestamp": (
                    datetime.fromisoformat(row[5])
                    if row[5] and isinstance(row[5], str)
                    else datetime.now()
                ),
                "severity": row[6],
                "recommendations": json.loads(row[7]) if row[7] else [],
                "tags": json.loads(row[8]) if row[8] else [],
                "related_cves": json.loads(row[9]) if row[9] else [],
                "remediation_status": row[10],
            }
            reports.append(SecurityReport.from_dict(data))
        return reports

    def save_report(self, report: SecurityReport) -> None:
        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()
        cur.execute(
            """
            INSERT OR REPLACE INTO reports
            (id, title, content, report_type, target, timestamp, severity,
             recommendations, tags, related_cves, remediation_status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                report.id,
                report.title,
                report.content,
                report.report_type,
                report.target,
                report.timestamp.isoformat(),
                report.severity,
                json.dumps(report.recommendations),
                json.dumps(report.tags),
                json.dumps(report.related_cves),
                report.remediation_status,
            ),
        )
        conn.commit()
        conn.close()

    # Alias expected by SecurityAgentTools.create_security_report
    store_report = save_report

    # ── Insights ────────────────────────────────────────────────────────
    def store_insight(
        self,
        content: str,
        category: str,
        confidence: float,
        related_reports: Optional[List[str]] = None,
    ):
        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO insights (content, category, confidence, timestamp, related_reports)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                content,
                category,
                confidence,
                datetime.now().isoformat(),
                json.dumps(related_reports or []),
            ),
        )
        conn.commit()
        conn.close()

    def get_insights(
        self, category: Optional[str] = None, min_confidence: float = 0.7
    ) -> List[Dict]:
        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()

        query = "SELECT * FROM insights WHERE confidence >= ?"
        params: list = [min_confidence]

        if category:
            query += " AND category = ?"
            params.append(category)

        query += " ORDER BY timestamp DESC LIMIT 50"
        cur.execute(query, params)
        rows = cur.fetchall()
        conn.close()

        return [
            {
                "id": row[0],
                "content": row[1],
                "category": row[2],
                "confidence": row[3],
                "timestamp": row[4],
                "related_reports": json.loads(row[5]),
            }
            for row in rows
        ]
