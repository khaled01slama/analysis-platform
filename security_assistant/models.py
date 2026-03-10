"""
Data models and state definitions for the security assistant.
"""

from datetime import datetime
from dataclasses import dataclass, asdict
from typing import Dict, List, Any, TypedDict


@dataclass
class SecurityReport:
    """Immutable representation of a security analysis report."""

    id: str
    title: str
    content: str
    report_type: str
    target: str
    timestamp: datetime
    severity: str
    recommendations: List[str]
    tags: List[str]
    related_cves: List[str]
    remediation_status: str = "pending"

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["timestamp"] = self.timestamp.isoformat()
        return data

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "SecurityReport":
        data["timestamp"] = (
            datetime.fromisoformat(data["timestamp"])
            if isinstance(data.get("timestamp"), str)
            else datetime.now()
        )
        return cls(**data)


class AgentState(TypedDict):
    """State definition for the LangGraph security agent workflow."""

    messages: List[Any]
    current_task: str
    target: str
    findings: List[Dict[str, Any]]
    reports: List[SecurityReport]
    search_results: List[Dict[str, Any]]
    recommendations: List[str]
    next_action: str
    context: Dict[str, Any]
    tools_used: List[str]
    confidence_score: float
