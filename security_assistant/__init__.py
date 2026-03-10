"""
security_assistant package – public API re-exports.
"""

from security_assistant.models import SecurityReport, AgentState
from security_assistant.llm import create_llm
from security_assistant.memory import PersistentMemory
from security_assistant.tools import SecurityAgentTools
from security_assistant.agent import LangGraphSecurityAgent

try:
    from security_assistant.vulnerability_correlation_agent import VulnerabilityCorrelationAgent
except Exception:
    VulnerabilityCorrelationAgent = None

__all__ = [
    "SecurityReport",
    "AgentState",
    "create_llm",
    "PersistentMemory",
    "SecurityAgentTools",
    "LangGraphSecurityAgent",
    "VulnerabilityCorrelationAgent",
]
