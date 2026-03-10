"""
LangGraph-based security agent – graph construction, nodes, and public ``run()`` API.
"""

import os
import re
import json
import logging
from typing import Dict, Any

from langchain_core.messages import SystemMessage, HumanMessage
from langgraph.graph import StateGraph, END

from security_assistant.models import AgentState
from security_assistant.llm import create_llm, _LLM_PROVIDER
from security_assistant.memory import PersistentMemory
from security_assistant.tools import SecurityAgentTools
from security_assistant import prompts

logger = logging.getLogger("security_assistant.agent")

# ── Keyword banks for task classification ───────────────────────────────
_GREETINGS = {
    "hello", "hi", "hey", "good morning", "good afternoon", "good evening",
    "how are you", "what's up", "greetings", "howdy", "salut", "bonjour",
    "hola", "ciao", "guten tag", "konnichiwa", "namaste", "shalom",
}
_COURTESY = {
    "thanks", "thank you", "bye", "goodbye", "see you", "farewell",
    "au revoir", "adios", "auf wiedersehen", "arrivederci", "sayonara",
    "good bye", "take care", "catch you later", "until next time",
}
_HELP = {"help", "what can you do", "commands", "capabilities", "features"}
_INFO = {
    "what is", "what are", "explain", "define", "how does", "how do",
    "tell me about", "describe", "difference between",
    "what do you know about", "can you explain", "i want to know",
    "information about", "details about",
}
_VULN_ASSESSMENT = {
    "assess vulnerabilities", "vulnerability assessment",
    "security assessment", "scan for vulnerabilities",
    "check for security issues", "analyze security",
}
_AUDIT = {"security audit", "conduct audit", "audit security", "security review"}
_INCIDENT = {
    "incident response", "security incident", "breach response",
    "handle incident",
}
_QUESTION_HINTS = {"?", "how", "why", "when", "where", "which", "what", "tell me", "explain"}


class LangGraphSecurityAgent:
    """AI Security Assistant powered by LangGraph + Groq (or Ollama)."""

    # ── Construction ────────────────────────────────────────────────────
    def __init__(self, web_search_enabled: bool = True, db_path: str = None):
        if db_path is None:
            root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            data_dir = os.path.join(root, "data")
            os.makedirs(data_dir, exist_ok=True)
            db_path = os.path.join(data_dir, "correlation_analysis.db")

        self.memory = PersistentMemory(db_path)
        self.web_search_enabled = web_search_enabled

        # Web search
        try:
            if web_search_enabled:
                try:
                    from security_assistant.web_search import VulnerabilitySearchEngine
                except ImportError:
                    from web_search import VulnerabilitySearchEngine
                self.web_search = VulnerabilitySearchEngine()
            else:
                self.web_search = None
        except ImportError:
            logger.warning("Web search not available")
            self.web_search = None
            self.web_search_enabled = False

        self.tools = SecurityAgentTools(self.memory, self.web_search)
        self.llm = create_llm(temperature=0.1)
        logger.info("LLM ready (provider=%s)", _LLM_PROVIDER)

        self.checkpointer = None
        self.graph = self._build_graph()

    # ── Graph construction ──────────────────────────────────────────────
    def _build_graph(self) -> StateGraph:
        g = StateGraph(AgentState)

        g.add_node("analyze_task", self._analyze_task)
        g.add_node("search_information", self._search_information)
        g.add_node("analyze_reports", self._analyze_reports)
        g.add_node("create_recommendations", self._create_recommendations)
        g.add_node("generate_report", self._generate_report)

        def _route(state: AgentState) -> str:
            if state["current_task"] in (
                "greeting", "courtesy", "help_request", "informational_query",
            ):
                return "generate_report"
            return "search_information"

        g.add_conditional_edges(
            "analyze_task", _route,
            {"search_information": "search_information", "generate_report": "generate_report"},
        )
        g.add_edge("search_information", "analyze_reports")
        g.add_edge("analyze_reports", "create_recommendations")
        g.add_edge("create_recommendations", "generate_report")
        g.add_edge("generate_report", END)
        g.set_entry_point("analyze_task")

        return g.compile(checkpointer=self.checkpointer)

    # ── Node: classify the user message ─────────────────────────────────
    def _analyze_task(self, state: AgentState) -> AgentState:
        msgs = state["messages"]
        if not msgs:
            return state

        content = msgs[-1].content if hasattr(msgs[-1], "content") else str(msgs[-1])
        low = content.lower().strip()

        if any(p in low for p in _GREETINGS):
            task = "greeting"
        elif any(p in low for p in _COURTESY):
            task = "courtesy"
        elif any(p in low for p in _HELP):
            task = "help_request"
        elif any(p in low for p in _INFO):
            task = "informational_query"
        elif any(p in low for p in _VULN_ASSESSMENT):
            task = "vulnerability_assessment"
        elif any(p in low for p in _AUDIT):
            task = "security_audit"
        elif any(p in low for p in _INCIDENT):
            task = "incident_response"
        elif any(p in low for p in _QUESTION_HINTS):
            task = "informational_query"
        else:
            task = "general_analysis"

        state["current_task"] = task
        state["target"] = self._extract_target(content)
        state["confidence_score"] = 0.7
        logger.info("Task: %s  Target: %s", task, state["target"])
        return state

    # ── Node: web search ────────────────────────────────────────────────
    def _search_information(self, state: AgentState) -> AgentState:
        if not self.web_search_enabled:
            state["search_results"] = []
            state["tools_used"].append("search_disabled")
            return state
        try:
            q = f"{state['current_task']} {state['target']}"
            state["search_results"] = self.web_search.search_vulnerabilities(q)
            state["tools_used"].append("search_vulnerabilities")
        except Exception as exc:
            logger.error("Search failed: %s", exc)
            state["search_results"] = []
        return state

    # ── Node: historical report analysis ────────────────────────────────
    def _analyze_reports(self, state: AgentState) -> AgentState:
        try:
            reports = self.memory.get_reports(target=state["target"], days_back=30)
            state["reports"] = reports
            state["context"]["report_analysis"] = self.tools.analyze_previous_reports(state["target"])

            findings: list[str] = []
            if self.web_search_enabled and state["search_results"]:
                findings.append("**Current Threat Landscape:**")
                for r in state["search_results"][:5]:
                    findings.append(f"- {r['title']}: {r['snippet'][:100]}...")
            elif not self.web_search_enabled:
                findings.append("**Note:** Web search disabled – using historical data only")
            if "report_analysis" in state["context"]:
                findings.append("\n**Historical Analysis:**")
                findings.append(state["context"]["report_analysis"])

            state["findings"] = [{"type": "analysis", "content": "\n".join(findings)}]
        except Exception as exc:
            logger.error("Report analysis failed: %s", exc)
            state["reports"] = []
            state["findings"] = [{"type": "error", "content": str(exc)}]
        return state

    # ── Node: recommendations ───────────────────────────────────────────
    def _create_recommendations(self, state: AgentState) -> AgentState:
        try:
            recs = self.tools.generate_action_recommendations(json.dumps(state["findings"]))
            state["recommendations"] = recs.split("\n")
        except Exception as exc:
            logger.error("Recommendation gen failed: %s", exc)
            state["recommendations"] = ["Unable to generate recommendations"]
        return state

    # ── Node: final response generation ─────────────────────────────────
    def _generate_report(self, state: AgentState) -> AgentState:
        try:
            task = state["current_task"]
            if task == "greeting":
                content = self._simple_llm(prompts.GREETING, state)
            elif task == "courtesy":
                content = self._simple_llm(prompts.COURTESY, state)
            elif task == "help_request":
                content = self._simple_llm(
                    prompts.HELP,
                    state,
                    user_override="What can you help me with? What are your capabilities?",
                )
            elif task == "informational_query":
                content = self._informational(state)
            else:
                content = self._analysis_response(state)

            state["context"]["report_content"] = content
        except Exception as exc:
            logger.error("Report generation failed: %s", exc)
            state["context"]["report_content"] = (
                "I'm experiencing a technical issue right now. Please try again."
            )
        return state

    # ── LLM helper: one-shot prompt ─────────────────────────────────────
    def _simple_llm(self, system: str, state: AgentState, user_override: str = None) -> str:
        user = user_override or (
            state["messages"][-1].content
            if state["messages"] and hasattr(state["messages"][-1], "content")
            else ""
        )
        try:
            resp = self.llm.invoke([SystemMessage(content=system), HumanMessage(content=user)])
            return resp.content if hasattr(resp, "content") else str(resp)
        except Exception as exc:
            logger.error("LLM call failed: %s", exc)
            return "I'm experiencing a technical issue right now. Please try again."

    # ── Informational queries (with optional web search) ────────────────
    def _informational(self, state: AgentState) -> str:
        user_query = (
            state["messages"][-1].content
            if state.get("messages") and hasattr(state["messages"][-1], "content")
            else "Hello"
        )

        is_security = ("CVE-" in user_query.upper()) or any(
            kw in user_query.lower() for kw in ("vulnerability", "exploit", "security", "cve")
        )

        if is_security and self.web_search_enabled:
            results = self.web_search.search_vulnerabilities(user_query)
            if results:
                ctx = ["Based on current security intelligence:"]
                for r in results[:5]:
                    ctx.append(f"- [{r.get('source','').upper()}] {r.get('title','')}")
                    ctx.append(f"  {r.get('snippet','')}")
                    if r.get("url"):
                        ctx.append(f"  Source: {r['url']}")
                search_info = "\n".join(ctx)
                return self._simple_llm(
                    prompts.INFORMATIONAL_WITH_RESULTS,
                    state,
                    user_override=(
                        f"User query: {user_query}\n\n"
                        f"Search results:\n{search_info}\n\n"
                        "Please provide a comprehensive response based on this information."
                    ),
                )
            return self._simple_llm(
                prompts.INFORMATIONAL_NO_RESULTS,
                state,
                user_override=(
                    f"User query: {user_query}\n\n"
                    "No relevant results were found. Provide a helpful response."
                ),
            )

        if is_security and not self.web_search_enabled:
            return (
                "Web search is currently disabled. I can only provide general "
                "guidance without access to current vulnerability databases. "
                "To get accurate CVE information, enable web search or check "
                "official sources like MITRE CVE or NVD directly."
            )

        return self._simple_llm(prompts.GENERAL_INFORMATIONAL, state)

    # ── Full analysis response ──────────────────────────────────────────
    def _analysis_response(self, state: AgentState) -> str:
        if not state["findings"] and not state["search_results"] and not state["recommendations"]:
            return self._informational(state)

        user_query = (
            state["messages"][-1].content if state.get("messages") else ""
        )

        # Report-generation request → delegate to DB tool
        if any(kw in user_query.lower() for kw in (
            "report", "generate report", "security report", "full report",
            "analysis report", "show report", "previous report",
        )):
            content = self.tools.query_analysis_database(user_query)
            self._maybe_persist_report(state, content)
            return content

        cve_match = re.search(r"CVE-\d{4}-\d{4,}", user_query.upper())
        if cve_match:
            return self._cve_response(state, cve_match.group(0))

        # Generic analysis answer
        ctx = self._build_context_text(state)
        content = self._simple_llm(
            prompts.INFORMAL_ANSWER,
            state,
            user_override=f"User query: {user_query}\n\nContext:\n{ctx}",
        )
        self._maybe_persist_report(state, content)
        return content

    def _cve_response(self, state: AgentState, cve_id: str) -> str:
        ctx_parts = [f"CVE Query: {cve_id}"]
        user_query = state["messages"][-1].content if state.get("messages") else ""
        low = user_query.lower()
        if any(kw in low for kw in ("finding", "findings", "recommendation", "recommendations", "next step")):
            for f in state.get("findings", []):
                if cve_id in f.get("content", ""):
                    ctx_parts.append(f"- {f['content'][:200]}...")
            for r in state.get("recommendations", []):
                if cve_id in r:
                    ctx_parts.append(f"- {r}")
            for s in state.get("search_results", []):
                if cve_id in str(s):
                    ctx_parts.append(f"- {s}")

        return self._simple_llm(
            prompts.CVE_CHAT,
            state,
            user_override=(
                f"Please provide a direct, actionable answer about {cve_id} "
                f"based on this context:\n\n" + "\n".join(ctx_parts)
            ),
        )

    # ── Helpers ─────────────────────────────────────────────────────────
    def _build_context_text(self, state: AgentState) -> str:
        parts = [f"Target: {state['target']}", f"Task Type: {state['current_task']}"]
        if state["findings"]:
            parts.append("Findings:")
            for f in state["findings"]:
                parts.append(f"- {f['content'][:200]}...")
        if state["recommendations"]:
            parts.append("Recommendations available")
        if state["search_results"]:
            parts.append(f"Search Results: {len(state['search_results'])} sources")
        return "\n".join(parts)

    def _maybe_persist_report(self, state: AgentState, content: str):
        user_query = state["messages"][-1].content if state.get("messages") else ""
        if any(kw in user_query.lower() for kw in ("report", "generate report", "security report", "full report")):
            rid = self.tools.create_security_report(
                title=f"Security Analysis - {state['target']}",
                content=content,
                target=state["target"],
                severity="MEDIUM",
                report_type=state["current_task"],
            )
            state["context"]["report_id"] = rid

    @staticmethod
    def _extract_target(content: str) -> str:
        for pattern in (
            r"\b(?:\d{1,3}\.){3}\d{1,3}\b",          # IP
            r"\b[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b",     # domain
            r"CVE-\d{4}-\d{4,}",                       # CVE
        ):
            m = re.search(pattern, content)
            if m:
                return m.group()
        return "general"

    # ── Public entry-point ──────────────────────────────────────────────
    def run(self, message: str, session_id: str = "default", context: Dict[str, Any] = None) -> str:
        try:
            initial: AgentState = {
                "messages": [HumanMessage(content=message)],
                "current_task": "",
                "target": "",
                "findings": [],
                "reports": [],
                "search_results": [],
                "recommendations": [],
                "next_action": "",
                "context": context or {},
                "tools_used": [],
                "confidence_score": 0.0,
            }

            if context:
                enhanced = self._enrich_message(message, context)
                if enhanced:
                    initial["messages"] = [HumanMessage(content=enhanced)]

            final = self.graph.invoke(initial, {"configurable": {"thread_id": session_id}})
            return final["context"].get("report_content", "Analysis completed, but report generation failed.")
        except Exception as exc:
            logger.error("Agent execution failed: %s", exc)
            return "I'm experiencing a technical issue right now. Please try again."

    @staticmethod
    def _enrich_message(message: str, context: Dict[str, Any]) -> str | None:
        parts: list[str] = []
        if context.get("analysis_type"):
            parts.append(f"Previous analysis type: {context['analysis_type']}")
        if context.get("vulnerabilities"):
            vs = context["vulnerabilities"]
            parts.append(f"Found {len(vs)} vulnerabilities in previous analysis")
            for v in vs[:3]:
                if isinstance(v, dict):
                    vid = v.get("id", v.get("cve_id", "Unknown"))
                    parts.append(f"- {vid} ({v.get('severity', 'Unknown')})")
        if context.get("correlations"):
            parts.append(f"Found {len(context['correlations'])} correlations")
        if context.get("sbom_data"):
            parts.append("SBOM data available from previous analysis")
        meta = context.get("metadata", {})
        if meta.get("repository_path"):
            parts.append(f"Repository analyzed: {meta['repository_path']}")
        if not parts:
            return None
        return (
            f"Previous Analysis Context:\n"
            + "\n".join(parts)
            + f"\n\nCurrent User Query: {message}\n\n"
            "Please provide a response that considers both the previous "
            "analysis results and the current query."
        )
