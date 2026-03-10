"""
LLM provider detection and factory.

Priority: Groq (via GROQ_API_KEY) → Ollama fallback.
"""

import os
import logging

logger = logging.getLogger("security_assistant.llm")

# ── Provider detection ──────────────────────────────────────────────────
try:
    from langchain_groq import ChatGroq as _LLMClass

    _LLM_PROVIDER = "groq"
except ImportError:
    try:
        from langchain_ollama import ChatOllama as _LLMClass

        _LLM_PROVIDER = "ollama"
    except ImportError:
        _LLMClass = None
        _LLM_PROVIDER = None

# Load .env if python-dotenv is available
try:
    from dotenv import load_dotenv

    load_dotenv()
except ImportError:
    pass


def create_llm(temperature: float = 0.1):
    """Return a ready-to-use LangChain chat model.

    Raises ``RuntimeError`` when no provider / API key is available.
    """
    if _LLMClass is None:
        raise RuntimeError(
            "No LLM provider available. Install langchain-groq or langchain-ollama."
        )

    if _LLM_PROVIDER == "groq":
        api_key = os.environ.get("GROQ_API_KEY", "")
        model = os.environ.get("GROQ_MODEL", "llama-3.1-8b-instant")
        if not api_key:
            raise RuntimeError(
                "GROQ_API_KEY is not set. Add it to your .env file or environment."
            )
        logger.info("Creating Groq LLM (%s)", model)
        return _LLMClass(api_key=api_key, model=model, temperature=temperature)

    # Ollama fallback
    model = os.environ.get("OLLAMA_MODEL", "llama3.1:latest")
    base_url = os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434")
    logger.info("Creating Ollama LLM (%s @ %s)", model, base_url)
    return _LLMClass(model=model, base_url=base_url, temperature=temperature)
