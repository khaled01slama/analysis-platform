#!/usr/bin/env python3
"""
Configuration for LangGraph Security Agent
"""

import os
from typing import Dict, List, Optional
from pydantic import Field
from pydantic_settings import BaseSettings
from pathlib import Path

class DatabaseConfig(BaseSettings):
    """Database configuration"""
    path: str = Field(default="correlation_analysis.db", env="DB_PATH")
    state_db_path: str = Field(default="correlation_analysis.db", env="STATE_DB_PATH")
    backup_interval: int = Field(default=24, env="BACKUP_INTERVAL_HOURS")

class WebSearchConfig(BaseSettings):
    """Web search configuration"""
    cache_ttl: int = Field(default=3600, env="SEARCH_CACHE_TTL")  # 1 hour
    max_results: int = Field(default=20, env="SEARCH_MAX_RESULTS")
    timeout: int = Field(default=10, env="SEARCH_TIMEOUT")
    virustotal_api_key: Optional[str] = Field(default=None, env="VIRUSTOTAL_API_KEY")
    github_token: Optional[str] = Field(default=None, env="GITHUB_TOKEN")

class LLMConfig(BaseSettings):
    """LLM configuration – Groq is the primary provider."""
    provider: str = Field(default="groq", env="LLM_PROVIDER")
    groq_api_key: Optional[str] = Field(default=None, env="GROQ_API_KEY")
    groq_model: str = Field(default="moonshotai/kimi-k2-instruct-0905", env="GROQ_MODEL")
    temperature: float = Field(default=0.1, env="LLM_TEMPERATURE")
    max_tokens: int = Field(default=4096, env="LLM_MAX_TOKENS")
    timeout: int = Field(default=120, env="LLM_TIMEOUT")

class SecurityConfig(BaseSettings):
    """Security configuration"""
    allowed_targets: List[str] = Field(default_factory=lambda: ["localhost", "127.0.0.1", "*.internal"])
    blocked_targets: List[str] = Field(default_factory=lambda: ["*.gov", "*.mil"])
    max_scan_threads: int = Field(default=5, env="MAX_SCAN_THREADS")
    safe_mode: bool = Field(default=True, env="SAFE_MODE")

class AgentConfig(BaseSettings):
    """Main agent configuration"""
    workspace_path: str = Field(default="./agent_workspace", env="WORKSPACE_PATH")
    log_level: str = Field(default="INFO", env="LOG_LEVEL")
    debug: bool = Field(default=False, env="DEBUG")
    
    # Component configurations
    database: DatabaseConfig = Field(default_factory=DatabaseConfig)
    web_search: WebSearchConfig = Field(default_factory=WebSearchConfig)
    llm: LLMConfig = Field(default_factory=LLMConfig)
    security: SecurityConfig = Field(default_factory=SecurityConfig)
    default_workflow_timeout: int = Field(default=300, env="WORKFLOW_TIMEOUT")  
    enable_parallel_execution: bool = Field(default=True, env="ENABLE_PARALLEL")
    
    class Config:
        env_nested_delimiter = "__"

config = AgentConfig()

def get_config() -> AgentConfig:
    """Get the global configuration"""
    return config

def update_config(**kwargs) -> None:
    """Update configuration values"""
    global config
    for key, value in kwargs.items():
        if hasattr(config, key):
            setattr(config, key, value)

def get_development_config() -> AgentConfig:
    """Get development configuration"""
    dev_config = AgentConfig()
    dev_config.debug = True
    dev_config.log_level = "DEBUG"
    dev_config.llm.temperature = 0.2
    dev_config.llm.provider = "groq"
    dev_config.security.safe_mode = True
    return dev_config

def get_production_config() -> AgentConfig:
    """Get production configuration"""
    prod_config = AgentConfig()
    prod_config.debug = False
    prod_config.log_level = "INFO"
    prod_config.llm.temperature = 0.1
    prod_config.security.safe_mode = True
    prod_config.database.backup_interval = 6  
    return prod_config

# Configuration validation
def validate_config(config: AgentConfig) -> List[str]:
    """Validate configuration and return any errors"""
    errors = []
    
    # Check workspace path
    workspace = Path(config.workspace_path)
    if not workspace.exists():
        try:
            workspace.mkdir(parents=True, exist_ok=True)
        except Exception as e:
            errors.append(f"Cannot create workspace directory: {e}")
    
    # Check database paths
    db_path = Path(config.database.path).parent
    if not db_path.exists():
        try:
            db_path.mkdir(parents=True, exist_ok=True)
        except Exception as e:
            errors.append(f"Cannot create database directory: {e}")
    
    # Validate LLM configuration
    if config.llm.temperature < 0 or config.llm.temperature > 1:
        errors.append("LLM temperature must be between 0 and 1")
    
    if config.llm.max_tokens < 100:
        errors.append("LLM max_tokens must be at least 100")
    
    # Validate security configuration
    if config.security.max_scan_threads < 1 or config.security.max_scan_threads > 50:
        errors.append("max_scan_threads must be between 1 and 50")
    
    return errors

# Logging configuration
def setup_logging(config: AgentConfig):
    """Setup logging configuration"""
    import logging
    import structlog
    
    # Configure standard logging
    logging.basicConfig(
        level=getattr(logging, config.log_level.upper()),
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Configure structured logging
    structlog.configure(
        processors=[
            structlog.stdlib.filter_by_level,
            structlog.stdlib.add_logger_name,
            structlog.stdlib.add_log_level,
            structlog.stdlib.PositionalArgumentsFormatter(),
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            structlog.processors.UnicodeDecoder(),
            structlog.processors.JSONRenderer()
        ],
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )



if __name__ == "__main__":
    # Validate current configuration
    errors = validate_config(config)
    if errors:
        print("Configuration errors:")
        for error in errors:
            print(f"  - {error}")
    else:
        print("Configuration is valid")
    

    
    # Setup logging
    setup_logging(config)
    
    print(f"Agent configured with provider={config.llm.provider}, groq_model={config.llm.groq_model}")
    print(f"Workspace: {config.workspace_path}")
    print(f"Debug mode: {config.debug}")
