try:
    from correlation_engine.correlation_engine import (
        Vulnerability,
        UnusedFunction,
        VulnerabilityCorrelation,
        VanirParser,
        JoernParser,
        CorrelationEngine,
        ReportGenerator,
        VanirToolRunner,
        JoernToolRunner,
        CorrelationAgent,
        main
    )
except ImportError:
    from .correlation_engine import (
        Vulnerability,
        UnusedFunction,
        VulnerabilityCorrelation,
        VanirParser,
        JoernParser,
        CorrelationEngine,
        ReportGenerator,
        VanirToolRunner,
        JoernToolRunner,
        CorrelationAgent,
        main
    )
