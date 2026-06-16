import logging
import structlog
import sys
from app.core.config import settings

def setup_logging():
    """Configure structured JSON logging for the application."""
    
    # Map string log level to logging constant
    log_level = getattr(logging, settings.LOG_LEVEL.upper(), logging.INFO)

    # Configure standard logging to pass through to structlog
    logging.basicConfig(
        format="%(message)s",
        stream=sys.stdout,
        level=log_level,
    )

    processors = [
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
    ]

    # Use JSON rendering in production, nice console rendering in dev
    if settings.LOG_FORMAT.lower() == "json" or settings.APP_ENV != "development":
        processors.append(structlog.processors.JSONRenderer())
    else:
        processors.append(structlog.dev.ConsoleRenderer(colors=True))

    structlog.configure(
        processors=processors,
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )

logger = structlog.get_logger("authclaw")
