"""
Structured logging setup using structlog + stdlib logging.

Call `configure_logging()` once at application startup (in main.py).
Every module obtains its logger via `get_logger(__name__)`.
"""

from __future__ import annotations

import logging
import logging.handlers
import sys
from pathlib import Path
from typing import Any

import structlog
from structlog.types import EventDict, WrappedLogger


# ---------------------------------------------------------------------------
# Custom processors
# ---------------------------------------------------------------------------

def _add_severity(
    logger: WrappedLogger,
    method_name: str,
    event_dict: EventDict,
) -> EventDict:
    """Map structlog level names to uppercase severity strings."""
    event_dict["severity"] = method_name.upper()
    return event_dict


def _drop_color_message_key(
    logger: WrappedLogger,
    method_name: str,
    event_dict: EventDict,
) -> EventDict:
    """Remove uvicorn's 'color_message' key if it leaks through."""
    event_dict.pop("color_message", None)
    return event_dict


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def configure_logging(
    level: str = "INFO",
    log_format: str = "console",
    log_dir: Path | None = None,
    rotation_mb: int = 10,
    retention_days: int = 30,
) -> None:
    """
    Configure structlog and stdlib logging for the application.

    Parameters
    ----------
    level:          Minimum log level (DEBUG / INFO / WARNING / ERROR / CRITICAL).
    log_format:     "console" for human-readable output, "json" for structured JSON.
    log_dir:        If provided, also write logs to a rotating file inside this directory.
    rotation_mb:    Maximum log-file size before rotation (MB).
    retention_days: Number of backup log files to keep.
    """
    numeric_level = getattr(logging, level.upper(), logging.INFO)

    shared_processors: list[Any] = [
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        _add_severity,
        _drop_color_message_key,
        structlog.stdlib.ExtraAdder(),
        structlog.processors.TimeStamper(fmt="iso", utc=True),
        structlog.processors.StackInfoRenderer(),
    ]

    if log_format == "json":
        renderer: Any = structlog.processors.JSONRenderer()
    else:
        renderer = structlog.dev.ConsoleRenderer(colors=sys.stderr.isatty())

    structlog.configure(
        processors=shared_processors
        + [
            structlog.stdlib.ProcessorFormatter.wrap_for_formatter,
        ],
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )

    formatter = structlog.stdlib.ProcessorFormatter(
        foreign_pre_chain=shared_processors,
        processors=[
            structlog.stdlib.ProcessorFormatter.remove_processors_meta,
            renderer,
        ],
    )

    # --- stderr handler (always present) ---
    stderr_handler = logging.StreamHandler(sys.stderr)
    stderr_handler.setFormatter(formatter)
    stderr_handler.setLevel(numeric_level)

    handlers: list[logging.Handler] = [stderr_handler]

    # --- rotating file handler (optional) ---
    if log_dir is not None:
        log_dir.mkdir(parents=True, exist_ok=True)
        log_file = log_dir / "pqhe.log"
        file_handler = logging.handlers.RotatingFileHandler(
            filename=log_file,
            maxBytes=rotation_mb * 1024 * 1024,
            backupCount=retention_days,
            encoding="utf-8",
        )
        file_handler.setFormatter(formatter)
        file_handler.setLevel(numeric_level)
        handlers.append(file_handler)

    root_logger = logging.getLogger()
    root_logger.setLevel(numeric_level)
    root_logger.handlers.clear()
    for handler in handlers:
        root_logger.addHandler(handler)

    # Silence noisy third-party loggers
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)


def get_logger(name: str) -> structlog.stdlib.BoundLogger:
    """Return a named structlog logger."""
    return structlog.get_logger(name)
