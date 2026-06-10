"""
Application entry point.

Bootstraps logging and configuration, then hands control to the CLI view.
No business logic lives here — this file is intentionally thin.
"""

from __future__ import annotations

import sys

from config.settings import settings
from src.utils.logging_config import configure_logging, get_logger


def _bootstrap() -> None:
    """Initialise logging and validate configuration before any other import."""
    configure_logging(
        level=settings.logging.log_level,
        log_format=settings.logging.log_format,
        log_dir=settings.logging.log_dir,
        rotation_mb=settings.logging.log_rotation_mb,
        retention_days=settings.logging.log_retention_days,
    )


def main() -> None:
    """CLI entry point registered in pyproject.toml [project.scripts]."""
    _bootstrap()
    log = get_logger(__name__)
    log.info(
        "pqhe.startup",
        version="1.0.0",
        env=settings.env,
        kem=settings.crypto.kem_algorithm,
    )

    # Deferred import so logging is configured before any module is loaded.
    from src.views.cli_view import cli  # noqa: PLC0415

    cli(standalone_mode=True)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)
