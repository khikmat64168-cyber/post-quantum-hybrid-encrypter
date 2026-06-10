"""Root conftest — configures logging for the test session."""

from src.utils.logging_config import configure_logging


def pytest_configure() -> None:
    configure_logging(level="DEBUG", log_format="console")
