"""Unit tests for the logging configuration helper."""

import logging
import pytest
from src.utils.logging_config import configure_logging, get_logger


@pytest.mark.unit
class TestConfigureLogging:
    def test_sets_root_level_info(self) -> None:
        configure_logging(level="INFO", log_format="console")
        assert logging.getLogger().level == logging.INFO

    def test_sets_root_level_debug(self) -> None:
        configure_logging(level="DEBUG", log_format="console")
        assert logging.getLogger().level == logging.DEBUG

    def test_get_logger_returns_logger(self) -> None:
        configure_logging(level="INFO", log_format="console")
        log = get_logger("test.module")
        assert log is not None

    def test_get_logger_has_info_method(self) -> None:
        log = get_logger("test.module")
        assert callable(getattr(log, "info", None))
