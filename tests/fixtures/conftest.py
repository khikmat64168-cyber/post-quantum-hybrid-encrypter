"""Shared pytest fixtures available to all test modules."""

from __future__ import annotations

import pytest
from src.models.config_models import AppConfig, CryptoConfig, LoggingConfig, StorageConfig


@pytest.fixture(scope="session")
def default_app_config() -> AppConfig:
    return AppConfig()


@pytest.fixture(scope="session")
def crypto_config() -> CryptoConfig:
    return CryptoConfig()


@pytest.fixture(scope="session")
def storage_config(tmp_path_factory: pytest.TempPathFactory) -> StorageConfig:
    keys_dir = tmp_path_factory.mktemp("keys")
    return StorageConfig(keys_dir=str(keys_dir))
