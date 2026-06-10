"""Unit tests for config model dataclasses."""

import pytest
from src.models.config_models import AppConfig, CryptoConfig, LoggingConfig, StorageConfig


@pytest.mark.unit
class TestCryptoConfig:
    def test_defaults(self) -> None:
        cfg = CryptoConfig()
        assert cfg.kem_algorithm == "Kyber768"
        assert cfg.hkdf_length == 32
        assert cfg.aes_key_size == 32
        assert cfg.aes_tag_length == 16
        assert cfg.iv_size == 12

    def test_immutable(self) -> None:
        cfg = CryptoConfig()
        with pytest.raises(Exception):
            cfg.kem_algorithm = "invalid"  # type: ignore[misc]


@pytest.mark.unit
class TestAppConfig:
    def test_defaults(self) -> None:
        cfg = AppConfig()
        assert cfg.env == "development"
        assert cfg.debug is False
        assert cfg.wipe_secrets_on_exit is True
        assert isinstance(cfg.crypto, CryptoConfig)
        assert isinstance(cfg.storage, StorageConfig)
        assert isinstance(cfg.logging, LoggingConfig)

    def test_is_production_false_by_default(self) -> None:
        cfg = AppConfig()
        assert cfg.is_production() is False

    def test_is_production_true(self) -> None:
        cfg = AppConfig(env="production")
        assert cfg.is_production() is True

    def test_is_debug(self) -> None:
        cfg = AppConfig(debug=True)
        assert cfg.is_debug() is True
