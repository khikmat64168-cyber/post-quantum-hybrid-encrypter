"""
Immutable dataclass models that carry configuration state through the system.
These are pure data containers — no business logic, no I/O, no CLI code.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal


@dataclass(frozen=True)
class CryptoConfig:
    """Parameters governing every cryptographic operation."""

    kem_algorithm: str = "Kyber768"
    hkdf_hash: Literal["SHA256", "SHA384", "SHA512"] = "SHA256"
    hkdf_length: int = 32
    aes_key_size: int = 32
    aes_tag_length: int = 16
    iv_size: int = 12


@dataclass(frozen=True)
class StorageConfig:
    """Filesystem paths used for key and payload persistence."""

    keys_dir: str = "./keys"
    key_file_permissions: int = 0o600


@dataclass(frozen=True)
class LoggingConfig:
    """Logging behaviour settings passed to the logging subsystem."""

    level: str = "INFO"
    log_format: Literal["json", "console"] = "console"
    log_dir: str = "./logs"
    rotation_mb: int = 10
    retention_days: int = 30


@dataclass(frozen=True)
class AppConfig:
    """
    Aggregated application configuration.
    Built once from `config.settings.AppSettings` and passed down
    through controllers so they never import global settings directly.
    """

    env: Literal["development", "staging", "production"] = "development"
    debug: bool = False
    wipe_secrets_on_exit: bool = True
    crypto: CryptoConfig = field(default_factory=CryptoConfig)
    storage: StorageConfig = field(default_factory=StorageConfig)
    logging: LoggingConfig = field(default_factory=LoggingConfig)

    def is_production(self) -> bool:
        return self.env == "production"

    def is_debug(self) -> bool:
        return self.debug

    @classmethod
    def from_settings(cls, s: object) -> "AppConfig":
        """
        Construct an AppConfig from the Pydantic AppSettings singleton.
        Decouples the model layer from the pydantic-settings dependency.
        """
        from config.settings import AppSettings  # local import to avoid circular deps

        assert isinstance(s, AppSettings)
        return cls(
            env=s.env,
            debug=s.debug,
            wipe_secrets_on_exit=s.wipe_secrets_on_exit,
            crypto=CryptoConfig(
                kem_algorithm=s.crypto.kem_algorithm,
                hkdf_hash=s.crypto.hkdf_hash,  # type: ignore[arg-type]
                hkdf_length=s.crypto.hkdf_length,
                aes_key_size=s.crypto.aes_key_size,
                aes_tag_length=s.crypto.aes_tag_length,
            ),
            storage=StorageConfig(
                keys_dir=str(s.storage.keys_dir),
                key_file_permissions=s.storage.key_file_permissions,
            ),
            logging=LoggingConfig(
                level=s.logging.log_level,
                log_format=s.logging.log_format,
                log_dir=str(s.logging.log_dir),
                rotation_mb=s.logging.log_rotation_mb,
                retention_days=s.logging.log_retention_days,
            ),
        )
