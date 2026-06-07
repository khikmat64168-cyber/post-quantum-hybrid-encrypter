"""
Application-wide configuration loaded from environment variables / .env file.
All fields are validated by Pydantic at startup so misconfiguration fails fast.
"""

from __future__ import annotations

from pathlib import Path
from typing import Literal

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class CryptoSettings(BaseSettings):
    """Cryptographic algorithm parameters."""

    model_config = SettingsConfigDict(env_prefix="PQHE_")

    kem_algorithm: str = Field(default="Kyber768", alias="PQHE_KEM_ALGORITHM")
    hkdf_hash: str = Field(default="SHA256", alias="PQHE_HKDF_HASH")
    hkdf_length: int = Field(default=32, alias="PQHE_HKDF_LENGTH")
    aes_key_size: int = Field(default=32, alias="PQHE_AES_KEY_SIZE")
    aes_tag_length: int = Field(default=16, alias="PQHE_AES_TAG_LENGTH")

    @field_validator("aes_key_size")
    @classmethod
    def validate_aes_key_size(cls, v: int) -> int:
        if v not in (16, 24, 32):
            raise ValueError("AES key size must be 16, 24, or 32 bytes (128/192/256-bit)")
        return v

    @field_validator("hkdf_length")
    @classmethod
    def validate_hkdf_length(cls, v: int) -> int:
        if v < 16 or v > 64:
            raise ValueError("HKDF output length must be between 16 and 64 bytes")
        return v


class StorageSettings(BaseSettings):
    """Key and payload storage paths."""

    model_config = SettingsConfigDict(env_prefix="PQHE_")

    keys_dir: Path = Field(default=Path("./keys"), alias="PQHE_KEYS_DIR")
    key_file_permissions: int = Field(default=0o600, alias="PQHE_KEY_FILE_PERMISSIONS")

    @field_validator("keys_dir", mode="before")
    @classmethod
    def resolve_keys_dir(cls, v: str | Path) -> Path:
        return Path(v).resolve()


class LoggingSettings(BaseSettings):
    """Logging configuration."""

    model_config = SettingsConfigDict(env_prefix="PQHE_")

    log_dir: Path = Field(default=Path("./logs"), alias="PQHE_LOG_DIR")
    log_level: str = Field(default="INFO", alias="PQHE_LOG_LEVEL")
    log_format: Literal["json", "console"] = Field(default="console", alias="PQHE_LOG_FORMAT")
    log_rotation_mb: int = Field(default=10, alias="PQHE_LOG_ROTATION_MB")
    log_retention_days: int = Field(default=30, alias="PQHE_LOG_RETENTION_DAYS")

    @field_validator("log_level")
    @classmethod
    def validate_log_level(cls, v: str) -> str:
        allowed = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
        upper = v.upper()
        if upper not in allowed:
            raise ValueError(f"Log level must be one of {allowed}")
        return upper

    @field_validator("log_dir", mode="before")
    @classmethod
    def resolve_log_dir(cls, v: str | Path) -> Path:
        return Path(v).resolve()


class AppSettings(BaseSettings):
    """Top-level application settings — single source of truth."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        env_prefix="PQHE_",
        case_sensitive=False,
        extra="ignore",
    )

    env: Literal["development", "staging", "production"] = Field(
        default="development", alias="PQHE_ENV"
    )
    debug: bool = Field(default=False, alias="PQHE_DEBUG")
    wipe_secrets_on_exit: bool = Field(default=True, alias="PQHE_WIPE_SECRETS_ON_EXIT")

    # Nested settings groups
    crypto: CryptoSettings = Field(default_factory=CryptoSettings)
    storage: StorageSettings = Field(default_factory=StorageSettings)
    logging: LoggingSettings = Field(default_factory=LoggingSettings)

    def is_production(self) -> bool:
        return self.env == "production"

    def is_debug(self) -> bool:
        return self.debug


# Module-level singleton — import this everywhere.
settings: AppSettings = AppSettings()
