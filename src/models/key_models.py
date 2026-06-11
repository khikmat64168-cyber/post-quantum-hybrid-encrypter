"""
Immutable key data models.

Pure data containers — no crypto operations, no I/O, no CLI code.
Sensitive fields override __repr__ so key material never leaks into logs.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass, field
from datetime import datetime, timezone


@dataclass(frozen=True)
class KeyMetadata:
    """Common metadata attached to every key object."""

    key_id: str
    algorithm: str
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> dict[str, str]:
        return {
            "key_id": self.key_id,
            "algorithm": self.algorithm,
            "created_at": self.created_at.isoformat(),
        }

    @classmethod
    def from_dict(cls, data: dict[str, str]) -> "KeyMetadata":
        return cls(
            key_id=data["key_id"],
            algorithm=data["algorithm"],
            created_at=datetime.fromisoformat(data["created_at"]),
        )


@dataclass(frozen=True)
class X25519PublicKeyModel:
    """Immutable container for an X25519 public key (32 raw bytes)."""

    raw_bytes: bytes
    metadata: KeyMetadata

    def __repr__(self) -> str:
        return f"X25519PublicKeyModel(key_id={self.metadata.key_id!r}, bytes=<32 bytes>)"

    def to_dict(self) -> dict[str, str]:
        return {
            "key_type": "public",
            "key_id": self.metadata.key_id,
            "algorithm": self.metadata.algorithm,
            "created_at": self.metadata.created_at.isoformat(),
            "raw_bytes_b64": base64.b64encode(self.raw_bytes).decode(),
        }

    @classmethod
    def from_dict(cls, data: dict[str, str]) -> "X25519PublicKeyModel":
        return cls(
            raw_bytes=base64.b64decode(data["raw_bytes_b64"]),
            metadata=KeyMetadata(
                key_id=data["key_id"],
                algorithm=data["algorithm"],
                created_at=datetime.fromisoformat(data["created_at"]),
            ),
        )


@dataclass(frozen=True)
class X25519PrivateKeyModel:
    """
    Immutable container for an X25519 private key (32 raw bytes).

    SECURITY: raw_bytes is intentionally hidden from __repr__ and __str__.
    Never pass this object to logging calls or exception messages.
    """

    raw_bytes: bytes
    metadata: KeyMetadata

    def __repr__(self) -> str:
        return f"X25519PrivateKeyModel(key_id={self.metadata.key_id!r}, bytes=<REDACTED>)"

    def __str__(self) -> str:
        return self.__repr__()

    def to_dict(self) -> dict[str, str]:
        return {
            "key_type": "private",
            "key_id": self.metadata.key_id,
            "algorithm": self.metadata.algorithm,
            "created_at": self.metadata.created_at.isoformat(),
            "raw_bytes_b64": base64.b64encode(self.raw_bytes).decode(),
        }

    @classmethod
    def from_dict(cls, data: dict[str, str]) -> "X25519PrivateKeyModel":
        return cls(
            raw_bytes=base64.b64decode(data["raw_bytes_b64"]),
            metadata=KeyMetadata(
                key_id=data["key_id"],
                algorithm=data["algorithm"],
                created_at=datetime.fromisoformat(data["created_at"]),
            ),
        )


@dataclass(frozen=True)
class SharedSecretModel:
    """
    Immutable container for a raw ECDH shared secret (32 bytes).

    This object must NEVER be persisted to disk or written to logs.
    Pass it directly to the HKDF layer and discard immediately after.

    Note: `bytes` is immutable in CPython, so in-memory wiping is not
    possible here. For higher-assurance environments, convert to a
    mutable `bytearray` and use `src.utils.secure_bytes.wipe()` before
    dropping the reference.
    """

    raw_bytes: bytes
    algorithm: str = "X25519-ECDH"

    def __repr__(self) -> str:
        return f"SharedSecretModel(algorithm={self.algorithm!r}, bytes=<REDACTED>)"

    def __str__(self) -> str:
        return self.__repr__()

    def __len__(self) -> int:
        return len(self.raw_bytes)
