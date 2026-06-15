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


# ============================================================
# X25519 Models
# ============================================================

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


# ============================================================
# ML-KEM-768 Models
# ============================================================

@dataclass(frozen=True)
class MLKEMPublicKeyModel:
    """
    Immutable container for an ML-KEM-768 public key (1184 raw bytes).

    Distributed to senders who will encapsulate a shared secret for this recipient.
    """

    raw_bytes: bytes
    metadata: KeyMetadata

    def __repr__(self) -> str:
        return (
            f"MLKEMPublicKeyModel(key_id={self.metadata.key_id!r}, "
            f"bytes=<{len(self.raw_bytes)} bytes>)"
        )

    def to_dict(self) -> dict[str, str]:
        return {
            "key_type": "public",
            "key_id": self.metadata.key_id,
            "algorithm": self.metadata.algorithm,
            "created_at": self.metadata.created_at.isoformat(),
            "raw_bytes_b64": base64.b64encode(self.raw_bytes).decode(),
        }

    @classmethod
    def from_dict(cls, data: dict[str, str]) -> "MLKEMPublicKeyModel":
        return cls(
            raw_bytes=base64.b64decode(data["raw_bytes_b64"]),
            metadata=KeyMetadata(
                key_id=data["key_id"],
                algorithm=data["algorithm"],
                created_at=datetime.fromisoformat(data["created_at"]),
            ),
        )


@dataclass(frozen=True)
class MLKEMPrivateKeyModel:
    """
    Immutable container for an ML-KEM-768 secret key (2400 raw bytes).

    SECURITY: raw_bytes is hidden from __repr__ and __str__.
    Store with 0o600 permissions; never log or print.
    """

    raw_bytes: bytes
    metadata: KeyMetadata

    def __repr__(self) -> str:
        return f"MLKEMPrivateKeyModel(key_id={self.metadata.key_id!r}, bytes=<REDACTED>)"

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
    def from_dict(cls, data: dict[str, str]) -> "MLKEMPrivateKeyModel":
        return cls(
            raw_bytes=base64.b64decode(data["raw_bytes_b64"]),
            metadata=KeyMetadata(
                key_id=data["key_id"],
                algorithm=data["algorithm"],
                created_at=datetime.fromisoformat(data["created_at"]),
            ),
        )


@dataclass(frozen=True)
class MLKEMCiphertextModel:
    """
    Immutable container for an ML-KEM-768 ciphertext (1088 raw bytes).

    Produced by the sender during encapsulation.
    Transmitted to the recipient so they can decapsulate to recover the shared secret.
    Safe to store and transmit; does not reveal the shared secret.
    """

    raw_bytes: bytes
    metadata: KeyMetadata

    def __repr__(self) -> str:
        return (
            f"MLKEMCiphertextModel(key_id={self.metadata.key_id!r}, "
            f"bytes=<{len(self.raw_bytes)} bytes>)"
        )

    def to_dict(self) -> dict[str, str]:
        return {
            "key_type": "ciphertext",
            "key_id": self.metadata.key_id,
            "algorithm": self.metadata.algorithm,
            "created_at": self.metadata.created_at.isoformat(),
            "raw_bytes_b64": base64.b64encode(self.raw_bytes).decode(),
        }

    @classmethod
    def from_dict(cls, data: dict[str, str]) -> "MLKEMCiphertextModel":
        return cls(
            raw_bytes=base64.b64decode(data["raw_bytes_b64"]),
            metadata=KeyMetadata(
                key_id=data["key_id"],
                algorithm=data["algorithm"],
                created_at=datetime.fromisoformat(data["created_at"]),
            ),
        )


# ============================================================
# Shared Secret (algorithm-agnostic)
# ============================================================

@dataclass(frozen=True)
class SharedSecretModel:
    """
    Immutable container for a raw shared secret (32 bytes).

    Used for both X25519-ECDH and ML-KEM-768 outputs.
    Both secrets are then combined and fed into HKDF (Phase 4).

    This object must NEVER be persisted to disk or written to logs.
    Discard immediately after passing to HKDF.

    Note: `bytes` is immutable in CPython, so in-memory wiping is not
    possible here. Use `src.utils.secure_bytes.wipe_bytes_copy()` if
    you need a wipeable copy.
    """

    raw_bytes: bytes
    algorithm: str = "X25519-ECDH"

    def __repr__(self) -> str:
        return f"SharedSecretModel(algorithm={self.algorithm!r}, bytes=<REDACTED>)"

    def __str__(self) -> str:
        return self.__repr__()

    def __len__(self) -> int:
        return len(self.raw_bytes)
