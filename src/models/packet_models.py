"""
Encrypted packet models.

An EncryptedPacket is the complete, self-contained JSON payload produced by
the encryption workflow. It contains everything the recipient needs to decrypt:
  - Sender's ephemeral X25519 public key (for ECDH shared secret)
  - ML-KEM ciphertext (for post-quantum shared secret, if used)
  - HKDF salt (to reproduce the master key)
  - AES-256-GCM IV and ciphertext

Nothing in this model is a secret — the master key is never stored here.
"""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any


CURRENT_VERSION = "1"
ALGORITHM_HYBRID = "X25519+ML-KEM-768+HKDF-SHA256+AES-256-GCM"
ALGORITHM_CLASSICAL = "X25519+HKDF-SHA256+AES-256-GCM"


@dataclass(frozen=True)
class PacketMetadata:
    """Descriptive fields that identify and bind a packet."""

    version: str
    algorithm: str
    created_at: datetime
    sender_key_id: str
    recipient_key_id: str

    def to_dict(self) -> dict[str, str]:
        return {
            "version": self.version,
            "algorithm": self.algorithm,
            "created_at": self.created_at.isoformat(),
            "sender_key_id": self.sender_key_id,
            "recipient_key_id": self.recipient_key_id,
        }

    @classmethod
    def from_dict(cls, data: dict[str, str]) -> "PacketMetadata":
        return cls(
            version=data["version"],
            algorithm=data["algorithm"],
            created_at=datetime.fromisoformat(data["created_at"]),
            sender_key_id=data["sender_key_id"],
            recipient_key_id=data["recipient_key_id"],
        )

    def make_aad(self) -> bytes:
        """
        Produce the AAD string bound to AES-GCM during encryption.

        Including metadata in AAD means any tampering with version,
        algorithm label, or key IDs causes decryption to fail.
        """
        return (
            f"v{self.version}|{self.algorithm}"
            f"|{self.sender_key_id}|{self.recipient_key_id}"
        ).encode()


@dataclass(frozen=True)
class EncryptedPacket:
    """
    Complete, self-contained encrypted packet.

    All binary fields are stored as base64-encoded strings so the packet
    can be serialised to JSON and transmitted or stored as a text file.

    Fields
    ------
    metadata                  : Version, algorithm, timestamps, key identifiers.
    x25519_ephemeral_public_b64: Sender's ephemeral X25519 public key (32 bytes).
    mlkem_ciphertext_b64      : ML-KEM-768 ciphertext (1088 bytes).
                                None when the X25519-only algorithm is used.
    hkdf_salt_b64             : Random HKDF salt (32 bytes).
    iv_b64                    : AES-GCM nonce (12 bytes).
    ciphertext_b64            : AES-GCM output: ciphertext || 16-byte auth tag.
    """

    metadata: PacketMetadata
    x25519_ephemeral_public_b64: str
    hkdf_salt_b64: str
    iv_b64: str
    ciphertext_b64: str
    mlkem_ciphertext_b64: str | None = None

    # ------------------------------------------------------------------
    # Derived byte accessors
    # ------------------------------------------------------------------

    @property
    def x25519_ephemeral_public_bytes(self) -> bytes:
        return base64.b64decode(self.x25519_ephemeral_public_b64)

    @property
    def mlkem_ciphertext_bytes(self) -> bytes | None:
        return base64.b64decode(self.mlkem_ciphertext_b64) if self.mlkem_ciphertext_b64 else None

    @property
    def hkdf_salt_bytes(self) -> bytes:
        return base64.b64decode(self.hkdf_salt_b64)

    @property
    def iv_bytes(self) -> bytes:
        return base64.b64decode(self.iv_b64)

    @property
    def ciphertext_bytes(self) -> bytes:
        return base64.b64decode(self.ciphertext_b64)

    @property
    def is_hybrid(self) -> bool:
        """True when ML-KEM ciphertext is present (full hybrid mode)."""
        return self.mlkem_ciphertext_b64 is not None

    # ------------------------------------------------------------------
    # Serialisation
    # ------------------------------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            **self.metadata.to_dict(),
            "x25519_ephemeral_public_b64": self.x25519_ephemeral_public_b64,
            "hkdf_salt_b64": self.hkdf_salt_b64,
            "iv_b64": self.iv_b64,
            "ciphertext_b64": self.ciphertext_b64,
        }
        if self.mlkem_ciphertext_b64 is not None:
            d["mlkem_ciphertext_b64"] = self.mlkem_ciphertext_b64
        return d

    def to_json(self, *, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "EncryptedPacket":
        return cls(
            metadata=PacketMetadata.from_dict(data),
            x25519_ephemeral_public_b64=data["x25519_ephemeral_public_b64"],
            hkdf_salt_b64=data["hkdf_salt_b64"],
            iv_b64=data["iv_b64"],
            ciphertext_b64=data["ciphertext_b64"],
            mlkem_ciphertext_b64=data.get("mlkem_ciphertext_b64"),
        )

    @classmethod
    def from_json(cls, json_str: str) -> "EncryptedPacket":
        return cls.from_dict(json.loads(json_str))
