"""
Payload data models.

Pure data containers for intermediate and final cryptographic material.
No crypto operations, no I/O, no CLI code.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass


@dataclass(frozen=True)
class HybridKeyMaterial:
    """
    Derived symmetric key material produced by the hybrid HKDF step.

    Contains the 32-byte AES-256 master key derived from combining the
    X25519 and ML-KEM-768 shared secrets through HKDF-SHA-256.

    SECURITY: master_key must NEVER be logged, printed, or persisted.
    Pass directly to the AES-GCM layer and discard.
    """

    master_key: bytes
    salt: bytes
    info: bytes

    def __repr__(self) -> str:
        return (
            f"HybridKeyMaterial("
            f"master_key=<REDACTED>, "
            f"salt=<{len(self.salt)} bytes>, "
            f"info={self.info!r})"
        )

    def __str__(self) -> str:
        return self.__repr__()

    def to_dict(self) -> dict[str, str]:
        """Serialise non-secret fields only — master_key is intentionally excluded."""
        return {
            "salt_b64": base64.b64encode(self.salt).decode(),
            "info": self.info.decode(errors="replace"),
        }


@dataclass(frozen=True)
class AESPayload:
    """
    Raw output of a single AES-256-GCM encryption operation.

    ciphertext : Encrypted data with 16-byte authentication tag appended.
                 len(ciphertext) == len(plaintext) + 16.
    iv         : 12-byte nonce used during encryption.
                 Must be stored alongside the ciphertext for decryption.
    aad        : Additional Authenticated Data (authenticated, not encrypted).
                 Must be reproduced exactly during decryption.

    This object is assembled into the full EncryptedPacket in Phase 6.
    It must not be persisted without the corresponding HKDF salt and
    ML-KEM ciphertext (Phase 6 wraps all of these together).
    """

    ciphertext: bytes
    iv: bytes
    aad: bytes | None = None

    def __repr__(self) -> str:
        return (
            f"AESPayload("
            f"ciphertext=<{len(self.ciphertext)} bytes>, "
            f"iv=<{len(self.iv)} bytes>)"
        )

    def to_dict(self) -> dict[str, str]:
        d: dict[str, str] = {
            "ciphertext_b64": base64.b64encode(self.ciphertext).decode(),
            "iv_b64": base64.b64encode(self.iv).decode(),
        }
        if self.aad is not None:
            d["aad_b64"] = base64.b64encode(self.aad).decode()
        return d

    @classmethod
    def from_dict(cls, data: dict[str, str]) -> "AESPayload":
        aad_b64 = data.get("aad_b64")
        return cls(
            ciphertext=base64.b64decode(data["ciphertext_b64"]),
            iv=base64.b64decode(data["iv_b64"]),
            aad=base64.b64decode(aad_b64) if aad_b64 else None,
        )
