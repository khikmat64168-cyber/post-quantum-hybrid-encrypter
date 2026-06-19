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

    master_key: bytes      # 32 bytes — AES-256 key
    salt: bytes            # 32 bytes — random salt used during derivation
    info: bytes            # HKDF info context string

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
