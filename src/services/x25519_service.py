"""
X25519 service — all business logic for classical key exchange.

This is the only layer permitted to call `src.crypto.classical.x25519`.
Controllers call this service; they never interact with crypto primitives directly.
"""

from __future__ import annotations

from datetime import datetime, timezone

from src.crypto.classical import x25519 as _x25519
from src.models.key_models import (
    KeyMetadata,
    SharedSecretModel,
    X25519PrivateKeyModel,
    X25519PublicKeyModel,
)
from src.utils.logging_config import get_logger

log = get_logger(__name__)

_ALGORITHM = "X25519"


class X25519Service:
    """Manages the full X25519 key-exchange lifecycle."""

    # ------------------------------------------------------------------
    # Key generation
    # ------------------------------------------------------------------

    def generate_keypair(
        self, key_id: str
    ) -> tuple[X25519PrivateKeyModel, X25519PublicKeyModel]:
        """
        Generate a fresh X25519 key pair.

        Returns (private_key_model, public_key_model).
        The private key must be stored securely (0o600).
        The public key may be distributed freely.
        """
        log.info("x25519_service.generate_keypair.start", key_id=key_id)

        private_key = _x25519.generate_private_key()
        public_key = _x25519.derive_public_key(private_key)

        metadata = KeyMetadata(
            key_id=key_id,
            algorithm=_ALGORITHM,
            created_at=datetime.now(timezone.utc),
        )

        private_model = X25519PrivateKeyModel(
            raw_bytes=_x25519.private_key_to_raw(private_key),
            metadata=metadata,
        )
        public_model = X25519PublicKeyModel(
            raw_bytes=_x25519.public_key_to_raw(public_key),
            metadata=metadata,
        )

        log.info("x25519_service.generate_keypair.complete", key_id=key_id)
        return private_model, public_model

    # ------------------------------------------------------------------
    # Shared secret
    # ------------------------------------------------------------------

    def compute_shared_secret(
        self,
        our_private_key: X25519PrivateKeyModel,
        peer_public_key: X25519PublicKeyModel,
    ) -> SharedSecretModel:
        """
        Compute a 32-byte X25519 shared secret.

        The returned SharedSecretModel must be fed to HKDF immediately
        and never persisted to disk or written to logs.
        """
        log.info(
            "x25519_service.compute_shared_secret.start",
            our_key=our_private_key.metadata.key_id,
            peer_key=peer_public_key.metadata.key_id,
        )

        private_key = _x25519.private_key_from_raw(our_private_key.raw_bytes)
        peer_pk = _x25519.public_key_from_raw(peer_public_key.raw_bytes)
        raw_secret = _x25519.exchange(private_key, peer_pk)

        log.info(
            "x25519_service.compute_shared_secret.complete",
            secret_length=len(raw_secret),
        )
        return SharedSecretModel(raw_bytes=raw_secret, algorithm="X25519-ECDH")

    # ------------------------------------------------------------------
    # Deserialization helpers
    # ------------------------------------------------------------------

    def public_key_from_raw_bytes(
        self, raw_bytes: bytes, key_id: str = "imported"
    ) -> X25519PublicKeyModel:
        """Wrap 32 raw bytes into a validated X25519PublicKeyModel."""
        _x25519.public_key_from_raw(raw_bytes)  # raises ValueError on bad length
        return X25519PublicKeyModel(
            raw_bytes=raw_bytes,
            metadata=KeyMetadata(
                key_id=key_id,
                algorithm=_ALGORITHM,
                created_at=datetime.now(timezone.utc),
            ),
        )

    def private_key_from_raw_bytes(
        self, raw_bytes: bytes, key_id: str = "imported"
    ) -> X25519PrivateKeyModel:
        """Wrap 32 raw bytes into a validated X25519PrivateKeyModel."""
        _x25519.private_key_from_raw(raw_bytes)  # raises ValueError on bad length
        return X25519PrivateKeyModel(
            raw_bytes=raw_bytes,
            metadata=KeyMetadata(
                key_id=key_id,
                algorithm=_ALGORITHM,
                created_at=datetime.now(timezone.utc),
            ),
        )
