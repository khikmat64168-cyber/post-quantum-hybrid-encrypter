"""
ML-KEM service — all business logic for post-quantum key encapsulation.

This is the only layer permitted to call `src.crypto.post_quantum.ml_kem`.
Controllers call this service; they never interact with crypto primitives directly.

Protocol summary
----------------
Key generation  (recipient, done once):
    private_model, public_model = MLKEMService().generate_keypair("alice")

Encapsulation   (sender, using recipient's public key):
    ciphertext_model, secret_model = MLKEMService().encapsulate(alice_public_model)
    # Send ciphertext_model to Alice.
    # Feed secret_model.raw_bytes into HKDF.

Decapsulation   (recipient, using their own private key):
    secret_model = MLKEMService().decapsulate(alice_private_model, ciphertext_model)
    # Feed secret_model.raw_bytes into HKDF — must equal sender's secret.
"""

from __future__ import annotations

from datetime import datetime, timezone

from src.crypto.post_quantum import ml_kem as _ml_kem
from src.models.key_models import (
    KeyMetadata,
    MLKEMCiphertextModel,
    MLKEMPrivateKeyModel,
    MLKEMPublicKeyModel,
    SharedSecretModel,
)
from src.utils.logging_config import get_logger

log = get_logger(__name__)

_ALGORITHM = "ML-KEM-768"


class MLKEMService:
    """Manages the full ML-KEM-768 key-encapsulation lifecycle."""

    # ------------------------------------------------------------------
    # Availability
    # ------------------------------------------------------------------

    @staticmethod
    def is_available() -> bool:
        """Return True if pyoqs/liboqs is installed and ML-KEM-768 is enabled."""
        return _ml_kem.is_available()

    # ------------------------------------------------------------------
    # Key generation
    # ------------------------------------------------------------------

    def generate_keypair(
        self, key_id: str
    ) -> tuple[MLKEMPrivateKeyModel, MLKEMPublicKeyModel]:
        """
        Generate a fresh ML-KEM-768 key pair.

        Returns (private_key_model, public_key_model).
        Distribute the public key freely.
        Store the private key with 0o600 permissions.
        """
        log.info("mlkem_service.generate_keypair.start", key_id=key_id)

        public_bytes, secret_bytes = _ml_kem.generate_keypair()

        metadata = KeyMetadata(
            key_id=key_id,
            algorithm=_ALGORITHM,
            created_at=datetime.now(timezone.utc),
        )

        private_model = MLKEMPrivateKeyModel(raw_bytes=secret_bytes, metadata=metadata)
        public_model = MLKEMPublicKeyModel(raw_bytes=public_bytes, metadata=metadata)

        log.info(
            "mlkem_service.generate_keypair.complete",
            key_id=key_id,
            public_key_size=len(public_bytes),
            secret_key_size=len(secret_bytes),
        )
        return private_model, public_model

    # ------------------------------------------------------------------
    # Encapsulation (sender side)
    # ------------------------------------------------------------------

    def encapsulate(
        self, recipient_public_key: MLKEMPublicKeyModel
    ) -> tuple[MLKEMCiphertextModel, SharedSecretModel]:
        """
        Encapsulate a shared secret for a recipient.

        The sender calls this with the recipient's public key.
        Returns (ciphertext_model, shared_secret_model).

        ciphertext_model  — transmit to recipient inside the encrypted payload.
        shared_secret_model — feed into HKDF immediately; never transmit or store.
        """
        log.info(
            "mlkem_service.encapsulate.start",
            recipient_key_id=recipient_public_key.metadata.key_id,
        )

        ciphertext_bytes, secret_bytes = _ml_kem.encapsulate(recipient_public_key.raw_bytes)

        metadata = KeyMetadata(
            key_id=recipient_public_key.metadata.key_id,
            algorithm=_ALGORITHM,
            created_at=datetime.now(timezone.utc),
        )

        ciphertext_model = MLKEMCiphertextModel(
            raw_bytes=ciphertext_bytes, metadata=metadata
        )
        secret_model = SharedSecretModel(
            raw_bytes=secret_bytes, algorithm="ML-KEM-768"
        )

        log.info(
            "mlkem_service.encapsulate.complete",
            ciphertext_size=len(ciphertext_bytes),
            secret_size=len(secret_bytes),
        )
        return ciphertext_model, secret_model

    # ------------------------------------------------------------------
    # Decapsulation (recipient side)
    # ------------------------------------------------------------------

    def decapsulate(
        self,
        private_key: MLKEMPrivateKeyModel,
        ciphertext: MLKEMCiphertextModel,
    ) -> SharedSecretModel:
        """
        Decapsulate the shared secret using the recipient's private key.

        The recipient calls this to recover the same shared secret the sender
        generated during encapsulation.

        Returns a SharedSecretModel whose raw_bytes must equal the sender's.
        Feed into HKDF immediately; never store or log.
        """
        log.info(
            "mlkem_service.decapsulate.start",
            key_id=private_key.metadata.key_id,
        )

        secret_bytes = _ml_kem.decapsulate(private_key.raw_bytes, ciphertext.raw_bytes)

        log.info(
            "mlkem_service.decapsulate.complete",
            secret_size=len(secret_bytes),
        )
        return SharedSecretModel(raw_bytes=secret_bytes, algorithm="ML-KEM-768")
