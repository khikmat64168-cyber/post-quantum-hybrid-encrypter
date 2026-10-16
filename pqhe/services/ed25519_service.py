"""Ed25519 digital signature service."""

from __future__ import annotations

from cryptography.exceptions import InvalidSignature

from pqhe.crypto.classical import ed25519 as _ed25519
from pqhe.models.key_models import Ed25519PrivateKeyModel, Ed25519PublicKeyModel, KeyMetadata
from pqhe.utils.logging_config import get_logger

log = get_logger(__name__)


class SignatureVerificationError(Exception):
    """Raised when an Ed25519 signature check fails."""


class Ed25519Service:
    """Generates Ed25519 keypairs, signs messages, and verifies signatures."""

    def generate_keypair(
        self, key_id: str
    ) -> tuple[Ed25519PrivateKeyModel, Ed25519PublicKeyModel]:
        """Generate a fresh Ed25519 keypair for the given identity."""
        priv_bytes, pub_bytes = _ed25519.generate_keypair()
        metadata = KeyMetadata(key_id=key_id, algorithm="Ed25519")
        priv = Ed25519PrivateKeyModel(raw_bytes=priv_bytes, metadata=metadata)
        pub = Ed25519PublicKeyModel(raw_bytes=pub_bytes, metadata=metadata)
        log.info("ed25519_service.generate_keypair", key_id=key_id)
        return priv, pub

    def sign(self, private_key: Ed25519PrivateKeyModel, message: bytes) -> bytes:
        """Sign message with the given Ed25519 private key. Returns 64-byte signature."""
        sig = _ed25519.sign(private_key.raw_bytes, message)
        log.info("ed25519_service.sign", key_id=private_key.metadata.key_id, msg_len=len(message))
        return sig

    def verify(
        self,
        public_raw_bytes: bytes,
        message: bytes,
        signature: bytes,
    ) -> None:
        """
        Verify an Ed25519 signature.

        Raises
        ------
        SignatureVerificationError : If the signature is invalid.
        """
        try:
            _ed25519.verify(public_raw_bytes, message, signature)
        except InvalidSignature as exc:
            raise SignatureVerificationError(
                "Ed25519 signature verification failed — packet may have been tampered with."
            ) from exc
        log.info("ed25519_service.verify.ok", sig_len=len(signature))
