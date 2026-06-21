"""
AES service — authenticated encryption and decryption business logic.

This is the only layer permitted to call `src.crypto.classical.aes_gcm`.
It takes a `HybridKeyMaterial` (output of HKDFService) and operates on
plaintext bytes, returning or consuming `AESPayload` objects.

Encryption flow
---------------
1. HKDFService.derive()  → HybridKeyMaterial (master_key + salt)
2. AESService.encrypt()  → AESPayload        (ciphertext + iv)
3. Phase 6 packages HybridKeyMaterial.salt + AESPayload + ML-KEM ciphertext

Decryption flow
---------------
1. Phase 6 unpacks stored salt + ML-KEM ciphertext
2. HKDFService.derive_with_salt() → HybridKeyMaterial (same master_key)
3. AESService.decrypt()           → plaintext bytes
"""

from __future__ import annotations

from cryptography.exceptions import InvalidTag

from src.crypto.classical import aes_gcm as _aes
from src.models.payload_models import AESPayload, HybridKeyMaterial
from src.utils.logging_config import get_logger

log = get_logger(__name__)


class AESService:
    """Provides AES-256-GCM encryption and decryption over HybridKeyMaterial."""

    def encrypt(
        self,
        key_material: HybridKeyMaterial,
        plaintext: bytes,
        aad: bytes | None = None,
    ) -> AESPayload:
        """
        Encrypt plaintext using the derived AES-256 master key.

        Parameters
        ----------
        key_material : Output of HKDFService — provides the 32-byte master key.
        plaintext    : Arbitrary data to encrypt (file contents, message, etc.).
        aad          : Optional Associated Authenticated Data.  If provided it is
                       authenticated (integrity-protected) but not encrypted.
                       Useful for binding metadata (algorithm IDs, key IDs) to
                       the ciphertext to prevent payload-swapping attacks.

        Returns
        -------
        AESPayload containing ciphertext (with auth tag) and the random IV.
        """
        log.info(
            "aes_service.encrypt.start",
            plaintext_size=len(plaintext),
            aad_present=aad is not None,
        )

        iv = _aes.generate_iv()
        ciphertext = _aes.encrypt(
            key=key_material.master_key,
            iv=iv,
            plaintext=plaintext,
            aad=aad,
        )

        log.info(
            "aes_service.encrypt.complete",
            ciphertext_size=len(ciphertext),
        )
        return AESPayload(ciphertext=ciphertext, iv=iv, aad=aad)

    def decrypt(
        self,
        key_material: HybridKeyMaterial,
        payload: AESPayload,
    ) -> bytes:
        """
        Decrypt and authenticate an AESPayload.

        Parameters
        ----------
        key_material : Must be derived with the same secrets and salt that were
                       used during encryption — produces the identical master key.
        payload      : AESPayload from the encrypted packet.

        Returns
        -------
        Original plaintext bytes.

        Raises
        ------
        AuthenticationError
            Wraps InvalidTag — raised on wrong key, tampered ciphertext,
            mismatched AAD, or wrong IV.  Always treat this as a security event.
        """
        log.info(
            "aes_service.decrypt.start",
            ciphertext_size=len(payload.ciphertext),
        )

        try:
            plaintext = _aes.decrypt(
                key=key_material.master_key,
                iv=payload.iv,
                ciphertext_with_tag=payload.ciphertext,
                aad=payload.aad,
            )
        except InvalidTag as exc:
            log.warning("aes_service.decrypt.authentication_failed")
            raise AuthenticationError(
                "AES-GCM authentication failed — ciphertext may be tampered, "
                "or the key/IV/AAD does not match."
            ) from exc

        log.info("aes_service.decrypt.complete", plaintext_size=len(plaintext))
        return plaintext


class AuthenticationError(Exception):
    """
    Raised when AES-GCM tag verification fails.

    Possible causes:
    - Wrong decryption key (different shared secrets or wrong HKDF salt)
    - Ciphertext or auth tag was tampered with
    - IV mismatch
    - AAD mismatch
    """
