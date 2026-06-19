"""
HKDF service — hybrid key derivation business logic.

Combines the X25519 and ML-KEM-768 shared secrets into a single 32-byte
AES-256 master key using HKDF-SHA-256.

Security rationale
------------------
Concatenating both secrets before HKDF (IKM = x25519_secret || mlkem_secret)
means an adversary must break BOTH X25519 and ML-KEM-768 to recover the IKM.
Even if one layer is broken in the future, the derived key remains secure.

Usage
-----
    hkdf_svc = HKDFService()
    key_material = hkdf_svc.derive(x25519_secret, mlkem_secret)
    # key_material.master_key → pass to AES-GCM
    # key_material.salt       → store in encrypted payload for decryption
"""

from __future__ import annotations

from src.crypto.hybrid import hkdf as _hkdf
from src.models.key_models import SharedSecretModel
from src.models.payload_models import HybridKeyMaterial
from src.utils.logging_config import get_logger

log = get_logger(__name__)

_INFO = b"pqhe-v1-aes256gcm"
_KEY_LENGTH = 32


class HKDFService:
    """Derives a hybrid AES-256 master key from classical and post-quantum secrets."""

    def derive(
        self,
        classical_secret: SharedSecretModel,
        pq_secret: SharedSecretModel,
        salt: bytes | None = None,
    ) -> HybridKeyMaterial:
        """
        Combine X25519 + ML-KEM-768 secrets and run HKDF-SHA-256.

        Parameters
        ----------
        classical_secret : SharedSecretModel from X25519 key exchange (32 bytes).
        pq_secret        : SharedSecretModel from ML-KEM-768 encapsulation (32 bytes).
        salt             : Optional 32-byte salt. A fresh random salt is generated
                           if not provided (normal case during encryption).
                           Provide the stored salt during decryption.

        Returns
        -------
        HybridKeyMaterial with the 32-byte master_key and the salt used.
        """
        log.info(
            "hkdf_service.derive.start",
            classical_algo=classical_secret.algorithm,
            pq_algo=pq_secret.algorithm,
            salt_provided=salt is not None,
        )

        if len(classical_secret.raw_bytes) != 32:
            raise ValueError(
                f"X25519 shared secret must be 32 bytes, "
                f"got {len(classical_secret.raw_bytes)}"
            )
        if len(pq_secret.raw_bytes) != 32:
            raise ValueError(
                f"ML-KEM shared secret must be 32 bytes, "
                f"got {len(pq_secret.raw_bytes)}"
            )

        if salt is None:
            salt = _hkdf.generate_salt()

        # IKM = X25519_secret || ML-KEM_secret  (64 bytes)
        ikm = classical_secret.raw_bytes + pq_secret.raw_bytes

        master_key = _hkdf.derive(
            ikm=ikm,
            salt=salt,
            info=_INFO,
            length=_KEY_LENGTH,
        )

        log.info(
            "hkdf_service.derive.complete",
            master_key_length=len(master_key),
            salt_length=len(salt),
        )

        return HybridKeyMaterial(
            master_key=master_key,
            salt=salt,
            info=_INFO,
        )

    def derive_with_salt(
        self,
        classical_secret: SharedSecretModel,
        pq_secret: SharedSecretModel,
        salt: bytes,
    ) -> HybridKeyMaterial:
        """
        Re-derive the master key using a known salt (decryption path).

        The salt was stored in the encrypted payload during encryption.
        Passing it here reproduces the identical master_key the sender derived.
        """
        return self.derive(classical_secret, pq_secret, salt=salt)
