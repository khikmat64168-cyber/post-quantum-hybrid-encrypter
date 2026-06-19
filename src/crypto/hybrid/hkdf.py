"""
Low-level HKDF-SHA-256 wrapper over the `cryptography` library.

This module contains zero business logic — only a thin typed interface
around HKDF. All decisions about what secrets to combine and what info
string to use live in `src.services.hkdf_service`.

HKDF (RFC 5869) operates in two steps:
    Extract: PRK = HMAC-SHA256(salt, IKM)
    Expand:  OKM = HKDF-Expand(PRK, info, length)

Using both X25519 and ML-KEM secrets as IKM ensures that an attacker
must break BOTH cryptographic schemes to recover the master key.
"""

from __future__ import annotations

import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

_HASH = hashes.SHA256()
_SALT_SIZE = 32
_DEFAULT_LENGTH = 32


def generate_salt() -> bytes:
    """Generate a cryptographically random 32-byte HKDF salt."""
    return os.urandom(_SALT_SIZE)


def derive(
    ikm: bytes,
    salt: bytes,
    info: bytes,
    length: int = _DEFAULT_LENGTH,
) -> bytes:
    """
    Derive a symmetric key from input keying material using HKDF-SHA-256.

    Parameters
    ----------
    ikm    : Input keying material (concatenated secrets from X25519 + ML-KEM).
    salt   : Random 32-byte value generated fresh for each encryption operation.
    info   : Context/application string binding the key to its purpose.
    length : Output key length in bytes (default 32 = AES-256).

    Returns
    -------
    Derived key of `length` bytes. Must not be used as-is — pass to AES-GCM.
    """
    if len(salt) == 0:
        raise ValueError("HKDF salt must not be empty")
    if len(ikm) == 0:
        raise ValueError("HKDF IKM must not be empty")

    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        info=info,
    )
    return hkdf.derive(ikm)
