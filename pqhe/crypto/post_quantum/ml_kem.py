"""
Low-level ML-KEM-768 operations — a thin typed wrapper over `liboqs-python`.

This module contains zero business logic. It accepts and returns raw bytes only.
All higher-level decisions (key IDs, metadata, logging) live in
`pqhe.services.mlkem_service`.

Algorithm: ML-KEM-768 (NIST FIPS 203), liboqs identifier "ML-KEM-768".
Note: this is NOT the pre-standard "Kyber768" — the two are not interoperable.

Key and ciphertext sizes for ML-KEM-768:
    Public key  : 1184 bytes
    Secret key  : 2400 bytes
    Ciphertext  : 1088 bytes
    Shared secret:  32 bytes

Requires:
    liboqs         (https://github.com/open-quantum-safe/liboqs)
    liboqs-python  (pip install liboqs-python — imports as `oqs`)
"""

from __future__ import annotations

import functools
from typing import Any

# liboqs algorithm identifier for ML-KEM-768 (FIPS 203)
_ALGORITHM = "ML-KEM-768"

# Expected sizes in bytes — used for input validation
PUBLIC_KEY_SIZE = 1184
SECRET_KEY_SIZE = 2400
CIPHERTEXT_SIZE = 1088
SHARED_SECRET_SIZE = 32


@functools.cache
def _load_oqs() -> Any:
    """
    Lazily import `oqs`, returning None if it cannot be loaded.

    The import is deferred to call time so this module (and the whole CLI) can be
    imported without liboqs. liboqs-python raises SystemExit — not ImportError —
    when the native library is missing and its auto-install fails, so that is
    caught too.
    """
    try:
        import oqs
    except (ImportError, OSError, RuntimeError, SystemExit):
        return None
    return oqs


def is_available() -> bool:
    """Return True if liboqs-python is installed and ML-KEM-768 is enabled."""
    oqs = _load_oqs()
    if oqs is None:
        return False
    try:
        return _ALGORITHM in oqs.get_enabled_kem_mechanisms()
    except Exception:
        return False


def _require_oqs() -> Any:
    """Return the `oqs` module, or raise a clear error if ML-KEM-768 is unusable."""
    oqs = _load_oqs()
    if oqs is None:
        raise ImportError(
            "liboqs-python is required for ML-KEM operations.\n"
            "1. Install liboqs:         brew install liboqs   (macOS)\n"
            "                           see https://github.com/open-quantum-safe/liboqs\n"
            "2. Install liboqs-python:  pip install liboqs-python"
        )
    if not is_available():
        raise RuntimeError(
            f"ML-KEM algorithm '{_ALGORITHM}' is not enabled in the installed liboqs build."
        )
    return oqs


def generate_keypair() -> tuple[bytes, bytes]:
    """
    Generate a fresh ML-KEM-768 key pair.

    Returns
    -------
    (public_key, secret_key) as raw bytes.
    public_key  : 1184 bytes — safe to distribute.
    secret_key  : 2400 bytes — must be stored with 0o600 permissions.
    """
    oqs = _require_oqs()
    with oqs.KeyEncapsulation(_ALGORITHM) as kem:
        public_key: bytes = kem.generate_keypair()
        secret_key: bytes = kem.export_secret_key()
    return public_key, secret_key


def encapsulate(public_key: bytes) -> tuple[bytes, bytes]:
    """
    Encapsulate a shared secret using the recipient's public key.

    This is the sender-side operation. The sender generates a random
    shared secret and encrypts it under the recipient's public key,
    producing a ciphertext.

    Parameters
    ----------
    public_key : Recipient's 1184-byte ML-KEM-768 public key.

    Returns
    -------
    (ciphertext, shared_secret) as raw bytes.
    ciphertext    : 1088 bytes — transmit to recipient.
    shared_secret :   32 bytes — feed into HKDF; never transmit.
    """
    oqs = _require_oqs()
    if len(public_key) != PUBLIC_KEY_SIZE:
        raise ValueError(
            f"ML-KEM-768 public key must be {PUBLIC_KEY_SIZE} bytes, got {len(public_key)}"
        )
    with oqs.KeyEncapsulation(_ALGORITHM) as kem:
        ciphertext: bytes
        shared_secret: bytes
        ciphertext, shared_secret = kem.encap_secret(public_key)
    return ciphertext, shared_secret


def decapsulate(secret_key: bytes, ciphertext: bytes) -> bytes:
    """
    Decapsulate the shared secret using the recipient's secret key.

    This is the recipient-side operation. Given the ciphertext from the
    sender and our own secret key, we recover the same shared secret the
    sender generated.

    Parameters
    ----------
    secret_key  : Recipient's 2400-byte ML-KEM-768 secret key.
    ciphertext  : 1088-byte ciphertext received from sender.

    Returns
    -------
    shared_secret : 32 bytes — must equal the sender's shared_secret.
    """
    oqs = _require_oqs()
    if len(secret_key) != SECRET_KEY_SIZE:
        raise ValueError(
            f"ML-KEM-768 secret key must be {SECRET_KEY_SIZE} bytes, got {len(secret_key)}"
        )
    if len(ciphertext) != CIPHERTEXT_SIZE:
        raise ValueError(
            f"ML-KEM-768 ciphertext must be {CIPHERTEXT_SIZE} bytes, got {len(ciphertext)}"
        )
    with oqs.KeyEncapsulation(_ALGORITHM, secret_key) as kem:
        shared_secret: bytes = kem.decap_secret(ciphertext)
    return shared_secret
