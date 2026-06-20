"""
Low-level AES-256-GCM operations — thin typed wrapper over the `cryptography` library.

This module contains zero business logic. It accepts and returns raw bytes only.
All higher-level decisions live in `src.services.aes_service`.

AES-256-GCM parameters
-----------------------
Key size  : 32 bytes  (256-bit)
IV / Nonce: 12 bytes  (96-bit  — NIST recommended for GCM)
Auth tag  : 16 bytes  (128-bit — appended to ciphertext by the library)
AAD       : optional  (any bytes bound to the ciphertext without being encrypted)

The `AESGCM.encrypt()` return value is: ciphertext || tag  (len = plaintext + 16).
`AESGCM.decrypt()` strips the tag, verifies it, and returns the plaintext.
If authentication fails it raises `cryptography.exceptions.InvalidTag`.
"""

from __future__ import annotations

import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

KEY_SIZE = 32
IV_SIZE = 12
TAG_SIZE = 16


def generate_iv() -> bytes:
    """Generate a cryptographically random 12-byte GCM nonce."""
    return os.urandom(IV_SIZE)


def encrypt(
    key: bytes,
    iv: bytes,
    plaintext: bytes,
    aad: bytes | None = None,
) -> bytes:
    """
    Encrypt plaintext with AES-256-GCM.

    Parameters
    ----------
    key       : 32-byte AES-256 key (from HKDF output).
    iv        : 12-byte nonce — must be unique per (key, message) pair.
    plaintext : Arbitrary-length data to encrypt.
    aad       : Additional Authenticated Data — authenticated but not encrypted.
                Include metadata (algorithm labels, key IDs) to bind them to
                this ciphertext and prevent splice attacks.

    Returns
    -------
    ciphertext || tag : len(plaintext) + 16 bytes.
    """
    _validate_key(key)
    _validate_iv(iv)
    return AESGCM(key).encrypt(iv, plaintext, aad)


def decrypt(
    key: bytes,
    iv: bytes,
    ciphertext_with_tag: bytes,
    aad: bytes | None = None,
) -> bytes:
    """
    Decrypt and authenticate AES-256-GCM ciphertext.

    Parameters
    ----------
    key                 : 32-byte AES-256 key — must match the encryption key.
    iv                  : 12-byte nonce — must match the encryption IV.
    ciphertext_with_tag : Output of `encrypt()` — ciphertext || 16-byte tag.
    aad                 : Must match the AAD provided during encryption exactly.

    Returns
    -------
    Plaintext bytes.

    Raises
    ------
    cryptography.exceptions.InvalidTag
        If authentication fails — wrong key, wrong IV, tampered ciphertext,
        or mismatched AAD.  Treat any InvalidTag as a security event.
    ValueError
        If key or IV length is incorrect.
    """
    _validate_key(key)
    _validate_iv(iv)
    if len(ciphertext_with_tag) < TAG_SIZE:
        raise ValueError(
            f"Ciphertext too short to contain a {TAG_SIZE}-byte auth tag "
            f"(got {len(ciphertext_with_tag)} bytes)"
        )
    return AESGCM(key).decrypt(iv, ciphertext_with_tag, aad)


def _validate_key(key: bytes) -> None:
    if len(key) != KEY_SIZE:
        raise ValueError(f"AES-256 key must be exactly {KEY_SIZE} bytes, got {len(key)}")


def _validate_iv(iv: bytes) -> None:
    if len(iv) != IV_SIZE:
        raise ValueError(f"AES-GCM IV must be exactly {IV_SIZE} bytes, got {len(iv)}")
