"""
Low-level X25519 operations — a thin typed wrapper over the `cryptography` library.

This module contains zero business logic. It accepts and returns `cryptography`
library objects and raw bytes only. All higher-level decisions live in
`src.services.x25519_service`.
"""

from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

_EXPECTED_KEY_LEN = 32


def generate_private_key() -> X25519PrivateKey:
    """Generate a new X25519 private key using OS-provided entropy (CSPRNG)."""
    return X25519PrivateKey.generate()


def derive_public_key(private_key: X25519PrivateKey) -> X25519PublicKey:
    """Derive the corresponding public key from a private key."""
    return private_key.public_key()


def exchange(private_key: X25519PrivateKey, peer_public_key: X25519PublicKey) -> bytes:
    """
    Perform an X25519 Diffie-Hellman exchange.

    Returns 32 bytes of raw shared secret material suitable for use as
    HKDF input keying material (IKM). This output must NOT be used
    directly as an encryption key.
    """
    return private_key.exchange(peer_public_key)


def private_key_to_raw(private_key: X25519PrivateKey) -> bytes:
    """Serialize a private key to 32 raw bytes (little-endian scalar)."""
    return private_key.private_bytes(
        encoding=Encoding.Raw,
        format=PrivateFormat.Raw,
        encryption_algorithm=NoEncryption(),
    )


def public_key_to_raw(public_key: X25519PublicKey) -> bytes:
    """Serialize a public key to 32 raw bytes (u-coordinate of the point)."""
    return public_key.public_bytes(
        encoding=Encoding.Raw,
        format=PublicFormat.Raw,
    )


def private_key_from_raw(data: bytes) -> X25519PrivateKey:
    """
    Deserialize an X25519 private key from 32 raw bytes.

    Raises ValueError if the input length is not exactly 32 bytes.
    """
    if len(data) != _EXPECTED_KEY_LEN:
        raise ValueError(
            f"X25519 private key must be exactly {_EXPECTED_KEY_LEN} bytes, got {len(data)}"
        )
    return X25519PrivateKey.from_private_bytes(data)


def public_key_from_raw(data: bytes) -> X25519PublicKey:
    """
    Deserialize an X25519 public key from 32 raw bytes.

    Raises ValueError if the input length is not exactly 32 bytes.
    """
    if len(data) != _EXPECTED_KEY_LEN:
        raise ValueError(
            f"X25519 public key must be exactly {_EXPECTED_KEY_LEN} bytes, got {len(data)}"
        )
    return X25519PublicKey.from_public_bytes(data)
