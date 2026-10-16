"""Ed25519 digital signature operations — thin wrapper over the cryptography library."""

from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

PRIVATE_KEY_SIZE = 32  # raw seed bytes
PUBLIC_KEY_SIZE = 32
SIGNATURE_SIZE = 64


def generate_keypair() -> tuple[bytes, bytes]:
    """Generate an Ed25519 keypair. Returns (private_seed_bytes, public_bytes)."""
    priv = Ed25519PrivateKey.generate()
    priv_bytes = priv.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    pub_bytes = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return priv_bytes, pub_bytes


def sign(private_seed_bytes: bytes, message: bytes) -> bytes:
    """Sign message with an Ed25519 private seed. Returns a 64-byte signature."""
    priv = Ed25519PrivateKey.from_private_bytes(private_seed_bytes)
    return priv.sign(message)


def verify(public_bytes: bytes, message: bytes, signature: bytes) -> None:
    """
    Verify an Ed25519 signature.

    Raises
    ------
    cryptography.exceptions.InvalidSignature : If the signature is not valid.
    """
    pub = Ed25519PublicKey.from_public_bytes(public_bytes)
    pub.verify(signature, message)
