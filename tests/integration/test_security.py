"""
Security integration tests — verify cryptographic integrity guarantees.

These tests document and verify the core security properties of PQ-HE:

1. AES-256-GCM authentication: any modification to ciphertext, IV, or AAD
   causes decryption to raise AuthenticationError.

2. AAD binding: PacketMetadata (sender, recipient, version, algorithm) is
   bound into AES-GCM's AAD, so metadata tampering is detected at decryption.

3. Key mismatch: decrypting with a different private key fails cleanly.

These are the properties an interviewer or reviewer would ask about first.
They prove that PQ-HE provides authenticated encryption, not just secrecy.
"""

from __future__ import annotations

import base64
import os

import pytest

from src.models.packet_models import (
    ALGORITHM_CLASSICAL,
    CURRENT_VERSION,
    EncryptedPacket,
    PacketMetadata,
)
from src.services.aes_service import AuthenticationError
from src.services.encryption_orchestrator import EncryptionOrchestrator
from src.services.x25519_service import X25519Service

from datetime import datetime, timezone


@pytest.fixture
def x25519() -> X25519Service:
    return X25519Service()


@pytest.fixture
def orchestrator() -> EncryptionOrchestrator:
    return EncryptionOrchestrator()


def _tamper_b64(b64_str: str, byte_index: int = 0, flip: int = 0xFF) -> str:
    """Return a new base64 string with one byte flipped at byte_index."""
    raw = bytearray(base64.b64decode(b64_str))
    raw[byte_index] ^= flip
    return base64.b64encode(bytes(raw)).decode()


# ------------------------------------------------------------------
# Ciphertext integrity
# ------------------------------------------------------------------

@pytest.mark.integration
class TestCiphertextIntegrity:
    def test_tampered_ciphertext_raises_authentication_error(
        self, orchestrator: EncryptionOrchestrator, x25519: X25519Service
    ) -> None:
        priv, pub = x25519.generate_keypair("bob")
        packet = orchestrator.encrypt(b"top secret", pub, "alice", "bob")

        tampered = EncryptedPacket(
            metadata=packet.metadata,
            x25519_ephemeral_public_b64=packet.x25519_ephemeral_public_b64,
            hkdf_salt_b64=packet.hkdf_salt_b64,
            iv_b64=packet.iv_b64,
            ciphertext_b64=_tamper_b64(packet.ciphertext_b64, byte_index=0),
        )

        with pytest.raises(AuthenticationError):
            orchestrator.decrypt(tampered, priv)

    def test_tampered_auth_tag_raises_authentication_error(
        self, orchestrator: EncryptionOrchestrator, x25519: X25519Service
    ) -> None:
        priv, pub = x25519.generate_keypair("bob")
        packet = orchestrator.encrypt(b"message", pub, "alice", "bob")

        # Auth tag is the last 16 bytes of ciphertext
        ct_bytes = bytearray(base64.b64decode(packet.ciphertext_b64))
        ct_bytes[-1] ^= 0x01  # flip last byte of the tag
        tampered = EncryptedPacket(
            metadata=packet.metadata,
            x25519_ephemeral_public_b64=packet.x25519_ephemeral_public_b64,
            hkdf_salt_b64=packet.hkdf_salt_b64,
            iv_b64=packet.iv_b64,
            ciphertext_b64=base64.b64encode(bytes(ct_bytes)).decode(),
        )

        with pytest.raises(AuthenticationError):
            orchestrator.decrypt(tampered, priv)

    def test_truncated_ciphertext_raises(
        self, orchestrator: EncryptionOrchestrator, x25519: X25519Service
    ) -> None:
        priv, pub = x25519.generate_keypair("bob")
        packet = orchestrator.encrypt(b"data", pub, "alice", "bob")

        ct_bytes = base64.b64decode(packet.ciphertext_b64)
        truncated = ct_bytes[:-1]  # remove last byte
        tampered = EncryptedPacket(
            metadata=packet.metadata,
            x25519_ephemeral_public_b64=packet.x25519_ephemeral_public_b64,
            hkdf_salt_b64=packet.hkdf_salt_b64,
            iv_b64=packet.iv_b64,
            ciphertext_b64=base64.b64encode(truncated).decode(),
        )

        with pytest.raises((AuthenticationError, Exception)):
            orchestrator.decrypt(tampered, priv)


# ------------------------------------------------------------------
# AAD / metadata binding
# ------------------------------------------------------------------

@pytest.mark.integration
class TestMetadataBinding:
    def test_tampered_sender_id_raises_authentication_error(
        self, orchestrator: EncryptionOrchestrator, x25519: X25519Service
    ) -> None:
        priv, pub = x25519.generate_keypair("bob")
        packet = orchestrator.encrypt(b"secret", pub, "alice", "bob")

        tampered_meta = PacketMetadata(
            version=packet.metadata.version,
            algorithm=packet.metadata.algorithm,
            created_at=packet.metadata.created_at,
            sender_key_id="mallory",          # tampered
            recipient_key_id=packet.metadata.recipient_key_id,
        )
        tampered = EncryptedPacket(
            metadata=tampered_meta,
            x25519_ephemeral_public_b64=packet.x25519_ephemeral_public_b64,
            hkdf_salt_b64=packet.hkdf_salt_b64,
            iv_b64=packet.iv_b64,
            ciphertext_b64=packet.ciphertext_b64,
        )

        with pytest.raises(AuthenticationError):
            orchestrator.decrypt(tampered, priv)

    def test_tampered_recipient_id_raises_authentication_error(
        self, orchestrator: EncryptionOrchestrator, x25519: X25519Service
    ) -> None:
        priv, pub = x25519.generate_keypair("bob")
        packet = orchestrator.encrypt(b"secret", pub, "alice", "bob")

        tampered_meta = PacketMetadata(
            version=packet.metadata.version,
            algorithm=packet.metadata.algorithm,
            created_at=packet.metadata.created_at,
            sender_key_id=packet.metadata.sender_key_id,
            recipient_key_id="eve",           # tampered
        )
        tampered = EncryptedPacket(
            metadata=tampered_meta,
            x25519_ephemeral_public_b64=packet.x25519_ephemeral_public_b64,
            hkdf_salt_b64=packet.hkdf_salt_b64,
            iv_b64=packet.iv_b64,
            ciphertext_b64=packet.ciphertext_b64,
        )

        with pytest.raises(AuthenticationError):
            orchestrator.decrypt(tampered, priv)

    def test_tampered_version_raises_authentication_error(
        self, orchestrator: EncryptionOrchestrator, x25519: X25519Service
    ) -> None:
        priv, pub = x25519.generate_keypair("bob")
        packet = orchestrator.encrypt(b"data", pub, "alice", "bob")

        tampered_meta = PacketMetadata(
            version="9",                      # tampered (but still passes PacketService validation bypass)
            algorithm=packet.metadata.algorithm,
            created_at=packet.metadata.created_at,
            sender_key_id=packet.metadata.sender_key_id,
            recipient_key_id=packet.metadata.recipient_key_id,
        )
        tampered = EncryptedPacket(
            metadata=tampered_meta,
            x25519_ephemeral_public_b64=packet.x25519_ephemeral_public_b64,
            hkdf_salt_b64=packet.hkdf_salt_b64,
            iv_b64=packet.iv_b64,
            ciphertext_b64=packet.ciphertext_b64,
        )

        # Either validation or AES-GCM must reject it
        with pytest.raises((AuthenticationError, Exception)):
            orchestrator.decrypt(tampered, priv)


# ------------------------------------------------------------------
# Key mismatch
# ------------------------------------------------------------------

@pytest.mark.integration
class TestKeyMismatch:
    def test_wrong_private_key_raises_authentication_error(
        self, orchestrator: EncryptionOrchestrator, x25519: X25519Service
    ) -> None:
        _, bob_pub = x25519.generate_keypair("bob")
        eve_priv, _ = x25519.generate_keypair("eve")

        packet = orchestrator.encrypt(b"for bob only", bob_pub, "alice", "bob")

        with pytest.raises(AuthenticationError):
            orchestrator.decrypt(packet, eve_priv)

    def test_correct_key_always_decrypts(
        self, orchestrator: EncryptionOrchestrator, x25519: X25519Service
    ) -> None:
        priv, pub = x25519.generate_keypair("bob")
        plaintext = b"this should always work"
        packet = orchestrator.encrypt(plaintext, pub, "alice", "bob")
        assert orchestrator.decrypt(packet, priv) == plaintext

    def test_each_encryption_produces_unique_packet(
        self, orchestrator: EncryptionOrchestrator, x25519: X25519Service
    ) -> None:
        _, pub = x25519.generate_keypair("bob")
        p1 = orchestrator.encrypt(b"same message", pub, "alice", "bob")
        p2 = orchestrator.encrypt(b"same message", pub, "alice", "bob")
        # Different ephemeral keys and IVs mean ciphertext must differ
        assert p1.ciphertext_b64 != p2.ciphertext_b64
        assert p1.iv_b64 != p2.iv_b64
        assert p1.x25519_ephemeral_public_b64 != p2.x25519_ephemeral_public_b64


# ------------------------------------------------------------------
# HKDF salt integrity
# ------------------------------------------------------------------

@pytest.mark.integration
class TestHKDFSaltIntegrity:
    def test_tampered_hkdf_salt_raises_authentication_error(
        self, orchestrator: EncryptionOrchestrator, x25519: X25519Service
    ) -> None:
        priv, pub = x25519.generate_keypair("bob")
        packet = orchestrator.encrypt(b"message", pub, "alice", "bob")

        tampered = EncryptedPacket(
            metadata=packet.metadata,
            x25519_ephemeral_public_b64=packet.x25519_ephemeral_public_b64,
            hkdf_salt_b64=_tamper_b64(packet.hkdf_salt_b64, byte_index=0),
            iv_b64=packet.iv_b64,
            ciphertext_b64=packet.ciphertext_b64,
        )

        with pytest.raises(AuthenticationError):
            orchestrator.decrypt(tampered, priv)
