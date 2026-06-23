"""
Integration test — full X25519-only encrypt → decrypt flow.

Tests the complete pipeline: key generation → encrypt → JSON → decrypt.
ML-KEM variant is skipped when pyoqs is not installed.
"""

import pytest

from src.models.packet_models import EncryptedPacket
from src.services.encryption_orchestrator import EncryptionOrchestrator
from src.services.packet_service import PacketService, PacketValidationError
from src.services.x25519_service import X25519Service


@pytest.fixture
def orchestrator() -> EncryptionOrchestrator:
    return EncryptionOrchestrator()


@pytest.fixture
def x25519() -> X25519Service:
    return X25519Service()


@pytest.mark.integration
class TestX25519OnlyFlow:
    def test_encrypt_returns_encrypted_packet(
        self, orchestrator: EncryptionOrchestrator, x25519: X25519Service
    ) -> None:
        _, pub = x25519.generate_keypair("bob")
        packet = orchestrator.encrypt(b"hello", pub, "alice", "bob")
        assert isinstance(packet, EncryptedPacket)

    def test_full_round_trip(
        self, orchestrator: EncryptionOrchestrator, x25519: X25519Service
    ) -> None:
        priv, pub = x25519.generate_keypair("bob")
        plaintext = b"top secret message"
        packet = orchestrator.encrypt(plaintext, pub, "alice", "bob")
        result = orchestrator.decrypt(packet, priv)
        assert result == plaintext

    def test_round_trip_large_payload(
        self, orchestrator: EncryptionOrchestrator, x25519: X25519Service
    ) -> None:
        import os
        priv, pub = x25519.generate_keypair("bob")
        plaintext = os.urandom(256 * 1024)  # 256 KB
        packet = orchestrator.encrypt(plaintext, pub, "alice", "bob")
        assert orchestrator.decrypt(packet, priv) == plaintext

    def test_round_trip_via_json(
        self, orchestrator: EncryptionOrchestrator, x25519: X25519Service
    ) -> None:
        """Simulate saving packet to disk and loading it back."""
        priv, pub = x25519.generate_keypair("bob")
        plaintext = b"saved to disk"
        packet = orchestrator.encrypt(plaintext, pub, "alice", "bob")

        json_str = packet.to_json()
        loaded = EncryptedPacket.from_json(json_str)
        result = orchestrator.decrypt(loaded, priv)
        assert result == plaintext

    def test_wrong_private_key_raises(
        self, orchestrator: EncryptionOrchestrator, x25519: X25519Service
    ) -> None:
        _, pub = x25519.generate_keypair("bob")
        wrong_priv, _ = x25519.generate_keypair("eve")
        packet = orchestrator.encrypt(b"secret", pub, "alice", "bob")
        from src.services.aes_service import AuthenticationError
        with pytest.raises(AuthenticationError):
            orchestrator.decrypt(packet, wrong_priv)

    def test_packet_is_not_hybrid(
        self, orchestrator: EncryptionOrchestrator, x25519: X25519Service
    ) -> None:
        _, pub = x25519.generate_keypair("bob")
        packet = orchestrator.encrypt(b"data", pub, "alice", "bob")
        assert not packet.is_hybrid

    def test_packet_metadata(
        self, orchestrator: EncryptionOrchestrator, x25519: X25519Service
    ) -> None:
        _, pub = x25519.generate_keypair("bob")
        packet = orchestrator.encrypt(b"data", pub, "alice", "bob")
        assert packet.metadata.sender_key_id == "alice"
        assert packet.metadata.recipient_key_id == "bob"
        assert packet.metadata.version == "1"

    def test_two_encryptions_produce_different_packets(
        self, orchestrator: EncryptionOrchestrator, x25519: X25519Service
    ) -> None:
        _, pub = x25519.generate_keypair("bob")
        p1 = orchestrator.encrypt(b"same", pub, "alice", "bob")
        p2 = orchestrator.encrypt(b"same", pub, "alice", "bob")
        assert p1.ciphertext_b64 != p2.ciphertext_b64
        assert p1.iv_b64 != p2.iv_b64


@pytest.mark.integration
class TestHybridFlow:
    def test_hybrid_flow(self, orchestrator: EncryptionOrchestrator) -> None:
        oqs = pytest.importorskip("oqs", reason="pyoqs not installed")
        from src.services.mlkem_service import MLKEMService
        from src.services.x25519_service import X25519Service

        x25519 = X25519Service()
        mlkem = MLKEMService()

        x25519_priv, x25519_pub = x25519.generate_keypair("bob")
        mlkem_priv, mlkem_pub = mlkem.generate_keypair("bob")

        plaintext = b"hybrid encrypted"
        packet = orchestrator.encrypt(
            plaintext, x25519_pub, "alice", "bob", recipient_mlkem_pub=mlkem_pub
        )
        assert packet.is_hybrid

        result = orchestrator.decrypt(packet, x25519_priv, recipient_mlkem_priv=mlkem_priv)
        assert result == plaintext
