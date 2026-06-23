"""Unit tests for PacketService — assembly, validation, serialisation."""

import base64
import json
import os

import pytest

from src.models.key_models import KeyMetadata, X25519PublicKeyModel
from src.models.packet_models import (
    ALGORITHM_CLASSICAL,
    ALGORITHM_HYBRID,
    CURRENT_VERSION,
    EncryptedPacket,
    PacketMetadata,
)
from src.models.payload_models import AESPayload, HybridKeyMaterial
from src.services.packet_service import (
    PacketService,
    PacketValidationError,
    UnsupportedVersionError,
)

from datetime import datetime, timezone


def _make_metadata(
    sender: str = "alice",
    recipient: str = "bob",
    algorithm: str = ALGORITHM_CLASSICAL,
) -> PacketMetadata:
    return PacketMetadata(
        version=CURRENT_VERSION,
        algorithm=algorithm,
        created_at=datetime.now(timezone.utc),
        sender_key_id=sender,
        recipient_key_id=recipient,
    )


def _make_packet(
    *,
    ciphertext_size: int = 64,
    include_mlkem: bool = False,
) -> EncryptedPacket:
    algorithm = ALGORITHM_HYBRID if include_mlkem else ALGORITHM_CLASSICAL
    return EncryptedPacket(
        metadata=_make_metadata(algorithm=algorithm),
        x25519_ephemeral_public_b64=base64.b64encode(os.urandom(32)).decode(),
        hkdf_salt_b64=base64.b64encode(os.urandom(32)).decode(),
        iv_b64=base64.b64encode(os.urandom(12)).decode(),
        ciphertext_b64=base64.b64encode(os.urandom(ciphertext_size)).decode(),
        mlkem_ciphertext_b64=(
            base64.b64encode(os.urandom(1088)).decode() if include_mlkem else None
        ),
    )


@pytest.fixture
def service() -> PacketService:
    return PacketService()


@pytest.mark.unit
class TestAssemble:
    def test_assemble_returns_encrypted_packet(self, service: PacketService) -> None:
        aes = AESPayload(
            ciphertext=os.urandom(32),
            iv=os.urandom(12),
        )
        km = HybridKeyMaterial(
            master_key=os.urandom(32),
            salt=os.urandom(32),
            info=b"pqhe-v1-aes256gcm",
        )
        pub = X25519PublicKeyModel(
            raw_bytes=os.urandom(32),
            metadata=KeyMetadata(key_id="alice", algorithm="X25519"),
        )
        packet = service.assemble(
            aes_payload=aes,
            key_material=km,
            ephemeral_x25519_pub=pub,
            sender_key_id="alice",
            recipient_key_id="bob",
        )
        assert isinstance(packet, EncryptedPacket)
        assert packet.metadata.sender_key_id == "alice"
        assert packet.metadata.recipient_key_id == "bob"
        assert packet.metadata.algorithm == ALGORITHM_CLASSICAL
        assert packet.mlkem_ciphertext_b64 is None

    def test_assemble_classical_mode(self, service: PacketService) -> None:
        packet = _make_packet(include_mlkem=False)
        assert not packet.is_hybrid
        assert packet.metadata.algorithm == ALGORITHM_CLASSICAL

    def test_assemble_hybrid_mode(self, service: PacketService) -> None:
        packet = _make_packet(include_mlkem=True)
        assert packet.is_hybrid
        assert packet.metadata.algorithm == ALGORITHM_HYBRID


@pytest.mark.unit
class TestValidation:
    def test_valid_packet_does_not_raise(self, service: PacketService) -> None:
        service.validate(_make_packet())

    def test_valid_hybrid_packet_does_not_raise(self, service: PacketService) -> None:
        service.validate(_make_packet(include_mlkem=True))

    def test_unsupported_version_raises(self, service: PacketService) -> None:
        packet = _make_packet()
        bad = EncryptedPacket(
            metadata=PacketMetadata(
                version="99",
                algorithm=ALGORITHM_CLASSICAL,
                created_at=datetime.now(timezone.utc),
                sender_key_id="alice",
                recipient_key_id="bob",
            ),
            x25519_ephemeral_public_b64=packet.x25519_ephemeral_public_b64,
            hkdf_salt_b64=packet.hkdf_salt_b64,
            iv_b64=packet.iv_b64,
            ciphertext_b64=packet.ciphertext_b64,
        )
        with pytest.raises(UnsupportedVersionError):
            service.validate(bad)

    def test_wrong_x25519_key_length_raises(self, service: PacketService) -> None:
        packet = _make_packet()
        bad = EncryptedPacket(
            metadata=packet.metadata,
            x25519_ephemeral_public_b64=base64.b64encode(os.urandom(16)).decode(),
            hkdf_salt_b64=packet.hkdf_salt_b64,
            iv_b64=packet.iv_b64,
            ciphertext_b64=packet.ciphertext_b64,
        )
        with pytest.raises(PacketValidationError, match="x25519_ephemeral_public_b64"):
            service.validate(bad)

    def test_wrong_iv_length_raises(self, service: PacketService) -> None:
        packet = _make_packet()
        bad = EncryptedPacket(
            metadata=packet.metadata,
            x25519_ephemeral_public_b64=packet.x25519_ephemeral_public_b64,
            hkdf_salt_b64=packet.hkdf_salt_b64,
            iv_b64=base64.b64encode(os.urandom(8)).decode(),
            ciphertext_b64=packet.ciphertext_b64,
        )
        with pytest.raises(PacketValidationError, match="iv_b64"):
            service.validate(bad)

    def test_ciphertext_too_short_raises(self, service: PacketService) -> None:
        packet = _make_packet()
        bad = EncryptedPacket(
            metadata=packet.metadata,
            x25519_ephemeral_public_b64=packet.x25519_ephemeral_public_b64,
            hkdf_salt_b64=packet.hkdf_salt_b64,
            iv_b64=packet.iv_b64,
            ciphertext_b64=base64.b64encode(b"\x00" * 4).decode(),
        )
        with pytest.raises(PacketValidationError, match="too short"):
            service.validate(bad)


@pytest.mark.unit
class TestSerialisation:
    def test_to_json_is_valid_json(self, service: PacketService) -> None:
        packet = _make_packet()
        js = service.to_json(packet)
        parsed = json.loads(js)
        assert "version" in parsed
        assert "ciphertext_b64" in parsed

    def test_from_json_round_trip(self, service: PacketService) -> None:
        packet = _make_packet()
        js = service.to_json(packet)
        restored = service.from_json(js)
        assert restored.ciphertext_b64 == packet.ciphertext_b64
        assert restored.metadata.sender_key_id == "alice"

    def test_from_json_invalid_json_raises(self, service: PacketService) -> None:
        with pytest.raises(PacketValidationError, match="Invalid JSON"):
            service.from_json("not json {{{")

    def test_hybrid_packet_round_trip(self, service: PacketService) -> None:
        packet = _make_packet(include_mlkem=True)
        restored = service.from_json(service.to_json(packet))
        assert restored.is_hybrid
        assert restored.mlkem_ciphertext_b64 == packet.mlkem_ciphertext_b64

    def test_classical_packet_has_no_mlkem_field(self, service: PacketService) -> None:
        packet = _make_packet(include_mlkem=False)
        d = json.loads(service.to_json(packet))
        assert "mlkem_ciphertext_b64" not in d


@pytest.mark.unit
class TestAAD:
    def test_aad_includes_key_ids(self) -> None:
        meta = _make_metadata(sender="alice", recipient="bob")
        aad = meta.make_aad()
        assert b"alice" in aad
        assert b"bob" in aad

    def test_different_senders_different_aad(self) -> None:
        m1 = _make_metadata(sender="alice")
        m2 = _make_metadata(sender="carol")
        assert m1.make_aad() != m2.make_aad()
