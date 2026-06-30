"""Unit tests for PacketMetadata and EncryptedPacket models."""

import base64
import json
import os
from datetime import datetime, timezone

import pytest

from src.models.packet_models import (
    ALGORITHM_CLASSICAL,
    ALGORITHM_HYBRID,
    CURRENT_VERSION,
    EncryptedPacket,
    PacketMetadata,
)


def _meta(
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


def _packet(*, include_mlkem: bool = False) -> EncryptedPacket:
    return EncryptedPacket(
        metadata=_meta(algorithm=ALGORITHM_HYBRID if include_mlkem else ALGORITHM_CLASSICAL),
        x25519_ephemeral_public_b64=base64.b64encode(os.urandom(32)).decode(),
        hkdf_salt_b64=base64.b64encode(os.urandom(32)).decode(),
        iv_b64=base64.b64encode(os.urandom(12)).decode(),
        ciphertext_b64=base64.b64encode(os.urandom(48)).decode(),
        mlkem_ciphertext_b64=base64.b64encode(os.urandom(1088)).decode() if include_mlkem else None,
    )


# ------------------------------------------------------------------
# PacketMetadata
# ------------------------------------------------------------------

@pytest.mark.unit
class TestPacketMetadata:
    def test_to_dict_contains_all_fields(self) -> None:
        meta = _meta()
        d = meta.to_dict()
        assert "version" in d
        assert "algorithm" in d
        assert "created_at" in d
        assert "sender_key_id" in d
        assert "recipient_key_id" in d

    def test_from_dict_round_trip(self) -> None:
        meta = _meta(sender="carol", recipient="dave")
        restored = PacketMetadata.from_dict(meta.to_dict())
        assert restored.sender_key_id == "carol"
        assert restored.recipient_key_id == "dave"
        assert restored.version == CURRENT_VERSION

    def test_created_at_is_preserved(self) -> None:
        now = datetime(2025, 1, 15, 12, 0, 0, tzinfo=timezone.utc)
        meta = PacketMetadata(
            version=CURRENT_VERSION,
            algorithm=ALGORITHM_CLASSICAL,
            created_at=now,
            sender_key_id="alice",
            recipient_key_id="bob",
        )
        restored = PacketMetadata.from_dict(meta.to_dict())
        assert restored.created_at == now

    def test_make_aad_contains_sender(self) -> None:
        meta = _meta(sender="alice")
        assert b"alice" in meta.make_aad()

    def test_make_aad_contains_recipient(self) -> None:
        meta = _meta(recipient="bob")
        assert b"bob" in meta.make_aad()

    def test_make_aad_contains_version(self) -> None:
        meta = _meta()
        assert CURRENT_VERSION.encode() in meta.make_aad()

    def test_make_aad_contains_algorithm(self) -> None:
        meta = _meta(algorithm=ALGORITHM_CLASSICAL)
        aad = meta.make_aad()
        assert b"X25519" in aad

    def test_different_senders_produce_different_aad(self) -> None:
        m1 = _meta(sender="alice")
        m2 = _meta(sender="mallory")
        assert m1.make_aad() != m2.make_aad()

    def test_different_recipients_produce_different_aad(self) -> None:
        m1 = _meta(recipient="bob")
        m2 = _meta(recipient="eve")
        assert m1.make_aad() != m2.make_aad()

    def test_make_aad_is_bytes(self) -> None:
        assert isinstance(_meta().make_aad(), bytes)

    def test_frozen_prevents_mutation(self) -> None:
        meta = _meta()
        with pytest.raises((AttributeError, TypeError)):
            meta.sender_key_id = "hacker"  # type: ignore[misc]


# ------------------------------------------------------------------
# EncryptedPacket
# ------------------------------------------------------------------

@pytest.mark.unit
class TestEncryptedPacket:
    def test_is_hybrid_false_without_mlkem(self) -> None:
        assert not _packet(include_mlkem=False).is_hybrid

    def test_is_hybrid_true_with_mlkem(self) -> None:
        assert _packet(include_mlkem=True).is_hybrid

    def test_mlkem_ciphertext_bytes_none_when_absent(self) -> None:
        p = _packet(include_mlkem=False)
        assert p.mlkem_ciphertext_bytes is None

    def test_mlkem_ciphertext_bytes_returned_when_present(self) -> None:
        p = _packet(include_mlkem=True)
        assert p.mlkem_ciphertext_bytes is not None
        assert len(p.mlkem_ciphertext_bytes) == 1088

    def test_x25519_ephemeral_public_bytes_length(self) -> None:
        p = _packet()
        assert len(p.x25519_ephemeral_public_bytes) == 32

    def test_hkdf_salt_bytes_length(self) -> None:
        p = _packet()
        assert len(p.hkdf_salt_bytes) == 32

    def test_iv_bytes_length(self) -> None:
        p = _packet()
        assert len(p.iv_bytes) == 12

    def test_ciphertext_bytes_roundtrip(self) -> None:
        raw = os.urandom(48)
        p = EncryptedPacket(
            metadata=_meta(),
            x25519_ephemeral_public_b64=base64.b64encode(os.urandom(32)).decode(),
            hkdf_salt_b64=base64.b64encode(os.urandom(32)).decode(),
            iv_b64=base64.b64encode(os.urandom(12)).decode(),
            ciphertext_b64=base64.b64encode(raw).decode(),
        )
        assert p.ciphertext_bytes == raw

    def test_to_json_is_valid_json(self) -> None:
        p = _packet()
        parsed = json.loads(p.to_json())
        assert isinstance(parsed, dict)

    def test_to_json_classical_excludes_mlkem_field(self) -> None:
        p = _packet(include_mlkem=False)
        parsed = json.loads(p.to_json())
        assert "mlkem_ciphertext_b64" not in parsed

    def test_to_json_hybrid_includes_mlkem_field(self) -> None:
        p = _packet(include_mlkem=True)
        parsed = json.loads(p.to_json())
        assert "mlkem_ciphertext_b64" in parsed

    def test_from_json_round_trip(self) -> None:
        p = _packet()
        restored = EncryptedPacket.from_json(p.to_json())
        assert restored.ciphertext_b64 == p.ciphertext_b64
        assert restored.metadata.sender_key_id == p.metadata.sender_key_id

    def test_from_dict_round_trip(self) -> None:
        p = _packet(include_mlkem=True)
        restored = EncryptedPacket.from_dict(p.to_dict())
        assert restored.is_hybrid
        assert restored.mlkem_ciphertext_b64 == p.mlkem_ciphertext_b64

    def test_frozen_prevents_mutation(self) -> None:
        p = _packet()
        with pytest.raises((AttributeError, TypeError)):
            p.iv_b64 = "new"  # type: ignore[misc]
