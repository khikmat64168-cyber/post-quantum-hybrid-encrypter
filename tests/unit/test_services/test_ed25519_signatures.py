"""Unit tests for Ed25519 digital signatures."""

from __future__ import annotations

import base64
import os
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path

import pytest
from cryptography.exceptions import InvalidSignature

from src.crypto.classical import ed25519 as _ed25519
from src.models.key_models import Ed25519PrivateKeyModel, Ed25519PublicKeyModel
from src.models.packet_models import (
    ALGORITHM_CLASSICAL,
    CURRENT_VERSION,
    EncryptedPacket,
    PacketMetadata,
)
from src.services.ed25519_service import Ed25519Service, SignatureVerificationError

# ──────────────────────────────────────────────────────────────
# Crypto layer — thin wrapper
# ──────────────────────────────────────────────────────────────

@pytest.mark.unit
class TestEd25519Crypto:
    def test_keypair_sizes(self) -> None:
        priv, pub = _ed25519.generate_keypair()
        assert len(priv) == _ed25519.PRIVATE_KEY_SIZE
        assert len(pub) == _ed25519.PUBLIC_KEY_SIZE

    def test_signature_size(self) -> None:
        priv, _ = _ed25519.generate_keypair()
        sig = _ed25519.sign(priv, b"msg")
        assert len(sig) == _ed25519.SIGNATURE_SIZE

    def test_sign_verify_round_trip(self) -> None:
        priv, pub = _ed25519.generate_keypair()
        msg = b"hello post-quantum world"
        sig = _ed25519.sign(priv, msg)
        _ed25519.verify(pub, msg, sig)  # must not raise

    def test_wrong_key_raises_invalid_signature(self) -> None:
        priv, _ = _ed25519.generate_keypair()
        _, other_pub = _ed25519.generate_keypair()
        sig = _ed25519.sign(priv, b"msg")
        with pytest.raises(InvalidSignature):
            _ed25519.verify(other_pub, b"msg", sig)

    def test_tampered_message_raises_invalid_signature(self) -> None:
        priv, pub = _ed25519.generate_keypair()
        sig = _ed25519.sign(priv, b"original")
        with pytest.raises(InvalidSignature):
            _ed25519.verify(pub, b"tampered", sig)

    def test_different_keys_produce_different_signatures(self) -> None:
        p1, _ = _ed25519.generate_keypair()
        p2, _ = _ed25519.generate_keypair()
        msg = b"same message"
        assert _ed25519.sign(p1, msg) != _ed25519.sign(p2, msg)


# ──────────────────────────────────────────────────────────────
# Ed25519Service
# ──────────────────────────────────────────────────────────────

@pytest.mark.unit
class TestEd25519Service:
    def test_generate_keypair_returns_models(self) -> None:
        svc = Ed25519Service()
        priv, pub = svc.generate_keypair("alice")
        assert isinstance(priv, Ed25519PrivateKeyModel)
        assert isinstance(pub, Ed25519PublicKeyModel)
        assert priv.metadata.key_id == "alice"
        assert pub.metadata.key_id == "alice"

    def test_private_key_size(self) -> None:
        svc = Ed25519Service()
        priv, _ = svc.generate_keypair("alice")
        assert len(priv.raw_bytes) == 32

    def test_public_key_size(self) -> None:
        svc = Ed25519Service()
        _, pub = svc.generate_keypair("alice")
        assert len(pub.raw_bytes) == 32

    def test_sign_returns_bytes(self) -> None:
        svc = Ed25519Service()
        priv, _ = svc.generate_keypair("alice")
        sig = svc.sign(priv, b"data")
        assert isinstance(sig, bytes)
        assert len(sig) == 64

    def test_verify_valid_signature_succeeds(self) -> None:
        svc = Ed25519Service()
        priv, pub = svc.generate_keypair("alice")
        sig = svc.sign(priv, b"data")
        svc.verify(pub.raw_bytes, b"data", sig)  # must not raise

    def test_verify_invalid_signature_raises(self) -> None:
        svc = Ed25519Service()
        priv, pub = svc.generate_keypair("alice")
        sig = svc.sign(priv, b"data")
        with pytest.raises(SignatureVerificationError):
            svc.verify(pub.raw_bytes, b"wrong data", sig)

    def test_verify_wrong_key_raises(self) -> None:
        svc = Ed25519Service()
        priv, _ = svc.generate_keypair("alice")
        _, other_pub = svc.generate_keypair("mallory")
        sig = svc.sign(priv, b"data")
        with pytest.raises(SignatureVerificationError):
            svc.verify(other_pub.raw_bytes, b"data", sig)

    def test_private_key_repr_is_redacted(self) -> None:
        svc = Ed25519Service()
        priv, _ = svc.generate_keypair("alice")
        assert "REDACTED" in repr(priv)
        assert base64.b64encode(priv.raw_bytes).decode() not in repr(priv)

    def test_algorithm_label(self) -> None:
        svc = Ed25519Service()
        priv, pub = svc.generate_keypair("alice")
        assert priv.metadata.algorithm == "Ed25519"
        assert pub.metadata.algorithm == "Ed25519"


# ──────────────────────────────────────────────────────────────
# EncryptedPacket — signature fields and signable bytes
# ──────────────────────────────────────────────────────────────

def _unsigned_packet() -> EncryptedPacket:
    return EncryptedPacket(
        metadata=PacketMetadata(
            version=CURRENT_VERSION,
            algorithm=ALGORITHM_CLASSICAL,
            created_at=datetime.now(UTC),
            sender_key_id="alice",
            recipient_key_id="bob",
        ),
        x25519_ephemeral_public_b64=base64.b64encode(os.urandom(32)).decode(),
        hkdf_salt_b64=base64.b64encode(os.urandom(32)).decode(),
        iv_b64=base64.b64encode(os.urandom(12)).decode(),
        ciphertext_b64=base64.b64encode(os.urandom(48)).decode(),
    )


@pytest.mark.unit
class TestSignedPacket:
    def test_is_signed_false_when_no_signature(self) -> None:
        assert not _unsigned_packet().is_signed

    def test_is_signed_true_when_both_fields_present(self) -> None:
        p = replace(
            _unsigned_packet(),
            signature_b64=base64.b64encode(os.urandom(64)).decode(),
            sender_ed25519_pub_b64=base64.b64encode(os.urandom(32)).decode(),
        )
        assert p.is_signed

    def test_to_signable_bytes_excludes_signature(self) -> None:
        sig_b64 = base64.b64encode(os.urandom(64)).decode()
        pub_b64 = base64.b64encode(os.urandom(32)).decode()
        unsigned = _unsigned_packet()
        signed = replace(unsigned, signature_b64=sig_b64, sender_ed25519_pub_b64=pub_b64)
        assert signed.to_signable_bytes() == unsigned.to_signable_bytes()

    def test_signable_bytes_are_stable(self) -> None:
        p = _unsigned_packet()
        assert p.to_signable_bytes() == p.to_signable_bytes()

    def test_signable_bytes_change_with_content(self) -> None:
        p1 = _unsigned_packet()
        p2 = _unsigned_packet()  # different random bytes inside
        assert p1.to_signable_bytes() != p2.to_signable_bytes()

    def test_to_json_includes_signature_when_signed(self) -> None:
        import json  # noqa: PLC0415
        p = replace(
            _unsigned_packet(),
            signature_b64=base64.b64encode(os.urandom(64)).decode(),
            sender_ed25519_pub_b64=base64.b64encode(os.urandom(32)).decode(),
        )
        d = json.loads(p.to_json())
        assert "signature_b64" in d
        assert "sender_ed25519_pub_b64" in d

    def test_to_json_excludes_signature_when_unsigned(self) -> None:
        import json  # noqa: PLC0415
        d = json.loads(_unsigned_packet().to_json())
        assert "signature_b64" not in d
        assert "sender_ed25519_pub_b64" not in d

    def test_from_dict_round_trip_with_signature(self) -> None:
        sig_b64 = base64.b64encode(os.urandom(64)).decode()
        pub_b64 = base64.b64encode(os.urandom(32)).decode()
        signed = replace(_unsigned_packet(), signature_b64=sig_b64, sender_ed25519_pub_b64=pub_b64)
        restored = EncryptedPacket.from_dict(signed.to_dict())
        assert restored.signature_b64 == sig_b64
        assert restored.sender_ed25519_pub_b64 == pub_b64
        assert restored.is_signed


# ──────────────────────────────────────────────────────────────
# Ed25519 key storage
# ──────────────────────────────────────────────────────────────

@pytest.mark.unit
class TestEd25519KeyStorage:
    def test_save_and_load_private_key(self, tmp_path: Path) -> None:
        from src.storage.key_storage import KeyStorage  # noqa: PLC0415
        svc = Ed25519Service()
        priv, _ = svc.generate_keypair("alice")
        storage = KeyStorage(tmp_path)
        path = storage.save_ed25519_private_key(priv)
        loaded = storage.load_ed25519_private_key(path)
        assert loaded.raw_bytes == priv.raw_bytes
        assert loaded.metadata.key_id == "alice"

    def test_save_and_load_public_key(self, tmp_path: Path) -> None:
        from src.storage.key_storage import KeyStorage  # noqa: PLC0415
        svc = Ed25519Service()
        _, pub = svc.generate_keypair("alice")
        storage = KeyStorage(tmp_path)
        path = storage.save_ed25519_public_key(pub)
        loaded = storage.load_ed25519_public_key(path)
        assert loaded.raw_bytes == pub.raw_bytes

    def test_private_key_permissions_are_0600(self, tmp_path: Path) -> None:
        from src.storage.key_storage import KeyStorage  # noqa: PLC0415
        svc = Ed25519Service()
        priv, _ = svc.generate_keypair("alice")
        storage = KeyStorage(tmp_path)
        path = storage.save_ed25519_private_key(priv)
        assert oct(path.stat().st_mode)[-3:] == "600"

    def test_public_key_permissions_are_0644(self, tmp_path: Path) -> None:
        from src.storage.key_storage import KeyStorage  # noqa: PLC0415
        svc = Ed25519Service()
        _, pub = svc.generate_keypair("alice")
        storage = KeyStorage(tmp_path)
        path = storage.save_ed25519_public_key(pub)
        assert oct(path.stat().st_mode)[-3:] == "644"

    def test_ed25519_private_key_exists_true(self, tmp_path: Path) -> None:
        from src.storage.key_storage import KeyStorage  # noqa: PLC0415
        svc = Ed25519Service()
        priv, _ = svc.generate_keypair("alice")
        storage = KeyStorage(tmp_path)
        storage.save_ed25519_private_key(priv)
        assert storage.ed25519_private_key_exists("alice") is True

    def test_ed25519_private_key_exists_false(self, tmp_path: Path) -> None:
        from src.storage.key_storage import KeyStorage  # noqa: PLC0415
        storage = KeyStorage(tmp_path)
        assert storage.ed25519_private_key_exists("nobody") is False


# ──────────────────────────────────────────────────────────────
# Orchestrator — sign on encrypt, verify on decrypt
# ──────────────────────────────────────────────────────────────

def _orch_setup() -> tuple:  # type: ignore[type-arg]
    from src.services.encryption_orchestrator import EncryptionOrchestrator  # noqa: PLC0415
    from src.services.x25519_service import X25519Service  # noqa: PLC0415
    x25519_svc = X25519Service()
    ed_svc = Ed25519Service()
    recipient_priv, recipient_pub = x25519_svc.generate_keypair("bob")
    ed_priv, ed_pub = ed_svc.generate_keypair("alice")
    orch = EncryptionOrchestrator()
    return orch, recipient_priv, recipient_pub, ed_priv, ed_pub


@pytest.mark.unit
class TestSignedEncryption:
    def test_unsigned_packet_has_no_signature(self) -> None:
        from src.services.encryption_orchestrator import EncryptionOrchestrator  # noqa: PLC0415
        from src.services.x25519_service import X25519Service  # noqa: PLC0415
        _, pub = X25519Service().generate_keypair("bob")
        orch = EncryptionOrchestrator()
        packet = orch.encrypt(
            plaintext=b"hello",
            recipient_x25519_pub=pub,
            sender_key_id="anonymous",
            recipient_key_id="bob",
        )
        assert not packet.is_signed

    def test_signed_packet_has_signature(self) -> None:
        orch, _, pub, ed_priv, ed_pub = _orch_setup()
        packet = orch.encrypt(
            plaintext=b"hello signed world",
            recipient_x25519_pub=pub,
            sender_key_id="alice",
            recipient_key_id="bob",
            sender_ed25519_priv=ed_priv,
            sender_ed25519_pub=ed_pub,
        )
        assert packet.is_signed
        assert packet.signature_b64 is not None
        assert packet.sender_ed25519_pub_b64 is not None

    def test_decrypt_valid_signed_packet_succeeds(self) -> None:
        orch, priv, pub, ed_priv, ed_pub = _orch_setup()
        packet = orch.encrypt(
            plaintext=b"secret message",
            recipient_x25519_pub=pub,
            sender_key_id="alice",
            recipient_key_id="bob",
            sender_ed25519_priv=ed_priv,
            sender_ed25519_pub=ed_pub,
        )
        plaintext = orch.decrypt(packet=packet, recipient_x25519_priv=priv)
        assert plaintext == b"secret message"

    def test_decrypt_tampered_signature_raises(self) -> None:
        orch, priv, pub, ed_priv, ed_pub = _orch_setup()
        packet = orch.encrypt(
            plaintext=b"hello",
            recipient_x25519_pub=pub,
            sender_key_id="alice",
            recipient_key_id="bob",
            sender_ed25519_priv=ed_priv,
            sender_ed25519_pub=ed_pub,
        )
        bad_sig = base64.b64encode(os.urandom(64)).decode()
        tampered = replace(packet, signature_b64=bad_sig)
        with pytest.raises(SignatureVerificationError):
            orch.decrypt(packet=tampered, recipient_x25519_priv=priv)

    def test_decrypt_unsigned_packet_succeeds(self) -> None:
        orch, priv, pub, _, _ = _orch_setup()
        packet = orch.encrypt(
            plaintext=b"unsigned but valid",
            recipient_x25519_pub=pub,
            sender_key_id="anonymous",
            recipient_key_id="bob",
        )
        plaintext = orch.decrypt(packet=packet, recipient_x25519_priv=priv)
        assert plaintext == b"unsigned but valid"
