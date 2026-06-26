"""Unit tests for EncryptController."""

import base64
import os
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from src.controllers.encrypt_controller import EncryptController, EncryptResult
from src.models.packet_models import (
    ALGORITHM_CLASSICAL,
    CURRENT_VERSION,
    EncryptedPacket,
    PacketMetadata,
)
from src.services.x25519_service import X25519Service
from src.storage.key_storage import KeyStorage


def _dummy_packet(sender: str = "alice", recipient: str = "bob") -> EncryptedPacket:
    return EncryptedPacket(
        metadata=PacketMetadata(
            version=CURRENT_VERSION,
            algorithm=ALGORITHM_CLASSICAL,
            created_at=datetime.now(timezone.utc),
            sender_key_id=sender,
            recipient_key_id=recipient,
        ),
        x25519_ephemeral_public_b64=base64.b64encode(os.urandom(32)).decode(),
        hkdf_salt_b64=base64.b64encode(os.urandom(32)).decode(),
        iv_b64=base64.b64encode(os.urandom(12)).decode(),
        ciphertext_b64=base64.b64encode(os.urandom(32)).decode(),
    )


@pytest.fixture
def keys_dir(tmp_path: Path) -> Path:
    """Write real X25519 keys for 'bob' into tmp_path."""
    svc = X25519Service()
    priv, pub = svc.generate_keypair("bob")
    storage = KeyStorage(tmp_path)
    storage.save_x25519_private_key(priv)
    storage.save_x25519_public_key(pub)
    return tmp_path


@pytest.fixture
def input_file(tmp_path: Path) -> Path:
    f = tmp_path / "plaintext.txt"
    f.write_bytes(b"hello world")
    return f


@pytest.mark.unit
class TestEncryptController:
    def test_encrypt_file_returns_encrypt_result(self, keys_dir: Path, input_file: Path) -> None:
        orchestrator = MagicMock()
        orchestrator.encrypt.return_value = _dummy_packet()

        ctrl = EncryptController(orchestrator=orchestrator)
        out = input_file.with_name("plaintext.txt.enc")
        result = ctrl.encrypt_file(
            input_path=input_file,
            output_path=out,
            sender_key_id="alice",
            recipient_key_id="bob",
            keys_dir=keys_dir,
        )

        assert isinstance(result, EncryptResult)

    def test_encrypt_file_creates_output_file(self, keys_dir: Path, input_file: Path) -> None:
        orchestrator = MagicMock()
        orchestrator.encrypt.return_value = _dummy_packet()

        ctrl = EncryptController(orchestrator=orchestrator)
        out = input_file.with_name("out.enc")
        ctrl.encrypt_file(
            input_path=input_file,
            output_path=out,
            sender_key_id="alice",
            recipient_key_id="bob",
            keys_dir=keys_dir,
        )

        assert out.exists()

    def test_encrypt_passes_correct_plaintext(self, keys_dir: Path, input_file: Path) -> None:
        orchestrator = MagicMock()
        orchestrator.encrypt.return_value = _dummy_packet()

        ctrl = EncryptController(orchestrator=orchestrator)
        ctrl.encrypt_file(
            input_path=input_file,
            output_path=input_file.with_suffix(".enc"),
            sender_key_id="alice",
            recipient_key_id="bob",
            keys_dir=keys_dir,
        )

        call_kwargs = orchestrator.encrypt.call_args.kwargs
        assert call_kwargs["plaintext"] == b"hello world"

    def test_encrypt_passes_sender_and_recipient_ids(self, keys_dir: Path, input_file: Path) -> None:
        orchestrator = MagicMock()
        orchestrator.encrypt.return_value = _dummy_packet()

        ctrl = EncryptController(orchestrator=orchestrator)
        ctrl.encrypt_file(
            input_path=input_file,
            output_path=input_file.with_suffix(".enc"),
            sender_key_id="alice",
            recipient_key_id="bob",
            keys_dir=keys_dir,
        )

        call_kwargs = orchestrator.encrypt.call_args.kwargs
        assert call_kwargs["sender_key_id"] == "alice"
        assert call_kwargs["recipient_key_id"] == "bob"

    def test_encrypt_result_has_correct_sizes(self, keys_dir: Path, input_file: Path) -> None:
        packet = _dummy_packet()
        orchestrator = MagicMock()
        orchestrator.encrypt.return_value = packet

        ctrl = EncryptController(orchestrator=orchestrator)
        result = ctrl.encrypt_file(
            input_path=input_file,
            output_path=input_file.with_suffix(".enc"),
            sender_key_id="alice",
            recipient_key_id="bob",
            keys_dir=keys_dir,
        )

        assert result.plaintext_size == 11  # len(b"hello world")
        assert result.ciphertext_size == len(packet.ciphertext_bytes)

    def test_encrypt_missing_recipient_raises_file_not_found(self, tmp_path: Path, input_file: Path) -> None:
        ctrl = EncryptController()
        with pytest.raises(FileNotFoundError, match="charlie"):
            ctrl.encrypt_file(
                input_path=input_file,
                output_path=input_file.with_suffix(".enc"),
                sender_key_id="alice",
                recipient_key_id="charlie",
                keys_dir=tmp_path,
            )

    def test_encrypt_error_message_suggests_keygen(self, tmp_path: Path, input_file: Path) -> None:
        ctrl = EncryptController()
        with pytest.raises(FileNotFoundError, match="keygen"):
            ctrl.encrypt_file(
                input_path=input_file,
                output_path=input_file.with_suffix(".enc"),
                sender_key_id="alice",
                recipient_key_id="nobody",
                keys_dir=tmp_path,
            )

    def test_result_is_not_hybrid_without_mlkem(self, keys_dir: Path, input_file: Path) -> None:
        orchestrator = MagicMock()
        orchestrator.encrypt.return_value = _dummy_packet()

        ctrl = EncryptController(orchestrator=orchestrator)
        result = ctrl.encrypt_file(
            input_path=input_file,
            output_path=input_file.with_suffix(".enc"),
            sender_key_id="alice",
            recipient_key_id="bob",
            keys_dir=keys_dir,
        )

        assert result.is_hybrid is False
