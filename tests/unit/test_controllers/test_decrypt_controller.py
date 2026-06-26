"""Unit tests for DecryptController."""

import base64
import os
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from src.controllers.decrypt_controller import DecryptController, DecryptResult
from src.models.packet_models import (
    ALGORITHM_CLASSICAL,
    CURRENT_VERSION,
    EncryptedPacket,
    PacketMetadata,
)
from src.services.aes_service import AuthenticationError
from src.services.x25519_service import X25519Service
from src.storage.key_storage import KeyStorage


def _dummy_packet(algorithm: str = ALGORITHM_CLASSICAL) -> EncryptedPacket:
    return EncryptedPacket(
        metadata=PacketMetadata(
            version=CURRENT_VERSION,
            algorithm=algorithm,
            created_at=datetime.now(timezone.utc),
            sender_key_id="alice",
            recipient_key_id="bob",
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
def packet_file(tmp_path: Path) -> Path:
    f = tmp_path / "data.enc"
    f.write_text(_dummy_packet().to_json(), encoding="utf-8")
    return f


@pytest.mark.unit
class TestDecryptController:
    def test_decrypt_file_returns_decrypt_result(self, keys_dir: Path, packet_file: Path, tmp_path: Path) -> None:
        orchestrator = MagicMock()
        orchestrator.decrypt.return_value = b"secret"

        out = tmp_path / "output.txt"
        ctrl = DecryptController(orchestrator=orchestrator)
        result = ctrl.decrypt_file(
            input_path=packet_file,
            output_path=out,
            recipient_key_id="bob",
            keys_dir=keys_dir,
        )

        assert isinstance(result, DecryptResult)

    def test_decrypt_file_writes_plaintext(self, keys_dir: Path, packet_file: Path, tmp_path: Path) -> None:
        orchestrator = MagicMock()
        orchestrator.decrypt.return_value = b"hello world"

        out = tmp_path / "output.txt"
        ctrl = DecryptController(orchestrator=orchestrator)
        ctrl.decrypt_file(
            input_path=packet_file,
            output_path=out,
            recipient_key_id="bob",
            keys_dir=keys_dir,
        )

        assert out.read_bytes() == b"hello world"

    def test_decrypt_result_plaintext_size(self, keys_dir: Path, packet_file: Path, tmp_path: Path) -> None:
        orchestrator = MagicMock()
        orchestrator.decrypt.return_value = b"hello world"

        out = tmp_path / "output.txt"
        ctrl = DecryptController(orchestrator=orchestrator)
        result = ctrl.decrypt_file(
            input_path=packet_file,
            output_path=out,
            recipient_key_id="bob",
            keys_dir=keys_dir,
        )

        assert result.plaintext_size == 11

    def test_decrypt_missing_private_key_raises_file_not_found(self, tmp_path: Path, packet_file: Path) -> None:
        ctrl = DecryptController()
        with pytest.raises(FileNotFoundError, match="bob"):
            ctrl.decrypt_file(
                input_path=packet_file,
                output_path=tmp_path / "out.txt",
                recipient_key_id="bob",
                keys_dir=tmp_path,  # no keys here
            )

    def test_decrypt_authentication_error_propagates(self, keys_dir: Path, packet_file: Path, tmp_path: Path) -> None:
        orchestrator = MagicMock()
        orchestrator.decrypt.side_effect = AuthenticationError("tag mismatch")

        out = tmp_path / "output.txt"
        ctrl = DecryptController(orchestrator=orchestrator)
        with pytest.raises(AuthenticationError):
            ctrl.decrypt_file(
                input_path=packet_file,
                output_path=out,
                recipient_key_id="bob",
                keys_dir=keys_dir,
            )

    def test_decrypt_result_stores_paths(self, keys_dir: Path, packet_file: Path, tmp_path: Path) -> None:
        orchestrator = MagicMock()
        orchestrator.decrypt.return_value = b"data"

        out = tmp_path / "output.txt"
        ctrl = DecryptController(orchestrator=orchestrator)
        result = ctrl.decrypt_file(
            input_path=packet_file,
            output_path=out,
            recipient_key_id="bob",
            keys_dir=keys_dir,
        )

        assert result.input_path == packet_file
        assert result.output_path == out

    def test_decrypt_result_stores_algorithm(self, keys_dir: Path, packet_file: Path, tmp_path: Path) -> None:
        orchestrator = MagicMock()
        orchestrator.decrypt.return_value = b"data"

        out = tmp_path / "output.txt"
        ctrl = DecryptController(orchestrator=orchestrator)
        result = ctrl.decrypt_file(
            input_path=packet_file,
            output_path=out,
            recipient_key_id="bob",
            keys_dir=keys_dir,
        )

        assert result.algorithm == ALGORITHM_CLASSICAL
