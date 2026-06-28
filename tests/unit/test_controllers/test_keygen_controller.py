"""Unit tests for KeygenController."""

import os
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from src.controllers.keygen_controller import KeygenController, KeygenResult
from src.models.key_models import KeyMetadata, MLKEMPrivateKeyModel, MLKEMPublicKeyModel, X25519PrivateKeyModel, X25519PublicKeyModel


def _x25519_priv(key_id: str) -> X25519PrivateKeyModel:
    return X25519PrivateKeyModel(
        raw_bytes=os.urandom(32),
        metadata=KeyMetadata(key_id=key_id, algorithm="X25519"),
    )


def _x25519_pub(key_id: str) -> X25519PublicKeyModel:
    return X25519PublicKeyModel(
        raw_bytes=os.urandom(32),
        metadata=KeyMetadata(key_id=key_id, algorithm="X25519"),
    )


def _mlkem_priv(key_id: str) -> MLKEMPrivateKeyModel:
    return MLKEMPrivateKeyModel(
        raw_bytes=os.urandom(2400),
        metadata=KeyMetadata(key_id=key_id, algorithm="ML-KEM-768"),
    )


def _mlkem_pub(key_id: str) -> MLKEMPublicKeyModel:
    return MLKEMPublicKeyModel(
        raw_bytes=os.urandom(1184),
        metadata=KeyMetadata(key_id=key_id, algorithm="ML-KEM-768"),
    )


@pytest.mark.unit
class TestKeygenController:
    def test_generate_returns_keygen_result(self, tmp_path: Path) -> None:
        x25519_svc = MagicMock()
        x25519_svc.generate_keypair.return_value = (_x25519_priv("alice"), _x25519_pub("alice"))
        mlkem_svc = MagicMock()
        mlkem_svc.is_available.return_value = False

        ctrl = KeygenController(x25519_service=x25519_svc, mlkem_service=mlkem_svc)
        result = ctrl.generate("alice", tmp_path)

        assert isinstance(result, KeygenResult)
        assert result.key_id == "alice"

    def test_generate_x25519_only_when_mlkem_unavailable(self, tmp_path: Path) -> None:
        x25519_svc = MagicMock()
        x25519_svc.generate_keypair.return_value = (_x25519_priv("alice"), _x25519_pub("alice"))
        mlkem_svc = MagicMock()
        mlkem_svc.is_available.return_value = False

        ctrl = KeygenController(x25519_service=x25519_svc, mlkem_service=mlkem_svc)
        result = ctrl.generate("alice", tmp_path)

        assert result.mlkem_available is False
        assert result.mlkem_private_path is None
        assert result.mlkem_public_path is None
        mlkem_svc.generate_keypair.assert_not_called()

    def test_generate_hybrid_when_mlkem_available(self, tmp_path: Path) -> None:
        x25519_svc = MagicMock()
        x25519_svc.generate_keypair.return_value = (_x25519_priv("bob"), _x25519_pub("bob"))
        mlkem_svc = MagicMock()
        mlkem_svc.is_available.return_value = True
        mlkem_svc.generate_keypair.return_value = (_mlkem_priv("bob"), _mlkem_pub("bob"))

        ctrl = KeygenController(x25519_service=x25519_svc, mlkem_service=mlkem_svc)
        result = ctrl.generate("bob", tmp_path)

        assert result.mlkem_available is True
        assert result.mlkem_private_path is not None
        assert result.mlkem_public_path is not None

    def test_generate_writes_x25519_files(self, tmp_path: Path) -> None:
        x25519_svc = MagicMock()
        x25519_svc.generate_keypair.return_value = (_x25519_priv("alice"), _x25519_pub("alice"))
        mlkem_svc = MagicMock()
        mlkem_svc.is_available.return_value = False

        ctrl = KeygenController(x25519_service=x25519_svc, mlkem_service=mlkem_svc)
        result = ctrl.generate("alice", tmp_path)

        assert result.x25519_private_path.exists()
        assert result.x25519_public_path.exists()

    def test_generate_private_key_has_0600_permissions(self, tmp_path: Path) -> None:
        x25519_svc = MagicMock()
        x25519_svc.generate_keypair.return_value = (_x25519_priv("alice"), _x25519_pub("alice"))
        mlkem_svc = MagicMock()
        mlkem_svc.is_available.return_value = False

        ctrl = KeygenController(x25519_service=x25519_svc, mlkem_service=mlkem_svc)
        result = ctrl.generate("alice", tmp_path)

        mode = result.x25519_private_path.stat().st_mode & 0o777
        assert mode == 0o600

    def test_generate_creates_keys_dir_if_absent(self, tmp_path: Path) -> None:
        x25519_svc = MagicMock()
        x25519_svc.generate_keypair.return_value = (_x25519_priv("carol"), _x25519_pub("carol"))
        mlkem_svc = MagicMock()
        mlkem_svc.is_available.return_value = False

        new_dir = tmp_path / "deep" / "nested" / "keys"
        ctrl = KeygenController(x25519_service=x25519_svc, mlkem_service=mlkem_svc)
        ctrl.generate("carol", new_dir)

        assert new_dir.exists()

    def test_generate_empty_key_id_raises(self, tmp_path: Path) -> None:
        from src.utils.validators import ValidationError
        ctrl = KeygenController()
        with pytest.raises((ValueError, ValidationError)):
            ctrl.generate("  ", tmp_path)

    def test_generate_blank_key_id_raises(self, tmp_path: Path) -> None:
        from src.utils.validators import ValidationError
        ctrl = KeygenController()
        with pytest.raises((ValueError, ValidationError)):
            ctrl.generate("", tmp_path)

    def test_generate_path_traversal_key_id_raises(self, tmp_path: Path) -> None:
        from src.utils.validators import ValidationError
        ctrl = KeygenController()
        with pytest.raises((ValueError, ValidationError)):
            ctrl.generate("../evil", tmp_path)

    def test_generate_slash_in_key_id_raises(self, tmp_path: Path) -> None:
        from src.utils.validators import ValidationError
        ctrl = KeygenController()
        with pytest.raises((ValueError, ValidationError)):
            ctrl.generate("alice/bob", tmp_path)

    def test_keys_dir_stored_in_result(self, tmp_path: Path) -> None:
        x25519_svc = MagicMock()
        x25519_svc.generate_keypair.return_value = (_x25519_priv("dave"), _x25519_pub("dave"))
        mlkem_svc = MagicMock()
        mlkem_svc.is_available.return_value = False

        ctrl = KeygenController(x25519_service=x25519_svc, mlkem_service=mlkem_svc)
        result = ctrl.generate("dave", tmp_path)

        assert result.keys_dir == tmp_path
