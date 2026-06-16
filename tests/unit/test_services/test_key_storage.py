"""Unit tests for key filesystem persistence."""

import json
import os
import stat
from pathlib import Path

import pytest

from src.models.key_models import X25519PrivateKeyModel, X25519PublicKeyModel
from src.services.x25519_service import X25519Service
from src.storage.key_storage import KeyStorage


@pytest.fixture
def service() -> X25519Service:
    return X25519Service()


@pytest.fixture
def storage(tmp_path: Path) -> KeyStorage:
    return KeyStorage(keys_dir=tmp_path / "keys")


@pytest.mark.unit
class TestSaveAndLoad:
    def test_save_and_load_public_key(
        self, service: X25519Service, storage: KeyStorage
    ) -> None:
        _, pub = service.generate_keypair("alice")
        path = storage.save_x25519_public_key(pub)
        loaded = storage.load_x25519_public_key(path)
        assert loaded.raw_bytes == pub.raw_bytes
        assert loaded.metadata.key_id == "alice"

    def test_save_and_load_private_key(
        self, service: X25519Service, storage: KeyStorage
    ) -> None:
        priv, _ = service.generate_keypair("alice")
        path = storage.save_x25519_private_key(priv)
        loaded = storage.load_x25519_private_key(path)
        assert loaded.raw_bytes == priv.raw_bytes
        assert loaded.metadata.key_id == "alice"

    def test_save_returns_correct_path(
        self, service: X25519Service, storage: KeyStorage
    ) -> None:
        priv, pub = service.generate_keypair("bob")
        priv_path = storage.save_x25519_private_key(priv)
        pub_path = storage.save_x25519_public_key(pub)
        assert priv_path.name == "bob_x25519_private.json"
        assert pub_path.name == "bob_x25519_public.json"


@pytest.mark.unit
class TestFilePermissions:
    def test_private_key_file_permissions(
        self, service: X25519Service, storage: KeyStorage
    ) -> None:
        priv, _ = service.generate_keypair("alice")
        path = storage.save_x25519_private_key(priv)
        file_mode = stat.S_IMODE(os.stat(path).st_mode)
        assert file_mode == 0o600, f"Expected 0o600, got {oct(file_mode)}"

    def test_public_key_file_permissions(
        self, service: X25519Service, storage: KeyStorage
    ) -> None:
        _, pub = service.generate_keypair("alice")
        path = storage.save_x25519_public_key(pub)
        file_mode = stat.S_IMODE(os.stat(path).st_mode)
        assert file_mode == 0o644, f"Expected 0o644, got {oct(file_mode)}"


@pytest.mark.unit
class TestFileFormat:
    def test_key_file_is_valid_json(
        self, service: X25519Service, storage: KeyStorage
    ) -> None:
        priv, _ = service.generate_keypair("alice")
        path = storage.save_x25519_private_key(priv)
        data = json.loads(path.read_text())
        assert "raw_bytes_b64" in data
        assert "algorithm" in data
        assert "created_at" in data

    def test_private_key_json_has_correct_type(
        self, service: X25519Service, storage: KeyStorage
    ) -> None:
        priv, _ = service.generate_keypair("alice")
        path = storage.save_x25519_private_key(priv)
        data = json.loads(path.read_text())
        assert data["key_type"] == "private"

    def test_public_key_json_has_correct_type(
        self, service: X25519Service, storage: KeyStorage
    ) -> None:
        _, pub = service.generate_keypair("alice")
        path = storage.save_x25519_public_key(pub)
        data = json.loads(path.read_text())
        assert data["key_type"] == "public"


@pytest.mark.unit
class TestExistenceChecks:
    def test_private_key_exists_after_save(
        self, service: X25519Service, storage: KeyStorage
    ) -> None:
        priv, _ = service.generate_keypair("charlie")
        assert not storage.x25519_private_key_exists("charlie")
        storage.save_x25519_private_key(priv)
        assert storage.x25519_private_key_exists("charlie")

    def test_public_key_exists_after_save(
        self, service: X25519Service, storage: KeyStorage
    ) -> None:
        _, pub = service.generate_keypair("charlie")
        assert not storage.x25519_public_key_exists("charlie")
        storage.save_x25519_public_key(pub)
        assert storage.x25519_public_key_exists("charlie")

    def test_load_missing_key_raises(self, storage: KeyStorage) -> None:
        with pytest.raises(FileNotFoundError):
            storage.load_x25519_public_key(Path("/nonexistent/key.json"))


@pytest.mark.unit
class TestSecureBytes:
    def test_wipe_zeroes_bytearray(self) -> None:
        from src.utils.secure_bytes import wipe

        buf = bytearray(b"\xff" * 32)
        wipe(buf)
        assert buf == bytearray(32)

    def test_wipe_rejects_bytes(self) -> None:
        from src.utils.secure_bytes import wipe

        with pytest.raises(TypeError):
            wipe(b"\xff" * 32)  # type: ignore[arg-type]

    def test_wipe_bytes_copy(self) -> None:
        from src.utils.secure_bytes import wipe, wipe_bytes_copy

        secret = b"\xde\xad\xbe\xef"
        mutable = wipe_bytes_copy(secret)
        assert isinstance(mutable, bytearray)
        assert bytes(mutable) == secret
        wipe(mutable)
        assert mutable == bytearray(4)
