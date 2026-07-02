"""Unit tests for key filesystem persistence."""

import json
import os
import stat
from pathlib import Path

import pytest

from src.models.key_models import (
    KeyMetadata,
    MLKEMCiphertextModel,
    MLKEMPrivateKeyModel,
    MLKEMPublicKeyModel,
    X25519PrivateKeyModel,
    X25519PublicKeyModel,
)
from src.services.x25519_service import X25519Service
from src.storage.key_storage import KeyStorage
from src.utils.validators import ValidationError


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


def _mlkem_ct(key_id: str) -> MLKEMCiphertextModel:
    return MLKEMCiphertextModel(
        raw_bytes=os.urandom(1088),
        metadata=KeyMetadata(key_id=key_id, algorithm="ML-KEM-768"),
    )


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
class TestMLKEMStorage:
    def test_save_and_load_mlkem_private_key(self, storage: KeyStorage) -> None:
        priv = _mlkem_priv("alice")
        path = storage.save_mlkem_private_key(priv)
        loaded = storage.load_mlkem_private_key(path)
        assert loaded.raw_bytes == priv.raw_bytes
        assert loaded.metadata.key_id == "alice"

    def test_save_and_load_mlkem_public_key(self, storage: KeyStorage) -> None:
        pub = _mlkem_pub("bob")
        path = storage.save_mlkem_public_key(pub)
        loaded = storage.load_mlkem_public_key(path)
        assert loaded.raw_bytes == pub.raw_bytes
        assert loaded.metadata.key_id == "bob"

    def test_save_and_load_mlkem_ciphertext(self, storage: KeyStorage) -> None:
        ct = _mlkem_ct("carol")
        path = storage.save_mlkem_ciphertext(ct)
        loaded = storage.load_mlkem_ciphertext(path)
        assert loaded.raw_bytes == ct.raw_bytes

    def test_mlkem_private_key_has_0600_permissions(self, storage: KeyStorage) -> None:
        priv = _mlkem_priv("alice")
        path = storage.save_mlkem_private_key(priv)
        assert stat.S_IMODE(os.stat(path).st_mode) == 0o600

    def test_mlkem_public_key_has_0644_permissions(self, storage: KeyStorage) -> None:
        pub = _mlkem_pub("alice")
        path = storage.save_mlkem_public_key(pub)
        assert stat.S_IMODE(os.stat(path).st_mode) == 0o644

    def test_mlkem_private_key_exists(self, storage: KeyStorage) -> None:
        assert not storage.mlkem_private_key_exists("dave")
        storage.save_mlkem_private_key(_mlkem_priv("dave"))
        assert storage.mlkem_private_key_exists("dave")

    def test_mlkem_public_key_exists(self, storage: KeyStorage) -> None:
        assert not storage.mlkem_public_key_exists("eve")
        storage.save_mlkem_public_key(_mlkem_pub("eve"))
        assert storage.mlkem_public_key_exists("eve")

    def test_mlkem_private_path_naming(self, storage: KeyStorage) -> None:
        path = storage.mlkem_private_key_path("frank")
        assert path.name == "frank_mlkem_private.json"

    def test_mlkem_public_path_naming(self, storage: KeyStorage) -> None:
        path = storage.mlkem_public_key_path("frank")
        assert path.name == "frank_mlkem_public.json"


@pytest.mark.unit
class TestPathTraversalPrevention:
    def test_path_traversal_key_id_raises(self, storage: KeyStorage) -> None:
        with pytest.raises((ValueError, ValidationError)):
            storage.x25519_private_key_path("../evil")

    def test_slash_in_key_id_raises(self, storage: KeyStorage) -> None:
        with pytest.raises((ValueError, ValidationError)):
            storage.x25519_public_key_path("alice/bob")

    def test_dotdot_key_id_raises(self, storage: KeyStorage) -> None:
        with pytest.raises((ValueError, ValidationError)):
            storage.mlkem_private_key_path("../../etc/passwd")

    def test_empty_key_id_raises(self, storage: KeyStorage) -> None:
        with pytest.raises((ValueError, ValidationError)):
            storage.x25519_private_key_path("")


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
