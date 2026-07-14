"""Unit tests for passphrase-protected key storage."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from src.models.key_models import X25519PrivateKeyModel
from src.services.x25519_service import X25519Service
from src.storage.key_storage import (
    KeyProtectedError,
    KeyStorage,
    WrongPassphraseError,
    _protect,
    _unprotect,
)

# ──────────────────────────────────────────────────────────────
# _protect / _unprotect round-trip
# ──────────────────────────────────────────────────────────────

@pytest.mark.unit
class TestProtectUnprotect:
    def test_round_trip(self) -> None:
        raw = os.urandom(32)
        envelope = _protect(raw, "secret")
        assert _unprotect(envelope, "secret") == raw

    def test_envelope_has_required_fields(self) -> None:
        envelope = _protect(os.urandom(32), "pw")
        assert envelope["protected"] is True
        assert "argon2_salt_b64" in envelope
        assert "aes_nonce_b64" in envelope
        assert "encrypted_bytes_b64" in envelope

    def test_envelope_does_not_contain_raw_bytes(self) -> None:
        raw = b"supersecretkey!!"
        envelope = _protect(raw, "pw")
        envelope_json = json.dumps(envelope)
        import base64
        assert base64.b64encode(raw).decode() not in envelope_json

    def test_wrong_passphrase_raises(self) -> None:
        envelope = _protect(os.urandom(32), "correct")
        with pytest.raises(WrongPassphraseError):
            _unprotect(envelope, "wrong")

    def test_different_passphrases_produce_different_ciphertexts(self) -> None:
        raw = os.urandom(32)
        e1 = _protect(raw, "pw1")
        e2 = _protect(raw, "pw2")
        assert e1["encrypted_bytes_b64"] != e2["encrypted_bytes_b64"]

    def test_same_passphrase_different_salts(self) -> None:
        raw = os.urandom(32)
        e1 = _protect(raw, "pw")
        e2 = _protect(raw, "pw")
        assert e1["argon2_salt_b64"] != e2["argon2_salt_b64"]

    def test_large_key_round_trip(self) -> None:
        raw = os.urandom(2400)  # ML-KEM secret key size
        envelope = _protect(raw, "strongpassphrase")
        assert _unprotect(envelope, "strongpassphrase") == raw


# ──────────────────────────────────────────────────────────────
# KeyStorage — protected save / load
# ──────────────────────────────────────────────────────────────

@pytest.fixture
def x25519_priv(tmp_path: Path) -> X25519PrivateKeyModel:
    svc = X25519Service()
    priv, _ = svc.generate_keypair("alice")
    return priv


@pytest.mark.unit
class TestProtectedKeyStorage:
    def test_save_protected_creates_file(
        self, x25519_priv: X25519PrivateKeyModel, tmp_path: Path
    ) -> None:
        storage = KeyStorage(tmp_path)
        path = storage.save_x25519_private_key_protected(x25519_priv, "pw")
        assert path.exists()

    def test_protected_file_has_protected_flag(
        self, x25519_priv: X25519PrivateKeyModel, tmp_path: Path
    ) -> None:
        storage = KeyStorage(tmp_path)
        path = storage.save_x25519_private_key_protected(x25519_priv, "pw")
        data = json.loads(path.read_text())
        assert data["protected"] is True

    def test_protected_file_has_no_raw_bytes(
        self, x25519_priv: X25519PrivateKeyModel, tmp_path: Path
    ) -> None:
        storage = KeyStorage(tmp_path)
        path = storage.save_x25519_private_key_protected(x25519_priv, "pw")
        data = json.loads(path.read_text())
        assert "raw_bytes_b64" not in data

    def test_load_protected_with_correct_passphrase(
        self, x25519_priv: X25519PrivateKeyModel, tmp_path: Path
    ) -> None:
        storage = KeyStorage(tmp_path)
        path = storage.save_x25519_private_key_protected(x25519_priv, "correct")
        loaded = storage.load_x25519_private_key(path, passphrase="correct")
        assert loaded.raw_bytes == x25519_priv.raw_bytes
        assert loaded.metadata.key_id == x25519_priv.metadata.key_id

    def test_load_protected_without_passphrase_raises(
        self, x25519_priv: X25519PrivateKeyModel, tmp_path: Path
    ) -> None:
        storage = KeyStorage(tmp_path)
        path = storage.save_x25519_private_key_protected(x25519_priv, "pw")
        with pytest.raises(KeyProtectedError):
            storage.load_x25519_private_key(path)

    def test_load_protected_with_wrong_passphrase_raises(
        self, x25519_priv: X25519PrivateKeyModel, tmp_path: Path
    ) -> None:
        storage = KeyStorage(tmp_path)
        path = storage.save_x25519_private_key_protected(x25519_priv, "correct")
        with pytest.raises(WrongPassphraseError):
            storage.load_x25519_private_key(path, passphrase="wrong")

    def test_unprotected_key_loads_without_passphrase(
        self, x25519_priv: X25519PrivateKeyModel, tmp_path: Path
    ) -> None:
        storage = KeyStorage(tmp_path)
        path = storage.save_x25519_private_key(x25519_priv)
        loaded = storage.load_x25519_private_key(path)
        assert loaded.raw_bytes == x25519_priv.raw_bytes

    def test_is_protected_true_for_protected_key(
        self, x25519_priv: X25519PrivateKeyModel, tmp_path: Path
    ) -> None:
        storage = KeyStorage(tmp_path)
        storage.save_x25519_private_key_protected(x25519_priv, "pw")
        assert storage.is_x25519_private_key_protected(x25519_priv.metadata.key_id) is True

    def test_is_protected_false_for_unprotected_key(
        self, x25519_priv: X25519PrivateKeyModel, tmp_path: Path
    ) -> None:
        storage = KeyStorage(tmp_path)
        storage.save_x25519_private_key(x25519_priv)
        assert storage.is_x25519_private_key_protected(x25519_priv.metadata.key_id) is False

    def test_is_protected_false_for_missing_key(self, tmp_path: Path) -> None:
        storage = KeyStorage(tmp_path)
        assert storage.is_x25519_private_key_protected("nobody") is False

    def test_protected_file_permissions_are_0600(
        self, x25519_priv: X25519PrivateKeyModel, tmp_path: Path
    ) -> None:
        storage = KeyStorage(tmp_path)
        path = storage.save_x25519_private_key_protected(x25519_priv, "pw")
        assert oct(path.stat().st_mode)[-3:] == "600"


# ──────────────────────────────────────────────────────────────
# KeygenController — passphrase integration
# ──────────────────────────────────────────────────────────────

@pytest.mark.unit
class TestKeygenWithPassphrase:
    def test_generate_with_passphrase_sets_protected_flag(self, tmp_path: Path) -> None:
        from src.controllers.keygen_controller import KeygenController
        ctrl = KeygenController()
        result = ctrl.generate("alice", tmp_path, passphrase="secret")
        assert result.protected is True

    def test_generate_without_passphrase_unprotected(self, tmp_path: Path) -> None:
        from src.controllers.keygen_controller import KeygenController
        ctrl = KeygenController()
        result = ctrl.generate("alice", tmp_path)
        assert result.protected is False

    def test_generated_protected_key_is_loadable(self, tmp_path: Path) -> None:
        from src.controllers.keygen_controller import KeygenController
        ctrl = KeygenController()
        result = ctrl.generate("alice", tmp_path, passphrase="mypassword")
        storage = KeyStorage(tmp_path)
        loaded = storage.load_x25519_private_key(
            result.x25519_private_path, passphrase="mypassword"
        )
        assert loaded.metadata.key_id == "alice"
