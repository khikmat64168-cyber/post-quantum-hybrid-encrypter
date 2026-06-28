"""
Key storage — secure filesystem persistence for key models.

Keys are stored as JSON files. Private key files are created with 0o600
permissions (owner read/write only — no group, no other).
This module has no knowledge of cryptographic algorithms; it serializes
and deserializes the model objects it receives.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

from src.models.key_models import (
    MLKEMCiphertextModel,
    MLKEMPrivateKeyModel,
    MLKEMPublicKeyModel,
    X25519PrivateKeyModel,
    X25519PublicKeyModel,
)
from src.utils.logging_config import get_logger
from src.utils.validators import validate_key_id

log = get_logger(__name__)

_PRIVATE_MODE = 0o600
_PUBLIC_MODE = 0o644


class KeyStorage:
    """Manages secure key persistence on the local filesystem."""

    def __init__(self, keys_dir: Path) -> None:
        self._dir = keys_dir
        self._dir.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------
    # X25519 — Write
    # ------------------------------------------------------------------

    def save_x25519_private_key(self, model: X25519PrivateKeyModel) -> Path:
        """Write an X25519 private key with 0o600 permissions."""
        path = self._dir / f"{model.metadata.key_id}_x25519_private.json"
        self._write(path, model.to_dict(), mode=_PRIVATE_MODE)
        log.info("key_storage.save_x25519_private_key", path=str(path))
        return path

    def save_x25519_public_key(self, model: X25519PublicKeyModel) -> Path:
        """Write an X25519 public key."""
        path = self._dir / f"{model.metadata.key_id}_x25519_public.json"
        self._write(path, model.to_dict(), mode=_PUBLIC_MODE)
        log.info("key_storage.save_x25519_public_key", path=str(path))
        return path

    # ------------------------------------------------------------------
    # X25519 — Read
    # ------------------------------------------------------------------

    def load_x25519_private_key(self, path: Path) -> X25519PrivateKeyModel:
        """Deserialize an X25519 private key from a JSON file."""
        data = self._read(path)
        log.info("key_storage.load_x25519_private_key", path=str(path))
        return X25519PrivateKeyModel.from_dict(data)

    def load_x25519_public_key(self, path: Path) -> X25519PublicKeyModel:
        """Deserialize an X25519 public key from a JSON file."""
        data = self._read(path)
        log.info("key_storage.load_x25519_public_key", path=str(path))
        return X25519PublicKeyModel.from_dict(data)

    # ------------------------------------------------------------------
    # ML-KEM-768 — Write
    # ------------------------------------------------------------------

    def save_mlkem_private_key(self, model: MLKEMPrivateKeyModel) -> Path:
        """Write an ML-KEM-768 private key with 0o600 permissions."""
        path = self._dir / f"{model.metadata.key_id}_mlkem_private.json"
        self._write(path, model.to_dict(), mode=_PRIVATE_MODE)
        log.info("key_storage.save_mlkem_private_key", path=str(path))
        return path

    def save_mlkem_public_key(self, model: MLKEMPublicKeyModel) -> Path:
        """Write an ML-KEM-768 public key."""
        path = self._dir / f"{model.metadata.key_id}_mlkem_public.json"
        self._write(path, model.to_dict(), mode=_PUBLIC_MODE)
        log.info("key_storage.save_mlkem_public_key", path=str(path))
        return path

    def save_mlkem_ciphertext(self, model: MLKEMCiphertextModel) -> Path:
        """Write an ML-KEM-768 ciphertext (included in encrypted payload)."""
        path = self._dir / f"{model.metadata.key_id}_mlkem_ciphertext.json"
        self._write(path, model.to_dict(), mode=_PUBLIC_MODE)
        log.info("key_storage.save_mlkem_ciphertext", path=str(path))
        return path

    # ------------------------------------------------------------------
    # ML-KEM-768 — Read
    # ------------------------------------------------------------------

    def load_mlkem_private_key(self, path: Path) -> MLKEMPrivateKeyModel:
        """Deserialize an ML-KEM-768 private key from a JSON file."""
        data = self._read(path)
        log.info("key_storage.load_mlkem_private_key", path=str(path))
        return MLKEMPrivateKeyModel.from_dict(data)

    def load_mlkem_public_key(self, path: Path) -> MLKEMPublicKeyModel:
        """Deserialize an ML-KEM-768 public key from a JSON file."""
        data = self._read(path)
        log.info("key_storage.load_mlkem_public_key", path=str(path))
        return MLKEMPublicKeyModel.from_dict(data)

    def load_mlkem_ciphertext(self, path: Path) -> MLKEMCiphertextModel:
        """Deserialize an ML-KEM-768 ciphertext from a JSON file."""
        data = self._read(path)
        log.info("key_storage.load_mlkem_ciphertext", path=str(path))
        return MLKEMCiphertextModel.from_dict(data)

    # ------------------------------------------------------------------
    # Path helpers — X25519
    # ------------------------------------------------------------------

    def x25519_private_key_path(self, key_id: str) -> Path:
        validate_key_id(key_id)
        return self._dir / f"{key_id}_x25519_private.json"

    def x25519_public_key_path(self, key_id: str) -> Path:
        validate_key_id(key_id)
        return self._dir / f"{key_id}_x25519_public.json"

    def x25519_private_key_exists(self, key_id: str) -> bool:
        return self.x25519_private_key_path(key_id).exists()

    def x25519_public_key_exists(self, key_id: str) -> bool:
        return self.x25519_public_key_path(key_id).exists()

    # ------------------------------------------------------------------
    # Path helpers — ML-KEM
    # ------------------------------------------------------------------

    def mlkem_private_key_path(self, key_id: str) -> Path:
        validate_key_id(key_id)
        return self._dir / f"{key_id}_mlkem_private.json"

    def mlkem_public_key_path(self, key_id: str) -> Path:
        validate_key_id(key_id)
        return self._dir / f"{key_id}_mlkem_public.json"

    def mlkem_private_key_exists(self, key_id: str) -> bool:
        return self.mlkem_private_key_path(key_id).exists()

    def mlkem_public_key_exists(self, key_id: str) -> bool:
        return self.mlkem_public_key_path(key_id).exists()

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _write(self, path: Path, data: dict[str, str], *, mode: int) -> None:
        path.write_text(json.dumps(data, indent=2), encoding="utf-8")
        os.chmod(path, mode)

    def _read(self, path: Path) -> dict[str, str]:
        if not path.exists():
            raise FileNotFoundError(f"Key file not found: {path}")
        raw: dict[str, str] = json.loads(path.read_text(encoding="utf-8"))
        return raw
