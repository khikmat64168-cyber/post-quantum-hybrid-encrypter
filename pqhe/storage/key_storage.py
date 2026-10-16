"""
Key storage — secure filesystem persistence for key models.

Keys are stored as JSON files. Private key files are created with 0o600
permissions (owner read/write only — no group, no other).

Passphrase-protected keys use Argon2id + AES-256-GCM to encrypt the raw
key bytes before writing. The on-disk format includes all parameters
needed for decryption (salt, nonce) but nothing sensitive.
"""

from __future__ import annotations

import base64
import json
import os
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidTag

from pqhe.crypto.classical import aes_gcm
from pqhe.crypto.classical.argon2_kdf import derive_key, new_salt
from pqhe.models.key_models import (
    Ed25519PrivateKeyModel,
    Ed25519PublicKeyModel,
    KeyMetadata,
    MLKEMCiphertextModel,
    MLKEMPrivateKeyModel,
    MLKEMPublicKeyModel,
    X25519PrivateKeyModel,
    X25519PublicKeyModel,
)
from pqhe.utils.logging_config import get_logger
from pqhe.utils.validators import validate_key_id

log = get_logger(__name__)

_PRIVATE_MODE = 0o600
_PUBLIC_MODE = 0o644


class KeyProtectedError(RuntimeError):
    """Raised when a key file is passphrase-protected but no passphrase was supplied."""


class WrongPassphraseError(ValueError):
    """Raised when the supplied passphrase fails to decrypt a protected key."""


class KeyStorage:
    """Manages secure key persistence on the local filesystem."""

    def __init__(self, keys_dir: Path) -> None:
        self._dir = keys_dir
        self._dir.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------
    # X25519 — Write
    # ------------------------------------------------------------------

    def save_x25519_private_key(self, model: X25519PrivateKeyModel) -> Path:
        """Write an unprotected X25519 private key with 0o600 permissions."""
        path = self._dir / f"{model.metadata.key_id}_x25519_private.json"
        self._write(path, model.to_dict(), mode=_PRIVATE_MODE)
        log.info("key_storage.save_x25519_private_key", path=str(path))
        return path

    def save_x25519_private_key_protected(
        self, model: X25519PrivateKeyModel, passphrase: str
    ) -> Path:
        """Write an Argon2id+AES-256-GCM-protected X25519 private key."""
        path = self._dir / f"{model.metadata.key_id}_x25519_private.json"
        data: dict[str, Any] = {
            "key_type": "private",
            "key_id": model.metadata.key_id,
            "algorithm": model.metadata.algorithm,
            "created_at": model.metadata.created_at.isoformat(),
            **_protect(model.raw_bytes, passphrase),
        }
        self._write(path, data, mode=_PRIVATE_MODE)
        log.info("key_storage.save_x25519_private_key_protected", path=str(path))
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

    def load_x25519_private_key(
        self, path: Path, passphrase: str | None = None
    ) -> X25519PrivateKeyModel:
        """
        Deserialize an X25519 private key from a JSON file.

        If the file is passphrase-protected, supply `passphrase`.
        Raises KeyProtectedError if protected and passphrase is None.
        Raises WrongPassphraseError if the passphrase is incorrect.
        """
        data = self._read(path)
        log.info("key_storage.load_x25519_private_key", path=str(path))
        if data.get("protected"):
            if passphrase is None:
                raise KeyProtectedError(
                    f"Key '{data.get('key_id', path.stem)}' is passphrase-protected."
                )
            raw_bytes = _unprotect(data, passphrase)
            return X25519PrivateKeyModel(
                raw_bytes=raw_bytes,
                metadata=KeyMetadata.from_dict(data),
            )
        return X25519PrivateKeyModel.from_dict(data)

    def load_x25519_public_key(self, path: Path) -> X25519PublicKeyModel:
        """Deserialize an X25519 public key from a JSON file."""
        data = self._read(path)
        log.info("key_storage.load_x25519_public_key", path=str(path))
        return X25519PublicKeyModel.from_dict(data)

    # ------------------------------------------------------------------
    # X25519 — Protected-key helpers
    # ------------------------------------------------------------------

    def is_x25519_private_key_protected(self, key_id: str) -> bool:
        """Return True if the X25519 private key for key_id is passphrase-protected."""
        path = self.x25519_private_key_path(key_id)
        if not path.exists():
            return False
        return bool(self._read(path).get("protected", False))

    # ------------------------------------------------------------------
    # ML-KEM-768 — Write
    # ------------------------------------------------------------------

    def save_mlkem_private_key(self, model: MLKEMPrivateKeyModel) -> Path:
        """Write an unprotected ML-KEM-768 private key with 0o600 permissions."""
        path = self._dir / f"{model.metadata.key_id}_mlkem_private.json"
        self._write(path, model.to_dict(), mode=_PRIVATE_MODE)
        log.info("key_storage.save_mlkem_private_key", path=str(path))
        return path

    def save_mlkem_private_key_protected(
        self, model: MLKEMPrivateKeyModel, passphrase: str
    ) -> Path:
        """Write an Argon2id+AES-256-GCM-protected ML-KEM-768 private key."""
        path = self._dir / f"{model.metadata.key_id}_mlkem_private.json"
        data: dict[str, Any] = {
            "key_type": "private",
            "key_id": model.metadata.key_id,
            "algorithm": model.metadata.algorithm,
            "created_at": model.metadata.created_at.isoformat(),
            **_protect(model.raw_bytes, passphrase),
        }
        self._write(path, data, mode=_PRIVATE_MODE)
        log.info("key_storage.save_mlkem_private_key_protected", path=str(path))
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

    def load_mlkem_private_key(
        self, path: Path, passphrase: str | None = None
    ) -> MLKEMPrivateKeyModel:
        """
        Deserialize an ML-KEM-768 private key from a JSON file.

        If the file is passphrase-protected, supply `passphrase`.
        Raises KeyProtectedError if protected and passphrase is None.
        Raises WrongPassphraseError if the passphrase is incorrect.
        """
        data = self._read(path)
        log.info("key_storage.load_mlkem_private_key", path=str(path))
        if data.get("protected"):
            if passphrase is None:
                raise KeyProtectedError(
                    f"Key '{data.get('key_id', path.stem)}' is passphrase-protected."
                )
            raw_bytes = _unprotect(data, passphrase)
            return MLKEMPrivateKeyModel(
                raw_bytes=raw_bytes,
                metadata=KeyMetadata.from_dict(data),
            )
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
    # ML-KEM — Protected-key helper
    # ------------------------------------------------------------------

    def is_mlkem_private_key_protected(self, key_id: str) -> bool:
        """Return True if the ML-KEM private key for key_id is passphrase-protected."""
        path = self.mlkem_private_key_path(key_id)
        if not path.exists():
            return False
        return bool(self._read(path).get("protected", False))

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
    # Ed25519 — Write
    # ------------------------------------------------------------------

    def save_ed25519_private_key(self, model: Ed25519PrivateKeyModel) -> Path:
        """Write an Ed25519 private key with 0o600 permissions."""
        path = self._dir / f"{model.metadata.key_id}_ed25519_private.json"
        self._write(path, model.to_dict(), mode=_PRIVATE_MODE)
        log.info("key_storage.save_ed25519_private_key", path=str(path))
        return path

    def save_ed25519_public_key(self, model: Ed25519PublicKeyModel) -> Path:
        """Write an Ed25519 public key with 0o644 permissions."""
        path = self._dir / f"{model.metadata.key_id}_ed25519_public.json"
        self._write(path, model.to_dict(), mode=_PUBLIC_MODE)
        log.info("key_storage.save_ed25519_public_key", path=str(path))
        return path

    # ------------------------------------------------------------------
    # Ed25519 — Read
    # ------------------------------------------------------------------

    def load_ed25519_private_key(self, path: Path) -> Ed25519PrivateKeyModel:
        """Deserialize an Ed25519 private key from a JSON file."""
        data = self._read(path)
        log.info("key_storage.load_ed25519_private_key", path=str(path))
        return Ed25519PrivateKeyModel.from_dict(data)

    def load_ed25519_public_key(self, path: Path) -> Ed25519PublicKeyModel:
        """Deserialize an Ed25519 public key from a JSON file."""
        data = self._read(path)
        log.info("key_storage.load_ed25519_public_key", path=str(path))
        return Ed25519PublicKeyModel.from_dict(data)

    # ------------------------------------------------------------------
    # Path helpers — Ed25519
    # ------------------------------------------------------------------

    def ed25519_private_key_path(self, key_id: str) -> Path:
        validate_key_id(key_id)
        return self._dir / f"{key_id}_ed25519_private.json"

    def ed25519_public_key_path(self, key_id: str) -> Path:
        validate_key_id(key_id)
        return self._dir / f"{key_id}_ed25519_public.json"

    def ed25519_private_key_exists(self, key_id: str) -> bool:
        return self.ed25519_private_key_path(key_id).exists()

    def ed25519_public_key_exists(self, key_id: str) -> bool:
        return self.ed25519_public_key_path(key_id).exists()

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

    def _write(self, path: Path, data: dict[str, Any], *, mode: int) -> None:
        path.write_text(json.dumps(data, indent=2), encoding="utf-8")
        os.chmod(path, mode)

    def _read(self, path: Path) -> dict[str, Any]:
        if not path.exists():
            raise FileNotFoundError(f"Key file not found: {path}")
        result: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
        return result


# ------------------------------------------------------------------
# Module-level protect / unprotect helpers
# ------------------------------------------------------------------

def _protect(raw_bytes: bytes, passphrase: str) -> dict[str, Any]:
    """Encrypt raw key bytes with Argon2id-derived AES-256-GCM key."""
    salt = new_salt()
    key = derive_key(passphrase, salt)
    nonce = aes_gcm.generate_iv()
    ciphertext = aes_gcm.encrypt(key, nonce, raw_bytes)
    return {
        "protected": True,
        "argon2_salt_b64": base64.b64encode(salt).decode(),
        "aes_nonce_b64": base64.b64encode(nonce).decode(),
        "encrypted_bytes_b64": base64.b64encode(ciphertext).decode(),
    }


def _unprotect(data: dict[str, Any], passphrase: str) -> bytes:
    """Decrypt a protected key envelope. Raises WrongPassphraseError on bad passphrase."""
    salt = base64.b64decode(data["argon2_salt_b64"])
    nonce = base64.b64decode(data["aes_nonce_b64"])
    ciphertext = base64.b64decode(data["encrypted_bytes_b64"])
    key = derive_key(passphrase, salt)
    try:
        return aes_gcm.decrypt(key, nonce, ciphertext)
    except InvalidTag as exc:
        raise WrongPassphraseError("Wrong passphrase — cannot decrypt key.") from exc
