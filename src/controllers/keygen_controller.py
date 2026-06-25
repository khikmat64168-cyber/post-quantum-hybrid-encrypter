"""
Keygen controller — orchestrates key-pair generation and persistence.

Generates X25519 keys unconditionally; generates ML-KEM-768 keys only
when pyoqs is installed. Returns a KeygenResult describing every file written.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from src.services.mlkem_service import MLKEMService
from src.services.x25519_service import X25519Service
from src.storage.key_storage import KeyStorage
from src.utils.logging_config import get_logger

log = get_logger(__name__)


@dataclass(frozen=True)
class KeygenResult:
    """Paths of all key files written during keygen."""

    key_id: str
    keys_dir: Path
    x25519_private_path: Path
    x25519_public_path: Path
    mlkem_private_path: Path | None
    mlkem_public_path: Path | None
    mlkem_available: bool


class KeygenController:
    """Generates and persists a hybrid key pair for a given identity."""

    def __init__(
        self,
        x25519_service: X25519Service | None = None,
        mlkem_service: MLKEMService | None = None,
    ) -> None:
        self._x25519 = x25519_service or X25519Service()
        self._mlkem = mlkem_service or MLKEMService()

    def generate(self, key_id: str, keys_dir: Path) -> KeygenResult:
        """
        Generate and save a key pair identified by key_id.

        Parameters
        ----------
        key_id   : Human-readable identifier (e.g. "alice").
        keys_dir : Directory to write key files (created if absent).

        Returns
        -------
        KeygenResult with paths to every written file.

        Raises
        ------
        ValueError : If key_id is blank.
        """
        key_id = key_id.strip()
        if not key_id:
            raise ValueError("key_id must not be empty")

        storage = KeyStorage(keys_dir)

        log.info("keygen_controller.generate.start", key_id=key_id)

        # X25519 — always generated
        x25519_priv, x25519_pub = self._x25519.generate_keypair(key_id)
        priv_path = storage.save_x25519_private_key(x25519_priv)
        pub_path = storage.save_x25519_public_key(x25519_pub)

        # ML-KEM-768 — only when pyoqs is available
        mlkem_priv_path: Path | None = None
        mlkem_pub_path: Path | None = None
        if self._mlkem.is_available():
            mlkem_priv, mlkem_pub = self._mlkem.generate_keypair(key_id)
            mlkem_priv_path = storage.save_mlkem_private_key(mlkem_priv)
            mlkem_pub_path = storage.save_mlkem_public_key(mlkem_pub)

        log.info(
            "keygen_controller.generate.complete",
            key_id=key_id,
            hybrid=self._mlkem.is_available(),
        )

        return KeygenResult(
            key_id=key_id,
            keys_dir=keys_dir,
            x25519_private_path=priv_path,
            x25519_public_path=pub_path,
            mlkem_private_path=mlkem_priv_path,
            mlkem_public_path=mlkem_pub_path,
            mlkem_available=self._mlkem.is_available(),
        )
