"""
Encrypt controller — reads a plaintext file, encrypts it, and writes an
EncryptedPacket JSON file.

Looks up recipient keys by key_id inside keys_dir using KeyStorage's
naming convention. ML-KEM public key is used automatically when present.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from src.services.encryption_orchestrator import EncryptionOrchestrator
from src.services.packet_service import PacketService
from src.storage.key_storage import KeyStorage
from src.utils.logging_config import get_logger

log = get_logger(__name__)


@dataclass(frozen=True)
class EncryptResult:
    """Summary of a completed encryption operation."""

    input_path: Path
    output_path: Path
    is_hybrid: bool
    plaintext_size: int
    ciphertext_size: int
    algorithm: str


class EncryptController:
    """Encrypts a file for a named recipient whose keys live in keys_dir."""

    def __init__(
        self,
        orchestrator: EncryptionOrchestrator | None = None,
        packet_service: PacketService | None = None,
    ) -> None:
        self._orchestrator = orchestrator or EncryptionOrchestrator()
        self._packet = packet_service or PacketService()

    def encrypt_file(
        self,
        input_path: Path,
        output_path: Path,
        sender_key_id: str,
        recipient_key_id: str,
        keys_dir: Path,
    ) -> EncryptResult:
        """
        Encrypt input_path for recipient_key_id and write packet to output_path.

        Parameters
        ----------
        input_path       : File to encrypt.
        output_path      : Destination for the EncryptedPacket JSON file.
        sender_key_id    : Label bound into packet metadata (no key lookup).
        recipient_key_id : Key ID used to load recipient public keys from keys_dir.
        keys_dir         : Directory containing key files.

        Raises
        ------
        FileNotFoundError : Recipient X25519 public key is missing in keys_dir.
        """
        storage = KeyStorage(keys_dir)

        if not storage.x25519_public_key_exists(recipient_key_id):
            raise FileNotFoundError(
                f"Recipient X25519 public key not found for '{recipient_key_id}' "
                f"in {keys_dir}.\n"
                f"Run: pqhe keygen --name {recipient_key_id} --keys-dir {keys_dir}"
            )

        recipient_x25519_pub = storage.load_x25519_public_key(
            storage.x25519_public_key_path(recipient_key_id)
        )

        recipient_mlkem_pub = None
        if storage.mlkem_public_key_exists(recipient_key_id):
            recipient_mlkem_pub = storage.load_mlkem_public_key(
                storage.mlkem_public_key_path(recipient_key_id)
            )

        plaintext = input_path.read_bytes()

        log.info(
            "encrypt_controller.encrypt_file.start",
            input=str(input_path),
            recipient=recipient_key_id,
            hybrid=recipient_mlkem_pub is not None,
            plaintext_size=len(plaintext),
        )

        packet = self._orchestrator.encrypt(
            plaintext=plaintext,
            recipient_x25519_pub=recipient_x25519_pub,
            sender_key_id=sender_key_id,
            recipient_key_id=recipient_key_id,
            recipient_mlkem_pub=recipient_mlkem_pub,
        )

        self._packet.save_to_file(packet, str(output_path))

        log.info(
            "encrypt_controller.encrypt_file.complete",
            output=str(output_path),
            is_hybrid=packet.is_hybrid,
            ciphertext_size=len(packet.ciphertext_bytes),
        )

        return EncryptResult(
            input_path=input_path,
            output_path=output_path,
            is_hybrid=packet.is_hybrid,
            plaintext_size=len(plaintext),
            ciphertext_size=len(packet.ciphertext_bytes),
            algorithm=packet.metadata.algorithm,
        )
