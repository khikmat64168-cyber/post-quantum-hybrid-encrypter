"""
Decrypt controller — loads an EncryptedPacket JSON file, decrypts it,
and writes the recovered plaintext.

Looks up recipient private keys by key_id inside keys_dir. When the
packet is flagged as hybrid, the ML-KEM private key is loaded automatically.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from src.services.aes_service import AuthenticationError
from src.services.encryption_orchestrator import EncryptionOrchestrator
from src.services.packet_service import PacketService
from src.storage.key_storage import KeyStorage
from src.utils.logging_config import get_logger

log = get_logger(__name__)


@dataclass(frozen=True)
class DecryptResult:
    """Summary of a completed decryption operation."""

    input_path: Path
    output_path: Path
    plaintext_size: int
    algorithm: str


class DecryptController:
    """Decrypts a packet file using a named recipient's private key."""

    def __init__(
        self,
        orchestrator: EncryptionOrchestrator | None = None,
        packet_service: PacketService | None = None,
    ) -> None:
        self._orchestrator = orchestrator or EncryptionOrchestrator()
        self._packet = packet_service or PacketService()

    def decrypt_file(
        self,
        input_path: Path,
        output_path: Path,
        recipient_key_id: str,
        keys_dir: Path,
    ) -> DecryptResult:
        """
        Decrypt input_path and write plaintext to output_path.

        Parameters
        ----------
        input_path       : EncryptedPacket JSON file to decrypt.
        output_path      : Destination for the recovered plaintext.
        recipient_key_id : Key ID used to load private keys from keys_dir.
        keys_dir         : Directory containing key files.

        Raises
        ------
        FileNotFoundError    : Private key missing from keys_dir.
        AuthenticationError  : AES-GCM tag check failed (wrong key / tampered).
        """
        packet = self._packet.load_from_file(str(input_path))

        storage = KeyStorage(keys_dir)

        if not storage.x25519_private_key_exists(recipient_key_id):
            raise FileNotFoundError(
                f"X25519 private key not found for '{recipient_key_id}' in {keys_dir}.\n"
                f"Run: pqhe keygen --name {recipient_key_id} --keys-dir {keys_dir}"
            )

        recipient_x25519_priv = storage.load_x25519_private_key(
            storage.x25519_private_key_path(recipient_key_id)
        )

        recipient_mlkem_priv = None
        if packet.is_hybrid:
            if not storage.mlkem_private_key_exists(recipient_key_id):
                raise FileNotFoundError(
                    f"ML-KEM private key not found for '{recipient_key_id}' in {keys_dir}. "
                    "This packet was encrypted in hybrid mode."
                )
            recipient_mlkem_priv = storage.load_mlkem_private_key(
                storage.mlkem_private_key_path(recipient_key_id)
            )

        log.info(
            "decrypt_controller.decrypt_file.start",
            input=str(input_path),
            recipient=recipient_key_id,
            hybrid=packet.is_hybrid,
        )

        plaintext = self._orchestrator.decrypt(
            packet=packet,
            recipient_x25519_priv=recipient_x25519_priv,
            recipient_mlkem_priv=recipient_mlkem_priv,
        )

        output_path.write_bytes(plaintext)

        log.info(
            "decrypt_controller.decrypt_file.complete",
            output=str(output_path),
            plaintext_size=len(plaintext),
        )

        return DecryptResult(
            input_path=input_path,
            output_path=output_path,
            plaintext_size=len(plaintext),
            algorithm=packet.metadata.algorithm,
        )
