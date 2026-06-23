"""
Packet service — assembly, disassembly, validation, and serialisation.

This service has no cryptographic logic. It converts between the typed
object graph (AESPayload, HybridKeyMaterial, key models) and the
wire-format EncryptedPacket that is written to disk or sent over a network.
"""

from __future__ import annotations

import base64
import json
from datetime import datetime, timezone

from src.models.key_models import MLKEMCiphertextModel, X25519PublicKeyModel
from src.models.packet_models import (
    ALGORITHM_CLASSICAL,
    ALGORITHM_HYBRID,
    CURRENT_VERSION,
    EncryptedPacket,
    PacketMetadata,
)
from src.models.payload_models import AESPayload, HybridKeyMaterial
from src.utils.logging_config import get_logger

log = get_logger(__name__)

_SUPPORTED_VERSIONS = frozenset({"1"})
_REQUIRED_FIELDS = frozenset({
    "version", "algorithm", "created_at",
    "sender_key_id", "recipient_key_id",
    "x25519_ephemeral_public_b64",
    "hkdf_salt_b64", "iv_b64", "ciphertext_b64",
})


class PacketValidationError(Exception):
    """Raised when an EncryptedPacket fails structural or semantic validation."""


class UnsupportedVersionError(PacketValidationError):
    """Raised when a packet's version field is not in _SUPPORTED_VERSIONS."""


class PacketService:
    """Assembles, validates, and serialises EncryptedPacket objects."""

    # ------------------------------------------------------------------
    # Assembly
    # ------------------------------------------------------------------

    def assemble(
        self,
        aes_payload: AESPayload,
        key_material: HybridKeyMaterial,
        ephemeral_x25519_pub: X25519PublicKeyModel,
        sender_key_id: str,
        recipient_key_id: str,
        mlkem_ciphertext: MLKEMCiphertextModel | None = None,
    ) -> EncryptedPacket:
        """
        Combine all encryption outputs into a single EncryptedPacket.

        Parameters
        ----------
        aes_payload        : Output of AESService.encrypt().
        key_material       : Output of HKDFService — provides the HKDF salt.
        ephemeral_x25519_pub: Sender's ephemeral X25519 public key.
        sender_key_id      : Human-readable identifier for the sender.
        recipient_key_id   : Human-readable identifier for the recipient.
        mlkem_ciphertext   : ML-KEM-768 ciphertext (None for X25519-only mode).
        """
        algorithm = ALGORITHM_HYBRID if mlkem_ciphertext else ALGORITHM_CLASSICAL

        metadata = PacketMetadata(
            version=CURRENT_VERSION,
            algorithm=algorithm,
            created_at=datetime.now(timezone.utc),
            sender_key_id=sender_key_id,
            recipient_key_id=recipient_key_id,
        )

        packet = EncryptedPacket(
            metadata=metadata,
            x25519_ephemeral_public_b64=base64.b64encode(
                ephemeral_x25519_pub.raw_bytes
            ).decode(),
            mlkem_ciphertext_b64=(
                base64.b64encode(mlkem_ciphertext.raw_bytes).decode()
                if mlkem_ciphertext
                else None
            ),
            hkdf_salt_b64=base64.b64encode(key_material.salt).decode(),
            iv_b64=base64.b64encode(aes_payload.iv).decode(),
            ciphertext_b64=base64.b64encode(aes_payload.ciphertext).decode(),
        )

        log.info(
            "packet_service.assemble",
            algorithm=algorithm,
            sender=sender_key_id,
            recipient=recipient_key_id,
            ciphertext_size=len(aes_payload.ciphertext),
        )
        return packet

    # ------------------------------------------------------------------
    # Disassembly
    # ------------------------------------------------------------------

    def disassemble(self, packet: EncryptedPacket) -> dict[str, bytes | None]:
        """
        Extract raw bytes from a validated packet for use by the decryption path.

        Returns a dict with keys:
            x25519_ephemeral_public  : bytes (32)
            mlkem_ciphertext         : bytes | None
            hkdf_salt                : bytes (32)
            iv                       : bytes (12)
            ciphertext               : bytes
        """
        self.validate(packet)
        return {
            "x25519_ephemeral_public": packet.x25519_ephemeral_public_bytes,
            "mlkem_ciphertext": packet.mlkem_ciphertext_bytes,
            "hkdf_salt": packet.hkdf_salt_bytes,
            "iv": packet.iv_bytes,
            "ciphertext": packet.ciphertext_bytes,
        }

    # ------------------------------------------------------------------
    # Serialisation
    # ------------------------------------------------------------------

    def to_json(self, packet: EncryptedPacket, *, indent: int = 2) -> str:
        """Serialise a packet to a pretty-printed JSON string."""
        return packet.to_json(indent=indent)

    def from_json(self, json_str: str) -> EncryptedPacket:
        """Deserialise and validate a packet from a JSON string."""
        try:
            data = json.loads(json_str)
        except json.JSONDecodeError as exc:
            raise PacketValidationError(f"Invalid JSON: {exc}") from exc

        packet = EncryptedPacket.from_dict(data)
        self.validate(packet)
        return packet

    def save_to_file(self, packet: EncryptedPacket, path: str) -> None:
        """Write a packet as JSON to a file."""
        import os
        from pathlib import Path

        p = Path(path)
        p.write_text(self.to_json(packet), encoding="utf-8")
        os.chmod(p, 0o644)
        log.info("packet_service.save_to_file", path=path)

    def load_from_file(self, path: str) -> EncryptedPacket:
        """Read and validate a packet from a JSON file."""
        from pathlib import Path

        text = Path(path).read_text(encoding="utf-8")
        packet = self.from_json(text)
        log.info("packet_service.load_from_file", path=path)
        return packet

    # ------------------------------------------------------------------
    # Validation
    # ------------------------------------------------------------------

    def validate(self, packet: EncryptedPacket) -> None:
        """
        Validate packet structure and field lengths.

        Raises
        ------
        UnsupportedVersionError   : Unknown version string.
        PacketValidationError     : Missing fields, wrong binary lengths, etc.
        """
        if packet.metadata.version not in _SUPPORTED_VERSIONS:
            raise UnsupportedVersionError(
                f"Unsupported packet version '{packet.metadata.version}'. "
                f"Supported: {sorted(_SUPPORTED_VERSIONS)}"
            )

        self._validate_base64_field(
            packet.x25519_ephemeral_public_b64,
            field="x25519_ephemeral_public_b64",
            expected_len=32,
        )
        self._validate_base64_field(
            packet.hkdf_salt_b64,
            field="hkdf_salt_b64",
            expected_len=32,
        )
        self._validate_base64_field(
            packet.iv_b64,
            field="iv_b64",
            expected_len=12,
        )

        ct_bytes = base64.b64decode(packet.ciphertext_b64)
        if len(ct_bytes) < 16:
            raise PacketValidationError(
                f"ciphertext_b64 too short to contain a 16-byte auth tag "
                f"(decoded {len(ct_bytes)} bytes)"
            )

        if packet.mlkem_ciphertext_b64 is not None:
            self._validate_base64_field(
                packet.mlkem_ciphertext_b64,
                field="mlkem_ciphertext_b64",
                expected_len=1088,
            )

        if not packet.metadata.sender_key_id.strip():
            raise PacketValidationError("sender_key_id must not be empty")
        if not packet.metadata.recipient_key_id.strip():
            raise PacketValidationError("recipient_key_id must not be empty")

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _validate_base64_field(
        self, value: str, *, field: str, expected_len: int
    ) -> None:
        try:
            decoded = base64.b64decode(value)
        except Exception as exc:
            raise PacketValidationError(
                f"'{field}' is not valid base64: {exc}"
            ) from exc
        if len(decoded) != expected_len:
            raise PacketValidationError(
                f"'{field}' decoded to {len(decoded)} bytes, expected {expected_len}"
            )
