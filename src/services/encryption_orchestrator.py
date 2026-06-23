"""
Encryption orchestrator — ties all cryptographic services together.

This is the top-level service called by controllers. It orchestrates:
    X25519Service → shared secret
    MLKEMService  → PQ shared secret   (optional, requires pyoqs)
    HKDFService   → master key
    AESService    → ciphertext
    PacketService → JSON packet

Encryption protocol (hybrid mode)
-----------------------------------
1. Generate ephemeral X25519 keypair (fresh per message).
2. Compute X25519 shared secret with recipient's long-term X25519 public key.
3. ML-KEM encapsulate using recipient's ML-KEM public key → (ciphertext, pq_secret).
4. HKDF-SHA256(x25519_secret || pq_secret, salt, info) → 32-byte master key.
5. AES-256-GCM encrypt plaintext with master key.
6. Package everything into an EncryptedPacket JSON.

Decryption protocol (hybrid mode)
-----------------------------------
1. Extract ephemeral X25519 public key from packet.
2. Compute X25519 shared secret with recipient's long-term X25519 private key.
3. ML-KEM decapsulate using recipient's ML-KEM private key + packet ciphertext.
4. HKDF re-derive master key using stored salt.
5. AES-256-GCM decrypt.
"""

from __future__ import annotations

from src.models.key_models import (
    MLKEMPrivateKeyModel,
    MLKEMPublicKeyModel,
    X25519PrivateKeyModel,
    X25519PublicKeyModel,
)
from src.models.packet_models import EncryptedPacket
from src.models.payload_models import AESPayload
from src.services.aes_service import AESService, AuthenticationError
from src.services.hkdf_service import HKDFService
from src.services.mlkem_service import MLKEMService
from src.services.packet_service import PacketService
from src.services.x25519_service import X25519Service
from src.utils.logging_config import get_logger

log = get_logger(__name__)


class EncryptionOrchestrator:
    """
    Coordinates all cryptographic services to encrypt and decrypt data.

    Injecting service instances via __init__ makes this testable and
    respects the Dependency Inversion Principle.
    """

    def __init__(
        self,
        x25519_service: X25519Service | None = None,
        mlkem_service: MLKEMService | None = None,
        hkdf_service: HKDFService | None = None,
        aes_service: AESService | None = None,
        packet_service: PacketService | None = None,
    ) -> None:
        self._x25519 = x25519_service or X25519Service()
        self._mlkem = mlkem_service or MLKEMService()
        self._hkdf = hkdf_service or HKDFService()
        self._aes = aes_service or AESService()
        self._packet = packet_service or PacketService()

    # ------------------------------------------------------------------
    # Encrypt
    # ------------------------------------------------------------------

    def encrypt(
        self,
        plaintext: bytes,
        recipient_x25519_pub: X25519PublicKeyModel,
        sender_key_id: str,
        recipient_key_id: str,
        recipient_mlkem_pub: MLKEMPublicKeyModel | None = None,
    ) -> EncryptedPacket:
        """
        Encrypt plaintext for a recipient.

        Parameters
        ----------
        plaintext            : Data to encrypt (arbitrary length).
        recipient_x25519_pub : Recipient's long-term X25519 public key.
        sender_key_id        : Identifier bound into the packet metadata + AAD.
        recipient_key_id     : Identifier bound into the packet metadata + AAD.
        recipient_mlkem_pub  : Recipient's ML-KEM-768 public key.
                               When None, falls back to X25519-only mode.

        Returns
        -------
        EncryptedPacket ready to be serialised to JSON.
        """
        log.info(
            "orchestrator.encrypt.start",
            sender=sender_key_id,
            recipient=recipient_key_id,
            plaintext_size=len(plaintext),
            hybrid=recipient_mlkem_pub is not None,
        )

        # Step 1: ephemeral X25519 keypair
        ephemeral_priv, ephemeral_pub = self._x25519.generate_keypair(
            key_id=f"ephemeral-{sender_key_id}"
        )

        # Step 2: X25519 shared secret
        classical_secret = self._x25519.compute_shared_secret(
            ephemeral_priv, recipient_x25519_pub
        )

        # Step 3: ML-KEM encapsulation (optional)
        mlkem_ciphertext_model = None
        pq_secret = None
        if recipient_mlkem_pub is not None and self._mlkem.is_available():
            mlkem_ciphertext_model, pq_secret = self._mlkem.encapsulate(
                recipient_mlkem_pub
            )

        # Step 4: HKDF — derive master key
        key_material = self._hkdf.derive_hybrid(classical_secret, pq_secret)

        # Step 5: AES-256-GCM — build AAD from metadata first, then encrypt
        from src.models.packet_models import (  # noqa: PLC0415
            ALGORITHM_CLASSICAL,
            ALGORITHM_HYBRID,
            CURRENT_VERSION,
            PacketMetadata,
        )
        from datetime import datetime, timezone  # noqa: PLC0415

        algorithm = ALGORITHM_HYBRID if mlkem_ciphertext_model else ALGORITHM_CLASSICAL
        temp_metadata = PacketMetadata(
            version=CURRENT_VERSION,
            algorithm=algorithm,
            created_at=datetime.now(timezone.utc),
            sender_key_id=sender_key_id,
            recipient_key_id=recipient_key_id,
        )
        aad = temp_metadata.make_aad()
        aes_payload = self._aes.encrypt(key_material, plaintext, aad=aad)

        # Step 6: assemble packet
        packet = self._packet.assemble(
            aes_payload=aes_payload,
            key_material=key_material,
            ephemeral_x25519_pub=ephemeral_pub,
            sender_key_id=sender_key_id,
            recipient_key_id=recipient_key_id,
            mlkem_ciphertext=mlkem_ciphertext_model,
        )

        log.info(
            "orchestrator.encrypt.complete",
            algorithm=algorithm,
            packet_ciphertext_size=len(aes_payload.ciphertext),
        )
        return packet

    # ------------------------------------------------------------------
    # Decrypt
    # ------------------------------------------------------------------

    def decrypt(
        self,
        packet: EncryptedPacket,
        recipient_x25519_priv: X25519PrivateKeyModel,
        recipient_mlkem_priv: MLKEMPrivateKeyModel | None = None,
    ) -> bytes:
        """
        Decrypt an EncryptedPacket.

        Parameters
        ----------
        packet               : EncryptedPacket from encryption or loaded from file.
        recipient_x25519_priv: Recipient's long-term X25519 private key.
        recipient_mlkem_priv : Recipient's ML-KEM-768 private key.
                               Required when packet.is_hybrid is True.

        Returns
        -------
        Original plaintext bytes.

        Raises
        ------
        AuthenticationError   : If AES-GCM tag verification fails.
        ValueError            : If the packet requires ML-KEM but no key provided.
        """
        log.info(
            "orchestrator.decrypt.start",
            sender=packet.metadata.sender_key_id,
            recipient=packet.metadata.recipient_key_id,
            hybrid=packet.is_hybrid,
        )

        self._packet.validate(packet)

        # Step 1: reconstruct ephemeral X25519 public key from packet
        ephemeral_pub = self._x25519.public_key_from_raw_bytes(
            packet.x25519_ephemeral_public_bytes,
            key_id="ephemeral",
        )

        # Step 2: X25519 shared secret
        classical_secret = self._x25519.compute_shared_secret(
            recipient_x25519_priv, ephemeral_pub
        )

        # Step 3: ML-KEM decapsulation (if packet is hybrid)
        pq_secret = None
        if packet.is_hybrid:
            if recipient_mlkem_priv is None:
                raise ValueError(
                    "Packet was encrypted in hybrid mode but no ML-KEM private key provided."
                )
            if not self._mlkem.is_available():
                raise RuntimeError(
                    "Packet requires ML-KEM-768 decapsulation but pyoqs is not installed."
                )
            from src.models.key_models import KeyMetadata, MLKEMCiphertextModel  # noqa: PLC0415
            from datetime import datetime, timezone  # noqa: PLC0415

            ct_model = MLKEMCiphertextModel(
                raw_bytes=packet.mlkem_ciphertext_bytes,  # type: ignore[arg-type]
                metadata=KeyMetadata(
                    key_id=packet.metadata.recipient_key_id,
                    algorithm="ML-KEM-768",
                    created_at=datetime.now(timezone.utc),
                ),
            )
            pq_secret = self._mlkem.decapsulate(recipient_mlkem_priv, ct_model)

        # Step 4: HKDF re-derive master key with stored salt
        key_material = self._hkdf.derive_hybrid(
            classical_secret, pq_secret, salt=packet.hkdf_salt_bytes
        )

        # Step 5: AES-256-GCM decrypt
        aad = packet.metadata.make_aad()
        aes_payload = AESPayload(
            ciphertext=packet.ciphertext_bytes,
            iv=packet.iv_bytes,
            aad=aad,
        )
        plaintext = self._aes.decrypt(key_material, aes_payload)

        log.info(
            "orchestrator.decrypt.complete",
            plaintext_size=len(plaintext),
        )
        return plaintext
