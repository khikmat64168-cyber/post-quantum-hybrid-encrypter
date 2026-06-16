"""
Unit tests for the ML-KEM-768 service layer.

All tests are skipped automatically if pyoqs/liboqs is not installed.
To install:
    brew install liboqs   (macOS)
    pip install pyoqs
"""

import pytest

pytest.importorskip("oqs", reason="pyoqs/liboqs not installed — skipping ML-KEM tests")

from src.models.key_models import (  # noqa: E402
    MLKEMCiphertextModel,
    MLKEMPrivateKeyModel,
    MLKEMPublicKeyModel,
    SharedSecretModel,
)
from src.services.mlkem_service import MLKEMService  # noqa: E402


@pytest.fixture
def service() -> MLKEMService:
    return MLKEMService()


@pytest.mark.unit
class TestAvailability:
    def test_is_available(self, service: MLKEMService) -> None:
        assert service.is_available() is True


@pytest.mark.unit
class TestGenerateKeypair:
    def test_returns_private_and_public_models(self, service: MLKEMService) -> None:
        priv, pub = service.generate_keypair("alice")
        assert isinstance(priv, MLKEMPrivateKeyModel)
        assert isinstance(pub, MLKEMPublicKeyModel)

    def test_key_id_propagated(self, service: MLKEMService) -> None:
        priv, pub = service.generate_keypair("alice")
        assert priv.metadata.key_id == "alice"
        assert pub.metadata.key_id == "alice"

    def test_algorithm_label(self, service: MLKEMService) -> None:
        priv, pub = service.generate_keypair("alice")
        assert priv.metadata.algorithm == "ML-KEM-768"
        assert pub.metadata.algorithm == "ML-KEM-768"

    def test_public_key_size(self, service: MLKEMService) -> None:
        _, pub = service.generate_keypair("alice")
        assert len(pub.raw_bytes) == 1184

    def test_private_key_size(self, service: MLKEMService) -> None:
        priv, _ = service.generate_keypair("alice")
        assert len(priv.raw_bytes) == 2400

    def test_two_keypairs_are_distinct(self, service: MLKEMService) -> None:
        _, pub1 = service.generate_keypair("alice")
        _, pub2 = service.generate_keypair("bob")
        assert pub1.raw_bytes != pub2.raw_bytes

    def test_private_key_repr_redacted(self, service: MLKEMService) -> None:
        priv, _ = service.generate_keypair("alice")
        assert "REDACTED" in repr(priv)
        assert priv.raw_bytes.hex() not in repr(priv)


@pytest.mark.unit
class TestEncapsulation:
    def test_returns_ciphertext_and_secret(self, service: MLKEMService) -> None:
        _, pub = service.generate_keypair("alice")
        ct, ss = service.encapsulate(pub)
        assert isinstance(ct, MLKEMCiphertextModel)
        assert isinstance(ss, SharedSecretModel)

    def test_ciphertext_size(self, service: MLKEMService) -> None:
        _, pub = service.generate_keypair("alice")
        ct, _ = service.encapsulate(pub)
        assert len(ct.raw_bytes) == 1088

    def test_shared_secret_size(self, service: MLKEMService) -> None:
        _, pub = service.generate_keypair("alice")
        _, ss = service.encapsulate(pub)
        assert len(ss.raw_bytes) == 32

    def test_shared_secret_algorithm_label(self, service: MLKEMService) -> None:
        _, pub = service.generate_keypair("alice")
        _, ss = service.encapsulate(pub)
        assert ss.algorithm == "ML-KEM-768"

    def test_shared_secret_repr_redacted(self, service: MLKEMService) -> None:
        _, pub = service.generate_keypair("alice")
        _, ss = service.encapsulate(pub)
        assert "REDACTED" in repr(ss)


@pytest.mark.unit
class TestDecapsulation:
    def test_returns_shared_secret_model(self, service: MLKEMService) -> None:
        priv, pub = service.generate_keypair("alice")
        ct, _ = service.encapsulate(pub)
        ss = service.decapsulate(priv, ct)
        assert isinstance(ss, SharedSecretModel)

    def test_shared_secret_is_symmetric(self, service: MLKEMService) -> None:
        """Sender and recipient must derive the identical shared secret."""
        priv, pub = service.generate_keypair("alice")
        ct, ss_sender = service.encapsulate(pub)
        ss_recipient = service.decapsulate(priv, ct)
        assert ss_sender.raw_bytes == ss_recipient.raw_bytes

    def test_shared_secret_size(self, service: MLKEMService) -> None:
        priv, pub = service.generate_keypair("alice")
        ct, _ = service.encapsulate(pub)
        ss = service.decapsulate(priv, ct)
        assert len(ss.raw_bytes) == 32

    def test_different_recipients_different_secrets(self, service: MLKEMService) -> None:
        priv_a, pub_a = service.generate_keypair("alice")
        priv_b, pub_b = service.generate_keypair("bob")
        ct_a, ss_a = service.encapsulate(pub_a)
        ct_b, ss_b = service.encapsulate(pub_b)
        assert ss_a.raw_bytes != ss_b.raw_bytes


@pytest.mark.unit
class TestModelSerialisation:
    def test_mlkem_public_key_round_trip(self, service: MLKEMService) -> None:
        _, pub = service.generate_keypair("alice")
        restored = MLKEMPublicKeyModel.from_dict(pub.to_dict())
        assert restored.raw_bytes == pub.raw_bytes
        assert restored.metadata.key_id == "alice"

    def test_mlkem_private_key_round_trip(self, service: MLKEMService) -> None:
        priv, _ = service.generate_keypair("alice")
        restored = MLKEMPrivateKeyModel.from_dict(priv.to_dict())
        assert restored.raw_bytes == priv.raw_bytes

    def test_mlkem_ciphertext_round_trip(self, service: MLKEMService) -> None:
        _, pub = service.generate_keypair("alice")
        ct, _ = service.encapsulate(pub)
        restored = MLKEMCiphertextModel.from_dict(ct.to_dict())
        assert restored.raw_bytes == ct.raw_bytes

    def test_to_dict_key_type_fields(self, service: MLKEMService) -> None:
        priv, pub = service.generate_keypair("alice")
        ct, _ = service.encapsulate(pub)
        assert priv.to_dict()["key_type"] == "private"
        assert pub.to_dict()["key_type"] == "public"
        assert ct.to_dict()["key_type"] == "ciphertext"
