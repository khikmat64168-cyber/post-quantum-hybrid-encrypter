"""Unit tests for the X25519 service layer."""

import pytest

from src.models.key_models import (
    SharedSecretModel,
    X25519PrivateKeyModel,
    X25519PublicKeyModel,
)
from src.services.x25519_service import X25519Service


@pytest.fixture
def service() -> X25519Service:
    return X25519Service()


@pytest.mark.unit
class TestGenerateKeypair:
    def test_returns_tuple_of_models(self, service: X25519Service) -> None:
        priv, pub = service.generate_keypair("alice")
        assert isinstance(priv, X25519PrivateKeyModel)
        assert isinstance(pub, X25519PublicKeyModel)

    def test_key_id_is_set(self, service: X25519Service) -> None:
        priv, pub = service.generate_keypair("alice")
        assert priv.metadata.key_id == "alice"
        assert pub.metadata.key_id == "alice"

    def test_algorithm_is_x25519(self, service: X25519Service) -> None:
        priv, pub = service.generate_keypair("alice")
        assert priv.metadata.algorithm == "X25519"
        assert pub.metadata.algorithm == "X25519"

    def test_private_key_is_32_bytes(self, service: X25519Service) -> None:
        priv, _ = service.generate_keypair("alice")
        assert len(priv.raw_bytes) == 32

    def test_public_key_is_32_bytes(self, service: X25519Service) -> None:
        _, pub = service.generate_keypair("alice")
        assert len(pub.raw_bytes) == 32

    def test_two_keypairs_are_unique(self, service: X25519Service) -> None:
        priv1, _ = service.generate_keypair("alice")
        priv2, _ = service.generate_keypair("bob")
        assert priv1.raw_bytes != priv2.raw_bytes

    def test_private_key_repr_redacts_bytes(self, service: X25519Service) -> None:
        priv, _ = service.generate_keypair("alice")
        assert "REDACTED" in repr(priv)
        assert priv.raw_bytes.hex() not in repr(priv)


@pytest.mark.unit
class TestComputeSharedSecret:
    def test_returns_shared_secret_model(self, service: X25519Service) -> None:
        alice_priv, alice_pub = service.generate_keypair("alice")
        bob_priv, bob_pub = service.generate_keypair("bob")
        secret = service.compute_shared_secret(alice_priv, bob_pub)
        assert isinstance(secret, SharedSecretModel)

    def test_secret_is_32_bytes(self, service: X25519Service) -> None:
        alice_priv, _ = service.generate_keypair("alice")
        _, bob_pub = service.generate_keypair("bob")
        secret = service.compute_shared_secret(alice_priv, bob_pub)
        assert len(secret) == 32

    def test_shared_secret_is_symmetric(self, service: X25519Service) -> None:
        """Both parties must derive the same shared secret."""
        alice_priv, alice_pub = service.generate_keypair("alice")
        bob_priv, bob_pub = service.generate_keypair("bob")

        alice_secret = service.compute_shared_secret(alice_priv, bob_pub)
        bob_secret = service.compute_shared_secret(bob_priv, alice_pub)

        assert alice_secret.raw_bytes == bob_secret.raw_bytes

    def test_different_peers_give_different_secrets(self, service: X25519Service) -> None:
        alice_priv, _ = service.generate_keypair("alice")
        _, bob_pub = service.generate_keypair("bob")
        _, carol_pub = service.generate_keypair("carol")

        s1 = service.compute_shared_secret(alice_priv, bob_pub)
        s2 = service.compute_shared_secret(alice_priv, carol_pub)

        assert s1.raw_bytes != s2.raw_bytes

    def test_secret_repr_redacts_bytes(self, service: X25519Service) -> None:
        alice_priv, _ = service.generate_keypair("alice")
        _, bob_pub = service.generate_keypair("bob")
        secret = service.compute_shared_secret(alice_priv, bob_pub)
        assert "REDACTED" in repr(secret)


@pytest.mark.unit
class TestDeserialization:
    def test_public_key_from_raw_bytes(self, service: X25519Service) -> None:
        _, pub = service.generate_keypair("alice")
        restored = service.public_key_from_raw_bytes(pub.raw_bytes, key_id="alice")
        assert restored.raw_bytes == pub.raw_bytes

    def test_private_key_from_raw_bytes(self, service: X25519Service) -> None:
        priv, _ = service.generate_keypair("alice")
        restored = service.private_key_from_raw_bytes(priv.raw_bytes, key_id="alice")
        assert restored.raw_bytes == priv.raw_bytes

    def test_public_key_from_raw_bytes_bad_length(self, service: X25519Service) -> None:
        with pytest.raises(ValueError):
            service.public_key_from_raw_bytes(b"\x00" * 10)

    def test_private_key_from_raw_bytes_bad_length(self, service: X25519Service) -> None:
        with pytest.raises(ValueError):
            service.private_key_from_raw_bytes(b"\x00" * 10)


@pytest.mark.unit
class TestModelSerialization:
    def test_public_key_to_dict_round_trip(self, service: X25519Service) -> None:
        _, pub = service.generate_keypair("alice")
        restored = X25519PublicKeyModel.from_dict(pub.to_dict())
        assert restored.raw_bytes == pub.raw_bytes
        assert restored.metadata.key_id == pub.metadata.key_id

    def test_private_key_to_dict_round_trip(self, service: X25519Service) -> None:
        priv, _ = service.generate_keypair("alice")
        restored = X25519PrivateKeyModel.from_dict(priv.to_dict())
        assert restored.raw_bytes == priv.raw_bytes
        assert restored.metadata.key_id == priv.metadata.key_id

    def test_to_dict_contains_expected_keys(self, service: X25519Service) -> None:
        priv, pub = service.generate_keypair("alice")
        priv_dict = priv.to_dict()
        pub_dict = pub.to_dict()

        for key in ("key_type", "key_id", "algorithm", "created_at", "raw_bytes_b64"):
            assert key in priv_dict
            assert key in pub_dict

        assert priv_dict["key_type"] == "private"
        assert pub_dict["key_type"] == "public"
