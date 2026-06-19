"""Unit tests for the HKDF service — hybrid key derivation."""

import pytest

from src.models.key_models import SharedSecretModel
from src.models.payload_models import HybridKeyMaterial
from src.services.hkdf_service import HKDFService


def _make_secret(algo: str = "X25519-ECDH") -> SharedSecretModel:
    """Create a fake 32-byte shared secret for testing."""
    import os
    return SharedSecretModel(raw_bytes=os.urandom(32), algorithm=algo)


@pytest.fixture
def service() -> HKDFService:
    return HKDFService()


@pytest.fixture
def classical_secret() -> SharedSecretModel:
    return _make_secret("X25519-ECDH")


@pytest.fixture
def pq_secret() -> SharedSecretModel:
    return _make_secret("ML-KEM-768")


@pytest.mark.unit
class TestDerive:
    def test_returns_hybrid_key_material(
        self,
        service: HKDFService,
        classical_secret: SharedSecretModel,
        pq_secret: SharedSecretModel,
    ) -> None:
        result = service.derive(classical_secret, pq_secret)
        assert isinstance(result, HybridKeyMaterial)

    def test_master_key_is_32_bytes(
        self,
        service: HKDFService,
        classical_secret: SharedSecretModel,
        pq_secret: SharedSecretModel,
    ) -> None:
        result = service.derive(classical_secret, pq_secret)
        assert len(result.master_key) == 32

    def test_salt_is_32_bytes(
        self,
        service: HKDFService,
        classical_secret: SharedSecretModel,
        pq_secret: SharedSecretModel,
    ) -> None:
        result = service.derive(classical_secret, pq_secret)
        assert len(result.salt) == 32

    def test_info_is_set(
        self,
        service: HKDFService,
        classical_secret: SharedSecretModel,
        pq_secret: SharedSecretModel,
    ) -> None:
        result = service.derive(classical_secret, pq_secret)
        assert result.info == b"pqhe-v1-aes256gcm"

    def test_two_calls_produce_different_salts(
        self,
        service: HKDFService,
        classical_secret: SharedSecretModel,
        pq_secret: SharedSecretModel,
    ) -> None:
        r1 = service.derive(classical_secret, pq_secret)
        r2 = service.derive(classical_secret, pq_secret)
        assert r1.salt != r2.salt

    def test_two_calls_produce_different_keys(
        self,
        service: HKDFService,
        classical_secret: SharedSecretModel,
        pq_secret: SharedSecretModel,
    ) -> None:
        r1 = service.derive(classical_secret, pq_secret)
        r2 = service.derive(classical_secret, pq_secret)
        assert r1.master_key != r2.master_key

    def test_master_key_repr_redacted(
        self,
        service: HKDFService,
        classical_secret: SharedSecretModel,
        pq_secret: SharedSecretModel,
    ) -> None:
        result = service.derive(classical_secret, pq_secret)
        assert "REDACTED" in repr(result)
        assert result.master_key.hex() not in repr(result)

    def test_wrong_classical_secret_length_raises(
        self, service: HKDFService, pq_secret: SharedSecretModel
    ) -> None:
        bad = SharedSecretModel(raw_bytes=b"\x00" * 16, algorithm="X25519-ECDH")
        with pytest.raises(ValueError, match="32 bytes"):
            service.derive(bad, pq_secret)

    def test_wrong_pq_secret_length_raises(
        self, service: HKDFService, classical_secret: SharedSecretModel
    ) -> None:
        bad = SharedSecretModel(raw_bytes=b"\x00" * 16, algorithm="ML-KEM-768")
        with pytest.raises(ValueError, match="32 bytes"):
            service.derive(classical_secret, bad)


@pytest.mark.unit
class TestDeriveWithSalt:
    def test_same_salt_reproduces_same_key(
        self,
        service: HKDFService,
        classical_secret: SharedSecretModel,
        pq_secret: SharedSecretModel,
    ) -> None:
        """Decryption path: re-deriving with the stored salt must give the same key."""
        r1 = service.derive(classical_secret, pq_secret)
        r2 = service.derive_with_salt(classical_secret, pq_secret, salt=r1.salt)
        assert r1.master_key == r2.master_key

    def test_different_salt_different_key(
        self,
        service: HKDFService,
        classical_secret: SharedSecretModel,
        pq_secret: SharedSecretModel,
    ) -> None:
        from src.crypto.hybrid.hkdf import generate_salt
        r1 = service.derive(classical_secret, pq_secret)
        r2 = service.derive_with_salt(classical_secret, pq_secret, salt=generate_salt())
        assert r1.master_key != r2.master_key

    def test_different_classical_secret_different_key(
        self, service: HKDFService, pq_secret: SharedSecretModel
    ) -> None:
        s1 = _make_secret("X25519-ECDH")
        s2 = _make_secret("X25519-ECDH")
        from src.crypto.hybrid.hkdf import generate_salt
        salt = generate_salt()
        r1 = service.derive_with_salt(s1, pq_secret, salt=salt)
        r2 = service.derive_with_salt(s2, pq_secret, salt=salt)
        assert r1.master_key != r2.master_key

    def test_different_pq_secret_different_key(
        self, service: HKDFService, classical_secret: SharedSecretModel
    ) -> None:
        s1 = _make_secret("ML-KEM-768")
        s2 = _make_secret("ML-KEM-768")
        from src.crypto.hybrid.hkdf import generate_salt
        salt = generate_salt()
        r1 = service.derive_with_salt(classical_secret, s1, salt=salt)
        r2 = service.derive_with_salt(classical_secret, s2, salt=salt)
        assert r1.master_key != r2.master_key


@pytest.mark.unit
class TestPayloadModel:
    def test_to_dict_excludes_master_key(
        self,
        service: HKDFService,
        classical_secret: SharedSecretModel,
        pq_secret: SharedSecretModel,
    ) -> None:
        result = service.derive(classical_secret, pq_secret)
        d = result.to_dict()
        assert "master_key" not in d
        assert "salt_b64" in d
        assert "info" in d
