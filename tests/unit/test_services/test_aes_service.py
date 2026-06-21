"""Unit tests for the AES service — authenticated encryption/decryption."""

import os

import pytest

from src.models.payload_models import AESPayload, HybridKeyMaterial
from src.services.aes_service import AESService, AuthenticationError


def _make_key_material(master_key: bytes | None = None) -> HybridKeyMaterial:
    return HybridKeyMaterial(
        master_key=master_key or os.urandom(32),
        salt=os.urandom(32),
        info=b"pqhe-v1-aes256gcm",
    )


@pytest.fixture
def service() -> AESService:
    return AESService()


@pytest.fixture
def key_material() -> HybridKeyMaterial:
    return _make_key_material()


@pytest.mark.unit
class TestEncrypt:
    def test_returns_aes_payload(
        self, service: AESService, key_material: HybridKeyMaterial
    ) -> None:
        payload = service.encrypt(key_material, b"hello")
        assert isinstance(payload, AESPayload)

    def test_iv_is_12_bytes(
        self, service: AESService, key_material: HybridKeyMaterial
    ) -> None:
        payload = service.encrypt(key_material, b"hello")
        assert len(payload.iv) == 12

    def test_ciphertext_size(
        self, service: AESService, key_material: HybridKeyMaterial
    ) -> None:
        plaintext = b"hello world"
        payload = service.encrypt(key_material, plaintext)
        assert len(payload.ciphertext) == len(plaintext) + 16

    def test_two_encryptions_produce_different_ivs(
        self, service: AESService, key_material: HybridKeyMaterial
    ) -> None:
        p1 = service.encrypt(key_material, b"same plaintext")
        p2 = service.encrypt(key_material, b"same plaintext")
        assert p1.iv != p2.iv
        assert p1.ciphertext != p2.ciphertext

    def test_encrypt_with_aad(
        self, service: AESService, key_material: HybridKeyMaterial
    ) -> None:
        payload = service.encrypt(key_material, b"data", aad=b"metadata")
        assert payload.aad == b"metadata"

    def test_encrypt_without_aad(
        self, service: AESService, key_material: HybridKeyMaterial
    ) -> None:
        payload = service.encrypt(key_material, b"data")
        assert payload.aad is None


@pytest.mark.unit
class TestDecrypt:
    def test_round_trip(
        self, service: AESService, key_material: HybridKeyMaterial
    ) -> None:
        plaintext = b"top secret message"
        payload = service.encrypt(key_material, plaintext)
        result = service.decrypt(key_material, payload)
        assert result == plaintext

    def test_round_trip_with_aad(
        self, service: AESService, key_material: HybridKeyMaterial
    ) -> None:
        plaintext = b"top secret"
        aad = b"algorithm=AES-256-GCM"
        payload = service.encrypt(key_material, plaintext, aad=aad)
        result = service.decrypt(key_material, payload)
        assert result == plaintext

    def test_empty_plaintext_round_trip(
        self, service: AESService, key_material: HybridKeyMaterial
    ) -> None:
        payload = service.encrypt(key_material, b"")
        assert service.decrypt(key_material, payload) == b""

    def test_large_plaintext_round_trip(
        self, service: AESService, key_material: HybridKeyMaterial
    ) -> None:
        plaintext = os.urandom(512 * 1024)
        payload = service.encrypt(key_material, plaintext)
        assert service.decrypt(key_material, payload) == plaintext

    def test_wrong_key_raises_authentication_error(
        self, service: AESService, key_material: HybridKeyMaterial
    ) -> None:
        payload = service.encrypt(key_material, b"secret")
        wrong_km = _make_key_material()
        with pytest.raises(AuthenticationError):
            service.decrypt(wrong_km, payload)

    def test_tampered_ciphertext_raises_authentication_error(
        self, service: AESService, key_material: HybridKeyMaterial
    ) -> None:
        payload = service.encrypt(key_material, b"secret")
        tampered = bytearray(payload.ciphertext)
        tampered[0] ^= 0xFF
        bad_payload = AESPayload(
            ciphertext=bytes(tampered), iv=payload.iv, aad=payload.aad
        )
        with pytest.raises(AuthenticationError):
            service.decrypt(key_material, bad_payload)

    def test_wrong_aad_raises_authentication_error(
        self, service: AESService, key_material: HybridKeyMaterial
    ) -> None:
        payload = service.encrypt(key_material, b"secret", aad=b"correct")
        bad_payload = AESPayload(
            ciphertext=payload.ciphertext, iv=payload.iv, aad=b"wrong"
        )
        with pytest.raises(AuthenticationError):
            service.decrypt(key_material, bad_payload)


@pytest.mark.unit
class TestAESPayloadModel:
    def test_to_dict_round_trip(
        self, service: AESService, key_material: HybridKeyMaterial
    ) -> None:
        payload = service.encrypt(key_material, b"hello")
        restored = AESPayload.from_dict(payload.to_dict())
        assert restored.ciphertext == payload.ciphertext
        assert restored.iv == payload.iv

    def test_to_dict_with_aad_round_trip(
        self, service: AESService, key_material: HybridKeyMaterial
    ) -> None:
        payload = service.encrypt(key_material, b"hello", aad=b"context")
        restored = AESPayload.from_dict(payload.to_dict())
        assert restored.aad == b"context"

    def test_to_dict_without_aad_has_no_aad_key(
        self, service: AESService, key_material: HybridKeyMaterial
    ) -> None:
        payload = service.encrypt(key_material, b"hello")
        d = payload.to_dict()
        assert "aad_b64" not in d

    def test_repr_does_not_expose_ciphertext(
        self, service: AESService, key_material: HybridKeyMaterial
    ) -> None:
        payload = service.encrypt(key_material, b"secret")
        r = repr(payload)
        assert payload.ciphertext.hex() not in r
        assert "bytes" in r
