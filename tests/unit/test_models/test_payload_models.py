"""Unit tests for HybridKeyMaterial and AESPayload models."""

import base64
import os

import pytest

from src.models.payload_models import AESPayload, HybridKeyMaterial


# ------------------------------------------------------------------
# HybridKeyMaterial
# ------------------------------------------------------------------

@pytest.mark.unit
class TestHybridKeyMaterial:
    def test_repr_redacts_master_key(self) -> None:
        km = HybridKeyMaterial(
            master_key=os.urandom(32),
            salt=os.urandom(32),
            info=b"pqhe-v1",
        )
        r = repr(km)
        assert "REDACTED" in r
        assert "master_key" in r

    def test_str_uses_repr(self) -> None:
        km = HybridKeyMaterial(master_key=os.urandom(32), salt=os.urandom(32), info=b"x")
        assert str(km) == repr(km)

    def test_to_dict_excludes_master_key(self) -> None:
        km = HybridKeyMaterial(master_key=os.urandom(32), salt=os.urandom(32), info=b"pqhe-v1")
        d = km.to_dict()
        assert "master_key" not in d
        assert "master_key_b64" not in d

    def test_to_dict_contains_salt_b64(self) -> None:
        salt = os.urandom(32)
        km = HybridKeyMaterial(master_key=os.urandom(32), salt=salt, info=b"info")
        d = km.to_dict()
        assert base64.b64decode(d["salt_b64"]) == salt

    def test_to_dict_contains_info(self) -> None:
        km = HybridKeyMaterial(master_key=os.urandom(32), salt=os.urandom(32), info=b"pqhe-v1-aes256gcm")
        d = km.to_dict()
        assert d["info"] == "pqhe-v1-aes256gcm"

    def test_frozen_prevents_mutation(self) -> None:
        km = HybridKeyMaterial(master_key=os.urandom(32), salt=os.urandom(32), info=b"x")
        with pytest.raises((AttributeError, TypeError)):
            km.master_key = b"new"  # type: ignore[misc]

    def test_two_instances_with_same_data_are_equal(self) -> None:
        key = os.urandom(32)
        salt = os.urandom(32)
        a = HybridKeyMaterial(master_key=key, salt=salt, info=b"x")
        b = HybridKeyMaterial(master_key=key, salt=salt, info=b"x")
        assert a == b


# ------------------------------------------------------------------
# AESPayload
# ------------------------------------------------------------------

@pytest.mark.unit
class TestAESPayload:
    def test_repr_shows_sizes_not_contents(self) -> None:
        payload = AESPayload(ciphertext=os.urandom(48), iv=os.urandom(12))
        r = repr(payload)
        assert "48" in r
        assert "12" in r

    def test_to_dict_without_aad(self) -> None:
        payload = AESPayload(ciphertext=b"\x01" * 32, iv=b"\x02" * 12)
        d = payload.to_dict()
        assert "ciphertext_b64" in d
        assert "iv_b64" in d
        assert "aad_b64" not in d

    def test_to_dict_with_aad(self) -> None:
        aad = b"metadata"
        payload = AESPayload(ciphertext=b"\x01" * 32, iv=b"\x02" * 12, aad=aad)
        d = payload.to_dict()
        assert "aad_b64" in d
        assert base64.b64decode(d["aad_b64"]) == aad

    def test_to_dict_ciphertext_roundtrip(self) -> None:
        ct = os.urandom(48)
        payload = AESPayload(ciphertext=ct, iv=os.urandom(12))
        d = payload.to_dict()
        assert base64.b64decode(d["ciphertext_b64"]) == ct

    def test_to_dict_iv_roundtrip(self) -> None:
        iv = os.urandom(12)
        payload = AESPayload(ciphertext=os.urandom(32), iv=iv)
        d = payload.to_dict()
        assert base64.b64decode(d["iv_b64"]) == iv

    def test_from_dict_without_aad(self) -> None:
        ct = os.urandom(32)
        iv = os.urandom(12)
        payload = AESPayload(ciphertext=ct, iv=iv)
        restored = AESPayload.from_dict(payload.to_dict())
        assert restored.ciphertext == ct
        assert restored.iv == iv
        assert restored.aad is None

    def test_from_dict_with_aad(self) -> None:
        ct = os.urandom(32)
        iv = os.urandom(12)
        aad = b"v1|sender|recipient"
        payload = AESPayload(ciphertext=ct, iv=iv, aad=aad)
        restored = AESPayload.from_dict(payload.to_dict())
        assert restored.aad == aad

    def test_frozen_prevents_mutation(self) -> None:
        payload = AESPayload(ciphertext=os.urandom(32), iv=os.urandom(12))
        with pytest.raises((AttributeError, TypeError)):
            payload.iv = b"new"  # type: ignore[misc]

    def test_aad_defaults_to_none(self) -> None:
        payload = AESPayload(ciphertext=b"ct", iv=b"iv_12bytes__")
        assert payload.aad is None
