"""Unit tests for the low-level HKDF-SHA-256 crypto wrapper."""

import pytest

from src.crypto.hybrid.hkdf import derive, generate_salt


@pytest.mark.unit
class TestGenerateSalt:
    def test_returns_32_bytes(self) -> None:
        assert len(generate_salt()) == 32

    def test_returns_bytes(self) -> None:
        assert isinstance(generate_salt(), bytes)

    def test_two_salts_are_unique(self) -> None:
        assert generate_salt() != generate_salt()


@pytest.mark.unit
class TestDerive:
    def test_returns_32_bytes_by_default(self) -> None:
        key = derive(ikm=b"\x01" * 64, salt=generate_salt(), info=b"test")
        assert len(key) == 32

    def test_returns_bytes(self) -> None:
        key = derive(ikm=b"\x01" * 64, salt=generate_salt(), info=b"test")
        assert isinstance(key, bytes)

    def test_custom_length(self) -> None:
        key = derive(ikm=b"\x01" * 64, salt=generate_salt(), info=b"test", length=16)
        assert len(key) == 16

    def test_same_inputs_same_output(self) -> None:
        salt = generate_salt()
        ikm = b"\xab" * 64
        info = b"pqhe-v1"
        k1 = derive(ikm=ikm, salt=salt, info=info)
        k2 = derive(ikm=ikm, salt=salt, info=info)
        assert k1 == k2

    def test_different_salt_different_output(self) -> None:
        ikm = b"\xab" * 64
        info = b"pqhe-v1"
        k1 = derive(ikm=ikm, salt=generate_salt(), info=info)
        k2 = derive(ikm=ikm, salt=generate_salt(), info=info)
        assert k1 != k2

    def test_different_ikm_different_output(self) -> None:
        salt = generate_salt()
        info = b"pqhe-v1"
        k1 = derive(ikm=b"\x01" * 64, salt=salt, info=info)
        k2 = derive(ikm=b"\x02" * 64, salt=salt, info=info)
        assert k1 != k2

    def test_different_info_different_output(self) -> None:
        salt = generate_salt()
        ikm = b"\xab" * 64
        k1 = derive(ikm=ikm, salt=salt, info=b"context-a")
        k2 = derive(ikm=ikm, salt=salt, info=b"context-b")
        assert k1 != k2

    def test_empty_salt_raises(self) -> None:
        with pytest.raises(ValueError, match="salt"):
            derive(ikm=b"\x01" * 64, salt=b"", info=b"test")

    def test_empty_ikm_raises(self) -> None:
        with pytest.raises(ValueError, match="IKM"):
            derive(ikm=b"", salt=generate_salt(), info=b"test")

    def test_output_is_not_ikm(self) -> None:
        ikm = b"\xaa" * 64
        key = derive(ikm=ikm, salt=generate_salt(), info=b"test")
        assert key != ikm[:32]
