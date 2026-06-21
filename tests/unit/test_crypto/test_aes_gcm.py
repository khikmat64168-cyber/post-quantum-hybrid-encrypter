"""Unit tests for the low-level AES-256-GCM crypto wrapper."""

import os

import pytest
from cryptography.exceptions import InvalidTag

from src.crypto.classical.aes_gcm import (
    IV_SIZE,
    KEY_SIZE,
    TAG_SIZE,
    decrypt,
    encrypt,
    generate_iv,
)

_KEY = os.urandom(KEY_SIZE)
_PLAINTEXT = b"Hello, post-quantum world!"


@pytest.mark.unit
class TestGenerateIV:
    def test_returns_12_bytes(self) -> None:
        assert len(generate_iv()) == IV_SIZE

    def test_two_ivs_are_unique(self) -> None:
        assert generate_iv() != generate_iv()

    def test_returns_bytes(self) -> None:
        assert isinstance(generate_iv(), bytes)


@pytest.mark.unit
class TestEncrypt:
    def test_returns_bytes(self) -> None:
        ct = encrypt(_KEY, generate_iv(), _PLAINTEXT)
        assert isinstance(ct, bytes)

    def test_ciphertext_length_is_plaintext_plus_tag(self) -> None:
        iv = generate_iv()
        ct = encrypt(_KEY, iv, _PLAINTEXT)
        assert len(ct) == len(_PLAINTEXT) + TAG_SIZE

    def test_empty_plaintext(self) -> None:
        ct = encrypt(_KEY, generate_iv(), b"")
        assert len(ct) == TAG_SIZE

    def test_two_encryptions_same_plaintext_different_iv(self) -> None:
        ct1 = encrypt(_KEY, generate_iv(), _PLAINTEXT)
        ct2 = encrypt(_KEY, generate_iv(), _PLAINTEXT)
        assert ct1 != ct2

    def test_wrong_key_length_raises(self) -> None:
        with pytest.raises(ValueError, match=str(KEY_SIZE)):
            encrypt(b"\x00" * 16, generate_iv(), _PLAINTEXT)

    def test_wrong_iv_length_raises(self) -> None:
        with pytest.raises(ValueError, match=str(IV_SIZE)):
            encrypt(_KEY, b"\x00" * 8, _PLAINTEXT)

    def test_with_aad(self) -> None:
        ct = encrypt(_KEY, generate_iv(), _PLAINTEXT, aad=b"metadata")
        assert len(ct) == len(_PLAINTEXT) + TAG_SIZE


@pytest.mark.unit
class TestDecrypt:
    def test_round_trip(self) -> None:
        iv = generate_iv()
        ct = encrypt(_KEY, iv, _PLAINTEXT)
        pt = decrypt(_KEY, iv, ct)
        assert pt == _PLAINTEXT

    def test_empty_plaintext_round_trip(self) -> None:
        iv = generate_iv()
        ct = encrypt(_KEY, iv, b"")
        pt = decrypt(_KEY, iv, ct)
        assert pt == b""

    def test_large_plaintext_round_trip(self) -> None:
        large = os.urandom(1024 * 1024)  # 1 MB
        iv = generate_iv()
        ct = encrypt(_KEY, iv, large)
        pt = decrypt(_KEY, iv, ct)
        assert pt == large

    def test_aad_round_trip(self) -> None:
        iv = generate_iv()
        aad = b"algorithm=AES-256-GCM,version=1"
        ct = encrypt(_KEY, iv, _PLAINTEXT, aad=aad)
        pt = decrypt(_KEY, iv, ct, aad=aad)
        assert pt == _PLAINTEXT

    def test_wrong_key_raises_invalid_tag(self) -> None:
        iv = generate_iv()
        ct = encrypt(_KEY, iv, _PLAINTEXT)
        wrong_key = os.urandom(KEY_SIZE)
        with pytest.raises(InvalidTag):
            decrypt(wrong_key, iv, ct)

    def test_wrong_iv_raises_invalid_tag(self) -> None:
        iv = generate_iv()
        ct = encrypt(_KEY, iv, _PLAINTEXT)
        with pytest.raises(InvalidTag):
            decrypt(_KEY, generate_iv(), ct)

    def test_tampered_ciphertext_raises_invalid_tag(self) -> None:
        iv = generate_iv()
        ct = encrypt(_KEY, iv, _PLAINTEXT)
        tampered = bytearray(ct)
        tampered[0] ^= 0xFF
        with pytest.raises(InvalidTag):
            decrypt(_KEY, iv, bytes(tampered))

    def test_tampered_tag_raises_invalid_tag(self) -> None:
        iv = generate_iv()
        ct = encrypt(_KEY, iv, _PLAINTEXT)
        tampered = bytearray(ct)
        tampered[-1] ^= 0xFF
        with pytest.raises(InvalidTag):
            decrypt(_KEY, iv, bytes(tampered))

    def test_wrong_aad_raises_invalid_tag(self) -> None:
        iv = generate_iv()
        ct = encrypt(_KEY, iv, _PLAINTEXT, aad=b"correct-aad")
        with pytest.raises(InvalidTag):
            decrypt(_KEY, iv, ct, aad=b"wrong-aad")

    def test_missing_aad_raises_invalid_tag(self) -> None:
        iv = generate_iv()
        ct = encrypt(_KEY, iv, _PLAINTEXT, aad=b"required-aad")
        with pytest.raises(InvalidTag):
            decrypt(_KEY, iv, ct, aad=None)

    def test_ciphertext_too_short_raises(self) -> None:
        with pytest.raises(ValueError, match="too short"):
            decrypt(_KEY, generate_iv(), b"\x00" * 4)
