"""
Unit tests for the low-level ML-KEM-768 crypto wrapper.

All tests in this file are skipped automatically if pyoqs/liboqs is not installed.
To install:
    brew install liboqs   (macOS)
    pip install pyoqs
"""

import pytest

# Skip entire module if pyoqs is not available
pytest.importorskip("oqs", reason="pyoqs/liboqs not installed — skipping ML-KEM tests")

from src.crypto.post_quantum import ml_kem as _ml_kem  # noqa: E402


@pytest.mark.unit
class TestAvailability:
    def test_is_available_returns_true(self) -> None:
        assert _ml_kem.is_available() is True


@pytest.mark.unit
class TestKeyGeneration:
    def test_generate_keypair_returns_two_byte_strings(self) -> None:
        pub, sec = _ml_kem.generate_keypair()
        assert isinstance(pub, bytes)
        assert isinstance(sec, bytes)

    def test_public_key_size(self) -> None:
        pub, _ = _ml_kem.generate_keypair()
        assert len(pub) == _ml_kem.PUBLIC_KEY_SIZE

    def test_secret_key_size(self) -> None:
        _, sec = _ml_kem.generate_keypair()
        assert len(sec) == _ml_kem.SECRET_KEY_SIZE

    def test_two_keypairs_are_distinct(self) -> None:
        pub1, sec1 = _ml_kem.generate_keypair()
        pub2, sec2 = _ml_kem.generate_keypair()
        assert pub1 != pub2
        assert sec1 != sec2


@pytest.mark.unit
class TestEncapsulation:
    def test_encapsulate_returns_ciphertext_and_secret(self) -> None:
        pub, _ = _ml_kem.generate_keypair()
        ct, ss = _ml_kem.encapsulate(pub)
        assert isinstance(ct, bytes)
        assert isinstance(ss, bytes)

    def test_ciphertext_size(self) -> None:
        pub, _ = _ml_kem.generate_keypair()
        ct, _ = _ml_kem.encapsulate(pub)
        assert len(ct) == _ml_kem.CIPHERTEXT_SIZE

    def test_shared_secret_size(self) -> None:
        pub, _ = _ml_kem.generate_keypair()
        _, ss = _ml_kem.encapsulate(pub)
        assert len(ss) == _ml_kem.SHARED_SECRET_SIZE

    def test_encapsulate_invalid_public_key_length(self) -> None:
        with pytest.raises(ValueError, match=str(_ml_kem.PUBLIC_KEY_SIZE)):
            _ml_kem.encapsulate(b"\x00" * 32)


@pytest.mark.unit
class TestDecapsulation:
    def test_decapsulate_returns_bytes(self) -> None:
        pub, sec = _ml_kem.generate_keypair()
        ct, _ = _ml_kem.encapsulate(pub)
        ss_dec = _ml_kem.decapsulate(sec, ct)
        assert isinstance(ss_dec, bytes)

    def test_shared_secret_is_symmetric(self) -> None:
        """Sender and recipient must derive the identical shared secret."""
        pub, sec = _ml_kem.generate_keypair()
        ct, ss_enc = _ml_kem.encapsulate(pub)
        ss_dec = _ml_kem.decapsulate(sec, ct)
        assert ss_enc == ss_dec

    def test_shared_secret_size_after_decap(self) -> None:
        pub, sec = _ml_kem.generate_keypair()
        ct, _ = _ml_kem.encapsulate(pub)
        ss = _ml_kem.decapsulate(sec, ct)
        assert len(ss) == _ml_kem.SHARED_SECRET_SIZE

    def test_different_keypairs_give_different_secrets(self) -> None:
        pub1, sec1 = _ml_kem.generate_keypair()
        pub2, sec2 = _ml_kem.generate_keypair()
        ct1, ss_enc1 = _ml_kem.encapsulate(pub1)
        ct2, ss_enc2 = _ml_kem.encapsulate(pub2)
        ss_dec1 = _ml_kem.decapsulate(sec1, ct1)
        ss_dec2 = _ml_kem.decapsulate(sec2, ct2)
        assert ss_enc1 == ss_dec1
        assert ss_enc2 == ss_dec2
        assert ss_enc1 != ss_enc2

    def test_wrong_secret_key_gives_different_secret(self) -> None:
        pub, sec_correct = _ml_kem.generate_keypair()
        _, sec_wrong = _ml_kem.generate_keypair()
        ct, ss_enc = _ml_kem.encapsulate(pub)
        ss_dec_wrong = _ml_kem.decapsulate(sec_wrong, ct)
        assert ss_enc != ss_dec_wrong

    def test_decapsulate_invalid_secret_key_length(self) -> None:
        pub, _ = _ml_kem.generate_keypair()
        ct, _ = _ml_kem.encapsulate(pub)
        with pytest.raises(ValueError, match=str(_ml_kem.SECRET_KEY_SIZE)):
            _ml_kem.decapsulate(b"\x00" * 32, ct)

    def test_decapsulate_invalid_ciphertext_length(self) -> None:
        _, sec = _ml_kem.generate_keypair()
        with pytest.raises(ValueError, match=str(_ml_kem.CIPHERTEXT_SIZE)):
            _ml_kem.decapsulate(sec, b"\x00" * 32)
