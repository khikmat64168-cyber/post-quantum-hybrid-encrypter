"""Unit tests for the low-level X25519 crypto wrapper."""

import pytest
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey

from src.crypto.classical import x25519 as _x25519


@pytest.mark.unit
class TestKeyGeneration:
    def test_generate_returns_private_key(self) -> None:
        key = _x25519.generate_private_key()
        assert isinstance(key, X25519PrivateKey)

    def test_derive_public_key(self) -> None:
        private_key = _x25519.generate_private_key()
        public_key = _x25519.derive_public_key(private_key)
        assert isinstance(public_key, X25519PublicKey)

    def test_two_keypairs_are_different(self) -> None:
        k1 = _x25519.generate_private_key()
        k2 = _x25519.generate_private_key()
        assert _x25519.private_key_to_raw(k1) != _x25519.private_key_to_raw(k2)


@pytest.mark.unit
class TestSerialization:
    def test_private_key_to_raw_is_32_bytes(self) -> None:
        key = _x25519.generate_private_key()
        raw = _x25519.private_key_to_raw(key)
        assert len(raw) == 32

    def test_public_key_to_raw_is_32_bytes(self) -> None:
        key = _x25519.generate_private_key()
        pub = _x25519.derive_public_key(key)
        raw = _x25519.public_key_to_raw(pub)
        assert len(raw) == 32

    def test_private_key_round_trip(self) -> None:
        original = _x25519.generate_private_key()
        raw = _x25519.private_key_to_raw(original)
        restored = _x25519.private_key_from_raw(raw)
        assert _x25519.private_key_to_raw(restored) == raw

    def test_public_key_round_trip(self) -> None:
        private_key = _x25519.generate_private_key()
        pub = _x25519.derive_public_key(private_key)
        raw = _x25519.public_key_to_raw(pub)
        restored = _x25519.public_key_from_raw(raw)
        assert _x25519.public_key_to_raw(restored) == raw

    def test_private_key_from_raw_invalid_length(self) -> None:
        with pytest.raises(ValueError, match="32 bytes"):
            _x25519.private_key_from_raw(b"\x00" * 16)

    def test_public_key_from_raw_invalid_length(self) -> None:
        with pytest.raises(ValueError, match="32 bytes"):
            _x25519.public_key_from_raw(b"\x00" * 64)


@pytest.mark.unit
class TestKeyExchange:
    def test_shared_secret_is_32_bytes(self) -> None:
        alice_priv = _x25519.generate_private_key()
        bob_priv = _x25519.generate_private_key()
        bob_pub = _x25519.derive_public_key(bob_priv)
        secret = _x25519.exchange(alice_priv, bob_pub)
        assert len(secret) == 32

    def test_shared_secret_is_symmetric(self) -> None:
        """Alice and Bob must derive identical shared secrets."""
        alice_priv = _x25519.generate_private_key()
        bob_priv = _x25519.generate_private_key()

        alice_pub = _x25519.derive_public_key(alice_priv)
        bob_pub = _x25519.derive_public_key(bob_priv)

        alice_secret = _x25519.exchange(alice_priv, bob_pub)
        bob_secret = _x25519.exchange(bob_priv, alice_pub)

        assert alice_secret == bob_secret

    def test_different_pairs_produce_different_secrets(self) -> None:
        alice_priv = _x25519.generate_private_key()
        bob_priv = _x25519.generate_private_key()
        carol_priv = _x25519.generate_private_key()

        bob_pub = _x25519.derive_public_key(bob_priv)
        carol_pub = _x25519.derive_public_key(carol_priv)

        secret_ab = _x25519.exchange(alice_priv, bob_pub)
        secret_ac = _x25519.exchange(alice_priv, carol_pub)

        assert secret_ab != secret_ac

    def test_shared_secret_is_bytes(self) -> None:
        priv = _x25519.generate_private_key()
        pub = _x25519.derive_public_key(_x25519.generate_private_key())
        assert isinstance(_x25519.exchange(priv, pub), bytes)
