"""Argon2id password-based key derivation — thin wrapper over argon2-cffi."""

from __future__ import annotations

import os

from argon2.low_level import Type, hash_secret_raw

# OWASP-recommended parameters for interactive logins (2024 guidance)
_TIME_COST = 3
_MEMORY_COST = 65536  # 64 MiB
_PARALLELISM = 4
_SALT_SIZE = 16
_HASH_LEN = 32


def new_salt() -> bytes:
    return os.urandom(_SALT_SIZE)


def derive_key(
    passphrase: str,
    salt: bytes,
    *,
    time_cost: int = _TIME_COST,
    memory_cost: int = _MEMORY_COST,
    parallelism: int = _PARALLELISM,
    hash_len: int = _HASH_LEN,
) -> bytes:
    """Derive a fixed-length key from a passphrase using Argon2id."""
    return hash_secret_raw(
        secret=passphrase.encode(),
        salt=salt,
        time_cost=time_cost,
        memory_cost=memory_cost,
        parallelism=parallelism,
        hash_len=hash_len,
        type=Type.ID,
    )
