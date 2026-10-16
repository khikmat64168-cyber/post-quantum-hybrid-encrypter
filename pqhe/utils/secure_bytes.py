"""
Secure memory utilities for sensitive byte buffers.

Uses ctypes to overwrite mutable bytearray memory before the object
is garbage-collected. This reduces (but cannot eliminate) the window
during which secret material lives in process memory.

Limitations:
- Only effective on `bytearray`, not on `bytes` (which is immutable).
- CPython may hold internal copies. This is best-effort, not guaranteed.
- On PyPy or other interpreters, ctypes memory semantics differ.
"""

from __future__ import annotations

import ctypes


def wipe(data: bytearray) -> None:
    """
    Overwrite a bytearray's backing memory with zeros in-place.

    Call this immediately after the sensitive value is no longer needed:

        secret = bytearray(get_shared_secret())
        try:
            use(secret)
        finally:
            wipe(secret)
    """
    if not isinstance(data, bytearray):
        raise TypeError(f"wipe() requires a bytearray, got {type(data).__name__}")
    n = len(data)
    if n == 0:
        return
    buf = (ctypes.c_char * n).from_buffer(data)
    ctypes.memset(ctypes.addressof(buf), 0, n)


def wipe_bytes_copy(data: bytes) -> bytearray:
    """
    Copy an immutable `bytes` object into a mutable `bytearray` so it
    can later be wiped with `wipe()`.

    Use when you receive a `bytes` secret from a third-party library
    that you need to hold temporarily.
    """
    return bytearray(data)
