"""Unit tests for secure memory wipe utilities."""

import pytest

from src.utils.secure_bytes import wipe, wipe_bytes_copy


@pytest.mark.unit
class TestWipe:
    def test_wipe_zeroes_all_bytes(self) -> None:
        buf = bytearray(b"\xff\xaa\x55\x00\xde\xad\xbe\xef")
        wipe(buf)
        assert all(b == 0 for b in buf)

    def test_wipe_modifies_in_place(self) -> None:
        buf = bytearray(b"\x01\x02\x03")
        original_id = id(buf)
        wipe(buf)
        assert id(buf) == original_id  # same object

    def test_wipe_32_byte_secret(self) -> None:
        import os
        secret = bytearray(os.urandom(32))
        wipe(secret)
        assert secret == bytearray(32)

    def test_wipe_empty_bytearray_is_noop(self) -> None:
        buf = bytearray(b"")
        wipe(buf)  # should not raise

    def test_wipe_rejects_bytes_type(self) -> None:
        with pytest.raises(TypeError, match="bytearray"):
            wipe(b"\xff\x00")  # type: ignore[arg-type]

    def test_wipe_rejects_string(self) -> None:
        with pytest.raises(TypeError):
            wipe("secret")  # type: ignore[arg-type]

    def test_wipe_rejects_list(self) -> None:
        with pytest.raises(TypeError):
            wipe([1, 2, 3])  # type: ignore[arg-type]

    def test_wipe_length_preserved(self) -> None:
        buf = bytearray(b"\xab" * 64)
        wipe(buf)
        assert len(buf) == 64

    def test_wipe_then_reuse(self) -> None:
        buf = bytearray(b"secret_data")
        wipe(buf)
        buf[:] = b"new_data___"
        assert buf == bytearray(b"new_data___")


@pytest.mark.unit
class TestWipeBytesCopy:
    def test_returns_bytearray(self) -> None:
        result = wipe_bytes_copy(b"hello")
        assert isinstance(result, bytearray)

    def test_content_matches_input(self) -> None:
        data = b"\x01\x02\x03\x04"
        result = wipe_bytes_copy(data)
        assert bytes(result) == data

    def test_copy_is_independent(self) -> None:
        data = b"immutable"
        copy = wipe_bytes_copy(data)
        wipe(copy)
        # original bytes object unchanged
        assert data == b"immutable"
        assert copy == bytearray(len(data))

    def test_empty_bytes_returns_empty_bytearray(self) -> None:
        result = wipe_bytes_copy(b"")
        assert isinstance(result, bytearray)
        assert len(result) == 0

    def test_round_trip_wipe(self) -> None:
        import os
        secret_bytes = os.urandom(32)
        mutable = wipe_bytes_copy(secret_bytes)
        assert bytes(mutable) == secret_bytes
        wipe(mutable)
        assert mutable == bytearray(32)
