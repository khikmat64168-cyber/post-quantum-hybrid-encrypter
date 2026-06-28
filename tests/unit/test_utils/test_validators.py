"""Unit tests for src/utils/validators.py."""

import os
from pathlib import Path

import pytest

from src.utils.validators import (
    MAX_PLAINTEXT_BYTES,
    ValidationError,
    validate_file_size,
    validate_key_id,
    validate_output_parent,
    validate_plaintext_not_empty,
)


# ------------------------------------------------------------------
# validate_key_id
# ------------------------------------------------------------------

@pytest.mark.unit
class TestValidateKeyId:
    @pytest.mark.parametrize("key_id", ["alice", "bob", "Alice123", "my-key", "my_key", "a" * 64])
    def test_valid_key_ids_are_returned(self, key_id: str) -> None:
        assert validate_key_id(key_id) == key_id

    def test_strips_surrounding_whitespace(self) -> None:
        assert validate_key_id("  alice  ") == "alice"

    def test_empty_string_raises(self) -> None:
        with pytest.raises(ValidationError, match="must not be empty"):
            validate_key_id("")

    def test_whitespace_only_raises(self) -> None:
        with pytest.raises(ValidationError, match="must not be empty"):
            validate_key_id("   ")

    def test_slash_raises(self) -> None:
        with pytest.raises(ValidationError):
            validate_key_id("alice/bob")

    def test_dotdot_raises(self) -> None:
        with pytest.raises(ValidationError):
            validate_key_id("../evil")

    def test_path_traversal_raises(self) -> None:
        with pytest.raises(ValidationError):
            validate_key_id("../../etc/passwd")

    def test_backslash_raises(self) -> None:
        with pytest.raises(ValidationError):
            validate_key_id("alice\\bob")

    def test_space_in_middle_raises(self) -> None:
        with pytest.raises(ValidationError):
            validate_key_id("alice bob")

    def test_too_long_raises(self) -> None:
        with pytest.raises(ValidationError):
            validate_key_id("a" * 65)

    def test_exactly_64_chars_is_valid(self) -> None:
        key_id = "a" * 64
        assert validate_key_id(key_id) == key_id

    def test_special_chars_raise(self) -> None:
        for bad in ["alice!", "alice@domain", "alice;rm", "alice&evil", "alice|cat"]:
            with pytest.raises(ValidationError):
                validate_key_id(bad)


# ------------------------------------------------------------------
# validate_file_size
# ------------------------------------------------------------------

@pytest.mark.unit
class TestValidateFileSize:
    def test_small_file_passes(self, tmp_path: Path) -> None:
        f = tmp_path / "small.txt"
        f.write_bytes(b"hello")
        validate_file_size(f)  # should not raise

    def test_file_at_limit_passes(self, tmp_path: Path) -> None:
        f = tmp_path / "limit.bin"
        f.write_bytes(b"\x00" * MAX_PLAINTEXT_BYTES)
        validate_file_size(f)  # exactly at limit — should not raise

    def test_file_over_limit_raises(self, tmp_path: Path) -> None:
        f = tmp_path / "huge.bin"
        f.write_bytes(b"\x00" * (MAX_PLAINTEXT_BYTES + 1))
        with pytest.raises(ValidationError, match="too large"):
            validate_file_size(f)

    def test_custom_limit(self, tmp_path: Path) -> None:
        f = tmp_path / "data.bin"
        f.write_bytes(b"\x00" * 101)
        with pytest.raises(ValidationError):
            validate_file_size(f, max_bytes=100)

    def test_empty_file_passes(self, tmp_path: Path) -> None:
        f = tmp_path / "empty.txt"
        f.write_bytes(b"")
        validate_file_size(f)  # size check doesn't reject empty — that's plaintext check's job


# ------------------------------------------------------------------
# validate_plaintext_not_empty
# ------------------------------------------------------------------

@pytest.mark.unit
class TestValidatePlaintextNotEmpty:
    def test_non_empty_bytes_passes(self) -> None:
        validate_plaintext_not_empty(b"hello")  # should not raise

    def test_single_byte_passes(self) -> None:
        validate_plaintext_not_empty(b"\x00")

    def test_empty_bytes_raises(self) -> None:
        with pytest.raises(ValidationError, match="empty"):
            validate_plaintext_not_empty(b"")


# ------------------------------------------------------------------
# validate_output_parent
# ------------------------------------------------------------------

@pytest.mark.unit
class TestValidateOutputParent:
    def test_existing_writable_parent_passes(self, tmp_path: Path) -> None:
        out = tmp_path / "output.txt"
        validate_output_parent(out)  # should not raise

    def test_nonexistent_parent_raises(self, tmp_path: Path) -> None:
        out = tmp_path / "nonexistent" / "output.txt"
        with pytest.raises(ValidationError, match="does not exist"):
            validate_output_parent(out)

    def test_nested_nonexistent_parent_raises(self, tmp_path: Path) -> None:
        out = tmp_path / "a" / "b" / "c" / "output.txt"
        with pytest.raises(ValidationError):
            validate_output_parent(out)

    def test_file_in_cwd_passes(self, tmp_path: Path) -> None:
        # parent is tmp_path itself — exists and writable
        out = tmp_path / "result.enc"
        validate_output_parent(out)
