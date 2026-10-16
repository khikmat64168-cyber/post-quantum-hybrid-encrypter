"""
Input validation utilities.

All public functions raise ValidationError (a ValueError subclass) on invalid
input so callers can catch a single exception type. No cryptographic logic here.

Security properties enforced
-----------------------------
- key_id allowlist prevents path-traversal attacks when key_id is embedded
  in a filename (e.g. "{key_id}_x25519_private.json").
- File-size limit prevents unbounded memory allocation when loading plaintext.
- Output-parent check surfaces a clear error before a write deep in the stack.
"""

from __future__ import annotations

import os
import re
from pathlib import Path

_KEY_ID_RE = re.compile(r"^[a-zA-Z0-9_\-]{1,64}$")

# 100 MiB — enough for any realistic message, prevents OOM on huge files.
MAX_PLAINTEXT_BYTES: int = 100 * 1024 * 1024


class ValidationError(ValueError):
    """Raised when user-supplied input fails validation."""


def validate_key_id(key_id: str) -> str:
    """
    Validate and return key_id after stripping whitespace.

    Allowed characters: letters, digits, hyphen (-), underscore (_).
    Maximum length: 64 characters.

    This allowlist prevents path-traversal when key_id is embedded in a
    filename — characters like '/', '\\', and '..' are rejected.

    Raises
    ------
    ValidationError : key_id is empty, too long, or contains disallowed chars.
    """
    key_id = key_id.strip()
    if not key_id:
        raise ValidationError("key_id must not be empty.")
    if not _KEY_ID_RE.match(key_id):
        raise ValidationError(
            f"Invalid key_id {key_id!r}. "
            "Use only letters, digits, hyphens (-), or underscores (_). "
            "Maximum 64 characters."
        )
    return key_id


def validate_file_size(path: Path, max_bytes: int = MAX_PLAINTEXT_BYTES) -> None:
    """
    Raise ValidationError if path is larger than max_bytes.

    Prevents unbounded memory use when the entire file is loaded into RAM
    before encryption.

    Raises
    ------
    ValidationError : File exceeds max_bytes.
    """
    size = path.stat().st_size
    if size > max_bytes:
        max_mib = max_bytes // (1024 * 1024)
        raise ValidationError(
            f"File too large: {size:,} bytes "
            f"(limit is {max_bytes:,} bytes / {max_mib} MiB)."
        )


def validate_plaintext_not_empty(data: bytes) -> None:
    """
    Raise ValidationError if plaintext is empty.

    Encrypting zero bytes is technically valid for AES-GCM but almost always
    indicates a user error (e.g. pointing to the wrong file).

    Raises
    ------
    ValidationError : data is empty.
    """
    if not data:
        raise ValidationError(
            "Plaintext file is empty — nothing to encrypt. "
            "Check that you specified the correct input file."
        )


def validate_output_parent(path: Path) -> None:
    """
    Raise ValidationError if path's parent directory doesn't exist or isn't
    writable by the current process.

    Surfaces a clear error before any file I/O, rather than a raw OS error
    raised from deep inside the call stack.

    Raises
    ------
    ValidationError : Parent directory missing or not writable.
    """
    parent = path.parent
    if not parent.exists():
        raise ValidationError(
            f"Output directory does not exist: {parent}\n"
            "Create it first or choose a different --output path."
        )
    if not os.access(parent, os.W_OK):
        raise ValidationError(
            f"Output directory is not writable: {parent}"
        )
