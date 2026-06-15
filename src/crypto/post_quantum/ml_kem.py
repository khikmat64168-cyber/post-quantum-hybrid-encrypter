"""
Low-level ML-KEM-768 operations — a thin typed wrapper over the `pyoqs` library.

This module contains zero business logic. It accepts and returns raw bytes only.
All higher-level decisions (key IDs, metadata, logging) live in
`src.services.mlkem_service`.

Algorithm: ML-KEM-768 (NIST FIPS 203), exposed by liboqs as "Kyber768".

Key and ciphertext sizes for ML-KEM-768 / Kyber768:
    Public key  : 1184 bytes
    Secret key  : 2400 bytes
    Ciphertext  : 1088 bytes
    Shared secret:  32 bytes

Requires:
    liboqs  >= 0.10.0  (https://github.com/open-quantum-safe/liboqs)
    pyoqs   >= 0.10.0  (pip install pyoqs)
"""

from __future__ import annotations

# Lazy import — the module can be imported even without pyoqs installed.
# Calling any public function without pyoqs raises ImportError with instructions.
try:
    import oqs as _oqs  # type: ignore[import-untyped]
    _OQS_AVAILABLE = True
except ImportError:
    _oqs = None  # type: ignore[assignment]
    _OQS_AVAILABLE = False

# liboqs algorithm identifier for ML-KEM-768
_ALGORITHM = "Kyber768"

# Expected sizes in bytes — used for input validation
PUBLIC_KEY_SIZE = 1184
SECRET_KEY_SIZE = 2400
CIPHERTEXT_SIZE = 1088
SHARED_SECRET_SIZE = 32


def is_available() -> bool:
    """Return True if pyoqs/liboqs is installed and ML-KEM-768 is enabled."""
    if not _OQS_AVAILABLE:
        return False
    try:
        return _ALGORITHM in _oqs.get_enabled_KEM_mechanisms()
    except Exception:
        return False


def _require_oqs() -> None:
    """Raise a clear ImportError if pyoqs is not installed."""
    if not _OQS_AVAILABLE:
        raise ImportError(
            "pyoqs is required for ML-KEM operations.\n"
            "1. Install liboqs:  brew install liboqs   (macOS)\n"
            "                    see https://github.com/open-quantum-safe/liboqs\n"
            "2. Install pyoqs:   pip install pyoqs"
        )
    if not is_available():
        raise RuntimeError(
            f"ML-KEM algorithm '{_ALGORITHM}' is not enabled in the installed liboqs build."
        )


def generate_keypair() -> tuple[bytes, bytes]:
    """
    Generate a fresh ML-KEM-768 key pair.

    Returns
    -------
    (public_key, secret_key) as raw bytes.
    public_key  : 1184 bytes — safe to distribute.
    secret_key  : 2400 bytes — must be stored with 0o600 permissions.
    """
    _require_oqs()
    with _oqs.KeyEncapsulation(_ALGORITHM) as kem:
        public_key: bytes = kem.generate_keypair()
        secret_key: bytes = kem.export_secret_key()
    return public_key, secret_key


def encapsulate(public_key: bytes) -> tuple[bytes, bytes]:
    """
    Encapsulate a shared secret using the recipient's public key.

    This is the sender-side operation. The sender generates a random
    shared secret and encrypts it under the recipient's public key,
    producing a ciphertext.

    Parameters
    ----------
    public_key : Recipient's 1184-byte ML-KEM-768 public key.

    Returns
    -------
    (ciphertext, shared_secret) as raw bytes.
    ciphertext    : 1088 bytes — transmit to recipient.
    shared_secret :   32 bytes — feed into HKDF; never transmit.
    """
    _require_oqs()
    if len(public_key) != PUBLIC_KEY_SIZE:
        raise ValueError(
            f"ML-KEM-768 public key must be {PUBLIC_KEY_SIZE} bytes, got {len(public_key)}"
        )
    with _oqs.KeyEncapsulation(_ALGORITHM) as kem:
        ciphertext: bytes
        shared_secret: bytes
        ciphertext, shared_secret = kem.encap_secret(public_key)
    return ciphertext, shared_secret


def decapsulate(secret_key: bytes, ciphertext: bytes) -> bytes:
    """
    Decapsulate the shared secret using the recipient's secret key.

    This is the recipient-side operation. Given the ciphertext from the
    sender and our own secret key, we recover the same shared secret the
    sender generated.

    Parameters
    ----------
    secret_key  : Recipient's 2400-byte ML-KEM-768 secret key.
    ciphertext  : 1088-byte ciphertext received from sender.

    Returns
    -------
    shared_secret : 32 bytes — must equal the sender's shared_secret.
    """
    _require_oqs()
    if len(secret_key) != SECRET_KEY_SIZE:
        raise ValueError(
            f"ML-KEM-768 secret key must be {SECRET_KEY_SIZE} bytes, got {len(secret_key)}"
        )
    if len(ciphertext) != CIPHERTEXT_SIZE:
        raise ValueError(
            f"ML-KEM-768 ciphertext must be {CIPHERTEXT_SIZE} bytes, got {len(ciphertext)}"
        )
    with _oqs.KeyEncapsulation(_ALGORITHM, secret_key) as kem:
        shared_secret: bytes = kem.decap_secret(ciphertext)
    return shared_secret
