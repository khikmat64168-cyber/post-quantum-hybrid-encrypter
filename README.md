# PQ-HE — Post-Quantum Hybrid Encrypter

> **A production-grade cybersecurity portfolio project demonstrating hybrid classical + post-quantum encryption.**

[![CI](https://github.com/khikmat64168-cyber/post-quantum-hybrid-encrypter/actions/workflows/ci.yml/badge.svg)](https://github.com/khikmat64168-cyber/post-quantum-hybrid-encrypter/actions/workflows/ci.yml)
[![Python 3.12+](https://img.shields.io/badge/python-3.12%2B-blue.svg)](https://www.python.org/)
[![NIST FIPS 203](https://img.shields.io/badge/NIST-FIPS%20203%20ML--KEM-brightgreen.svg)](https://csrc.nist.gov/pubs/fips/203/final)
[![Tests](https://img.shields.io/badge/tests-398%20passed-success.svg)](#testing)
[![Coverage](https://img.shields.io/badge/coverage-90%25-success.svg)](#testing)
[![License: MIT](https://img.shields.io/badge/license-MIT-yellow.svg)](LICENSE)

---

## What is PQ-HE?

**PQ-HE** is a command-line file encryption tool that protects data against both classical and quantum adversaries. It combines **X25519 ECDH** (classical) with **ML-KEM-768** (post-quantum) in a hybrid scheme: an attacker must break *both* algorithms to recover the plaintext.

```
                    ┌─────────────────────────────────────────────┐
                    │              HYBRID KEY EXCHANGE             │
                    │                                             │
  Sender            │   X25519 ECDH    ──►  classical_secret      │
  generates         │   ML-KEM-768     ──►  pq_secret             │
  ephemeral key     │                                             │
                    │   HKDF-SHA-256(classical_secret ‖ pq_secret)│
                    │                   ──►  32-byte master key   │
                    └───────────────────────┬─────────────────────┘
                                            │
                    ┌───────────────────────▼─────────────────────┐
                    │           AES-256-GCM ENCRYPTION             │
                    │   master_key + IV + AAD  ──►  ciphertext    │
                    └─────────────────────────────────────────────┘
```

---

## Cryptographic Stack

| Layer | Algorithm | Standard | Key / Output Size |
|---|---|---|---|
| Classical KE | X25519 (ECDH over Curve25519) | RFC 7748 | 32 B public key, 32 B secret |
| Post-Quantum KEM | ML-KEM-768 | NIST FIPS 203 | 1184 B pub, 1088 B ciphertext |
| Key Derivation | HKDF-SHA-256 | RFC 5869 | 32 B master key |
| Symmetric Enc | AES-256-GCM | NIST SP 800-38D | 256-bit key, 96-bit IV, 128-bit tag |
| Digital Signature | Ed25519 | RFC 8032 | 32 B key, 64 B signature |
| Key Protection | Argon2id + AES-256-GCM | OWASP 2024 | t=3, m=64 MiB, p=4 |

### Why Hybrid?

NIST finalized ML-KEM in August 2024 (FIPS 203). During the transition period, best practice is to **layer** a post-quantum algorithm over a battle-tested classical one. By feeding `X25519_secret ‖ ML-KEM_secret` into HKDF, the master key is secure as long as *either* algorithm holds.

> A quantum computer running Shor's algorithm breaks X25519, but not ML-KEM.  
> If ML-KEM has an undiscovered flaw, X25519 still protects the data.

---

## Architecture

PQ-HE follows a strict **MVC + Clean Architecture** pattern:

```
pqhe/
├── views/           # CLI rendering (Rich + Click) — no crypto, no business logic
├── controllers/     # Application flow — orchestrates services, validates input
├── services/        # All cryptographic business logic
│   ├── x25519_service.py          # Key generation and ECDH
│   ├── mlkem_service.py           # ML-KEM-768 key gen, encap, decap
│   ├── hkdf_service.py            # HKDF-SHA-256 key derivation
│   ├── aes_service.py             # AES-256-GCM encrypt / decrypt
│   ├── ed25519_service.py         # Ed25519 sign / verify
│   ├── packet_service.py          # Packet assembly, validation, serialization
│   └── encryption_orchestrator.py # Top-level encrypt / decrypt flow (DI)
├── crypto/
│   ├── classical/   # Low-level X25519 + AES-GCM + Ed25519 + Argon2id primitives
│   ├── post_quantum/# Low-level ML-KEM-768 wrapper (lazy import of liboqs-python)
│   └── hybrid/      # HKDF combiner
├── models/          # Frozen dataclasses — pure data, no I/O, no logic
├── storage/         # Filesystem key persistence (0o600 / 0o644 permissions)
├── utils/           # Logging, input validators, secure memory wipe
└── config/          # Pydantic-settings — typed configuration from .env
tests/
├── unit/            # 278 unit tests (crypto, services, models, controllers)
└── integration/     # 27 integration tests (end-to-end + security/tampering)
```

**Dependency rule:** `views → controllers → services → crypto`. Models flow between all layers. Nothing crosses this boundary.

---

## Encryption Flow (step-by-step)

```
ENCRYPT(plaintext, recipient_x25519_pub, [recipient_mlkem_pub], [sender_ed25519_priv])
  │
  ├─ 1. Generate ephemeral X25519 key pair  (fresh per message)
  ├─ 2. X25519 ECDH(ephemeral_priv, recipient_pub) → classical_secret (32 B)
  ├─ 3. ML-KEM-768 Encapsulate(recipient_mlkem_pub) → (ciphertext, pq_secret) [optional]
  ├─ 4. HKDF-SHA-256(classical_secret ‖ pq_secret, salt, info) → master_key (32 B)
  ├─ 5. Build PacketMetadata → encode as AAD
  ├─ 6. AES-256-GCM Encrypt(master_key, plaintext, aad=AAD) → ciphertext ‖ tag
  ├─ 7. Serialize all fields to EncryptedPacket JSON
  └─ 8. Ed25519 Sign(sender_ed25519_priv, canonical_json) → embed signature [optional]

DECRYPT(packet, recipient_x25519_priv, [recipient_mlkem_priv])
  │
  ├─ 1. Validate packet structure and version
  ├─ 2. X25519 ECDH(recipient_priv, ephemeral_pub_from_packet) → classical_secret
  ├─ 3. ML-KEM-768 Decapsulate(recipient_mlkem_priv, ct_from_packet) → pq_secret [if hybrid]
  ├─ 4. HKDF-SHA-256(classical_secret ‖ pq_secret, salt_from_packet, info) → master_key
  ├─ 5. Reconstruct AAD from packet metadata
  ├─ 6. AES-256-GCM Decrypt(master_key, ciphertext, aad=AAD) → plaintext
  └─ 7. Ed25519 Verify(sender_pub_from_packet, canonical_json, signature) [if signed]
```

---

## Security Properties

| Property | Mechanism |
|---|---|
| **Confidentiality** | AES-256-GCM with a fresh ephemeral X25519 key per message |
| **Integrity** | AES-GCM 128-bit authentication tag — any ciphertext modification is detected |
| **Authenticity** | Ed25519 signature over the canonical packet JSON — proves sender identity |
| **Metadata binding** | Sender ID, recipient ID, version, and algorithm are bound into AES-GCM AAD |
| **Forward secrecy** | Ephemeral X25519 key is never stored — compromise of long-term keys doesn't expose past messages |
| **Quantum resistance** | ML-KEM-768 (standardised from CRYSTALS-Kyber, Level 3 — 192-bit classical security equivalent) |
| **Key isolation** | Private keys stored with `0o600` permissions; never written to logs |
| **Key protection** | Optional Argon2id + AES-256-GCM passphrase encryption for private keys at rest |
| **Memory safety** | Shared secrets wiped via `ctypes.memset` after use |
| **Input sanitization** | `key_id` allowlist prevents path-traversal; file-size cap prevents OOM |

---

## Installation

```bash
# 1. Clone the repository
git clone https://github.com/khikmat64168-cyber/post-quantum-hybrid-encrypter.git
cd post-quantum-hybrid-encrypter

# 2. Create a Python 3.12+ virtual environment
python3 -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate

# 3. Install as a package — makes `pqhe` available system-wide
pip install -e .

# 4. (Optional) Enable ML-KEM-768 / post-quantum layer
pip install -e ".[pq]"
# liboqs-python needs the native liboqs library. If it is not found, the first
# `import oqs` clones and builds liboqs into ~/_oqs (requires git, cmake and a C compiler).
# Or install it yourself first — macOS: brew install liboqs

# 5. Configure environment
cp .env.example .env             # edit as needed

# 6. Verify installation
pqhe status
```

> Without the `[pq]` extra, PQ-HE falls back to **X25519-only mode** automatically. All features — including Ed25519 signatures and passphrase-protected keys — work; the ML-KEM layer is simply skipped.

---

## Usage

### 1. Generate a key pair

```bash
pqhe keygen --name alice --keys-dir ./keys
```

Creates in `./keys/`:

| File | Type | Permissions |
|---|---|---|
| `alice_x25519_private.json` | X25519 private key | 0600 |
| `alice_x25519_public.json` | X25519 public key | 0644 |
| `alice_ed25519_private.json` | Ed25519 signing key | 0600 |
| `alice_ed25519_public.json` | Ed25519 verify key | 0644 |
| `alice_mlkem_private.json` | ML-KEM-768 private key *(if liboqs-python installed)* | 0600 |
| `alice_mlkem_public.json` | ML-KEM-768 public key *(if liboqs-python installed)* | 0644 |

Add `--protect` to encrypt private keys with a passphrase (Argon2id + AES-256-GCM):

```bash
pqhe keygen --name alice --keys-dir ./keys --protect
```

### 2. Encrypt a file

```bash
pqhe encrypt secret.txt \
    --sender bob \
    --recipient alice \
    --keys-dir ./keys \
    --output secret.txt.enc
```

Looks up Alice's public keys in `./keys/`. If Bob has an Ed25519 private key in `./keys/`, the packet is **signed** automatically. Writes a self-contained JSON packet to `secret.txt.enc`.

### 3. Decrypt a file

```bash
pqhe decrypt secret.txt.enc \
    --recipient alice \
    --keys-dir ./keys \
    --output recovered.txt
```

Loads Alice's private keys from `./keys/`, decrypts, and **verifies the Ed25519 signature** if present. If Alice's keys are passphrase-protected, the passphrase is prompted interactively.

### 4. System status

```bash
pqhe status
```

Shows Python version, dependency versions, and ML-KEM availability.

### Output packet format (`.enc` file)

```json
{
  "version": "1",
  "algorithm": "X25519+ML-KEM-768+HKDF-SHA256+AES-256-GCM",
  "created_at": "2025-07-05T12:00:00+00:00",
  "sender_key_id": "bob",
  "recipient_key_id": "alice",
  "x25519_ephemeral_public_b64": "<base64, 32 bytes>",
  "hkdf_salt_b64": "<base64, 32 bytes>",
  "iv_b64": "<base64, 12 bytes>",
  "ciphertext_b64": "<base64, len(plaintext) + 16 bytes>",
  "mlkem_ciphertext_b64": "<base64, 1088 bytes>",
  "signature_b64": "<base64, 64 bytes — Ed25519 signature over canonical packet JSON>",
  "sender_ed25519_pub_b64": "<base64, 32 bytes — sender's Ed25519 public key>"
}
```

`signature_b64` and `sender_ed25519_pub_b64` are absent for anonymous/unsigned packets. `mlkem_ciphertext_b64` is absent in classical (non-hybrid) mode.

---

## Testing

```bash
# Full suite
python3 -m pytest

# By marker
python3 -m pytest -m unit
python3 -m pytest -m integration

# With coverage report
python3 -m pytest --cov=pqhe --cov-report=html
open htmlcov/index.html
```

**Test results:** 398 passed with liboqs installed (ML-KEM tests are skipped without it), **89% coverage**

| Test category | Count | What's covered |
|---|---|---|
| Crypto primitives | 47 | X25519, AES-GCM, HKDF, ML-KEM, Ed25519 |
| Services | 113 | All service logic incl. signatures + key protection |
| Models | 57 | Frozen dataclasses, serialization, repr redaction |
| Controllers | 40 | Keygen, encrypt, decrypt, status |
| Utils | 43 | Validators, secure bytes, logging |
| Integration | 32 | End-to-end flows + **security/tampering detection** |

---

## Project Roadmap

| Phase | Description | Status |
|---|---|---|
| 1 | Project Foundation | ✅ Complete |
| 2 | Classical Cryptography Layer | ✅ Complete |
| 3 | Post-Quantum Cryptography Layer | ✅ Complete |
| 4 | Hybrid Key Derivation (HKDF) | ✅ Complete |
| 5 | AES-GCM Encryption Engine | ✅ Complete |
| 6 | Secure Data Packaging (EncryptedPacket) | ✅ Complete |
| 7 | CLI Application | ✅ Complete |
| 8 | Security Hardening | ✅ Complete |
| 9 | Testing Suite | ✅ Complete |
| 10 | Documentation & Showcase | ✅ Complete |
| 11 | CI/CD Pipeline (GitHub Actions) | ✅ Complete |
| 12 | Passphrase-Protected Keys (Argon2id) | ✅ Complete |
| 13 | Ed25519 Digital Signatures + Packaging | ✅ Complete |

---

## Tech Stack

- **Python 3.12+** — pattern matching, `tomllib`, stricter type hints
- **cryptography** — X25519, AES-256-GCM, HKDF (backed by OpenSSL)
- **liboqs-python / liboqs** — ML-KEM-768 (NIST FIPS 203)
- **Click** — CLI framework
- **Rich** — terminal UI (tables, panels, banners)
- **Pydantic Settings** — typed configuration from environment variables
- **structlog** — structured JSON logging with stdlib bridge
- **pytest** — test runner with markers, coverage, and fixtures

---

## Further Reading

- [Architecture Guide](docs/ARCHITECTURE.md)
- [Threat Model](docs/THREAT_MODEL.md)
- [Interview Guide — Cryptographic Design Decisions](docs/INTERVIEW_GUIDE.md)
- [NIST FIPS 203 — ML-KEM Standard](https://csrc.nist.gov/pubs/fips/203/final)
- [RFC 7748 — X25519](https://www.rfc-editor.org/rfc/rfc7748)
- [RFC 5869 — HKDF](https://www.rfc-editor.org/rfc/rfc5869)

---

## License

MIT — see [LICENSE](LICENSE).

---

> **Disclaimer:** PQ-HE is a portfolio and educational project. It has not undergone a professional security audit. Do not use it to protect sensitive data in production without independent review.
