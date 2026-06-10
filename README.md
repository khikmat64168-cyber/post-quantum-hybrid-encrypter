# PQ-HE — Post-Quantum Hybrid Encrypter

> **A production-grade cybersecurity portfolio project demonstrating classical and post-quantum hybrid encryption.**

[![Python 3.12+](https://img.shields.io/badge/python-3.12%2B-blue.svg)](https://www.python.org/)
[![Security: ML-KEM + X25519](https://img.shields.io/badge/security-ML--KEM%20%2B%20X25519-brightgreen.svg)](#cryptography)
[![License: MIT](https://img.shields.io/badge/license-MIT-yellow.svg)](LICENSE)

---

## Overview

**PQ-HE** is a command-line encryption tool that combines **classical elliptic-curve key exchange (X25519)** with **post-quantum key encapsulation (ML-KEM-768)** to produce a hybrid symmetric key used for **AES-256-GCM authenticated encryption**.

The design ensures that even if one cryptographic layer is broken — either a classical computer breaks X25519, or a quantum computer breaks classical ECDH — the data remains protected by the other layer.

---

## Cryptography

| Layer | Algorithm | Standard |
|---|---|---|
| Classical KE | X25519 (ECDH over Curve25519) | RFC 7748 |
| Post-Quantum KEM | ML-KEM-768 (Kyber) | NIST FIPS 203 |
| Key Derivation | HKDF-SHA-256 | RFC 5869 |
| Symmetric Encryption | AES-256-GCM | NIST SP 800-38D |

### Why Hybrid?

NIST finalized ML-KEM (formerly Kyber) in 2024 (FIPS 203). Best practice during the transition period is to **combine** a classical algorithm (whose security is well-understood) with the new post-quantum algorithm.  
Concatenating the two shared secrets before HKDF means an attacker must break **both** schemes.

---

## Architecture

```
src/
├── models/          # Immutable data containers (keys, payloads, config)
├── views/           # CLI rendering only — no crypto, no business logic
├── controllers/     # Application flow — orchestrates services
├── crypto/
│   ├── classical/   # X25519 low-level wrapper
│   ├── post_quantum/# ML-KEM-768 low-level wrapper (via pyoqs)
│   └── hybrid/      # Secret combination + HKDF
├── services/        # All cryptographic business logic
├── storage/         # Filesystem persistence
└── utils/           # Logging, validators, helpers
config/              # Pydantic-settings configuration
tests/               # pytest suite (unit + integration)
```

MVC boundaries are strictly enforced:
- **Views** call **Controllers** only.
- **Controllers** call **Services** only.
- **Services** call **Crypto** primitives.
- **Models** are passed between all layers as data.

---

## Installation

```bash
# 1. Clone
git clone https://github.com/your-username/pq-he.git
cd pq-he

# 2. Create virtual environment
python3.12 -m venv .venv
source .venv/bin/activate

# 3. Install liboqs (required for ML-KEM)
# macOS:
brew install liboqs
# Linux:
# See https://github.com/open-quantum-safe/liboqs#building

# 4. Install Python dependencies
pip install -r requirements.txt

# 5. Configure environment
cp .env.example .env

# 6. Verify setup
pqhe status
```

---

## Usage

```bash
# Generate a hybrid key pair
pqhe keygen --name alice --output-dir ./keys

# Encrypt a file
pqhe encrypt secret.txt --recipient-key ./keys/alice_public.json

# Decrypt a file
pqhe decrypt secret.txt.enc --private-key ./keys/alice_private.json

# System status
pqhe status
```

---

## Testing

```bash
pytest                        # full suite
pytest -m unit                # unit tests only
pytest -m integration         # integration tests only
pytest --cov=src              # with coverage
```

---

## Security Considerations

- Private keys are stored with `0o600` permissions and never logged.
- All cryptographic secrets are wiped from memory after use via `ctypes.memset`.
- Input validation is enforced at every system boundary.
- This project is for **educational and portfolio purposes**. Conduct a professional security review before using in production.

---

## Project Roadmap

| Phase | Description | Status |
|---|---|---|
| 1 | Project Foundation | ✅ Complete |
| 2 | Classical Cryptography Layer | ⬜ Pending |
| 3 | Post-Quantum Cryptography Layer | ⬜ Pending |
| 4 | Hybrid Key Derivation | ⬜ Pending |
| 5 | AES-GCM Encryption Engine | ⬜ Pending |
| 6 | Secure Data Packaging | ⬜ Pending |
| 7 | CLI Application | ⬜ Pending |
| 8 | Security Hardening | ⬜ Pending |
| 9 | Testing Suite | ⬜ Pending |
| 10 | Documentation & Showcase | ⬜ Pending |

---

## License

MIT — see [LICENSE](LICENSE).
