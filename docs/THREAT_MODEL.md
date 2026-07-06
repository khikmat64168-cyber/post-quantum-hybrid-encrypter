# PQ-HE Threat Model

## Assets Being Protected

| Asset | Sensitivity |
|---|---|
| Plaintext file contents | High — the primary thing being encrypted |
| X25519 private keys | High — compromise allows decryption of future messages |
| ML-KEM-768 private keys | High — same; compromise breaks hybrid mode |
| HKDF master key | Critical — directly decrypts ciphertext; never persisted |
| X25519 shared secrets | Critical — same; ephemeral, wiped after HKDF |
| ML-KEM shared secrets | Critical — same; ephemeral, wiped after HKDF |

---

## Threat Actors and Assumptions

| Actor | Capability | In scope? |
|---|---|---|
| **Network eavesdropper** | Reads `.enc` files in transit or at rest | ✅ Yes |
| **Classical computer attacker** | Can attempt brute-force, ECDH attacks, crypto analysis | ✅ Yes |
| **Cryptographically-relevant quantum computer (CRQC)** | Can run Shor's algorithm, breaking X25519 | ✅ Yes (ML-KEM layer) |
| **Attacker with read access to keys dir** | Can read files in `./keys/` | ⚠️ Partial — `0o600` limits this to root/owner |
| **Attacker with write access to `.enc` files** | Can tamper with ciphertext/metadata | ✅ Yes — AES-GCM tag + AAD detect tampering |
| **Attacker with full OS compromise** | Can dump process memory | ❌ Out of scope (OS security boundary) |
| **Side-channel attacker** | Timing, power, EM attacks on key operations | ❌ Out of scope (library-level concern) |
| **Supply chain attacker** | Compromises `cryptography` or `pyoqs` packages | ❌ Out of scope |

---

## Threats and Mitigations

### T1 — Ciphertext confidentiality (eavesdropping)

**Attack:** Attacker intercepts `.enc` file and tries to recover plaintext.

**Mitigation:**
- AES-256-GCM with a fresh 32-byte master key per message.
- Master key derived from X25519 ECDH shared secret. Without the recipient's private key, the ECDH output cannot be reproduced.
- Even with unlimited classical compute, AES-256 is computationally infeasible to brute-force.

**Residual risk:** None for a classical attacker. Reduced to ML-KEM security level for a quantum attacker.

---

### T2 — Quantum attack (CRQC breaks X25519)

**Attack:** A cryptographically-relevant quantum computer runs Shor's algorithm and recovers the X25519 shared secret from the ephemeral public key.

**Mitigation:**
- In hybrid mode, the master key = `HKDF(X25519_secret ‖ ML-KEM_secret)`.
- Breaking X25519 gives the attacker `X25519_secret`, but they still need `ML-KEM_secret`.
- ML-KEM-768 is based on Module Learning With Errors (MLWE) — no known quantum algorithm breaks it faster than classical best.
- NIST security level 3 ≈ 192-bit equivalent security against quantum adversaries.

**Residual risk:** If BOTH X25519 AND ML-KEM are broken simultaneously, the master key is recoverable. This is considered infeasible with current knowledge.

---

### T3 — Ciphertext integrity (tampering)

**Attack:** Attacker modifies the `.enc` file — flips bits in the ciphertext, changes the IV, or alters metadata fields.

**Mitigation:**
- AES-GCM produces a 128-bit authentication tag over `ciphertext ‖ AAD`.
- Any modification to ciphertext bytes causes tag verification to fail → `AuthenticationError`.
- Metadata (sender_id, recipient_id, version, algorithm) is included in AAD → tampering with any of these fields also causes decryption to fail.

**Verified by:** `tests/integration/test_security.py` — tests for ciphertext, auth tag, metadata, and HKDF salt tampering.

---

### T4 — Wrong-key decryption

**Attack:** Eve intercepts a packet addressed to Bob and tries to decrypt it with her own private key.

**Mitigation:**
- Eve's X25519 key exchange produces a different shared secret → different HKDF output → different master key → AES-GCM tag verification fails.

**Verified by:** `test_wrong_private_key_raises_authentication_error` in security integration tests.

---

### T5 — Key file confidentiality

**Attack:** Local attacker reads private key files from `./keys/`.

**Mitigation:**
- Private key files created with `0o600` (owner read/write only).
- `KeyStorage` enforces this at write time via `os.chmod()`.
- Key ID validated against `^[a-zA-Z0-9_\-]{1,64}$` to prevent path traversal.

**Residual risk:** Root user or same UID can still read files. Full-disk encryption is the recommended complementary control.

---

### T6 — Path traversal via key_id

**Attack:** Attacker passes `key_id="../../../etc/passwd"` to read or overwrite arbitrary files.

**Mitigation:**
- `validate_key_id()` enforces `^[a-zA-Z0-9_\-]{1,64}$` before any filesystem use.
- Applied at: CLI option parsing, `KeygenController.generate()`, and all `KeyStorage` path helper methods (defense in depth).
- Any disallowed character raises `ValidationError` before a path is constructed.

**Verified by:** `TestPathTraversalPrevention` in `test_key_storage.py` and `TestValidateKeyId` in `test_validators.py`.

---

### T7 — Denial of service via large file

**Attack:** Attacker or user passes a multi-GB file, causing the process to exhaust RAM.

**Mitigation:**
- `validate_file_size(input_path, max_bytes=100 MiB)` checked before reading the file into memory.
- Raises `ValidationError` with a clear message.

---

### T8 — Sensitive data in logs

**Attack:** Log aggregation system captures raw key material.

**Mitigation:**
- All private key and shared secret models override `__repr__` to return `<REDACTED>`.
- `HybridKeyMaterial.__repr__` redacts `master_key`.
- `SharedSecretModel.__repr__` redacts `raw_bytes`.
- `structlog` is used; no f-string formatting of key models in log calls.

---

## Out-of-Scope Threats

| Threat | Reason out of scope |
|---|---|
| Process memory dump | Requires OS-level attacker; beyond the application security boundary |
| Side-channel attacks | Delegated to `cryptography` / `pyoqs` library implementations |
| Key compromise by malware | Physical/OS security; not an application-layer concern |
| Supply chain (pypi packages) | Use lockfiles and verify hashes in production deployments |
| Social engineering | Human-factor attack; out of scope for this tool |
| Replay attacks | PQ-HE is stateless; replay of a `.enc` file produces the same plaintext — by design |

---

## Security Properties Summary

| Property | Status | Mechanism |
|---|---|---|
| Confidentiality | ✅ | AES-256-GCM + hybrid key exchange |
| Integrity | ✅ | AES-GCM 128-bit authentication tag |
| Authenticity of metadata | ✅ | AAD binding via `PacketMetadata.make_aad()` |
| Forward secrecy | ✅ | Ephemeral X25519 key per message |
| Post-quantum resilience | ✅ (when pyoqs installed) | ML-KEM-768 (NIST FIPS 203) |
| Non-repudiation | ❌ | No signatures — not in scope |
| Key revocation | ❌ | No PKI infrastructure — not in scope |
| Multi-recipient encryption | ❌ | One recipient per packet — by design |
