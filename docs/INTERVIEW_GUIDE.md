# PQ-HE Interview Guide — Cryptographic Design Decisions

Answers to questions a hiring manager, security engineer, or technical interviewer is likely to ask.

---

## Q1: Why do you combine X25519 and ML-KEM? Isn't one enough?

**Short answer:** Defense in depth during the post-quantum transition.

**Full answer:**

ML-KEM was standardized by NIST in August 2024 (FIPS 203). It's new. Despite years of cryptanalysis, it lacks the decades of real-world battle-testing that X25519/Curve25519 has. At the same time, X25519 is vulnerable to Shor's algorithm running on a cryptographically-relevant quantum computer (CRQC).

The hybrid approach hedges both risks:
- If ML-KEM has an undiscovered flaw → X25519 still protects the data.
- If a CRQC breaks X25519 → ML-KEM still protects the data.

The key insight: the master key = `HKDF(X25519_secret ‖ ML-KEM_secret)`. An attacker needs *both* secrets. This is the approach recommended by NIST SP 800-56C Rev 2 and is used in TLS 1.3 hybrid key exchange drafts (RFC 8446 + ML-KEM extensions).

---

## Q2: Why ML-KEM-768 specifically? Why not ML-KEM-512 or ML-KEM-1024?

**Short answer:** Level 3 gives the right tradeoff between security and performance.

| Variant | NIST Level | Classical equiv | Public key | Ciphertext |
|---|---|---|---|---|
| ML-KEM-512 | 1 | ~128-bit | 800 B | 768 B |
| **ML-KEM-768** | **3** | **~192-bit** | **1184 B** | **1088 B** |
| ML-KEM-1024 | 5 | ~256-bit | 1568 B | 1568 B |

Level 3 matches AES-192 in classical equivalent security, making it a natural pair with AES-256-GCM (which is already overkill for most use cases). ML-KEM-1024 adds ~35% key/ciphertext size for minimal real-world gain when used in a hybrid scheme where X25519 already provides 128-bit classical security.

---

## Q3: How does HKDF combine the two secrets?

**Short answer:** Concatenate the secrets as input key material (IKM), then extract + expand.

```
IKM  = X25519_secret (32 B) ‖ ML-KEM_secret (32 B)   = 64 B total
Salt = os.urandom(32)          — fresh per message
Info = b"pqhe-v1-aes256gcm"   — domain separation label
Output = HKDF-SHA-256(IKM, Salt, Info, length=32)     → master_key
```

HKDF (RFC 5869) has two stages:
1. **Extract:** `PRK = HMAC-SHA256(salt, IKM)` — mixes entropy into a uniform pseudorandom key.
2. **Expand:** `OKM = HMAC-SHA256(PRK, info ‖ counter)` — stretches to the desired length with domain separation.

Why not XOR the secrets? XOR is only safe if both secrets are independently uniformly random. HKDF is safe even if one secret is biased or partially compromised.

---

## Q4: Why AES-256-GCM? Why not ChaCha20-Poly1305?

**Short answer:** Both are excellent; AES-256-GCM was chosen for NIST alignment.

ChaCha20-Poly1305 is often preferred on devices without hardware AES acceleration (e.g., ARM IoT). AES-256-GCM has hardware acceleration (`AESNI`) on all modern x86/x64 processors and is the NIST-approved choice. Since this project targets desktop/server environments and uses the `cryptography` library (backed by OpenSSL, which uses `AESNI`), AES-256-GCM is the natural fit.

Both provide authenticated encryption — they're equally secure for this use case.

---

## Q5: What is AAD and why do you put metadata in it?

**Short answer:** Additional Authenticated Data binds the ciphertext to its metadata — tampering with metadata is detected.

In AES-256-GCM, the authentication tag covers both the ciphertext and the AAD. AAD is *not* encrypted — it's just authenticated. This means:

- You can read the metadata (sender, recipient, version) without decrypting.
- Any modification to the metadata causes the tag check to fail.

PQ-HE binds: `version ‖ algorithm ‖ sender_key_id ‖ recipient_key_id` into AAD via `PacketMetadata.make_aad()`.

**Without AAD binding:** An attacker could change the `sender_key_id` in the JSON from "alice" to "mallory" without detection — the ciphertext would still decrypt successfully. With AAD binding, this tampering is caught.

This is verified by `TestMetadataBinding` in the security integration tests.

---

## Q6: What does "forward secrecy" mean and does PQ-HE have it?

**Short answer:** Yes, partial forward secrecy via ephemeral X25519 key generation.

Forward secrecy means that compromise of a long-term private key doesn't expose *past* messages.

PQ-HE generates a **fresh ephemeral X25519 key pair for every encryption**. The ephemeral private key is never stored. The ciphertext contains only the ephemeral *public* key. 

- If Alice's long-term X25519 private key is compromised tomorrow, past messages remain safe because each uses a different ephemeral key.
- The ML-KEM layer uses the recipient's *long-term* public key, so it does not provide forward secrecy (this is inherent to KEMs — the ciphertext can always be re-decapsulated with the static key).

---

## Q7: How are shared secrets protected in memory?

**Short answer:** Best-effort wiping via `ctypes.memset`; inherently limited by Python.

`src/utils/secure_bytes.py` provides `wipe(bytearray)`, which calls `ctypes.memset` to zero the backing memory in-place. This works for `bytearray` objects.

Limitations:
- Python's `bytes` type is immutable and cannot be wiped.
- The `cryptography` library returns `bytes` from ECDH/AES operations.
- CPython's garbage collector may move objects or hold internal copies.

The mitigation is `wipe_bytes_copy(secret_bytes) → bytearray` which makes a wipeable copy. Shared secrets are wiped after being passed to HKDF. This reduces (but cannot eliminate) the window during which secrets live in process memory.

---

## Q8: Why use frozen dataclasses for models?

**Short answer:** Immutability, hashability, and accidental mutation prevention.

`@dataclass(frozen=True)` provides:
1. **Immutability** — fields cannot be changed after construction. A key model cannot be accidentally modified mid-flight.
2. **Hashability** — frozen dataclasses are hashable (unless they contain mutable fields), enabling use as dict keys or in sets.
3. **Security** — private key `raw_bytes` can never be overwritten — you must construct a new object.
4. **Clarity** — models are pure data carriers. No methods that modify state. Easy to reason about.

The tradeoff: you can't update a field in-place. For immutable cryptographic material, this is a feature, not a bug.

---

## Q9: Why lazy-import `pyoqs`?

**Short answer:** Graceful degradation — the tool should work without ML-KEM support.

`pyoqs` requires `liboqs` (a C library). Not every environment has it installed. If we imported `oqs` at module load time, the entire application would crash on import.

The lazy import pattern:
```python
_OQS_AVAILABLE = False
try:
    import oqs as _oqs
    _OQS_AVAILABLE = True
except ImportError:
    pass

def generate_keypair():
    if not _OQS_AVAILABLE:
        raise RuntimeError("pyoqs is not installed. Install liboqs + pyoqs.")
    ...
```

This way:
- `pqhe status` works and shows "ML-KEM: missing" with install instructions.
- `pqhe keygen` and `pqhe encrypt/decrypt` work in X25519-only mode.
- ML-KEM features activate automatically when pyoqs is installed.

---

## Q10: What would happen if a quantum computer attacked this system?

**If only X25519-only mode is used:**
- A CRQC running Shor's algorithm could recover the X25519 shared secret from the ephemeral public key in the packet.
- Combined with the HKDF salt (also in the packet), it could recompute the master key and decrypt the ciphertext.
- **X25519-only packets are NOT quantum-safe.**

**If hybrid mode is used (ML-KEM-768):**
- The CRQC breaks X25519 → gets `classical_secret`.
- The master key = `HKDF(classical_secret ‖ ML-KEM_secret)`. The CRQC still needs `ML-KEM_secret`.
- ML-KEM is based on MLWE (Module Learning With Errors). No known quantum algorithm (including Grover's) breaks it faster than its classical equivalent.
- The attacker would need a breakthrough in lattice cryptanalysis to proceed.
- **Hybrid mode packets are designed to be quantum-safe.**

---

## Q11: What are the limitations of this project?

1. **No digital signatures** — PQ-HE provides confidentiality and integrity, but not non-repudiation. A message cannot be proven to have come from Alice.

2. **No PKI / key distribution** — Public keys are distributed out-of-band (files). There's no certificate authority, no key server, no revocation.

3. **Single recipient per packet** — Encrypting for multiple recipients requires creating multiple packets.

4. **File size limit** — 100 MiB maximum plaintext. Streaming encryption is not implemented.

5. **No key derivation from passphrase** — Private keys are stored as raw bytes. Passphrase-protected keys (PKCS#8) are not supported.

6. **Not production-audited** — This is a portfolio project. A professional cryptographic audit is required before use in production systems.

---

## Q12: How would you extend this for production use?

1. **Passphrase-protected keys** — wrap private key bytes in PKCS#8 with AES-256-GCM + Argon2id.
2. **Streaming encryption** — chunk plaintext for files > 100 MiB; use a derived per-chunk key.
3. **Digital signatures** — add Ed25519 signing of the packet JSON for non-repudiation.
4. **Key server** — X.509-like infrastructure or a simple REST API for public key distribution.
5. **HSM / TPM support** — offload private key operations to hardware for the most sensitive deployments.
6. **Cross-language interoperability** — publish the `.enc` JSON schema so other implementations can interoperate.
