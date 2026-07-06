# PQ-HE Architecture Guide

## Design Principles

| Principle | How it's applied |
|---|---|
| **MVC** | Views render, Controllers orchestrate, Services compute |
| **Clean Architecture** | Dependency rule: outer layers depend on inner layers, never reversed |
| **SOLID** | Single-responsibility per class; DI in `EncryptionOrchestrator` |
| **Fail-safe defaults** | Missing ML-KEM falls back to X25519-only without configuration |
| **Defense in depth** | Validation at CLI, controller, and storage layers independently |

---

## Layer Diagram

```
┌──────────────────────────────────────────────────────────────────┐
│                          CLI (views)                             │
│  keygen_cmd  encrypt_cmd  decrypt_cmd  status_cmd                │
│  Click + Rich — zero crypto, zero file I/O                       │
└────────────────────────────┬─────────────────────────────────────┘
                             │ calls
┌────────────────────────────▼─────────────────────────────────────┐
│                       Controllers                                │
│  KeygenController  EncryptController  DecryptController          │
│  StatusController                                                │
│  Validates input, calls services, returns result dataclass       │
└───────────────────┬────────────────────────┬─────────────────────┘
                    │ calls                  │ calls
┌───────────────────▼────────┐  ┌────────────▼────────────────────┐
│         Services           │  │           Storage               │
│  X25519Service             │  │  KeyStorage                     │
│  MLKEMService              │  │  0o600 private / 0o644 public   │
│  HKDFService               │  └─────────────────────────────────┘
│  AESService                │
│  PacketService             │
│  EncryptionOrchestrator    │
└───────────────────┬────────┘
                    │ calls
┌───────────────────▼────────────────────────────────────────────┐
│                      Crypto Primitives                         │
│  classical/x25519.py    — X25519 ECDH                          │
│  classical/aes_gcm.py   — AES-256-GCM                         │
│  hybrid/hkdf.py         — HKDF-SHA-256                        │
│  post_quantum/ml_kem.py — ML-KEM-768 (lazy import of pyoqs)   │
└────────────────────────────────────────────────────────────────┘

Models flow between all layers as immutable frozen dataclasses.
```

---

## Encryption Data Flow

```
Input: plaintext (bytes), recipient X25519 pub, [recipient ML-KEM pub]

Step 1 — Ephemeral key generation
  X25519Service.generate_keypair("ephemeral-{sender_id}")
  → (ephemeral_priv: X25519PrivateKeyModel, ephemeral_pub: X25519PublicKeyModel)

Step 2 — Classical ECDH
  X25519Service.compute_shared_secret(ephemeral_priv, recipient_x25519_pub)
  → classical_secret: SharedSecretModel  (32 bytes)

Step 3 — Post-quantum KEM (optional)
  MLKEMService.encapsulate(recipient_mlkem_pub)
  → (mlkem_ciphertext: MLKEMCiphertextModel, pq_secret: SharedSecretModel)
  [skipped if pyoqs unavailable or recipient_mlkem_pub is None]

Step 4 — Hybrid key derivation
  HKDFService.derive_hybrid(classical_secret, pq_secret=None|SharedSecretModel)
  IKM = classical_secret.raw_bytes [‖ pq_secret.raw_bytes if hybrid]
  HKDF-SHA-256(IKM, salt=os.urandom(32), info=b"pqhe-v1-aes256gcm", length=32)
  → key_material: HybridKeyMaterial  (master_key=32 B, salt=32 B, info=bytes)

Step 5 — AAD construction
  PacketMetadata(version, algorithm, created_at, sender_id, recipient_id)
  .make_aad() → b"v1|X25519+...|alice|bob"

Step 6 — AES-256-GCM encryption
  AESService.encrypt(key_material, plaintext, aad=aad)
  → AESPayload(ciphertext=plaintext+tag, iv=12B, aad=aad)

Step 7 — Packet assembly
  PacketService.assemble(aes_payload, key_material, ephemeral_pub, ...)
  → EncryptedPacket (JSON-serializable frozen dataclass)

Output: EncryptedPacket written to .enc file as JSON
```

---

## Decryption Data Flow

```
Input: EncryptedPacket (loaded from .enc file), recipient X25519 priv, [recipient ML-KEM priv]

Step 1 — Packet validation
  PacketService.validate(packet)
  Checks: version in {"1"}, field lengths, non-empty key IDs

Step 2 — Reconstruct ephemeral public key
  X25519Service.public_key_from_raw_bytes(packet.x25519_ephemeral_public_bytes)
  → ephemeral_pub: X25519PublicKeyModel

Step 3 — Classical ECDH (reversed)
  X25519Service.compute_shared_secret(recipient_x25519_priv, ephemeral_pub)
  → classical_secret: SharedSecretModel  (same 32 bytes as encryption)

Step 4 — ML-KEM decapsulation (if packet.is_hybrid)
  MLKEMService.decapsulate(recipient_mlkem_priv, mlkem_ciphertext_from_packet)
  → pq_secret: SharedSecretModel

Step 5 — HKDF re-derivation (using stored salt)
  HKDFService.derive_hybrid(classical_secret, pq_secret, salt=packet.hkdf_salt_bytes)
  → key_material: HybridKeyMaterial  (same master_key as encryption)

Step 6 — AES-256-GCM decryption + integrity check
  Reconstruct AAD from packet.metadata.make_aad()
  AESService.decrypt(key_material, AESPayload(ct, iv, aad))
  → plaintext bytes  [raises AuthenticationError if tag invalid]

Output: plaintext bytes written to output file
```

---

## EncryptedPacket JSON Format

The on-disk format is self-contained — everything needed for decryption is present:

```
{
  // Metadata (also bound into AES-GCM AAD — tampering is detected)
  "version": "1",
  "algorithm": "X25519+ML-KEM-768+HKDF-SHA256+AES-256-GCM",
  "created_at": "2025-07-05T12:00:00.000000+00:00",
  "sender_key_id": "alice",
  "recipient_key_id": "bob",

  // Ephemeral public key for ECDH (NOT a secret — safe to transmit)
  "x25519_ephemeral_public_b64": "<base64, 32 bytes>",

  // ML-KEM ciphertext (NOT a secret — only the recipient can decapsulate)
  "mlkem_ciphertext_b64": "<base64, 1088 bytes>",  // absent in classical mode

  // HKDF parameters
  "hkdf_salt_b64": "<base64, 32 bytes>",

  // AES-256-GCM output
  "iv_b64": "<base64, 12 bytes>",
  "ciphertext_b64": "<base64, len(plaintext) + 16 bytes>"
                                                   // +16 = GCM auth tag
}
```

**Nothing secret is in the packet file.** The master key exists only in memory during encryption/decryption.

---

## Key File Format

### X25519 private key (`{id}_x25519_private.json`) — `0o600`
```json
{
  "key_type": "private",
  "key_id": "alice",
  "algorithm": "X25519",
  "created_at": "2025-07-05T12:00:00+00:00",
  "raw_bytes_b64": "<base64, 32 bytes>"
}
```

### X25519 public key (`{id}_x25519_public.json`) — `0o644`
Same structure with `"key_type": "public"`.

### ML-KEM-768 private key (`{id}_mlkem_private.json`) — `0o600`
Same structure; `raw_bytes_b64` is 2400 bytes (base64-encoded).

### ML-KEM-768 public key (`{id}_mlkem_public.json`) — `0o644`
Same structure; `raw_bytes_b64` is 1184 bytes.

---

## Dependency Injection

`EncryptionOrchestrator` accepts all five services via constructor:

```python
class EncryptionOrchestrator:
    def __init__(
        self,
        x25519_service=None,
        mlkem_service=None,
        hkdf_service=None,
        aes_service=None,
        packet_service=None,
    ):
        self._x25519 = x25519_service or X25519Service()
        ...
```

This makes unit testing trivial — inject mocks without patching global state.

---

## Configuration

All configuration comes from environment variables (`.env` file) prefixed `PQHE_`:

| Variable | Default | Description |
|---|---|---|
| `PQHE_KEYS_DIR` | `./keys` | Default key storage directory |
| `PQHE_LOG_LEVEL` | `INFO` | Log level |
| `PQHE_LOG_FORMAT` | `json` | `json` or `console` |
| `PQHE_LOG_DIR` | `./logs` | Log file directory |
| `PQHE_ENV` | `development` | `development` or `production` |
| `PQHE_KEM_ALGORITHM` | `Kyber768` | ML-KEM variant (for pyoqs) |

Pydantic-settings validates types and raises on startup if required vars are missing.
