# LTP Core Hardening: Real Cryptographic Backend Integration

## What This Achieves

The dual-lane architecture was architecturally complete but running entirely on **simulated cryptographic primitives** — hash-derived keystreams pretending to be encryption, lookup tables pretending to be key encapsulation/signatures. This work swaps in **real cryptographic backends** while preserving the PoC fallback for environments without the libraries installed.

## Before vs After

| Primitive | Before | After |
|-----------|--------|-------|
| **AEAD** | HMAC-XOR keystream (PoC) | **XChaCha20-Poly1305** via `pynacl` (24B nonce, 16B Poly1305 tag) |
| **ML-KEM-768** | Lookup tables simulating encaps/decaps | **Real lattice math** via `pqcrypto.kem.ml_kem_768` (FIPS 203 algorithm) |
| **ML-DSA-65** | Lookup tables simulating sign/verify | **Real lattice math** via `pqcrypto.sign.ml_dsa_65` (FIPS 204 algorithm) |
| **BLAKE3** | Already worked when installed | Unchanged — internal lane only |
| **SHA3-256** | Already real (`hashlib`) | Unchanged — canonical lane |
| **Canonical lane policy** | Rejected BLAKE3 only with `set_compliance_strict(True)` | **Always rejects non-FIPS** — the wall is enforced unconditionally |

## Files Changed (11 total)

### 1. `pyproject.toml` — Dependency declarations

Added `crypto` optional-dependency group (`pqcrypto`, `pynacl`) and included them in `dev`.

### 2. `src/ltp/dual_lane/hashing.py` — Canonical lane hard-pinning

`canonical_hash()` and `canonical_hash_bytes()` now **unconditionally reject** BLAKE3 and BLAKE2b. Previously this was gated behind `set_compliance_strict(True)`. The canonical lane is the trust root for entity IDs, commitment records, Merkle roots, approval receipts, and signatures — it must always be FIPS-approved. The `set_compliance_strict()` function still exists for backward compatibility but is now redundant for the canonical lane.

### 3. `src/ltp/primitives.py` — Backend detection + dispatch (the core change)

**Backend detection** — Three `try/except ImportError` blocks at module top probe for `pqcrypto.kem.ml_kem_768`, `pqcrypto.sign.ml_dsa_65`, and `nacl.bindings`. Boolean flags (`_pqcrypto_kem_available`, etc.) control dispatch. The PoC warning now only fires when pqcrypto is absent.

**AEAD class** — When pynacl is available:
- `NONCE_SIZE` = 24 (XChaCha20), `TAG_SIZE` = 16 (Poly1305)
- `encrypt()` delegates to `crypto_aead_xchacha20poly1305_ietf_encrypt`
- `decrypt()` delegates to the decrypt counterpart
- Size assertions at the boundary verify output matches expectations
- PoC code (hash keystream + HMAC tag) becomes the `else` branch, untouched

**MLKEM class** — `_use_real_backend()` checks if pqcrypto is installed AND current profile sizes match ML-KEM-768 (Level 3). This is critical: the real backend only implements ML-KEM-768 (ek=1184, dk=2400), so Level 5 (ML-KEM-1024, ek=1568, dk=3168) gracefully falls back to PoC. When real:
- `keygen()` calls `pqcrypto.kem.ml_kem_768.generate_keypair()`
- `encaps()` calls `encrypt(ek)` and **swaps the return order** from `(ct, ss)` to `(ss, ct)` to match LTP's API
- `decaps()` calls `decrypt(dk, ct)` — real lattice decryption, no lookup tables needed
- All three have `RuntimeError` size assertions (not `assert`, survives `-O`)

**MLDSA class** — Same pattern. `_use_real_backend()` checks sizes match ML-DSA-65:
- `keygen()` calls `pqcrypto.sign.ml_dsa_65.generate_keypair()`
- `sign()` calls `sign(sk, message)` with size assertion on the 3309-byte signature
- `verify()` is **exception-tolerant**: wraps `_dsa_verify()` in try/except because some backends raise on invalid signatures while others return False. Handles both.

### 4. `src/ltp/hsm.py` — HSM decapsulation fix

`SoftwareHSM.kem_decaps()` previously used a brittle hack: importing `SealedBox._PoC_encaps_table` and doing manual lookup. Now it simply calls `MLKEM.decaps(entry["private"], kem_ciphertext)` — works for both real and PoC backends.

### 5. `src/ltp/keypair.py` — Dynamic nonce sizes in SealedBox

`SealedBox.seal()` generates `os.urandom(AEAD.NONCE_SIZE)` instead of hardcoded 16. `SealedBox.unseal()` uses `AEAD.NONCE_SIZE` for framing offsets (where to split kem_ct | nonce | aead_ct in the sealed blob).

### 6. `src/ltp/shards.py` — Dynamic nonce in shard encryption

`ShardEncryptor._nonce()` derives `digest[:AEAD.NONCE_SIZE]` instead of `digest[:16]`.

### 7. `src/ltp/protocol.py` — Dynamic sizes in logging

Added `AEAD` import, replaced hardcoded "nonce: 16 bytes | aead_tag: 32 bytes" with dynamic values.

### 8. `src/ltp/__main__.py` — Demo nonce fix

The compliance demo generated a 16-byte nonce for an AEAD round-trip test. Updated to `AEAD.NONCE_SIZE`.

### 9. `tests/test_backend_boundaries.py` — New test file (25 tests)

Four test categories:

- **Lane boundary enforcement (7 tests)**: Proves canonical lane always rejects BLAKE3/BLAKE2b, accepts SHA3-256/SHA-384/SHA-512, and that strict mode is now redundant.
- **Trust anchor independence (3 tests)**: Proves entity IDs, commitment record hashes, and ML-DSA signatures never touch the internal lane.
- **Protocol-shape assertions (12 tests)**: Verifies FIPS 203/204 sizes (ek=1184, dk=2400, ct=1088, ss=32, vk=1952, sk=4032, sig=3309), AEAD nonce/tag sizes, sealed box framing, and includes **stateless decaps/verify tests** (skipped if pqcrypto isn't installed) that clear PoC tables and prove real backends work without them.
- **Trust artifact invariance (3 tests)**: Proves entity IDs, commitment hashes, and ML-DSA signatures are byte-for-byte identical regardless of whether BLAKE3 is installed for the internal lane.

### 10. `tests/test_compliance.py` — Adapted existing tests

- Removed `SealedBox._PoC_encaps_table` hacks from HSM KEM tests
- Updated wrong-key tests for **implicit rejection** (real ML-KEM returns a different shared secret instead of raising)
- Updated nonces from hardcoded 16 to `AEAD.NONCE_SIZE`
- Updated `test_different_algos_different_hashes` to use only FIPS-approved algorithms
- Updated sealed-box size assertions to use dynamic sizes

### 11. `tests/test_primitives.py` + `tests/test_dual_lane.py` — Adapted

- All AEAD tests use `AEAD.NONCE_SIZE`
- Wrong-dk test handles implicit rejection
- Error message patterns updated for the always-strict canonical lane

## Key Design Decisions

1. **Graceful Level 5 fallback**: `_use_real_backend()` checks if profile sizes match the imported backend (ML-KEM-768 / ML-DSA-65). Level 5 (ML-KEM-1024 / ML-DSA-87) silently falls back to PoC. No code changes needed when a Level 5 backend is eventually added — just add the import and update the size check.

2. **Zero API changes**: Every caller of `MLKEM.keygen()`, `AEAD.encrypt()`, `SealedBox.seal()`, etc. works unchanged. The dispatch is entirely internal.

3. **Implicit rejection**: Real ML-KEM doesn't raise on wrong-key decapsulation — it returns a pseudorandom shared secret (FIPS 203 spec). This is correct behavior. The AEAD layer downstream catches the failure (wrong key = wrong ciphertext = authentication failure).

4. **RuntimeError over assert**: All size checks at backend boundaries use explicit `RuntimeError`/`ValueError` so they survive Python's `-O` optimization flag.

## Test Results

- **884 passed**, 3 pre-existing failures (unrelated to this work), 0 regressions
- All 25 new backend boundary tests pass
- Demo runs cleanly end-to-end
