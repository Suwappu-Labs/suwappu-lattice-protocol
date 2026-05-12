# Threshold BLS Signing (Spec C3c)

**Author:** Javier Calderon Jr, CTO — Global Settlement (GSX)
**Date:** May 11, 2026
**Depends on:** C3b (Threshold DKG) — completed
**Delivers:** Committees produce threshold BLS signatures over attestations, state roots, and cross-VM messages

---

## Overview

Spec C3c adds threshold BLS signing on top of the DKG-produced keys from C3b. Each committee member creates a partial signature using their secret share, partial signatures are combined via Lagrange interpolation in G2, and the result is a standard BLS signature verifiable by anyone with the group public key.

The combined threshold signature is mathematically identical to a regular BLS signature. Verifiers do not need to know it was threshold-produced.

---

## Approach: Hybrid (ec_backend sign, BLS verify)

Partial signing uses `ec_backend.py` G2 operations (participants need raw scalar access to their secret shares). Combination is Lagrange interpolation in G2. Verification delegates to the existing `BLS` class in `bls.py`, which gives `blst` speed in production and `py_ecc` fallback in development.

**Why hybrid:**
- Signing needs raw curve access for scalar-mul with secret shares — consistent with the DKG layer's `py_ecc` dependency
- Verification is called far more often than signing — gets the `blst` fast path when available
- A combined threshold BLS signature is indistinguishable from a regular BLS signature — clean abstraction boundary

---

## 1. Data Types

### ThresholdSigningKey (frozen dataclass)

The private material each participant holds after DKG.

| Field | Type | Description |
|-------|------|-------------|
| `participant_fp` | `bytes` | 32-byte fingerprint of the participant |
| `participant_index` | `int` | 1-based index in the DKG ceremony |
| `secret_share` | `int` | Scalar in Z_r — the signing key |
| `group_pk` | `bytes` | 96-byte serialized uncompressed G1 — the group public key |
| `threshold` | `int` | t in t-of-n |
| `epoch` | `int` | Which epoch this key belongs to |
| `vm_tag` | `int` | Which VM |

### PartialSignature (frozen dataclass)

What a participant produces when signing.

| Field | Type | Description |
|-------|------|-------------|
| `signer_fp` | `bytes` | 32-byte fingerprint — who signed |
| `signer_index` | `int` | DKG participant index — needed for Lagrange coefficient |
| `signature` | `bytes` | 96-byte compressed G2 point |
| `epoch` | `int` | Which epoch's key was used |

### DKGResult extension

Add one optional field to the existing `DKGResult` frozen dataclass:

```python
my_secret_share: Optional[int] = None  # using field(default=None) for frozen compat
```

- **Software mode:** Populated with the participant's secret share scalar. A `ThresholdSigningKey` can be constructed directly from the `DKGResult`.
- **HSM mode:** `None`. The key arrives through a separate secure channel.

This is a dual-mode design: both storage approaches are supported, with the security context determining which path is used.

---

## 2. Signing Protocol

### partial_sign(key, message, domain) -> PartialSignature

1. Prepend domain tag to message: `tagged = domain + message`
2. Hash `tagged` to a G2 point using the same hash-to-curve algorithm that `py_ecc.bls.G2ProofOfPossession.Sign()` uses internally (`hash_to_G2` per draft-irtf-cfrg-hash-to-curve). This exact match is what makes the combined sig compatible with `BLS.verify()`. Implementation: call `py_ecc`'s `hash_to_G2(tagged, DST)` directly with the standard `BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_` DST.
3. Scalar-multiply the G2 hash point by `key.secret_share`: `sig_i = share_i * H(tagged)`
4. Compress the G2 point to 96 bytes
5. Return as `PartialSignature`

### combine_partial_signatures(partials, threshold) -> bytes

1. Validate `len(partials) >= threshold` — raise `ValueError` if not
2. Extract signer indices from the partials
3. For each partial, compute Lagrange coefficient `L_i(0)` using `ScalarPoly.lagrange_coefficient(i, indices)`
4. Decompress each partial signature back to a G2 point
5. Compute: `combined = sum(L_i(0) * sig_i)` — Lagrange-weighted G2 point addition
6. Compress to 96 bytes — this is now a standard BLS signature

**Mathematical identity:** `combined = Σ(L_i(0) * share_i * H(m)) = (Σ L_i(0) * share_i) * H(m) = secret * H(m)` — Lagrange reconstruction recovers the group secret in the exponent without ever exposing it.

### threshold_verify(group_pk, message, signature, domain) -> bool

1. Prepend domain tag: `tagged = domain + message`
2. Convert `group_pk` from 96-byte uncompressed G1 (DKG format) to 48-byte compressed G1 (`BLS.verify()` format) via `g1_compress()`
3. Call `BLS.verify(compressed_pk, tagged, signature)` — delegates to `blst` or `py_ecc`
4. Return the boolean result

The combined signature is indistinguishable from a regular BLS signature. `BLS.verify()` works unchanged.

### Domain Separation Constants

```python
DOMAIN_ATTESTATION = b"ETP-THRESHOLD-ATTESTATION:v1"
DOMAIN_STATE_ROOT  = b"ETP-THRESHOLD-STATE-ROOT:v1"
DOMAIN_CROSS_VM    = b"ETP-THRESHOLD-CROSS-VM:v1"
```

These prevent cross-context replay. A signature over an attestation cannot be reinterpreted as a signature over a state root.

---

## 3. ec_backend G2 Additions

New functions added to `src/ltp/zk/ec_backend.py`, mirroring existing G1 functions:

| Function | Returns | Description |
|----------|---------|-------------|
| `g2_generator()` | `G2Point` | BLS12-381 G2 generator |
| `g2_scalar_mul(point, scalar)` | `G2Point` | Scalar multiplication in G2 |
| `g2_add(p1, p2)` | `G2Point` | Point addition in G2 |
| `g2_identity()` | `G2Point` | Point at infinity in G2 |
| `g2_serialize(point)` | `bytes` | 192-byte uncompressed G2 (4 x 48B) |
| `g2_deserialize(data)` | `G2Point` | Deserialize 192 bytes to G2 point |
| `g2_compress(point)` | `bytes` | 96-byte compressed G2 (BLS.verify format) |
| `g1_compress(point)` | `bytes` | 48-byte compressed G1 (BLS.verify format) |

Implementation uses `py_ecc.bls12_381.G2`, `multiply`, `add` — same module the G1 ops already import from. All functions guarded by `_require_backend()`.

The G2 serialization must produce output compatible with the `blst` and `py_ecc` BLS verification APIs. Compressed G2 follows the Zcash serialization format (same as Ethereum 2.0).

No changes to existing G1 functions.

---

## 4. DKG Integration & Secret Share Flow

### DKGSession.finalize() changes

Current: returns `DKGResult` only, `my_secret_share` is a local variable that's discarded.

New signature:

```python
def finalize(self) -> tuple[DKGResult, ThresholdSigningKey]:
```

1. `DKGResult` gets `my_secret_share` populated (software mode)
2. A `ThresholdSigningKey` is constructed from the share, index, group_pk, threshold, epoch, vm_tag
3. Both are returned

**Breaking change** — three callers need updating:
- `CommitteeManager._run_dkg_ceremony()`
- `tests/test_dkg_session.py`
- `tests/test_dkg_e2e.py`

### CommitteeManager changes

New private state:

```python
self._signing_keys: dict[int, list[ThresholdSigningKey]] = {}
```

Maps epoch to signing keys. In the current single-process model, all participants' keys are held (the manager runs all DKG sessions locally). In multi-node (D2), each node holds only its own key.

New public method:

```python
def sign_as_committee(self, message: bytes, domain: bytes) -> bytes | None:
```

1. Get current epoch's signing keys from `self._signing_keys`
2. Select `threshold` participants (first `t` keys)
3. Call `partial_sign()` for each
4. Call `combine_partial_signatures()`
5. Return the 96-byte combined signature, or `None` if no DKG result exists

This is the synchronous single-process version. When D2 lands, the internals become an async protocol where each node signs its partial and broadcasts it. The method signature stays the same.

### Verification convenience

```python
def verify_committee_signature(self, message: bytes, signature: bytes, domain: bytes, epoch: int | None = None) -> bool:
```

Looks up the group_pk for the given epoch (defaults to current), calls `threshold_verify()`.

---

## 5. File Structure

| Action | Path | Responsibility |
|--------|------|---------------|
| Create | `src/ltp/execution/committee/dkg/threshold_signing.py` | `ThresholdSigningKey`, `PartialSignature`, `partial_sign()`, `combine_partial_signatures()`, `threshold_verify()`, domain constants |
| Modify | `src/ltp/zk/ec_backend.py` | Add G2 operations: `g2_generator`, `g2_scalar_mul`, `g2_add`, `g2_identity`, `g2_serialize`, `g2_deserialize`, `g2_compress`, `g1_compress` |
| Modify | `src/ltp/execution/committee/dkg/types.py` | Add `my_secret_share` field to `DKGResult` |
| Modify | `src/ltp/execution/committee/dkg/session.py` | `finalize()` returns `tuple[DKGResult, ThresholdSigningKey]` |
| Modify | `src/ltp/execution/committee/manager.py` | Add `_signing_keys`, `sign_as_committee()`, `verify_committee_signature()` |
| Modify | `src/ltp/execution/committee/dkg/__init__.py` | Export new types |
| Modify | `src/ltp/execution/committee/__init__.py` | Re-export new types |
| Modify | `src/ltp/execution/__init__.py` | Re-export new types |
| Create | `tests/test_ec_backend_g2.py` | G2 operation tests |
| Create | `tests/test_threshold_signing.py` | Unit tests for signing protocol |
| Create | `tests/test_threshold_signing_e2e.py` | Full DKG -> sign -> verify ceremony tests |
| Create | `tests/test_threshold_signing_integration.py` | CommitteeManager integration tests |
| Modify | `tests/test_dkg_session.py` | Update for new `finalize()` return type |
| Modify | `tests/test_dkg_e2e.py` | Update for new `finalize()` return type |

---

## 6. Testing Strategy

### Unit tests (test_threshold_signing.py)

- `partial_sign()` produces a valid G2 point (96-byte compressed)
- Two partial sigs from same key + message are identical (deterministic)
- Partial sig from a different message differs
- `combine_partial_signatures()` succeeds with exactly `t` partials
- `combine_partial_signatures()` raises with `t-1` partials
- `threshold_verify()` accepts combined sig against group_pk
- `threshold_verify()` rejects tampered message
- `threshold_verify()` rejects sig from a different group
- Domain separation: same message + different domains = different signatures

### ec_backend G2 tests (test_ec_backend_g2.py)

- `g2_generator()` returns non-identity point
- `g2_scalar_mul()` by 1 returns generator
- `g2_scalar_mul()` by 0 returns identity
- `g2_add()` is commutative
- `g2_serialize()` / `g2_deserialize()` round-trip
- `g1_compress()` produces 48 bytes
- `g2_compress()` produces 96 bytes
- Compressed G1/G2 output is compatible with `BLS.verify()` input formats

### End-to-end (test_threshold_signing_e2e.py)

- Full ceremony: DKG -> extract signing keys -> partial sign -> combine -> verify
- Multiple epochs produce different group keys, both sign/verify independently
- Any t-subset of n participants produces a valid combined sig
- Different t-subsets produce the same combined signature (key property)
- t-1 participants cannot produce a valid sig

### Integration (test_threshold_signing_integration.py)

- `CommitteeManager.sign_as_committee()` returns valid sig when `dkg_threshold > 0`
- `CommitteeManager.sign_as_committee()` returns `None` when `dkg_threshold == 0`
- `verify_committee_signature()` accepts the signature
- Signature survives epoch advance (verified against correct epoch's group_pk)

### Property-based (added to test_dkg_hypothesis.py)

- For any random message and valid DKG ceremony, `threshold_verify(combine(partial_sign(...)))` holds
- Any t-sized subset of n participants reconstructs the same combined signature

### All G2/signing tests gated by

```python
@pytest.mark.skipif(not bls12_381_available(), reason="py_ecc not installed")
```

**Estimated:** ~40-50 new tests across 4 new test files + updates to 2 existing files.

---

## 7. Gate 5 Criteria

- [ ] `partial_sign()` + `combine_partial_signatures()` produces valid BLS signature
- [ ] `threshold_verify()` accepts t-of-n partial sigs, rejects t-1
- [ ] Different t-subsets produce the same combined signature
- [ ] Domain separation prevents cross-context replay
- [ ] `CommitteeManager.sign_as_committee()` produces threshold-signed output when DKG result exists
- [ ] `verify_committee_signature()` validates against group_pk
- [ ] All 3,530+ existing tests still pass (no regressions)
- [ ] New tests: ~40-50 added

---

## 8. Non-Goals (Deferred)

- **Async partial signature collection over P2P** — requires D2 (transport). Current implementation is synchronous single-process.
- **HSM-backed secret share storage** — requires F2 (HSM integration). The `ThresholdSigningKey` abstraction supports it; the concrete HSM path is deferred.
- **Signature aggregation across VMs** — out of scope for C3c. Each VM's committee signs independently.
- **On-chain threshold verification** — the Solidity contracts verify standard BLS sigs. Since threshold sigs are indistinguishable, no contract changes needed.
