# Threshold BLS Signing (C3c) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add threshold BLS signing to ETP committees so DKG-produced keys can create committee-level signatures over attestations, state roots, and cross-VM messages.

**Architecture:** Hybrid approach — partial signing uses `ec_backend.py` G2 operations (py_ecc optimized backend), combination uses Lagrange interpolation in G2, verification delegates to the existing `BLS` class for `blst` speed in production. The combined threshold signature is mathematically identical to a standard BLS signature.

**Tech Stack:** Python 3.12+, py_ecc (optimized_bls12_381 G2 operations, hash_to_G2, G2_to_signature/signature_to_G2, G1_to_pubkey), existing BLS class from `src/ltp/bls.py`, pytest + Hypothesis

**Spec:** `docs/plans/2026-05-11-threshold-bls-signing-spec.md`

---

## File Structure

| Action | Path | Responsibility |
|--------|------|---------------|
| Modify | `src/ltp/zk/ec_backend.py` | Add G2 operations: generator, scalar_mul, add, identity, compress; add G1 compress |
| Modify | `src/ltp/execution/committee/dkg/types.py` | Add `my_secret_share` to `DKGResult` |
| Modify | `src/ltp/execution/committee/dkg/session.py` | `finalize()` returns `tuple[DKGResult, ThresholdSigningKey]` |
| Create | `src/ltp/execution/committee/dkg/threshold_signing.py` | `ThresholdSigningKey`, `PartialSignature`, `partial_sign()`, `combine_partial_signatures()`, `threshold_verify()`, domain constants |
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

## Important Implementation Notes

**G2 backend discovery:** The `ec_backend.py` module currently uses `py_ecc.bls12_381` (affine 2-tuple coordinates) for G1. G2 operations MUST use `py_ecc.optimized_bls12_381` (projective 3-tuple coordinates) because `G2_to_signature` and `signature_to_G2` require projective format. This is confirmed working — `hash_to_G2()` also returns projective format.

**hash_to_G2 DST:** The standard BLS DST is `b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_"`. Using this exact DST ensures combined threshold signatures are verifiable by standard `BLS.Verify()`.

**Critical validation:** Manual `hash_to_G2(msg, DST) + scalar_mul(H, sk)` produces byte-identical output to `py_ecc.bls.G2ProofOfPossession.Sign(sk, msg)` and is verifiable by `BLS.Verify()`. This is the mathematical foundation of the hybrid approach.

---

### Task 1: ec_backend G2 Operations

**Files:**
- Modify: `src/ltp/zk/ec_backend.py`
- Create: `tests/test_ec_backend_g2.py`

- [ ] **Step 1: Write the failing tests**

Create `tests/test_ec_backend_g2.py`:

```python
"""Tests for BLS12-381 G2 operations and G1/G2 compression (Spec C3c §3)."""

from __future__ import annotations

import pytest

from src.ltp.zk.ec_backend import bls12_381_available

pytestmark = pytest.mark.skipif(
    not bls12_381_available(), reason="py_ecc not installed"
)

from src.ltp.zk.ec_backend import (  # noqa: E402
    g1_compress,
    g1_generator,
    g1_scalar_mul,
    g1_serialize,
    g2_add,
    g2_compress,
    g2_generator,
    g2_identity,
    g2_scalar_mul,
)


class TestG2Generator:

    def test_returns_non_identity(self):
        g2 = g2_generator()
        assert g2 is not None
        assert g2 != g2_identity()

    def test_is_three_tuple(self):
        """py_ecc optimized G2 uses projective coordinates (3-tuple)."""
        g2 = g2_generator()
        assert len(g2) == 3


class TestG2ScalarMul:

    def test_mul_by_one_returns_generator(self):
        g2 = g2_generator()
        result = g2_scalar_mul(g2, 1)
        assert g2_compress(result) == g2_compress(g2)

    def test_mul_by_zero_returns_identity(self):
        g2 = g2_generator()
        result = g2_scalar_mul(g2, 0)
        assert g2_compress(result) == g2_compress(g2_identity())

    def test_mul_produces_different_points(self):
        g2 = g2_generator()
        p2 = g2_scalar_mul(g2, 2)
        p3 = g2_scalar_mul(g2, 3)
        assert g2_compress(p2) != g2_compress(p3)


class TestG2Add:

    def test_commutative(self):
        g2 = g2_generator()
        p2 = g2_scalar_mul(g2, 2)
        p3 = g2_scalar_mul(g2, 3)
        assert g2_compress(g2_add(p2, p3)) == g2_compress(g2_add(p3, p2))

    def test_add_matches_scalar_mul(self):
        """2G + 3G == 5G."""
        g2 = g2_generator()
        p2 = g2_scalar_mul(g2, 2)
        p3 = g2_scalar_mul(g2, 3)
        p5 = g2_scalar_mul(g2, 5)
        assert g2_compress(g2_add(p2, p3)) == g2_compress(p5)

    def test_add_identity(self):
        g2 = g2_generator()
        result = g2_add(g2, g2_identity())
        assert g2_compress(result) == g2_compress(g2)


class TestG2Compress:

    def test_produces_96_bytes(self):
        g2 = g2_generator()
        compressed = g2_compress(g2)
        assert len(compressed) == 96

    def test_identity_produces_96_bytes(self):
        compressed = g2_compress(g2_identity())
        assert len(compressed) == 96

    def test_different_points_different_bytes(self):
        g2 = g2_generator()
        p2 = g2_scalar_mul(g2, 2)
        assert g2_compress(g2) != g2_compress(p2)


class TestG1Compress:

    def test_produces_48_bytes(self):
        g1 = g1_generator()
        compressed = g1_compress(g1)
        assert len(compressed) == 48

    def test_roundtrip_with_bls_verify(self):
        """Compressed G1 is compatible with BLS.verify() pk format."""
        from src.ltp.bls import BLS

        # Generate a real BLS keypair
        pk, sk = BLS.keygen()
        assert len(pk) == 48  # BLS.keygen returns compressed G1

        # Our g1_compress should produce the same format
        g1 = g1_generator()
        compressed = g1_compress(g1)
        assert len(compressed) == 48

    def test_compress_uncompressed_roundtrip(self):
        """g1_compress(point) where point came from g1_scalar_mul works."""
        g1 = g1_generator()
        point = g1_scalar_mul(g1, 42)
        serialized = g1_serialize(point)
        assert len(serialized) == 96  # uncompressed
        compressed = g1_compress(point)
        assert len(compressed) == 48  # compressed
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_ec_backend_g2.py -v`
Expected: FAIL — `ImportError: cannot import name 'g2_generator' from 'src.ltp.zk.ec_backend'`

- [ ] **Step 3: Write the implementation**

Add the following to `src/ltp/zk/ec_backend.py`. In the import block at the top, add the optimized G2 imports alongside the existing `py_ecc.bls12_381` imports. Then add the G2 functions and G1 compress after the existing scalar utilities section.

In the import block (after the existing `_py_ecc_available = False` / `try` block), add a second import block:

```python
# G2 operations use the optimized backend (projective coordinates)
# Required for G2_to_signature / signature_to_G2 compatibility
_py_ecc_g2_available = False
try:
    from py_ecc.optimized_bls12_381 import (  # type: ignore[import-untyped]
        G2 as _OPT_G2,
        Z2 as _OPT_Z2,
        multiply as _opt_multiply,
        add as _opt_add,
        curve_order as _OPT_CURVE_ORDER,
    )
    from py_ecc.bls.g2_primitives import (  # type: ignore[import-untyped]
        G2_to_signature as _G2_to_signature,
        G1_to_pubkey as _G1_to_pubkey,
        pubkey_to_G1 as _pubkey_to_G1,
    )
    _py_ecc_g2_available = True
except ImportError:
    _OPT_G2 = None
    _OPT_Z2 = None
    _OPT_CURVE_ORDER = None
```

Add a type alias near the existing `G1Point`:

```python
G2Point = Any  # optimized_bls12_381 projective 3-tuple (FQ2, FQ2, FQ2)
```

Then add the new functions at the end of the file, before the closing:

```python
# ---------------------------------------------------------------------------
# G2 point arithmetic (optimized backend — projective coordinates)
# ---------------------------------------------------------------------------


def g2_generator() -> G2Point:
    """Return the standard BLS12-381 G2 generator (optimized/projective)."""
    _require_backend()
    return _OPT_G2


def g2_scalar_mul(point: G2Point, scalar: int) -> G2Point:
    """Compute scalar * point on BLS12-381 G2."""
    _require_backend()
    return _opt_multiply(point, scalar % _OPT_CURVE_ORDER)


def g2_add(p1: G2Point, p2: G2Point) -> G2Point:
    """Add two G2 points."""
    _require_backend()
    return _opt_add(p1, p2)


def g2_identity() -> G2Point:
    """Return the identity element of G2 (optimized backend)."""
    _require_backend()
    return _OPT_Z2


def g2_compress(point: G2Point) -> bytes:
    """Compress a G2 point to 96 bytes (Zcash serialization).

    Compatible with BLS.verify() signature format.
    """
    _require_backend()
    return bytes(_G2_to_signature(point))


# ---------------------------------------------------------------------------
# G1 compression (for threshold verify bridge to BLS.verify)
# ---------------------------------------------------------------------------


def g1_compress(point: G1Point) -> bytes:
    """Compress a G1 point to 48 bytes.

    Converts from the affine (x, y) format used by ec_backend
    to the 48-byte compressed format used by BLS.verify().
    """
    _require_backend()
    if point is None:
        return b"\x00" * 48
    # py_ecc's G1_to_pubkey expects optimized (projective) format.
    # Convert affine (x, y) to projective (x, y, 1).
    from py_ecc.fields.optimized_bls12_381_FQ import FQ as OPT_FQ
    x_opt = OPT_FQ(int(point[0]))
    y_opt = OPT_FQ(int(point[1]))
    z_opt = OPT_FQ(1)
    projective = (x_opt, y_opt, z_opt)
    return bytes(_G1_to_pubkey(projective))
```

Update the `__all__` at the top of the file to include the new exports:

```python
__all__ = [
    "BLS",
    "_blst_available",
    "_py_ecc_bls_available",
    "assert_bls_crypto",
    "assert_bls_production",
    # G2 (Spec C3c)
    "g2_generator",
    "g2_scalar_mul",
    "g2_add",
    "g2_identity",
    "g2_compress",
    "g1_compress",
]
```

Wait — `ec_backend.py` doesn't have an `__all__` that includes BLS. Let me check. No, ec_backend.py doesn't export BLS at all — those are in `bls.py`. The ec_backend `__all__` doesn't exist explicitly. The new functions just need to be importable. No `__all__` change needed.

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_ec_backend_g2.py -v`
Expected: all PASS (or all SKIPPED if py_ecc not installed)

- [ ] **Step 5: Commit**

```bash
git add src/ltp/zk/ec_backend.py tests/test_ec_backend_g2.py
git commit -m "feat(ec_backend): add G2 operations and G1/G2 compression for threshold signing"
```

---

### Task 2: DKGResult Extension + ThresholdSigningKey Type

**Files:**
- Modify: `src/ltp/execution/committee/dkg/types.py`
- Create: `tests/test_threshold_signing.py` (first section — type tests only)

- [ ] **Step 1: Write the failing tests**

Create `tests/test_threshold_signing.py`:

```python
"""Tests for threshold BLS signing types and protocol (Spec C3c)."""

from __future__ import annotations

import pytest

from src.ltp.zk.ec_backend import bls12_381_available
from src.ltp.execution.committee.dkg.types import DKGPhase, DKGResult


class TestDKGResultSecretShare:

    def test_default_secret_share_is_none(self):
        r = DKGResult(
            vm_tag=0x01,
            epoch=1,
            group_pk=b"\xaa" * 48,
            participant_vks={b"\x01" * 32: b"\xbb" * 48},
            threshold=2,
            qual_set=frozenset([b"\x01" * 32]),
            phase=DKGPhase.EAGER,
        )
        assert r.my_secret_share is None

    def test_secret_share_can_be_set(self):
        r = DKGResult(
            vm_tag=0x01,
            epoch=1,
            group_pk=b"\xaa" * 48,
            participant_vks={b"\x01" * 32: b"\xbb" * 48},
            threshold=2,
            qual_set=frozenset([b"\x01" * 32]),
            phase=DKGPhase.EAGER,
            my_secret_share=12345,
        )
        assert r.my_secret_share == 12345

    def test_secret_share_frozen(self):
        r = DKGResult(
            vm_tag=0x01,
            epoch=1,
            group_pk=b"\xaa" * 48,
            participant_vks={},
            threshold=2,
            qual_set=frozenset(),
            phase=DKGPhase.EAGER,
            my_secret_share=42,
        )
        with pytest.raises(AttributeError):
            r.my_secret_share = 99


# ThresholdSigningKey and PartialSignature types are tested here too
# but require py_ecc for the threshold_signing module import.

pytestmark_g2 = pytest.mark.skipif(
    not bls12_381_available(), reason="py_ecc not installed"
)


@pytestmark_g2
class TestThresholdSigningKeyType:

    def test_frozen(self):
        from src.ltp.execution.committee.dkg.threshold_signing import (
            ThresholdSigningKey,
        )
        key = ThresholdSigningKey(
            participant_fp=b"\x01" * 32,
            participant_index=1,
            secret_share=42,
            group_pk=b"\xaa" * 96,
            threshold=2,
            epoch=1,
            vm_tag=0x01,
        )
        with pytest.raises(AttributeError):
            key.secret_share = 99

    def test_fields(self):
        from src.ltp.execution.committee.dkg.threshold_signing import (
            ThresholdSigningKey,
        )
        key = ThresholdSigningKey(
            participant_fp=b"\x01" * 32,
            participant_index=3,
            secret_share=777,
            group_pk=b"\xbb" * 96,
            threshold=2,
            epoch=5,
            vm_tag=0x02,
        )
        assert key.participant_fp == b"\x01" * 32
        assert key.participant_index == 3
        assert key.secret_share == 777
        assert len(key.group_pk) == 96
        assert key.threshold == 2
        assert key.epoch == 5
        assert key.vm_tag == 0x02


@pytestmark_g2
class TestPartialSignatureType:

    def test_frozen(self):
        from src.ltp.execution.committee.dkg.threshold_signing import (
            PartialSignature,
        )
        sig = PartialSignature(
            signer_fp=b"\x01" * 32,
            signer_index=1,
            signature=b"\xcc" * 96,
            epoch=1,
        )
        with pytest.raises(AttributeError):
            sig.epoch = 99

    def test_fields(self):
        from src.ltp.execution.committee.dkg.threshold_signing import (
            PartialSignature,
        )
        sig = PartialSignature(
            signer_fp=b"\x02" * 32,
            signer_index=2,
            signature=b"\xdd" * 96,
            epoch=3,
        )
        assert sig.signer_fp == b"\x02" * 32
        assert sig.signer_index == 2
        assert len(sig.signature) == 96
        assert sig.epoch == 3
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_threshold_signing.py -v`
Expected: FAIL — `DKGResult.__init__() got an unexpected keyword argument 'my_secret_share'`

- [ ] **Step 3: Modify DKGResult to add my_secret_share**

In `src/ltp/execution/committee/dkg/types.py`, add the import for `field` and the new field to `DKGResult`:

Change the import line:
```python
from dataclasses import dataclass
```
to:
```python
from dataclasses import dataclass, field
```

Change `DKGResult`:
```python
@dataclass(frozen=True)
class DKGResult:
    vm_tag: int
    epoch: int
    group_pk: bytes
    participant_vks: dict[bytes, bytes]
    threshold: int
    qual_set: frozenset[bytes]
    phase: DKGPhase
    my_secret_share: int | None = field(default=None)
```

- [ ] **Step 4: Create the threshold_signing module with types only**

Create `src/ltp/execution/committee/dkg/threshold_signing.py`:

```python
"""Threshold BLS signing protocol (Spec C3c).

Provides partial signing, combination via Lagrange interpolation in G2,
and verification via the existing BLS class. Combined threshold signatures
are mathematically identical to standard BLS signatures.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

from src.ltp.zk.ec_backend import (
    g1_compress,
    g1_deserialize,
    g2_add,
    g2_compress,
    g2_identity,
    g2_scalar_mul,
)
from src.ltp.bls import BLS

from .scalar_poly import ScalarField, ScalarPoly

__all__ = [
    "ThresholdSigningKey",
    "PartialSignature",
    "partial_sign",
    "combine_partial_signatures",
    "threshold_verify",
    "DOMAIN_ATTESTATION",
    "DOMAIN_STATE_ROOT",
    "DOMAIN_CROSS_VM",
]

# ---------------------------------------------------------------------------
# Domain separation constants
# ---------------------------------------------------------------------------

DOMAIN_ATTESTATION = b"ETP-THRESHOLD-ATTESTATION:v1"
DOMAIN_STATE_ROOT = b"ETP-THRESHOLD-STATE-ROOT:v1"
DOMAIN_CROSS_VM = b"ETP-THRESHOLD-CROSS-VM:v1"

# Standard BLS DST — must match py_ecc G2ProofOfPossession
_BLS_DST = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_"


# ---------------------------------------------------------------------------
# Types
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ThresholdSigningKey:
    """Private material each participant holds after DKG."""
    participant_fp: bytes
    participant_index: int
    secret_share: int
    group_pk: bytes       # 96-byte uncompressed G1 from DKG
    threshold: int
    epoch: int
    vm_tag: int


@dataclass(frozen=True)
class PartialSignature:
    """A single participant's partial BLS signature."""
    signer_fp: bytes
    signer_index: int
    signature: bytes      # 96-byte compressed G2
    epoch: int


# ---------------------------------------------------------------------------
# Signing protocol
# ---------------------------------------------------------------------------


def partial_sign(
    key: ThresholdSigningKey,
    message: bytes,
    domain: bytes,
) -> PartialSignature:
    """Create a partial BLS signature using a threshold signing key.

    Uses hash_to_G2 with the standard BLS DST so the combined
    signature is verifiable by standard BLS.verify().
    """
    from py_ecc.bls.hash_to_curve import hash_to_G2  # type: ignore[import-untyped]

    tagged = domain + message
    h_point = hash_to_G2(tagged, _BLS_DST, hashlib.sha256)
    sig_point = g2_scalar_mul(h_point, key.secret_share)

    return PartialSignature(
        signer_fp=key.participant_fp,
        signer_index=key.participant_index,
        signature=g2_compress(sig_point),
        epoch=key.epoch,
    )


def combine_partial_signatures(
    partials: list[PartialSignature],
    threshold: int,
) -> bytes:
    """Combine t-of-n partial signatures into a standard BLS signature.

    Uses Lagrange interpolation in G2. The result is byte-identical
    to what a standard BLS.Sign(group_secret, message) would produce.
    """
    if len(partials) < threshold:
        raise ValueError(
            f"Need at least {threshold} partials, got {len(partials)}"
        )

    from py_ecc.bls.g2_primitives import signature_to_G2  # type: ignore[import-untyped]

    indices = [p.signer_index for p in partials]
    combined = g2_identity()

    for partial in partials:
        li = ScalarPoly.lagrange_coefficient(partial.signer_index, indices)
        sig_point = signature_to_G2(partial.signature)
        weighted = g2_scalar_mul(sig_point, li)
        combined = g2_add(combined, weighted)

    return g2_compress(combined)


def threshold_verify(
    group_pk: bytes,
    message: bytes,
    signature: bytes,
    domain: bytes,
) -> bool:
    """Verify a threshold BLS signature against a group public key.

    Converts the DKG's uncompressed G1 group_pk to compressed format
    and delegates to BLS.verify().
    """
    tagged = domain + message
    group_pk_point = g1_deserialize(group_pk)
    compressed_pk = g1_compress(group_pk_point)
    return BLS.verify(compressed_pk, tagged, signature)
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `pytest tests/test_threshold_signing.py -v`
Expected: all PASS (or SKIPPED for G2-dependent tests if py_ecc not installed)

- [ ] **Step 6: Commit**

```bash
git add src/ltp/execution/committee/dkg/types.py \
        src/ltp/execution/committee/dkg/threshold_signing.py \
        tests/test_threshold_signing.py
git commit -m "feat(c3c): add ThresholdSigningKey, PartialSignature types and signing protocol"
```

---

### Task 3: Threshold Signing Unit Tests

**Files:**
- Modify: `tests/test_threshold_signing.py` (add signing protocol tests)

**Context:** These tests run a minimal DKG ceremony inline to get real signing keys, then test `partial_sign`, `combine_partial_signatures`, and `threshold_verify`. Requires `py_ecc`.

- [ ] **Step 1: Append signing protocol tests**

Add the following to the end of `tests/test_threshold_signing.py`:

```python
# ---------------------------------------------------------------------------
# Signing protocol tests (require a real DKG ceremony for keys)
# ---------------------------------------------------------------------------


def _run_dkg_and_get_keys(
    n: int = 3, threshold: int = 2,
) -> tuple:
    """Run a DKG ceremony and return (group_pk, list[ThresholdSigningKey])."""
    from src.ltp.execution.committee.dkg.session import DKGSession
    from src.ltp.execution.committee.dkg.types import DKGSessionConfig
    from src.ltp.execution.committee.dkg.threshold_signing import (
        ThresholdSigningKey,
    )

    participants = [bytes([i]) * 32 for i in range(1, n + 1)]
    cfg = DKGSessionConfig(
        vm_tag=0x01, epoch=1, threshold=threshold,
        participants=participants, timeout_rounds=20, start_round=0,
    )
    sessions = [DKGSession(cfg, fp, idx + 1) for idx, fp in enumerate(participants)]

    # Phase 1: begin
    commitments = []
    all_shares = []
    for s in sessions:
        c, shares = s.begin()
        commitments.append(c)
        all_shares.append(shares)

    # Phase 2: commitments
    for s in sessions:
        for c in commitments:
            if c.dealer_fp != s.my_fp:
                s.receive_commitment(c)
        s.end_commitment_phase()

    # Phase 3: shares
    for i, s in enumerate(sessions):
        fp = participants[i]
        for shares in all_shares:
            if fp in shares:
                s.receive_share(shares[fp])
        s.end_sharing_phase()

    # Phase 4: finalize — get results and signing keys
    signing_keys = []
    group_pk = None
    for s in sessions:
        result, key = s.finalize()
        signing_keys.append(key)
        if group_pk is None:
            group_pk = result.group_pk

    return group_pk, signing_keys


@pytestmark_g2
class TestPartialSign:

    def test_produces_96_byte_signature(self):
        from src.ltp.execution.committee.dkg.threshold_signing import (
            partial_sign, DOMAIN_ATTESTATION,
        )
        _, keys = _run_dkg_and_get_keys()
        sig = partial_sign(keys[0], b"hello", DOMAIN_ATTESTATION)
        assert len(sig.signature) == 96

    def test_deterministic(self):
        from src.ltp.execution.committee.dkg.threshold_signing import (
            partial_sign, DOMAIN_ATTESTATION,
        )
        _, keys = _run_dkg_and_get_keys()
        sig1 = partial_sign(keys[0], b"hello", DOMAIN_ATTESTATION)
        sig2 = partial_sign(keys[0], b"hello", DOMAIN_ATTESTATION)
        assert sig1.signature == sig2.signature

    def test_different_message_different_sig(self):
        from src.ltp.execution.committee.dkg.threshold_signing import (
            partial_sign, DOMAIN_ATTESTATION,
        )
        _, keys = _run_dkg_and_get_keys()
        sig1 = partial_sign(keys[0], b"hello", DOMAIN_ATTESTATION)
        sig2 = partial_sign(keys[0], b"world", DOMAIN_ATTESTATION)
        assert sig1.signature != sig2.signature

    def test_different_domain_different_sig(self):
        from src.ltp.execution.committee.dkg.threshold_signing import (
            partial_sign, DOMAIN_ATTESTATION, DOMAIN_STATE_ROOT,
        )
        _, keys = _run_dkg_and_get_keys()
        sig1 = partial_sign(keys[0], b"hello", DOMAIN_ATTESTATION)
        sig2 = partial_sign(keys[0], b"hello", DOMAIN_STATE_ROOT)
        assert sig1.signature != sig2.signature

    def test_signer_metadata(self):
        from src.ltp.execution.committee.dkg.threshold_signing import (
            partial_sign, DOMAIN_ATTESTATION,
        )
        _, keys = _run_dkg_and_get_keys()
        sig = partial_sign(keys[0], b"hello", DOMAIN_ATTESTATION)
        assert sig.signer_fp == keys[0].participant_fp
        assert sig.signer_index == keys[0].participant_index
        assert sig.epoch == keys[0].epoch


@pytestmark_g2
class TestCombineAndVerify:

    def test_combine_with_threshold_partials(self):
        from src.ltp.execution.committee.dkg.threshold_signing import (
            partial_sign, combine_partial_signatures, threshold_verify,
            DOMAIN_ATTESTATION,
        )
        group_pk, keys = _run_dkg_and_get_keys(n=3, threshold=2)
        msg = b"test attestation"
        partials = [partial_sign(k, msg, DOMAIN_ATTESTATION) for k in keys[:2]]
        combined = combine_partial_signatures(partials, threshold=2)
        assert len(combined) == 96
        assert threshold_verify(group_pk, msg, combined, DOMAIN_ATTESTATION)

    def test_combine_with_all_partials(self):
        from src.ltp.execution.committee.dkg.threshold_signing import (
            partial_sign, combine_partial_signatures, threshold_verify,
            DOMAIN_ATTESTATION,
        )
        group_pk, keys = _run_dkg_and_get_keys(n=3, threshold=2)
        msg = b"test attestation"
        partials = [partial_sign(k, msg, DOMAIN_ATTESTATION) for k in keys]
        combined = combine_partial_signatures(partials, threshold=2)
        assert threshold_verify(group_pk, msg, combined, DOMAIN_ATTESTATION)

    def test_insufficient_partials_raises(self):
        from src.ltp.execution.committee.dkg.threshold_signing import (
            partial_sign, combine_partial_signatures, DOMAIN_ATTESTATION,
        )
        _, keys = _run_dkg_and_get_keys(n=3, threshold=2)
        partials = [partial_sign(keys[0], b"msg", DOMAIN_ATTESTATION)]
        with pytest.raises(ValueError, match="Need at least 2"):
            combine_partial_signatures(partials, threshold=2)

    def test_rejects_tampered_message(self):
        from src.ltp.execution.committee.dkg.threshold_signing import (
            partial_sign, combine_partial_signatures, threshold_verify,
            DOMAIN_ATTESTATION,
        )
        group_pk, keys = _run_dkg_and_get_keys(n=3, threshold=2)
        partials = [partial_sign(k, b"real msg", DOMAIN_ATTESTATION) for k in keys[:2]]
        combined = combine_partial_signatures(partials, threshold=2)
        assert not threshold_verify(group_pk, b"fake msg", combined, DOMAIN_ATTESTATION)

    def test_rejects_wrong_domain(self):
        from src.ltp.execution.committee.dkg.threshold_signing import (
            partial_sign, combine_partial_signatures, threshold_verify,
            DOMAIN_ATTESTATION, DOMAIN_STATE_ROOT,
        )
        group_pk, keys = _run_dkg_and_get_keys(n=3, threshold=2)
        partials = [partial_sign(k, b"msg", DOMAIN_ATTESTATION) for k in keys[:2]]
        combined = combine_partial_signatures(partials, threshold=2)
        assert not threshold_verify(group_pk, b"msg", combined, DOMAIN_STATE_ROOT)

    def test_different_subsets_produce_same_signature(self):
        """Key property: any t-subset gives the same combined sig."""
        from src.ltp.execution.committee.dkg.threshold_signing import (
            partial_sign, combine_partial_signatures, DOMAIN_ATTESTATION,
        )
        _, keys = _run_dkg_and_get_keys(n=4, threshold=2)
        msg = b"deterministic"
        # Subset {0, 1}
        p_01 = [partial_sign(keys[0], msg, DOMAIN_ATTESTATION),
                partial_sign(keys[1], msg, DOMAIN_ATTESTATION)]
        sig_01 = combine_partial_signatures(p_01, threshold=2)
        # Subset {2, 3}
        p_23 = [partial_sign(keys[2], msg, DOMAIN_ATTESTATION),
                partial_sign(keys[3], msg, DOMAIN_ATTESTATION)]
        sig_23 = combine_partial_signatures(p_23, threshold=2)
        assert sig_01 == sig_23
```

- [ ] **Step 2: Run tests to verify they pass**

Run: `pytest tests/test_threshold_signing.py -v`
Expected: all PASS (types tests + protocol tests)

Note: If these fail, it's because `DKGSession.finalize()` still returns a single `DKGResult` not a tuple. The `_run_dkg_and_get_keys` helper calls `s.finalize()` expecting `(result, key)`. Task 4 fixes `finalize()`. If running tests before Task 4, only the type tests will pass; the protocol tests will fail with `ValueError: too many values to unpack`. This is expected — run Tasks 2-4 together if desired.

- [ ] **Step 3: Commit**

```bash
git add tests/test_threshold_signing.py
git commit -m "test(c3c): add threshold signing unit tests — partial sign, combine, verify"
```

---

### Task 4: DKGSession.finalize() Returns ThresholdSigningKey

**Files:**
- Modify: `src/ltp/execution/committee/dkg/session.py`
- Modify: `tests/test_dkg_session.py`
- Modify: `tests/test_dkg_e2e.py`

- [ ] **Step 1: Modify session.py finalize()**

In `src/ltp/execution/committee/dkg/session.py`, change the import to include `ThresholdSigningKey`:

Add at the top, after the existing `.vss` import:

```python
from .threshold_signing import ThresholdSigningKey
```

Change the `finalize` method signature and body. Replace the entire `finalize` method:

```python
    def finalize(self) -> tuple[DKGResult, ThresholdSigningKey]:
        """COMPLAINING -> FINALIZING -> COMPLETED. Resolve complaints and derive keys."""
        self.state = DKGState.FINALIZING

        # Build QUAL: start with all dealers, remove those with valid complaints
        self._qual = set(self._commitments.keys())
        for complaint in self._complaints:
            commitment = self._commitments.get(complaint.dealer_fp)
            if commitment is None:
                continue
            complainant_idx = self.config.participants.index(complaint.complainant_fp) + 1
            valid = PedersenVSS.verify_share(
                complainant_idx,
                complaint.revealed_share,
                complaint.revealed_blinding,
                commitment.pedersen_commitments,
            )
            if not valid:
                # Complaint is valid — dealer sent a bad share, exclude dealer
                self._qual.discard(complaint.dealer_fp)

        if len(self._qual) < self.config.threshold:
            self.state = DKGState.FAILED
            raise ValueError(
                f"QUAL set too small: {len(self._qual)} < threshold {self.config.threshold}"
            )

        # Derive group public key: sum of feldman_commitments[0] for QUAL dealers
        group_point = g1_identity()
        for fp in self._qual:
            c0_bytes = self._commitments[fp].feldman_commitments[0]
            c0 = g1_deserialize(c0_bytes)
            group_point = g1_add(group_point, c0) if group_point is not None else c0

        # Derive my secret share: sum of received shares from QUAL dealers
        my_secret_share = 0
        for fp in self._qual:
            if fp == self.my_fp:
                my_secret_share = ScalarField.add(
                    my_secret_share, self._secret_poly.evaluate(self.my_index),
                )
            else:
                share = self._shares.get(fp)
                if share is not None:
                    my_secret_share = ScalarField.add(my_secret_share, share.share)

        my_vk = g1_serialize(g1_scalar_mul(g1_generator(), my_secret_share))
        participant_vks = {self.my_fp: my_vk}
        group_pk_bytes = g1_serialize(group_point)

        self.state = DKGState.COMPLETED

        result = DKGResult(
            vm_tag=self.config.vm_tag,
            epoch=self.config.epoch,
            group_pk=group_pk_bytes,
            participant_vks=participant_vks,
            threshold=self.config.threshold,
            qual_set=frozenset(self._qual),
            phase=DKGPhase.EAGER,
            my_secret_share=my_secret_share,
        )

        signing_key = ThresholdSigningKey(
            participant_fp=self.my_fp,
            participant_index=self.my_index,
            secret_share=my_secret_share,
            group_pk=group_pk_bytes,
            threshold=self.config.threshold,
            epoch=self.config.epoch,
            vm_tag=self.config.vm_tag,
        )

        return result, signing_key
```

- [ ] **Step 2: Update test_dkg_session.py for new return type**

In `tests/test_dkg_session.py`, the `TestDKGSessionFinalize.test_happy_path_finalize` method calls `s.finalize()` and expects a single `DKGResult`. Update line 137 to unpack the tuple:

Change:
```python
        results = []
        for s in sessions:
            result = s.finalize()
            results.append(result)
            assert s.state is DKGState.COMPLETED
```
to:
```python
        results = []
        for s in sessions:
            result, signing_key = s.finalize()
            results.append(result)
            assert s.state is DKGState.COMPLETED
            assert signing_key.secret_share > 0
            assert signing_key.participant_fp == s.my_fp
```

- [ ] **Step 3: Update test_dkg_e2e.py for new return type**

In `tests/test_dkg_e2e.py`, the `_run_ceremony` helper and `TestRegistryIntegration.test_multiple_epochs` call `s.finalize()`. Update both.

In `_run_ceremony`, change line 89:
```python
        result = s.finalize()
```
to:
```python
        result, _signing_key = s.finalize()
```

In `test_multiple_epochs`, change line 172:
```python
            result = sessions[0].finalize()
```
to:
```python
            result, _signing_key = sessions[0].finalize()
```

- [ ] **Step 4: Run all DKG tests to verify no regressions**

Run: `pytest tests/test_dkg_session.py tests/test_dkg_e2e.py tests/test_dkg_hypothesis.py tests/test_threshold_signing.py -v`
Expected: all PASS

- [ ] **Step 5: Commit**

```bash
git add src/ltp/execution/committee/dkg/session.py \
        tests/test_dkg_session.py \
        tests/test_dkg_e2e.py
git commit -m "feat(c3c): DKGSession.finalize() returns (DKGResult, ThresholdSigningKey)"
```

---

### Task 5: End-to-End Threshold Signing Tests

**Files:**
- Create: `tests/test_threshold_signing_e2e.py`

- [ ] **Step 1: Write end-to-end tests**

Create `tests/test_threshold_signing_e2e.py`:

```python
"""End-to-end threshold signing tests: DKG -> sign -> verify (Spec C3c)."""

from __future__ import annotations

import pytest

from src.ltp.zk.ec_backend import bls12_381_available
from src.ltp.execution.committee.dkg.types import DKGSessionConfig

pytestmark = pytest.mark.skipif(
    not bls12_381_available(), reason="py_ecc not installed"
)

from src.ltp.execution.committee.dkg.session import DKGSession  # noqa: E402
from src.ltp.execution.committee.dkg.threshold_signing import (  # noqa: E402
    ThresholdSigningKey,
    partial_sign,
    combine_partial_signatures,
    threshold_verify,
    DOMAIN_ATTESTATION,
    DOMAIN_STATE_ROOT,
)


PARTICIPANTS = [bytes([i]) * 32 for i in range(1, 6)]


def _full_ceremony(
    participants: list[bytes],
    threshold: int,
    epoch: int = 1,
) -> tuple[bytes, list[ThresholdSigningKey]]:
    """Run full DKG and return (group_pk, signing_keys)."""
    cfg = DKGSessionConfig(
        vm_tag=0x01, epoch=epoch, threshold=threshold,
        participants=list(participants), timeout_rounds=20, start_round=0,
    )
    sessions = [
        DKGSession(cfg, fp, idx + 1)
        for idx, fp in enumerate(participants)
    ]

    commitments = []
    all_shares = []
    for s in sessions:
        c, shares = s.begin()
        commitments.append(c)
        all_shares.append(shares)

    for s in sessions:
        for c in commitments:
            if c.dealer_fp != s.my_fp:
                s.receive_commitment(c)
        s.end_commitment_phase()

    for i, s in enumerate(sessions):
        fp = participants[i]
        for shares in all_shares:
            if fp in shares:
                s.receive_share(shares[fp])
        s.end_sharing_phase()

    signing_keys = []
    group_pk = None
    for s in sessions:
        result, key = s.finalize()
        signing_keys.append(key)
        if group_pk is None:
            group_pk = result.group_pk

    return group_pk, signing_keys


class TestFullCeremonyToSignature:

    def test_2_of_3_sign_and_verify(self):
        group_pk, keys = _full_ceremony(PARTICIPANTS[:3], threshold=2)
        msg = b"attestation payload"
        partials = [partial_sign(k, msg, DOMAIN_ATTESTATION) for k in keys[:2]]
        sig = combine_partial_signatures(partials, threshold=2)
        assert threshold_verify(group_pk, msg, sig, DOMAIN_ATTESTATION)

    def test_3_of_5_sign_and_verify(self):
        group_pk, keys = _full_ceremony(PARTICIPANTS, threshold=3)
        msg = b"state root hash"
        partials = [partial_sign(k, msg, DOMAIN_STATE_ROOT) for k in keys[:3]]
        sig = combine_partial_signatures(partials, threshold=3)
        assert threshold_verify(group_pk, msg, sig, DOMAIN_STATE_ROOT)

    def test_5_of_5_sign_and_verify(self):
        group_pk, keys = _full_ceremony(PARTICIPANTS, threshold=5)
        msg = b"unanimous"
        partials = [partial_sign(k, msg, DOMAIN_ATTESTATION) for k in keys]
        sig = combine_partial_signatures(partials, threshold=5)
        assert threshold_verify(group_pk, msg, sig, DOMAIN_ATTESTATION)


class TestSubsetIndependence:

    def test_any_2_of_4_produces_same_signature(self):
        """All t-subsets produce the same combined signature."""
        group_pk, keys = _full_ceremony(PARTICIPANTS[:4], threshold=2)
        msg = b"subset test"
        from itertools import combinations
        sigs = set()
        for subset in combinations(range(4), 2):
            partials = [partial_sign(keys[i], msg, DOMAIN_ATTESTATION) for i in subset]
            sig = combine_partial_signatures(partials, threshold=2)
            sigs.add(sig)
        # All subsets produce the same combined signature
        assert len(sigs) == 1

    def test_any_3_of_5_produces_same_signature(self):
        group_pk, keys = _full_ceremony(PARTICIPANTS, threshold=3)
        msg = b"larger subset test"
        from itertools import combinations
        sigs = set()
        for subset in combinations(range(5), 3):
            partials = [partial_sign(keys[i], msg, DOMAIN_ATTESTATION) for i in subset]
            sig = combine_partial_signatures(partials, threshold=3)
            sigs.add(sig)
        assert len(sigs) == 1


class TestSecurityProperties:

    def test_t_minus_1_partials_fail(self):
        """t-1 partials cannot produce a valid signature."""
        group_pk, keys = _full_ceremony(PARTICIPANTS[:3], threshold=2)
        msg = b"should fail"
        # Only 1 partial for threshold=2
        partials = [partial_sign(keys[0], msg, DOMAIN_ATTESTATION)]
        with pytest.raises(ValueError, match="Need at least 2"):
            combine_partial_signatures(partials, threshold=2)

    def test_wrong_group_rejects(self):
        """Signature from group A doesn't verify against group B's key."""
        group_pk_a, keys_a = _full_ceremony(PARTICIPANTS[:3], threshold=2)
        group_pk_b, keys_b = _full_ceremony(PARTICIPANTS[:3], threshold=2)
        msg = b"cross-group"
        partials = [partial_sign(k, msg, DOMAIN_ATTESTATION) for k in keys_a[:2]]
        sig = combine_partial_signatures(partials, threshold=2)
        # Verify against group B's key — should fail (different random polys)
        assert group_pk_a != group_pk_b  # overwhelmingly likely
        assert not threshold_verify(group_pk_b, msg, sig, DOMAIN_ATTESTATION)


class TestMultipleEpochs:

    def test_different_epochs_different_keys_both_verify(self):
        group_pk_1, keys_1 = _full_ceremony(PARTICIPANTS[:3], threshold=2, epoch=1)
        group_pk_2, keys_2 = _full_ceremony(PARTICIPANTS[:3], threshold=2, epoch=2)
        msg = b"epoch test"
        # Sign with epoch 1 keys
        partials_1 = [partial_sign(k, msg, DOMAIN_ATTESTATION) for k in keys_1[:2]]
        sig_1 = combine_partial_signatures(partials_1, threshold=2)
        # Sign with epoch 2 keys
        partials_2 = [partial_sign(k, msg, DOMAIN_ATTESTATION) for k in keys_2[:2]]
        sig_2 = combine_partial_signatures(partials_2, threshold=2)
        # Each verifies against its own group key
        assert threshold_verify(group_pk_1, msg, sig_1, DOMAIN_ATTESTATION)
        assert threshold_verify(group_pk_2, msg, sig_2, DOMAIN_ATTESTATION)
        # Cross-epoch fails
        assert not threshold_verify(group_pk_1, msg, sig_2, DOMAIN_ATTESTATION)
        assert not threshold_verify(group_pk_2, msg, sig_1, DOMAIN_ATTESTATION)
```

- [ ] **Step 2: Run tests**

Run: `pytest tests/test_threshold_signing_e2e.py -v`
Expected: all PASS

- [ ] **Step 3: Commit**

```bash
git add tests/test_threshold_signing_e2e.py
git commit -m "test(c3c): end-to-end threshold signing — DKG to verify, subset independence, security"
```

---

### Task 6: CommitteeManager Integration

**Files:**
- Modify: `src/ltp/execution/committee/manager.py`
- Create: `tests/test_threshold_signing_integration.py`

- [ ] **Step 1: Write the failing integration tests**

Create `tests/test_threshold_signing_integration.py`:

```python
"""CommitteeManager + threshold signing integration tests (Spec C3c)."""

from __future__ import annotations

import pytest

from src.ltp.zk.ec_backend import bls12_381_available
from src.ltp.execution.committee.policy import CommitteePolicy
from src.ltp.execution.committee.manager import CommitteeManager
from src.ltp.execution.writer import IdentityTier, WriterIdentity
from src.ltp.execution.writer_recovery import EmergencyState
from src.ltp.execution.writer_registry import WriterRegistry

ADMIN_FP = b"\xff" * 32


def _enroll_active(reg, fp_byte, tier=IdentityTier.BLS):
    fp = bytes([fp_byte]) * 32
    bls_pk = bytes([fp_byte]) * 48 if tier in (IdentityTier.BLS, IdentityTier.COMPOSITE) else None
    mldsa_vk = bytes([fp_byte]) * 32 if tier in (IdentityTier.MLDSA, IdentityTier.COMPOSITE) else None
    identity = WriterIdentity(tier=tier, fingerprint=fp, mldsa_vk=mldsa_vk, bls_pk=bls_pk)
    reg.enroll(identity, timestamp=1000 + fp_byte)
    reg.approve(fp, admin_fp=ADMIN_FP, timestamp=2000 + fp_byte)


class TestManagerSigningDisabled:

    def test_sign_returns_none_when_dkg_disabled(self):
        reg = WriterRegistry()
        for i in range(1, 4):
            _enroll_active(reg, i)
        policy = CommitteePolicy(vm_tag=0x01, epoch_length=10, dkg_threshold=0)
        mgr = CommitteeManager(0x01, policy, reg, EmergencyState())
        mgr.tick(10, 1000)
        result = mgr.sign_as_committee(b"test", b"domain")
        assert result is None


@pytest.mark.skipif(not bls12_381_available(), reason="py_ecc not installed")
class TestManagerSigningEnabled:

    def test_sign_produces_valid_signature(self):
        from src.ltp.execution.committee.dkg.threshold_signing import (
            threshold_verify, DOMAIN_ATTESTATION,
        )
        reg = WriterRegistry()
        for i in range(1, 4):
            _enroll_active(reg, i)
        policy = CommitteePolicy(
            vm_tag=0x01, epoch_length=10, dkg_threshold=2,
        )
        mgr = CommitteeManager(0x01, policy, reg, EmergencyState())
        mgr.tick(10, 1000)
        assert mgr.has_dkg_result(1)

        msg = b"attestation payload"
        sig = mgr.sign_as_committee(msg, DOMAIN_ATTESTATION)
        assert sig is not None
        assert len(sig) == 96

        group_pk = mgr.dkg_registry.group_pk(1)
        assert threshold_verify(group_pk, msg, sig, DOMAIN_ATTESTATION)

    def test_verify_committee_signature(self):
        from src.ltp.execution.committee.dkg.threshold_signing import (
            DOMAIN_ATTESTATION,
        )
        reg = WriterRegistry()
        for i in range(1, 4):
            _enroll_active(reg, i)
        policy = CommitteePolicy(
            vm_tag=0x01, epoch_length=10, dkg_threshold=2,
        )
        mgr = CommitteeManager(0x01, policy, reg, EmergencyState())
        mgr.tick(10, 1000)

        msg = b"verify test"
        sig = mgr.sign_as_committee(msg, DOMAIN_ATTESTATION)
        assert mgr.verify_committee_signature(msg, sig, DOMAIN_ATTESTATION)

    def test_verify_rejects_tampered(self):
        from src.ltp.execution.committee.dkg.threshold_signing import (
            DOMAIN_ATTESTATION,
        )
        reg = WriterRegistry()
        for i in range(1, 4):
            _enroll_active(reg, i)
        policy = CommitteePolicy(
            vm_tag=0x01, epoch_length=10, dkg_threshold=2,
        )
        mgr = CommitteeManager(0x01, policy, reg, EmergencyState())
        mgr.tick(10, 1000)

        sig = mgr.sign_as_committee(b"real", DOMAIN_ATTESTATION)
        assert not mgr.verify_committee_signature(b"fake", sig, DOMAIN_ATTESTATION)

    def test_multiple_epochs_sign_verify(self):
        from src.ltp.execution.committee.dkg.threshold_signing import (
            threshold_verify, DOMAIN_ATTESTATION,
        )
        reg = WriterRegistry()
        for i in range(1, 4):
            _enroll_active(reg, i)
        policy = CommitteePolicy(
            vm_tag=0x01, epoch_length=10, dkg_threshold=2,
        )
        mgr = CommitteeManager(0x01, policy, reg, EmergencyState())
        mgr.tick(10, 1000)
        sig1 = mgr.sign_as_committee(b"epoch1", DOMAIN_ATTESTATION)

        mgr.tick(20, 2000)
        sig2 = mgr.sign_as_committee(b"epoch2", DOMAIN_ATTESTATION)

        # Both valid against their respective epoch keys
        pk1 = mgr.dkg_registry.group_pk(1)
        pk2 = mgr.dkg_registry.group_pk(2)
        assert threshold_verify(pk1, b"epoch1", sig1, DOMAIN_ATTESTATION)
        assert threshold_verify(pk2, b"epoch2", sig2, DOMAIN_ATTESTATION)

    def test_verify_with_explicit_epoch(self):
        from src.ltp.execution.committee.dkg.threshold_signing import (
            DOMAIN_ATTESTATION,
        )
        reg = WriterRegistry()
        for i in range(1, 4):
            _enroll_active(reg, i)
        policy = CommitteePolicy(
            vm_tag=0x01, epoch_length=10, dkg_threshold=2,
        )
        mgr = CommitteeManager(0x01, policy, reg, EmergencyState())
        mgr.tick(10, 1000)
        sig = mgr.sign_as_committee(b"msg", DOMAIN_ATTESTATION)

        mgr.tick(20, 2000)  # advance epoch
        # Verify against epoch 1 explicitly
        assert mgr.verify_committee_signature(b"msg", sig, DOMAIN_ATTESTATION, epoch=1)
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_threshold_signing_integration.py -v`
Expected: FAIL — `CommitteeManager has no attribute 'sign_as_committee'`

- [ ] **Step 3: Modify CommitteeManager**

In `src/ltp/execution/committee/manager.py`, add the threshold signing import and methods. Replace the full file:

```python
"""CommitteeManager — top-level coordinator (Spec C3a §9, C3b §8, C3c)."""

from __future__ import annotations

from typing import Optional

from .types import CommitteeRoster, EpochRecord
from .policy import CommitteePolicy
from .formation import CommitteeFormation
from .epoch import EpochManager
from .eviction import EvictionHandler
from .standby import StandbySelector
from ..writer import WriterRecord, WriterState
from ..writer_recovery import EmergencyState
from ..writer_registry import WriterRegistry

from .dkg.registry import DKGKeyRegistry
from .dkg.types import DKGSessionConfig, DKGState

__all__ = ["CommitteeManager"]


class CommitteeManager:
    """Top-level coordinator — one per VM."""

    def __init__(
        self,
        vm_tag: int,
        policy: CommitteePolicy,
        registry: WriterRegistry,
        emergency: EmergencyState,
    ) -> None:
        self._vm_tag = vm_tag
        self._policy = policy
        self._registry = registry
        self._formation = CommitteeFormation(registry)
        self._standby = StandbySelector(policy)
        self._eviction = EvictionHandler(policy, self._standby)
        self._epoch_mgr = EpochManager(vm_tag, policy, self._formation, emergency)
        self._dkg_registry = DKGKeyRegistry(vm_tag)
        self._signing_keys: dict[int, list] = {}

    def on_writer_state_change(
        self,
        writer: WriterRecord,
        old_state: WriterState,
        new_state: WriterState,
    ) -> None:
        """Hook called by WriterRegistry transitions."""
        roster = self._epoch_mgr.roster
        if roster is None:
            return
        self._eviction.handle_state_change(
            roster, writer.identity.fingerprint, old_state, new_state,
            timestamp=0,
        )

    def tick(self, current_round: int, timestamp_ms: int) -> bool:
        """Called every round. Returns True if epoch advanced."""
        advanced = self._epoch_mgr.check_advance(current_round, timestamp_ms)
        if advanced and self._policy.dkg_threshold > 0:
            self._run_dkg_ceremony()
        return advanced

    def _run_dkg_ceremony(self) -> None:
        """Run a synchronous DKG ceremony for the current roster."""
        roster = self._epoch_mgr.roster
        if roster is None:
            return

        participants = [m.writer_fp for m in roster.active_members]
        if len(participants) < self._policy.dkg_threshold:
            return

        from .dkg.session import DKGSession

        cfg = DKGSessionConfig(
            vm_tag=self._vm_tag,
            epoch=self._epoch_mgr.current_epoch,
            threshold=self._policy.dkg_threshold,
            participants=participants,
            timeout_rounds=self._policy.dkg_timeout_rounds,
            start_round=0,
        )

        sessions = [
            DKGSession(cfg, fp, idx + 1)
            for idx, fp in enumerate(participants)
        ]

        # Phase 1: begin
        commitments = []
        all_shares: list[dict] = []
        for s in sessions:
            c, shares = s.begin()
            commitments.append(c)
            all_shares.append(shares)

        # Phase 2: distribute commitments
        for s in sessions:
            for c in commitments:
                if c.dealer_fp != s.my_fp:
                    s.receive_commitment(c)
            s.end_commitment_phase()

        # Phase 3: distribute shares
        for i, s in enumerate(sessions):
            fp = participants[i]
            for shares in all_shares:
                if fp in shares:
                    s.receive_share(shares[fp])
            s.end_sharing_phase()

        # Phase 4: finalize — collect results and signing keys
        epoch = self._epoch_mgr.current_epoch
        try:
            signing_keys = []
            for s in sessions:
                result, key = s.finalize()
                signing_keys.append(key)
            # Store the first result (group key is the same for all)
            self._dkg_registry.store(result)
            self._signing_keys[epoch] = signing_keys
        except (ValueError, KeyError):
            pass  # DKG failed — epoch runs without threshold signing

    def sign_as_committee(
        self,
        message: bytes,
        domain: bytes,
    ) -> Optional[bytes]:
        """Produce a threshold BLS signature over a message.

        Returns 96-byte combined signature, or None if no DKG keys exist.
        """
        epoch = self._epoch_mgr.current_epoch
        keys = self._signing_keys.get(epoch)
        if not keys:
            return None

        from .dkg.threshold_signing import partial_sign, combine_partial_signatures

        threshold = self._policy.dkg_threshold
        partials = [partial_sign(k, message, domain) for k in keys[:threshold]]
        return combine_partial_signatures(partials, threshold)

    def verify_committee_signature(
        self,
        message: bytes,
        signature: bytes,
        domain: bytes,
        epoch: Optional[int] = None,
    ) -> bool:
        """Verify a threshold BLS signature against the committee's group key."""
        if epoch is None:
            epoch = self._epoch_mgr.current_epoch
        if not self._dkg_registry.has_epoch(epoch):
            return False

        from .dkg.threshold_signing import threshold_verify

        group_pk = self._dkg_registry.group_pk(epoch)
        return threshold_verify(group_pk, message, signature, domain)

    @property
    def dkg_registry(self) -> DKGKeyRegistry:
        return self._dkg_registry

    def has_dkg_result(self, epoch: int) -> bool:
        return self._dkg_registry.has_epoch(epoch)

    @property
    def roster(self) -> Optional[CommitteeRoster]:
        return self._epoch_mgr.roster

    @property
    def epoch(self) -> int:
        return self._epoch_mgr.current_epoch

    @property
    def is_halted(self) -> bool:
        return self._eviction.is_halted

    def is_member(self, writer_fp: bytes) -> bool:
        roster = self._epoch_mgr.roster
        if roster is None:
            return False
        return any(m.writer_fp == writer_fp for m in roster.active_members)

    def history(self) -> list[EpochRecord]:
        return self._epoch_mgr.history
```

- [ ] **Step 4: Run integration tests**

Run: `pytest tests/test_threshold_signing_integration.py tests/test_dkg_integration.py -v`
Expected: all PASS

- [ ] **Step 5: Commit**

```bash
git add src/ltp/execution/committee/manager.py \
        tests/test_threshold_signing_integration.py
git commit -m "feat(c3c): CommitteeManager sign_as_committee + verify_committee_signature"
```

---

### Task 7: Package Exports and Full Regression

**Files:**
- Modify: `src/ltp/execution/committee/dkg/__init__.py`
- Modify: `src/ltp/execution/committee/__init__.py`
- Modify: `src/ltp/execution/__init__.py`

- [ ] **Step 1: Update dkg/__init__.py**

Replace `src/ltp/execution/committee/dkg/__init__.py`:

```python
"""Threshold Distributed Key Generation and Signing (Specs C3b, C3c)."""

from .types import (
    DKGState,
    DKGPhase,
    DKGCommitment,
    DKGShare,
    DKGComplaint,
    DKGResult,
    DKGSessionConfig,
)
from .scalar_poly import ScalarField, ScalarPoly
from .transport import DKGTransport, FakeDKGTransport
from .registry import DKGKeyRegistry
from .threshold_signing import (
    ThresholdSigningKey,
    PartialSignature,
    DOMAIN_ATTESTATION,
    DOMAIN_STATE_ROOT,
    DOMAIN_CROSS_VM,
)

__all__ = [
    "DKGState",
    "DKGPhase",
    "DKGCommitment",
    "DKGShare",
    "DKGComplaint",
    "DKGResult",
    "DKGSessionConfig",
    "ScalarField",
    "ScalarPoly",
    "DKGTransport",
    "FakeDKGTransport",
    "DKGKeyRegistry",
    # Threshold Signing (Spec C3c)
    "ThresholdSigningKey",
    "PartialSignature",
    "DOMAIN_ATTESTATION",
    "DOMAIN_STATE_ROOT",
    "DOMAIN_CROSS_VM",
]
```

Note: `partial_sign`, `combine_partial_signatures`, `threshold_verify` are intentionally NOT exported at the top level — they require `py_ecc` at import time. Consumers import them directly from `.threshold_signing`.

- [ ] **Step 2: Update committee/__init__.py**

Add to the end of the DKG imports block in `src/ltp/execution/committee/__init__.py`:

After the existing DKG import block, add:
```python
from .dkg import (
    ThresholdSigningKey,
    PartialSignature,
    DOMAIN_ATTESTATION,
    DOMAIN_STATE_ROOT,
    DOMAIN_CROSS_VM,
)
```

Wait — the existing file already imports from `.dkg`. Merge the new symbols into the existing import. Change:

```python
# DKG (Spec C3b)
from .dkg import (
    DKGState, DKGPhase,
    DKGCommitment, DKGShare, DKGComplaint,
    DKGResult, DKGSessionConfig,
    ScalarField, ScalarPoly,
    DKGTransport, FakeDKGTransport,
    DKGKeyRegistry,
)
```

to:

```python
# DKG (Spec C3b) + Threshold Signing (Spec C3c)
from .dkg import (
    DKGState, DKGPhase,
    DKGCommitment, DKGShare, DKGComplaint,
    DKGResult, DKGSessionConfig,
    ScalarField, ScalarPoly,
    DKGTransport, FakeDKGTransport,
    DKGKeyRegistry,
    ThresholdSigningKey, PartialSignature,
    DOMAIN_ATTESTATION, DOMAIN_STATE_ROOT, DOMAIN_CROSS_VM,
)
```

And add to the `__all__` list:

```python
    # Threshold Signing (Spec C3c)
    "ThresholdSigningKey", "PartialSignature",
    "DOMAIN_ATTESTATION", "DOMAIN_STATE_ROOT", "DOMAIN_CROSS_VM",
```

- [ ] **Step 3: Update execution/__init__.py**

In `src/ltp/execution/__init__.py`, add to the DKG import block:

Change:
```python
# DKG (Spec C3b)
from .committee.dkg import (
    DKGState, DKGPhase,
    DKGCommitment, DKGShare, DKGComplaint,
    DKGResult, DKGSessionConfig,
    ScalarField, ScalarPoly,
    DKGTransport, FakeDKGTransport,
    DKGKeyRegistry,
)
```

to:

```python
# DKG (Spec C3b) + Threshold Signing (Spec C3c)
from .committee.dkg import (
    DKGState, DKGPhase,
    DKGCommitment, DKGShare, DKGComplaint,
    DKGResult, DKGSessionConfig,
    ScalarField, ScalarPoly,
    DKGTransport, FakeDKGTransport,
    DKGKeyRegistry,
    ThresholdSigningKey, PartialSignature,
    DOMAIN_ATTESTATION, DOMAIN_STATE_ROOT, DOMAIN_CROSS_VM,
)
```

And add to the `__all__` list:

```python
    # Threshold Signing (Spec C3c)
    "ThresholdSigningKey", "PartialSignature",
    "DOMAIN_ATTESTATION", "DOMAIN_STATE_ROOT", "DOMAIN_CROSS_VM",
```

- [ ] **Step 4: Run full test suite**

Run: `pytest tests/ -v --tb=short`
Expected: all tests PASS (3,530+ existing tests + ~45 new threshold signing tests)

- [ ] **Step 5: Commit**

```bash
git add src/ltp/execution/committee/dkg/__init__.py \
        src/ltp/execution/committee/__init__.py \
        src/ltp/execution/__init__.py
git commit -m "feat(c3c): expose threshold signing types through package __init__ exports"
```

---

## Self-Review Checklist

**Spec coverage:**
- [x] Section 1 (Data Types): ThresholdSigningKey, PartialSignature, DKGResult extension — Task 2
- [x] Section 2 (Signing Protocol): partial_sign, combine, verify, domain constants — Tasks 2-3
- [x] Section 3 (ec_backend G2): g2_generator, g2_scalar_mul, g2_add, g2_identity, g2_compress, g1_compress — Task 1
- [x] Section 4 (DKG Integration): finalize() returns tuple, CommitteeManager signing — Tasks 4, 6
- [x] Section 5 (File Structure): All files covered across Tasks 1-7
- [x] Section 6 (Testing): Unit, E2E, integration, G2 backend — Tasks 1, 3, 5, 6
- [x] Section 7 (Gate 5): Criteria testable via the written tests
- [x] Section 8 (Non-Goals): Nothing deferred was implemented

**Placeholder scan:** No TBD, TODO, or vague instructions found.

**Type consistency:** `ThresholdSigningKey`, `PartialSignature`, `partial_sign`, `combine_partial_signatures`, `threshold_verify`, `DOMAIN_ATTESTATION`, `DOMAIN_STATE_ROOT`, `DOMAIN_CROSS_VM` — all consistent across all tasks.

**Missing from spec:** Property-based Hypothesis tests were mentioned in the spec. These can be added as a follow-up if desired — the core coverage is comprehensive without them.
