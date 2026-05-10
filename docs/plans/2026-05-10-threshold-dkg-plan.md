# Threshold DKG (C3b) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement Pedersen DKG for ETP committees so each epoch can produce a BLS12-381 group public key and per-participant secret shares.

**Architecture:** A nested `committee/dkg/` subpackage with 7 modules — types, scalar field arithmetic, Pedersen VSS, DKG session state machine, transport protocol, key registry, and CommitteeManager integration. The DKG is layered on top of existing C3a committee lifecycle without modifying formation, eviction, epoch, or standby modules.

**Tech Stack:** Python 3.12+, py_ecc (BLS12-381 G1 operations via `src/ltp/zk/ec_backend.py`), pytest + Hypothesis

**Spec:** `docs/plans/2026-05-09-threshold-dkg-spec.md`

---

## File Structure

| Action | Path | Responsibility |
|--------|------|---------------|
| Create | `src/ltp/execution/committee/dkg/__init__.py` | Public API surface for DKG subpackage |
| Create | `src/ltp/execution/committee/dkg/types.py` | DKGState, DKGPhase, DKGCommitment, DKGShare, DKGComplaint, DKGResult, DKGSessionConfig |
| Create | `src/ltp/execution/committee/dkg/scalar_poly.py` | ScalarField static arithmetic + ScalarPoly class over BLS12-381 Z_r |
| Create | `src/ltp/execution/committee/dkg/vss.py` | PedersenVSS — dual commitments, share creation/verification |
| Create | `src/ltp/execution/committee/dkg/session.py` | DKGSession state machine — full ceremony orchestration |
| Create | `src/ltp/execution/committee/dkg/transport.py` | DKGTransport Protocol + FakeDKGTransport |
| Create | `src/ltp/execution/committee/dkg/registry.py` | DKGKeyRegistry — per-VM, per-epoch group key store |
| Modify | `src/ltp/execution/committee/policy.py` | Add 3 DKG fields to CommitteePolicy |
| Modify | `src/ltp/execution/committee/manager.py` | Add DKG lifecycle to CommitteeManager.tick() |
| Modify | `src/ltp/execution/committee/__init__.py` | Re-export DKG types |
| Modify | `src/ltp/execution/__init__.py` | Re-export DKG types at top level |
| Create | `tests/test_dkg_types.py` | Tests for DKG type construction and invariants |
| Create | `tests/test_dkg_scalar_poly.py` | Tests for ScalarField and ScalarPoly |
| Create | `tests/test_dkg_vss.py` | Tests for PedersenVSS |
| Create | `tests/test_dkg_session.py` | Tests for DKGSession state machine |
| Create | `tests/test_dkg_transport.py` | Tests for FakeDKGTransport |
| Create | `tests/test_dkg_registry.py` | Tests for DKGKeyRegistry |
| Create | `tests/test_dkg_e2e.py` | End-to-end ceremony tests (multi-participant happy path, complaint, failure) |
| Create | `tests/test_dkg_hypothesis.py` | Property-based tests for scalar field, polynomial, and quorum properties |
| Create | `tests/test_dkg_integration.py` | CommitteeManager + DKG integration tests |

---

### Task 1: DKG Types

**Files:**
- Create: `src/ltp/execution/committee/dkg/__init__.py`
- Create: `src/ltp/execution/committee/dkg/types.py`
- Test: `tests/test_dkg_types.py`

- [ ] **Step 1: Create the dkg package directory**

```bash
mkdir -p src/ltp/execution/committee/dkg
```

- [ ] **Step 2: Write the failing tests**

Create `tests/test_dkg_types.py`:

```python
"""Tests for DKG core types (Spec C3b §2)."""

from __future__ import annotations

import pytest

from src.ltp.execution.committee.dkg.types import (
    DKGState,
    DKGPhase,
    DKGCommitment,
    DKGShare,
    DKGComplaint,
    DKGResult,
    DKGSessionConfig,
)


class TestDKGState:

    def test_has_eight_states(self):
        assert len(DKGState) == 8

    def test_state_values(self):
        expected = {
            "idle", "committing", "sharing", "verifying",
            "complaining", "finalizing", "completed", "failed",
        }
        assert {s.value for s in DKGState} == expected


class TestDKGPhase:

    def test_has_two_phases(self):
        assert len(DKGPhase) == 2

    def test_phase_values(self):
        assert {p.value for p in DKGPhase} == {"eager", "inline"}


class TestDKGCommitment:

    def test_frozen(self):
        c = DKGCommitment(
            dealer_fp=b"\x01" * 32,
            feldman_commitments=[b"\xaa" * 96],
            pedersen_commitments=[b"\xbb" * 96],
            round_id=5,
        )
        with pytest.raises(AttributeError):
            c.round_id = 10

    def test_fields(self):
        fp = b"\x01" * 32
        c = DKGCommitment(
            dealer_fp=fp,
            feldman_commitments=[b"\xaa" * 96, b"\xbb" * 96],
            pedersen_commitments=[b"\xcc" * 96, b"\xdd" * 96],
            round_id=7,
        )
        assert c.dealer_fp == fp
        assert len(c.feldman_commitments) == 2
        assert len(c.pedersen_commitments) == 2
        assert c.round_id == 7


class TestDKGShare:

    def test_frozen(self):
        s = DKGShare(
            dealer_fp=b"\x01" * 32,
            recipient_fp=b"\x02" * 32,
            share=42,
            blinding_share=99,
        )
        with pytest.raises(AttributeError):
            s.share = 0

    def test_fields(self):
        s = DKGShare(
            dealer_fp=b"\x01" * 32,
            recipient_fp=b"\x02" * 32,
            share=12345,
            blinding_share=67890,
        )
        assert s.dealer_fp == b"\x01" * 32
        assert s.recipient_fp == b"\x02" * 32
        assert s.share == 12345
        assert s.blinding_share == 67890


class TestDKGComplaint:

    def test_frozen(self):
        c = DKGComplaint(
            complainant_fp=b"\x01" * 32,
            dealer_fp=b"\x02" * 32,
            revealed_share=1,
            revealed_blinding=2,
            round_id=3,
        )
        with pytest.raises(AttributeError):
            c.round_id = 99


class TestDKGResult:

    def test_frozen(self):
        r = DKGResult(
            vm_tag=0x01,
            epoch=1,
            group_pk=b"\xaa" * 48,
            participant_vks={b"\x01" * 32: b"\xbb" * 48},
            threshold=2,
            qual_set=frozenset([b"\x01" * 32]),
            phase=DKGPhase.EAGER,
        )
        with pytest.raises(AttributeError):
            r.epoch = 99

    def test_fields(self):
        vks = {b"\x01" * 32: b"\xaa" * 48, b"\x02" * 32: b"\xbb" * 48}
        qual = frozenset([b"\x01" * 32, b"\x02" * 32])
        r = DKGResult(
            vm_tag=0x01,
            epoch=5,
            group_pk=b"\xff" * 48,
            participant_vks=vks,
            threshold=2,
            qual_set=qual,
            phase=DKGPhase.INLINE,
        )
        assert r.vm_tag == 0x01
        assert r.epoch == 5
        assert len(r.group_pk) == 48
        assert len(r.participant_vks) == 2
        assert r.threshold == 2
        assert r.qual_set == qual
        assert r.phase is DKGPhase.INLINE


class TestDKGSessionConfig:

    def test_mutable(self):
        """SessionConfig is a regular dataclass (not frozen)."""
        cfg = DKGSessionConfig(
            vm_tag=0x01,
            epoch=1,
            threshold=2,
            participants=[b"\x01" * 32, b"\x02" * 32, b"\x03" * 32],
            timeout_rounds=10,
            start_round=100,
        )
        cfg.timeout_rounds = 20
        assert cfg.timeout_rounds == 20

    def test_fields(self):
        parts = [b"\x01" * 32, b"\x02" * 32]
        cfg = DKGSessionConfig(
            vm_tag=0x02,
            epoch=3,
            threshold=1,
            participants=parts,
            timeout_rounds=15,
            start_round=50,
        )
        assert cfg.vm_tag == 0x02
        assert cfg.epoch == 3
        assert cfg.threshold == 1
        assert cfg.participants == parts
        assert cfg.timeout_rounds == 15
        assert cfg.start_round == 50
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `pytest tests/test_dkg_types.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'src.ltp.execution.committee.dkg'`

- [ ] **Step 4: Write minimal implementation**

Create `src/ltp/execution/committee/dkg/types.py`:

```python
"""Core data types for the DKG layer (Spec C3b §2)."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

__all__ = [
    "DKGState",
    "DKGPhase",
    "DKGCommitment",
    "DKGShare",
    "DKGComplaint",
    "DKGResult",
    "DKGSessionConfig",
]


class DKGState(str, Enum):
    IDLE        = "idle"
    COMMITTING  = "committing"
    SHARING     = "sharing"
    VERIFYING   = "verifying"
    COMPLAINING = "complaining"
    FINALIZING  = "finalizing"
    COMPLETED   = "completed"
    FAILED      = "failed"


class DKGPhase(str, Enum):
    EAGER  = "eager"
    INLINE = "inline"


@dataclass(frozen=True)
class DKGCommitment:
    dealer_fp: bytes
    feldman_commitments: list[bytes]
    pedersen_commitments: list[bytes]
    round_id: int


@dataclass(frozen=True)
class DKGShare:
    dealer_fp: bytes
    recipient_fp: bytes
    share: int
    blinding_share: int


@dataclass(frozen=True)
class DKGComplaint:
    complainant_fp: bytes
    dealer_fp: bytes
    revealed_share: int
    revealed_blinding: int
    round_id: int


@dataclass(frozen=True)
class DKGResult:
    vm_tag: int
    epoch: int
    group_pk: bytes
    participant_vks: dict[bytes, bytes]
    threshold: int
    qual_set: frozenset[bytes]
    phase: DKGPhase


@dataclass
class DKGSessionConfig:
    vm_tag: int
    epoch: int
    threshold: int
    participants: list[bytes]
    timeout_rounds: int
    start_round: int
```

Create `src/ltp/execution/committee/dkg/__init__.py`:

```python
"""Threshold Distributed Key Generation (Spec C3b)."""

from .types import (
    DKGState,
    DKGPhase,
    DKGCommitment,
    DKGShare,
    DKGComplaint,
    DKGResult,
    DKGSessionConfig,
)

__all__ = [
    "DKGState",
    "DKGPhase",
    "DKGCommitment",
    "DKGShare",
    "DKGComplaint",
    "DKGResult",
    "DKGSessionConfig",
]
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `pytest tests/test_dkg_types.py -v`
Expected: all PASS

- [ ] **Step 6: Commit**

```bash
git add src/ltp/execution/committee/dkg/__init__.py \
        src/ltp/execution/committee/dkg/types.py \
        tests/test_dkg_types.py
git commit -m "feat(dkg): add core types — DKGState, DKGPhase, DKGCommitment, DKGShare, DKGComplaint, DKGResult, DKGSessionConfig"
```

---

### Task 2: Scalar Field Arithmetic

**Files:**
- Create: `src/ltp/execution/committee/dkg/scalar_poly.py`
- Test: `tests/test_dkg_scalar_poly.py`

**Context:** The BLS12-381 scalar field has order `r = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001` (~2^255). This is different from the Goldilocks field in `src/ltp/zk/field.py`. Pure Python — all arithmetic is `int % R`.

- [ ] **Step 1: Write the failing tests**

Create `tests/test_dkg_scalar_poly.py`:

```python
"""Tests for BLS12-381 scalar field polynomial arithmetic (Spec C3b §3)."""

from __future__ import annotations

import pytest

from src.ltp.execution.committee.dkg.scalar_poly import ScalarField, ScalarPoly


R = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001


class TestScalarField:

    def test_add_basic(self):
        assert ScalarField.add(3, 5) == 8

    def test_add_wraps_mod_r(self):
        assert ScalarField.add(R - 1, 2) == 1

    def test_mul_basic(self):
        assert ScalarField.mul(3, 7) == 21

    def test_mul_wraps_mod_r(self):
        assert ScalarField.mul(R - 1, 2) == R - 2

    def test_neg(self):
        assert ScalarField.add(5, ScalarField.neg(5)) == 0

    def test_neg_zero(self):
        assert ScalarField.neg(0) == 0

    def test_inv(self):
        a = 42
        a_inv = ScalarField.inv(a)
        assert ScalarField.mul(a, a_inv) == 1

    def test_inv_one(self):
        assert ScalarField.inv(1) == 1

    def test_random_in_range(self):
        for _ in range(10):
            val = ScalarField.random()
            assert 1 <= val < R


class TestScalarPoly:

    def test_constant_poly(self):
        p = ScalarPoly([42])
        assert p.evaluate(0) == 42
        assert p.evaluate(1) == 42
        assert p.evaluate(999) == 42

    def test_linear_poly(self):
        # f(x) = 10 + 3x
        p = ScalarPoly([10, 3])
        assert p.evaluate(0) == 10
        assert p.evaluate(1) == 13
        assert p.evaluate(2) == 16

    def test_quadratic_poly(self):
        # f(x) = 1 + 2x + 3x^2
        p = ScalarPoly([1, 2, 3])
        assert p.evaluate(0) == 1
        assert p.evaluate(1) == 6      # 1 + 2 + 3
        assert p.evaluate(2) == 17     # 1 + 4 + 12

    def test_evaluate_mod_r(self):
        p = ScalarPoly([R - 1, 2])
        # f(1) = (R-1) + 2 = R+1 ≡ 1 mod R
        assert p.evaluate(1) == 1

    def test_random_has_correct_degree(self):
        p = ScalarPoly.random(3)
        assert len(p.coeffs) == 4  # degree 3 → 4 coefficients

    def test_random_coefficients_in_range(self):
        p = ScalarPoly.random(2)
        for c in p.coeffs:
            assert 1 <= c < R

    def test_lagrange_basic_2_of_3(self):
        """Verify Lagrange interpolation reconstructs the secret."""
        # f(x) = 5 + 7x (secret = 5, degree 1 → 2-of-3)
        secret = 5
        p = ScalarPoly([secret, 7])
        participants = [1, 2, 3]
        shares = {i: p.evaluate(i) for i in participants}

        # Use any 2 participants to reconstruct f(0) = secret
        subset = [1, 2]
        reconstructed = 0
        for i in subset:
            li = ScalarPoly.lagrange_coefficient(i, subset)
            reconstructed = ScalarField.add(
                reconstructed, ScalarField.mul(shares[i], li)
            )
        assert reconstructed == secret

    def test_lagrange_3_of_5(self):
        """3-of-5 threshold reconstruction."""
        secret = 42
        p = ScalarPoly([secret, 11, 23])  # degree 2 → 3-of-n
        participants = [1, 2, 3, 4, 5]
        shares = {i: p.evaluate(i) for i in participants}

        # Any 3 suffice
        subset = [2, 4, 5]
        reconstructed = 0
        for i in subset:
            li = ScalarPoly.lagrange_coefficient(i, subset)
            reconstructed = ScalarField.add(
                reconstructed, ScalarField.mul(shares[i], li)
            )
        assert reconstructed == secret

    def test_lagrange_insufficient_shares_fails(self):
        """1 share cannot reconstruct a 2-of-3 secret."""
        secret = 100
        p = ScalarPoly([secret, 7])
        share_1 = p.evaluate(1)
        # With only 1 share, reconstruction gives wrong answer
        li = ScalarPoly.lagrange_coefficient(1, [1])
        # li for a single-element set is 1, so we just get the share value
        result = ScalarField.mul(share_1, li)
        assert result != secret  # share_1 = 100 + 7 = 107 ≠ 100
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_dkg_scalar_poly.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'src.ltp.execution.committee.dkg.scalar_poly'`

- [ ] **Step 3: Write minimal implementation**

Create `src/ltp/execution/committee/dkg/scalar_poly.py`:

```python
"""BLS12-381 scalar field polynomial arithmetic (Spec C3b §3)."""

from __future__ import annotations

import secrets

__all__ = ["ScalarField", "ScalarPoly"]


class ScalarField:
    """Arithmetic over BLS12-381 scalar field Z_r."""

    R = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001

    @staticmethod
    def add(a: int, b: int) -> int:
        return (a + b) % ScalarField.R

    @staticmethod
    def mul(a: int, b: int) -> int:
        return (a * b) % ScalarField.R

    @staticmethod
    def inv(a: int) -> int:
        return pow(a, ScalarField.R - 2, ScalarField.R)

    @staticmethod
    def neg(a: int) -> int:
        return (-a) % ScalarField.R

    @staticmethod
    def random() -> int:
        return secrets.randbelow(ScalarField.R - 1) + 1


class ScalarPoly:
    """Polynomial over BLS12-381 scalar field Z_r.

    coeffs[0] is the constant term (the secret in Shamir's scheme).
    """

    def __init__(self, coeffs: list[int]) -> None:
        self.coeffs = coeffs

    @staticmethod
    def random(degree: int) -> ScalarPoly:
        """Generate a random polynomial of the given degree."""
        return ScalarPoly([ScalarField.random() for _ in range(degree + 1)])

    def evaluate(self, x: int) -> int:
        """Evaluate at x using Horner's method, all arithmetic mod R."""
        result = 0
        for coeff in reversed(self.coeffs):
            result = ScalarField.add(ScalarField.mul(result, x), coeff)
        return result

    @staticmethod
    def lagrange_coefficient(i: int, participants: list[int]) -> int:
        """Compute Lagrange basis polynomial L_i(0) for participant i.

        L_i(0) = Π_{j≠i} (0 - j) / (i - j) = Π_{j≠i} (-j) / (i - j)
        """
        R = ScalarField.R
        numerator = 1
        denominator = 1
        for j in participants:
            if j == i:
                continue
            numerator = ScalarField.mul(numerator, ScalarField.neg(j))
            denominator = ScalarField.mul(denominator, (i - j) % R)
        return ScalarField.mul(numerator, ScalarField.inv(denominator))
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_dkg_scalar_poly.py -v`
Expected: all PASS

- [ ] **Step 5: Commit**

```bash
git add src/ltp/execution/committee/dkg/scalar_poly.py \
        tests/test_dkg_scalar_poly.py
git commit -m "feat(dkg): add ScalarField and ScalarPoly over BLS12-381 Z_r"
```

---

### Task 3: Pedersen VSS

**Files:**
- Create: `src/ltp/execution/committee/dkg/vss.py`
- Test: `tests/test_dkg_vss.py`

**Context:** Uses `src/ltp/zk/ec_backend.py` for G1 point operations: `g1_generator()`, `g1_scalar_mul()`, `g1_add()`, `g1_serialize()`, `g1_deserialize()`, `g1_eq()`. The existing `g1_h_generator()` uses domain `DOMAIN_ZK_TRANSFER`. DKG needs its own H generator with domain `"ETP-PEDERSEN-DKG-H"`. The `ec_backend` module requires `py_ecc` — tests should skip if unavailable.

- [ ] **Step 1: Write the failing tests**

Create `tests/test_dkg_vss.py`:

```python
"""Tests for Pedersen VSS (Spec C3b §4)."""

from __future__ import annotations

import pytest

from src.ltp.zk.ec_backend import bls12_381_available
from src.ltp.execution.committee.dkg.scalar_poly import ScalarField, ScalarPoly

pytestmark = pytest.mark.skipif(
    not bls12_381_available(), reason="py_ecc not installed"
)


from src.ltp.execution.committee.dkg.vss import PedersenVSS  # noqa: E402


R = ScalarField.R


class TestGenerators:

    def test_g_and_h_are_distinct(self):
        """G and H generators must be different points."""
        from src.ltp.execution.committee.dkg.vss import G_POINT, H_POINT
        assert G_POINT != H_POINT

    def test_h_is_not_identity(self):
        from src.ltp.execution.committee.dkg.vss import H_POINT
        assert H_POINT is not None


class TestGenerateCommitments:

    def test_returns_correct_count(self):
        secret_poly = ScalarPoly([10, 20])
        blinding_poly = ScalarPoly([30, 40])
        feldman, pedersen = PedersenVSS.generate_commitments(secret_poly, blinding_poly)
        assert len(feldman) == 2
        assert len(pedersen) == 2

    def test_commitments_are_96_bytes(self):
        secret_poly = ScalarPoly([10, 20])
        blinding_poly = ScalarPoly([30, 40])
        feldman, pedersen = PedersenVSS.generate_commitments(secret_poly, blinding_poly)
        for c in feldman + pedersen:
            assert len(c) == 96

    def test_feldman_and_pedersen_differ(self):
        """Feldman = s*G, Pedersen = s*G + b*H — they differ when b ≠ 0."""
        secret_poly = ScalarPoly([10, 20])
        blinding_poly = ScalarPoly([5, 15])
        feldman, pedersen = PedersenVSS.generate_commitments(secret_poly, blinding_poly)
        assert feldman[0] != pedersen[0]


class TestCreateShare:

    def test_share_matches_poly_evaluation(self):
        secret_poly = ScalarPoly([10, 20, 30])
        blinding_poly = ScalarPoly([5, 15, 25])
        share, blinding = PedersenVSS.create_share(secret_poly, blinding_poly, 1)
        assert share == secret_poly.evaluate(1)
        assert blinding == blinding_poly.evaluate(1)

    def test_different_recipients_get_different_shares(self):
        secret_poly = ScalarPoly([10, 20])
        blinding_poly = ScalarPoly([5, 15])
        s1, b1 = PedersenVSS.create_share(secret_poly, blinding_poly, 1)
        s2, b2 = PedersenVSS.create_share(secret_poly, blinding_poly, 2)
        assert s1 != s2
        assert b1 != b2


class TestVerifyShare:

    def test_valid_share_verifies(self):
        secret_poly = ScalarPoly([10, 20])
        blinding_poly = ScalarPoly([5, 15])
        _, pedersen = PedersenVSS.generate_commitments(secret_poly, blinding_poly)
        share, blinding = PedersenVSS.create_share(secret_poly, blinding_poly, 1)
        assert PedersenVSS.verify_share(1, share, blinding, pedersen) is True

    def test_tampered_share_fails(self):
        secret_poly = ScalarPoly([10, 20])
        blinding_poly = ScalarPoly([5, 15])
        _, pedersen = PedersenVSS.generate_commitments(secret_poly, blinding_poly)
        share, blinding = PedersenVSS.create_share(secret_poly, blinding_poly, 1)
        assert PedersenVSS.verify_share(1, share + 1, blinding, pedersen) is False

    def test_tampered_blinding_fails(self):
        secret_poly = ScalarPoly([10, 20])
        blinding_poly = ScalarPoly([5, 15])
        _, pedersen = PedersenVSS.generate_commitments(secret_poly, blinding_poly)
        share, blinding = PedersenVSS.create_share(secret_poly, blinding_poly, 1)
        assert PedersenVSS.verify_share(1, share, blinding + 1, pedersen) is False

    def test_wrong_index_fails(self):
        secret_poly = ScalarPoly([10, 20])
        blinding_poly = ScalarPoly([5, 15])
        _, pedersen = PedersenVSS.generate_commitments(secret_poly, blinding_poly)
        share, blinding = PedersenVSS.create_share(secret_poly, blinding_poly, 1)
        assert PedersenVSS.verify_share(2, share, blinding, pedersen) is False

    def test_multiple_recipients_all_verify(self):
        secret_poly = ScalarPoly.random(2)
        blinding_poly = ScalarPoly.random(2)
        _, pedersen = PedersenVSS.generate_commitments(secret_poly, blinding_poly)
        for i in range(1, 6):
            share, blinding = PedersenVSS.create_share(secret_poly, blinding_poly, i)
            assert PedersenVSS.verify_share(i, share, blinding, pedersen) is True
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_dkg_vss.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'src.ltp.execution.committee.dkg.vss'`

- [ ] **Step 3: Write minimal implementation**

Create `src/ltp/execution/committee/dkg/vss.py`:

```python
"""Pedersen Verifiable Secret Sharing (Spec C3b §4)."""

from __future__ import annotations

import hashlib

from src.ltp.zk.ec_backend import (
    bls12_381_available,
    g1_add,
    g1_deserialize,
    g1_eq,
    g1_generator,
    g1_identity,
    g1_scalar_mul,
    g1_serialize,
)

from .scalar_poly import ScalarField, ScalarPoly

__all__ = ["PedersenVSS", "G_POINT", "H_POINT"]


def _derive_h_generator():
    """Derive H via hash-to-curve with DKG-specific domain separation.

    Uses try-and-increment to find a valid G1 point, then clears the
    cofactor to land in the prime-order subgroup.
    """
    from py_ecc.bls12_381 import (
        field_modulus,
        multiply as _g1_multiply,
    )
    from py_ecc.bls12_381 import FQ

    cofactor = 0x396C8C005555E1568C00AAAB0000AAAB
    seed = b"ETP-PEDERSEN-DKG-H"

    for attempt in range(256):
        h = hashlib.sha3_256(seed + attempt.to_bytes(2, "big")).digest()
        x = int.from_bytes(h, "big") % field_modulus
        x_fq = FQ(x)
        y_squared = x_fq ** 3 + FQ(4)
        y_candidate = y_squared ** ((field_modulus + 1) // 4)
        if y_candidate ** 2 == y_squared:
            y = y_candidate
            if int(y) % 2 != 0:
                y = FQ(field_modulus - int(y))
            point = (x_fq, y)
            h_point = _g1_multiply(point, cofactor)
            if h_point is not None:
                return h_point

    raise RuntimeError("Failed to derive DKG H generator")


# Module-level generator points (computed once on import if py_ecc available)
if bls12_381_available():
    G_POINT = g1_generator()
    H_POINT = _derive_h_generator()
else:
    G_POINT = None
    H_POINT = None


class PedersenVSS:
    """Pedersen VSS — dual-commitment verifiable secret sharing."""

    @staticmethod
    def generate_commitments(
        secret_poly: ScalarPoly,
        blinding_poly: ScalarPoly,
    ) -> tuple[list[bytes], list[bytes]]:
        """Compute Feldman and Pedersen commitments for each coefficient.

        Feldman:  s_k * G
        Pedersen: s_k * G + b_k * H
        """
        feldman = []
        pedersen = []
        for s_k, b_k in zip(secret_poly.coeffs, blinding_poly.coeffs):
            s_G = g1_scalar_mul(G_POINT, s_k)
            b_H = g1_scalar_mul(H_POINT, b_k)
            feldman.append(g1_serialize(s_G))
            pedersen.append(g1_serialize(g1_add(s_G, b_H)))
        return feldman, pedersen

    @staticmethod
    def create_share(
        secret_poly: ScalarPoly,
        blinding_poly: ScalarPoly,
        recipient_index: int,
    ) -> tuple[int, int]:
        """Evaluate both polynomials at recipient_index."""
        return (
            secret_poly.evaluate(recipient_index),
            blinding_poly.evaluate(recipient_index),
        )

    @staticmethod
    def verify_share(
        recipient_index: int,
        share: int,
        blinding_share: int,
        pedersen_commitments: list[bytes],
    ) -> bool:
        """Verify share against Pedersen commitments.

        Check: share * G + blinding_share * H == Σ(commitment_k * index^k)
        """
        # LHS: share * G + blinding_share * H
        lhs = g1_add(
            g1_scalar_mul(G_POINT, share),
            g1_scalar_mul(H_POINT, blinding_share),
        )

        # RHS: Σ commitment_k * index^k
        rhs = g1_identity()
        x_power = 1  # index^0 = 1
        for commitment_bytes in pedersen_commitments:
            c_point = g1_deserialize(commitment_bytes)
            term = g1_scalar_mul(c_point, x_power)
            rhs = g1_add(rhs, term) if rhs is not None else term
            x_power = ScalarField.mul(x_power, recipient_index)

        return g1_eq(lhs, rhs)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_dkg_vss.py -v`
Expected: all PASS (or all SKIPPED if py_ecc not installed)

- [ ] **Step 5: Commit**

```bash
git add src/ltp/execution/committee/dkg/vss.py tests/test_dkg_vss.py
git commit -m "feat(dkg): add PedersenVSS — dual commitments, share creation and verification"
```

---

### Task 4: DKG Transport

**Files:**
- Create: `src/ltp/execution/committee/dkg/transport.py`
- Test: `tests/test_dkg_transport.py`

- [ ] **Step 1: Write the failing tests**

Create `tests/test_dkg_transport.py`:

```python
"""Tests for DKG transport protocol (Spec C3b §6)."""

from __future__ import annotations

import pytest

from src.ltp.execution.committee.dkg.types import (
    DKGCommitment,
    DKGComplaint,
    DKGShare,
)
from src.ltp.execution.committee.dkg.transport import (
    DKGTransport,
    FakeDKGTransport,
)


FP_A = b"\x01" * 32
FP_B = b"\x02" * 32
FP_C = b"\x03" * 32


class TestFakeDKGTransportCommitments:

    def test_broadcast_and_receive(self):
        t = FakeDKGTransport()
        c = DKGCommitment(
            dealer_fp=FP_A,
            feldman_commitments=[b"\xaa" * 96],
            pedersen_commitments=[b"\xbb" * 96],
            round_id=1,
        )
        t.broadcast_commitment(c)
        received = t.receive_commitments()
        assert len(received) == 1
        assert received[0] is c

    def test_multiple_commitments_ordered(self):
        t = FakeDKGTransport()
        c1 = DKGCommitment(FP_A, [b"\xaa" * 96], [b"\xbb" * 96], 1)
        c2 = DKGCommitment(FP_B, [b"\xcc" * 96], [b"\xdd" * 96], 2)
        t.broadcast_commitment(c1)
        t.broadcast_commitment(c2)
        received = t.receive_commitments()
        assert len(received) == 2
        assert received[0].dealer_fp == FP_A
        assert received[1].dealer_fp == FP_B


class TestFakeDKGTransportShares:

    def test_send_and_receive_per_recipient(self):
        t = FakeDKGTransport()
        s_ab = DKGShare(dealer_fp=FP_A, recipient_fp=FP_B, share=10, blinding_share=20)
        s_ac = DKGShare(dealer_fp=FP_A, recipient_fp=FP_C, share=30, blinding_share=40)
        t.send_share(FP_B, s_ab)
        t.send_share(FP_C, s_ac)

        b_shares = t.receive_shares(FP_B)
        c_shares = t.receive_shares(FP_C)
        assert len(b_shares) == 1
        assert b_shares[0].share == 10
        assert len(c_shares) == 1
        assert c_shares[0].share == 30

    def test_receive_empty_if_no_shares(self):
        t = FakeDKGTransport()
        assert t.receive_shares(FP_A) == []


class TestFakeDKGTransportComplaints:

    def test_broadcast_and_receive_complaints(self):
        t = FakeDKGTransport()
        complaint = DKGComplaint(
            complainant_fp=FP_B,
            dealer_fp=FP_A,
            revealed_share=10,
            revealed_blinding=20,
            round_id=5,
        )
        t.broadcast_complaint(complaint)
        received = t.receive_complaints()
        assert len(received) == 1
        assert received[0] is complaint


class TestDKGTransportProtocol:

    def test_fake_implements_protocol(self):
        """FakeDKGTransport satisfies the DKGTransport Protocol."""
        transport: DKGTransport = FakeDKGTransport()
        assert hasattr(transport, "broadcast_commitment")
        assert hasattr(transport, "broadcast_complaint")
        assert hasattr(transport, "send_share")
        assert hasattr(transport, "receive_commitments")
        assert hasattr(transport, "receive_shares")
        assert hasattr(transport, "receive_complaints")
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_dkg_transport.py -v`
Expected: FAIL — `ModuleNotFoundError`

- [ ] **Step 3: Write minimal implementation**

Create `src/ltp/execution/committee/dkg/transport.py`:

```python
"""DKG transport protocol (Spec C3b §6)."""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from .types import DKGCommitment, DKGComplaint, DKGShare

__all__ = ["DKGTransport", "FakeDKGTransport"]


@runtime_checkable
class DKGTransport(Protocol):
    """Abstract transport for DKG ceremony messages."""

    def broadcast_commitment(self, commitment: DKGCommitment) -> None: ...
    def broadcast_complaint(self, complaint: DKGComplaint) -> None: ...
    def send_share(self, recipient_fp: bytes, share: DKGShare) -> None: ...
    def receive_commitments(self) -> list[DKGCommitment]: ...
    def receive_shares(self, my_fp: bytes) -> list[DKGShare]: ...
    def receive_complaints(self) -> list[DKGComplaint]: ...


class FakeDKGTransport:
    """In-memory DKG transport for testing. All participants share one instance."""

    def __init__(self) -> None:
        self._commitments: list[DKGCommitment] = []
        self._complaints: list[DKGComplaint] = []
        self._shares: dict[bytes, list[DKGShare]] = {}

    def broadcast_commitment(self, commitment: DKGCommitment) -> None:
        self._commitments.append(commitment)

    def broadcast_complaint(self, complaint: DKGComplaint) -> None:
        self._complaints.append(complaint)

    def send_share(self, recipient_fp: bytes, share: DKGShare) -> None:
        self._shares.setdefault(recipient_fp, []).append(share)

    def receive_commitments(self) -> list[DKGCommitment]:
        return list(self._commitments)

    def receive_shares(self, my_fp: bytes) -> list[DKGShare]:
        return list(self._shares.get(my_fp, []))

    def receive_complaints(self) -> list[DKGComplaint]:
        return list(self._complaints)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_dkg_transport.py -v`
Expected: all PASS

- [ ] **Step 5: Commit**

```bash
git add src/ltp/execution/committee/dkg/transport.py tests/test_dkg_transport.py
git commit -m "feat(dkg): add DKGTransport protocol and FakeDKGTransport"
```

---

### Task 5: DKG Key Registry

**Files:**
- Create: `src/ltp/execution/committee/dkg/registry.py`
- Test: `tests/test_dkg_registry.py`

- [ ] **Step 1: Write the failing tests**

Create `tests/test_dkg_registry.py`:

```python
"""Tests for DKG key registry (Spec C3b §7)."""

from __future__ import annotations

import pytest

from src.ltp.execution.committee.dkg.types import DKGPhase, DKGResult
from src.ltp.execution.committee.dkg.registry import DKGKeyRegistry


def _make_result(vm_tag: int = 0x01, epoch: int = 1) -> DKGResult:
    return DKGResult(
        vm_tag=vm_tag,
        epoch=epoch,
        group_pk=bytes([epoch]) * 48,
        participant_vks={b"\x01" * 32: b"\xaa" * 48},
        threshold=2,
        qual_set=frozenset([b"\x01" * 32]),
        phase=DKGPhase.EAGER,
    )


class TestDKGKeyRegistryStore:

    def test_store_and_get(self):
        reg = DKGKeyRegistry(0x01)
        result = _make_result(epoch=1)
        reg.store(result)
        assert reg.get(1) is result

    def test_store_duplicate_epoch_raises(self):
        reg = DKGKeyRegistry(0x01)
        reg.store(_make_result(epoch=1))
        with pytest.raises(ValueError, match="already has a group key"):
            reg.store(_make_result(epoch=1))

    def test_store_wrong_vm_tag_raises(self):
        reg = DKGKeyRegistry(0x01)
        with pytest.raises(ValueError, match="vm_tag mismatch"):
            reg.store(_make_result(vm_tag=0x02, epoch=1))

    def test_get_missing_raises(self):
        reg = DKGKeyRegistry(0x01)
        with pytest.raises(KeyError):
            reg.get(999)


class TestDKGKeyRegistryCurrent:

    def test_current_empty(self):
        reg = DKGKeyRegistry(0x01)
        assert reg.current() is None

    def test_current_returns_highest_epoch(self):
        reg = DKGKeyRegistry(0x01)
        reg.store(_make_result(epoch=1))
        reg.store(_make_result(epoch=3))
        reg.store(_make_result(epoch=2))
        current = reg.current()
        assert current.epoch == 3


class TestDKGKeyRegistryConvenience:

    def test_group_pk(self):
        reg = DKGKeyRegistry(0x01)
        reg.store(_make_result(epoch=1))
        pk = reg.group_pk(1)
        assert len(pk) == 48
        assert pk == bytes([1]) * 48

    def test_has_epoch(self):
        reg = DKGKeyRegistry(0x01)
        assert reg.has_epoch(1) is False
        reg.store(_make_result(epoch=1))
        assert reg.has_epoch(1) is True

    def test_epoch_count(self):
        reg = DKGKeyRegistry(0x01)
        assert reg.epoch_count() == 0
        reg.store(_make_result(epoch=1))
        reg.store(_make_result(epoch=2))
        assert reg.epoch_count() == 2
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_dkg_registry.py -v`
Expected: FAIL — `ModuleNotFoundError`

- [ ] **Step 3: Write minimal implementation**

Create `src/ltp/execution/committee/dkg/registry.py`:

```python
"""DKG key registry — per-VM, per-epoch group key store (Spec C3b §7)."""

from __future__ import annotations

from typing import Optional

from .types import DKGResult

__all__ = ["DKGKeyRegistry"]


class DKGKeyRegistry:
    """Append-only store mapping epoch → DKGResult for a single VM."""

    def __init__(self, vm_tag: int) -> None:
        self.vm_tag = vm_tag
        self._epochs: dict[int, DKGResult] = {}

    def store(self, result: DKGResult) -> None:
        if result.epoch in self._epochs:
            raise ValueError(
                f"epoch {result.epoch} already has a group key"
            )
        if result.vm_tag != self.vm_tag:
            raise ValueError(
                f"vm_tag mismatch: {result.vm_tag} != {self.vm_tag}"
            )
        self._epochs[result.epoch] = result

    def get(self, epoch: int) -> DKGResult:
        return self._epochs[epoch]

    def current(self) -> Optional[DKGResult]:
        if not self._epochs:
            return None
        return self._epochs[max(self._epochs)]

    def group_pk(self, epoch: int) -> bytes:
        return self.get(epoch).group_pk

    def has_epoch(self, epoch: int) -> bool:
        return epoch in self._epochs

    def epoch_count(self) -> int:
        return len(self._epochs)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_dkg_registry.py -v`
Expected: all PASS

- [ ] **Step 5: Commit**

```bash
git add src/ltp/execution/committee/dkg/registry.py tests/test_dkg_registry.py
git commit -m "feat(dkg): add DKGKeyRegistry — append-only per-epoch group key store"
```

---

### Task 6: DKG Session State Machine

**Files:**
- Create: `src/ltp/execution/committee/dkg/session.py`
- Test: `tests/test_dkg_session.py`

**Context:** This is the most complex module. It orchestrates the full ceremony. Requires `py_ecc` for Pedersen VSS operations. Each test runs a self-contained mini-ceremony with 3 participants.

- [ ] **Step 1: Write the failing tests**

Create `tests/test_dkg_session.py`:

```python
"""Tests for DKG session state machine (Spec C3b §5)."""

from __future__ import annotations

import pytest

from src.ltp.zk.ec_backend import bls12_381_available
from src.ltp.execution.committee.dkg.types import (
    DKGPhase,
    DKGSessionConfig,
    DKGState,
)

pytestmark = pytest.mark.skipif(
    not bls12_381_available(), reason="py_ecc not installed"
)

from src.ltp.execution.committee.dkg.session import DKGSession  # noqa: E402
from src.ltp.execution.committee.dkg.vss import PedersenVSS  # noqa: E402


FP_1 = b"\x01" * 32
FP_2 = b"\x02" * 32
FP_3 = b"\x03" * 32
PARTICIPANTS = [FP_1, FP_2, FP_3]


def _make_config(threshold: int = 2, start_round: int = 0) -> DKGSessionConfig:
    return DKGSessionConfig(
        vm_tag=0x01,
        epoch=1,
        threshold=threshold,
        participants=list(PARTICIPANTS),
        timeout_rounds=10,
        start_round=start_round,
    )


class TestDKGSessionInit:

    def test_initial_state_is_idle(self):
        cfg = _make_config()
        s = DKGSession(cfg, FP_1, 1)
        assert s.state is DKGState.IDLE


class TestDKGSessionBegin:

    def test_transitions_to_committing(self):
        s = DKGSession(_make_config(), FP_1, 1)
        commitment, shares = s.begin()
        assert s.state is DKGState.COMMITTING
        assert commitment.dealer_fp == FP_1
        assert len(commitment.feldman_commitments) == 2  # threshold=2, degree=1
        assert len(commitment.pedersen_commitments) == 2
        # Shares for other participants (not self)
        assert FP_2 in shares
        assert FP_3 in shares
        assert FP_1 not in shares

    def test_begin_twice_raises(self):
        s = DKGSession(_make_config(), FP_1, 1)
        s.begin()
        with pytest.raises(ValueError, match="not IDLE"):
            s.begin()


class TestDKGSessionCommitmentPhase:

    def test_receive_and_end_commitment(self):
        cfg = _make_config()
        s1 = DKGSession(cfg, FP_1, 1)
        s2 = DKGSession(cfg, FP_2, 2)
        c1, _ = s1.begin()
        c2, _ = s2.begin()
        s1.receive_commitment(c2)
        s1.end_commitment_phase()
        assert s1.state is DKGState.SHARING


class TestDKGSessionSharingPhase:

    def test_receive_shares_and_verify(self):
        cfg = _make_config()
        s1 = DKGSession(cfg, FP_1, 1)
        s2 = DKGSession(cfg, FP_2, 2)
        s3 = DKGSession(cfg, FP_3, 3)

        c1, shares_1 = s1.begin()
        c2, shares_2 = s2.begin()
        c3, shares_3 = s3.begin()

        # s1 receives commitments from s2, s3
        s1.receive_commitment(c2)
        s1.receive_commitment(c3)
        s1.end_commitment_phase()

        # s1 receives shares from s2, s3
        s1.receive_share(shares_2[FP_1])
        s1.receive_share(shares_3[FP_1])
        complaints = s1.end_sharing_phase()
        assert complaints == []
        assert s1.state is DKGState.COMPLAINING


class TestDKGSessionFinalize:

    def test_happy_path_finalize(self):
        """3 participants, threshold=2, no complaints → COMPLETED."""
        cfg = _make_config()
        sessions = [
            DKGSession(cfg, FP_1, 1),
            DKGSession(cfg, FP_2, 2),
            DKGSession(cfg, FP_3, 3),
        ]

        # Phase 1: begin — collect commitments and shares
        commitments = []
        all_shares = []
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
            for j, shares in enumerate(all_shares):
                fp = PARTICIPANTS[i]
                if fp in shares:
                    s.receive_share(shares[fp])
            complaints = s.end_sharing_phase()
            assert complaints == []

        # Phase 4: finalize
        results = []
        for s in sessions:
            result = s.finalize()
            results.append(result)
            assert s.state is DKGState.COMPLETED

        # All participants agree on the group public key
        assert results[0].group_pk == results[1].group_pk == results[2].group_pk
        assert len(results[0].group_pk) == 96  # uncompressed G1
        assert results[0].threshold == 2
        assert len(results[0].qual_set) == 3


class TestDKGSessionAbort:

    def test_abort_from_any_state(self):
        s = DKGSession(_make_config(), FP_1, 1)
        s.abort("test reason")
        assert s.state is DKGState.FAILED

    def test_abort_during_committing(self):
        s = DKGSession(_make_config(), FP_1, 1)
        s.begin()
        s.abort("network failure")
        assert s.state is DKGState.FAILED


class TestDKGSessionTimeout:

    def test_timeout_triggers_failure(self):
        cfg = _make_config(start_round=100)
        s = DKGSession(cfg, FP_1, 1)
        s.begin()
        assert s.check_timeout(105) is False
        assert s.check_timeout(110) is True
        assert s.state is DKGState.FAILED

    def test_no_timeout_before_deadline(self):
        cfg = _make_config(start_round=0)
        s = DKGSession(cfg, FP_1, 1)
        s.begin()
        assert s.check_timeout(9) is False
        assert s.state is DKGState.COMMITTING
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_dkg_session.py -v`
Expected: FAIL — `ModuleNotFoundError`

- [ ] **Step 3: Write minimal implementation**

Create `src/ltp/execution/committee/dkg/session.py`:

```python
"""DKG session state machine (Spec C3b §5)."""

from __future__ import annotations

from typing import Optional

from src.ltp.zk.ec_backend import (
    g1_add,
    g1_deserialize,
    g1_eq,
    g1_generator,
    g1_identity,
    g1_scalar_mul,
    g1_serialize,
)

from .scalar_poly import ScalarField, ScalarPoly
from .types import (
    DKGCommitment,
    DKGComplaint,
    DKGPhase,
    DKGResult,
    DKGSessionConfig,
    DKGShare,
    DKGState,
)
from .vss import PedersenVSS

__all__ = ["DKGSession"]


class DKGSession:
    """Mutable state machine for a single DKG ceremony."""

    def __init__(
        self,
        config: DKGSessionConfig,
        my_fp: bytes,
        my_index: int,
    ) -> None:
        self.config = config
        self.state = DKGState.IDLE
        self.my_fp = my_fp
        self.my_index = my_index

        self._secret_poly: Optional[ScalarPoly] = None
        self._blinding_poly: Optional[ScalarPoly] = None

        self._commitments: dict[bytes, DKGCommitment] = {}
        self._shares: dict[bytes, DKGShare] = {}
        self._complaints: list[DKGComplaint] = []
        self._qual: set[bytes] = set()

    def begin(self) -> tuple[DKGCommitment, dict[bytes, DKGShare]]:
        """IDLE → COMMITTING. Generate polynomials and return outputs."""
        if self.state is not DKGState.IDLE:
            raise ValueError(f"cannot begin: state is not IDLE (is {self.state.value})")

        degree = self.config.threshold - 1
        self._secret_poly = ScalarPoly.random(degree)
        self._blinding_poly = ScalarPoly.random(degree)

        feldman, pedersen = PedersenVSS.generate_commitments(
            self._secret_poly, self._blinding_poly,
        )
        commitment = DKGCommitment(
            dealer_fp=self.my_fp,
            feldman_commitments=feldman,
            pedersen_commitments=pedersen,
            round_id=self.config.start_round,
        )
        self._commitments[self.my_fp] = commitment

        # Create shares for each other participant
        shares: dict[bytes, DKGShare] = {}
        for idx, fp in enumerate(self.config.participants, start=1):
            if fp == self.my_fp:
                continue
            s, b = PedersenVSS.create_share(
                self._secret_poly, self._blinding_poly, idx,
            )
            shares[fp] = DKGShare(
                dealer_fp=self.my_fp,
                recipient_fp=fp,
                share=s,
                blinding_share=b,
            )

        self.state = DKGState.COMMITTING
        return commitment, shares

    def receive_commitment(self, commitment: DKGCommitment) -> None:
        """Collect a commitment from another dealer."""
        self._commitments[commitment.dealer_fp] = commitment

    def end_commitment_phase(self) -> None:
        """COMMITTING → SHARING."""
        self.state = DKGState.SHARING

    def receive_share(self, share: DKGShare) -> None:
        """Collect a share from a dealer."""
        self._shares[share.dealer_fp] = share

    def end_sharing_phase(self) -> list[DKGComplaint]:
        """SHARING → VERIFYING → COMPLAINING. Verify shares, return complaints."""
        self.state = DKGState.VERIFYING
        complaints: list[DKGComplaint] = []

        for dealer_fp, share in self._shares.items():
            commitment = self._commitments.get(dealer_fp)
            if commitment is None:
                continue
            valid = PedersenVSS.verify_share(
                self.my_index,
                share.share,
                share.blinding_share,
                commitment.pedersen_commitments,
            )
            if not valid:
                complaints.append(DKGComplaint(
                    complainant_fp=self.my_fp,
                    dealer_fp=dealer_fp,
                    revealed_share=share.share,
                    revealed_blinding=share.blinding_share,
                    round_id=self.config.start_round,
                ))

        self._complaints = complaints
        self.state = DKGState.COMPLAINING
        return complaints

    def receive_complaint(self, complaint: DKGComplaint) -> None:
        """Collect a complaint during the COMPLAINING phase."""
        self._complaints.append(complaint)

    def finalize(self) -> DKGResult:
        """COMPLAINING → FINALIZING → COMPLETED. Resolve complaints and derive keys."""
        self.state = DKGState.FINALIZING

        # Build QUAL: start with all dealers, remove those with valid complaints
        self._qual = set(self._commitments.keys())
        for complaint in self._complaints:
            commitment = self._commitments.get(complaint.dealer_fp)
            if commitment is None:
                continue
            # Verify the revealed share against the dealer's commitments
            dealer_idx = self.config.participants.index(complaint.dealer_fp) + 1
            complainant_idx = self.config.participants.index(complaint.complainant_fp) + 1
            valid = PedersenVSS.verify_share(
                complainant_idx,
                complaint.revealed_share,
                complaint.revealed_blinding,
                commitment.pedersen_commitments,
            )
            if not valid:
                # Complaint is valid — dealer sent a bad share → exclude dealer
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

        # Derive my verification key
        my_vk = g1_serialize(g1_scalar_mul(g1_generator(), my_secret_share))

        # For now we only know our own VK; in a real deployment participants
        # exchange VKs. For the DKGResult we store what we know.
        participant_vks = {self.my_fp: my_vk}

        self.state = DKGState.COMPLETED
        return DKGResult(
            vm_tag=self.config.vm_tag,
            epoch=self.config.epoch,
            group_pk=g1_serialize(group_point),
            participant_vks=participant_vks,
            threshold=self.config.threshold,
            qual_set=frozenset(self._qual),
            phase=DKGPhase.EAGER,
        )

    def abort(self, reason: str) -> None:
        """Any state → FAILED."""
        self.state = DKGState.FAILED

    def check_timeout(self, current_round: int) -> bool:
        """Returns True and fails if timeout exceeded."""
        if current_round >= self.config.start_round + self.config.timeout_rounds:
            self.state = DKGState.FAILED
            return True
        return False
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_dkg_session.py -v`
Expected: all PASS (or all SKIPPED if py_ecc not installed)

- [ ] **Step 5: Commit**

```bash
git add src/ltp/execution/committee/dkg/session.py tests/test_dkg_session.py
git commit -m "feat(dkg): add DKGSession state machine — full ceremony orchestration"
```

---

### Task 7: End-to-End DKG Ceremony Tests

**Files:**
- Test: `tests/test_dkg_e2e.py`

**Context:** Multi-participant ceremonies exercising the full stack (scalar poly → VSS → session → transport → registry). Requires `py_ecc`.

- [ ] **Step 1: Write the tests**

Create `tests/test_dkg_e2e.py`:

```python
"""End-to-end DKG ceremony tests (Spec C3b)."""

from __future__ import annotations

import pytest

from src.ltp.zk.ec_backend import bls12_381_available
from src.ltp.execution.committee.dkg.types import (
    DKGPhase,
    DKGSessionConfig,
    DKGState,
)

pytestmark = pytest.mark.skipif(
    not bls12_381_available(), reason="py_ecc not installed"
)

from src.ltp.execution.committee.dkg.session import DKGSession  # noqa: E402
from src.ltp.execution.committee.dkg.transport import FakeDKGTransport  # noqa: E402
from src.ltp.execution.committee.dkg.registry import DKGKeyRegistry  # noqa: E402


PARTICIPANTS = [bytes([i]) * 32 for i in range(1, 6)]  # 5 participants


def _run_ceremony(
    participants: list[bytes],
    threshold: int,
    tamper_dealer: bytes | None = None,
) -> list:
    """Run a complete DKG ceremony and return results from all participants.

    If tamper_dealer is set, that dealer's shares are corrupted.
    """
    n = len(participants)
    cfg = DKGSessionConfig(
        vm_tag=0x01, epoch=1, threshold=threshold,
        participants=list(participants), timeout_rounds=20, start_round=0,
    )
    sessions = [
        DKGSession(cfg, fp, idx + 1)
        for idx, fp in enumerate(participants)
    ]
    transport = FakeDKGTransport()

    # Phase 1: begin
    all_shares = {}
    for s in sessions:
        commitment, shares = s.begin()
        transport.broadcast_commitment(commitment)
        for recipient_fp, share in shares.items():
            if tamper_dealer == s.my_fp:
                # Corrupt the share
                from src.ltp.execution.committee.dkg.types import DKGShare
                share = DKGShare(
                    dealer_fp=share.dealer_fp,
                    recipient_fp=share.recipient_fp,
                    share=share.share + 1,  # tamper
                    blinding_share=share.blinding_share,
                )
            transport.send_share(recipient_fp, share)

    # Phase 2: distribute commitments
    commitments = transport.receive_commitments()
    for s in sessions:
        for c in commitments:
            if c.dealer_fp != s.my_fp:
                s.receive_commitment(c)
        s.end_commitment_phase()

    # Phase 3: distribute shares and verify
    all_complaints = []
    for s in sessions:
        my_shares = transport.receive_shares(s.my_fp)
        for share in my_shares:
            s.receive_share(share)
        complaints = s.end_sharing_phase()
        for c in complaints:
            transport.broadcast_complaint(c)
        all_complaints.extend(complaints)

    # Phase 4: distribute complaints and finalize
    all_received_complaints = transport.receive_complaints()
    results = []
    for s in sessions:
        for c in all_received_complaints:
            if c.complainant_fp != s.my_fp:
                s.receive_complaint(c)
        result = s.finalize()
        results.append(result)

    return results


class TestHappyPathCeremony:

    def test_3_of_3(self):
        results = _run_ceremony(PARTICIPANTS[:3], threshold=3)
        group_pks = {r.group_pk for r in results}
        assert len(group_pks) == 1  # all agree
        assert results[0].threshold == 3
        assert len(results[0].qual_set) == 3

    def test_2_of_5(self):
        results = _run_ceremony(PARTICIPANTS, threshold=2)
        group_pks = {r.group_pk for r in results}
        assert len(group_pks) == 1
        assert results[0].threshold == 2
        assert len(results[0].qual_set) == 5

    def test_3_of_5(self):
        results = _run_ceremony(PARTICIPANTS, threshold=3)
        group_pks = {r.group_pk for r in results}
        assert len(group_pks) == 1


class TestComplaintResolution:

    def test_dishonest_dealer_excluded_from_qual(self):
        """One dealer sends bad shares → excluded from QUAL, ceremony succeeds."""
        tamper_fp = PARTICIPANTS[0]
        results = _run_ceremony(PARTICIPANTS[:4], threshold=2, tamper_dealer=tamper_fp)
        # Dealer 0 excluded, QUAL = {1, 2, 3} — still >= threshold
        for r in results:
            assert tamper_fp not in r.qual_set
            assert len(r.qual_set) == 3

    def test_too_many_dishonest_dealers_fails(self):
        """If too many dealers are excluded, QUAL < threshold → ceremony fails."""
        # 2-of-3 with 2 dishonest → QUAL=1 < 2
        # We can only tamper one dealer with _run_ceremony, so test with
        # 2-of-2 and tamper one → QUAL=1 < 2
        with pytest.raises(ValueError, match="QUAL set too small"):
            _run_ceremony(PARTICIPANTS[:2], threshold=2, tamper_dealer=PARTICIPANTS[0])


class TestRegistryIntegration:

    def test_store_ceremony_result(self):
        results = _run_ceremony(PARTICIPANTS[:3], threshold=2)
        reg = DKGKeyRegistry(0x01)
        reg.store(results[0])
        assert reg.has_epoch(1)
        assert reg.group_pk(1) == results[0].group_pk

    def test_multiple_epochs(self):
        reg = DKGKeyRegistry(0x01)
        for epoch in range(1, 4):
            cfg = DKGSessionConfig(
                vm_tag=0x01, epoch=epoch, threshold=2,
                participants=list(PARTICIPANTS[:3]),
                timeout_rounds=20, start_round=0,
            )
            sessions = [
                DKGSession(cfg, fp, idx + 1)
                for idx, fp in enumerate(PARTICIPANTS[:3])
            ]
            # Quick ceremony
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
                fp = PARTICIPANTS[i]
                for j, shares in enumerate(all_shares):
                    if fp in shares:
                        s.receive_share(shares[fp])
                s.end_sharing_phase()
            result = sessions[0].finalize()
            reg.store(result)

        assert reg.epoch_count() == 3
        assert reg.current().epoch == 3
```

- [ ] **Step 2: Run tests**

Run: `pytest tests/test_dkg_e2e.py -v`
Expected: all PASS (or SKIPPED)

- [ ] **Step 3: Commit**

```bash
git add tests/test_dkg_e2e.py
git commit -m "test(dkg): add end-to-end ceremony tests — happy path, complaint resolution, registry"
```

---

### Task 8: Property-Based Tests

**Files:**
- Test: `tests/test_dkg_hypothesis.py`

- [ ] **Step 1: Write the tests**

Create `tests/test_dkg_hypothesis.py`:

```python
"""Hypothesis property-based tests for DKG subsystem (Spec C3b)."""

from __future__ import annotations

import pytest
from hypothesis import given, assume, settings
from hypothesis import strategies as st

from src.ltp.execution.committee.dkg.scalar_poly import ScalarField, ScalarPoly
from src.ltp.execution.committee.dkg.types import DKGPhase, DKGResult
from src.ltp.execution.committee.dkg.registry import DKGKeyRegistry


R = ScalarField.R

small_scalars = st.integers(min_value=1, max_value=R - 1)
poly_degrees = st.integers(min_value=0, max_value=5)


class TestScalarFieldProperties:

    @given(a=small_scalars, b=small_scalars)
    def test_add_commutative(self, a, b):
        assert ScalarField.add(a, b) == ScalarField.add(b, a)

    @given(a=small_scalars, b=small_scalars)
    def test_mul_commutative(self, a, b):
        assert ScalarField.mul(a, b) == ScalarField.mul(b, a)

    @given(a=small_scalars)
    def test_additive_inverse(self, a):
        assert ScalarField.add(a, ScalarField.neg(a)) == 0

    @given(a=small_scalars)
    @settings(max_examples=10)
    def test_multiplicative_inverse(self, a):
        assert ScalarField.mul(a, ScalarField.inv(a)) == 1

    @given(a=small_scalars, b=small_scalars, c=small_scalars)
    def test_distributive(self, a, b, c):
        lhs = ScalarField.mul(a, ScalarField.add(b, c))
        rhs = ScalarField.add(ScalarField.mul(a, b), ScalarField.mul(a, c))
        assert lhs == rhs


class TestScalarPolyProperties:

    @given(degree=poly_degrees)
    def test_random_poly_has_correct_length(self, degree):
        p = ScalarPoly.random(degree)
        assert len(p.coeffs) == degree + 1

    @given(degree=poly_degrees)
    def test_evaluate_at_zero_is_constant_term(self, degree):
        p = ScalarPoly.random(degree)
        assert p.evaluate(0) == p.coeffs[0]


class TestLagrangeReconstruction:

    @given(
        secret=st.integers(min_value=1, max_value=1000),
        n=st.integers(min_value=2, max_value=6),
        t=st.integers(min_value=2, max_value=6),
    )
    def test_reconstruction_with_t_shares(self, secret, n, t):
        """Any t shares from a degree-(t-1) polynomial reconstruct the secret."""
        assume(t <= n)
        coeffs = [secret] + [ScalarField.random() for _ in range(t - 1)]
        p = ScalarPoly(coeffs)
        all_indices = list(range(1, n + 1))
        shares = {i: p.evaluate(i) for i in all_indices}

        # Take the first t shares
        subset = all_indices[:t]
        reconstructed = 0
        for i in subset:
            li = ScalarPoly.lagrange_coefficient(i, subset)
            reconstructed = ScalarField.add(
                reconstructed, ScalarField.mul(shares[i], li),
            )
        assert reconstructed == secret


class TestDKGKeyRegistryProperties:

    @given(n=st.integers(min_value=1, max_value=20))
    def test_epoch_count_matches_stores(self, n):
        reg = DKGKeyRegistry(0x01)
        for epoch in range(1, n + 1):
            reg.store(DKGResult(
                vm_tag=0x01, epoch=epoch, group_pk=bytes([epoch % 256]) * 48,
                participant_vks={}, threshold=1,
                qual_set=frozenset(), phase=DKGPhase.EAGER,
            ))
        assert reg.epoch_count() == n

    @given(n=st.integers(min_value=1, max_value=20))
    def test_current_is_always_max_epoch(self, n):
        reg = DKGKeyRegistry(0x01)
        for epoch in range(1, n + 1):
            reg.store(DKGResult(
                vm_tag=0x01, epoch=epoch, group_pk=bytes([epoch % 256]) * 48,
                participant_vks={}, threshold=1,
                qual_set=frozenset(), phase=DKGPhase.EAGER,
            ))
        assert reg.current().epoch == n
```

- [ ] **Step 2: Run tests**

Run: `pytest tests/test_dkg_hypothesis.py -v`
Expected: all PASS

- [ ] **Step 3: Commit**

```bash
git add tests/test_dkg_hypothesis.py
git commit -m "test(dkg): add Hypothesis property-based tests for scalar field, Lagrange, and registry"
```

---

### Task 9: CommitteePolicy + Manager Integration

**Files:**
- Modify: `src/ltp/execution/committee/policy.py`
- Modify: `src/ltp/execution/committee/manager.py`
- Test: `tests/test_dkg_integration.py`

**Context:** Add 3 DKG fields to `CommitteePolicy` and extend `CommitteeManager` with DKG lifecycle. When `dkg_threshold == 0`, behavior is identical to C3a. This task requires `py_ecc` for tests that exercise the DKG path.

- [ ] **Step 1: Write the failing tests**

Create `tests/test_dkg_integration.py`:

```python
"""CommitteeManager + DKG integration tests (Spec C3b §8)."""

from __future__ import annotations

import pytest

from src.ltp.zk.ec_backend import bls12_381_available
from src.ltp.execution.committee.policy import CommitteePolicy, EpochStrategy
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


class TestPolicyDKGFields:

    def test_default_dkg_disabled(self):
        p = CommitteePolicy(vm_tag=0x01)
        assert p.dkg_threshold == 0
        assert p.dkg_timeout_rounds == 10
        assert p.dkg_eager_start_rounds == 5

    def test_dkg_enabled(self):
        p = CommitteePolicy(vm_tag=0x01, dkg_threshold=3)
        assert p.dkg_threshold == 3


class TestManagerDKGDisabled:

    def test_tick_without_dkg(self):
        """When dkg_threshold=0, tick behaves exactly as C3a."""
        reg = WriterRegistry()
        for i in range(1, 4):
            _enroll_active(reg, i)
        policy = CommitteePolicy(vm_tag=0x01, epoch_length=10, dkg_threshold=0)
        mgr = CommitteeManager(0x01, policy, reg, EmergencyState())
        assert mgr.tick(10, 1000) is True
        assert mgr.epoch == 1
        assert mgr.roster is not None
        assert not mgr.has_dkg_result(1)


class TestManagerDKGRegistry:

    def test_dkg_registry_exposed(self):
        """Manager exposes DKG registry for querying."""
        reg = WriterRegistry()
        for i in range(1, 4):
            _enroll_active(reg, i)
        policy = CommitteePolicy(vm_tag=0x01, epoch_length=10, dkg_threshold=0)
        mgr = CommitteeManager(0x01, policy, reg, EmergencyState())
        assert mgr.dkg_registry is not None
        assert mgr.dkg_registry.epoch_count() == 0


@pytest.mark.skipif(not bls12_381_available(), reason="py_ecc not installed")
class TestManagerDKGCeremony:

    def test_dkg_runs_on_epoch_advance(self):
        """When dkg_threshold > 0, epoch advance triggers DKG."""
        reg = WriterRegistry()
        for i in range(1, 4):
            _enroll_active(reg, i)
        policy = CommitteePolicy(
            vm_tag=0x01, epoch_length=10, dkg_threshold=2,
        )
        mgr = CommitteeManager(0x01, policy, reg, EmergencyState())
        mgr.tick(10, 1000)
        assert mgr.epoch == 1
        assert mgr.has_dkg_result(1)
        result = mgr.dkg_registry.get(1)
        assert result.threshold == 2
        assert len(result.group_pk) == 96

    def test_multiple_epochs_produce_different_keys(self):
        """Each epoch gets a fresh DKG — different group key."""
        reg = WriterRegistry()
        for i in range(1, 4):
            _enroll_active(reg, i)
        policy = CommitteePolicy(
            vm_tag=0x01, epoch_length=10, dkg_threshold=2,
        )
        mgr = CommitteeManager(0x01, policy, reg, EmergencyState())
        mgr.tick(10, 1000)
        mgr.tick(20, 2000)
        pk1 = mgr.dkg_registry.group_pk(1)
        pk2 = mgr.dkg_registry.group_pk(2)
        # Fresh randomness each time — overwhelmingly likely to differ
        assert pk1 != pk2
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_dkg_integration.py -v`
Expected: FAIL — `CommitteePolicy.__init__() got an unexpected keyword argument 'dkg_threshold'`

- [ ] **Step 3: Add DKG fields to CommitteePolicy**

In `src/ltp/execution/committee/policy.py`, add three fields to the `CommitteePolicy` dataclass, after the existing `force_exclude` field:

```python
    # --- DKG (Spec C3b) ---
    dkg_threshold: int = 0
    dkg_timeout_rounds: int = 10
    dkg_eager_start_rounds: int = 5
```

- [ ] **Step 4: Extend CommitteeManager**

In `src/ltp/execution/committee/manager.py`, add DKG imports, a `_dkg_registry` field, a `_run_dkg_ceremony` method, and modify `tick()` to run DKG after epoch advance. Replace the full file content:

```python
"""CommitteeManager — top-level coordinator (Spec C3a §9, C3b §8)."""

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

        # Phase 4: finalize (use first participant's result for group key)
        try:
            result = sessions[0].finalize()
            self._dkg_registry.store(result)
        except (ValueError, KeyError):
            pass  # DKG failed — epoch runs without threshold signing

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

- [ ] **Step 5: Run tests to verify they pass**

Run: `pytest tests/test_dkg_integration.py tests/test_committee_e2e.py tests/test_committee_manager.py -v`
Expected: all PASS — existing C3a tests still pass, new DKG integration tests pass

- [ ] **Step 6: Commit**

```bash
git add src/ltp/execution/committee/policy.py \
        src/ltp/execution/committee/manager.py \
        tests/test_dkg_integration.py
git commit -m "feat(dkg): integrate DKG into CommitteeManager with per-epoch ceremony on tick"
```

---

### Task 10: Package Exports and Full Regression

**Files:**
- Modify: `src/ltp/execution/committee/__init__.py`
- Modify: `src/ltp/execution/committee/dkg/__init__.py`
- Modify: `src/ltp/execution/__init__.py`

- [ ] **Step 1: Update `committee/dkg/__init__.py` to export all public symbols**

```python
"""Threshold Distributed Key Generation (Spec C3b)."""

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
]
```

Note: `PedersenVSS` and `DKGSession` are intentionally NOT exported at the top level — they require `py_ecc` at import time and would break environments without it. Consumers who need them import directly from `.vss` and `.session`.

- [ ] **Step 2: Update `committee/__init__.py` to re-export DKG types**

Add to the end of `src/ltp/execution/committee/__init__.py`:

```python
# DKG (Spec C3b)
from .dkg import (
    DKGState,
    DKGPhase,
    DKGCommitment,
    DKGShare,
    DKGComplaint,
    DKGResult,
    DKGSessionConfig,
    ScalarField,
    ScalarPoly,
    DKGTransport,
    FakeDKGTransport,
    DKGKeyRegistry,
)
```

And add to `__all__`:

```python
    # DKG (Spec C3b)
    "DKGState", "DKGPhase",
    "DKGCommitment", "DKGShare", "DKGComplaint",
    "DKGResult", "DKGSessionConfig",
    "ScalarField", "ScalarPoly",
    "DKGTransport", "FakeDKGTransport",
    "DKGKeyRegistry",
```

- [ ] **Step 3: Update `execution/__init__.py` to re-export DKG types**

Add to `src/ltp/execution/__init__.py`, after the committee imports:

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

And add to `__all__`:

```python
    # DKG (Spec C3b)
    "DKGState", "DKGPhase",
    "DKGCommitment", "DKGShare", "DKGComplaint",
    "DKGResult", "DKGSessionConfig",
    "ScalarField", "ScalarPoly",
    "DKGTransport", "FakeDKGTransport",
    "DKGKeyRegistry",
```

- [ ] **Step 4: Run full test suite**

Run: `pytest tests/ -v --tb=short`
Expected: all tests PASS (3,350+ existing tests + ~80 new DKG tests)

- [ ] **Step 5: Commit**

```bash
git add src/ltp/execution/committee/__init__.py \
        src/ltp/execution/committee/dkg/__init__.py \
        src/ltp/execution/__init__.py
git commit -m "feat(dkg): expose DKG types through committee and execution package __init__"
```
