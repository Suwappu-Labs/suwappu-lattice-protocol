# Spec C3b: Threshold Distributed Key Generation

**Goal:** Add Pedersen DKG to ETP committees so each epoch produces a BLS12-381 group public key and per-participant secret shares, enabling threshold signature capability.

**Depends on:** Spec C3a (Committee Formation + Epoch Management) — fully implemented.

---

## 1. Architecture

C3b lives as a nested subpackage under the existing committee module:

```
src/ltp/execution/committee/dkg/
    __init__.py        # public API surface
    types.py           # DKGState, DKGPhase, DKGCommitment, DKGShare, DKGComplaint, DKGResult, DKGSessionConfig
    scalar_poly.py     # ScalarField arithmetic + ScalarPoly over BLS12-381 Z_r
    vss.py             # PedersenVSS — dual commitments, share creation, share verification
    session.py         # DKGSession state machine — orchestrates the full ceremony
    transport.py       # DKGTransport Protocol + FakeDKGTransport
    registry.py        # DKGKeyRegistry — per-VM, per-epoch group key store
```

**Two independent G1 generators:**

- `g` — standard BLS12-381 G1 generator (well-known, fixed)
- `h` — `hash_to_curve("ETP-PEDERSEN-DKG-H")` — provably unknown discrete log relation to `g`, required for Pedersen commitments to be information-theoretically hiding

**Protocol:** Pedersen DKG (Pedersen 1991 + Gennaro et al. 1999). Each dealer commits to two polynomials with dual commitments, preventing any single dealer from biasing the group public key.

---

## 2. Core Types (`types.py`)

### DKGState (enum, 8 values)

```
IDLE, COMMITTING, SHARING, VERIFYING, COMPLAINING, FINALIZING, COMPLETED, FAILED
```

State transition path:
```
IDLE → COMMITTING → SHARING → VERIFYING → COMPLAINING → FINALIZING → COMPLETED
                                                                   ↘ FAILED
Any state → FAILED (on timeout or unrecoverable error)
```

### DKGPhase (enum, 2 values)

```
EAGER    — pre-epoch DKG attempt (started before epoch boundary)
INLINE   — fallback DKG after epoch has begun (if eager failed)
```

### DKGCommitment (frozen dataclass)

| Field | Type | Description |
|-------|------|-------------|
| `dealer_fp` | `bytes` | Fingerprint of the dealer who generated this commitment |
| `feldman_commitments` | `list[bytes]` | `coeffs[k] * G` for each coefficient — G1 points (48 bytes each) |
| `pedersen_commitments` | `list[bytes]` | `coeffs[k] * G + blinding[k] * H` — G1 points (48 bytes each) |
| `round_id` | `int` | Consensus round when commitment was published |

### DKGShare (frozen dataclass)

| Field | Type | Description |
|-------|------|-------------|
| `dealer_fp` | `bytes` | Fingerprint of the dealer |
| `recipient_fp` | `bytes` | Fingerprint of the intended recipient |
| `share` | `int` | `secret_poly(recipient_index)` — scalar field element |
| `blinding_share` | `int` | `blinding_poly(recipient_index)` — scalar field element |

Private, sent P2P (encrypted by transport layer).

### DKGComplaint (frozen dataclass)

| Field | Type | Description |
|-------|------|-------------|
| `complainant_fp` | `bytes` | Who is complaining |
| `dealer_fp` | `bytes` | Who is being accused |
| `revealed_share` | `int` | The share the complainant received |
| `revealed_blinding` | `int` | The blinding share the complainant received |
| `round_id` | `int` | Consensus round when complaint was published |

Public, broadcast through consensus for resolution.

### DKGResult (frozen dataclass)

| Field | Type | Description |
|-------|------|-------------|
| `vm_tag` | `int` | VM this ceremony was for |
| `epoch` | `int` | Epoch number |
| `group_pk` | `bytes` | 48-byte BLS12-381 G1 point — the group public key |
| `participant_vks` | `dict[bytes, bytes]` | `fingerprint → verification_key` (G1 points) |
| `threshold` | `int` | `t` in the t-of-n scheme |
| `qual_set` | `frozenset[bytes]` | Fingerprints of qualified dealers |
| `phase` | `DKGPhase` | Whether this came from an EAGER or INLINE attempt |

### DKGSessionConfig (dataclass)

| Field | Type | Description |
|-------|------|-------------|
| `vm_tag` | `int` | Target VM |
| `epoch` | `int` | Target epoch |
| `threshold` | `int` | `t` — minimum shares for reconstruction |
| `participants` | `list[bytes]` | Ordered list of participant fingerprints |
| `timeout_rounds` | `int` | Max consensus rounds before ceremony fails |
| `start_round` | `int` | Consensus round when ceremony began (for timeout calculation) |

---

## 3. Scalar Field Polynomial (`scalar_poly.py`)

BLS12-381 scalar field order:
```
r = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
```

This is ~2^255, different from the Goldilocks field in `src/ltp/zk/field.py` (2^64 - 2^32 + 1). Dedicated module required.

### ScalarField (static utility)

| Method | Signature | Description |
|--------|-----------|-------------|
| `add` | `(a: int, b: int) -> int` | `(a + b) % R` |
| `mul` | `(a: int, b: int) -> int` | `(a * b) % R` |
| `inv` | `(a: int) -> int` | Modular inverse via `pow(a, R-2, R)` |
| `neg` | `(a: int) -> int` | `(-a) % R` |
| `random` | `() -> int` | `secrets.randbelow(R - 1) + 1` (never zero) |

### ScalarPoly (polynomial over Z_r)

| Method | Signature | Description |
|--------|-----------|-------------|
| `__init__` | `(coeffs: list[int])` | `coeffs[0]` = constant term (the secret) |
| `random` | `(degree: int) -> ScalarPoly` | Random polynomial with `degree+1` coefficients |
| `evaluate` | `(x: int) -> int` | Horner's method, all arithmetic mod R |
| `lagrange_coefficient` | `(i: int, participants: list[int]) -> int` | Lagrange basis at x=0, for threshold reconstruction |

Design: pure Python, no external deps. All arithmetic is `int % R`. Randomness uses `secrets` module.

---

## 4. Pedersen VSS (`vss.py`)

### Generators

- `G` — BLS12-381 standard G1 generator
- `H` — `hash_to_curve("ETP-PEDERSEN-DKG-H")`, computed once at import time

### PedersenVSS (stateless utility)

| Method | Signature | Description |
|--------|-----------|-------------|
| `generate_commitments` | `(secret_poly, blinding_poly) -> (list[bytes], list[bytes])` | Feldman: `s_k * G`, Pedersen: `s_k * G + b_k * H` for each coefficient |
| `create_share` | `(secret_poly, blinding_poly, recipient_index) -> (int, int)` | Evaluate both polynomials at `recipient_index` (1-based) |
| `verify_share` | `(recipient_index, share, blinding_share, pedersen_commitments) -> bool` | Check: `share * G + blinding_share * H == Σ(commitment_k * index^k)` |

Both polynomials must have the same degree (t-1). Feldman commitments are used for group public key derivation (`group_pk = Σ feldman_0` across QUAL dealers). Pedersen commitments are used for share verification. All commitments are 48-byte compressed G1 points.

---

## 5. DKG Session State Machine (`session.py`)

### DKGSession (mutable, one per ceremony)

**Constructor:** `DKGSession(config: DKGSessionConfig, my_fp: bytes, my_index: int)`

**Internal state:**
- `_secret_poly`, `_blinding_poly` — this participant's contribution
- `_commitments: dict[bytes, DKGCommitment]` — collected from all dealers
- `_shares: dict[bytes, DKGShare]` — shares received from other dealers
- `_complaints: list[DKGComplaint]` — filed complaints
- `_qual: set[bytes]` — qualified dealer set (survives complaint phase)

**Phase transitions:**

| Method | Transition | Returns |
|--------|-----------|---------|
| `begin()` | IDLE → COMMITTING | `(DKGCommitment, dict[bytes, DKGShare])` — my commitment (broadcast) + per-recipient shares (P2P) |
| `receive_commitment(c)` | during COMMITTING | None |
| `end_commitment_phase()` | COMMITTING → SHARING | None |
| `receive_share(s)` | during SHARING | None |
| `end_sharing_phase()` | SHARING → VERIFYING → COMPLAINING | `list[DKGComplaint]` — complaints for invalid shares |
| `receive_complaint(c)` | during COMPLAINING | None |
| `finalize()` | COMPLAINING → FINALIZING → COMPLETED | `DKGResult` |
| `abort(reason)` | Any → FAILED | None |
| `check_timeout(round)` | Any → FAILED if expired | `bool` |

**Complaint resolution:** When a complaint is filed, the dealer's share and blinding share are revealed publicly. All participants verify against the dealer's Pedersen commitments. If the revealed share matches commitments, complaint is invalid (complainant dishonest). If it doesn't match, dealer is excluded from QUAL.

**QUAL set:** Set of qualified dealers. Threshold scheme works as long as `|QUAL| >= t`. If `|QUAL| < t`, ceremony fails.

**Final key derivation:**
- `group_pk = Σ feldman_commitments[0]` across all QUAL dealers
- `my_secret_share = Σ shares[dealer]` across all QUAL dealers
- `participant_vk[i] = my_secret_share * G`

No session reuse — if eager attempt fails, a new `DKGSession` is created for inline fallback.

---

## 6. DKG Transport (`transport.py`)

### DKGTransport (Protocol)

| Method | Channel | Description |
|--------|---------|-------------|
| `broadcast_commitment(c)` | Consensus (public) | Ordered, auditable commitment publication |
| `broadcast_complaint(c)` | Consensus (public) | Ordered, auditable complaint publication |
| `send_share(recipient_fp, s)` | P2P (private) | Encrypted point-to-point share delivery |
| `receive_commitments()` | Consensus | Collect all published commitments |
| `receive_shares()` | P2P | Collect shares sent to this participant |
| `receive_complaints()` | Consensus | Collect all published complaints |

### FakeDKGTransport (in-memory, for testing)

All participants share the same instance. Commitments and complaints stored in lists, shares keyed by recipient fingerprint. Synchronous, no networking. Mirrors `FakeConsensusAdapter` pattern.

Share encryption is a transport-layer concern — `DKGSession` produces plaintext `DKGShare` objects; real transport encrypts with recipient's ML-KEM public key. Production transport implementation (libp2p/gRPC) is deferred.

---

## 7. DKG Key Registry (`registry.py`)

### DKGKeyRegistry (per-VM key store)

| Method | Signature | Description |
|--------|-----------|-------------|
| `__init__` | `(vm_tag: int)` | One registry per VM |
| `store(result)` | `(DKGResult) -> None` | Append-only. Raises if epoch already exists or vm_tag mismatch |
| `get(epoch)` | `(int) -> DKGResult` | Raises `KeyError` if missing |
| `current()` | `() -> Optional[DKGResult]` | Highest-epoch result, or None |
| `group_pk(epoch)` | `(int) -> bytes` | Convenience: 48-byte group public key |
| `has_epoch(epoch)` | `(int) -> bool` | Check existence |
| `epoch_count()` | `() -> int` | Number of stored results |

Append-only, immutable values (`DKGResult` is frozen). Mirrors `PolicySnapshotStore` pattern but simpler (no rollback — DKG results are final).

---

## 8. CommitteeManager Integration

### New CommitteePolicy fields

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `dkg_threshold` | `int` | `0` | `0` = DKG disabled; `>0` = t-of-n threshold |
| `dkg_timeout_rounds` | `int` | `10` | Rounds before ceremony times out |
| `dkg_eager_start_rounds` | `int` | `5` | Rounds before epoch boundary to start eager DKG |

When `dkg_threshold == 0`, no DKG runs. Existing C3a behavior fully preserved.

### CommitteeManager changes

New fields: `_dkg_registry: DKGKeyRegistry`, `_active_dkg: Optional[DKGSession]`, `_dkg_phase: DKGPhase`

**Extended `tick()` logic:**

1. If DKG is active, drive it (feed messages, check timeout)
2. If approaching epoch boundary and no DKG started, begin eager DKG
3. If epoch advances and eager DKG completed, store result
4. If epoch advances and eager DKG failed/not started, begin inline DKG
5. Original epoch advance logic unchanged

**Eager-with-fallback flow:**

```
Epoch N, round R approaching boundary
  │
  ├─ R == (boundary - dkg_eager_start_rounds)
  │   └─ Start eager DKG for epoch N+1 using next roster
  │
  ├─ Eager DKG completes before boundary
  │   └─ Store result in DKGKeyRegistry for epoch N+1
  │
  ├─ Epoch N+1 begins
  │   ├─ DKG result exists → committee has threshold signing
  │   └─ No result (eager failed/timed out)
  │       └─ Start inline DKG for epoch N+1 using current roster
  │           ├─ Completes → store result, committee gains signing
  │           └─ Fails → epoch runs without threshold signing
```

**Untouched modules:** `CommitteeFormation`, `EvictionHandler`, `EpochManager`, `StandbySelector` — DKG is layered on top, not woven into existing logic.

---

## 9. Design Decisions Summary

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Trust model | Configurable t-of-n per VM | Different VMs have different security needs |
| Protocol | Pedersen DKG (dual-commitment) | Bias-resistant — no dealer can influence group key |
| Transport | Hybrid (consensus + P2P) | Commitments need ordering; shares need privacy |
| Timing | Eager-with-fallback | Minimizes epoch-start latency; graceful degradation |
| Key lifecycle | Fresh DKG per epoch + registry | Clean security boundary; no resharing complexity |
| Scalar field | Dedicated module over Z_r | BLS field differs from Goldilocks; can't reuse zk/field.py |
| Generators | `g` standard, `h` hash-to-curve | Provably independent — required for Pedersen security |
