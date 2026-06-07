# Gate 5 + Gate 6 Closure

**Date:** 2026-05-15
**Branch:** `corridor/wire-mirror` (PR #8)
**Status:** Closed at the in-process integration surface

## Scope

This doc records the conditions under which Gates 5 (Threshold BLS Signing) and 6 (Multi-Node Mysticeti Consensus) are considered closed for the purpose of opening the repo to outside developers.

Closure here means: a single end-to-end integration test demonstrates that the production code paths cooperate correctly, against the in-process simulator. It is **not** a claim that the protocol has been validated in a real multi-machine deployment — that is a separate gate (Transport, real libp2p) tracked in `docs/plans/2026-05-11-production-roadmap.md`.

## What Gate 5 covers

- `CommitteeManager.sign_as_committee(message, domain)` produces a 96-byte BLS12-381 aggregate signature.
- The signature verifies under `threshold_verify(group_pk, message, signature, domain)` against the group public key produced by the DKG ceremony for the same epoch.
- The threshold-signing scheme uses `BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_` (`BLS_CORRIDOR_DST`) — byte-for-byte matching the Rust reference at `suwappu-dag/crates/suwappu-crypto/src/bls.rs:24::BLS_DST`.

### Tests that prove Gate 5

| Test | What it asserts |
|---|---|
| `tests/test_threshold_signing_integration.py::test_sign_produces_valid_signature` | `sign_as_committee` returns a valid 96-byte signature under `DOMAIN_ATTESTATION` |
| `tests/test_threshold_signing_integration.py::test_verify_committee_signature` | The signature verifies under the same epoch's group PK |
| `tests/test_threshold_signing_integration.py::test_verify_rejects_tampered` | Verification fails on a tampered message |
| `tests/test_threshold_signing_integration.py::test_multiple_epochs_sign_verify` | Signatures from epoch N verify against epoch-N PK and only that PK |
| `tests/test_threshold_signing_integration.py::test_verify_with_explicit_epoch` | Cross-epoch verification works when the caller passes `epoch=` |
| `tests/test_threshold_signing_integration.py::test_sign_returns_none_when_dkg_disabled` | Pre-DKG, `sign_as_committee` returns `None` instead of failing silently |

## What Gate 6 covers

- `MysticetiAdapter` start/stop lifecycle wires together a real `LocalConsensusBackend`, a `ValidatorSet` built from the committee roster, a `BLSCertificateManager`, and `CommitteeSync`.
- The adapter drives Mysticeti-C consensus rounds over 4 in-process validators and produces deterministic `OrderedBatch` objects with `consensus_type="dag"`, monotonic `round`, and the correct `leader_authority` rotation.
- Byzantine fault injection (crash, equivocation, withhold, delay, censor, partition) is handled by the underlying engine and surfaces as bounded liveness loss, not safety violations.
- The adapter handles epoch transitions, validator eviction, and key rotation across epochs.

### Tests that prove Gate 6

| Test | What it asserts |
|---|---|
| `tests/test_consensus_adapter.py` (full file, ~18 cases) | MysticetiAdapter satisfies the `ConsensusAdapter` protocol; lifecycle, batch production, epoch transition, eviction, signing-key wiring |
| `tests/test_consensus_e2e.py::TestE2EFourValidators` | 4-validator end-to-end pipeline: submit → run rounds → collect ordered batches |
| `tests/test_consensus_e2e.py::TestE2ESevenValidators` | Same with 7 validators (higher fault tolerance) |
| `tests/test_consensus_e2e.py::TestE2EEdgeCases::test_large_batch_1000_txs` | 1,000 transactions through the pipeline without loss |
| `tests/test_consensus_e2e.py::TestAsyncMode` | Async mode: engine runs on a background thread, commits stream out |
| `tests/test_consensus_byzantine.py` | Equivocation / crash / withhold / delay / censor / partition fault tests |
| `tests/test_node_executor.py` | `NodeExecutor` integrates `MysticetiAdapter` with the execution pipeline |

## Combined closure test

`tests/test_gate_5_6_closure.py` is the explicit, single test that proves Gate 5 and Gate 6 cooperate end-to-end:

1. Build a 4-validator committee roster.
2. Run a full DKG ceremony to produce `ThresholdSigningKey` objects and the group public key.
3. Spin up `MysticetiAdapter` with the keys, submit transactions, and drive rounds.
4. Take the committed `OrderedBatch`, compute its canonical SHA3-256 digest (matching `MysticetiAdapter._serialize_batch`), and call the committee's `sign_as_committee` over it.
5. Wrap the result in a `CorridorAttestation` (with a corridor `AttestationPayload` describing the batch's source/target/height/state-root/timestamp).
6. Round-trip the attestation through the JSON wire format (`corridor_attestation_to_dict` ↔ `corridor_attestation_from_dict`).
7. Assert `threshold_verify` is green on the deserialized aggregate signature.
8. Negative path: flip a single byte in the aggregate signature, roundtrip again, assert verification fails.

This test is the single "outside dev can trust the closure" proof. It depends only on the production code paths — no test-only adapters or short-circuits.

## What this does NOT cover (intentionally deferred)

The following are out of scope for Gates 5 and 6 closure and tracked in `docs/plans/2026-05-11-production-roadmap.md`:

| Deferral | Why |
|---|---|
| **Real libp2p P2P transport** | `InMemoryFederationTransport` and `FakeDKGTransport` are used. Real libp2p with ML-KEM-encrypted share channels is a separate gate (Transport / D2). |
| **Live multi-machine deploy** | All validators run in a single Python process. Standing up a 3-node Docker / K8s testnet is a separate operations track. |
| **On-chain submission against a live testnet** | The closure test stops at "aggregate signature verifies"; submitting the resulting attestation to `LTPAnchorRegistry` on Base Sepolia is covered by `tests/test_contract_integration.py` against local anvil and by the deployed contracts at `docs/DEPLOYED_CONTRACTS.md`. |
| **Real EVM / Move execution backends** | `EVMExecutor` and `MoveExecutor` are still stubs. Wiring them to real geth/reth/Aptos/Sui is a separate gate (Execution / E1-E3). |
| **DID / identity layer** | Zero implementation. The archived `docs/plans/archive/did-expansion-plan.md` captures the design rationale; implementation is a separate track. |

## How to verify locally

```bash
cd ~/suwappu-build/suwappu-lattice-protocol

# The single closure test
pytest tests/test_gate_5_6_closure.py -v

# Gate 5 surface
pytest tests/test_threshold_signing_integration.py -v

# Gate 6 surface
pytest tests/test_consensus_adapter.py tests/test_consensus_e2e.py tests/test_consensus_byzantine.py -v

# Cross-language BLS DST parity (sanity)
grep -n BLS_CORRIDOR_DST src/ltp/corridor/constants.py
grep -n BLS_DST ../suwappu-dag/crates/suwappu-crypto/src/bls.rs
```

## Next gates

- **Gate 7 — Transport.** Replace `InMemoryFederationTransport` and `FakeDKGTransport` with real libp2p over ML-KEM-encrypted channels. Spin up 3 nodes across separate hosts. Run DKG and a consensus round against real P2P latency.
- **Gate 8 — Execution.** Decide on EVM client (reth vs geth) and Move variant (Aptos vs Sui). Wire `EVMExecutor` / `MoveExecutor` to real backends. Run a Base Sepolia L1 → L2 bridge transfer end-to-end.
- **Gate 9 — Production hardening.** Real HSM (PKCS#11 or cloud KMS), real cloud queue/scheduler/orchestrator backends, fuzzing harness, Certora contract proofs.
