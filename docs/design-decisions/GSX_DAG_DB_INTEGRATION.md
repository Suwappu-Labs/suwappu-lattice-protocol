# GSX DAG and GSX-DB Integration

This note keeps the Lattice Transfer Protocol repository aligned with the
current GSX stack:

- `gsx-lattice-protocol` owns COMMIT/LATTICE/MATERIALIZE, lattice keys,
  commitment logs, gateway flows, federation, and `LTPAnchorRegistry`.
- `gsx-dag` owns the Mysticeti-style certificate DAG, validator rings,
  block ordering, LTP corridor attestation, and execution wiring.
- `gsx-db` owns the state substrate: canonical `BalanceSlot`s, dual EVM/Move
  projections, OCC block execution, state tree roots, anchor dispatch, recovery
  replay, and L2 sync.

## Boundary

LTP does not embed the GSX-DB runtime. The integration boundary is the anchor
and attestation surface:

1. `gsx-dag` linearizes ordered blocks through the certificate DAG.
2. `gsx-execution` applies those ordered intents against `gsx-db`.
3. `gsx-db` computes the canonical state root and emits per-chain anchors.
4. LTP corridor super-nodes attest, submit, and verify those anchors through
   `LTPAnchorRegistry`.
5. Receivers materialize committed snapshots or deltas with lattice keys.

This preserves LTP's role as the transfer and attestation layer while keeping
state mutation inside GSX-DB's capability-gated Rust substrate.

## Assessment Boundary

For FedRAMP High readiness, this repository's assessment boundary stops at
LTP-owned transfer, attestation, gateway, compliance, and anchor-registry
controls. It can provide evidence that LTP receives, verifies, anchors, and
materializes committed state roots, but it cannot provide direct evidence for
GSX-DAG validator ordering or GSX-DB state mutation.

Cross-repo claims must be written as explicit dependencies:

- `gsx-lattice-protocol` provides the LTP evidence package, gateway preflight,
  audit schema, contracts, and transfer tests.
- `gsx-dag` provides ordering, validator consensus, LTP corridor attestation,
  and execution-adapter evidence.
- `gsx-db` provides state mutation, state root construction, recovery, sync,
  lane separation, and cross-parity evidence.

Release reports must pin exact commits or tags for all three repositories.

## Wire-Compatible Surfaces

`src/ltp/corridor/` is the Python mirror of `gsx-dag/crates/gsx-ltp`. Digests
produced by the Python module are byte-exact reproductions of the Rust digests
so a Python corridor witness can interoperate with the DAG L1 attestation
pipeline.

| Concern | Rust source | Python mirror |
|---|---|---|
| Corridor attestation (7-of-9) | `gsx-dag/crates/gsx-ltp/src/attestation.rs` | `src/ltp/corridor/attestation.py` |
| Commitment-Node DA SLA | `gsx-dag/crates/gsx-ltp/src/da.rs` | `src/ltp/corridor/da.py` |
| Cross-chain DID rotation statement | `gsx-dag/crates/gsx-ltp/src/did_stark.rs` | `src/ltp/corridor/did_stark.py` |
| Length-prefixed SHA3-256 domain hash | `gsx-dag/crates/gsx-crypto/src/hash.rs::sha3_256_domain` | `src/ltp/corridor/digest.py::sha3_256_domain` |
| Quorum + commitment-size constants | `gsx-dag/crates/gsx-ltp/src/lib.rs` | `src/ltp/corridor/constants.py` |
| Per-chain state anchor (Rust BLAKE3) | `gsx-db/crates/gsxdb-bridge/src/anchor/types.rs` | `src/ltp/corridor/state_anchor.py::hash_anchor_blake3` |
| Per-chain state anchor (Solidity placeholder) | `gsx-db/contracts/src/LTPAnchorRegistry.sol` | `src/ltp/corridor/state_anchor.py::hash_anchor_keccak256` |

### Two `LTPAnchorRegistry` contracts — disambiguation

The name `LTPAnchorRegistry` appears on two distinct contracts. They are not
interchangeable:

| Contract | Schema | Scope |
|---|---|---|
| `gsx-lattice-protocol/contracts/src/LTPAnchorRegistry.sol` | `(anchorDigest, entityIdHash, merkleRoot, policyHash, signerVkHash, sequence, validUntil, receiptType)` | Per-entity commitment-log anchor for LTP entities |
| `gsx-db/contracts/src/LTPAnchorRegistry.sol` | `(chainId, height, stateRoot, parent, mac)` | Per-chain state-root anchor that gsx-db emits |

`src/ltp/corridor/state_anchor.py` mirrors the **gsx-db** schema so an LTP
corridor witness can construct the same anchor bytes that gsx-db's Rust crate
and the Solidity contract operate on. The MAC field is `BLAKE3-keyed` in the
Rust canonical path; Solidity uses `keccak256` as a phase-1 placeholder
pending the gsx-db S11 BLAKE3-precompile sprint. The Rust hash also folds in
`auth_scheme`; the Solidity hash does not — `tests/corridor/test_state_anchor_parity.py::test_auth_scheme_invisible_to_solidity_hash`
pins this divergence so it cannot regress silently.

The constants `ON_CHAIN_COMMITMENT_BYTES = 1_600`,
`LTP_ATTESTATION_QUORUM_THRESHOLD = 7`, and
`LTP_ATTESTATION_QUORUM_SIZE = 9` are pinned on both sides; the parity tests
in `tests/corridor/test_digest_parity.py` lock the canonical digest hex
strings against the Rust reference.

### BLS DST decision

LTP's general-purpose `src/ltp/bls.py::BLS` signs under py_ecc's
`G2ProofOfPossession` ciphersuite (DST
`BLS_SIG_BLS12381G2_XMD:SHA-256_POP_`). The cross-repo corridor surface in
`gsx-dag/crates/gsx-crypto/src/bls.rs` signs under
`BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_`. Signatures under one DST do not
verify under the other.

To preserve both surfaces, `src/ltp/corridor/bls.py` exposes a narrow
`corridor_sign` / `corridor_verify` / `corridor_aggregate_*` shim keyed to
`BLS_CORRIDOR_DST` (the `_NUL_` DST). The `corridor.attestation` pipeline
routes through this shim; existing `AttestationEngine`, threshold-signing,
and DKG code continues to use `ltp.bls.BLS` and its `G2ProofOfPossession`
DST unchanged.

## Source Paths

| Concern | Repository | Source path |
|---|---|---|
| LTP anchor registry | `gsx-lattice-protocol` | `contracts/src/LTPAnchorRegistry.sol` |
| LTP transfer lifecycle | `gsx-lattice-protocol` | `src/ltp/protocol.py` |
| LTP gateway VM | `gsx-lattice-protocol` | `src/ltp/gateway_vm/` |
| DAG L1 LTP corridor | `gsx-dag` | `crates/gsx-ltp/` |
| DAG execution adapter | `gsx-dag` | `crates/gsx-execution/` |
| GSX-DB state substrate | `gsx-db` | `crates/gsxdb-state/` |
| GSX-DB capability gate | `gsx-db` | `crates/gsxdb-bridge/` |
| GSX-DB untrusted lane | `gsx-db` | `crates/gsxdb-lane/` |
| GSX-DB L2 sync | `gsx-db` | `crates/gsxdb-bridge/src/sync/` |

## State Synchronization

In LTP terms, state synchronization means exchanging a lattice key for a
committed state snapshot or delta. In the GSX stack, the state being committed
is the GSX-DB state root produced after DAG ordering. That gives the flow one
canonical direction:

```text
GSX-DAG ordered block
  -> gsx-db block execution
  -> gsx-db state root / anchor
  -> LTP corridor attestation
  -> lattice-key materialization of snapshot or delta
```

The reverse direction is deliberately not allowed: a lattice key can authorize
materialization, but it cannot mutate GSX-DB state. State mutation must pass
through `gsxdb-bridge` and its `BridgeToken` gate.

## Verification Trail

The companion repositories carry the current hardening checks:

- `gsx-dag`: `cargo test --workspace`
- `gsx-dag`: `PROPTEST_CASES=10000 cargo test --workspace --release`
- `gsx-db`: `cargo test --workspace`
- `gsx-db`: `PROPTEST_CASES=10000 cargo test --workspace --release`
- `gsx-db`: `scripts/check-lane-separation.sh`
- `gsx-db`: `scripts/cross-parity.sh`

LTP tests remain focused on transfer correctness, anchor registry behavior,
gateway/federation flows, and Python/Solidity parity. Cross-repo claims should
cite the repository and source path above rather than duplicating GSX-DB
internals here.

## Government Readiness Evidence

The FedRAMP High readiness package for this repo lives under
`docs/compliance/fedramp-high/`. For cross-repo release evidence, attach:

- `gsx-lattice-protocol`: pytest, Foundry, simulator, SBOM, dependency scan,
  Semgrep, signed artifacts, provenance, and POA&M.
- `gsx-dag`: `cargo test --workspace` plus the 10k release property-test run.
- `gsx-db`: `cargo test --workspace`, lane separation, cross parity, and the
  10k release property-test run.

DKG and threshold-signing evidence belongs in the key ceremony and signer
accountability story. The evidence set should include quorum signing, subset
independence, key finalization, complaint handling, and verification tests from
the relevant LTP and DAG components.
