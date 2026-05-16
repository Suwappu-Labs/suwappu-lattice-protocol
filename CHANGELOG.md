# Changelog

All notable changes to the Entanglement Transfer Protocol will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Breaking changes are marked **[BREAKING]** inline. See
[`docs/STABILITY_PROMISES.md`](docs/STABILITY_PROMISES.md) for the
public-surface promise and the cross-version compatibility matrix.

## [Unreleased]

### Added
- Repository governance baseline: `CODE_OF_CONDUCT.md` (Contributor Covenant 2.1),
  `.github/CODEOWNERS` (per-area required reviewers), `.github/FUNDING.yml`
- `pyproject.toml` metadata: PEP 621 keywords, classifiers, and `[project.urls]`
- Persona-based docs landing under `docs/personas/` (dApp developer, node
  operator, cryptographer, compliance auditor, contributor)
- Auto-generated Python API reference via `pdoc` — `make docs-api` target
- Cross-version compatibility matrix in `docs/STABILITY_PROMISES.md`
- Security hardening: LTP-A-001 (Option E + Slither/Echidna/Foundry-invariant
  suite), LTP-A-005 (Option C-3 owner-signed binding + on-chain dispute),
  LTP-A-006 (Option E independent arbiter + time-decay paths),
  LTP-A-014 (KyberSlash audit — confirmed-OK + pin tightened),
  LTP-A-022 (cross-language BLS DST pinning — confirmed-OK)

### Changed
- `CHANGELOG.md` entries now flag breaking changes inline with `**[BREAKING]**`

### Known issues
- LICENSE discrepancy: repo file declares Elastic 2.0 while `pyproject.toml`
  declares MIT — resolution pending in Linear GLO-785

## [5.0.0] - 2026-03-25

### Added
- LTPAnchorRegistry v5 deployed on GSX Testnet (Chain ID `103115120`)
  - UUPS Proxy: `0xB29d8BFF4973D1D7bcB10E32112EBB8fdd530bF4`
  - Implementation: `0xADf01df5B6Bef8e37d253571ab6e21177aCb7796`
  - MultiSig (2-of-2): `0x0106A79e9236009a05742B3fB1e3B7a52F44373D`
  - Timelock (60s): `0x7C2665F7e68FE635ee8F10aa0130AEBC603a9Db8`
- Author attribution in contract `version()` return

### Changed
- **[BREAKING]** Contract version bumped from 4 to 5 — clients pinned to
  `version() == 4` will reject; update version checks before upgrading
- All 84 Solidity tests passing with v5 assertions
- Full end-to-end PQC pipeline verified before deployment

## [4.0.0] - 2026-03-25

### Added
- Verified production deployment on GSX Testnet (block 687137)
- 84 Solidity tests: unit, integration, fuzz (256 iterations), invariant (3,840 calls), cross-parity
- `FormalVerification.t.sol` — fuzz testing + invariant testing
- `CrossParityTest` — Python ↔ Solidity state machine validation
- `DeployMainnet.s.sol` — configurable N-of-M + timelock for production
- `UpgradeV4.s.sol` — 4-step governance-controlled UUPS upgrade script

### Changed
- Test suite expanded from 821 to 1,251+ (1,167 Python + 84 Solidity)
- All four pillars verified end-to-end before on-chain deployment

## [3.2.0] - 2026-03-24

### Added
- TimelockController governance (OpenZeppelin) between MultiSig and Registry
- Governance chain: MultiSig → Timelock (60s) → Registry

### Changed
- **[BREAKING]** Registry admin transferred from MultiSig to Timelock —
  governance scripts that called the registry directly through the
  MultiSig must now route through the Timelock with a queued + executed
  pattern. See `OPERATOR_RUNBOOK.md` §"Governance Operations"
- 60-second delay on testnet (production: 24-48 hours)

## [3.1.0] - 2026-03-23

### Added
- **Smart Contracts:**
  - `LTPAnchorRegistry.sol` — on-chain anchor registry with UUPS proxy pattern
  - `LTPMultiSig.sol` — N-of-M multi-signature governance wallet
  - `ILTPAnchorRegistry.sol` — registry interface with events and errors
  - `Deploy.s.sol`, `DeployTestnet.s.sol` — deployment scripts
  - `contracts.yml` CI workflow — 3-stage pipeline (forge → pytest → integration)
  - Initial GSX Testnet deployment (Chain ID `103115120`)
- **New Python modules (40+):**
  - `src/ltp/anchor/` — EntityState machine, AnchorSubmission, AnchorClient with circuit breaker
  - `src/ltp/dual_lane/` — SHA3-256 canonical + BLAKE3-256 internal lane separation
  - `src/ltp/merkle_log/` — RFC 6962 Merkle tree, signed tree heads, inclusion/consistency proofs
  - `src/ltp/network/` — gRPC client/server with 7 RPCs, RemoteNode proxy
  - `src/ltp/storage/` — Memory, SQLite (WAL mode), Filesystem shard stores
  - `src/ltp/verify/` — Pure verification SDK (no state, no side effects)
  - `domain.py` — 11 domain separation tags (`GSX-LTP:*`)
  - `encoding.py` — Deterministic canonical binary serialization
  - `envelope.py` — ML-DSA-65 signed envelope wrapper
  - `receipt.py` — Approval receipts with RFC 8392 temporal semantics
  - `sequencing.py` — Per-signer monotonic sequence tracking
  - `governance.py` — SignerPolicy, ApprovalRule framework
  - `evidence.py` — Self-contained trust artifact bundles
  - `hybrid.py` — ML-DSA-65 + Ed25519-SHA512 composite signatures
  - `entity.py` — Entity model with `canonicalize_shape()` media type normalization
  - `run_trust_layer.py` — Full demo entry point covering all trust layer features

### Changed
- **[BREAKING]** Dual-lane architecture enforced: SHA3-256 for settlement,
  BLAKE3-256 for internal only — anchors signed under the wrong lane are
  rejected on-chain; clients mixing lanes must migrate to SHA3-256 for
  the settlement path
- **[BREAKING]** Real PQ crypto active (`_USE_REAL_KEM`, `_USE_REAL_DSA`,
  `_USE_REAL_AEAD` all `True`) — the previous in-tree stub crypto is no
  longer accepted at runtime; deploys must install `pqcrypto` + `pynacl`
  via `pip install -e '.[production]'`
- Python test count from 821 to 1,167 across 38 test files
- Module count from ~35 to 60+ across 8 subpackages

## [3.0.0] - 2026-03-13

### Added
- Pluggable commitment backends (Local, Monad L1, Ethereum L2) with factory pattern
- Cross-chain bridge protocol (L1Anchor, Relayer, L2Materializer) with replay protection
- Cross-deployment federation with three-tier trust model (UNTRUSTED/VERIFIED/FEDERATED)
- Chunked streaming protocol with backpressure and pipelined distribution
- ZK transfer mode with Poseidon hiding commitments and simulated Groth16 proofs
- Economics engine with staking, rewards, progressive slashing, and correlation penalties
- Enforcement pipeline with PDP storage proofs, programmable slashing, VDF-enhanced audits
- Compliance framework with 9 control families and automated evidence collection
- HSM interface for hardware-backed key management
- Merkle log with append-only hash chain and signed tree heads
- Configurable security levels (Standard, Enhanced, Maximum, Post-Quantum, Custom)

### Changed
- Test suite expanded from 160 to 821 tests across 19 test files
- **[BREAKING]** Commitment records now store Merkle root of encrypted
  shard hashes — plaintext shard IDs no longer appear in the log; clients
  that indexed by shard ID must migrate to root-based lookup
- **[BREAKING]** Lattice key reduced from ~869 bytes to ~160 bytes
  (Option C: encrypted shards + derivable metadata) — pre-v3 lattice keys
  are not parseable by the v3 SDK; re-issue keys before upgrading

## [2.0.0] - 2026-02-24

### Added
- Option C security model: shard encryption with random CEK + sealed envelope
- Post-quantum cryptographic primitives (ML-KEM-768, ML-DSA-65)
- Formal security proofs for 7 theorems (TSEC, SINT, IMM, TRECON, TCONF, TNREP, TLINK)
- Security review and attack chain analysis (001-lattice-key-shard-exposure)

### Changed
- **[BREAKING]** Lattice key sealed via ML-KEM-768 envelope encryption —
  replaces the v1 plaintext JSON lattice key format entirely; v1 keys
  cannot be loaded by v2
- **[BREAKING]** Commitment nodes store AEAD-encrypted ciphertext —
  nodes cannot read shard content; any operator monitoring that depended
  on plaintext shard inspection must migrate to ciphertext metadata
- **[BREAKING]** Commitment log stores Merkle root only — individual
  shard IDs removed from the log; off-chain indexers must rebuild from
  the root + per-entity proofs

## [1.0.0] - 2026-02-01

### Added
- Initial COMMIT / LATTICE / MATERIALIZE three-phase protocol
- Erasure coding (Reed-Solomon over GF(256)) with k-of-n reconstruction
- Content-addressed entity identity via BLAKE2b hashing
- Append-only commitment log with hash-chain integrity
- Commitment network with consistent-hash shard placement
- Burst audit challenge-response protocol for storage verification
- Proof-of-concept demo with end-to-end transfer flow
