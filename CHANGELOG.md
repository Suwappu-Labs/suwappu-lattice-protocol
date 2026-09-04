# Changelog

All notable changes to LTP (Lattice Transfer Protocol) will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Breaking changes are marked **[BREAKING]** inline. See
[`docs/STABILITY_PROMISES.md`](docs/STABILITY_PROMISES.md) for the
public-surface promise and the cross-version compatibility matrix.

## [Unreleased]

### Fixed
- Inference gateway no longer routes the request's own model name into
  a log line or an error body. CodeQL flagged it as a high-severity
  `py/log-injection`: a model id carrying newlines forges entries in the
  log an operator reads during an incident, and the same value was
  being reflected back in the 404. The pricing lookup now returns the
  listing and the operator-registered `pricing.model_id` is used
  downstream, so neither hazard survives; two regression tests pin it,
  verified to fail with the fix reverted

### Added
- `docs/economics/BILLING_LEDGER_GAP_ANALYSIS.md`: measures the shipped
  billing surface against production ledger practice (Modern Treasury
  double-entry, TigerBeetle two-phase transfers, Stripe/Brandur
  idempotency keys with recovery points, Trail of Bits blockchain
  finality, LiteLLM token holds) and lists the gaps in priority order —
  no durability, no cross-process coordination, no pending/posted
  primitive, `tx_hash`-only deposit dedup, block-count instead of the
  chain's `finalized` tag. Three limits were reproduced against this
  code first: a restart resurrects spent balances and re-credits
  on-chain deposits while `solvent=True` throughout, and the receipt
  log retains ~3,951 B/receipt indefinitely. `incentives.py`,
  `inference.py`, and `bridge_deposits.py` now carry the same
  disclosure in their module docstrings
- Chain deposit adapter: `BridgeEmitterDepositSource` reads
  `BridgeEmitter.BridgeTransfer` logs (sender topic, amount word,
  recipient-vault topic filter) over a sliding block window and feeds
  the `DepositWatcher`; the inference service polls it on a background
  thread when `SUWAPPU_INFER_BRIDGE_*` is configured, so an on-chain
  stablecoin transfer becomes a prepaid balance with no manual step.
  Window re-scans lean on the watcher's per-tx idempotency, which
  holds within a process lifetime — the dedup set is in memory, so a
  restart re-credits deposits still inside the lookback window (see
  `docs/economics/BILLING_LEDGER_GAP_ANALYSIS.md`); tested against a
  stub web3 client including decode, filtering, divisor,
  malformed-data skip, and the live background-poll lifecycle
- Runnable inference marketplace: `ltp.inference_service` composes the
  whole stack (ledger, market, HSM-safe receipt log per LTP-A-032,
  deposit watcher, epoch settlement, gateway) into one
  `build_inference_service()` with env-driven config
  (`SUWAPPU_INFER_*`) and pluggable model backends —
  `openai_compatible_backend` fronts the deployment's own runtime
  (vLLM/TGI/llama.cpp) and bills on the runtime's `usage` counts.
  `ltp.bridge_deposits.DepositWatcher` closes the money-in link:
  idempotent-per-tx, confirmation-gated, attribution-explicit crediting
  of bridged stablecoins into customer balances (unbound senders
  quarantined, never guessed). `examples/inference_marketplace.py`
  runs the full loop live — deposit → completion over real HTTP →
  committed bill → verified audit proof → provider payout → solvency —
  and `tests/test_inference_service.py` pins it as an integration
  test, including under the implicit-HSM production posture the test
  conftest normally disables
- Committed inference receipts: `ReceiptCommitmentLog` commits every
  bill's canonical, domain-separated receipt (new
  `DOMAIN_INFERENCE_RECEIPT` tag) into the CT-style `MerkleLog` with an
  ML-DSA-65 signed tree head per commit; the gateway commits before
  settlement and the market verifier is the log, so an uncommitted or
  tampered receipt cannot settle. Completions carry a
  `billing.commitment` block and `GET /inference/v1/receipts/{id}`
  serves the self-contained audit bundle (record, inclusion proof,
  signed STH) a customer can verify without trusting the gateway
- Prepaid inference billing: customer stablecoin balances on the
  `StablecoinLedger` (deposit/balance/debit-to-fees/refund, inside the
  solvency invariant), `InferenceMarket.settle_prepaid` debiting the
  metered quote atomically (`InsufficientBalance` moves nothing and the
  request stays settleable after a top-up), a configurable serve floor
  bounding unbilled-compute exposure, gateway 402 flows before serving
  and after metering, JWT-subject customer resolution with a dev header
  fallback, and `GET /inference/v1/balance`
- Inference revenue lane (`src/ltp/inference.py` + gateway router
  `/inference/v1/*`, private surface — not re-exported from
  `ltp.__init__`): sell metered model inference in stablecoins against a
  deployment-injected model backend. Per-million-token pricing with
  ceiling rounding, replay-guarded receipt settlement (SHA3-256
  request/response digests, injectable verifier for LTP-commitment
  auditing), revenue split through the incentive ledger so the serving
  provider's claim is paid at epoch settlement under the solvency clamp.
  OpenAI-shaped `/inference/v1/chat/completions` endpoint (JWT-protected),
  `/models` and `/stats` reads. Design doc:
  `docs/economics/INFERENCE_REVENUE.md`
- Validator compute incentives (`src/ltp/incentives.py`, private surface —
  not yet re-exported from `ltp.__init__`): stablecoin-denominated
  implementation of the whitepaper §5.5 interfaces (`NodeIncentive`,
  `CommitmentPricing`, `AdmissionControl`) per the deferred-token
  architecture — proof-gated pay (zero passed audits earn zero), a
  solvency-enforced `StablecoinLedger` (no minting; underfunded epochs
  settle pro-rata and carry claims), stablecoin operator bonds with
  progressive slashing into the insurance pool, and fee splits with the
  burn share redirected to treasury. Design doc:
  `docs/economics/VALIDATOR_COMPUTE_INCENTIVES.md` (also closes the §4
  open question in `docs/economics/DEFERRED_TOKEN_ARCHITECTURE.md`);
  chain-side counterpart lands in `suwappu-dag`
  (`suwappu-precompiles::rewards`)
- Quality-parity pass (cross-repo bar set by suwappubot):
  `scripts/verify.sh` single verification entrypoint with lanes
  (lint / semgrep / python / fast / contracts / secaudit / docs / all);
  CodeQL analysis workflow (python + actions, SHA-pinned); the
  `.semgrep/` crypto/key-handling rules now run in CI (advisory,
  documented finding baseline); Python test matrix widened to
  3.10/3.11/3.12; coverage measurement with an enforced floor
  (`pytest-cov`, `[tool.coverage.report] fail_under`); DST regression
  gate resurrected from the orphaned `deploy/ci/test.yml` into live CI
  (advisory — the harness currently reports real violations on seeds
  123/777); root `AGENTS.md` and `SUPPORT.md`
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

### Fixed
- **Ledger solvency under concurrency.** Balance movements are
  read-modify-write and the shipped service runs the bridge deposit
  poller on its own thread against the same `StablecoinLedger` the
  gateway debits, so unsynchronized movement broke the invariant the
  whole economic design rests on — reproduced losing customer funds
  *and* fabricating micro the ledger never held. Every mutator, the
  check-and-debit sequence, `pay_from_pool`'s clamp, and the invariant
  read now hold a reentrant lock (`ledger.lock` exposed for multi-step
  atomicity); `InferenceMarket` guards its settled-set and revenue
  counters; `settle_prepaid` defers to the ledger's locked
  check-and-debit instead of reading the balance first. Regression
  tests assert exact accounting across concurrent deposit/debit,
  double-spend, and pool-overdraw paths, plus a service-level test
  billing completions from four threads while the poller credits

### Changed
- `AGENTS.md` is now the single source of truth for AI coding agents;
  `CLAUDE.md` and `.cursorrules` are symlinks to it (the pattern used by
  `vercel/next.js` and `apache/airflow`). Stale test counts and the
  `plans/` path were corrected; `docs/AI_AGENTS.md` now holds only
  per-tool notes
- `CHANGELOG.md` entries now flag breaking changes inline with `**[BREAKING]**`

### Known issues
- LICENSE discrepancy: repo file declares Elastic 2.0 while `pyproject.toml`
  declares MIT — resolution pending in Linear GLO-785

## [5.0.0] - 2026-03-25

### Added
- LTPAnchorRegistry v5 deployed on SUWAPPU Testnet (Chain ID `103115120`)
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
- Verified production deployment on SUWAPPU Testnet (block 687137)
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
  - Initial Suwappu Testnet deployment (Chain ID `103115120`)
- **New Python modules (40+):**
  - `src/ltp/anchor/` — EntityState machine, AnchorSubmission, AnchorClient with circuit breaker
  - `src/ltp/dual_lane/` — SHA3-256 canonical + BLAKE3-256 internal lane separation
  - `src/ltp/merkle_log/` — RFC 6962 Merkle tree, signed tree heads, inclusion/consistency proofs
  - `src/ltp/network/` — gRPC client/server with 7 RPCs, RemoteNode proxy
  - `src/ltp/storage/` — Memory, SQLite (WAL mode), Filesystem shard stores
  - `src/ltp/verify/` — Pure verification SDK (no state, no side effects)
  - `domain.py` — 11 domain separation tags (`SUWAPPU-LTP:*`)
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
