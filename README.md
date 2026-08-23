<div align="center">

# Lattice Transfer Protocol (LTP)

## A Post-Quantum Cryptographic Data Transfer Protocol

> *"Don't move the data. Transfer the proof. Reconstruct the truth."*

[![Tests](https://img.shields.io/badge/tests-4,033_passing-brightgreen)]()
[![Python](https://img.shields.io/badge/python-3.10+-blue)]()
[![License](https://img.shields.io/badge/license-MIT-green)]()
[![SDK](https://img.shields.io/badge/SDK-3.0.0-orange)]()
[![Whitepaper](https://img.shields.io/badge/whitepaper-0.2.4-informational)](docs/WHITEPAPER.md)
[![Formal](https://img.shields.io/badge/Lean_4-67_theorems-9cf)](formal/lean/README.md)
[![Post-Quantum](https://img.shields.io/badge/crypto-post--quantum-purple)]()
[![Claude Code](https://img.shields.io/badge/Claude_Code-supported-blueviolet)](CLAUDE.md)
[![Cursor](https://img.shields.io/badge/Cursor-supported-black)](.cursorrules)

</div>

---

> **Note on naming.** LTP was formerly called **ETP (Entanglement Transfer
> Protocol)**. Some artifacts retain the old name for compatibility — notably
> the Verifpal model `docs/formal/etp-protocol.vp` and the
> `ETP_REQUIRE_REAL_CRYPTO` environment variable. The protocol, the package
> (`ltp`), and the specification are LTP.
>
> **Two version numbers, deliberately.** The **SDK** (this repository, the
> `ltp` Python package) is at 3.0.0. The **protocol specification**
> ([whitepaper](docs/WHITEPAPER.md)) is at 0.2.4 — a public draft issued for
> comment. They version independently; see
> [`docs/STABILITY_PROMISES.md`](docs/STABILITY_PROMISES.md).

## Visuals

Diagrams of LTP, SUWAPPU DAG, SUWAPPU-DB, and the ecosystem atlas live in [`docs/visuals/`](docs/visuals/README.md) — each in three forms (inline Mermaid that renders on GitHub/GitBook, standalone HTML decks, and editable Mermaid/Excalidraw sources).

- [Visuals overview](docs/visuals/README.md) — inline-rendered Mermaid diagrams
- [LTP presentation](docs/visuals/ltp.html), [SUWAPPU DAG presentation](docs/visuals/suwappu-dag.html), [SUWAPPU DB presentation](docs/visuals/suwappu-db.html)
- [SUWAPPU Ecosystem Atlas](docs/visuals/suwappu-ecosystem-atlas.html), [Visual index](docs/visuals/index.html)
- Mermaid sources: [LTP](docs/visuals/mermaid/ltp.md) · [SUWAPPU DAG](docs/visuals/mermaid/suwappu-dag.md) · [SUWAPPU DB](docs/visuals/mermaid/suwappu-db.md)
- Excalidraw sources: [LTP](docs/visuals/excalidraw/ltp.excalidraw) · [SUWAPPU DAG](docs/visuals/excalidraw/suwappu-dag.excalidraw) · [SUWAPPU DB](docs/visuals/excalidraw/suwappu-db.excalidraw)

## The Problem

Every existing protocol -- TCP/IP, HTTP, FTP, QUIC -- operates on the same
foundational assumption: **data is a payload that must travel from Point A to
Point B.** This chains us to three unsolvable constraints:

1. **Latency** -- bound by the speed of light and routing hops
2. **Geography** -- further = slower, always
3. **Compute** -- larger payloads demand more processing at both ends

LTP rejects this assumption. Data transfer is not about moving bits. It is about
transferring the *ability to reconstruct* a deterministic output at a destination,
verified by an immutable commitment.

## Three-Phase Protocol

```mermaid
flowchart LR
    S[Sender] -->|"1. COMMIT"| CL[Commitment Layer]
    CL -->|"Encrypted shards"| N1[Node 1]
    CL -->|"Encrypted shards"| N2[Node 2]
    CL -->|"Encrypted shards"| N3[Node ...]
    S -->|"2. LATTICE (~1.3KB sealed key)"| R[Receiver]
    R -->|"3. MATERIALIZE"| CL
    CL -->|"Reconstruct"| R
```

| Phase | Operation | What Happens |
|-------|-----------|-------------|
| **COMMIT** | Sender commits entity | Erasure encode, encrypt shards with random CEK, distribute to nodes, append to Merkle log |
| **LATTICE** | Sender seals key to receiver | ML-KEM-768 sealed envelope (~1.3KB) containing entity_id + CEK + commitment reference |
| **MATERIALIZE** | Receiver reconstructs entity | Unseal key, verify commitment, fetch k-of-n shards, decrypt, decode, verify integrity |

The entity is never serialized and shipped as a monolithic payload. It is
**committed, proved, and reconstructed**.

## Core Guarantees

| Property | Guarantee | Mechanism |
|----------|-----------|-----------|
| O(1) transfer path | Sender-to-receiver carries ~1.3KB regardless of entity size | ML-KEM sealed lattice key |
| Immutability | Committed entities cannot be altered | Append-only Merkle log with ML-DSA-65 signatures |
| Threshold secrecy | < k plaintext shards leak only a bounded, proportional share of entropy (t·log₂ 256 bits per byte position from t shards — whitepaper §3.3.5); AEAD encryption is the primary confidentiality layer | Erasure-coding threshold (partial, defense-in-depth) + XChaCha20-Poly1305 |
| Non-repudiation | Sender cannot deny having committed an entity | ML-DSA-65 signatures on commitment records |
| Post-quantum security | Resistant to quantum computer attacks | ML-KEM-768 (FIPS 203) + ML-DSA-65 (FIPS 204) |
| Forward secrecy | Compromising one transfer doesn't compromise others | Fresh ML-KEM encapsulation per transfer |

## Four Pillars

| Pillar | Implementation | Status |
|--------|---------------|--------|
| **Post-Quantum Cryptography** | ML-KEM-768/1024 (FIPS 203) + ML-DSA-65/87 (FIPS 204) + XChaCha20-Poly1305 | Active — real crypto, Level 3 + Level 5 |
| **Lattice Transfer Protocol** | 3-phase lifecycle with erasure coding, Merkle audit log, threshold reconstruction | Complete |
| **Dual-Lane Hashing** | SHA3-256 (canonical/on-chain) + BLAKE3-256 (internal/performance) | Enforced separation |
| **On-Chain Settlement** | LTPAnchorRegistry v6 with UUPS proxy + MultiSig + Timelock governance | Deployed on SUWAPPU Testnet + Base Sepolia |

## SUWAPPU Stack Alignment

LTP is the transfer and attestation layer for the SUWAPPU stack. `suwappu-dag` owns DAG
ordering and validator-ring consensus; `suwappu-db` owns the canonical EVM/Move
state substrate and emits the state roots that LTP anchors and attests.

| Layer | Repository | LTP Integration |
|-------|------------|-----------------|
| Transfer + attestation | `suwappu-lattice-protocol` | COMMIT/LATTICE/MATERIALIZE, gateway VM, `LTPAnchorRegistry` |
| Consensus + ordering | `suwappu-dag` | Consumes LTP corridor attestations through `crates/suwappu-ltp` |
| State substrate | `suwappu-db` | Produces state roots and anchors through `suwappudb-bridge` / `suwappudb-state` |

See [SUWAPPU DAG and SUWAPPU-DB Integration](docs/design-decisions/SUWAPPU_DAG_DB_INTEGRATION.md)
for the current cross-repo boundary.

The Python wire-compatible mirror of `suwappu-dag/crates/suwappu-ltp` lives in
[`src/ltp/corridor/`](src/ltp/corridor): 7-of-9 corridor attestation,
Commitment-Node DA SLA, cross-chain DID rotation statement, and the
length-prefixed SHA3-256 domain digest the DAG L1 signs over. Digest parity
against the Rust reference is locked in `tests/corridor/test_digest_parity.py`.

## Implementation Reality

| Area | Runtime Truth | Details |
|------|--------------|---------|
| **PQC (ML-KEM / ML-DSA / AEAD)** | Real — `pqcrypto` + `pynacl` | `assert_real_crypto()` at import; no PoC fallback |
| **ZK Proofs (STARK)** | Real — FRI over Goldilocks field | Default backend; ~10KB proofs with Merkle commitments |
| **ZK Proofs (Pedersen/Sigma)** | Real — BLS12-381 via `py_ecc` | Pedersen commitments + Schnorr/Sigma protocol (160B proofs) |
| **VDF (Wesolowski)** | Real — RSA group repeated squaring | Miller-Rabin k=40; O(1) verification with `pi^l * x^r == y` |
| **VDF (Hash-chain)** | Real — SHA3-256 iterative | PQ-safe alternative with checkpoint proofs |
| **Bridge Provers (STARK/SP1/R0)** | Real — FRI-based STARK | Mock modes delegate to real STARK prover |
| **Federation Signatures** | Real — ML-DSA `verify_sth()` | No hash-based simulation |
| **On-chain Anchoring** | Real — AnchorClient + web3.py | Circuit breaker, rate limiter, fail-fast config verification |
| **gRPC Transport** | Real — mTLS when configured | `NodeClient` uses `secure_channel`; fail-fast on TLS errors |
| **Gateway (REST)** | Real — JWT (ML-DSA-65) + rate limiting | FastAPI with Prometheus metrics |
| **HSM Custody** | Real boundary — sentinels for dk/sk | `hsm_sign()` / `hsm_decaps()` route through HSM; no plaintext leak |
| **Ethereum Backend** | Real when RPC configured | Fail-closed; no silent fallback to simulation in real mode |
| **Base L1 Backend** | Local simulation for testing | Production requires deployed chain infrastructure |
| **SUWAPPU-DAG Boundary** | External Rust L1 | DAG ordering and validator-ring consensus live in `suwappu-dag` |
| **SUWAPPU-DB Boundary** | External Rust substrate | State mutation, OCC, state roots, recovery, and L2 sync live in `suwappu-db` |

## What's Implemented

| Capability | Status | Module |
|------------|--------|--------|
| Three-phase protocol (COMMIT/LATTICE/MATERIALIZE) | Done | `protocol.py` |
| Erasure coding (Reed-Solomon GF(256)) | Done | `erasure.py` |
| AEAD shard encryption (CEK per entity) | Done | `shards.py` |
| ML-KEM-768 sealed envelope | Done | `keypair.py` |
| ML-DSA-65 commitment signatures | Done | `primitives.py` |
| Append-only Merkle commitment log | Done | `commitment.py` |
| Pluggable backends (Local, Base L1, Ethereum L2) | Done | `backends/` |
| Cross-chain bridge (L1Anchor, Relayer, L2Materializer) | Done | `bridge/` |
| Cross-deployment federation | Done | `federation.py` |
| Chunked streaming with backpressure | Done | `streaming.py` |
| ZK transfer mode (hiding commitments) | Done | `zk_transfer.py` |
| Economics engine (staking, slashing, rewards) | Done | `economics.py` |
| Enforcement pipeline (PDP, programmable slashing) | Done | `enforcement.py` |
| Compliance framework (9 control families) | Done | `compliance.py` |

## Architecture

```mermaid
flowchart TD
    subgraph Core["Core Protocol"]
        P[protocol.py] --> E[erasure.py]
        P --> S[shards.py]
        P --> K[keypair.py]
        P --> C[commitment.py]
        P --> PR[primitives.py]
        P --> L[lattice.py]
        P --> EN[entity.py]
    end

    subgraph Extensions["Extensions"]
        ST[streaming.py]
        ZK[zk_transfer.py]
        FED[federation.py]
    end

    subgraph Infrastructure["Infrastructure"]
        EC[economics.py]
        ENF[enforcement.py]
        EP[enforcement_pipeline.py]
        CO[compliance.py]
        HSM[hsm.py]
    end

    subgraph Backends["Commitment Backends"]
        BF[factory.py]
        BL[local.py]
        BB[base_l1.py]
        BE[ethereum.py]
    end

    subgraph Bridge["Bridge Protocol"]
        BA[anchor.py]
        BR[relayer.py]
        BMA[materializer.py]
    end

    P --> ST
    P --> ZK
    C --> BF
    BF --> BL
    BF --> BB
    BF --> BE
    P --> BA
    P --> BR
    P --> BMA
```

## Security Stack

```mermaid
flowchart BT
    L1["Layer 1: Threshold Structure (defense-in-depth)\nErasure coding (k-of-n threshold)\n< k shards: bounded proportional leakage (§3.3.5)"]
    L2["Layer 2: Cryptographic Integrity\nBLAKE3-256 content addressing\nMerkle root + ML-DSA-65 signatures"]
    L3["Layer 3: Zero-Knowledge (Optional)\nPedersen hiding commitments (BLS12-381)\nFRI-based STARK proofs (PQ-safe)"]
    L4["Layer 4: Shard Encryption\nAEAD with random 256-bit CEK\nPer-shard nonce derivation"]
    L5["Layer 5: Sealed Envelope\nML-KEM-768 encapsulation\nForward secrecy per transfer"]
    L6["Layer 6: Access Policy\nOne-time materialization\nTime-bounded, delegatable, revocable"]

    L1 --> L2
    L2 --> L3
    L3 --> L4
    L4 --> L5
    L5 --> L6
```

## Formal Verification

Two machine-checked artifacts, both gated in CI. What they establish — and
what they do not — is stated in full in
[`docs/FORMAL_VERIFICATION_STATUS.md`](docs/FORMAL_VERIFICATION_STATUS.md).

**Lean 4** ([`formal/lean/`](formal/lean/README.md)) — 67 audited theorems, no
`sorry`, no Mathlib dependency, negative-tested axiom audit. Covers the
corridor 7-of-9 quorum (safety and liveness), the constant-size commitment and
sealed-lattice-key invariants, the §6.4 bandwidth break-even, the k-of-n
erasure threshold consequences, the access-policy algebra, 2/3-supermajority
BFT bounds, and both whitepaper interoperability test vectors recomputed
inside the proof kernel over a from-scratch GF(2⁸).

**Verifpal** ([`docs/formal/`](docs/formal/ANALYSIS.md)) — symbolic analysis
under an active Dolev-Yao attacker, first run recorded 2026-08-16:

| Query | Result |
|---|---|
| `confidentiality? cek` | ✅ Verified |
| `confidentiality? content` | ✅ Verified |
| `authentication? commitment` | ❌ Fails — delivery of the (public, self-authenticating) record is unauthenticated |
| `authentication? sealed_key` | ❌ Fails — **cross-session replay**; no freshness or receiver binding |

The sealed-key replay finding is real, disclosed rather than deferred, and
corroborates a KEM ciphertext-binding gap the whitepaper documents in §3.3
(ML-KEM is not MAL-BIND-K-CT, so this must be closed at the protocol layer).
The planned fix — binding the receiver encapsulation-key fingerprint and
entity_id into the sealed key's AEAD associated data — is tracked in
[`docs/plans/2026-08-16-research-round.md`](docs/plans/2026-08-16-research-round.md).
Reproduction instructions for both artifacts are in their respective READMEs.

## Smart Contracts

### SUWAPPU Testnet (v5) — Chain ID `103115120`

| Contract | Address |
|----------|---------|
| UUPS Proxy (registry) | `0xB29d8BFF4973D1D7bcB10E32112EBB8fdd530bF4` |
| Implementation v5 | `0xADf01df5B6Bef8e37d253571ab6e21177aCb7796` |
| MultiSig (2-of-2) | `0x0106A79e9236009a05742B3fB1e3B7a52F44373D` |
| Timelock (60s delay) | `0x7C2665F7e68FE635ee8F10aa0130AEBC603a9Db8` |

### Base Sepolia (v6) — Chain ID `84532`

| Contract | Address |
|----------|---------|
| UUPS Proxy (registry) | `0x79eF1B7914f98C5C1404617449AB1f377c475996` |
| Implementation v6 | `0xb1Da18e714dD067f17d15C3Fe2EC2f39A5a3459E` |
| MultiSig (2-of-2) | `0x4c324c3c3475f58b67d3c879880D6c94eDC82E49` |
| Timelock (60s delay) | `0xc915740e35E38569E47f611eA5772Ff5278bc5Ae` |

**Governance chain:** MultiSig (2-of-2) → Timelock (60s) → Registry

**Deployment evolution:**
```
v1 (Mar 23)   Implementation only          No proxy, no governance
v2 (Mar 23)   + UUPS Proxy + MultiSig      Upgradeable, 2-of-2 control
v3 (Mar 23)   + TimelockController          Time-delayed governance
v4 (Mar 25)   Verified production deploy    84 Solidity + 1,167 Python tests
v5 (Mar 25)   Author attribution + v5      SUWAPPU Testnet production
v6 (Apr 14)   Base Sepolia L2 deployment   Bidirectional bridge
```

---

## Quick Start

```bash
# Clone and install
git clone https://github.com/Suwappu-Labs/suwappu-lattice-protocol.git
cd suwappu-lattice-protocol
pip install -e ".[dev]"

# Run the demo
python run_trust_layer.py

# Run all tests
pytest tests/ -v

# Run Solidity tests (requires Foundry)
cd contracts && forge test -vvv
```

## Project Structure

```
suwappu-lattice-protocol/
├── src/ltp/                    # Core protocol library (60+ modules)
│   ├── protocol.py             # Three-phase COMMIT/LATTICE/MATERIALIZE
│   ├── primitives.py           # ML-KEM-768, ML-DSA-65, AEAD, hashing
│   ├── commitment.py           # Merkle log, commitment network, node lifecycle
│   ├── erasure.py              # Reed-Solomon erasure coding over GF(256)
│   ├── shards.py               # AEAD shard encryption with CEK
│   ├── keypair.py              # ML-KEM sealed envelope (lattice key)
│   ├── lattice.py              # Lattice key construction
│   ├── entity.py               # Entity identity and shape analysis
│   ├── economics.py            # Staking, rewards, progressive slashing
│   ├── enforcement.py          # PDP proofs, programmable slashing, VDF audits
│   ├── enforcement_pipeline.py # Enforcement orchestration
│   ├── compliance.py           # 9-family compliance framework
│   ├── federation.py           # Cross-deployment discovery and trust
│   ├── streaming.py            # Chunked streaming with backpressure
│   ├── zk_transfer.py          # ZK hiding commitments (Pedersen + STARK)
│   ├── hsm.py                  # HSM interface for key management
│   ├── anchor/                 # On-chain anchoring client
│   ├── backends/               # Local, BaseL1, Ethereum backends
│   ├── bridge/                 # Cross-chain bridge protocol
│   ├── dual_lane/              # SHA3/BLAKE3 lane separation
│   ├── merkle_log/             # RFC 6962 Merkle tree + proofs
│   ├── network/                # gRPC client/server (7 RPCs)
│   ├── storage/                # SQLite (WAL), filesystem, memory stores
│   └── verify/                 # Verification SDK
│
├── contracts/
│   ├── src/
│   │   ├── LTPAnchorRegistry.sol      # On-chain anchor registry (UUPS)
│   │   ├── LTPMultiSig.sol            # N-of-M multi-signature wallet
│   │   └── interfaces/
│   │       └── ILTPAnchorRegistry.sol  # Registry interface
│   ├── test/
│   │   ├── LTPAnchorRegistry.t.sol    # 63 unit/integration tests
│   │   └── FormalVerification.t.sol   # 21 fuzz/invariant/parity tests
│   └── script/
│       ├── Deploy.s.sol               # Local deployment
│       ├── DeployTestnet.s.sol        # SUWAPPU Testnet deployment
│       ├── DeployMainnet.s.sol        # Production deployment (configurable)
│       └── UpgradeV4.s.sol            # Governance-controlled UUPS upgrade
│
├── formal/lean/                # Lean 4 machine-checked proofs (67 theorems)
├── tests/                      # 4,033 Python tests across 247 files
├── docs/                       # Protocol documentation
│   ├── WHITEPAPER.md           # Full protocol specification
│   └── ...                     # See docs/README.md for index
├── pyproject.toml              # Package configuration
├── CHANGELOG.md                # Version history
├── CONTRIBUTING.md             # Contribution guidelines
├── SECURITY.md                 # Security policy
└── LICENSE                     # MIT License
```

## Documentation

See [docs/README.md](docs/README.md) for the full documentation index.

| Document | Description |
|----------|-------------|
| [Whitepaper](docs/WHITEPAPER.md) | Full protocol specification (v0.2.4, public draft for comment) |
| [Formal Verification Status](docs/FORMAL_VERIFICATION_STATUS.md) | What is machine-checked, what is paper-proven, what is neither |
| [Extension Registry](docs/extension-registry.md) | Registered `x-ltp/` shape types |
| [Architecture](docs/design-decisions/ARCHITECTURE.md) | System components and data flow |
| [Visuals](docs/visuals/README.md) | Inline-Mermaid diagrams (LTP, SUWAPPU DAG, SUWAPPU-DB, anchor lifecycle, trust boundary, DKG) |
| [SUWAPPU DAG and SUWAPPU-DB Integration](docs/design-decisions/SUWAPPU_DAG_DB_INTEGRATION.md) | Cross-repo boundary with the DAG L1 and state substrate |
| [Production Roadmap](docs/plans/2026-05-11-production-roadmap.md) | Current milestones (2026-05-11) |
| [Deployment Guide](docs/DEPLOYMENT_GUIDE.md) | Docker, Kubernetes, CI/CD |
| [Bridge MVP](docs/bridge-mvp-scope.md) | Cross-chain bridge scope |
| [Bridge Trust Model](docs/BRIDGE_TRUST_MODEL.md) | What secures the on-chain bridge today, stated plainly — including the live fast-path ZK-verification stub and zero-bond challenge window |
| [Security Review](docs/security/audits/internal/SECURITY_REVIEW-2-24-2026.md) | Formal security analysis |

## Test Coverage

| Category | Count |
|----------|-------|
| Python tests | 4,033 |
| Solidity test/invariant functions | 339 |
| Lean 4 theorems (machine-checked, `sorry`-free) | 67 |
| ZK proof tests (EC + STARK) | 59 |
| Adversarial/attack tests | 56 |
| Security audit tests | 24 findings verified |
| Negative-path transport tests | 14 |
| State machine exhaustive (36 transition pairs) | Verified |
| Storage backend parametrized | 3 backends x 14 methods |
| gRPC round-trip (real servers) | 14 tests |
| Contract integration (anvil) | 17 tests |
| Fuzz runs (per test) | 256 iterations |
| Invariant tests | 256 runs x 3,840 calls each |
| **Total (Python + Solidity)** | **4,372** |

```bash
# Run Python tests
pip install -e ".[dev]"
pytest tests/ -v

# Run Solidity tests
cd contracts && forge test -vvv
```

## Key Properties

- **Constant-bandwidth sealed keys:** 1,220–1,250 bytes with ML-KEM-768, O(1) and
  independent of payload size — machine-checked in Lean
  (`lattice_key_size_payload_independent`, `sealed_768_bounded`)
- **FIPS-compliant settlement:** SHA3-256 canonical hashing on all on-chain paths
- **No simulations:** Real PQC mandatory at import via `assert_real_crypto()`; real FRI-based STARK; real Wesolowski VDF
- **Python↔Solidity parity:** Identical accept/reject for all validation rules
- **HSM-safe key custody:** `KeyPair.generate(hsm=...)` keeps private keys in HSM boundary — sentinel dk/sk, operations via `hsm_sign()`/`hsm_decaps()`
- **Fail-closed infrastructure:** AnchorClient circuit breaker + rate limiter + `verify_live_configuration()` — no silent degradation

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup and guidelines.

## Security

For external auditors and security researchers:

- **Reporting a vulnerability:** see [SECURITY.md](SECURITY.md).
- **Audit-evidence package (start here):**
  [docs/security/audits/internal/RED_TEAM_REPORT_2026-05.md](docs/security/audits/internal/RED_TEAM_REPORT_2026-05.md)
  — consolidated internal red-team report (May 2026 campaign).
  33 scenarios across 8 attack layers, 1 finding surfaced and
  remediated (LTP-A-031, HIGH). Audit-firm-style format
  (Executive Summary → Scope → Methodology → Threat Model →
  Findings → Defenses Verified → Maturity Self-Assessment →
  Recommended External-Audit Focus Areas).
- **Standing audit findings:** [docs/security/audits/internal/SECURITY_AUDIT_2026-05-15.md](docs/security/audits/internal/SECURITY_AUDIT_2026-05-15.md)
  — 31 LTP-A-* findings catalog + 20-entry strengths register.
- **Internal-testing charter:** [SECURITY_TESTING.md](SECURITY_TESTING.md)
  — authorization and scope rules for red-team campaigns.

## Supply chain

Supply-chain transparency tooling for this repository. These are
machine-generated inventories and automated posture checks — not a
third-party security audit and not a SOC 2 attestation.

- **Software Bill of Materials (SBOM):** a CycloneDX 1.6 JSON SBOM is
  committed at [`sbom/suwappu-lattice-protocol.cdx.json`](sbom/suwappu-lattice-protocol.cdx.json).
  It is generated from the project's *declared* Python dependency set
  (the `[project.optional-dependencies]` extras in `pyproject.toml`)
  using the pip / PyPI toolchain and `cyclonedx-bom`, with every
  component pinned as `pkg:pypi/<name>@<version>`. The core library
  itself declares zero required runtime dependencies (stdlib only); the
  SBOM captures the optional crypto, chain, gateway, federation and
  related extras plus their transitive closure.
- **Release SBOMs ([`.github/workflows/sbom.yml`](.github/workflows/sbom.yml)):**
  on every published GitHub Release, Syft (`anchore/sbom-action`) scans
  the working tree and attaches a freshly generated CycloneDX SBOM as a
  release asset. Also runnable on demand via `workflow_dispatch`.
- **OpenSSF Scorecard ([`.github/workflows/scorecard.yml`](.github/workflows/scorecard.yml)):**
  weekly (and on push to `main`) the `ossf/scorecard-action` evaluates
  supply-chain posture and uploads SARIF to the GitHub Security tab.
  Results are kept internal (`publish_results: false`); there is no
  public Scorecard badge.

All workflow Actions are SHA-pinned by commit (audit finding LTP-A-025).
GitHub Actions billing is currently disabled for this organization, so
the two workflows above are committed ready-to-run but will not execute
until billing is restored; the committed SBOM is the value-today
artifact in the meantime.

## License

MIT License. See [LICENSE](LICENSE).
