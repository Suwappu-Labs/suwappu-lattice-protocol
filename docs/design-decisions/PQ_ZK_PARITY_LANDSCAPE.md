# Post-Quantum and ZK Parity Landscape

**Status:** research + recommendation, 2026-11-20. No protocol change is
committed by this document.

**Question this answers:** which other post-quantum and zero-knowledge
projects have a live network and public source we can read, where does LTP
stand against them, and what should we build to reach parity?

**Short answer:** no project we could find, with a live network and public
code, anchors post-quantum-signed state roots on an EVM chain. On LTP's
core idea there is nobody to match. The parity gaps are elsewhere: nothing
LTP signs is verified on-chain, the corridor quorum is classical BLS, and
the ZK fast path is simulated. Runnable open-source code exists to close
the first two today, on testnets LTP already deploys to.

**Scope rule:** a project is in scope only if it has a public testnet or
mainnet (or, for libraries, maintained code with benchmarks) *and* a
readable source repository. Whitepaper-only and closed-source projects are
listed under [Rejected](#8-checked-and-rejected) with the reason.

## 1. How to read the evidence

This is a desk survey. Nothing external was built or run. Each external
claim carries a marker:

| Marker | Meaning |
|---|---|
| **V** | A page stating the claim was fetched during the survey (repo README, EIP page, project blog, explorer) |
| **U** | Search snippet, secondary press, or recall. Treat as a lead, not a fact |

Known limits:

- Last-commit dates were mostly not visible, so "activity" is commit count
  or the newest dated artifact seen.
- All gas, proof-size and timing figures are the projects' own
  self-reported numbers. None were reproduced.
- Network status changes fast. Re-check before quoting any row externally.
- The survey does not duplicate
  [`PQ_ONCHAIN_VERIFICATION.md`](PQ_ONCHAIN_VERIFICATION.md), which already
  analyses EIP-8051, EIP-8052, EIP-7932, ERC-7913 and calldata cost. This
  document only records what changed since (section 5.3).

## 2. Where LTP stands today

Inventory of the tree at the date above. "Code" means it runs; "docs
only" means it is specified but not implemented.

| Area | State | Where |
|---|---|---|
| ML-KEM-768 / ML-KEM-1024 | Code, via `pqcrypto` | `src/ltp/primitives.py` |
| ML-DSA-65 / ML-DSA-87 | Code, verified off-chain only | `src/ltp/primitives.py` |
| Composite ML-DSA-65 + Ed25519 signature | Code, but no caller; `envelope.py` does not use it | `src/ltp/hybrid.py` |
| Hybrid KEM (X-Wing) | Backlog item only | [`2026-08-16-research-round.md`](../plans/2026-08-16-research-round.md) |
| Corridor 7-of-9 attestation | Classical BLS12-381. Not post-quantum | `src/ltp/corridor/`, `src/ltp/bls.py` |
| On-chain check of the BLS aggregate | None | [`CORRIDOR_INTEGRATION.md`](../CORRIDOR_INTEGRATION.md) |
| On-chain check of any ML-DSA signature | None. The registry stores statement and signature hashes | `contracts/src/LTPAnchorRegistry.sol` |
| `LTPMultiSig`, governance | Rest on ECDSA accounts; ML-DSA checked off-chain | `contracts/src/` |
| SP1 guest verifying ML-DSA-65 | Code, but a full proof has never completed (out of memory locally) | `zkvm/sp1-mldsa-verifier/` |
| RISC Zero host | Placeholder that exits with an error | `zkvm/risc0-host/` |
| `zkvm/` in CI | Not built | `.github/workflows/` |
| In-tree STARK/FRI | Real FRI over Goldilocks, but it proves low degree, not the signature-verification relation | `src/ltp/zk/` |
| `ZKBridgeVerifier` on testnets | Deployed in simulated mode on both networks; forgeable (LTP-A-007) | [`DEPLOYED_CONTRACTS.md`](../DEPLOYED_CONTRACTS.md), [`BRIDGE_TRUST_MODEL.md`](../BRIDGE_TRUST_MODEL.md) |
| Groth16 + Poseidon ZK mode | Docs only | [`WHITEPAPER.md`](../WHITEPAPER.md), [`ZK_TRANSFER_MODE.md`](ZK_TRANSFER_MODE.md) |
| Deployments | SUWAPPU Testnet and Base Sepolia. No mainnet | [`DEPLOYED_CONTRACTS.md`](../DEPLOYED_CONTRACTS.md) |

Two documentation claims overstate the code and should be corrected before
LTP is compared publicly:

- [`WHITEPAPER.md`](../WHITEPAPER.md) specifies Groth16 over BLS12-381 with
  Poseidon circuits. No such circuit exists in the tree.
- [`2026-05-11-production-roadmap.md`](../plans/2026-05-11-production-roadmap.md)
  calls the STARK stack "fully real". The FRI code is real; the claim that
  it proves signature validity is not.

## 3. Parity matrix

| Area | LTP today | Who is shipping | Code to go off |
|---|---|---|---|
| ML-DSA verified on-chain | None | ZKNOX verifier on Sepolia, Arbitrum Sepolia, Base Sepolia (V); QRL 2.0 testnet with ML-DSA-87 accounts (V) | [ETHDILITHIUM][ethdil], [Fireblocks verifier][fb] |
| Post-quantum quorum certificate | Classical BLS, unchecked on-chain | Lean Ethereum devnets and Tezos Quantumnet (hash-based signatures aggregated by a hash-based proof) (V); Algorand mainnet Falcon state proofs (V) | [leanSig][leansig], [leanMultisig][leanms], [go-stateproof-verification][algosp] |
| ZK proof of ML-DSA verification | Guest written, never proven | Two public benchmarks: Dilithium5 in SP1, ML-DSA-44 in RISC Zero (section 5.5). Neither is deployed | [dilithium5-poseidon][d5p], [kaspa-pq-zk-bench][kpq] |
| End-to-end post-quantum proof on EVM | None | No production zkVM. All end in a BN254 pairing proof | [sol-spartan-whir][ssw] (research) |
| Hybrid admin and account keys | ECDSA accounts | Kohaku hybrid ML-DSA + ECDSA accounts on three testnets (V); NEAR mainnet in-place key rotation (one secondary source) | [Kohaku `pq-account`][kohaku] |
| ML-KEM transport | ML-KEM, no hybrid | Quantus (ML-KEM-768 + ML-DSA-87 handshake) (V); age v1.3 `mlkem768x25519` (V); Signal SPQR (V) | [Quantus chain][quantus], [age][age], [SPQR][spqr] |
| Key migration from classical | Not applicable yet | NEAR, Algorand (rotate in place); Tezos (deadline plus ZK seed-phrase recovery) (V) | Design reference only |

## 4. Post-quantum chains with running code

### 4.1 Passes the bar

| Project | Source | Network | PQ primitives | ZK, and is it PQ | Worth borrowing |
|---|---|---|---|---|---|
| QRL 2.0 (Zond) | [theQRL/go-zond][zond], LGPL/GPL-3.0, Go; [go-qrllib][qrllib], MIT (V) | Public PoS Testnet V2, 2026-03-31; mainnet gated on audits (V) | ML-DSA-87 for transactions and validators (V) | None found | Closest EVM analogue: a go-ethereum fork with ML-DSA accounts, plus a dependency-free Go ML-DSA library |
| Algorand | [algorand/go-algorand][algo], AGPL-3.0, Go (V) | Mainnet. Falcon state proofs since 2022 (V); Falcon accounts in 2026 (V, exact date U) | Falcon-1024. Consensus and VRF still classical (V) | None | Falcon-signed compact state proofs are the nearest prior art to a PQ-attested state root |
| NEAR | near/nearcore (U, not fetched) | Mainnet upgrade 2.13, 2026-07-20 (one secondary source) | ML-DSA-65 as an access-key type | n/a | Migration model: one key-rotation transaction, same address |
| Quantus | [Quantus-Network/chain][quantus], MIT, Rust/Substrate (V) | PoW mainnet 2026-09-09 (U) | ML-DSA-87 transactions; ML-DSA-87 identity + ML-KEM-768 transport in an extended Noise handshake (V, whitepaper) | Plonky2 recursive aggregation, hash-based (V) | The only project verified shipping LTP's exact pair, ML-KEM transport with ML-DSA identity |
| BTQ Bitcoin Quantum | [btq-ag/btq-core][btq], MIT, C++ (V) | Public testnet 2026-01-12 (U) | ML-DSA replacing ECDSA; parameter set unconfirmed (U) | None | Baseline for the cost of no aggregation (64 MiB blocks, U) |
| Nervos CKB lock script | [cryptape/quantum-resistant-lock-script][ckb], MIT (V) | CKB mainnet and testnet; code hashes in README (V) | All 12 FIPS 205 SLH-DSA sets (V) | None | Published verification-cost table per parameter set |
| Abelian | [pqabelian/abec][abec], Go, **no licence file** (V) | PoW mainnet since 2022 (U) | Lattice linkable ring signatures and commitments, not the NIST schemes (V) | Lattice range and balance proofs (U) | Only live lattice-privacy chain. Read; do not copy |
| Cellframe | [demlabs-cellframe/cellframe-node][cell], LGPL-3.0 (V) | "Backbone" mainnet plus testnets (V) | Dilithium wallet type (V); other claims U | None found | Multi-scheme agility; thin docs |
| Lean Ethereum | [leanSig][leansig], [leanMultisig][leanms], Apache-2.0/MIT, Rust (V) | **Devnets only**, pq-devnet-0 to -5, eight clients, 1,024 validators (V, survey) | XMSS-style hash-based signatures over Poseidon; unaudited (V) | leanVM, hash-based, "not production ready" (V) | Reference design for PQ signature aggregation. See section 6.2 |
| Tezos Quantumnet | gitlab.com/tezos/tezos (U, not fetched) | Experimental public testnet 2026-09-24 (V) | ML-DSA-44 accounts; XMSS attestations (V) | Lean-style STARK aggregation (V) | ZK proof of seed-phrase knowledge as a recovery path for stragglers |

### 4.2 What the chain survey says about parity

- **Parameter choice is splitting three ways.** ML-DSA-87 (QRL, Quantus),
  ML-DSA-65 (NEAR), ML-DSA-44 (Tezos). Falcon where size dominates
  (Algorand). SLH-DSA as the conservative vault option (CKB). LTP's
  ML-DSA-65 default sits in the middle and matches the only ML-DSA-65
  Solidity verifier found.
- **ML-KEM is rare.** Only Quantus was verified using it for transport.
  LTP's ML-KEM data-transfer lane is a differentiator, not table stakes.
- **Aggregation is the open problem.** Nobody aggregates ML-DSA natively.
  Live answers are hash-based signatures plus proof aggregation, recursive
  FRI proofs, or bigger blocks.
- **Migration converges on in-place key rotation**, with a deadline and a
  ZK fallback in the most developed design.

## 5. Zero-knowledge and on-chain verification

### 5.1 Hash-based proof systems and zkVMs

The question for each is whether the path stays post-quantum through
on-chain verification, or ends in a pairing-based wrapper.

| System | Source | Status | Post-quantum through to EVM? |
|---|---|---|---|
| SP1 | [succinctlabs/sp1][sp1], MIT/Apache (V) | Production; Groth16 about 270k gas, PLONK about 300k (V) | **No.** Succinct's own post calls the Groth16 wrapper "not post-quantum"; hash-based wrapper planned, no date (V) |
| RISC Zero | [risc0/risc0][r0], Apache-2.0 (V) | Production; docs cover only the Groth16 verifier (V) | **No** |
| OpenVM | [openvm-org/openvm][openvm], MIT/Apache (V) | v2 recommended for production (V) | **No.** Halo2-KZG on BN254 (U) |
| Pico | [brevis-network/pico][pico], MIT/Apache (V) | v3.1; WHIR internally (V) | **No.** README says the on-chain step is held to BN254 security (V) |
| Airbender | [matter-labs/zksync-airbender][airb], MIT/Apache (V) | Current wrapper FFLONK + KZG (U); a hash-commitment L1 path announced, no code seen (V, press) | Not today |
| Stwo | [starkware-libs/stwo][stwo], Apache-2.0 (V) | Live on Starknet mainnet since 2025-11-03 (V) | Hash-based to a Solidity verifier via SHARP; only usable if you settle through Starknet |
| Plonky3 | [Plonky3/Plonky3][p3], MIT/Apache (V) | Toolkit with FRI, STIR and WHIR (V) | No EVM verifier; base layer for a custom AIR |
| Binius64 | [binius-zk/binius64][binius], MIT/Apache (V) | No releases, no on-chain verifier (V) | No EVM path |
| Jolt | [a16z/jolt][jolt], MIT/Apache (V) | README still says alpha (V) | No on-chain verifier |
| leanVM / leanMultisig | [leanEthereum/leanMultisig][leanms] (V) | "Not (yet) production ready" (V) | Hash-based throughout, but the EVM verifier is impractical (below) |

**Direct hash-based verification on EVM** exists as research code in
[sol-spartan-whir][ssw] (MIT) and its successor [ethereum/sol-whir-p3][swp3]
(MIT, last commit 2026-10-21), whose README repeats these figures and
states that the contracts need a split verifier to deploy on a chain that
enforces the code-size limit. README transaction gas (V):

| Verifier | Tx gas | Note |
|---|---|---|
| KoalaBear quartic | 899,380 | About 80-bit target |
| KoalaBear quintic | 2,972,399 | Exceeds the EIP-170 code-size limit |
| BabyBear quintic | 3,364,794 | Exceeds EIP-170 |
| KoalaBear octic | 5,637,745 | Exceeds EIP-170 |
| leanVM grouped terminal | 10,666,368 | Exceeds EIP-170 |

**Consequence for LTP:** finishing the SP1 path in `zkvm/` yields a real
proof on-chain and removes the forgeable simulated mode, but the last step
is Groth16 over BN254. It must be described as a real proof with a
classical final step, not as a post-quantum bridge.

### 5.2 Lattice-based proof systems

| System | Source | Maturity | On a network? |
|---|---|---|---|
| Lattice Jolt | [a16z/jolt][jolt] (V) | Announced 2026-09-09; no zero-knowledge yet; self-reported speed; no audit (V) | No |
| LaBRADOR + Greyhound | [lattice-dogs/labrador][labrador] (V) | C, AVX-512 only, 5 commits (V) | No |
| Lazer | [lazer-crypto/lazer][lazer], MIT (V) | C with Python bindings; demos include proofs about Kyber secrets (V) | No |
| LatticeFold / LatticeFold+ | [NethermindEth/latticefold][lfold], MIT/Apache (V) | "Proof-of-concept, NOT ready for production" (V) | No |
| lattirust | github.com/lattirust (V) | Last updated spring 2025; looks stalled (V) | No |

None has an on-chain verifier. Lazer is the only one callable from Python
and so the only one that fits the SDK for experiments.

### 5.3 On-chain post-quantum signature verification

All verifiers below are unaudited by their own statements.

| Verifier | Source | Gas (self-reported) | Deployed |
|---|---|---|---|
| ZKNOX ETHDILITHIUM | [ZKNoxHQ/ETHDILITHIUM][ethdil], MIT (V) | See section 5.4; depends on branch | ML-DSA-44 verifier `0x092c5d82069de997E34Ce2505CA7D5042f3721ef` on Sepolia, Arbitrum Sepolia and Base Sepolia (V, Kohaku deployment file; contract source-verified on Sepolia; contract code confirmed present on Base Sepolia by `eth_getCode`) |
| Fireblocks ML-DSA-44 | [fireblocks-labs/evm-ml-dsa-verifier][fb], MIT (V) | 1,226,311 per verify, plus about 4.11M once per key (V) | None |
| ZKNOX ETHFALCON | [ZKNoxHQ/ETHFALCON][ethfal], MIT (V) | Falcon 3.8M; EVM-tuned 1.4M (V) | Sepolia, Arbitrum Sepolia (V) |
| Kohaku `pq-account` | [ethereum/kohaku][kohaku] (V) | n/a | Hybrid ML-DSA + ECDSA ERC-4337 account factories on the same three testnets (V) |
| SPHINCS- | [nconsigny/SPHINCS-][sphm] (V) | 39k to 204k per verify call; a signer bug is disclosed (V) | Sepolia (V) |
| Stylus ML-DSA-65 | [multivmlabs/pq-smart-wallet][stylus], no licence (V) | 374k on a local devnode (V) | None |

EIP changes since [`PQ_ONCHAIN_VERIFICATION.md`](PQ_ONCHAIN_VERIFICATION.md)
was written (all fetched from eips.ethereum.org):

| EIP | Status | Note |
|---|---|---|
| 8051 ML-DSA precompile | Draft | Still ML-DSA-44 only |
| **8355 ML-DSA precompiles** | Draft, created 2026-07-30 | **New.** ML-DSA-44/65/87 with compressed keys. Competes with 8051 for the same addresses. This is the draft that would cover LTP's ML-DSA-65 |
| 8052 Falcon precompile | Draft | |
| 7932 Secondary signature algorithms | Draft | |
| 7701 Native account abstraction | **Withdrawn** | Superseded by 8141 |
| 8141 Frame transaction | Draft | Cites a PQ off-ramp as motivation |

No fork-inclusion status was found for any of them. The unposted review
in [`eip-8051-ltp-feedback.md`](../eips/eip-8051-ltp-feedback.md) should be
re-read against EIP-8355 before it is sent anywhere.

### 5.4 What the verifier code says when read

Both ML-DSA verifier repositories were cloned and read on 2026-11-20.
Nothing was built: Foundry is not installed in the survey environment, so
every gas figure is still the repository's own.

**ZKNOX ETHDILITHIUM** (MIT, 7 contributors, about 370 commits per
branch). The useful work is on branches, not `main`:

| Branch | Last commit | What it has | Gas per verify (README) |
|---|---|---|---|
| `main` | 2026-09-16 | ML-DSA-44, unpacked arithmetic. This is what is deployed | 8.1M |
| `exp/packed-verifier` | 2026-09-09 | ML-DSA-44 packed; ML-DSA-65; key in a stored blob | 1.19M (44), 1.54M (65) |
| `mldsa65-calldata` | 2026-10-21 | ML-DSA-44 and -65, key passed in calldata | 1.01M + 0.31M calldata (44); 1.20M + 0.54M calldata (65) |
| `mldsa87` | 2026-10-30 | All three sets, key in calldata. NIST KAT and ACVP `sigVer` vectors pass per README | As above, plus 1.63M + 0.93M calldata (87) |

Interface of the ML-DSA-65 verifier on `mldsa87`
(`src/ZKNOX_dilithium65.sol`):

- `verify(bytes pk, bytes m, bytes signature, bytes ctx)` forms
  `M' = 0x00 || len(ctx) || ctx || M` as FIPS 204 specifies. `ctx` may be
  up to 255 bytes. The message is arbitrary length.
- `verify(bytes pk, bytes32 m, bytes signature)` is the fixed-digest form
  with an empty context.
- `signature` is the standard 3,309-byte FIPS 204 encoding.
- `pk` is **not** the 1,952-byte FIPS key. It is a 38,112-byte expanded
  key (the matrix and `t1` in the NTT domain, then `tr`) passed in
  calldata on every call. Nothing is stored; the caller must bind the
  blob to a signer by `keccak256`. A JavaScript helper derives it from
  the standard key.
- It depends on one shared Keccak-f[1600] helper contract per chain
  (about 4.32M gas to deploy, bound by code hash). The EVM hashing opcode
  cannot produce SHAKE.

**Fit with LTP.** `MLDSA.sign` in `src/ltp/primitives.py` takes no context
argument, so LTP signs with an empty context. A standard LTP ML-DSA-65
signature should therefore verify unmodified through the four-argument
form with `ctx = ""`, or with a real context once the signing side gains
one. Both objections recorded against EIP-8051 in
[`PQ_ONCHAIN_VERIFICATION.md`](PQ_ONCHAIN_VERIFICATION.md) (fixed 32-byte
message, no `ctx`) do not apply to this verifier. This is a reading of the
interface, not a test: no LTP signature has been run through it.

**Fireblocks** (MIT, one commit, 2026-09-02). ML-DSA-44 only; empty
context is hard-wired. `verify(address pkBlob, bytes message, bytes
signature)` reads a prepared 20,545-byte key from a per-key data contract.
Runtime size is 24,032 bytes against the 24,576-byte limit. It is the
best-checked of the two: 320 tests including ACVP and Wycheproof, 62 Z3
properties, 64 Lean theorems on the arithmetic, and a mutation campaign.
Its README says it restores two FIPS 204 checks that the ZKNOX baseline
omitted, which is a reason to prefer the newer ZKNOX branches over the
deployed `main` contract. It does not cover ML-DSA-65.

**Not done:** an independent gas measurement, an explorer check of source
verification on Base Sepolia, and an end-to-end test with an LTP-produced
signature.

### 5.5 Proving ML-DSA verification in a zkVM

A second pass cloned and read the repositories below (not built) and read
`zkvm/` in this tree.

**Public measurements.** All self-reported by their authors.

| Repository | What is proven | Numbers |
|---|---|---|
| [gabrielemorciano/dilithium5-poseidon][d5p] (`zkvm-comparison/`; MIT per README, no licence file; last commit 2026-09-20) | Unmodified Dilithium5 verification in SP1 6.0.1, no precompile patches | 3,796,397 cycles; 124 s STARK plus 594 s Groth16 wrap; **peak 23.9 GB** on 16 cores; 208,352 gas to verify on-chain |
| [KaspaKii/kaspa-pq-zk-bench][kpq] (MIT; last commit 2026-07-22) | ML-DSA-44 (RustCrypto `ml-dsa 0.1.1`, the crate this repo resolves to), Falcon-512 and SLH-DSA-128s as RISC Zero 3.0.5 guests | High-end GPU means: Falcon 1.91 s, ML-DSA-44 5.35 s, SLH-DSA 16.33 s. No cycle counts |
| `kota1026/pq-wallet-sp1-ntt-gadget-` | Landing page claims ML-DSA-65 in SP1 | Repository is empty. Not a usable artefact |
| [a16z/jolt][jolt] | No ML-DSA example | Has inline Keccak and an NTT helper for odd primes below 2^30, which covers the ML-DSA modulus |

No Dilithium or Falcon verifier was found in Noir, Cairo, halo2, Plonky2/3,
OpenVM, ZisK, Pico or Airbender, and no official Succinct or RISC Zero
example. That is an absence of search results, not proof of absence.

**Estimate for ML-DSA-65.** Derived, not measured:

- One verification needs about 175 Keccak permutations (150 of them to
  expand the 6×5 matrix) and 18 NTTs of 256 points. Dilithium5 needs about
  311 permutations and 24 NTTs.
- Scaling the measured 3.80M cycles for Dilithium5 gives roughly 2–4M
  cycles unpatched, and plausibly 1–2M with the Keccak precompile in use.
- `client.execute()` returns the real cycle count in seconds without
  prover memory. That is the first thing to run.

**Why the proof in `zkvm/` has never completed.** Four findings from the
tree, each checked against the files:

| Finding | Where | Consequence |
|---|---|---|
| `Cargo.toml` asks for `ml-dsa 0.1.0-rc.8` but `Cargo.lock` resolves `ml-dsa 0.1.1`, which hashes through the `shake 0.1.0` and `keccak 0.2.0` crates rather than `sha3` | `zkvm/sp1-mldsa-verifier/Cargo.lock` | SP1's Keccak precompile is reached through its patched `sha3` and `tiny-keccak` crates only (V, Succinct docs). ML-DSA's SHAKE runs in software |
| No `[patch.crates-io]` section | `zkvm/sp1-mldsa-verifier/Cargo.toml` | Even the guest's own `SHA3-256(vk)` is unaccelerated |
| The host uses the CPU prover and a plain `prove` call with no Groth16 or PLONK mode | `zkvm/sp1-host/src/main.rs` | It produces a core proof, which an EVM verifier cannot check |
| 15 GB sandbox | Guest header comment | Succinct documents 16 GB or more for core and Groth16 proofs, and the executor defaults to a 24 GiB memory limit (V). The one comparable measurement peaked at 23.9 GB |

Separately, the pinned `sp1-zkvm 6.3.1` falls inside advisory
GHSA-p7v2-jjv3-8p8f (High, published 2026-10-11; native Rust verifier
6.0.0 to 6.8.0, fixed in 6.8.1; Groth16 and PLONK verification stated
unaffected) (V). The host's `client.verify` self-check is the affected
path. See <https://github.com/succinctlabs/sp1/security/advisories/GHSA-p7v2-jjv3-8p8f>.

**Shortest route to one real proof on Base Sepolia:**

1. Run `execute` and record cycles.
2. Move SP1 to 6.8.1 or later and re-derive the program verification key.
3. Request a Groth16 proof in the host.
4. Prove on a 16-core machine with at least 32 GB, or through the Succinct
   Prover Network. No concrete network price was found.
5. Point `ZKBridgeVerifier` at Succinct's verifier for the matching
   version. Its Base Sepolia address was not verified in this survey.

Routing ML-DSA's SHAKE to the precompile is optional for the first proof.
No off-the-shelf patch exists for the `keccak 0.2` and `shake` crates; it
would need a small fork modelled on the `sha3` patch, which counts as a
new dependency source under this repository's rules.

**What a proof buys here.** The guest proves one signature. Verifying
that signature directly in Solidity (section 5.4) is post-quantum today
with no wrapper and costs about 1.2–1.5M gas. The SP1 route costs about
0.2–0.3M gas on-chain but ends in Groth16 over BN254. The proof route
earns its place when many signatures or a long log-consistency statement
are compressed into one proof, not for a single signature.

**Other 2026 lattice code.** Lattice Jolt's code is on `a16z/jolt` main
(`crates/jolt-akita`), with the commitment scheme pinned to
`LayerZero-Labs/akita`. [a16z/hachi][hachi] is a polynomial-commitment
library only. `nicarq/halo3` implements SuperNeo folding and labels itself
not production-ready. `dfaranha/aggregate-falcon` (Falcon aggregated with
LaBRADOR) has no licence file and no commits since 2024. No ML-DSA
aggregation implementation and no lattice proof system with a Solidity
verifier was found. EIP-7885 (an NTT precompile that lists the ML-DSA
modulus) is Draft with no fork assigned (V).

## 6. Replacing the BLS corridor quorum

### 6.1 Threshold and multi-signature schemes

| Scheme | Source | Why it does not fit 7-of-9 |
|---|---|---|
| Threshold ML-DSA (Celi et al.) | github.com/GuilhemN/threshold-ml-dsa (V) | Capped at 6 parties; academic proof of concept |
| `tss-lib/v2/mldsatss` | pkg.go.dev/github.com/KarpelesLab/tss-lib/v2/mldsatss, MIT (V) | ML-DSA-44 only, n ≤ 6, trusted dealer. Output is standard FIPS 204, which is its appeal |
| Ringtail | [daryakaviani/ringtail][ringtail], Apache-2.0 (V) | 3 commits; custom non-FIPS signature; no Solidity verifier |
| Threshold Raccoon, TOPCOAT, Chipmunk, Squirrel, MuSig-L, DualMS | — | No confirmed public code |
| NIST threshold call | csrc.nist.gov/Projects/threshold-cryptography (V) | Package deadline not before 2027-03-01; no code linked yet |

### 6.2 Hash-based signatures aggregated by a proof

Lean Ethereum's design: each signer uses a stateful XMSS-style key
([leanSig][leansig]), and a hash-based zkVM aggregates the signatures.
Self-reported on an M4 Max: 1,400 signatures in 0.885 s, a 209 KiB proof,
4.5 ms to verify (V).

It is the design to watch and not to adopt for the corridor:

- A proof of 200 KiB or more is costly as calldata.
- The only EVM verifier measured costs about 10.7M gas and exceeds the
  contract size limit.
- Signer keys are stateful, which adds an operational failure mode the
  super-nodes do not have today.
- It is built for thousands of signers. The corridor has nine.

### 6.3 Proof of quorum in a zkVM

Proving seven ML-DSA verifications in SP1 and checking one proof on-chain
is cheap in gas (about 270k). Two cautions:

- The on-chain wrapper is a BN254 pairing proof. A quantum attacker could
  forge the wrapper even though the inner signatures are post-quantum.
- No published cycle count for ML-DSA-65 itself was found. Section 5.5
  gives the nearest measurements (Dilithium5 in SP1, ML-DSA-44 in RISC
  Zero) and an estimate. [slh-dsa-stark-bench][slhbench] adds SLH-DSA in
  RISC Zero: 8 signatures in 28.9 s on a high-end GPU, 222 KiB.

### 6.4 No aggregation

With nine signers, the lowest-risk path that runs today is to verify seven
individual ML-DSA signatures in Solidity.

| Option | Per verify | Seven signatures | Calldata for seven |
|---|---|---|---|
| ML-DSA-44, Fireblocks, key in a data contract | about 1.23M gas | about 8.6M gas | about 17 KB of signatures |
| ML-DSA-65, ZKNOX `exp/packed-verifier`, key in a stored blob | about 1.54M gas | about 10.8M gas | about 23 KB of signatures |
| ML-DSA-65, ZKNOX `mldsa87`, key in calldata | 1.20M execution + 0.54M calldata | about 12.2M gas | about 290 KB (seven 38 KB keys plus signatures) |

These totals are arithmetic on the self-reported per-verify figures, not
measurements. They are acceptable on an L2 or the SUWAPPU testnet and
expensive on L1.

For a fixed set of nine known keys, the stored-key layout is the better
fit: each key is published once and the per-epoch transaction carries only
signatures. The calldata layout is designed for accounts whose keys are
not known in advance; at about 290 KB per transaction it would also exceed
typical transaction-size limits. The newest arithmetic lives on the
calldata branch, so adopting it for the corridor means porting the
stored-key loading onto it.

## 7. Transport, hybrid KEM and libraries

| System | Source | Hybrid construction |
|---|---|---|
| TLS 1.3 | Standardised hybrid group X25519MLKEM768 (U) | Concatenated shared secrets into the key schedule |
| age | [FiloSottile/age][age], BSD-3-Clause (V) | Native `mlkem768x25519` recipients since v1.3.0 (V) |
| Signal SPQR | [signalapp/SparsePostQuantumRatchet][spqr], AGPL-3.0 (V) | ML-KEM ratchet, formally verified, mixed with the classical ratchet (V) |
| Rosenpass | [rosenpass/rosenpass][rosen], Apache-2.0/MIT (V) | Feeds a rotating pre-shared key to WireGuard (V) |
| Quantus p2p | [Quantus-Network/chain][quantus] (V) | ML-KEM-768 inside an extended Noise handshake (V) |

No libp2p post-quantum Noise implementation was found.

Libraries:

| Library | Source | Notes |
|---|---|---|
| mlkem-native, mldsa-native | [pq-code-package][pqcp] (V) | FIPS 203 and 204; CBMC and HOL-Light proofs; used by AWS-LC and liboqs (V). Strongest verification story found |
| liboqs | open-quantum-safe/liboqs, MIT (V) | README still advises against production reliance (V) |
| RustCrypto `ml-dsa` | RustCrypto/signatures (V) | FIPS 204 final; never independently audited (V). This is the crate the `zkvm/` guests use |
| libcrux | cryspen/libcrux (V) | Verified code, pre-release (V) |
| `pqcrypto` (PyPI) | backbone-hq/pqcrypto (V) | 1.0.0 replaced the backend with unaudited Rust crates (V) |

`pyproject.toml` already holds `pqcrypto` below 0.5 on purpose and
documents why. This survey found nothing that argues for changing that
pin.

## 8. Checked and rejected

| Project | Reason |
|---|---|
| Naoris | Mainnet claimed (U); GitHub organisation has no public repositories (V) |
| Monolythium | Node source private until mainnet (V) |
| QANplatform | SDKs and docs only; no node source seen (V) |
| Bitcoin BIP-360 | Draft; specifies no PQ signature; running code only in BTQ's fork (V) |
| Solana L1 | Falcon code in clients, not activated (U). A Winternitz vault program exists as a contract-level pattern |
| Aptos, Sui, Hedera, Starknet, Zcash | Proposals or roadmaps; no shipped PQ signature path confirmed (U) |
| Project Eleven | Open tooling and a registry, not a chain |
| Neo, SuperNeo, Hachi, Cyclo | Paper only, or no licence |
| Shamir-nonce threshold ML-DSA preprint | No repository linked |
| LayerZero Aerie | Large aggregation numbers in press; no code released |
| Wormhole, Hyperlane, Axelar, IBC | No post-quantum quorum code or roadmap found |
| Quranium, Tectonic, Sei, Tron, Mina, Aztec, Besu | Searches returned nothing usable. Not assessed, rather than confirmed absent |

## 9. Recommendation

In order. Each item that touches `contracts/`, the wire format, or a
dependency needs its own plan and ticket under the existing rules; this
document commits none of them.

1. **Verify ML-DSA on-chain with no aggregation.** Each super-node signs
   the state root with ML-DSA-65; the contract checks seven signatures.
   Start from the ZKNOX experimental branch or a port of the Fireblocks
   verifier. Keep BLS alongside as a hybrid until a verifier is audited.
   Both LTP to-dos already listed in
   [`PQ_ONCHAIN_VERIFICATION.md`](PQ_ONCHAIN_VERIFICATION.md) section 6
   (sign a 32-byte digest, add `ctx`) are prerequisites.
2. **Finish one real SP1 proof and retire simulated mode.** This closes
   the forgeable fast path. Follow the route in section 5.5: measure
   cycles with `execute`, move off the SP1 version covered by the
   advisory, request Groth16, and prove with enough memory. Build `zkvm/`
   in CI.
3. **Correct the documentation claims** listed in section 2.
4. **Add the hybrid KEM** already in the backlog (ML-KEM-768 + X25519),
   which is what age and TLS converged on.
5. **Use the composite signature or remove it.** `src/ltp/hybrid.py` has
   no caller.

Do not adopt, for now: threshold ML-DSA (n ≤ 6), Ringtail, lattice proof
systems, Lean-style aggregation for nine signers, or a Groth16-wrapped
proof presented as the post-quantum story.

Watch: EIP-8355, NIST threshold submissions (2027), a hash-based on-chain
wrapper from any production zkVM, and a practical leanVM EVM verifier.

## 10. Sources

Primary pages fetched during the survey, beyond the repositories linked
above:

- QRL: <https://www.theqrl.org/press/qrl-launches-testnet-v2-for-its-postquantum-evmfriendly-blockchain/>
- Algorand: <https://algorand.co/technology/post-quantum>
- NEAR (secondary): <https://cryptobriefing.com/near-protocol-post-quantum-key-support/>
- Lean Ethereum: <https://pq.ethereum.org/>, <https://hackmd.io/@goatresearch/H1G2tOCwGx>
- Tezos: <https://spotlight.tezos.com/why-post-quantum-why-now/>
- SP1 proof types and wrapper: <https://docs.succinct.xyz/docs/sp1/generating-proofs/proof-types>, <https://blog.succinct.xyz/veil>
- RISC Zero verifier contracts: <https://dev.risczero.com/api/blockchain-integration/contracts/verifier>
- WHIR on EVM: <https://ethresear.ch/t/evm-verification-of-whir-over-a-31-bit-field/24902>
- Lattice Jolt: <https://a16zfrontier.com/posts/article/lattice-snarks-jolt-post-quantum-faster>
- Fireblocks verifier write-up: <https://www.fireblocks.com/blog/post-quantum-signatures-ethereum-cheaper-gas>
- Kohaku deployments: <https://raw.githubusercontent.com/ethereum/kohaku/master/packages/pq-account/deployments/deployments.json>
- EIPs: <https://eips.ethereum.org/EIPS/eip-8051>, <https://eips.ethereum.org/EIPS/eip-8355>, <https://eips.ethereum.org/EIPS/eip-8052>, <https://eips.ethereum.org/EIPS/eip-7932>, <https://eips.ethereum.org/EIPS/eip-8141>
- NIST threshold call: <https://csrc.nist.gov/Projects/threshold-cryptography/tcall-1>
- Signal SPQR: <https://signal.org/blog/spqr/>

[ethdil]: https://github.com/ZKNoxHQ/ETHDILITHIUM
[ethfal]: https://github.com/ZKNoxHQ/ETHFALCON
[fb]: https://github.com/fireblocks-labs/evm-ml-dsa-verifier
[kohaku]: https://github.com/ethereum/kohaku
[sphm]: https://github.com/nconsigny/SPHINCS-
[stylus]: https://github.com/multivmlabs/pq-smart-wallet
[leansig]: https://github.com/leanEthereum/leanSig
[leanms]: https://github.com/leanEthereum/leanMultisig
[algosp]: https://github.com/algorand/go-stateproof-verification
[algo]: https://github.com/algorand/go-algorand
[zond]: https://github.com/theQRL/go-zond
[qrllib]: https://github.com/theQRL/go-qrllib
[quantus]: https://github.com/Quantus-Network/chain
[btq]: https://github.com/btq-ag/btq-core
[ckb]: https://github.com/cryptape/quantum-resistant-lock-script
[abec]: https://github.com/pqabelian/abec
[cell]: https://github.com/demlabs-cellframe/cellframe-node
[sp1]: https://github.com/succinctlabs/sp1
[r0]: https://github.com/risc0/risc0
[openvm]: https://github.com/openvm-org/openvm
[pico]: https://github.com/brevis-network/pico
[airb]: https://github.com/matter-labs/zksync-airbender
[stwo]: https://github.com/starkware-libs/stwo
[p3]: https://github.com/Plonky3/Plonky3
[binius]: https://github.com/binius-zk/binius64
[jolt]: https://github.com/a16z/jolt
[ssw]: https://github.com/privacy-ethereum/sol-spartan-whir
[slhbench]: https://github.com/remix7531/slh-dsa-stark-bench
[swp3]: https://github.com/ethereum/sol-whir-p3
[d5p]: https://github.com/gabrielemorciano/dilithium5-poseidon
[kpq]: https://github.com/KaspaKii/kaspa-pq-zk-bench
[hachi]: https://github.com/a16z/hachi
[labrador]: https://github.com/lattice-dogs/labrador
[lazer]: https://github.com/lazer-crypto/lazer
[lfold]: https://github.com/NethermindEth/latticefold
[ringtail]: https://github.com/daryakaviani/ringtail
[age]: https://github.com/FiloSottile/age
[spqr]: https://github.com/signalapp/SparsePostQuantumRatchet
[rosen]: https://github.com/rosenpass/rosenpass
[pqcp]: https://github.com/pq-code-package
