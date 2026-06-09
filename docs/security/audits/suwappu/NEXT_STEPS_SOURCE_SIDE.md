# Suwappu Bridge — Source-Side NEXT-STEPS Roadmap

**Doc:** `docs/security/audits/suwappu/NEXT_STEPS_SOURCE_SIDE.md`
**Canonical source-side roadmap for the Suwappu PQ bridge (GSX-DAG home corridor).**
**Date:** 2026-06-08 · **Repo (destination):** `/Users/toma/gsx/gsx-lattice-protocol` · **Source chain:** `suwappu-dag` under `/Users/toma/gsx/gsx-dag`

> All source-chain anchors are crate-qualified (`crates/suwappu-*/src/...`). Resolve them against the live worktree only — there are stale copies of these files under sibling `gsx-*` worktrees; do not anchor against those.

---

## 1. Honest status

The destination half of the trust-minimized corridor is **merged and green (473 tests)**. PR #14 (k-of-N threshold mint verifier + SP1 chain/instance binding) and PR #16 (P10 source-lock proof seam + real MPT verifier + header oracles) are merged; the GSX-DAG validator-registry + quorum-header-oracle work landed as part of that baseline (note: PR #17, which proposed them standalone, is **CLOSED, not merged** — do not attribute the registry/oracle to #17). The frozen destination contracts `GsxDagQuorumHeaderOracle`, `GsxDagValidatorRegistry`, and `StorageProofSourceLockVerifier` compile and are waiting. **THE KEY GAP: every one of these verifiers is UNWIRED on the source side — GSX-DAG validators do not sign anything the destination consumes.** There is no header-attestation duty, no epoch-transition certificate, and no provable EVM-state-root path on the home chain; the daemon signs *only* certificates per tick. Beyond unwired, the storage-proof path is additionally **structurally unsupplied** (the home chain has no EVM, no keccak-MPT state root, no per-lock storage slot, no round-indexed signed root). The live system therefore reduces to a **single-ECDSA-key, trusted-relayer custody model** — that is what ships today. This is a **validator-quorum side-attestation trust class** (sync-committee style: an honest >2/3-stake quorum of the tracked set, NOT a consensus light client, NOT trustless, NOT end-to-end post-quantum, with NO coupling to the Mysticeti-C commit rule). The relayer in every variant below is **untrusted for safety** (the contract re-verifies signatures, strict pkHash ordering, and the stake threshold) but **relied on for liveness/censorship** (it is the sole submission path and can stall a transition by withholding).

---

## 2. Source-side signing-duty roadmap

Three net-new duties, each with the smallest real first PR into `suwappu-dag` and (where applicable) the exact signing preimage verified byte-for-byte against the frozen contract.

### 2.0 The two cross-cutting deploy-binding decisions (apply to BOTH the header and epoch duties)

Both the header oracle and the validator registry pack a `networkId` as a **`uint256`** at preimage offset 32. The consensus `network_id` in GSX-DAG is a **Rust `String`** (`crates/suwappu-node/src/config.rs:163`, free-form ASCII e.g. `"perf"`, `"suwappu-perf-7r"`) and is fed into `Certificate::hash` as raw UTF-8 (`network_id.as_bytes()`, `crates/suwappu-consensus/src/cert.rs:117`). A UTF-8 string does **not** widen to a `uint256` — there is no integer to widen, and **no numeric network/chain id exists anywhere in the codebase** (the L2 `chain_id_hash` is an unrelated `[u8;32]`).

**Therefore the bridge requires a NET-NEW, currently-UNDEFINED design decision:** a canonical `String → uint256` mapping (e.g. `bridge_network_id = uint256(keccak256(bytes(network_id)))`, or a registered integer per network) that is (a) DEFINED once, (b) applied byte-identically on the GSX-DAG signer side, and (c) configured identically into the deployed registry AND oracle `networkId` immutables at deploy time. Until this mapping is specified, no digest can bind to the network. The signer must **never** reuse the consensus `network_id` String — doing so produces a digest the contract never computes and every quorum check fails silently. Carry one `bridge_network_id: U256` config value derived from that mapping into both duties.

The second bound value is the **deployed contract address**, which is folded into each digest as `address(this)` — and it differs per duty: the header duty binds the **oracle** address (`bridge_oracle_address: [u8;20]`), the epoch duty binds the **registry** address (`bridge_registry_address: [u8;20]`). Both must equal the on-chain deployment or every check fails silently.

### 2.A Header-attestation duty

**What it attests.** `blockNumber` = the DAG `round` at which a block commits (`ExecutionReport.round`, `crates/suwappu-execution/src/block.rs:40`); `stateRoot` = `ExecutionReport.post_root` (`block.rs:49`), the home chain's **BLAKE3 L1 state root — NOT an EVM-MPT root**. The oracle NatSpec says "EVM state root," which is aspirational; this duty is usable only as an opaque finalized-header anchor, not as something a storage-proof verifier can prove against (see §2.C and §3 residual R0).

**Exact signing preimage** — verified byte-for-byte against `contracts/src/verifiers/GsxDagQuorumHeaderOracle.sol:31,81-85,107-113`:

```
HEADER_DOMAIN = keccak256("SUWAPPU_GSXDAG_HEADER_V1")   // 32B compile-time constant, hard-pinned literal; NOT BLAKE3'd, packed raw

preimage = abi.encodePacked(        // 148 bytes, no length words, no padding
  [  0.. 32)  HEADER_DOMAIN          32B  raw bytes32
  [ 32.. 64)  bridge_network_id      32B  uint256 big-endian   (U256::to_be_bytes::<32>)
  [ 64.. 84)  bridge_oracle_address  20B  raw (no left-pad)
  [ 84..116)  block_number           32B  uint256 big-endian   (round as u64 -> U256 BE)
  [116..148)  state_root             32B  raw bytes32
)
digest = blake3(preimage)                       // 32 bytes (single BLAKE3 pass)
sig    = mldsa::sign(&digest, &self_mldsa_sk)?.0 // detached ML-DSA-65; .0 unwraps the Signature(Vec<u8>)
```

`epoch` is **NOT** in the preimage — it is only a `submitHeader` param for set selection/staleness. On-chain validation feeds `pubkey ‖ sig ‖ digest` to precompile `0x0101`, valid iff `out[31]==0x01` (`contracts/src/verifiers/GsxDagValidatorRegistry.sol:179-187`). The relayer's `pubkeys[]`/`sigs[]` arrays must be strictly increasing by `keccak256(pubkey)` across the entire array (reverts `UnsortedOrDuplicate` otherwise); quorum is `totalStake*2/3 + 1`.

**Capture point (corrected anchor).** The `(round, post_root)` pair is co-available **only** at commit, at **`crates/suwappu-node/src/daemon.rs:1414`**, where `execute_block` runs under the `inner` lock and its `ExecutionReport` is **currently discarded** (`let _ = execute_block(&mut inner.substrate, &block);`). Bind that return and push `(report.round, report.post_root)` — equivalently `(cert_round, inner.substrate.state_root())` — into a new bounded `state.bridge_header_buffer: RwLock<VecDeque<(u64,[u8;32])>>`. The epoch-boundary/governance region at `daemon.rs:1468-1497` does NOT have `post_root` in scope and is the wrong anchor. No round-indexed root archive exists (`BlockView` has no `state_root`; `suwappu_getL1StateRoot` is latest-only), so the pair cannot be reconstructed later — it must be captured here.

**Signing task.** Spawn `run_bridge_attester` as a sibling task at the spawn block `daemon.rs:585-602` (cloning `state`, the static `self_mldsa_sk` from `daemon.rs:583`, plus `bridge_oracle_address` + `bridge_network_id`), on its own `tokio::time::interval` independent of the 250ms consensus tick so it never contends with the `sign_cert` hot path. Gate on `self` being a current signer in `state.authority_registry`. Gossip a new `HeaderAttestation { block_number, state_root, authority_id, pubkey, sig }` wire variant over the existing `outbound` broadcast path; collect into `state.header_attestations: RwLock<HashMap<(u64,[u8;32]), HashMap<u32,(Vec<u8>,Vec<u8>)>>>`, locally ML-DSA-verifying each peer sig before storing. Expose via a new RPC `suwappu_getHeaderAttestations` (mirror `get_l1_state_root` at `crates/suwappu-rpc/src/methods.rs:294-300`; add the dispatch arm in `router.rs:204-216`; add a `StateView` trait method next to `l1_state_root` at `crates/suwappu-rpc/src/context.rs:261`), returning arrays **pre-sorted ascending by `keccak256(pubkey)`** so the relayer passes them straight into `submitHeader`. The node never calls `submitHeader` itself (no EVM/keccak tx path on the home chain) — it only serves materials; the relayer holds the EVM key.

> Note: the `rpc_adapter.rs:328-331` anchor cited in the source maps is **invented** — there is no `rpc_adapter.rs` in `crates/suwappu-rpc/src/`. The real chain is `methods.rs:294-300` → the `StateView::l1_state_root` trait (`context.rs:261`).

**IMMEDIATE NEXT PR (first slice):** `bridge: header-attestation digest + signer (suwappu-crypto/suwappu-node)`. Pure function + unit test only — **no daemon wiring, no RPC, no gossip.** Add `crates/suwappu-node/src/bridge_header.rs` with `header_digest(network_id: U256, oracle: [u8;20], block_number: u64, state_root: [u8;32]) -> [u8;32]` and `sign_header(...) -> Vec<u8>` (the latter does `mldsa::sign(&digest, sk)?.0` — unwrap the `Signature` wrapper). The deliverable's teeth is a **golden cross-language vector**: generate the expected 32-byte digest from the contract's `headerDigest(blockNumber, stateRoot)` view (`GsxDagQuorumHeaderOracle.sol:107`) via a one-off `forge` script, paste it as a fixture, and assert byte-for-byte equality — this pins the 148-byte packing including networkId-as-uint256 and the 20-byte address. Then emit `(pubkey, sig, digest)` to a fixture a paired Solidity test feeds to `_mldsaValid` (`GsxDagValidatorRegistry.sol:179-187`), asserting `out[31]==0x01`. This converts the entire silent-quorum-failure risk into one deterministic vector with zero consensus surface touched.

### 2.B Epoch-transition certificate

**What it attests.** The **NEW** epoch's validator set `(newEpoch, newPkHashes, newStakes)`, signed by a >2/3-stake quorum of the **OLD/current** epoch's validators. The contract requires `newEpoch == currentEpoch + 1` and verifies against the current set (`GsxDagValidatorRegistry.transitionEpoch`, `:85-107`). Epoch 0 is governance-bootstrapped (`bootstrapEpoch0`, the trusted root). The signing key is the same `self_mldsa_sk` used for certs — `apply_governance_intent` seats the identical `mldsa_public_key` into both the Authority and Validator rings (`daemon.rs:1591`/`:1609`), so one node key serves both capacities.

**Per-validator leaf — the load-bearing sort.** For each seated `ValidatorMember`: `pkHash = keccak256(public_key_bytes)`, `stake = stake_suwappu` (`u128 → uint256`). **Sort `(pkHash, stake)` pairs by `pkHash` ASCENDING, carrying stake in that permutation — NOT by id.** `members()` yields ascending-*id* order (`crates/suwappu-validator/src/registry.rs:124`), but `_installSet`/`_verifyQuorum` require strictly-increasing `keccak256(pubkey)` (`:158`/`:130`). Ascending-id ≠ ascending-pkHash; emitting in id order bricks the install.

**Exact signing preimage (two-hash split)** — verified against `GsxDagValidatorRegistry.sol:31,96-98`:

```
// Stage 1 — keccak256 over STANDARD ABI (head/tail, NOT packed):
setHash = keccak256(abi.encode(newEpoch /*uint256*/, newPkHashes /*bytes32[]*/, newStakes /*uint256[]*/))
//   newPkHashes strictly increasing; newStakes index-aligned, all non-zero; equal non-empty lengths.

// Stage 2 — BLAKE3 over PACKED encoding (148 bytes):
digest = blake3(abi.encodePacked(
  [  0.. 32)  EPOCH_DOMAIN = keccak256("SUWAPPU_GSXDAG_EPOCH_V1")   32B raw, hard-pinned literal
  [ 32.. 64)  bridge_network_id          32B  uint256 big-endian
  [ 64.. 84)  bridge_registry_address    20B  raw — address(this) is the REGISTRY, not the oracle
  [ 84..116)  newEpoch                   32B  uint256 big-endian   (appears twice: here AND inside setHash)
  [116..148)  setHash                    32B  raw bytes32
))
sig = mldsa::sign(&digest, &self_mldsa_sk)?.0   // .0 unwraps the Signature wrapper
```

Do not conflate the two hashes or the two encoders: `setHash` is **keccak256** over **standard ABI**; the final `digest` is **BLAKE3** over **packed** bytes; signers sign the BLAKE3 output. All uint256 are 32-byte big-endian (Rust is little-endian — convert explicitly). This duty pulls **keccak256 + a Solidity-ABI codec** into a BLAKE3-native codebase (GSX-DAG has neither today) — the single most likely place parity silently breaks.

**Hook point.** Inside the boundary block at `daemon.rs:1479-1497`, **after** the `apply_governance_intent` drain loop completes and the registries reflect the new set, snapshot the post-drain validator set, sort by pkHash, compute `setHash`/`digest`, sign this node's leaf, and publish it for aggregation. Determinism is the whole game: every honest validator must sign the byte-identical digest, which holds only because the boundary drain is atomic across the mesh (the Issue #18 rationale, `daemon.rs:140-148`). A new collector accumulates `(pubkey, sig)` leaves until valid signers exceed `totalStake[currentEpoch]*2/3 + 1`; a net-new off-chain relayer submits `transitionEpoch(...)`.

**Unresolved edge case to flag (do not paper over):** `epoch_for(round) = round / rounds_per_epoch` can leap >1 epoch on sparse commits (`boundary_crossed_by` only checks `> current`, `daemon.rs:183-193`), but the contract advances exactly one epoch per call and holds no data for skipped epochs. Either GSX-DAG must emit one cert per intermediate epoch (sets the in-memory model does not currently materialize) or liveness must guarantee no skips. The first slice does not resolve this.

**IMMEDIATE NEXT PR (first slice):** a pure `epoch_transition_digest(validators: &[(Vec<u8>, u128)], new_epoch: u64, network_id: U256, registry_addr: [u8;20])` returning `{new_pk_hashes, new_stakes, set_hash, digest}` — performing the keccak pkHash, the pkHash sort, the standard-ABI `setHash`, and the packed BLAKE3 `digest` — paired with a **forge fixture asserting byte-equal `setHash` AND `digest`** against the contract's exact expressions. Zero daemon/signing/aggregation/RPC changes. This isolates the entire parity surface (keccak256, two distinct ABI encoders, the two-hash split, big-endian conversion, pkHash sort). Deferred to later slices: the boundary signing hook, the stake-weighted aggregator + threshold gate, RPC/event exposure, the relayer, the epoch-jump>1 resolution, and the `bridge_network_id` mapping (§2.0).

### 2.C Provable source-stateRoot path (storage-proof corridor)

**This is unwired AND structurally unsupplied.** `StorageProofSourceLockVerifier.verifyLock` (`StorageProofSourceLockVerifier.sol:52-98`) pulls `headerOracle.headerStateRoot(...)`, then MPT-proves the Vault account → `storageRoot` → three slots of `commits[commitId]` (`destRecipient @ structSlot+2`, `amount @ +3`, packed `status==LOCKED @ +6 >> 64`, `structSlot = keccak256(abi.encode(commitId, 7))`). This requires a **standard Ethereum secure-MPT account+storage trie** — exactly `eth_getProof`. The home chain provides none of it:

- **G1 (dominant): no keccak-MPT state tree.** The L1 root is a flat `BLAKE3("SUWAPPU-STATE-ROOT-V2" ‖ balances_root ‖ bytes_state_root)` (`crates/suwappu-execution/src/substrate.rs:972-987`). No keccak, RLP, Patricia trie, or `eth_getProof` exists. The L2 is no escape: `compute_state_root` is also a flat ledger hash, and revm-in-guest is scaffolding gated behind unresolved #88, never landed (L1 or L2).
- **G2: no per-commit storage slot.** `Intent::L1Lock` is a bare escrow balance delta with no event and no `commitId → {recipient, amount, asset}` record (`substrate.rs:2533-2562`); on the production backend it is a **no-op** (`crates/suwappu-execution/src/suwappu_db_substrate.rs:202-216`). The verifier's pinned layout describes the destination `SuwappuVault.sol`, which has no home-chain counterpart.
- **G3: no round-indexed root over RPC.** `suwappu_getL1StateRoot` is latest-only; `BlockView` has no `state_root`; the one signed `(round, state_root)` checkpoint object is not exposed (`crates/suwappu-execution/src/checkpoint.rs`).
- **G4: no signing duty** — the §2.A header duty is its prerequisite.

**Required gap-closure ORDER (execution FIRST, signing LAST):** (1) MPT-proofable state + EVM execution (closes G1); (2) a home-chain Vault writing `commits[commitId]` at the pinned layout, honored by the production backend, un-stubbing the no-op (closes G2); (3) round-indexed root retrieval over RPC (closes G3); (4) **LAST**, the §2.A validator signing duty. Signing a flat BLAKE3 root before G1/G2 produces something `extractAccountFromProof` rejects structurally — wrong order is the trap. **Caveat:** the production backend plans IPA-over-banderwagon (Verkle) at launch (`suwappu_db_substrate.rs:266-279`), incompatible with a keccak-MPT verifier — so this entire corridor is a **phase-1-bounded bet**; the Verkle migration would force the consensus-signature `ISourceLockVerifier` variant instead. The home chain's actual *implemented* cross-chain primitive is the LTP off-chain 7-of-9 BLS super-node attestation (`crates/suwappu-ltp/src/attestation.rs:85-106`), deliberately distinct from this storage-proof model.

**IMMEDIATE NEXT PR (first slice):** a **destination-side conformance harness** that de-risks the corridor before any home-chain work — explicitly NOT a hand-rolled MPT. Stand up a local EVM (anvil/revm) hosting the already-merged `SuwappuVault.sol`, perform a real lock to populate `commits[commitId]`, then assert that (a) `eth_getProof` against that account yields proofs the merged `StorageProofSourceLockVerifier` accepts end-to-end (account → storageRoot → all three slot proofs → `verifyLock == true`), confirming the pinned layout (base slot 7, `+2/+3/+6 >> 64`) is byte-exact; and (b) a `GsxDagQuorumHeaderOracle` fed that block's root via a mocked quorum returns it through `headerStateRoot`. This pins the exact artifact the home chain must eventually emit (an `eth_getProof`-shaped account+storage proof over `SuwappuVault.commits`) and reduces the home-chain task to one sentence: *make the home chain produce an `eth_getProof`-able account root containing a `commits[commitId]` slot* — i.e. closing G1+G2.

---

## 3. Audit-prep package

> **THIS IS NOT AN AUDIT.** This is an internal reconciliation of the prior agent audit (`SUWAPPU_AUDIT_REPORT.md`, 2026-06-07) against the merged verifier PRs (#14, #16), grounded in a read of the real Solidity/Rust. The custody layer remains NO-GO for mainnet funds. Where this disagrees with the in-repo `GATE.md`, **this wins** — `GATE.md` row 1 ("ALL code findings FIXED + green") overclaims. **Central distinction held at every row: `exists-in-code` ≠ `wired-in-deploy`.** "CLOSED" = mechanism in code AND on the wired/fail-closed path. "MITIGATED-BUT-UNWIRED" = strong mechanism exists but the shipped deploy uses a weaker interim.

### 3.1 Finding-disposition table

| ID | Sev | Title | Reconciled disposition | Basis |
|---|---|---|---|---|
| **C1** | Crit | `MintAdapter.mint` never binds commitId → arbitrary unbacked mint | **MITIGATED-BUT-UNWIRED** | Root closer = storage-proof of `status==LOCKED`+recipient+amount (`StorageProofSourceLockVerifier.sol:80-97` via `SuwappuMintAdapter.sol:202-219`); **no script wires `sourceLockVerifier`.** Wired interim = single-key ECDSA attestation (`SuwappuMintAdapter.sol:224-237`). Trust on one operator key. |
| **C2** | Crit | Refund/unlock-vs-mint cross-domain double-spend | **MITIGATED → residual STILL-OPEN** | Operator attestation over refund digest + status XOR LOCKED→REFUNDED + timelock backstop (`SuwappuVault.sol:475-512`); but same single-key ECDSA verifier, and it attests "refund-eligible" only — does NOT cryptographically prove the destination mint did not occur. Status XOR is same-chain. Cross-domain binding still operator-trusted. |
| **C3** | High | ZK `verifyAndFinalize`: no access control + anchorDigest unbound | **CLOSED** | `isProver` gate + anchorDigest bound into proofId/tag/publicValues (`ZKBridgeVerifier.sol:134,153-164,223-233,328-336`). |
| **P3-1** | Crit | ZK never checks `operatorVkHash` ∈ authorized set | **CLOSED** | `authorizedOperatorVk` required, reverts `UnauthorizedOperator`; fail-closed empty set (`ZKBridgeVerifier.sol:146-148`). |
| **P3-3** | Crit | WrappedToken `DEFAULT_ADMIN_ROLE` = parallel minter | **CLOSED** | Role-admin split; constructor reverts on `admin_==minterManager_` (`SuwappuWrappedToken.sol:76,84-87`); scripts wire a distinct Timelock as minterManager. |
| **P3-5** | High | One lock → N mints across adapter instances | **MITIGATED-BUT-UNWIRED** | Digest binds `block.chainid`+`address(this)`; per-commitId bitmap blocks same-instance replay (`SuwappuMintAdapter.sol:200,224-233`); full closure is the unwired source-proof path. |
| **P3-4** | High | No rate-limit/ceiling on `unlock`/`mint` | **MITIGATED, PARTIALLY WIRED** | Leaky-bucket `dailyReleaseCap` + guardian `pause()` + `emergencyRescuer` wired on mainnet (`SuwappuVault.sol:107,408-441`); **lock-side `setDailyCap` never called → off by default; no M-of-N unlocker.** |
| **P3-7** | Med | Rebasing-token post-lock solvency drift | **CLOSED (mechanism) / per-token gate unwired** | `lockERC20` reverts unless `allowedToken[token]`; `setAllowedToken` admin-gated (`SuwappuVault.sol:285,599`); **no script calls it → allowlist empty = fail-closed (safe).** |
| **P3-2/P3-6** | Low | sp1ProgramVKey zero-default; proofId omits chainId/addr | **CLOSED** | proofId + publicValues bind `block.chainid`+`address(this)`; `_verifySP1` reverts if verifier unset/code-less (`ZKBridgeVerifier.sol:153-164,311-316`). |
| **C4** | High | `_verifySP1` accepts code-less verifier | **CLOSED** (carried) | Report FIXED; consistent with `ZKBridgeVerifier.sol:311-316`. |
| **C5** | Med | Vault FOT under-collateralization (inbound) | **CLOSED** (carried) | Received-balance accounting (`SuwappuVault.sol:296-298`). |
| **C6** | Med | Escrow `sweepUnclaimed` cross-round drain | **NOT RE-EXAMINED** | Report FIXED (forge unit). Flag for auditor. |
| **C7** | Med | Escrow claim not keyed by token | **NOT RE-EXAMINED** | Report FIXED. Not re-verified this pass. |
| **C8** | Med | Guardian selector not bound to target | **NOT RE-EXAMINED** | Report FIXED ("(target,selector) binding sound"). Not re-verified this pass. |
| **C9/FE1** | Prod | Front end displays fabricated proofs as real | **STILL-OPEN (out of this repo)** | Separate `suwappu-bridge` Next.js app; "REAL-wired 2026-06-08" claim is **unverified and outside this repo** — treat as open. |

**Net:** CLOSED — C3, P3-1, P3-3, P3-2/6, P3-7(mechanism), C4, C5. MITIGATED-BUT-UNWIRED — C1, P3-5, P3-4(lock cap off; no M-of-N). MITIGATED→residual STILL-OPEN — **C2**. STILL-OPEN — C9/FE1. NOT RE-EXAMINED (carried) — C6, C7, C8. The trust-minimized source↔dest binding is fixed **as code that exists** but is **not the wired default in any shipped deploy.**

### 3.2 Wired-vs-unwired verifier matrix

| Verifier / mechanism | Exists? | Wired by a deploy script? | Source-side feed exists? | Trust grade |
|---|---|---|---|---|
| **SuwappuEcdsaMintVerifier** (single key) | ✅ | ✅ **EVERY** script (`DeploySuwappuDestination.s.sol:51`, `DeploySuwappuMainnet.s.sol:108-111`) | n/a | **WEAKEST / LIVE** — 1 key = mint authority. The actual shipped model. |
| **SuwappuThresholdMintVerifier** (k-of-N, #14) | ✅ | ❌ wired by NO script | n/a | Stronger, dormant. |
| **StorageProofSourceLockVerifier** (MPT proof) | ✅ | ❌ stood up only by `DeploySp1HeliosOracle.s.sol`; setters printed as manual NEXT steps, never called | ❌ **structurally absent** (§2.C) | Strongest, unwired AND unsupplied. |
| **GsxDagQuorumHeaderOracle** (>2/3 ML-DSA quorum) | ✅ | ❌ unwired | ❌ validators don't sign | Validator-quorum side-attestation; inert without source signers. |
| **GsxDagValidatorRegistry** (epoch set) | ✅ | ❌ unwired | ❌ no source epoch-transition signer | Epoch 0 governance-bootstrapped; rest needs source duty. |
| **Sp1HeliosHeaderOracle** (SP1 Helios LC) | ✅ | ⚠️ `DeploySp1HeliosOracle.s.sol` only; adapter wiring manual | depends on Helios | Shor-broken (Groth16/BLS12-381), not PQ. |
| **Refund verifier** (C2 gate) | ✅ | ✅ — but **same single-key ECDSA** (`DeploySuwappuMainnet.s.sol:122`) | n/a | Attests "refund-eligible" only; no cross-domain proof. |

**Reading:** the only thing on the live wired path is **single-key ECDSA** for both mint and refund. Every trust-minimizing alternative is code-present but unwired; the two strongest are also unsupplied by the source chain.

### 3.3 Trust-assumptions table

| Layer | What MUST be trusted today | What would relax it (state) |
|---|---|---|
| **Source consensus** | Honest >2/3 stake; certs BLAKE3-then-ML-DSA-65 signed (`cert.rs:117`); `self_mldsa_sk` static for process lifetime, no rotation (`daemon.rs:530`); registries in-memory only, no on-chain set. | On-chain validator-set + key rotation. Does not exist. |
| **Source state root** | Flat BLAKE3 over balance+bytes maps, NOT an MPT (`substrate.rs:972-987`); production `L1Lock` is a no-op (`suwappu_db_substrate.rs:202-216`). | EVM/MPT + real lock event/slot. None exist. |
| **Source cross-chain (designed)** | Off-chain 7-of-9 BLS super-node quorum attests `(source_height, state_root)` (`attestation.rs:85-106`) — the LTP "bridgeless" model, deliberately NOT a storage-proof bridge and NOT the ML-DSA quorum oracle; the daemon only *verifies* pre-aggregated attestations and **fails OPEN** (`ltp_unverified`) when no corridor is registered. The checkpoint `(round,state_root)` is ML-DSA-co-signed but not RPC-exposed. | Validators ML-DSA-signing the oracle preimage. UNWIRED — first-of-its-kind duty (§2.A). |
| **Relayer (mint)** | A single ECDSA key honestly mints only against real source locks. Key compromise = unbacked mint. Bitmap + chainid/address binding prevent *replay*, not *forgery by the key holder*. Untrusted for safety, relied on for liveness. | k-of-N (exists, unwired) or storage-proof (exists, unwired+unsupplied). |
| **Relayer (refund)** | The same key attests refund-eligibility AND that the destination mint did not occur. No on-chain proof of the negative. | Storage-proof of destination mint-status. Unwired path only. |
| **WrappedToken** | Timelock minterManager + role-admin split; DEFAULT_ADMIN cannot mint. | — (CLOSED). |
| **Vault custody** | Governance allowlists each asset (fail-closed empty default); release cap + guardian + Timelock rescuer on mainnet. Lock-side cap off by default. | Wire `setDailyCap`; add M-of-N unlocker. |
| **ZK finalization** | SP1 verifier + authorized-vk set correctly provisioned; cryptography is **Shor-broken (Groth16/BLS12-381), NOT PQ**. Access control + binding CLOSED. | On-chain ML-DSA (P5b precompile built, NOT wired into this path). |
| **Front end** | Must be trusted not to render fabricated proofs as real (separate repo, out of scope). | Real wiring (claimed 2026-06-08, unverified). |

### 3.4 Residual-risk list

- **R0 — HEADLINE:** `StorageProofSourceLockVerifier` and `GsxDagQuorumHeaderOracle` are not merely undeployed — they are **structurally unsupplied by the source chain** (no EVM/MPT root, no lock event or per-deposit slot, no round-indexed signed root over RPC, no validator signing loop). Even if wired tomorrow they would have nothing to prove against. The trust-minimized path is **a destination half with no source half.** Score the bridge on the **ECDSA path**, not the dormant verifiers.
- **R1 — Single-key mint/refund authority (C1, C2):** one ECDSA key compromise → unbacked mint and/or false refund (Ronin/Wormhole bug class).
- **R2 — Cross-domain refund binding is operator-trusted (C2 residual):** Vault status XOR is same-chain; cannot observe the destination mint.
- **R3 — Lock-side rate cap off by default (P3-4):** `setDailyCap` never called; no M-of-N unlocker.
- **R4 — PQ claim does not reach live custody:** on-chain custody/finalization is NOT PQ today (ZK mode is Shor-broken). P5b ML-DSA precompile built but not wired into mint/unlock/finalize.
- **R5 — `contracts-secaudit` cannot gate:** the suite is RED at baseline (LTPMultiSig deprecation breaks SCN_004/008/009 + LTPAnchorRegistry multisig tests). Repo hard-rule "secaudit green" is currently impossible — no automated security gate is enforcing anything.
- **R6 — Source-chain operational trust:** static signing key (no rotation), in-memory registries, admit-lazy/exit-eager `n_authorities` asymmetry — all sit underneath any future bridge attestation.
- **R7 — `GATE.md` overclaim:** row 1 is inaccurate; C6/C7/C8 are report-FIXED but not re-verified this pass.
- **R8 — Front end (C9/FE1):** out-of-repo; "real-wired" claim unverified. A UI rendering fabricated proofs as real is a fund-loss vector independent of the contracts.

### 3.5 Destination P1 punch-list

| # | Item | State | Detail |
|---|---|---|---|
| **P1-1** | `SuwappuFeeCollector.sol` | **DOES NOT EXIST** | No file/reference under `contracts/src/`. The Vault accrues `feeBps` internally; there is no separate collector contract. |
| **P1-2** | `BridgeEmitter.sol` | **UNIMPROVED — test scaffolding, not custody emitter** | (a) `payloadHash` is `string` not `bytes32` (`:23,69`); (b) nonce is **global** `nextNonce++`, not per-sender (`:38,68`); (c) no `destChainId` in the event (`:19-25`); (d) no zero-recipient/zero-amount check (`:60-70`), permissionless default. |
| **P1-3** | Bricked deploy scripts | **RUNTIME-BRICKED** (compile OK, revert on broadcast) | `DeployTestnet.s.sol:38`, `DeployL2.s.sol:50`, `DeployMainnet.s.sol:86` each `new LTPMultiSig(...)` whose constructor unconditionally reverts (`LTPMultiSig.sol:80` "DEPRECATED"). Same deprecation holds `contracts-secaudit` RED (R5). Healthy custody scripts (`DeploySuwappuDestination/Mainnet/Vault`, `DeploySp1HeliosOracle`) don't instantiate LTPMultiSig — but none wire the threshold verifier, and only `DeploySp1HeliosOracle` touches the source-lock path (manual NEXT steps). |
| **P1-4** | Vault → Base Sepolia deploy | **PENDING (from project memory, NOT verified on-chain)** | Pending funding of deployer `0xB377…78e`; **predicted** Vault `0x76688BDb…7cB7F`. Not yet deployed; treat predicted address as unconfirmed. Sourced from memory only, not code triage. |

**Auditor/bounty priority:** (1) the R0 source-side gap dwarfs everything — the trust-minimized verifiers are inert; (2) single-key C1/C2 is the live exploitable surface; (3) P1-3 bricked scripts + R5 RED gate block clean automated assurance; (4) P1-1 FeeCollector is missing; (5) P1-2 BridgeEmitter is unsafe but is scaffolding — confirm it is on no funded path before deploy.

**Bottom line for the external reviewer:** Score the bridge as a **single-ECDSA-key, trusted-relayer custody system** — that is what ships. The post-quantum, threshold, storage-proof, and validator-quorum machinery all exist in code but are **unwired**, and the two strongest are **also unsupported by the source chain**, which today exposes no MPT root, no lock event, no round-indexed signed root, and no validator signing duty. Independent audit + funded bounty remain hard preconditions before any real funds. Nothing here was independently audited.

---

## 4. Doc hygiene

`docs/security/audits/suwappu/P11_GSXDAG_CONSENSUS_LIGHT_CLIENT.md` is **mis-named**. The contract it documents was renamed to **`GsxDagQuorumHeaderOracle`**, and "Consensus light client" **overclaims** the trust model: this is a **validator-quorum side-attestation** (sync-committee trust class — an honest >2/3-stake quorum of the tracked ML-DSA set), with NO DAG-causality / Mysticeti-C commit-rule reconstruction, NOT trustless, NOT end-to-end PQ. Rename the file (e.g. `P11_GSXDAG_QUORUM_HEADER_ORACLE.md`) and reframe its body to the quorum-side-attestation language used throughout this doc, fixing inbound references (the contract NatSpec citations and any links). Until renamed, the doc name itself is a trust-model overclaim in the audit trail.