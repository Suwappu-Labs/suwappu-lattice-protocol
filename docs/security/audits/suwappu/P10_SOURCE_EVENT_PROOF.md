# P10 — Trust-Minimized Source-Lock Proof (closing LTP-A-001 the real way)

Date: 2026-06-08. Status: **DESIGN SPEC** (no code yet). Owner decision: "the actual fix."

## 0. Why this exists

Every audit of this bridge lands on the same residual: **the destination `SuwappuMintAdapter.mint`
never proves that a real `Locked` event happened on the source chain.** Mint correctness rests on a
trusted relayer/operator key (now a k-of-N quorum after PR #14, but still *attestation*, not *proof*).
This is LTP-A-001 and the Ronin/Wormhole/Harmony bug class.

P5b (`P5b_ONCHAIN_PQ.md`) makes the *attestation* post-quantum and consensus-pinned, but an attestation —
even a PQ one over a committee key — is still "someone signed that the lock happened," not a cryptographic
proof that it did. **This document specifies the thing that actually closes the residual: an on-chain proof
that the canonical source Vault recorded the lock, in a finalized source block, with no relayer trust.**

It is explicitly NOT the optimistic anchor-gate (bonded `OptimisticBridgeChallenge` window) — that is
economic/watchtower security, useful as an *interim fallback* (§7) but not a source-event proof.

## 1. The one structural idea

The Vault already persists every lock:

```solidity
mapping(bytes32 => CommitData) public commits;   // SuwappuVault.sol
// commits[commitId].status == LOCKED  after a successful lockETH/lockERC20
```

and `commitId` itself binds every mint-relevant field:

```
commitId = keccak256(abi.encodePacked(
    block.chainid, vault, nonce, from, token, netAmount, destChainId, destRecipient))
```

So proving "the lock happened" reduces to a single, well-understood primitive:

> **Prove that `commits[commitId].status == LOCKED` in the source Vault's storage, under a source-chain
> `stateRoot` that the destination independently trusts.**

This is exactly the **Across V4** design (storage-slot Merkle proof against a ZK-light-client state root).
No new source-side event parsing, no source contract change — the source Vault is already the witness.

## 2. Decomposition (the two hard halves, kept separate)

| Half | What it proves | Primitive | Audited building block | Gas |
|---|---|---|---|---|
| **(A) Header trust** | "this `stateRoot` is a finalized source-chain block" | ZK light client (EVM source) / consensus-sig light client (PQ source) | SP1 Helios (OZ-audited, live in Across V4) | ~280k |
| **(B) Inclusion proof** | "`commits[commitId].status == LOCKED` under that `stateRoot`" | Merkle-Patricia storage proof | Herodotus / Axiom V2 / Relic (audited) | ~400–450k |

Keeping these separate is the whole architecture: (B) is a solved, cheap, audited commodity; (A) is the
trust root and the only place the PQ question lives. We can ship (B) against a *mocked* (A) first, then
swap real header oracles in per source chain without touching custody.

## 3. Two source classes → two header oracles

### 3a. EVM source chains (Base Sepolia now; Ethereum L1 / L2s later) — ZK light client
- **Oracle:** SP1 Helios (`succinctlabs/sp1-helios`, OZ-audited, live in Across V4). A SNARK over the
  Ethereum sync-committee proves beacon→execution `stateRoot`; the on-chain `SP1Helios` contract stores
  verified `(blockNumber → stateRoot)`. ~280k gas/update.
- **PQ caveat (honest):** SP1 Helios wraps the STARK in **Groth16/BN254 → Shor-broken → NOT PQ-sound
  end-to-end** (the exact trap `P5b_ONCHAIN_PQ.md` §3 calls out). On an EVM source this is an *interim,
  non-PQ* trust root. Acceptable as hardening over the relayer; must be documented as non-PQ.
- **Cheaper same-ecosystem variant:** for an Ethereum-anchored L2 source, EIP-4788 (beacon block root in
  the EVM) + a beacon-state proof can avoid a full light client. Track as an optimization.

### 3b. GSX-DAG home chain as source — consensus-signature light client (the PQ path)
- **Oracle:** a destination verifier of GSX-DAG's validator-committee signatures over the block header.
  GSX-DAG consensus is **ML-DSA** → verifying those signatures on the destination is **end-to-end PQ with
  no SNARK wrapper.** This is where P5b's on-chain ML-DSA verification (the `0x0101` precompile on the home
  chain, an ETHDILITHIUM-style verifier or a committee-attestation on EVM destinations) becomes the
  header-trust root, not just the mint attestation.
- **Reality:** no audited ML-DSA EVM verifier exists yet (~5–12M gas direct; `P5b_ONCHAIN_PQ.md` §1). So
  GSX-DAG-source → EVM-destination PQ proof is the *long pole*; interim is a BLS (EIP-2537, ~70k–1.2M gas)
  or threshold-attestation committee proof, documented as not-yet-PQ.
- **Implication:** the only **end-to-end PQ + trust-minimized** corridor is GSX-DAG↔GSX-DAG (both sides
  verify ML-DSA via precompile). EVM destinations are transitively PQ at best — consistent with P5b's
  honest claim posture.

## 4. Contract architecture

```solidity
// The exact source-lock claim. Every field is bound by commitId, so the proof
// reduces to "the canonical Vault on sourceChainId has commits[commitId].status == LOCKED".
struct LockClaim {
    uint256 sourceChainId;
    address sourceVault;     // pinned canonical Vault per sourceChainId (governance-set)
    bytes32 commitId;
    address destRecipient;
    uint256 amount;          // net amount
    uint256 destChainId;     // must == block.chainid on the destination
}

interface ISourceLockVerifier {
    /// @return ok true iff `proof` cryptographically shows commits[commitId].status == LOCKED
    ///         in `sourceVault` on `sourceChainId`, under a source stateRoot this verifier trusts,
    ///         AND the claim fields are consistent with commitId.
    function verifyLock(LockClaim calldata claim, bytes calldata proof) external view returns (bool ok);
}
```

- `ISourceHeaderOracle` (header trust, half A): `headerStateRoot(uint256 sourceChainId, uint256 blockNumber)
  returns (bytes32)`. Implementations: `Sp1HeliosHeaderOracle` (EVM sources), `GsxDagConsensusHeaderOracle`
  (home chain), `HashiAggregatorOracle` (N-of-M redundancy, §7).
- `StorageProofSourceLockVerifier is ISourceLockVerifier` (half B): given `claim` + `proof =
  abi.encode(blockNumber, accountProof, storageProof)`, (1) reads `stateRoot` from the header oracle,
  (2) verifies the account proof for `sourceVault` → its `storageRoot`, (3) verifies the storage proof for
  the slot of `commits[commitId].status` equals `LOCKED`, (4) checks `destChainId == block.chainid` and the
  claim binds `commitId`. Uses an audited MPT library.

### Integration into mint (behind a flag — never breaks testnet)
```solidity
// SuwappuMintAdapter
ISourceLockVerifier public sourceLockVerifier;   // governance-set (Timelock); 0 = disabled
function mint(bytes32 commitId, address recipient, uint256 amount, uint256 sourceChainId, bytes calldata proofOrAttestation) external onlyRelayer {
    ...
    if (address(sourceLockVerifier) != address(0)) {
        LockClaim memory claim = LockClaim(sourceChainId, vaultOf[sourceChainId], commitId, recipient, amount, block.chainid);
        require(sourceLockVerifier.verifyLock(claim, proofOrAttestation), "source lock not proven");
    } else {
        // legacy path: existing IMintAttestationVerifier (k-of-N, PR #14)
    }
    ... mint ...
}
```
When `sourceLockVerifier` is set, the **proof replaces operator trust as the security gate**; the relayer
set + k-of-N attestation (PR #14) degrade to spam/sequencing control (anyone with a valid proof could
otherwise submit). Keep them AND-ed for defense-in-depth during rollout.

### Storage-slot derivation (concrete — verified against the compiled layout 2026-06-08)
`forge inspect SuwappuVault storage-layout` confirms `commits` is at **base slot 7** (slot 0 is
ReentrancyGuard `_status`, so do not assume slot 0). The `CommitData` struct for `commitId` starts at
`structSlot = keccak256(abi.encode(commitId, uint256(7)))`. Field packing: `token`(slot+0), `from`(slot+1),
`destRecipient`(slot+2), `amount`(slot+3), `fee`(slot+4), `destChainId`(slot+5), then `lockedAt`(uint64) and
`status`(LockStatus enum, uint8) **pack together at `structSlot+6`** — `lockedAt` at byte offset 0,
**`status` at byte offset 8**. So the storage proof targets slot `structSlot+6` and the verifier asserts
byte 8 of the value `== 1 (LOCKED)`. (`released[commitId]` lives at base slot 17 for the return-leg proof.)
**Migration risk:** any change to the Vault's storage layout breaks these pinned slots → the layout is a
**stability promise** for any source Vault that destinations prove against (add a layout-lock CI check).

## 5. Phasing (each phase independently shippable + testable)

- **Phase A — seam (small, unblocked):** `ISourceLockVerifier` + `LockClaim` + `ISourceHeaderOracle`
  interfaces; wire `SuwappuMintAdapter.mint` behind the `sourceLockVerifier` flag; ship a
  `MockSourceLockVerifier` for tests proving the gate engages/bypasses correctly. No real crypto yet.
- **Phase B — inclusion proof (medium, unblocked):** `StorageProofSourceLockVerifier` against a *provided*
  `stateRoot` (header oracle mocked), using an audited MPT lib (vendored Herodotus/Relic verifier). Test
  with real Base-Sepolia `eth_getProof` fixtures of `commits[commitId]`. This is the cheap, well-understood
  half — gets us a real proof against a trusted root.
- **Phase C — header trust (large):** integrate `SP1Helios` as `Sp1HeliosHeaderOracle` for EVM sources
  (deploy + relayer that posts header updates); design `GsxDagConsensusHeaderOracle` for the home chain
  (ML-DSA committee — ties into P5b precompile work). This is the trust root + the PQ question.
- **Phase D — redundancy + PQ posture:** `HashiAggregatorOracle` (N-of-M independent header oracles, no
  single-oracle failure); document the per-corridor PQ status (GSX-DAG↔GSX-DAG = PQ; EVM source = interim
  non-PQ via Helios Groth16).

## 6. What this composes with (already shipped)
- **k-of-N threshold verifier (PR #14):** becomes the *operational* gate (who may submit / sequencing) and
  the fallback authorizer when `sourceLockVerifier` is unset. The source-lock proof is the *security* gate.
- **emergencyRefund / unlockPartial / caps (P9 PR #12):** unchanged; the refund side still needs its own
  "the dest did NOT mint" proof to be fully trustless — a symmetric P10 problem on the return leg (noted).
- **ZKBridgeVerifier / OptimisticBridgeChallenge:** the SP1 circuit here proves *ML-DSA-over-STH*, not
  log/storage inclusion — it is NOT this proof and must not be conflated. The challenge contract is the §7
  interim fallback only.

## 7. Interim fallback while Phase C matures
Optimistic + bonded: require `OptimisticBridgeChallenge.isFinalized(anchorDigest(claim))` as a *temporary*
gate, with a watchtower that storage-proofs fraudulent anchors to slash. Honest framing: economic security,
watchtower-dependent, NOT a source-event proof. Replaced by Phase B+C. (This is option (b) the owner
declined as "P5b" — retained only as scaffolding, clearly labeled.)

## 8. Trust model & honest caveats
- After Phase B+C on an **EVM source**: mint requires a **cryptographic proof** the source lock is in a
  finalized source block — relayer trust for *correctness* is **eliminated**; residual trust is in (i) the
  SP1 Helios light client's soundness + its Groth16/BN254 (**non-PQ**) wrapper, and (ii) the source chain's
  own finality. This is a real, large reduction over k-of-N attestation.
- After the **GSX-DAG-source** path: end-to-end PQ + trust-minimized for the GSX-DAG↔GSX-DAG corridor.
- **NO-GO for mainnet funds still stands** until: Phase B+C shipped + an **independent professional audit**
  of the MPT verifier and the light-client integration + the header oracle is live and funded + a bug
  bounty (gate criterion 6). A storage-proof bug or a light-client soundness bug is a total-loss class.

## 9. Effort / risk
- Phase A: S (days). Phase B: M (vendoring + fixture-driven MPT tests; the slot derivation + RLP decoding
  are the fiddly parts). Phase C: L (SP1 Helios deploy + relayer infra; the GSX-DAG consensus verifier is
  research-adjacent). Phase D: M.
- Top risks: (1) MPT/RLP verifier correctness — use an audited vendored lib, fuzz against real `eth_getProof`
  fixtures, never hand-roll; (2) storage-layout drift on the source Vault — pin + treat as a stability
  promise; (3) light-client liveness/soundness — multi-oracle (Hashi) + the optimistic fallback during
  bring-up; (4) PQ overstatement — never call the Helios-EVM path "post-quantum."

## 10. Recommended first step
**Phase A + a fixture-grounded Phase B spike:** implement the interfaces + the flagged mint gate + a
`StorageProofSourceLockVerifier` that verifies a real `eth_getProof` of `commits[commitId]` from the LIVE
Base-Sepolia Vault (0x76688BDb…7cB7F) against a hard-coded known-good `stateRoot`. That proves the core
mechanism end-to-end against real source data before taking on the light-client (Phase C) trust root.

---
Sources: Across V4 (SP1 Helios + storage proof), `succinctlabs/sp1-helios` (OZ audit), Herodotus/Axiom V2/
Relic MPT verifiers, Hashi (N-of-M header oracle), EIP-2537 (BLS), EIP-4788 (beacon root), `P5b_ONCHAIN_PQ.md`.
