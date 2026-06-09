# quorum-core

Validator-quorum verification logic shared across all verifier backends in the
Suwappu bridge. This crate contains the security-critical quorum-check algorithm
that every circuit and every on-chain verifier must implement identically.

## What it does

Given a registered validator set and a set of signed-header witnesses, `quorum-core`
determines whether a `>2/3`-stake quorum of registered validators has honestly
attested a header digest. It enforces:

- **pkHash ordering:** signers must arrive strictly-increasing by
  `keccak256(pubkey)` — same invariant as `GsxDagValidatorRegistry._verifyQuorum`
  and `submitHeader`. Out-of-order signers cause an `Err` result, not a skip.
- **Set membership + stake accumulation:** each signer's stake is looked up by
  `pkHash`; unregistered pubkeys (`stakeOf == 0`) contribute 0 stake and are
  skipped without error.
- **ML-DSA-65 signature verification:** each signer's ML-DSA-65 signature over the
  header digest is verified. An invalid signature contributes 0 stake and is
  skipped without error.
- **Threshold:** `sigStake >= (totalStake * 2) / 3 + 1` (integer division,
  strictly greater than two-thirds).

The implementation mirrors `GsxDagValidatorRegistry._verifyQuorum` (Solidity)
byte-for-byte in Rust, including the keccak256 pkHash (not SHA3-256 — they differ
in padding).

## Role in the bridge

`quorum-core` is the single source of truth for quorum logic. Every consumer
reuses it and must not reimplement the check independently:

| Consumer | How it uses quorum-core |
|---|---|
| `zkvm/sp1-quorum-verifier` | SP1 zkVM guest circuit (Path C) — wraps `verify_quorum_stake` in-circuit; the resulting Groth16 proof carries this check to any EVM without the 0x0101 precompile. Groth16 BN254 = classical, NOT PQ. |
| Future Track B circuit | Will swap `ml-dsa::verify` for an XMSS verify gadget, reusing threshold + dedup + set-membership logic unchanged. |
| Host test harness | `zkvm/sp1-quorum-host` runs the circuit + verifies the proof natively for end-to-end tests. |
| Native tests | The crate's own `#[cfg(test)]` suite uses real ML-DSA-65 keys to verify non-vacuous properties: correct quorum passes, sub-quorum fails, tampered sig excluded, out-of-order signer rejected, unregistered signer contributes 0 stake. |

## Trust model

This crate does not establish trustlessness. The quorum check is correct when an
honest `>2/3`-stake quorum of registered validators attests the header. It is a
**validator-quorum side-attestation (sync-committee trust class)** — not a
consensus light client, not a ZK proof by itself, and not end-to-end post-quantum
unless the outer proof system is also hash-based (Track B).

## Build

```bash
cargo test                  # native tests — real ML-DSA-65 keys, no zkVM toolchain needed
cargo build --release       # library for use by sp1-quorum-verifier
```

The crate is intentionally a standalone Cargo workspace so it can be compiled
natively (for tests and host integration) and also reused inside the SP1 zkVM
guest without pulling in `std`-only dependencies.

## Related

- `contracts/src/verifiers/GsxDagValidatorRegistry.sol` — the Solidity reference
  this crate mirrors exactly.
- `zkvm/sp1-quorum-verifier/` — the SP1 circuit that wraps this crate.
- `docs/BRIDGE_ARCHITECTURE.md` — full architecture reference.
- `docs/security/audits/suwappu/DUAL_TRACK_PQ_BRIDGE_PLAN.md` — where this crate
  fits in the dual-track roadmap.
