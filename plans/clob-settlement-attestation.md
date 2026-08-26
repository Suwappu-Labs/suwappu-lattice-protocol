# Plan: LTP attestation of CLOB settlement batch roots

Status: proposed · 2026-08-26
Depends on: `Suwappu-Labs/suwappu-dag` crate `suwappu-clob` (branch
`claude/parity-dominance-execution-c4hz5l`)

## Why

The DAG L1 now has a headless exchange lane (`suwappu-clob`): deterministic
price-time-priority matching plus multilateral netting of fills into
per-account deltas. Each netting window produces a single 32-byte,
domain-separated SHA3-256 **settlement batch root**. To settle exchange
activity cross-chain — the venue/market-maker integration story — those
roots need to ride the existing LTP corridor as attested payload roots.

## What changes (and what doesn't)

**No new commitment bytes.** The batch root slots directly into the
existing 32-byte SHA3-256 payload-root field of an LTP attestation. The
on-chain commitment stays ≈1,600 B (ML-KEM-768 ciphertext + BLS aggregate +
payload root) regardless of how many fills the batch nets — the constant-size
commitment promise is preserved by construction, because netting happens
off the commitment surface.

**No wire-format bump.** `LTP-corridor-v1` carries the root as an opaque
payload root. Consumers that want the underlying batch fetch it from the
DA layer and re-derive the root.

## Domain separation (LTP-A-022 applies)

The batch root is computed as
`SHA3-256(DST ‖ canonical-encoding)` with

```
DST = "SUWAPPU-CLOB-SETTLEMENT-V1"   (ASCII, 26 bytes)
```

and the canonical encoding defined in
`suwappu-dag/crates/suwappu-clob/src/settlement.rs` (`batch_root`):
market id (32 B) ‖ fill_count (u64 BE) ‖ first_seq (u64 BE) ‖
last_seq (u64 BE) ‖ per-account `(account 32 B ‖ base i128 BE ‖
quote i128 BE)` in `BTreeMap` (lexicographic) account order.

Per audit finding LTP-A-022, the DST must be **byte-identical** in every
verifier — Python SDK, Solidity, and any future implementation. No Unicode
normalization, no trim, no re-encoding.

## Verifier work (scoped, not started here)

1. Python SDK: a `verify_clob_settlement_root(batch, root)` helper that
   re-derives the canonical encoding and checks the DST'd hash. Pure
   addition; no change to existing corridor code paths.
2. Solidity registry: no change required — roots anchor through the
   existing payload-root path. If on-chain re-derivation is ever wanted,
   that is a new precompile-style contract and requires
   `make contracts-secaudit` green plus a deployed-contracts upgrade plan.
3. Conformance vector: one cross-language test vector (batch → root) added
   to the corridor conformance suite, mirroring how BLS DST vectors are
   pinned today.

## Rollout order

1. Land `suwappu-clob` in suwappu-dag (done on the branch above).
2. Pin the conformance vector in this repo (Python side first).
3. Wire the DAG anchor pipeline to submit batch roots as payload roots.
4. Operator runbook addendum: how to audit a settled batch from a root.

## Invariant checklist

- [x] Constant-size commitment: unchanged (root occupies the existing 32 B slot).
- [x] Corridor wire format: unchanged (`LTP-corridor-v1` opaque payload root).
- [x] DST byte-identity rule: stated above; enforced by conformance vector in step 2.
- [ ] Deployed contract addresses: untouched by this plan.
