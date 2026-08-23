# Verifpal run — revised sealed-key construction (2026-08-23)

Two runs, recorded here: a **reproduction** of the 2026-08-16 baseline
on the unmodified v1 model, and the **first run of the revised model**
`etp-protocol-revised.vp`, which encodes the planned sealed-key
mitigation exactly as whitepaper Theorem 9 (§3.3.6) specifies it.

Toolchain: Verifpal 0.27.4, built from source at tag `v0.27.4`
(Go 1.24.7, linux/amd64), per the build instructions in
`docs/FORMAL_VERIFICATION_STATUS.md`.

## Run 1 — baseline reproduction (`etp-protocol.vp`, unmodified)

Command: `verifpal verify docs/formal/etp-protocol.vp`
Duration: ≈ 9 minutes (~420,000 analysis states).

| Query | 2026-08-16 recorded | 2026-08-23 reproduced |
|---|---|---|
| `confidentiality? cek` | ✅ Verified | ✅ Verified |
| `confidentiality? content` | ✅ Verified | ✅ Verified |
| `authentication? Sender -> Receiver: commitment` | ❌ Fails | ❌ Fails |
| `authentication? Sender -> Receiver: sealed_key` | ❌ Fails | ❌ Fails |

The 2026-08-16 results reproduce exactly. The two authentication
failures are the misbinding/replay weakness disclosed in whitepaper
§3.3.3 and formalized as the Theorem 8 fourth attack path (§3.3.6).

## Run 2 — revised construction (`etp-protocol-revised.vp`)

The revised model changes exactly what the planned mitigation changes
(see the model header for the full mapping to Theorem 9):

1. **Freshness** — receiver-generated per-transfer nonce `eta`,
   delivered to the sender over an unguarded channel before LATTICE;
2. **Receiver binding** — sealed-key AEAD associated data
   `CONCAT(HASH(receiver_ek), entity_id, eta)`;
3. **Record binding** — the sealed payload carries
   `(cek, entity_id, shard_root)` and the receiver verifies the
   commitment signature against the *sealed* values, not the publicly
   delivered copies.

Command: `verifpal verify docs/formal/etp-protocol-revised.vp`

**Status: run in progress at the time of this commit** — the full
verdict table will be recorded here when the analysis completes. One
interim finding is already recorded, because it drives the next model
iteration:

- `authentication? Sender -> Receiver: sealed_key` — ❌ a mutation
  trace was found: the attacker **relays the genuine sealed key
  unchanged** while nulling the surrounding phase-1 delivery
  (encrypted_shards, entity_nonce, the record copy). The sealed key's
  AD check still passes (receiver fingerprint, entity_id, and eta are
  intact), so the receiver accepts the sealed key inside a rearranged
  run; the downstream signature check then fails closed, so no wrong
  entity is accepted — but strict delivery-authentication of the sealed
  key itself is not met. Planned iteration: the receiver must
  cross-check the sealed commitment reference against the delivered
  record (`ASSERT(entity_id_r, entity_id)?`,
  `ASSERT(shard_root_r, shard_root)?`) so that a tampered companion
  delivery kills the run before the sealed key counts as accepted.

## Interpretation caveats

- These are symbolic results: ML-KEM-768 is modeled as DH, and the
  symbolic AEAD is *ideal* — in particular perfectly committing to its
  key and associated data. The real protocol's XChaCha20-Poly1305 is
  **not** committing (whitepaper §3.3.3, Bellare–Hoang), so this model
  is faithful to the revision **only if** the committing-AEAD
  requirement of §3.3.3 is implemented. A run of this model does not
  discharge that requirement; it assumes it.
- The guarded identity-key exchange is Theorem 9's single long-term
  trust anchor (the sender-key pin) — the same assumption the baseline
  model and `ANALYSIS.md` always made.
- The revised model describes the **planned** protocol revision, not
  the v1 wire format. `etp-protocol.vp` remains the model of record
  for what is implemented today.
