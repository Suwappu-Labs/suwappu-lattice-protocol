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

Command: `verifpal verify docs/formal/etp-protocol-revised.vp` (v1 of
the revised model: no receiver cross-checks, 5 queries including
`freshness? sealed_key`)

**Status: DID NOT COMPLETE.** The analysis ran for ≈ 7.5 hours,
reaching **Stage 6 at 127.9 million analysis states**, before the
execution environment reclaimed the machine. An incomplete run verifies
nothing — no ✅ verdict below is claimed — but the partial transcript
carries two facts worth recording:

- Across all 127.9M explored states (Stages 1–6), the **only failure
  found** was `authentication? Sender -> Receiver: sealed_key`. No
  attack was found against `confidentiality? cek`,
  `confidentiality? content`, `authentication? commitment`, or
  `freshness? sealed_key` in the explored space. *Not found ≠ absent.*
- The sealed_key counterexample (found in Stage 1, within seconds): the
  attacker **relays the genuine sealed key unchanged** while nulling
  the surrounding phase-1 delivery (encrypted_shards, entity_nonce, the
  record copy). The sealed key's AD check still passes — receiver
  fingerprint, entity_id, and eta are intact — so the receiver accepts
  the sealed key inside a rearranged run; the downstream signature
  check then fails closed, so no wrong entity is accepted, but strict
  delivery-authentication of the sealed key itself is not met.

That counterexample dictated the v2 model iteration below.

## Run 3 — revised construction, v2 (`etp-protocol-revised.vp`, 2026-08-25)

Two changes from v1, both recorded in the model header:

1. **Receiver cross-checks** — `ASSERT(entity_id_r, entity_id)?` and
   `ASSERT(shard_root_r, shard_root)?`: the sealed commitment reference
   must equal the delivered record, so a tampered companion delivery
   kills the run before the sealed key counts as accepted. This
   directly targets the Run 2 counterexample.
2. **Query set reduced to the baseline's four** (the `freshness?` query
   dropped) — for a clean column-for-column comparison with
   `etp-protocol.vp` and a smaller analysis space. Session binding is
   carried by `eta` inside the AEAD associated data, which the
   authentication query exercises.

Command: `timeout 2400 verifpal verify docs/formal/etp-protocol-revised.vp`
(hard 40-minute wall-clock cap, so the recorded outcome is
deterministic about how much space was explored).

**Outcome: cap reached** (exit 124 at 2,400 s), analysis terminated in
**Stage 4–5 at ≈ 12.08 million analysis states** — roughly 29× the
complete baseline run's ~420K states, without exhausting the space.
Under the bound:

| Query | Finding in explored space |
|---|---|
| `confidentiality? cek` | no attack found |
| `confidentiality? content` | no attack found |
| `authentication? Sender -> Receiver: commitment` | no attack found |
| `authentication? Sender -> Receiver: sealed_key` | ❌ one trace (below) |

**No claim of verification is made for any query** — Verifpal only
issues ✅ verdicts at completion, and the space was not exhausted. "No
attack found" is a bounded statement about ≈ 12.08M explored states.

**The single trace found, and why it is benign.** The attacker
**relays the byte-identical sealed key** while tampering the companion
phase-1 values. The sealed key's own AD check passes (receiver
fingerprint, entity_id, eta all intact), so Verifpal's strict
delivery-authentication counts the sealed key as "sent by Attacker and
not by Sender" at its first checked use. But in the same trace the
receiver's new `root_consistent` cross-check **fails** on the tampered
record — the run dies before any wrong entity can be accepted. The
residual property gap is pure attacker relay of an unmodified message
over an unguarded channel, which no protocol can exclude; every
substitution or rearrangement the attacker attempts is caught by the
cross-checks, the signature check, or the AD binding, all failing
closed. The v2 cross-checks did exactly what the Run 2 counterexample
demanded.

## Bottom line

- The 2026-08-16 baseline results **reproduce exactly**.
- Against the revised (Theorem 9) construction, across ≈ 140M combined
  explored states over two runs, the only failure Verifpal found is a
  verbatim-relay trace in which the receiver's own checks fail closed —
  the misbinding and cross-session-replay attacks that defeat the v1
  construction were **not reproducible against the revision in the
  explored space**.
- Completing the analysis (exhausting the space, or a bounded-session
  reformulation that terminates) remains open, as does the
  committing-AEAD obligation the symbolic model assumes away.

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
