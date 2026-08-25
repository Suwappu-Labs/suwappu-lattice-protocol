# Formal Protocol Analysis — ETP (now LTP)

**Date:** 2026-03-29 (model), 2026-08-16 (first verification run)
**Tool:** [Verifpal](https://verifpal.com/) v0.27.4, built from source
**Model:** [`etp-protocol.vp`](etp-protocol.vp)

## Overview

This document presents a formal symbolic analysis of the Entanglement Transfer
Protocol's three-phase COMMIT / LATTICE / MATERIALIZE lifecycle using Verifpal.

## Model Design

### Attacker Model

The protocol is analyzed under an **active attacker** (Dolev-Yao model) with
unbounded sessions and fresh values. The attacker can intercept, modify, replay,
and inject messages on any channel.

### Cryptographic Abstractions

| ETP Primitive | Verifpal Model | Rationale |
|---------------|---------------|-----------|
| ML-KEM-768 | Diffie-Hellman key exchange (`G^a`, `ga^b`) | Semantically equivalent for confidentiality under symbolic model |
| ML-DSA-65 | `SIGN` / `SIGNVERIF` | Built-in signature primitives |
| XChaCha20-Poly1305 | `AEAD_ENC` / `AEAD_DEC` | Built-in AEAD primitives |
| SHA3-256 | `HASH` | Built-in hash function |
| Erasure coding | Not modeled | Information-theoretic; outside symbolic scope |

### Limitations

1. **ML-KEM is modeled as DH** — Verifpal has no native KEM primitive. DH and KEM
   provide equivalent confidentiality guarantees in the symbolic model (both derive
   a shared secret from public/private key pairs).

2. **Erasure coding not modeled** — the k-of-n threshold property is information-theoretic
   and cannot be captured in a symbolic verifier. It is verified by the test suite.

3. **Commitment network topology not modeled** — shard distribution across nodes is an
   infrastructure concern, not a protocol-level property.

## Security Properties Verified

| Property | Query | Expected |
|----------|-------|----------|
| CEK confidentiality | `confidentiality? cek` | Attacker cannot learn CEK |
| Content confidentiality | `confidentiality? content` | Attacker cannot learn plaintext content |
| Commitment authentication | `authentication? Sender -> Receiver: commitment` | Commitment is from Sender |
| Sealed key authentication | `authentication? Sender -> Receiver: sealed_key` | Sealed key is from Sender |

## How to Run

```bash
# Install Verifpal
brew install verifpal
# or: go install github.com/symbolicsoft/verifpal@latest

# Run analysis
verifpal verify docs/formal/etp-protocol.vp
```

## Results

First run 2026-08-16, Verifpal 0.27.4 (active attacker, unbounded
sessions). Full output: [`verifpal-run-2026-08-16.md`](verifpal-run-2026-08-16.md).

| Property | Query | Verdict |
|----------|-------|---------|
| CEK confidentiality | `confidentiality? cek` | ✅ **Verified** — attacker never learns the CEK |
| Content confidentiality | `confidentiality? content` | ✅ **Verified** — attacker never learns the plaintext |
| Commitment authentication | `authentication? Sender -> Receiver: commitment` | ❌ **Fails** — the attacker can (re)deliver the signed commitment; there is no session binding on the delivery |
| Sealed key authentication | `authentication? Sender -> Receiver: sealed_key` | ❌ **Fails** — a sealed lattice key can be **replayed across sessions**; the Receiver accepts an old sealed key as fresh |

**Model corrections.** The 2026-03-29 model had never been run and did
not pass Verifpal's model checks (a duplicate `sender_vk` send; the
Receiver consuming `cek`, `entity_nonce`, and `encrypted_shards` it was
never sent). The 2026-08-16 revision fixes those while preserving the
protocol's intent, and marks the pre-protocol identity-key exchange as
guarded (authentic distribution) — the assumption this document's
Interpretation section always made. The change log is at the top of
[`etp-protocol.vp`](etp-protocol.vp).

## Interpretation

1. **An active attacker cannot learn the CEK or content** — verified.
   The ML-KEM-768 envelope (modeled as DH) ensures that only the
   intended receiver can derive the shared secret needed to unseal the
   lattice key, *given authentic identity-key distribution* (the guarded
   pre-protocol exchange). Without that assumption the unauthenticated
   key exchange is trivially MITM-able; deployments must provide it (key
   directory, out-of-band verification).

2. **The authentication failures are replay findings, not forgery.**
   The attacker cannot forge a commitment (the ML-DSA signature holds)
   or open the sealed key. What Verifpal shows is *message agreement
   with freshness* failing: both artifacts are accepted by the Receiver
   when delivered (or re-delivered, across sessions) by the attacker.
   - For the **commitment record** this is largely by design — it is a
     public, self-authenticating artifact that anyone may relay; the
     signature, not the channel, carries its authority. The finding
     still stands as stated: the *delivery* is not authenticated.
   - For the **sealed lattice key** the finding is substantive: nothing
     binds a sealed key to a session, to freshness, or to the receiver's
     encapsulation key. A replayed sealed key causes re-materialization
     of the same entity. This independently corroborates the KEM
     ciphertext-binding gap disclosed in whitepaper §3.3.
     **Status update (SDK / whitepaper 0.5.0):** the fix has landed as
     the v2 receiver-bound sealed envelope — AEAD associated data
     committing to SHA3-256(receiver_ek) and SHA3-256(kem_ct), plus an
     authenticated `sealed_at` freshness stamp bounded by an optional
     receiver-side maximum seal age; entity_id is bound inside the
     authenticated payload rather than in cleartext AAD (opacity —
     whitepaper §3.3.3 records the reasoning and the exact residual
     surface). Policy enforcement (`max_materializations`, §2.2.1,
     enforced since 0.4.1) additionally bounds same-instance replay.
     The v2 construction was modeled and analysed on 2026-08-22
     (`ltp-protocol-v2.vp`, `verifpal-run-2026-08-22-v2.md`). Result:
     `authentication? sealed_key` still fails and cannot pass — the
     query demands injective agreement, the v2 AAD is built from public
     values, and sealing to a public encapsulation key is something any
     party can do. Sender authentication is supplied by the ML-DSA
     commitment signature and the end-to-end EntityID check, outside
     this query's scope. The traces below describe the pre-binding
     protocol; the v2 analysis is a separate, negative result rather
     than an open task.

3. **Computational security** depends on the hardness of the Module-LWE
   problem (ML-KEM-768) and Module-SIS problem (ML-DSA-65), both
   conjectured to be quantum-resistant. The symbolic model says nothing
   about this.

## Next Steps

- ~~Run the model and record results in the Results section above~~ — done 2026-08-16
- Re-run after the sealed-key AAD binding lands and check that the
  sealed-key authentication query flips to verified
- Extend the model to cover bridge relay (L1→L2 transfer)
- Explore key compromise impersonation (KCI) resistance
- Consider modeling the governance/upgrade path
