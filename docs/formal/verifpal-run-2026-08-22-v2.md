# Verifpal run — 2026-08-22 (v2 receiver-bound envelope)

Attempted re-verification of the sealed-key replay finding against the
v0.5.0 v2 envelope ([`ltp-protocol-v2.vp`](ltp-protocol-v2.vp)). The
2026-08-16 run of the pre-binding model is at
[`verifpal-run-2026-08-16.md`](verifpal-run-2026-08-16.md).

**Headline: the re-verification did not, and structurally cannot, turn
`authentication? sealed_key` green.** The reason is a property mismatch,
not a defect in the v2 binding and not a shortage of compute. Details in
§3 below. This file records a negative result and the reasoning behind
it, which is more useful than an indefinitely "pending" status.

## 1. Environment

| | |
|---|---|
| Tool | Verifpal **0.27.4** — the same version as the 2026-08-16 run |
| Install | `go install verifpal.com/cmd/verifpal@v0.27.4` (note: the module path is `verifpal.com`, not the GitHub path) |
| Attacker | `active` (Dolev-Yao), unbounded sessions |
| Host | 4-CPU shared VM — slower than the 2026-08-16 host |

## 2. Baseline reproduction (toolchain validation)

Before analysing the new model, the **pre-binding** model was re-run to
confirm the toolchain reproduces the recorded result.

| Query | 2026-08-16 record | 2026-08-22 re-run |
|---|---|---|
| `confidentiality? cek` | verified | **verified** (not in failed summary) |
| `confidentiality? content` | verified | **verified** |
| `authentication? commitment` | failed | **failed** — same trace shape |
| `authentication? sealed_key` | failed | **failed** — same trace shape |

Completed cleanly in ~9 minutes, Stage 6, ~5.69M analysis states. The
recorded verdicts reproduce exactly, so the toolchain is sound and any
difference in the v2 run is attributable to the model, not the tool.

## 3. The v2 run — and why the query cannot pass

The v2 run **did not complete**. It was stopped after 2h14m at ~15.3M
analysis states, still in Stage 4-5 — 2.7x the baseline's *total* state
count, two stages behind. The state-space blowup is attributable to the
model's added unguarded message (`seal_epk`), the three-element
`CONCAT`/`SPLIT`, and the extra `ASSERT`.

But the run had already emitted the decisive result, and finishing it
would not change the verdict. The trace:

```
seal_epk  → G^nil ← mutated by Attacker (originally G^seal_esk)
shared_secret_r → G^nil^receiver_sk
seal_ad_r → CONCAT(HASH(G^receiver_sk), HASH(G^nil))
lattice_payload_r → AEAD_DEC(G^nil^receiver_sk, ..., CONCAT(HASH(G^receiver_sk), HASH(G^nil)))?
```

The attacker substitutes **its own** ephemeral key, derives a shared
secret with the receiver, and computes a **valid** associated data
value — because the AAD's two inputs are `HASH(receiver_ek)` (public)
and `HASH(seal_epk)` (attacker-chosen). It then seals whatever it likes.

**This is correct behaviour, not a break.** The v2 envelope provides
*recipient binding*: an envelope cannot be re-targeted at another
receiver's key, and a payload cannot be spliced onto a different
encapsulation. It does **not** provide *sender authentication* — and it
cannot, because sealing to a public encapsulation key is an operation
anyone can perform. That is what public-key encryption is.

Verifpal's `authentication?` query demands injective agreement: the
receiver accepts a value only if the sender sent that specific instance.
That is strictly stronger than recipient binding. No AAD built from
public values can satisfy it.

**Where sender authentication actually comes from** in LTP: the ML-DSA-65
signature on the commitment record (whitepaper §2.3.1 step 5) and the
end-to-end EntityID check (step 10). In the trace above the attacker also
had to mutate `commitment`, which it cannot forge — so the *protocol*
rejects the substituted key, even though the *envelope* accepted it. The
envelope and the signature are complementary mechanisms, and the query
tests only the former.

## 4. What would need to change for a green verdict

Injective agreement on the sealed key requires one of:

- **Sender signature over the envelope** — the sender signs the sealed
  key with its ML-DSA key. This authenticates the sender but breaks the
  sealed key's opacity property unless the signature is placed inside
  the AEAD payload, and it enlarges the constant-size token.
- **An interactive freshness value** — a receiver-supplied nonce, which
  an offline, asynchronously-collected capability cannot carry by
  construction (whitepaper §3.3.3).

Neither is a free change; both trade against properties the design
deliberately holds. Adopting one is a protocol-design decision, not a
verification task, and is out of scope for this run.

## 5. Status

| Claim | Status |
|---|---|
| Toolchain reproduces the recorded 2026-08-16 verdicts | **Confirmed** |
| v2 closes re-targeting and payload splicing | Argued in whitepaper §3.3.3; **not** what the `authentication?` query tests |
| `authentication? sealed_key` passes under v2 | **No — and cannot**, for the structural reason in §3 |
| v2 model run to completion | **No** — stopped at 2h14m, non-convergent on this host |

The prior "symbolic re-verification pending" language should be read as
resolved-with-a-negative-result rather than outstanding: re-running this
query is not a useful open task.
