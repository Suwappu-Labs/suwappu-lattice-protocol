# Bridge Tokenomics — LTP's §5.5 Interfaces, Committed

> **Status:** committed economic design for the bridge launch. Per
> [`NODE_UNIFICATION.md`](NODE_UNIFICATION.md), the bridge is the **first product to
> actually stake and slash SUWP** — bot doesn't, and the chain doesn't exist yet to get
> this wrong on. There is one shot at this: the constants in §4 are a monetary
> constitution, changed only by a deliberate, announced governance act, never silently.
> Extends [`UNIFIED_TOKENOMICS.md`](UNIFIED_TOKENOMICS.md) (SUWP as the one token) and
> the whitepaper's [§5.5 interfaces](../WHITEPAPER.md#55-network-economics-interface-not-implementation)
> (`NodeIncentive`, `CommitmentPricing`, `AdmissionControl`) with concrete parameters.

## 1. The one design decision that shapes everything else

**The bridge does not mint SUWP. It only stakes it, and earns fees in the asset being
transferred.**

This is the load-bearing choice, and it's forced by two things already committed:

- SUWP is fixed at 1,000,000,000 max supply
  (`suwappubot/docs/economics/SEASONS_TOKENOMICS.md`), and `suwappu-dag#23` just closed
  the one open-ended minting path (`Intent::MintInflation`) that could have violated it.
  A bridge that mints its own emission — which is what the pre-existing
  `src/ltp/economics.py` did, denominated in a standalone `LTP` token
  (`WEI_PER_LTP`) — reopens exactly the problem that was just closed.
- The bridge moves **stablecoins**. Charging transfer fees in SUWP would force every
  user to acquire SUWP just to move USDC — friction with no product justification.
  Charging fees in the stablecoin being transferred, and using **SUWP purely as
  operator collateral** (bonded to back `AdmissionControl` and `NodeIncentive.slash`),
  cleanly separates "what secures the network" (SUWP stake) from "what the network
  earns" (fee revenue in-kind).

Consequence: operator compensation is real-time fee revenue, not deferred emission. The
`economics.py` precedent (below) built substantial vesting infrastructure specifically
to control sell-through pressure from a token *it minted itself*. Once compensation is
fee revenue rather than newly-created supply, that justification disappears — operators
get paid promptly, like any service business, with no protocol-level vesting on their
fee share (§3.3). Vesting continues to matter for SUWP itself, at the buy-and-burn step
(§3.4).

## 2. What's reused from `economics.py`, and what's replaced

`src/ltp/economics.py`'s slashing/audit/admission mechanics are well-designed and are
**reused wholesale**, just re-pointed at SUWP bonds instead of `LTP`-token stake. What's
**replaced** is everything that assumed the module could mint its own supply:

| Mechanism | `economics.py` today | This document |
|---|---|---|
| Slashing tiers, correlation penalty, grace period, offense decay | ✅ Reused as-is (§4) | — |
| Staking minimums (bootstrap/growth/maturity) | ✅ Reused as-is, re-denominated in SUWP (§4) | — |
| Bootstrap/growth subsidy (500 `LTP`/epoch emission, tapering) | ❌ Replaced | One-time, capped SUWP grant from an existing allocation — not perpetual emission (§3.5) |
| Reward vesting (50% immediate / 50% over 720 epochs) | ❌ Replaced | No vesting on operator fee income; SUWP buy-and-burn instead (§3.3–3.4) |
| Fee model (flat `base_commit_fee` in `LTP`) | ❌ Replaced | bps-of-transfer-value fee, paid in the transferred stablecoin (§3.2) |
| Fee split (60/15/10/15 operator/burn/endowment/insurance) | ✅ Reused as-is, re-scoped (§3.4) | — |

## 3. The economics, interface by interface

### 3.1 `AdmissionControl` — SUWP bond

A node operator bonds SUWP to `apply()`. Reuses `economics.py`'s three-phase minimum
(bootstrap/growth/maturity), re-denominated:

- Bootstrap: 100 SUWP minimum.
- Growth: 1,000 SUWP minimum.
- Maturity: 10,000 SUWP minimum.
- Cap: 1,000,000 SUWP per operator (anti-centralization ceiling, unchanged from
  `economics.py`).

This is the same bond `NODE_UNIFICATION.md` describes as carrying forward into
suwappu-dag Ring candidacy — one bond, two roles.

### 3.2 `CommitmentPricing` — stablecoin transfer fee

Scoped to stablecoin transfer per `NODE_UNIFICATION.md` §3. Fee is basis points of
transfer value, not a flat per-commitment charge (a flat fee doesn't make sense once the
entity being priced is "$10" vs "$10,000,000"):

```
fee = clamp(base_bps, floor_bps, ceiling_bps) × utilization_multiplier × transfer_value
```

- `base_bps = 5` (0.05%).
- `floor_bps = 2` (0.02%) — fee never drops below this even at zero utilization.
- `ceiling_bps = 15` (0.15%) — fee never exceeds this regardless of congestion.
- Utilization elasticity: reused from `economics.py` — target 50% network utilization,
  fee doubles per 2x over target, capped at the ceiling above.

At 5 bps base, the bridge prices below typical lock-mint bridge fees (10–30 bps) and
above CCTP's near-zero (CCTP has no PQ-attestation cost to recoup); the differentiator
is the PQ security guarantee, not being the cheapest rail.

### 3.3 `NodeIncentive.compensate` — paid in-kind, no vesting

Fee revenue is paid in the stablecoin transferred, split per §3.4. The operator's 60%
share is paid **immediately, unvested** — it's earned service revenue, not newly-minted
supply, so there's no sell-pressure rationale for deferring it (see §1).

### 3.4 Fee split — reused bps, re-scoped destinations

Reuses `economics.py`'s exact 60/15/10/15 split (already validated to sum to 10,000 bps
by that module's own `__post_init__` check) — only the destinations change:

| Share | bps | Destination |
|---|---|---|
| Operator | 6,000 (60%) | Paid immediately, in-kind, to the commitment node(s) that served the transfer. |
| SUWP buy-and-burn | 1,500 (15%) | Swapped for SUWP on the open market and burned. This is where bridge volume creates SUWP scarcity — the replacement for `economics.py`'s literal token burn, which isn't possible here since the fee isn't collected in SUWP. |
| Availability endowment | 1,000 (10%) | Reserve funding long-term data availability for in-flight transfers (unchanged rationale from `economics.py` §5.4.4 — "without economic incentives, rational nodes evict data"). |
| Insurance fund | 1,500 (15%) | Covers slashing shortfalls (a slashed bond that doesn't fully cover a loss) — unchanged rationale from `economics.py`. |

### 3.5 Bootstrap incentive — capped grant, not emission

Early operators face a cold-start problem: fee revenue is proportional to transfer
volume, which is near-zero at launch. `economics.py` solved this with perpetual
tapering emission (500 `LTP`/epoch, 3x→1x bootstrap multiplier). That mechanism is
exactly what §1 rules out for SUWP.

Instead: bootstrap incentives, if the foundation determines they're needed to attract
initial operators, are funded from a **fixed, one-time, capped grant** drawn from
SUWP's existing non-Seasons allocation (the 70% of the 1B supply outside the Seasons
program's 300M pool) — not from new minting. The exact grant size is a foundation
decision to make before bridge launch, not specified here; what's fixed by this document
is the constraint: **capped and one-time, never perpetual, never minted.**

## 4. Slashing — reused as-is, re-denominated

| Tier | Threshold (cumulative offenses) | Slash rate |
|---|---|---|
| Warning | 1 | 1% of bonded SUWP |
| Minor | 2–3 | 5% |
| Major | 4–5 | 15% |
| Critical | 6+ | 30% + eviction |

- **Correlation penalty**: `min(3.0, 1 + 2.0 × concurrent_slashed / total_staked)` —
  unchanged from `economics.py`, Ethereum-inspired (many nodes slashed in the same
  window scales the penalty, up to 3x, since correlated failure is more dangerous than
  independent failure).
- **Grace period**: 168 epochs (7 days) before a slash finalizes — reversible window,
  unchanged.
- **Offense decay**: 720 clean epochs (30 days) of good behavior removes one offense,
  unchanged.
- **Cooldown**: 24 epochs (1 day) per offense before the node can earn again, unchanged.

Slashed SUWP routes to the insurance fund (§3.4) first, up to the fund's obligations;
any remainder is burned rather than distributed, keeping slashing strictly punitive.

## 5. Summary

The bridge is the first Suwappu product to put SUWP economically at risk, and it only
gets one launch. The core design choice — **stake SUWP, earn fees in-kind, never mint**
— is forced by two already-committed facts: SUWP's fixed 1B supply, and the bridge
moving stablecoins users shouldn't need SUWP to touch. `economics.py`'s slashing,
correlation-penalty, and audit mechanics were already well-designed and are kept
unchanged, just re-denominated; what's replaced is everything that assumed the bridge
could mint its own token — replaced with a bps-of-value fee (2–15 bps, elastic), an
unvested in-kind operator payout, a reused 60/15/10/15 fee split (with the 15% burn leg
now a SUWP buy-and-burn instead of a literal token burn), and — if the foundation
decides it's needed — a capped, one-time bootstrap grant instead of perpetual emission.
