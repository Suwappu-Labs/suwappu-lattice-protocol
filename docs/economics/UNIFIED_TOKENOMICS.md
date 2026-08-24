# Unified Tokenomics — SUWP Across suwappubot, suwappu-dag, and LTP

> **Status: SUPERSEDED.** See
> [`DEFERRED_TOKEN_ARCHITECTURE.md`](DEFERRED_TOKEN_ARCHITECTURE.md) — whose
> deferral was itself superseded on 2026-08-24 by the genesis pre-mine +
> fair-launch decision in
> [`suwappu-dag/docs/whitepaper/TOKENOMICS.md`](https://github.com/Suwappu-Labs/suwappu-dag/blob/main/docs/whitepaper/TOKENOMICS.md),
> which is the current authority on SUWP supply and distribution. This document's
> naming-collision fix (SUWAPPU = SUWP, one asset) still stands — that part was
> correct and isn't revisited. What's superseded is the premise underneath it: that a
> SUWP token needs to exist, and needs to be staked, before the bridge or the chain can
> function. It doesn't. Kept for history; do not build against this document without
> reading the superseding one first.
>
> This is the cross-repo economic constitution referenced from `suwappu-dag/ROADMAP.md`
> (previously a dangling citation to a nonexistent `Suwappu-Labs/suwappu-papers` repo —
> that repo was never created; the LTP whitepaper lives in this repo at
> [`docs/WHITEPAPER.md`](../WHITEPAPER.md)) and from `suwappu-dag/docs/testnet/POINTS.md`.

## 1. The question this answers

Three repos independently reference a Suwappu-branded token without agreeing on what it is:

| Repo | Name used | What it currently implements |
|---|---|---|
| `suwappubot` | **SUWP** | Fixed max supply (1,000,000,000), 30% distributed via an 8-season decaying-pool Seasons program, fee-denominated points. See `docs/economics/SEASONS_TOKENOMICS.md` in that repo. |
| `suwappu-dag` | **SUWAPPU** | Native gas/staking denomination (`validator_stake_suwappu`, `balance_suwappu` in genesis). Rewards minted via `Intent::MintInflation`, per-ring per-epoch — open-ended inflation. |
| `suwappu-lattice-protocol` (LTP) | *(unnamed — see §5.5 of the whitepaper)* + `WEI_PER_LTP` in `src/ltp/economics.py` | The whitepaper deliberately specifies **interfaces only** (`NodeIncentive`, `CommitmentPricing`, `AdmissionControl`) and defers the token choice to the deployer. The checked-in `economics.py` implementation, however, hardcodes its own three-phase inflationary model denominated in a token called `LTP` — this predates and contradicts the whitepaper's §5.5 interface-only stance. |

This is a naming collision, not a designed relationship — no file anywhere states that
SUWAPPU (dag) and SUWP (Seasons) are the same asset, and their supply models actively
conflict (fixed vs. inflationary).

## 2. Decision

**SUWP is the one token.** Max supply 1,000,000,000, as committed in
`suwappubot/docs/economics/SEASONS_TOKENOMICS.md`. Every "SUWAPPU" reference in
`suwappu-dag` and every LTP economic interface settle in SUWP. There is no separate
gas token and no separate `LTP` token.

This resolves the three collisions:

### 2.1 suwappu-dag: SUWAPPU is a spelled-out unit of SUWP

`validator_stake_suwappu`, `authority_stake_suwappu`, and `balance_suwappu` in genesis
denominate in SUWP. The chain's native gas/stake unit is not a separate asset —
suwappu-dag is where SUWP settles and where validators stake it.

**Required follow-up (tracked separately, not resolved by this doc alone):**
`Intent::MintInflation` currently mints new supply per-ring per-epoch with no ceiling
tied to SUWP's 1B fixed cap. This must be reconciled before mainnet — validator staking
rewards need to draw down a pre-committed allocation (analogous to the Seasons program's
30% pool) rather than open-ended minting. Until that reconciliation lands, testnet
`SUWAPPU` balances are **not** 1:1 redeemable for mainnet SUWP; see
`suwappu-dag/docs/testnet/POINTS.md`'s existing points→mainnet-token conversion formula,
which already models this as a conversion rather than a peg.

### 2.2 LTP: the §5.5 interfaces are backed by SUWP

LTP's whitepaper design (§5.5) is correct and does not need to change — it should
continue to define interfaces rather than mandate a token, so non-public deployments
(enterprise/consortium) remain possible. For Suwappu's own public deployment, the
interfaces are backed by SUWP:

- `NodeIncentive.compensate(...)` pays commitment nodes in SUWP.
- `NodeIncentive.slash(...)` slashes staked SUWP.
- `CommitmentPricing.price(...)` / `.renew(...)` are denominated in SUWP.
- `AdmissionControl.apply(...)` requires a SUWP storage bond.

**Required follow-up:** `src/ltp/economics.py` currently implements a standalone
three-phase inflationary model denominated in a fictional `LTP` token
(`WEI_PER_LTP = 10**18`), with its own vesting split (50% immediate / 50% over 720
epochs) that does not match Seasons' 40/60-over-2-seasons vesting. This module predates
whitepaper §5.5 and should be rewritten to (a) implement the `NodeIncentive` /
`CommitmentPricing` / `AdmissionControl` interfaces as specified, and (b) denominate in
SUWP rather than minting its own unit. That rewrite is a separate, larger change and is
out of scope for this document — this document only fixes the naming/identity question
so that rewrite has a target to build against.

## 3. What is NOT changed by this document

- LTP's whitepaper text (§5.5, §10 Open Question 1) is unchanged — it correctly stays
  token-agnostic at the protocol-spec level. Only *Suwappu's specific deployment* of LTP
  is declared to use SUWP.
- SUWP's Seasons distribution mechanics (`SEASONS_TOKENOMICS.md`) are unchanged.
- No code changes ship with this document. It is the identity/naming resolution that the
  two follow-up items in §2.1 and §2.2 are scoped against.

## 4. Summary

One token, SUWP, fixed at 1,000,000,000 max supply. `suwappu-dag`'s "SUWAPPU" genesis
fields are SUWP's on-chain gas/stake unit, not a separate asset — pending a follow-up to
cap dag validator rewards against SUWP's fixed supply instead of open-ended
`MintInflation`. LTP's economic interfaces (§5.5) settle in SUWP for Suwappu's
deployment — pending a follow-up to rewrite `economics.py` off its standalone `LTP`
token and onto the interface contract it was designed to implement.
