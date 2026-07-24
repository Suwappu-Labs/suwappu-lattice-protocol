# Node Unification & Launch Sequencing

> **Status:** adopted design direction. Extends
> [`UNIFIED_TOKENOMICS.md`](UNIFIED_TOKENOMICS.md), which declared SUWP as the single
> token across suwappubot, suwappu-dag, and LTP. This document answers the follow-on
> question: when the bridge (LTP) and the chain (suwappu-dag) both need a set of
> economically-bonded node operators, should they recruit and stake those operators
> separately, or once?

## 1. Launch sequencing

Three products, in order:

1. **Bot** (`suwappubot`) — live today. Routes swaps across 14 chains via existing
   third-party liquidity (Li.Fi, Socket, CCTP, Wormhole, etc.). Does not depend on
   anything in this document.
2. **Bridge** (LTP, `suwappu-lattice-protocol`) — next to launch. Public commitment
   network for cross-chain data transfer, initially scoped to **stablecoin transfer**
   (see §3).
3. **Chain** (`suwappu-dag`) — launches last, once the bridge's operator set and
   economics have been proven in production.

Tokenomics has to be settled *before* the bridge launches (`UNIFIED_TOKENOMICS.md`),
because the bridge is the first product that actually stakes and slashes SUWP — the bot
doesn't, and the chain doesn't exist yet to get it wrong on. This document is the second
prerequisite: the bridge's operator/staking design has to anticipate the chain, not be
redone when the chain arrives.

## 2. The problem: two node-operator sets, or one?

Both the bridge and the chain need a set of economically-bonded operators:

| | LTP (bridge) | suwappu-dag (chain) |
|---|---|---|
| Role | Commitment nodes: store/serve shards, attest anchors | Authority Ring + Validator Ring: order transactions, finalize blocks |
| Admission | §5.5 `AdmissionControl.apply(node_identity, storage_proof, bond)` | Genesis allocation + `Intent::Delegate` / stake registries |
| Incentive | §5.5 `NodeIncentive.compensate` / `.slash` | `Intent::MintInflation` → `DistributeRewards`, slashing waterfall |
| Currently backed by | SUWP (per `UNIFIED_TOKENOMICS.md`) | SUWP (per `UNIFIED_TOKENOMICS.md`) |

Nothing today ties these together. If built independently, launching the chain means
recruiting and vetting a second operator set from scratch — new KYC, new bonding, no
carried-over trust or slashing history — even though it's the same kind of
economically-bonded, geographically-distributed operator role both times.

**Decision: one operator/stake registry, not two.** A node operator bonds SUWP once.
That bond:

- Backs their LTP commitment-node role immediately (admission, pricing, incentive —
  §5.5's three interfaces).
- Simultaneously registers them as a **candidate** for suwappu-dag's Authority/Validator
  Ring when the chain launches — not automatic promotion, but no second bonding process
  and no cold-start trust. Their LTP-era slashing history (or clean record) carries over
  as a real signal for genesis validator selection.

This is a bootstrap-sequencing decision, not a technical merge of the two codebases —
LTP's §5.5 interfaces and suwappu-dag's Ring registries stay their own implementations
(they operate at different layers: LTP is a storage/attestation network, suwappu-dag is
a consensus chain). What's shared is the **operator identity and stake**, not the
mechanism.

## 3. Why stablecoins first, and how that scopes the design

The bridge's initial `CommitmentPricing` profile (§5.5) is scoped narrowly to stablecoin
transfer:

- Smaller, more uniform entity sizes than general data → simpler pricing, tighter TTLs.
- Higher-frequency audit cadence justified by higher-value transfers.
- suwappu-dag's existing "bridge asset whitelist" primitive (`ROADMAP.md` Phase 2,
  `crates/suwappu-execution` substrate layer) already anticipates a whitelisted-asset
  model — stablecoins are the natural first whitelist entry once the chain exists.

**This is a pricing/admission profile, not a protocol fork.** §5.5's interfaces don't
change for stablecoins vs. general data — only the parameters
(`price(entity_size, replication_factor, ttl_seconds)`, bond minimums, audit frequency)
do. When "other things eventually" (per the product direction) get added — arbitrary
entity transfer, non-stablecoin assets — they're a second `CommitmentPricing` profile on
the same admission/incentive substrate and the same shared operator set, not a new
system requiring its own operators.

## 4. What this does NOT do yet

- Does not implement shared operator identity in code. `src/ltp/economics.py` still
  needs its rewrite (flagged in `UNIFIED_TOKENOMICS.md` §2.2) onto the §5.5 interfaces;
  that rewrite is where a `NodeOperatorRegistry` shared with suwappu-dag's Ring
  candidacy would actually live.
- Does not specify the exact mechanics of "candidacy carries into genesis validator
  selection" (e.g., is it automatic above a stake threshold, foundation-reviewed, or
  voted?). That's a suwappu-dag Phase 6 (mainnet candidate) design question, to be
  answered before genesis, not before bridge launch.
- Does not change suwappu-dag's own inflation/stake registries — those already exist and
  are already SUWP-denominated (`suwappu-dag#23`, the `MAX_SUPPLY` cap on
  `Intent::MintInflation`).

## 5. Summary

Launch order is bot → bridge → chain. The bridge is the first product to actually stake
and slash SUWP, so its operator/staking design has to be built anticipating the chain
rather than redone when the chain arrives: **one SUWP-bonded operator identity, shared
between LTP's commitment-node role now and suwappu-dag's Ring candidacy later**, scoped
initially to stablecoin transfer via a narrow `CommitmentPricing` profile that
generalizes to other entity types without requiring a second operator set.
