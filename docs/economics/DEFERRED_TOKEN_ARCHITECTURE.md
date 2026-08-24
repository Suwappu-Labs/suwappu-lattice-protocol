# Deferred-Token Architecture — Bridge and Chain Security Without a Premined SUWP

> **Status update (2026-08-24): the deferral is SUPERSEDED.** The decision was
> made to launch SUWP with the chain after all: the full fixed 1,000,000,000
> supply is pre-mined in the mainnet genesis block and distributed as a fair
> launch (no team/investor/treasury allocation, no inflation budget). The
> authoritative tokenomics now live in
> [`suwappu-dag/docs/whitepaper/TOKENOMICS.md`](https://github.com/Suwappu-Labs/suwappu-dag/blob/main/docs/whitepaper/TOKENOMICS.md)
> with the auditable genesis ledger in `suwappu-dag/scripts/tge/`.
> What survives from this document: the LTP bridge remains stablecoin-native
> per §3.1 (attestor bonds are posted in the transferred stablecoin — SUWP is
> not required to move value across the bridge), and the whitepaper's §5.5
> interface-only stance is unchanged. What is superseded: §3.2's
> stablecoin-bootstrap of chain consensus (mainnet stakes SUWP from genesis)
> and §3.3's "token only after observed usage" sequencing.
>
> **Original status:** adopted. Supersedes [`UNIFIED_TOKENOMICS.md`](UNIFIED_TOKENOMICS.md)'s
> premise (not its naming-collision fix — SUWAPPU = SUWP still stands if/when a token
> exists), and replaces the now-closed `NODE_UNIFICATION.md` / `BRIDGE_TOKENOMICS.md`
> PRs (Suwappu-Labs/suwappu-lattice-protocol#46, #47), which staked bridge security on
> SUWP before either the bridge or SUWP existed.

## 1. The question this document answers

Nothing is live yet: no bridge, no chain, no token. That's a reason to check the premise
before building on it, not a reason to lock in the first design that was internally
consistent. The premise being checked: **does the bridge, or even the chain, actually
need a brand-new native token to be economically secure?**

## 2. What production systems actually did

Three real precedents, not analogies:

- **Circle's CCTP** bridges USDC across 13+ chains with **zero native token**.
  Burn-and-mint: source-chain USDC is burned, an attestation service signs the burn
  event, destination-chain USDC is minted fresh. No vault, no wrapped asset, no
  bridge-held reserve to drain. Security is "is the attestation trustworthy," not "is a
  staked token valuable enough to deter attacks."
- **EigenLayer** solved "how does a new protocol bootstrap a validator set" without
  launching a token to recruit one. Restaking lets a new service **rent already-staked
  capital** (ETH/LSTs) instead of recruiting and paying its own validators from
  scratch — real economic security from day one, no new token, no separate
  capital-raise-sized incentive budget.
- **Arbitrum and Optimism** ran live, with real usage and real value at stake, for
  **one to two years** before their tokens existed. ARB had no presale. The token
  showed up once there was real usage to distribute against and a governance function
  to serve — it was never a prerequisite for the chain working.

None of these are edge cases — they're the dominant patterns among the systems Suwappu
is directly competing with or building on top of (LTP's own §5.5 already cites Filecoin
and Storj as the token-requiring end of the deployment spectrum; CCTP is the
token-free end of that same spectrum, and it's the one moving the most stablecoin
volume today).

## 3. The revised architecture

### 3.1 Bridge (LTP) — stablecoin-native, no SUWP dependency

CCTP-shaped: burn-and-mint (or lock-and-release, for chains without a native mint
authority) of the stablecoin itself, attested by the PQ quorum-signature infrastructure
already built this cycle (`SuwappuDagQuorumHeaderOracle.sol`,
`SuwappuDagValidatorRegistry.sol` in `suwappu-revm`) rather than a token-staked
validator set. Node/attestor collateral is posted **in the stablecoin being
transferred**, not in a separate speculative asset — an attestor bonds USDC to attest
USDC transfers. This removes the circularity of the previous design (users need SUWP to
move USDC, operators need to acquire SUWP before the bridge has any volume to earn SUWP
from) entirely.

### 3.2 Chain (suwappu-dag) — bootstrap security via bonded/restaked stablecoins

When the chain launches, it doesn't need a freshly-launched SUWP stake to secure
consensus on day one. Per the EigenLayer pattern, it can bootstrap Authority/Validator
Ring security using the **same bonded stablecoin capital** already backing bridge
attestors — one shared operator identity and one shared collateral pool across bridge
and chain, which was the genuinely good idea in the now-superseded
`NODE_UNIFICATION.md`. What's dropped is the requirement that the shared collateral be
a token nobody can acquire yet; what's kept is "one operator set, not two."

`suwappu-dag#23`'s `MAX_SUPPLY` cap on `Intent::MintInflation` remains good
infrastructure regardless of this change — a hard ceiling on any future emission is
correct hygiene independent of whether that emission is pre-mined or security-mined.
What's now explicitly provisional is the **number** (1,000,000,000), which was derived
from the old pre-mine model. If/when a token launches under this architecture, its
supply curve is a separate decision to make at that time, informed by real bridge
volume data this architecture is designed to produce.

### 3.3 SUWP — deferred, not designed yet

If a token launches at all, it arrives **after** the bridge and chain are already
running on stablecoin-native security, the same way ARB arrived after Arbitrum had two
years of real usage. At that point it is a governance/value-capture token distributed
against real, observed usage — not a bootstrapping mechanism, and not something this
document specifies, because specifying it now would repeat the exact mistake being
corrected here: designing a token's economics before there's any real data to design
them from.

## 4. What this deliberately does not do

- Does not specify token supply, emission, vesting, or distribution for SUWP. That's a
  future decision, made with real usage data, not now.
- Does not change LTP's whitepaper §5.5 interfaces (`NodeIncentive`,
  `CommitmentPricing`, `AdmissionControl`) — they're still the right abstraction; only
  the asset backing them changes (bonded stablecoins instead of SUWP).
- Does not touch `suwappu-dag#23`'s on-chain cap mechanism — kept, with its specific
  number flagged as provisional.
- Does not resolve the mechanics of "how does bonded stablecoin collateral convert into
  chain consensus rights" in code. That's the next design question, once the bridge is
  live and there's real bonded capital to reason about — not before.

## 5. Summary

The bridge and the chain don't need SUWP to be economically secure — CCTP proves a
bridge can run on zero native token, and EigenLayer proves a chain can bootstrap
security by renting already-staked capital instead of recruiting its own. Suwappu
adopts both patterns: the bridge bonds and attests in the stablecoin being transferred,
the chain later reuses that same bonded capital pool for consensus security
(one shared operator identity, per the idea `NODE_UNIFICATION.md` got right), and SUWP —
if it exists at all — launches after both are running, against real usage, the way
ARB and OP did. Nothing about token supply or emission is decided by this document;
that decision is deferred to when it can be made with real data instead of a guess.
