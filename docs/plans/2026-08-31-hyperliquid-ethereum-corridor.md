# Plan — Ethereum mainnet <> Hyperliquid HyperEVM corridor

**Date:** 2026-08-31
**Status:** SDK surface landed (chain profiles + corridor lanes); everything
on-chain in this plan is proposed sequencing, not committed work.
**Driver:** SuwappuBot is launching a DEX on Hyperliquid's HIP-4 outcome
markets, and LTP should be the first-class Ethereum↔Hyperliquid bridge
under it.

## 1. Context: what HIP-4 is and what it is not

HIP-4 (live on Hyperliquid since 2026-05-02) adds fully collateralized
binary outcome contracts to the native trading engine, with permissionless
market deployment gated on a 500,000 HYPE deployer stake (6-month lock).
Two consequences for this plan:

- The HIP-4 market surface lives on **HyperCore** (the native Rust trading
  layer), not on HyperEVM. LTP does not integrate with HIP-4 directly;
  it bridges the **HyperEVM** side (chain ID `999`), which shares HyperBFT
  consensus and state with HyperCore. Moving assets between HyperEVM and
  HyperCore uses Hyperliquid's own system contracts and is SuwappuBot's
  DEX-side concern.
- The 500k HYPE deployer stake is a SuwappuBot business prerequisite, not
  an LTP protocol concern. Nothing in this repo touches it.

## 2. What already exists in this repo

The corridor and anchor surfaces are EVM-generic, so Hyperliquid needs no
new cryptography and **no wire-format change**:

| Piece | State |
|---|---|
| `AnchorClient` (EVM JSON-RPC, rate limiter, circuit breaker) | Implemented — works against any EVM chain, HyperEVM included |
| `LTP-corridor-v1` attestation payload | Keys chains by u32; `1` and `999` are ordinary payload values — no `v2` bump, so no wire-format Linear ticket is triggered |
| Registry + bridge contracts | Deployed on SUWAPPU Testnet and Base Sepolia (`docs/DEPLOYED_CONTRACTS.md`); Solidity is chain-agnostic |
| Chain profiles (`src/ltp/anchor/chain_profiles.py`) | **Added by this change** — `ethereum_mainnet` (1), `ethereum_sepolia` (11155111), `hyperevm_mainnet` (999), `hyperevm_testnet` (998) with finality postures |
| Corridor lanes (`src/ltp/corridor/lanes.py`) | **Added by this change** — directional Ethereum↔HyperEVM lanes with asymmetric confirmation policy |

### The asymmetric confirmation policy

- **Ethereum → HyperEVM (deposit lane):** the corridor signs only heights
  at depth ≥ 64 (2 PoS epochs, the chain's own `finalized` tag). An
  Ethereum block below finality can legally reorg; a bridge that attests
  earlier re-creates the class of failure this protocol exists to close.
- **HyperEVM → Ethereum (withdrawal lane):** depth 1. HyperEVM shares
  HyperBFT with HyperCore; a committed block is final and there are no
  reorgs after commit.

## 3. Proposed deploy sequence

### Phase 0 — staging pair (Sepolia `11155111` <> HyperEVM testnet `998`)

1. Deploy `LTPAnchorRegistry` (UUPS), `LTPMultiSig`, `TimelockController`,
   `OptimisticBridgeChallenge`, `ZKBridgeVerifier` on HyperEVM testnet with
   the existing `contracts/script/` flow, and the registry set on Sepolia.
2. **HyperEVM gotcha:** the chain interleaves small blocks (~1s, low gas
   limit) with big blocks (~1min, high gas limit). Contract *deployment*
   transactions generally exceed the small-block gas limit — the deployer
   wallet must flip itself to the big-block lane first (Hyperliquid's
   `evmUserModify` action). Steady-state `anchor(...)` writes fit small
   blocks. Verify both empirically on `998` before writing the runbook.
3. Fund the operator wallet with testnet HYPE (gas token on `999`/`998` is
   HYPE, not ETH) and register corridor signers through the full
   governance path (MultiSig propose → confirm → Timelock schedule → wait
   → execute), same as the Base Sepolia deploy.
4. Run the staging lanes (`eth-sepolia:hyperevm-testnet` and reverse)
   end-to-end: anchor → 7-of-9 attestation → optimistic window →
   finalize. Soak long enough to catch at least one Sepolia reorg below
   depth 64 and confirm the corridor correctly refuses to attest it.

### Phase 1 — mainnet pair (Ethereum `1` <> HyperEVM `999`)

Gated on the v7 hardening actually deploying (see
`docs/DEPLOYED_CONTRACTS.md` §v7): MultiSig threshold ≥ ceil(N/2)+1,
Timelock ≥ 24h, `BridgeEmitter` with `permissionless=false`, and
`ZKBridgeVerifier.lockProduction()`. Until v7, the live verifier is
`MODE_SIMULATED` — mainnet value must treat the **optimistic path**
(`openWindow` → challenge period → `finalizeWindow`) as the only real
finality, exactly as `BRIDGE_TRUST_MODEL.md` says for Base Sepolia today.

Mainnet-only additions:

- Ethereum L1 gas is the dominant operating cost; anchor batching cadence
  needs an economics pass before launch (out of scope here).
- Operator keys move to KMS (`operator_kms_key_id`), no plaintext keys.

### Phase 2 — lane activation and operations

- Wire the relayer/watcher stack (`src/ltp/bridge/`) to the two
  `ChainConfig`s produced from the new profiles.
- Extend `docs/OPERATOR_RUNBOOK.md` with the HyperEVM section (HYPE gas
  monitoring, big-block procedure, RPC failover).
- After each real deployment lands, record addresses in
  `docs/DEPLOYED_CONTRACTS.md` — that file changes **only** when contracts
  actually deploy, per repo rule.

## 4. Explicitly out of scope

- HIP-4 market deployment, HYPE staking, HyperCore↔HyperEVM transfers
  (SuwappuBot DEX-side).
- ERC-20 wrapping / token issuance on either side.
- Corridor wire-format changes (none needed).
- Any edit to deployed-contract addresses (nothing has deployed yet).

## 5. Open questions

1. **RPC provider** for HyperEVM (public `rpc.hyperliquid.xyz/evm` rate
   limits vs a dedicated provider) — needs a decision before Phase 0 soak.
2. **Big-block mechanics** — confirm current `evmUserModify` semantics
   against live Hyperliquid docs at deploy time; the cadence and gas
   limits here are as-of-writing and Hyperliquid iterates fast.
3. **Withdrawal-lane challenge window** on Ethereum: HyperBFT gives the
   corridor depth-1 attestation, but the Ethereum-side optimistic window
   is still the user-facing latency. Whether to shorten it for this lane
   is a trust-model decision, not a default.
4. Linear tracking: file the Phase 0 deploy work under **LTP Dev Net**
   when it is picked up (no wire ticket needed — see §2).
