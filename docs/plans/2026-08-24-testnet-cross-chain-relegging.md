# Testnet Cross-Chain Re-Legging Plan

**Date:** 2026-08-24
**Status:** Tooling landed; deploys pending funded keys
**Tracks:** suwappu-dag `/goal` items E2 (deploy registry + bridge pair on new
chains), E3 (regenerate/register gateway keypair, fund operators), E4 (run
`scripts/bridge_live.py` end-to-end)

## Context

The bridge was legged on two chains (see `DEPLOYED_CONTRACTS.md`):

| Leg | Status (verified 2026-08-24) |
|---|---|
| Base Sepolia (84532) | **Alive** — registry proxy `0x79eF1B79…` answers `version() = 6`; deployer holds ~0.059 ETH |
| SUWAPPU Testnet (103115120) | **Dead** — RPC was an AWS ELB (`us-east-2`); AWS infra is retired. Contracts unreachable |

With one living leg there is nothing to bridge across. This plan re-legs the
bridge onto public L2 testnets that nobody has to operate, so cross-chain
transfers can be exercised while the SUWAPPU chain's own public testnet
(suwappu-dag `/goal` section D) is stood up separately. Hosting for the bridge
operator/relayer services is now **Railway** (project `suwappu`), not AWS.

## Target chains

| Chain | Chain ID | Why |
|---|---|---|
| Base Sepolia | 84532 | Existing live leg — keep as-is, no redeploy |
| **Arbitrum Sepolia** | 421614 | New leg. Cheap gas, easy faucets, different L2 stack than Base |
| **OP Sepolia** | 11155420 | New leg. Same reasons; gives a 3-leg mesh |
| Ethereum Sepolia | 11155111 | Optional; faucet ETH is scarcer. Config template provided |

Adding legs **adds** rows to `DEPLOYED_CONTRACTS.md`; no deployed address
changes (satisfies the "no address changes without a plan" rule — this file is
that plan for the additions).

## What was built (this branch)

- `config/deploy/*.env.template` — per-chain deploy configs (only templates are
  tracked; filled copies are gitignored)
- `scripts/deploy_testnet_leg.sh` — one-command leg deploy:
  `DeployTestnet.s.sol` (registry impl + ERC1967 proxy + 2-of-2 multisig +
  60s timelock, admin → timelock) then `DeployBridge.s.sol`
  (OptimisticBridgeChallenge + ZKBridgeVerifier, wired, admin → timelock);
  verifies `version()`/`admin()` post-deploy and writes
  `deployments/<label>.json` + the markdown for `DEPLOYED_CONTRACTS.md`
- `scripts/register_signer_leg.sh` — signer registration through the full
  governance path (MultiSig submit/confirm/execute → Timelock schedule → wait
  → second MultiSig round → Timelock execute), parameterized per chain;
  idempotent if interrupted mid-wait
- `scripts/bridge_live.py` — generalized to any leg pair via `--l1-prefix` /
  `--l2-prefix` (`<PREFIX>_RPC_URL/_ANCHOR_REGISTRY/_OPERATOR_KEY/_CHAIN_ID`);
  legacy env names still work

The whole path was validated end-to-end against a local anvil chain
(deploy → governance signer registration → `authorizedSigners == true`).
The Solidity suite passes on these sources (333 passed / 1 skipped).

## Runbook per new leg

```bash
# 0. One-time: foundry installed, deps installed
cd contracts && forge install foundry-rs/forge-std OpenZeppelin/openzeppelin-contracts && cd ..

# 1. Fund the deployer EOA on the target chain (faucet links in config/deploy/README.md).
#    A full leg costs well under 0.01 ETH on the L2 testnets.

# 2. Configure
cp config/deploy/arbitrum-sepolia.env.template config/deploy/arbitrum-sepolia.env
$EDITOR config/deploy/arbitrum-sepolia.env   # DEPLOYER_PRIVATE_KEY, SUWAPPU_OPERATOR_ADDRESS, OPERATOR_PRIVATE_KEY

# 3. Deploy registry + governance + bridge pair
scripts/deploy_testnet_leg.sh config/deploy/arbitrum-sepolia.env

# 4. Register the bridge-operator ML-DSA-65 vkHash (~6 txs, includes 60s timelock wait)
scripts/register_signer_leg.sh config/deploy/arbitrum-sepolia.env

# 5. Record: paste the printed markdown into docs/DEPLOYED_CONTRACTS.md (PR referencing this plan)

# 6. Smoke-test a cross-chain transfer against the Base Sepolia leg
python scripts/bridge_live.py \
    --l1-prefix ARBITRUM_SEPOLIA --l2-prefix BASE_SEPOLIA \
    --direction both --env-file contracts/.env --keypair bridge_operator_keypair.json
# Capture bridge_results.json as the /goal E4 transcript.
```

Repeat for `op-sepolia.env`.

## Hosting (Railway)

Railway project `suwappu` already runs `suwappu-bridge` and `suwappu-relayer`
services. After a leg deploys, give those services the new leg's variables
(from `deployments/<label>.json`):

```
ARBITRUM_SEPOLIA_RPC_URL=https://sepolia-rollup.arbitrum.io/rpc
ARBITRUM_SEPOLIA_CHAIN_ID=421614
ARBITRUM_SEPOLIA_ANCHOR_REGISTRY=<ERC1967Proxy address>
ARBITRUM_SEPOLIA_OPERATOR_KEY=<operator key>   # or reuse RELAYER_PRIVATE_KEY
```

## Honest caveats (unchanged from `BRIDGE_TRUST_MODEL.md` / `/goal` E5)

- `ZKBridgeVerifier` deploys in `MODE_SIMULATED` (BRIDGE_ZK_MODE=0): finality
  comes from the **optimistic path only**. Do not market instant finality.
- Trust model is 2-of-2 discretionary with zero bonds — fine for a testnet
  demo, not for value-bearing settlement.
- 60s timelock and 3600s challenge window are testnet parameters; mainnet
  minimums are enforced separately by `DeployMainnet*.s.sol` (v7 hardening).
- The corridor daemon (`/goal` E1) still does not exist; the 7-of-9 super-node
  quorum remains an in-process simulation.

## Exit criteria

1. Two new legs live (Arbitrum Sepolia + OP Sepolia), signer registered on each.
2. `DEPLOYED_CONTRACTS.md` updated with the new tables (PR referencing this plan).
3. `bridge_live.py` transcript showing a successful transfer in both directions
   between at least two living legs.
4. Railway `suwappu-bridge` / `suwappu-relayer` pointed at the new legs.
