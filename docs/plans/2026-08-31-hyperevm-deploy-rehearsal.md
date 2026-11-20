# HyperEVM testnet deploy — rehearsal record

**Date:** 2026-08-31
**Status:** rehearsal evidence. No transaction was broadcast to the public
HyperEVM testnet (that needs a faucet-funded key — see §5). Everything
below was run locally against the pinned toolchain and against a fork of
the live chain.

This record backs the sequencing in
[`2026-08-31-hyperliquid-ethereum-corridor.md`](2026-08-31-hyperliquid-ethereum-corridor.md)
with measured numbers, so the go-live in §5 is a fill-in-the-key step, not
a discovery step.

## 1. Toolchain

- Foundry **v1.7.1** (the exact CI pin from `.github/workflows/contracts.yml`),
  installed from the pinned release tarball.
- Contract deps at the `foundry.lock` revisions: forge-std v1.16.2,
  openzeppelin-contracts v5.7.0, sp1-contracts v6.1.1.
- `forge test`: **335 passed, 0 failed, 1 skipped** (44 suites).
- Python: `make test-python` equivalent — **4,204 passed, 9 skipped**.

## 2. Live HyperEVM testnet facts (measured, not assumed)

Queried directly from `https://rpc.hyperliquid-testnet.xyz/evm` on
2026-08-31 (~block 63,030,7xx):

| Fact | Value | How measured |
|---|---|---|
| Chain ID | `998` | `eth_chainId` |
| Small-block gas limit | **3,000,000** | every sampled head block |
| Big-block gas limit | **30,000,000** | found big block `63,030,476` while scanning |
| Block cadence | small ~1s, big ~1/min | gasLimit histogram over 240 blocks |
| Gas token | HYPE | chain metadata |

**Consequence:** the batched stack deploy needs ~6.3M gas (forge estimate
against the live RPC), and even split per-CREATE the registry-side batch
exceeds the 3,000,000 small-block limit. The deployer **must** ride the
big-block lane. `scripts/hyperevm_enable_big_blocks.py` does this via the
official Hyperliquid SDK (`Exchange.use_big_blocks(True)`), and
`scripts/deploy_hyperevm_testnet.sh` invokes it automatically at preflight
(unless `BIG_BLOCKS_READY=1`).

## 3. Deploy on a fork of the live testnet

`anvil --fork-url https://rpc.hyperliquid-testnet.xyz/evm --chain-id 998`
forked the real chain at block **63,030,833** (inheriting its 3M gas
limit), so the contracts executed against actual live HyperEVM state and
EVM configuration — not a vanilla local chain.

- `DeployTestnet.s.sol` → **ONCHAIN EXECUTION COMPLETE & SUCCESSFUL**
  (LTPAnchorRegistry impl + ERC1967Proxy + LTPMultiSig + TimelockController).
- `DeployBridge.s.sol` → **COMPLETE & SUCCESSFUL**. Measured CREATE gas on
  the fork: `OptimisticBridgeChallenge` **1,208,649**, `ZKBridgeVerifier`
  **813,256**.

(Note: anvil does not reproduce HyperEVM's small/big-block mempool gating —
that lane behavior is a HyperCore feature. The gating requirement is
established from the §2 live measurement, not the fork.)

## 4. Full flow on a local chain-998 EVM

`scripts/deploy_hyperevm_testnet.sh` + `scripts/verify_corridor_deployment.py`
run green end-to-end:

1. Deploy registry stack + bridge stack.
2. Register the bridge signer's ML-DSA-65 vk hash through the **complete
   governance path** — MultiSig(submit→confirm→execute) wrapping
   `Timelock.schedule`, then after the delay a second MultiSig round for
   `Timelock.execute`. On-chain check: `authorizedSigners(vkHash) == true`
   and registry admin == Timelock.
3. SDK leg: `HYPEREVM_TESTNET` profile → `AnchorClient` → live-config check
   → on-chain `anchor()` under the registered signer → read back
   `isAnchored == true`, state `ANCHORED` → build the
   `hyperevm-testnet:eth-sepolia` corridor payload and confirm the depth-1
   signing policy holds at the chain head.

A real bug was caught and fixed during this rehearsal: the repo's older
`RegisterGatewaySigner.s.sol` assumes a `transactionCount()` /
`submit()` MultiSig ABI that the deployed `LTPMultiSig` does not have (it
exposes `getTransactionCount()` / `submitTransaction()`); the new driver
uses the correct interface.

## 5. Go-live — the only remaining step

Broadcasting to the public testnet needs a key holding testnet HYPE.
Public faucets Sybil-gate on Ethereum-mainnet history (gas.zip returns
`reward_amount: 0` for a fresh key) or require an account login / captcha,
none of which a headless session can satisfy. Once a funded deployer +
operator pair exists:

```bash
export PATH="$PATH:<foundry>/bin"
DEPLOYER_PRIVATE_KEY=0x...   \
OPERATOR_PRIVATE_KEY=0x...   \
BRIDGE_OPERATOR_VK_HASH=0x... \
scripts/deploy_hyperevm_testnet.sh          # preflights, enables big blocks, deploys, registers

REGISTRY_ADDRESS=0x<proxy from output> \
ANCHOR_SENDER_PRIVATE_KEY=0x...           \
BRIDGE_OPERATOR_VK_HASH=0x...             \
python3 scripts/verify_corridor_deployment.py
```

Then record the printed addresses in
[`../DEPLOYED_CONTRACTS.md`](../DEPLOYED_CONTRACTS.md) and link the
governance proposal, per the repo rule that that file changes only when
contracts actually deploy.
