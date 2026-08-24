# Per-chain deploy leg configuration

One `.env.template` per target chain for `scripts/deploy_testnet_leg.sh`.
Copy the template for the chain you are deploying to, fill in the secrets,
and keep the filled copy out of git (only `*.template` files are tracked):

```bash
cp config/deploy/arbitrum-sepolia.env.template config/deploy/arbitrum-sepolia.env
$EDITOR config/deploy/arbitrum-sepolia.env      # fill DEPLOYER_PRIVATE_KEY etc.
scripts/deploy_testnet_leg.sh config/deploy/arbitrum-sepolia.env
```

Each leg deploys the same stack the live Base Sepolia leg runs
(see `docs/DEPLOYED_CONTRACTS.md`):

```
LTPMultiSig (2-of-2) → TimelockController (60s) → LTPAnchorRegistry (UUPS proxy)
                                                → OptimisticBridgeChallenge
                                                → ZKBridgeVerifier
```

Variables:

| Variable | Meaning |
|---|---|
| `CHAIN_LABEL` | Short label; names `deployments/<label>.json` and env-var prefixes |
| `CHAIN_ID` | Expected chain ID; the deploy script aborts if the RPC disagrees |
| `RPC_URL` | JSON-RPC endpoint |
| `EXPLORER_URL` | Block explorer base URL (informational) |
| `DEPLOYER_PRIVATE_KEY` | Funded EOA; becomes multisig owner 1 |
| `SUWAPPU_OPERATOR_ADDRESS` | Multisig owner 2 (address only; name kept for `DeployTestnet.s.sol` compat) |
| `BRIDGE_CHALLENGE_PERIOD` | Optimistic challenge window seconds (testnet default 3600) |
| `BRIDGE_MIN_OPERATOR_BOND` | Wei (testnet default 0) |
| `BRIDGE_MIN_CHALLENGER_BOND` | Wei (testnet default 0) |
| `BRIDGE_ZK_MODE` | 0 = SIMULATED (testnet), 3 = STARK. Testnet legs run 0 — see the `MODE_SIMULATED` caveat in `docs/DEPLOYED_CONTRACTS.md` |
| `SIGNER_VK_HASH` | ML-DSA-65 vkHash to register via `scripts/register_signer_leg.sh` |
| `OPERATOR_PRIVATE_KEY` | Multisig owner 2 key; only needed for the signer-registration confirm step |

Gas: a full leg (5 contract-creating transactions + wiring) costs well under
0.01 ETH on the L2 testnets. Faucets:

- Arbitrum Sepolia — https://faucet.quicknode.com/arbitrum/sepolia
- OP Sepolia — https://console.optimism.io/faucet
- Ethereum Sepolia — https://sepolia-faucet.pk910.de (PoW) or Google Cloud faucet
- Base Sepolia — https://portal.cdp.coinbase.com/products/faucet
