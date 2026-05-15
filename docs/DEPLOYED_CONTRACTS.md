# ETP Deployed Contracts and Wallets

**Author:** Javier Calderon Jr, CTO — Global Settlement (GSX)
**Last Updated:** April 27, 2026

---

## Wallets

| Role | Address | Scope |
|---|---|---|
| Deployer | `0xcBFDDCb830eE902248F6d1b0A0C64f6e4E35b8E9` | Both chains |
| Bridge Operator VK Hash | `0x4212a67b46dd5fea793af0b980911ab6656313eb2ffb7d68b858187464ed2541` | Both chains |

The deployer wallet deployed all contracts on both chains. After deployment, admin was irreversibly transferred to the Timelock on each chain. The deployer has no privileged access post-deployment.

---

## GSX Testnet — Chain ID `103115120`

### Registry (v5, deployed block 687,609)

| Contract | Address |
|---|---|
| LTPAnchorRegistry (Implementation) | `0xADf01df5B6Bef8e37d253571ab6e21177aCb7796` |
| ERC1967Proxy | `0xB29d8BFF4973D1D7bcB10E32112EBB8fdd530bF4` |
| LTPMultiSig (2-of-2) | `0x0106A79e9236009a05742B3fB1e3B7a52F44373D` |
| TimelockController (60s delay) | `0x7C2665F7e68FE635ee8F10aa0130AEBC603a9Db8` |

### Bridge (deployed block 915,896)

| Contract | Address |
|---|---|
| OptimisticBridgeChallenge | `0x51FAaEB0e0464C3F5bd50C27679d05CF52F0F6Dc` |
| ZKBridgeVerifier | `0x80DC1079B1a9A4eb5a4e7a0A389542f060D61A2A` |

### Transaction Summary

| Category | Transactions | Blocks |
|---|---|---|
| Registry Deployment | 5 | 687,609 |
| Registry Signer Registration | 6 | 911,653 - 911,738 |
| Bridge Contract Deployment | 5 | 915,896 |
| Bridge Signer Registration | 6 | 916,133 - 916,351 |
| Bridge Anchor (April 7) | 2 | ~916,329 |
| Bridge Anchor (April 9) | 2 | Latest |
| **Total** | **26** | |

---

## Base Sepolia — Chain ID `84532`

### Registry (v6, deployed block 39,835,640)

| Contract | Address |
|---|---|
| LTPAnchorRegistry (Implementation) | `0xb1Da18e714dD067f17d15C3Fe2EC2f39A5a3459E` |
| ERC1967Proxy | `0x79eF1B7914f98C5C1404617449AB1f377c475996` |
| LTPMultiSig (2-of-2) | `0x4c324c3c3475f58b67d3c879880D6c94eDC82E49` |
| TimelockController (60s delay) | `0xc915740e35E38569E47f611eA5772Ff5278bc5Ae` |

### Bridge (deployed block 39,928,377)

| Contract | Address |
|---|---|
| OptimisticBridgeChallenge | `0x5083194d9e8EB54Fc397E69A518Be9503C767Dd0` |
| ZKBridgeVerifier | `0x4Df2D23269D0841200b36106AA90ba653e30DFf3` |

### Transaction Summary

| Category | Transactions | Blocks |
|---|---|---|
| Registry Deployment | 6 | 39,835,640 |
| Registry Signer Registration | 6 | 39,917,964 - 39,918,095 |
| Bridge Contract Deployment | 5 | 39,928,377 |
| Bridge Signer Registration | 6 | 39,929,353 - 39,929,406 |
| Bridge Anchor (April 7) | 2 | ~39,929,433 |
| Bridge Anchor (April 9) | 2 | Latest |
| **Total** | **27** | |

---

## Governance Architecture (Both Chains)

```
MultiSig (2-of-2) → TimelockController (60s) → LTPAnchorRegistry (Proxy)
                                               → OptimisticBridgeChallenge
                                               → ZKBridgeVerifier
```

- Admin on all contracts is the **Timelock** — never the deployer or MultiSig directly
- Signer registration requires the full governance path: MultiSig propose → confirm → execute schedule → wait 60s → execute register
- Bridge contracts are wired together: `OptimisticBridgeChallenge.setZKVerifier(zkVerifier)` enables instant finality via ZK proof
- Timelock delay is 60s (testnet); production target is 24-48 hours

## On-Chain Verification Commands

```bash
# GSX Testnet
cast call 0xB29d8BFF4973D1D7bcB10E32112EBB8fdd530bF4 "version()(uint256)" --rpc-url "$GSX_RPC_URL"
cast call 0xB29d8BFF4973D1D7bcB10E32112EBB8fdd530bF4 "admin()(address)" --rpc-url "$GSX_RPC_URL"

# Base Sepolia
cast call 0x79eF1B7914f98C5C1404617449AB1f377c475996 "version()(uint256)" --rpc-url "$BASE_SEPOLIA_RPC_URL"
cast call 0x79eF1B7914f98C5C1404617449AB1f377c475996 "admin()(address)" --rpc-url "$BASE_SEPOLIA_RPC_URL"
```

## ABIs for Non-Python Integrators

The full `LTPAnchorRegistry` ABI is checked in at
[`contracts/abi/LTPAnchorRegistry.json`](../contracts/abi/LTPAnchorRegistry.json)
so dApp developers can verify anchors from JavaScript / TypeScript / Go
without running a local Solidity build. A worked ethers v6 example lives
at [`examples/verify_anchor_from_js.mjs`](../examples/verify_anchor_from_js.mjs):

```bash
node examples/verify_anchor_from_js.mjs \
  https://sepolia.base.org \
  0x79eF1B7914f98C5C1404617449AB1f377c475996 \
  <entityIdHash>
```

To regenerate the ABI after a contract change, run `forge build` in
`contracts/` and copy the `abi` field of
`contracts/out/LTPAnchorRegistry.sol/LTPAnchorRegistry.json` into
`contracts/abi/LTPAnchorRegistry.json` (or use the `make abi` target).

---

**Total across both chains: 53 on-chain transactions, all status `0x1` (success).**
