# LTP Deployed Contracts and Wallets

**Author:** Javier Calderon Jr, CTO — Suwappu (SUWAPPU)
**Last Updated:** August 24, 2026

---

## Live legs at a glance

The bridge is legged on **two live chains**. Every leg runs the same stack:
`LTPAnchorRegistry` (UUPS proxy) + `LTPMultiSig` (2-of-2) + `TimelockController`,
plus the `OptimisticBridgeChallenge` / `ZKBridgeVerifier` pair.

| Leg | Chain ID | Registry proxy | Registry version | Status |
|---|---|---|---|---|
| Base Sepolia | `84532` | `0x79eF1B7914f98C5C1404617449AB1f377c475996` | v6 | **Live** |
| Ethereum Sepolia | `11155111` | `0xfd66b836cbe118001156c006e05cfe4432733cd3` | v6 | **Live** (deployed 2026-08-24) |
| SUWAPPU Testnet | `103115120` | `0xB29d8BFF4973D1D7bcB10E32112EBB8fdd530bF4` | v5 | **Retired** — RPC gone with the AWS teardown |

A cross-chain anchor pair has been demonstrated across the two live legs — see
[Verified cross-chain anchor pair](#verified-cross-chain-anchor-pair) below.

---

## Wallets

| Role | Address | Scope |
|---|---|---|
| Deployer (original) | `0xcBFDDCb830eE902248F6d1b0A0C64f6e4E35b8E9` | Base Sepolia, SUWAPPU Testnet (retired) |
| Deployer (2026-08 re-legging) | `0xdC517061243D7659b5CeeCCAB5E1269cE3dcD1F1` | Ethereum Sepolia |
| MultiSig owner 2 / operator (2026-08 re-legging) | `0xC830218082187A693AA6aa735528Cf9daE4d1a94` | Ethereum Sepolia |
| Bridge Operator VK Hash | `0x4212a67b46dd5fea793af0b980911ab6656313eb2ffb7d68b858187464ed2541` | All legs |

On every leg, admin is irreversibly transferred to that leg's Timelock at deploy
time — no deployer retains privileged access post-deployment. This is asserted
on-chain by the deploy script (`registry.admin() == timelock`) before it records
the leg, so a leg that failed the handoff never gets written down here.

The 2026-08 re-legging keypair is **testnet-only** and custodied in Turnkey
(organization `5cf56ed5-…`; private-key ids `a5f1eb39-…` deployer,
`047f429f-…` operator). It holds no mainnet value and is not an upgrade
authority on any leg beyond its 1-of-2 seat in the Ethereum Sepolia MultiSig.

---

## SUWAPPU Testnet — Chain ID `103115120` — RETIRED

> **This leg is no longer reachable.** Its RPC endpoint was an AWS load balancer
> in `us-east-2` that was torn down with the rest of the AWS footprint; the chain
> itself is gone, so these contracts cannot be called. The addresses are retained
> as a historical record of the v5 deployment and for auditing the transaction
> history below — **do not** point an integration at this leg. The re-legging that
> replaced it is documented in
> [`plans/2026-08-24-testnet-cross-chain-relegging.md`](plans/2026-08-24-testnet-cross-chain-relegging.md).

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

## Ethereum Sepolia — Chain ID `11155111`

Deployed 2026-08-24 as a second **living** leg after the original SUWAPPU
Testnet leg (chain `103115120`) was retired with its AWS infrastructure. This
is the re-legging target from
[`docs/plans/2026-08-24-testnet-cross-chain-relegging.md`](plans/2026-08-24-testnet-cross-chain-relegging.md);
deployed with `scripts/deploy_testnet_leg.sh` +
`scripts/register_signer_leg.sh`. Deployer/operator keys are custodied in
Turnkey (org `5cf56ed5-…`, private-key ids `a5f1eb39-…` deployer /
`047f429f-…` operator).

### Registry (v6, deployed block 11,553,962)

| Contract | Address |
|---|---|
| LTPAnchorRegistry (Implementation) | `0x4896da1439e679ed56cfb8c773e3b57cadfd5c9c` |
| ERC1967Proxy | `0xfd66b836cbe118001156c006e05cfe4432733cd3` |
| LTPMultiSig (2-of-2) | `0xda3781fa161caaa824d7c478638d427ba5676664` |
| TimelockController (60s delay) | `0x42c4017cee96b19c467dcf44e926da365cd0499c` |

### Bridge (deployed block 11,553,963)

| Contract | Address |
|---|---|
| OptimisticBridgeChallenge | `0x0af67a32d2578f57397f0022bff9ba2647d66b58` |
| ZKBridgeVerifier (`MODE_SIMULATED`) | `0x4d687361cc02e134c70d1a0d3e2e9ee7cc51f1fa` |

Registry admin is the Timelock (verified on-chain: `admin() == 0x42c4017c…`).
Bridge-operator signer `0x4212a67b…64ed2541` registered through the full
MultiSig → Timelock governance path.

---

## Verified cross-chain anchor pair

The two live legs have been exercised end to end: the **same entity**, under the
**same registered bridge-operator signer**, with the **same Merkle root**,
anchored on both chains. Each registry stamps `targetChainId` from its own
`block.chainid` rather than from caller-supplied data — that is the contract's
cross-chain replay guard, and the differing values below are it working.

| Field | Ethereum Sepolia | Base Sepolia |
|---|---|---|
| Anchor tx | [`0x4c3a2276…e02d4e`](https://sepolia.etherscan.io/tx/0x4c3a2276b9dd9ea81cda85b938f6ed47a460810f2112e5faf3a6525eaee02d4e) | [`0xe78567c7…bc26d8`](https://sepolia.basescan.org/tx/0xe78567c7609bb3b251960a3cf764ce8e33b0d1b3b27be54b5459441fe8bc26d8) |
| `targetChainId` (self-stamped) | `11155111` | `84532` |
| Sequence | 1 | 14 |
| `entityState` | `ANCHORED` | `ANCHORED` |

Shared across both: `entityIdHash` `0xdb1404697e58e26737f755a3da21a338bbf11e4b529a415345366c661e5a3945`,
`signerVkHash` `0x4212a67b46dd5fea793af0b980911ab6656313eb2ffb7d68b858187464ed2541`,
`merkleRoot` `0xb1364cf2b85965d2c544542a435c0f4425104a179777df60c2a2e2369b7ad0f4`.
Machine-readable record: [`deployments/cross_chain_anchor_pair.json`](../deployments/cross_chain_anchor_pair.json).

**Scope of what this proves.** On-chain, `anchor()` authorizes by *registered
`signerVkHash`* — it does not verify the ML-DSA signature, which is an off-chain
concern (see [`STABILITY_PROMISES.md`](STABILITY_PROMISES.md)). So this
demonstrates the registry write path and the replay guard across two live chains;
it is **not** a test of the off-chain LTP signing pipeline. The full signed path
runs through [`scripts/bridge_live.py`](../scripts/bridge_live.py) and needs the
bridge-operator ML-DSA keypair.

---

## Governance Architecture (All Live Legs)

```
MultiSig (2-of-2) → TimelockController (60s) → LTPAnchorRegistry (Proxy)
                                               → OptimisticBridgeChallenge
                                               → ZKBridgeVerifier
```

- Admin on all contracts is the **Timelock** — never the deployer or MultiSig directly
- Signer registration requires the full governance path: MultiSig propose → confirm → execute schedule → wait 60s → execute register
- Bridge contracts are wired together: `OptimisticBridgeChallenge.setZKVerifier(zkVerifier)` is meant to enable instant finality via ZK proof — **but the live `ZKBridgeVerifier` on every leg above is currently deployed in `MODE_SIMULATED`** (a keccak-based placeholder, not a real proof system; see `contracts/src/ZKBridgeVerifier.sol`). No production-deployed ZK verifier for ML-DSA/lattice-based signatures exists anywhere in the industry as of this writing — this is an honest R&D gap, not a swap-in-a-library task. Until `lockProduction()` is called after a real verifier backend lands, treat every anchor's finality as coming from the **optimistic path** (`openWindow` → `challengePeriod` → `finalizeWindow`), which is fully real. Don't rely on "instant finality" for anything moving value today.
- Timelock delay is 60s (testnet); production target is 24-48 hours

## On-Chain Verification Commands

Each command below is against a **live** leg. Both should report `6` for
`version()`, and an `admin()` equal to that leg's Timelock (the addresses in the
tables above) — if `admin()` ever comes back as an EOA, treat the leg as
compromised and stop using it.

```bash
# Base Sepolia (chain 84532)
export BASE_SEPOLIA_RPC_URL=https://sepolia.base.org
cast call 0x79eF1B7914f98C5C1404617449AB1f377c475996 "version()(uint256)" --rpc-url "$BASE_SEPOLIA_RPC_URL"
cast call 0x79eF1B7914f98C5C1404617449AB1f377c475996 "admin()(address)"   --rpc-url "$BASE_SEPOLIA_RPC_URL"

# Ethereum Sepolia (chain 11155111)
export ETHEREUM_SEPOLIA_RPC_URL=https://ethereum-sepolia-rpc.publicnode.com
cast call 0xfd66b836cbe118001156c006e05cfe4432733cd3 "version()(uint256)" --rpc-url "$ETHEREUM_SEPOLIA_RPC_URL"
cast call 0xfd66b836cbe118001156c006e05cfe4432733cd3 "admin()(address)"   --rpc-url "$ETHEREUM_SEPOLIA_RPC_URL"

# Confirm the bridge-operator signer is authorized on a leg
cast call 0xfd66b836cbe118001156c006e05cfe4432733cd3 \
  "authorizedSigners(bytes32)(bool)" \
  0x4212a67b46dd5fea793af0b980911ab6656313eb2ffb7d68b858187464ed2541 \
  --rpc-url "$ETHEREUM_SEPOLIA_RPC_URL"
```

The retired SUWAPPU Testnet leg is deliberately absent — its RPC no longer
resolves, so any command against it fails at the transport layer rather than
telling you anything about the contracts.

## ABIs for Non-Python Integrators

The full `LTPAnchorRegistry` ABI is checked in at
[`contracts/abi/LTPAnchorRegistry.json`](../contracts/abi/LTPAnchorRegistry.json)
so dApp developers can verify anchors from JavaScript / TypeScript / Go
without running a local Solidity build. A worked ethers v6 example lives
at [`examples/verify_anchor_from_js.mjs`](../examples/verify_anchor_from_js.mjs):

```bash
# Base Sepolia
node examples/verify_anchor_from_js.mjs \
  https://sepolia.base.org \
  0x79eF1B7914f98C5C1404617449AB1f377c475996 \
  <entityIdHash>

# Ethereum Sepolia
node examples/verify_anchor_from_js.mjs \
  https://ethereum-sepolia-rpc.publicnode.com \
  0xfd66b836cbe118001156c006e05cfe4432733cd3 \
  <entityIdHash>
```

The ABI is identical across both live legs — they run the same v6 implementation
bytecode, deployed separately per chain.

To regenerate the ABI after a contract change, run `forge build` in
`contracts/` and copy the `abi` field of
`contracts/out/LTPAnchorRegistry.sol/LTPAnchorRegistry.json` into
`contracts/abi/LTPAnchorRegistry.json` (or use the `make abi` target).

---

## v7 Governance Hardening (Source Updates — Pending Deploy)

The Solidity changes in PR #8 Commit 5 (`docs/security/audits/internal/SECURITY_AUDIT_2026-05-15.md` LTP-A-002, LTP-A-007, LTP-A-009, LTP-A-017) are source-only — they do **not** modify any deployed v5/v6 contract. They take effect when the next batch (v7) is deployed using the tightened `DeployMainnet.s.sol` script.

See [Bridge Trust Model](BRIDGE_TRUST_MODEL.md) for what this means concretely for a user of the live deployments today — most importantly, that `lockProduction()` (the ZK production-mode lock) does not exist on the currently-deployed contracts, so the `MODE_SIMULATED` fast path (no real cryptographic verification, LTP-A-007) cannot be locked out until v7 actually deploys.

**This applies to *both* live legs, including the new one.** The Ethereum Sepolia
leg was deployed 2026-08-24 with `DeployTestnet.s.sol` + `DeployBridge.s.sol` —
the testnet scripts — so it carries the same pre-v7 posture as Base Sepolia:
2-of-2 MultiSig, 60-second Timelock, `MODE_SIMULATED` verifier. Re-legging
restored a second *live* chain to bridge across; it did **not** advance the
governance hardening. Do not read "newly deployed" as "hardened".

| Change | File | What it enforces at the next deploy |
|---|---|---|
| MultiSig Byzantine threshold | `contracts/script/DeployMainnet.s.sol` | `threshold >= ceil(N/2) + 1` (no more 2-of-2) |
| Timelock minimum delay | `contracts/script/DeployMainnet.s.sol` | `>= 24 hours` for mainnet (no more 60-second windows) |
| Reject testnet deploys via mainnet script | `contracts/script/DeployMainnet.s.sol` | Refuses chain IDs 31337, 84532, 11155111, 103115120 unless `ALLOW_TESTNET_DEPLOY=true` |
| ZK production-mode lock | `contracts/src/ZKBridgeVerifier.sol::lockProduction()` | Admin call irreversibly refuses `MODE_SIMULATED` |
| BridgeEmitter authorized senders | `contracts/src/BridgeEmitter.sol` | New deploys pass `permissionless=false` and call `setAuthorized(...)` per legitimate caller |
| Signer rotation grace period | `contracts/src/LTPAnchorRegistry.sol::rotateSignerWithGrace` | New optional admin function lets in-flight anchors signed by the old key remain valid for up to 7 days after rotation |

After v7 deploys, update the SUWAPPU Testnet / Base Sepolia tables above with the new addresses and link the corresponding governance proposal IDs.
