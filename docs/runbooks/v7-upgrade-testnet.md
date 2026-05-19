# v7 Upgrade — testnet ceremony

Step-by-step ceremony for swapping the v6 implementation behind the
GSX testnet (chain `103115120`) and Base Sepolia (chain `84532`)
`LTPAnchorRegistry` proxies with the v7 implementation that's on
`main` today. Mainnet runs from a different runbook
(`docs/runbooks/mainnet-deploy.md`, Phase D — not yet authored).

> **Roles:** This ceremony needs **both** signers of the 2-of-2
> `LTPMultiSig` to be available and reachable. Don't start without
> confirming attendance.

---

## What v7 changes

v7's deltas land in three places:

1. **Source-only** (no on-chain action): `rotateSignerWithGrace`,
   audit-finding-driven hardening throughout the registry. The
   implementation swap below is the only on-chain change.
2. **Mainnet-only** (DeployMainnet.s.sol enforces): 5-of-7 multisig
   floor, 24h timelock floor for upgrades. Testnet stays 2-of-2,
   60-second timelock — nothing to do here.
3. **Optional post-upgrade calls**: `lockProduction()` on
   ZKBridgeVerifier irreversibly locks production mode; this is
   appropriate for mainnet but **NOT for testnet** (locking on
   testnet would block in-development test flows). Skipped here.

Net: this ceremony is purely the registry implementation swap. The
pause rehearsal at the end drills the emergency-stop path that the
Phase B observability stack will trigger.

---

## Pre-flight (operator workstation, before any tx)

```bash
# 1. Confirm v7 source is on main and your local checkout is up to date.
git fetch origin main && git rev-parse origin/main
git diff origin/main..HEAD          # should be empty

# 2. Compile clean. Confirm v7 fits the 24 576-byte limit.
cd contracts && forge build --sizes

# 3. Storage-layout dry-run against the live testnets. This catches
#    slot reordering BEFORE the upgrade tx broadcasts.
export GSX_RPC_URL=<the gsx testnet rpc you have>
export BASE_SEPOLIA_RPC_URL=<base sepolia rpc>
forge test --match-path contracts/test/deployment/UpgradeV7.dryrun.t.sol -vv

# All four tests must pass (gsx + base × layout + pause-rehearsal).
```

If any dry-run test fails, **STOP**. The upgrade will revert or — worse
— silently corrupt state on a live proxy. Investigate the layout
diff with `forge inspect LTPAnchorRegistry storage-layout` before
proceeding.

---

## Ceremony — GSX testnet first

The 60-second timelock means the whole thing takes ~5 minutes if both
signers are at their keyboards. Run from a clean shell with:

```bash
export GSX_RPC_URL=...
export GSX_DEPLOYER_KEY=...   # the deployer wallet from DEPLOYED_CONTRACTS.md
export GSX_OPERATOR_KEY=...   # the second multisig signer
```

### Step 1 — Deploy v7 impl + submit schedule + execute (deployer)

```bash
cd contracts
forge script script/UpgradeV7.s.sol --sig "step1()" \
    --rpc-url $GSX_RPC_URL \
    --broadcast \
    --private-key $GSX_DEPLOYER_KEY
```

Save the printed `Schedule txId` and `Execute txId` — you need both
for steps 2-4.

### Step 2 — Operator confirms both txIds

Run twice, once per txId:

```bash
forge script script/UpgradeV7.s.sol --sig "step2(uint256)" <scheduleTxId> \
    --rpc-url $GSX_RPC_URL --broadcast --private-key $GSX_OPERATOR_KEY

forge script script/UpgradeV7.s.sol --sig "step2(uint256)" <executeTxId> \
    --rpc-url $GSX_RPC_URL --broadcast --private-key $GSX_OPERATOR_KEY
```

### Step 3 — Execute the schedule call through the multisig (deployer)

```bash
forge script script/UpgradeV7.s.sol --sig "step3(uint256)" <scheduleTxId> \
    --rpc-url $GSX_RPC_URL --broadcast --private-key $GSX_DEPLOYER_KEY
```

The timelock countdown starts now. **Wait 60 seconds.**

### Step 4 — Execute the upgrade (deployer, ≥ 60s after step 3)

```bash
forge script script/UpgradeV7.s.sol --sig "step4(uint256)" <executeTxId> \
    --rpc-url $GSX_RPC_URL --broadcast --private-key $GSX_DEPLOYER_KEY
```

The script's tail prints the new implementation address. Backfill it
into [`docs/DEPLOYED_CONTRACTS.md`](../DEPLOYED_CONTRACTS.md) under the
"v7, pending deploy" row in the same PR you open immediately after the
ceremony.

### Post-flight — storage-layout verification (live state)

```bash
forge inspect LTPAnchorRegistry storage-layout > /tmp/v7-layout.json
# Compare against the post-upgrade slot reads:
cast call $PROXY "admin()(address)"  --rpc-url $GSX_RPC_URL
cast call $PROXY "paused()(bool)"    --rpc-url $GSX_RPC_URL
cast call $PROXY "version()(uint256)"--rpc-url $GSX_RPC_URL
```

The dry-run test asserted these; the live-state read confirms the
broadcast tx didn't deviate from the simulated path.

---

## Then: Base Sepolia

Same script, swap RPC + addresses:

```bash
export BASE_SEPOLIA_RPC_URL=...
export BASE_SEPOLIA_DEPLOYER_KEY=...
export BASE_SEPOLIA_OPERATOR_KEY=...

# Edit contracts/script/UpgradeV7.s.sol — replace the GSX constants
# with the Base Sepolia ones from DEPLOYED_CONTRACTS.md, OR copy the
# script to UpgradeV7Base.s.sol if you want to keep both invocations
# self-documenting. (The plan's follow-up PR consolidates them under
# a CHAIN env var.)
```

Repeat steps 1-4 with `BASE_SEPOLIA_*` env vars.

---

## Pause rehearsal — MANDATORY before Phase C

After the upgrade lands, the operator team must drill the emergency
pause path end-to-end. This is the test that the observability stack
deployed in Phase B will trigger in anger if a CRITICAL alert fires.

**Goal:** sub-5-minute response, alert → `paused == true`.

### Drill steps (do these on GSX testnet, NOT mainnet)

1. **Time start.** Someone calls `T0` — note the wall-clock minute.
2. **Operator proposes pause** using the script:

   ```bash
   scripts/propose_pause.sh \
       --rpc-url   $GSX_RPC_URL \
       --multisig  0x0106A79e9236009a05742B3fB1e3B7a52F44373D \
       --registry  0xB29d8BFF4973D1D7bcB10E32112EBB8fdd530bF4
   ```

   Copy and run the printed `cast send …` line as the proposer.

3. **Cosigner confirms** via:

   ```bash
   cast send $MULTISIG 'confirmTransaction(uint256)' <txId> \
       --rpc-url $GSX_RPC_URL --private-key $GSX_OPERATOR_KEY
   ```

   then:

   ```bash
   cast send $MULTISIG 'executeTransaction(uint256)' <txId> \
       --rpc-url $GSX_RPC_URL --private-key $GSX_OPERATOR_KEY
   ```

4. **Verify** `paused == true`:

   ```bash
   cast call $REGISTRY 'paused()(bool)' --rpc-url $GSX_RPC_URL
   ```

5. **Time end.** Record `T_paused - T0`. Target < 5 min.
6. **Unpause** to restore testnet operation:

   ```bash
   # Mirror of step 2-3 with `unpause()` selector 0x3f4ba83a:
   cast send $MULTISIG 'proposeTransaction(address,uint256,bytes)' \
       $REGISTRY 0 0x3f4ba83a \
       --rpc-url $GSX_RPC_URL --private-key $GSX_DEPLOYER_KEY
   # confirm + execute as above.
   ```

### Recording the drill

Append a row to the table below with the measured time. The
governance committee uses this row in the Phase D mainnet sign-off.

| Date | Operator | T_paused − T_alert | Notes |
|---|---|---|---|
| _post-drill backfill_ | _name_ | _MM:SS_ | _any deviations_ |

---

## If something goes wrong

| Symptom | Cause | Recovery |
|---|---|---|
| `step1` reverts with `"NotOwner"` | Wrong key for `$GSX_DEPLOYER_KEY` | Confirm wallet — see DEPLOYED_CONTRACTS.md `Deployer` row |
| `step3` reverts with `"NotEnoughConfirmations"` | Operator hasn't confirmed the schedule txId | Run `step2(<scheduleTxId>)` first |
| `step4` reverts with `"TimelockController: operation is not ready"` | Less than 60 seconds since step 3 | Wait the full minute, retry |
| `step4` reverts with `"NotEnoughConfirmations"` | Operator hasn't confirmed the execute txId | Run `step2(<executeTxId>)` and retry |
| Pause drill exceeds 5 min target | Cosigner unavailability or muxing latency | File a post-mortem; the gap must close before Phase D |
| `paused() != true` after pause tx mined | Tx receipt status 0 (revert) or wrong registry address | `cast tx <hash>` → check status; verify address |

For any state corruption suspected (e.g. `admin()` no longer points at
the Timelock), **STOP** and engage the core team. The recovery path is
a follow-up upgrade through the existing multisig — not a fresh
deploy, which would orphan the proxy's storage.

---

## After both chains are upgraded

1. Open a doc-only follow-up PR that backfills `docs/DEPLOYED_CONTRACTS.md`
   with the two new v7 implementation addresses.
2. Update [`README.md`](../../README.md) and [`docs/SUMMARY.md`](../SUMMARY.md)
   if either references v6 explicitly.
3. File the pause-drill time row in the table above.
4. Phase C (etp-node + etp-gateway services) can now point at the
   upgraded testnets — Phase C ships the container build pipeline
   (PR C1) and the etp services Helm chart (PR C2) in the
   production-rollout sequence.
