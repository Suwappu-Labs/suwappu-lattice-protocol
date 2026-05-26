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
#    slot reordering BEFORE the upgrade tx broadcasts. Path is relative
#    to the Foundry project root (= `contracts/` after the `cd` above).
export GSX_RPC_URL=<the gsx testnet rpc you have>
export BASE_SEPOLIA_RPC_URL=<base sepolia rpc>
forge test --match-path test/deployment/UpgradeV7.dryrun.t.sol -vv

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

step4 logs `Registry version:` and `Proxy:` as a sanity check; it does
**not** re-print the implementation address. The new impl address was
logged by **step1** earlier in the ceremony as
`New v7 implementation: 0x…` — backfill that value into
[`docs/DEPLOYED_CONTRACTS.md`](../DEPLOYED_CONTRACTS.md) under the
"v7, pending deploy" row in the same PR you open immediately after
the ceremony.

### Post-flight — storage-layout verification (live state)

```bash
# The GSX testnet LTPAnchorRegistry proxy address (source-of-truth:
# DEPLOYED_CONTRACTS.md). Same value as the $REGISTRY variable
# exported in the pause-rehearsal section below.
export PROXY=0xB29d8BFF4973D1D7bcB10E32112EBB8fdd530bF4

forge inspect LTPAnchorRegistry storage-layout > /tmp/v7-layout.json
# Compare against the post-upgrade slot reads:
cast call $PROXY "admin()(address)"   --rpc-url $GSX_RPC_URL
cast call $PROXY "paused()(bool)"     --rpc-url $GSX_RPC_URL
cast call $PROXY "version()(uint256)" --rpc-url $GSX_RPC_URL
```

The dry-run test asserted these; the live-state read confirms the
broadcast tx didn't deviate from the simulated path.

---

## Then: Base Sepolia

The same script targets Base Sepolia (chain 84532). Open a fresh
shell **or** `unset` the GSX vars first — chain-targeting mistakes
here overwrite the wrong proxy:

```bash
unset GSX_RPC_URL GSX_DEPLOYER_KEY GSX_OPERATOR_KEY PROXY
```

Export the Base Sepolia values (source-of-truth:
[`docs/DEPLOYED_CONTRACTS.md`](../DEPLOYED_CONTRACTS.md)):

```bash
# Base Sepolia chain 84532:
#   Proxy:    0x79eF1B7914f98C5C1404617449AB1f377c475996
#   Multisig: 0x4c324c3c3475f58b67d3c879880D6c94eDC82E49
#   Timelock: 0xc915740e35E38569E47f611eA5772Ff5278bc5Ae
export BASE_SEPOLIA_RPC_URL=<base sepolia rpc>
export BASE_SEPOLIA_DEPLOYER_KEY=<base sepolia deployer key>
export BASE_SEPOLIA_OPERATOR_KEY=<base sepolia operator key>

# In `contracts/script/UpgradeV7.s.sol`, replace the GSX address
# constants (PROXY/MULTISIG/TIMELOCK) inline with the Base Sepolia
# values from the comment block above. Re-running step1-4 below
# then invokes the same `script/UpgradeV7.s.sol` file with the
# correct chain targets. (The plan's follow-up PR consolidates
# this under a CHAIN env var so the in-file edit goes away.)
```

Now repeat steps 1-4 above with these literal substitutions in
**every** command:

| In step 1-4 | Replace with |
|---|---|
| `$GSX_RPC_URL` | `$BASE_SEPOLIA_RPC_URL` |
| `$GSX_DEPLOYER_KEY` | `$BASE_SEPOLIA_DEPLOYER_KEY` |
| `$GSX_OPERATOR_KEY` | `$BASE_SEPOLIA_OPERATOR_KEY` |

For the post-flight verification block, swap the proxy too:

```bash
export PROXY=0x79eF1B7914f98C5C1404617449AB1f377c475996
# Re-run the three `cast call $PROXY ...` reads from the GSX
# post-flight block, substituting $BASE_SEPOLIA_RPC_URL for $GSX_RPC_URL.
```

---

## Pause rehearsal — MANDATORY before Phase C

After the upgrade lands, the operator team must drill the emergency
pause path end-to-end. This is the test that the observability stack
deployed in Phase B will trigger in anger if a CRITICAL alert fires.

**Goal:** sub-5-minute response, alert → `paused == true`. With the
60-second testnet timelock delay the drill is ~3.5 minutes wall-clock
under best conditions.

**Why the drill spans 7 multisig txs**: `LTPAnchorRegistry.pause()`
is `onlyAdmin`, and the registry admin in the deployed governance
model is the **TimelockController**, not the multisig. The flow is
`multisig → timelock.schedule → wait → multisig → timelock.execute
→ registry.pause()`. A direct `multisig → registry.pause()` reverts
`NotAdmin`. This mirrors the upgrade ceremony's multisig→timelock
pattern in `UpgradeV7.s.sol`.

### Before starting the drill

The ceremony's step 1 left you in `contracts/`; the helper script
lives at the repo root. Reset the working directory back to GSX env
vars (if you ran the Base Sepolia ceremony in the same shell) and
export the addresses + keys every step below references:

```bash
cd "$(git rev-parse --show-toplevel)"

# If you continued from the Base Sepolia run, clear its env vars so
# they cannot accidentally re-target. The drill is GSX-only.
unset BASE_SEPOLIA_RPC_URL BASE_SEPOLIA_DEPLOYER_KEY \
      BASE_SEPOLIA_OPERATOR_KEY PROXY

# GSX testnet (chain 103115120) — source-of-truth: DEPLOYED_CONTRACTS.md
export GSX_RPC_URL=<gsx testnet rpc>
export MULTISIG=0x0106A79e9236009a05742B3fB1e3B7a52F44373D
export REGISTRY=0xB29d8BFF4973D1D7bcB10E32112EBB8fdd530bF4
export TIMELOCK=0x7C2665F7e68FE635ee8F10aa0130AEBC603a9Db8

# Multisig keys (load from your secret store; do NOT commit literals):
export LTP_PROPOSER_PRIVATE_KEY=<2-of-2 signer A — submits txs>
export LTP_COSIGNER_PRIVATE_KEY=<2-of-2 signer B — confirms>
export LTP_OWNER_PRIVATE_KEY=<any multisig owner — fires executeTransaction>
```

### Drill steps (do these on GSX testnet, NOT mainnet)

1. **Time start.** Someone calls `T0` — note the wall-clock minute.

2. **Generate the multisig command sequence** with the helper. The
   script queries `timelock.getMinDelay()` and prints `cast send`
   lines for the full STEP A–G flow:

   ```bash
   scripts/propose_pause.sh \
       --rpc-url   $GSX_RPC_URL \
       --multisig  $MULTISIG \
       --registry  $REGISTRY \
       --timelock  $TIMELOCK
   ```

3. **Run STEP A** (proposer submits the timelock-schedule tx). Capture
   the printed `txId` (call it `<scheduleTxId>`) from the receipt —
   the cosigner-confirm and executor steps need it.

4. **Run STEP B** (cosigner confirms `<scheduleTxId>`).

5. **Run STEP C** (any owner executes `<scheduleTxId>`) — this fires
   `timelock.schedule(...)` and starts the timelock delay countdown.

6. **Run STEP D** — the helper's banner shows the exact wait derived
   from `timelock.getMinDelay()` (typically 60s on testnet):
   `sleep "$TIMELOCK_DELAY"`. Do NOT use a literal 60s — the delay
   is governance-updatable and would mismatch on chains where it has
   been raised.

7. **Run STEP E** (proposer submits the timelock-execute tx). Capture
   `<executeTxId>`.

8. **Run STEP F** (cosigner confirms `<executeTxId>`).

9. **Run STEP G** (any owner executes `<executeTxId>`) — this fires
   `timelock.execute(...) → registry.pause()`.

10. **Verify** `paused == true`:

    ```bash
    cast call $REGISTRY 'paused()(bool)' --rpc-url $GSX_RPC_URL
    ```

11. **Time end.** Record `T_paused - T0`. Target < 5 min.

12. **Unpause** to restore testnet operation. Same timelock-gated
    pattern, swapping the `pause()` selector `0x8456cb59` for
    `unpause()` `0x3f4ba83a`. **The salt must be unique per
    rehearsal/incident** — re-using a salt that hit `Done` on a
    prior cycle makes `schedule(...)` revert because the Timelock
    op id is no longer `Unset`. Reuse the same `$SALT` across the
    schedule + execute calldata of this cycle so the op ids match:

    ```bash
    UNPAUSE_CALLDATA=0x3f4ba83a
    PREDECESSOR=0x0000000000000000000000000000000000000000000000000000000000000000

    # Read the timelock's CURRENT min delay rather than hard-coding 60s.
    # Timelock delay is governance-updatable; a stale literal here would
    # cause schedule(...) to revert and delay restoring service.
    TIMELOCK_DELAY=$(cast call $TIMELOCK 'getMinDelay()(uint256)' \
        --rpc-url $GSX_RPC_URL)
    TIMELOCK_DELAY="${TIMELOCK_DELAY%% *}"
    echo "timelock.getMinDelay() == $TIMELOCK_DELAY seconds"

    # Per-cycle unique salt (re-derive for each unpause attempt).
    SALT=$(cast keccak "$(date -u +%s%N)-${RANDOM}-unpause-$REGISTRY")
    echo "salt for this unpause cycle: $SALT"

    # STEP A — proposer submits timelock-schedule for unpause()
    SCHEDULE_UNPAUSE=$(cast calldata \
        'schedule(address,uint256,bytes,bytes32,bytes32,uint256)' \
        $REGISTRY 0 $UNPAUSE_CALLDATA $PREDECESSOR $SALT $TIMELOCK_DELAY)
    cast send $MULTISIG \
        'submitTransaction(address,uint256,bytes)' \
        $TIMELOCK 0 $SCHEDULE_UNPAUSE \
        --rpc-url $GSX_RPC_URL --private-key $LTP_PROPOSER_PRIVATE_KEY
    # → capture <scheduleTxId>; STEP B/C as above

    sleep "$TIMELOCK_DELAY"

    # STEP E — proposer submits timelock-execute for unpause()
    # Salt MUST match the schedule call so the Timelock resolves
    # the same op id; don't re-derive here.
    EXECUTE_UNPAUSE=$(cast calldata \
        'execute(address,uint256,bytes,bytes32,bytes32)' \
        $REGISTRY 0 $UNPAUSE_CALLDATA $PREDECESSOR $SALT)
    cast send $MULTISIG \
        'submitTransaction(address,uint256,bytes)' \
        $TIMELOCK 0 $EXECUTE_UNPAUSE \
        --rpc-url $GSX_RPC_URL --private-key $LTP_PROPOSER_PRIVATE_KEY
    # → capture <executeTxId>; STEP F/G as above

    # Verify
    cast call $REGISTRY 'paused()(bool)' --rpc-url $GSX_RPC_URL
    # expect: false
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
