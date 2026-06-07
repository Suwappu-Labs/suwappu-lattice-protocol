# P3 — Adversarial review by attack class

Multi-agent fan-out over the canonical bridge-hack taxonomy (one agent per class),
free-text VERDICT-line adjudication. Goal: surface NEW findings beyond the known C1-C9.
**Result: 7 NEW findings (2 critical, 2 high, 1 medium, 2 low); 2 classes clean.**

| Attack class | Verdict | Finding |
|---|---|---|
| Wormhole (sig/source) | NEW | **P3-1 CRITICAL** — operatorVkHash never authorized |
| Nomad (init/zero-root) | NEW | P3-2 LOW — sp1ProgramVKey zero-default ungated |
| Ronin/Harmony (threshold/opsec) | NEW | **P3-3 CRITICAL** + **P3-4 HIGH** |
| Poly (delegatecall/selector) | CLEAN | (C8 binding sound; 2 deployment-dependent op notes) |
| Orbit (replay/domain) | NEW | **P3-5 HIGH** + P3-6 LOW |
| Accounting/supply | NEW | P3-7 MEDIUM — rebasing-token drift |
| Reentrancy/call-flow | CLEAN | all payout paths nonReentrant + CEI |

## Forge-confirmed (empirical proof, `test/security/SuwappuP3Findings.security.t.sol`, both PASS)

### P3-3 [CRITICAL] — WrappedToken `DEFAULT_ADMIN_ROLE` is a parallel, unconstrained minter
`SuwappuWrappedToken` is plain OZ `AccessControl`; `DEFAULT_ADMIN_ROLE` is role-admin of
`MINTER_ROLE`. The admin can `grantRole(MINTER_ROLE, anyone)` and mint **uncapped, unbacked**
supply directly — no commitId, no mintRecords bitmap, no vault lock, no relayer bond.
**Confirmed:** `test_P3_3_...` mints 1,000,000 unbacked tokens with zero collateral.
Distinct from C1 (C1 = relayer under-validated *inside* the adapter; P3-3 = a second principal
minting *outside* the adapter). *Severity in production depends on who holds DEFAULT_ADMIN_ROLE —
no deploy script locks it down today.* **Fix:** token admin must be the Timelock; set
`MINTER_ROLE`'s admin to a frozen address so the minter set is fixed to the adapter.

### P3-5 [HIGH] — one source Lock replays into N mints across MintAdapter instances
`MintAdapter.mint` takes `sourceChainId` as an **unused** param, takes no `destChainId`, never
reads `commit.destChainId`, and dedups via per-instance `mintRecords`. With the documented
"one adapter per asset per dest chain" model, the same backed commitId mints once **per
instance**. **Confirmed:** `test_P3_5_...` — one 10-ETH lock mints 20 wrapped ETH across two
adapters (only 10 ETH locked). Distinct from C1 (even a correct commitId replays). **Fix:**
bind `destChainId == block.chainid` into the recomputed commitId (subsumes C1's recompute).

## Code-confirmed (by inspection; repro needs the SP1 production path)

### P3-1 [CRITICAL] — `operatorVkHash` never authenticated against the authorized-operator set
`ZKBridgeVerifier.verifyAndFinalize` checks `operatorVkHash != 0` but **never** checks it against
`ETPGovernance.authorizedOperators` — and holds no governance reference at all. An attacker
self-signs a forged STH with their own ML-DSA key, produces a genuinely-valid SP1 proof for that
key, calls `openWindow` (permissionless) + `verifyAndFinalize` (permissionless, no access
control — overlaps C3), and **instant-finalizes any anchorDigest**, bypassing the challenge
window. Distinct from C3 (C3 = *which digest* binds to the proof; P3-1 = *which signer* is
trusted). **Fix:** require `governance.authorizedOperators(inputs.operatorVkHash)` after proof
success, honoring revocation/expiry. **Needs a forge repro on the MODE_SP1 path before final
sign-off** (the simulated path is C4-gated).

## Lower-severity NEW
- **P3-4 [HIGH]** — no rate-limit / per-tx ceiling / threshold on `Vault.unlock` & `MintAdapter.mint`.
  Daily/TVL caps live only in `_lock` (deposit side); `unlock` has none and `recipient` is
  attacker-chosen (not pinned to `c.destRecipient`/`c.from`). One compromised unlocker/relayer key
  drains 100% of TVL/supply in one tx (Ronin blast radius). Adjacent: `addUnlocker`/`addRelayer`
  fall to the 3-day `PARAM_DELAY`, not `UPGRADE_DELAY`. **Fix:** daily release cap + guardian-pause
  on unlock/mint; M-of-N unlocker quorum; raise role-grant selectors to UPGRADE_DELAY.
- **P3-7 [MEDIUM]** — rebasing/elastic tokens (stETH/AMPL-style) break vault solvency: `totalLocked`
  is a frozen accumulator never reconciled to live balance, and there's no token allowlist
  (`tvlCap==0` = uncapped). Negative rebase → tail unlock/refund reverts (under-collateralization);
  positive rebase → user yield swept as "fees". Distinct from C5 (C5 = inbound FOT at lock time).
  **Fix:** token allowlist gating `lockERC20`; make `tvlCap==0` mean disabled.
- **P3-2 [LOW]** — `sp1ProgramVKey == 0` not gated by `setSP1Verifier`/`lockProduction` (fail-closed;
  hardening). **P3-6 [LOW]** — ZK `proofId` + SP1 publicValues omit `block.chainid`/`address(this)`
  → cross-instance proof replay (fold into the C3 fix).

## Clean (defenses confirmed — credit for the gate)
- **Poly/delegatecall:** no delegatecall/Multicall/ERC-2771; OZ timelock uses CALL; C8 (target,
  selector) binding sound. (Two deployment-dependent op notes: a whitelisted `emergencyWithdraw`
  selector would let the guardian drain at zero delay; emergencyWithdraw's 3-day vs documented
  7-day tier mismatch.)
- **Reentrancy:** all payout paths `nonReentrant` + CEI; WrappedToken has no ERC777 hooks;
  challenge bond handling defended by a non-overlapping terminal status machine.

## Human-review items
- P3-3 severity hinges on the production role-assignment plan (who holds DEFAULT_ADMIN_ROLE).
- P3-1 needs a MODE_SP1 forge repro to fully close.
- The two Poly-lens operational notes are deployment-config decisions.
