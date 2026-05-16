# SCN-006 — Euler donate-to-self accounting

**Status.** VERIFIED-GREEN (defenses hold + bond-conservation invariant pre-exists).
**Layer.** 1 — Smart-contract input validation / accounting.
**Historical incident.** Euler Finance, 13 Mar 2023, ~$197M (recovered).
**LTP-A-* link.** No specific LTP-A-* — covered structurally by
`invariant_bonds_conserved` in
`contracts/test/invariant/OptimisticBridgeChallenge.invariant.t.sol`
(pre-existing audit work).

## What happened (Euler)

Euler's `donateToReserves` function let users contribute their assets
to the protocol's reserves. The bug: the user could donate assets
they had **borrowed**, without their personal debt being reduced.
After a large donation, the user's account had:

  collateral < debt   →   violating the protocol's solvency invariant

This triggered Euler's self-liquidation path. The attacker had
pre-positioned a "violator" account and a "liquidator" account; the
liquidator received the violator's collateral as protocol-paid
incentive. Net effect: the attacker drained ~$197M before the team
patched.

Root primitive: **a write path mutated protocol-wide accounting
totals without keeping the per-account invariant.** The attacker
manufactured an invariant violation on their own account.

## LTP analogue

`OptimisticBridgeChallenge` keeps a strict accounting invariant:

  address(ch).balance == sum of all unsettled bonds

This is the same shape as Euler's solvency invariant, just for
bond escrow instead of lending balances. The defenses pinned in
this scenario:

| ID | Defense | Source |
|----|---------|--------|
| V1 | NO `receive()` or `fallback()` — bare ETH transfers revert | `OptimisticBridgeChallenge.sol` (no such function exists) |
| V2 | Only `openWindow` (operatorBond) and `submitChallenge` (challengerBond) are `payable`; both update bond-tracking state in the same call | :151, :175 |
| V3 | Selfdestruct force-deposit primitive (post-EIP-6780, narrow) — still detectable via the strict `invariant_bonds_conserved` equality |  pre-existing invariant |

## Test pack

| Test type | Path | What it pins |
|---|---|---|
| Forge unit | `contracts/test/security/historical/SCN_006_Euler_DonateToSelf.t.sol` | V1 (bare ETH + missing-selector both revert), V2 (openWindow + submitChallenge accounting), V3 (selfdestruct force-deposit creates detectable drift) |
| **Pre-existing forge invariant** | `contracts/test/invariant/OptimisticBridgeChallenge.invariant.t.sol::invariant_bonds_conserved` | Strict equality: `address(ch).balance == sum of bonds`. Any donation drift fails. |

This scenario reuses the existing invariant — it does not duplicate
it. The per-scenario test pack documents the LTP-side primitive
(no donation surface) and confirms the invariant covers the
residual force-deposit case.

## How to run

```bash
cd contracts && forge test --match-path 'test/security/historical/SCN_006_*' -vvv
cd contracts && forge test --match-test invariant_bonds_conserved -vvv
```

## Findings opened

None. Donation surface is absent by design; invariant pre-exists.
