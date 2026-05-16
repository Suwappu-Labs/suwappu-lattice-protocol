# SCN-005 — Penpie callback reentrancy

**Status.** VERIFIED-GREEN expected (defenses hold; CI verifies).
**Layer.** 1 — Smart-contract input validation / control-flow.
**Historical incident.** Penpie (Pendle integration), 3 Sep 2024, ~$27M.
**LTP-A-* link.** No pre-existing LTP-A-* finding (this scenario is
flagged as a "may surface a new finding" candidate in the campaign
plan). Cross-references existing reentrancy hardening in
`OptimisticBridgeChallenge.sol` (LTP-A-001 Option E suite).

## What happened (Penpie)

Penpie integrated with Pendle by allowing market registration. The
attacker registered a market whose "reward token" was a contract
they controlled. When Penpie's `harvest` path called `transfer()` on
the reward token to deliver yield, the attacker's `transfer`
function re-entered `depositMarket` and `claimRewards` on Penpie.
State that Penpie hadn't yet written produced inflated reward
accounting; the attacker drained ~$27M.

Root primitive: **a callback during an external call lets the
attacker re-enter a sibling withdrawal path while invariant state is
in transition.** Shared with Cream (Oct 2021), Cover Protocol
(Dec 2020), Lendf.me (Apr 2020), and the broader class of ERC-777
hook attacks.

## LTP analogue

`OptimisticBridgeChallenge` makes ETH payouts to caller-supplied
recipient addresses on 6 paths:

- `resolveChallenge` → challenger or opener
- `finalizeWindow` → opener
- `resolveChallengeByArbiter` → winner
- `resolveByTimeDecay` → challenger
- `finalizeWithZKProof` → opener (and challenger refund)
- `finalizeWithFraudProof` → challenger

Every recipient could be a contract whose `receive()` /
`fallback()` re-enters the bridge. The defenses pinned in this
scenario:

| ID | Defense | Source line |
|----|---------|-------------|
| E1 | All 6 payout functions carry `nonReentrant` modifier | OptimisticBridgeChallenge.sol:197, 218, 302, 328, 366, 402 |
| E2 | `c.status` is set to its terminal state BEFORE `payable.call` | :201, :223, :309 etc. (CEI ordering) |
| E3 | The reentrancy guard is contract-wide: re-entry into ANY guarded function from ANY other guarded function reverts | :15-23 |
| E4 | Even without the guard, status precondition checks (`STATUS_OPEN`, `STATUS_CHALLENGED`) reject same-digest replay |  precondition lines at top of each function |

## Test pack

| Test type | Path | What it pins |
|---|---|---|
| Forge unit + fuzz | `contracts/test/security/historical/SCN_005_Penpie_Reentrancy.t.sol` | E1+E3 cross-path re-entry blocked; E2 status-set-before-transfer; E4 same-digest replay rejected |
| Forge invariant | `contracts/test/security/historical/SCN_005_Penpie_Reentrancy.invariant.t.sol` | X1 no-double-payout, X2 status-terminal-monotone |
| Echidna properties | `contracts/test/echidna/SCN_005_PenpieEchidna.sol` | Y1 no-successful-reentry; harness arms its receive() to attempt re-entry during finalizeWindow |

## How to run

```bash
cd contracts && forge test --match-path 'test/security/historical/SCN_005_*' -vvv
cd contracts && echidna . --contract SCN_005_PenpieEchidna --config echidna.yaml
```

## Findings opened

None expected on first run; CI will confirm.
