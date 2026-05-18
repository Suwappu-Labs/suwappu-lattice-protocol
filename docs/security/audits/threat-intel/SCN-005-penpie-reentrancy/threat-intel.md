# SCN-005 — Threat intelligence sources

Historical incident: **Penpie exploit (Pendle integration), 3 September 2024, ~$27M.**

## Primary sources

- **Penpie team post-mortem** — published shortly after the
  exploit on the project's Medium / Mirror account.
- **Pendle Finance response** — confirming Pendle core contracts
  were unaffected; the bug was on Penpie's wrapper.
- **Patch PR** in Penpie's monorepo introducing reentrancy guards
  on the harvest path.

## Secondary technical analyses

- **Rekt News** — coverage of the exploit.
- **SlowMist incident report** — call-trace breakdown showing
  the malicious `transfer` re-entering `depositMarket`.
- **PeckShield** — on-chain trace and attacker-flow diagram.

## Root primitive

A `transfer()` callback on a caller-controlled token re-entered a
sibling state-changing function before the calling function had
finished writing its effects. The class includes:

- Penpie (Sep 2024) — ERC-20-with-callback (custom token)
- Cream Finance (Oct 2021) — flashloan + oracle composability
- Cover Protocol (Dec 2020) — infinite-mint via state-overwrite
- Lendf.me / dForce (Apr 2020) — ERC-777 transfer hook
- The DAO (Jun 2016) — original reentrancy

General defense:
1. **CEI ordering** — write effects before external calls.
2. **Reentrancy guard** — `nonReentrant` modifier on every payout
   path, contract-wide.
3. **State precondition checks** — even without a guard, terminal
   status would reject replay.

## Mapping to LTP

LTP's `OptimisticBridgeChallenge` applies all three defenses on
all six payout paths. SCN-005 verifies them empirically.

## Date of last verification

2026-05-16 — SCN-005 added under R-2.
