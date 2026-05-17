# SCN-014 — Mt Gox-class hot-wallet drain

**Status.** STRUCTURALLY-N/A. No on-chain primitive exists; documentation-only.
**Layer.** 3 — Key management (operator-tier).
**Historical incident.** Mt Gox, 2011-2014, ~650k BTC (~\$450M at the time;
~\$28B at later peaks). Sustained hot-wallet drain over years; the
canonical "exchange custody" failure mode.
**LTP-A-* link.** None directly. Operationally adjacent to LTP-A-004.

## What happened (Mt Gox)

Mt Gox was the dominant Bitcoin exchange of its era. Customer
deposits sat in hot-wallet addresses that the operator used for
day-to-day withdrawals. From at least 2011 onward, those wallets
were drained by a combination of (a) compromised key material,
(b) the unencrypted private-key file at one point, and (c) what
later analysis suggests was insider participation. The drain went
unnoticed because:

1. The operator had no automated balance-vs-liabilities check
   that would have surfaced the gap.
2. The hot wallet didn't enforce a balance ceiling — outbound
   transactions could drain the wallet down to zero without an
   alert.
3. The replenish-from-cold-storage flow had no human-in-the-loop
   confirmation against an independent ledger.

By Feb 2014 the gap was ~650k BTC. The exchange filed for
bankruptcy.

## LTP analogue

**LTP has no on-chain hot-wallet contract.** The only ETH-bearing
contract is `OptimisticBridgeChallenge`, which holds bonds
in escrow per challenge window, and which:

- has no `receive()` / `fallback()` function (SCN-006 V1
  pinned this; bare ETH transfers revert)
- has no `withdraw` / `drain` / general-purpose ETH-out
  function — every ETH transfer is gated to a specific
  challenge resolution path with pre-set recipients (opener,
  challenger, arbiter winner)
- has a strict bond-conservation invariant
  (`invariant_bonds_conserved` in
  `contracts/test/invariant/OptimisticBridgeChallenge.invariant.t.sol`)
  that fails on any drift between balance and tracked bonds

The Mt Gox primitive — "operator-controlled hot wallet drained
by compromised key" — has NO on-chain target in LTP.

## What IS in scope

The OFF-CHAIN gateway (operator's signing host + RPC submission
endpoint) is the operational analogue. Defenses live in the
operator runbook, not in contract code:

| ID | Policy | Owner |
|----|--------|-------|
| MG1 | Operator hot-wallet balance ceiling: any RPC-submission host should keep < N ETH at rest (gas budget + safety margin) | `OPERATOR_RUNBOOK.md` §6 (key management) |
| MG2 | Daily balance reconciliation: compare on-chain operator-address balance to expected baseline; alert on drift | future runbook §11 |
| MG3 | Replenish-from-cold flow with dual-control: any top-up from cold storage requires two human approvals | future runbook §13.6 |
| MG4 | Active-set monitoring: alert on signing cadence anomalies (volume spikes, off-hours signing, novel destination addresses) | future runbook §11 |

These are documented here as **policy items**, to be formalized
in the operator runbook during the R-5 drill phase (SCN-031..033
context).

## Test pack

| Test type | Path | What it pins |
|---|---|---|
| **None.** | _structural_ | No on-chain primitive exists. The SCN-006 forge tests already cover OptimisticBridgeChallenge's no-`receive()` and bond-conservation invariants. SCN-011 covers the HSM trust boundary. SCN-014 has no NEW code-level deliverable. |

## Cross-references

- **SCN-006** (Euler donate-to-self) — pins
  `OptimisticBridgeChallenge` has no donation surface
- **SCN-011** (Lazarus HSM) — pins the HSM-tier trust boundary
- **SCN-012** (Multichain single-custody) — pins threshold-
  signing for operator-key custody
- **SCN-013** (Radiant blind-signing) — pins operator-policy
  items for hardware-wallet usage
- **R-5 tabletops** (SCN-031..033) — will formalize MG1-MG4
  into operator runbook sections

## Findings opened

None. Scenario is structurally-N/A.
