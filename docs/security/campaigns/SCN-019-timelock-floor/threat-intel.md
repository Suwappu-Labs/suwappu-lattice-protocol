# SCN-019 — Threat intelligence sources

Historical incident: **Cypher Protocol exploit, 7 August 2023, ~\$1M**
(Timelock-delay angle).

The same incident is covered from the pause-bypass angle in
SCN-016. SCN-019 covers the Timelock-delay primitive specifically.

## Primary sources

Same as SCN-016 — see
[../SCN-016-cypher-pause-bypass/threat-intel.md](../SCN-016-cypher-pause-bypass/threat-intel.md).

Additional Timelock-specific references:

- **OpenZeppelin TimelockController documentation** — covers the
  pattern's intended use and the requirement that the minimum
  delay be set to a meaningful value.
- **Compound Governor docs** — historical context for the
  Timelock delay primitive in DeFi governance.

## Root primitive

A `TimelockController` with near-zero `minDelay` provides no
defense at all — operations execute as soon as they're scheduled.
The contract is a cosmetic wrapper around `call()`. The defense
must live at deploy time, where the operator chooses the delay.

Related governance-delay incidents:
- Several DAO governance-attack scenarios where the attacker
  acquired voting power and scheduled+executed within one
  block, bypassing community reaction.
- "Speed runs" against bridges where the attacker raced the
  governance reaction window.

## Mapping to LTP

LTP's `DeployMainnet.s.sol:48` enforces `timelockDelay >= 24 hours`
on every mainnet deploy. The test pack replicates this predicate
in a pure-Solidity wrapper (SCN-009 pattern) and pins boundary
cases via unit tests + fuzz.

The 24h floor gives honest governance a reaction window large
enough to mobilize multisig signers, alert auditors, and pause
the contract before a malicious upgrade can execute.

## Date of last verification

2026-05-17 — SCN-019 added under R-3.
