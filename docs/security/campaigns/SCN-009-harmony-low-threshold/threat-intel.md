# SCN-009 — Threat intelligence sources

Historical incident: **Harmony Horizon bridge exploit, 23 June 2022, ~$100M.**

## Primary sources

- **Harmony post-mortem** —
  https://medium.com/harmony-one/harmonys-horizon-bridge-hack-1e8d283b6d66
  Initial team statement; subsequent updates covered the validator
  rotation and the bounty offer.
- **FBI / Treasury attribution** — Lazarus Group / DPRK named
  in subsequent OFAC sanctions.

## Secondary technical analyses

- **Rekt News** — https://rekt.news/harmony-rekt/
- **Chainalysis crypto crime reports (2022, 2023)** — fund-
  movement tracing through Tornado Cash and Bitcoin mixers.
- **Elliptic** — independent attribution analysis.
- **SlowMist** — incident report.

## Root primitive

Threshold was chosen without regard to value-at-risk. A 2-of-5
multisig means any 2 keys provide quorum. With Lazarus-tier
operational capability (phishing, hot-wallet harvesting,
developer-laptop compromise), 2 keys is well within reach.

The structural lesson: **the threshold is the maximum number of
trustees the protocol can afford to lose before the bridge is
drained.** A bridge securing $100M cannot tolerate the loss of
just 2 trustees. A reasonable Byzantine threshold for that
value-at-risk is roughly `ceil(N/2) + 1`, with N chosen high
enough that compromising the threshold-many keys is genuinely
hard.

Related incidents that share the "threshold-too-low" primitive:
- Ronin (Mar 2022, SCN-008) — different shape (proxy-signing)
  but the M-effective collapsed to operator-only
- Multichain (Jul 2023) — collapsed to 1-of-1 single-custody
- WazirX (Jul 2024) — 4-of-6 with insufficient guardian
  independence

## Mapping to LTP

The contract layer alone cannot defend against a low-threshold
configuration — that's by design. The defense lives in the
deploy policy: `DeployMainnet.s.sol:43-47` enforces
`threshold >= ceil(N/2) + 1`, which would reject every threshold
LTP-A-002 flagged as dangerous. The testnet deploy uses 2-of-2
intentionally (development convenience) and the audit calls this
out as a testnet-only choice.

The operational defense (HSM custody, regular rotation, active-
set monitoring) is documented in OPERATOR_RUNBOOK.md and tracked
under LTP-A-004. SCN-011 covers the sustained-compromise scenario
in more depth.

## Date of last verification

2026-05-16 — SCN-009 added under R-3.
