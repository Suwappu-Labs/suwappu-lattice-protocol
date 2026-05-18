# SCN-033 — Threat intelligence sources

Historical incident: **Heco Bridge + HTX drains, November 2023, cumulative ~\$116M.**

## Primary sources

- **Justin Sun statements** (HTX founder, ecosystem
  affiliated with Heco) — partial public acknowledgements
  during the incident window.
- **HTX (Huobi) team statements** — limited; the team's
  comms about the drain were notably opaque.

## Secondary technical analyses

- **Bloomberg / The Block** — investigative reporting on the
  internal operational practices that contributed.
- **CertiK** — incident timeline and on-chain analysis.
- **SlowMist** — multi-chain drain tracking.

## Root primitive

Long-term drift in operational hygiene: shared credentials,
broad production access, informal incident-response, absent
key custody discipline. No single technical exploit; rather
the gradual accumulation of small choices that left no defense
when an attacker eventually probed.

This is the OPPOSITE failure mode from a fast-moving zero-day:
not a clever exploit but the absence of routine practices that
would have stopped an unsophisticated attack.

## Defense class

The defense is **routine self-audit + posture maintenance**.
Specific practices:

1. Quarterly self-audit using a fixed checklist (see SCN-033
   README).
2. Annual external red-team / penetration test of the
   operational boundary.
3. Mandatory annual OPSEC training.
4. Public sign-off on risk-accepted items so the team owns
   the trade-off.

## Mapping to LTP

LTP is at the inflection point where operational culture is
being established. SCN-033 scaffolds the self-audit drill that
should run quarterly from production launch onward. The
"baseline" practices (HSM custody, multi-region keys, IAM
hygiene) already exist in `OPERATOR_RUNBOOK.md` §13.1 — SCN-033
ensures they're verified, not just documented.

## Date of last verification

2026-05-17 — SCN-033 scaffolded under R-5.
