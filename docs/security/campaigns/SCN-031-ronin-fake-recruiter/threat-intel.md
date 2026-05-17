# SCN-031 — Threat intelligence sources

Historical incident: **Ronin Bridge initial-access vector, Mar 2022, ~\$625M (cascade).**

## Primary sources

- **Ronin Network post-mortem** — confirmed the social-
  engineering vector via fake-LinkedIn recruiter.
- **Mandiant APT38 profile** — Lazarus Group toolkit including
  TraderTraitor and AppleJeus families used in the social-
  engineering phase.
- **FBI / OFAC sanctions notices** — attribution.

## Secondary technical analyses

- **Chainalysis Crypto Crime Report** (2022, 2023, 2024) —
  Lazarus TTP evolution.
- **Elliptic / TRM Labs** — fund-tracing.
- **CISA AA22-249A advisory** — TraderTraitor specifics.

## Root primitive

A single targeted social-engineering attack against an engineer
with privileged access. The cryptographic protections were
intact; the human-in-the-loop was the weakest link.

Same TTP family applied later to:
- Atomic Wallet (Jun 2023)
- DMM Bitcoin (May 2024)
- WazirX (Jul 2024)
- Radiant Capital (Oct 2024, SCN-013)

The defense is **operator awareness + recognition training**
combined with **system-level isolation of high-trust
operations** (dedicated signing host, hardware-token MFA on
work accounts, no general browsing on signing devices).

## Mapping to LTP

LTP's defense-in-depth across this attack class:

- **Operator awareness** — formalized through quarterly
  tabletop drills (SCN-031, SCN-032, SCN-033).
- **System isolation** — operator runbook §13 specifies
  hardware-wallet usage; SCN-013 drafts the blind-signing
  policy.
- **HSM trust boundary** — SCN-011 covers the cryptographic
  layer that the social-engineering attack would target.
- **Multi-region key distribution** — SCN-012 covers the
  threshold-signing layer that limits single-host compromise.

The tabletop drill verifies the OPERATOR-AWARENESS portion of
this defense stack.

## Date of last verification

2026-05-17 — SCN-031 scaffolded under R-5. Live drill pending
operator-team consent.
