# SCN-023 — Threat intelligence sources

Historical incident: **Curve Finance DNS hijack, 9 August 2022, ~\$610k.**

## Primary sources

- **Curve Finance team statements** — published on the project's
  Twitter and Discord during and after the incident.
- **Iwantmyname (the registrar) post-incident statement** —
  acknowledged the social-engineering account takeover.

## Secondary technical analyses

- **CertiK / SlowMist** — incident reports.
- **Reddit r/CryptoCurrency** community discussions captured
  the timeline.
- **DNS Observability Foundation** — wrote a retrospective on
  registrar-level defenses that would have prevented it.

## Root primitive

The protocol's WEBSITE was compromised, not its CONTRACT. Users
were tricked into signing wallet-draining transactions because
the UI prompt looked legitimate. The defense stack is entirely
registrar-tier + dApp-distribution-tier:

- Registrar account MFA (hardware token, not SMS).
- Domain transfer locks.
- DNSSEC.
- Cert pinning at the client level (when feasible).
- External DNS monitoring with immediate alerting.

Related incidents:
- Convex Finance (Jun 2022) — similar registrar / DNS path.
- KyberSwap UI (Sep 2022) — Cloudflare worker injection
  (SCN-025's primitive, related).
- Multiple smaller projects — pattern is recurring.

## Mapping to LTP

LTP has no customer-facing dApp domain today. The policy items
C1-C6 in the scenario README will move into the operator runbook
when a dApp is added. The current contract-only architecture
means there is no SCN-023 attack surface to exploit.

## Date of last verification

2026-05-17 — SCN-023 added under R-4.
