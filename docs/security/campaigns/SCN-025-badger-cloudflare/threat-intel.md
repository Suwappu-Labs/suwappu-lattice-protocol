# SCN-025 — Threat intelligence sources

Historical incident: **Badger DAO Cloudflare Worker injection, 1 December 2021, ~\$120M.**

## Primary sources

- **Badger DAO post-mortem** (Mythril team conducted the
  investigation; report published on Badger forum).
- **Cloudflare post-incident statement** acknowledging the
  account compromise vector.

## Secondary technical analyses

- **Peckshield** — early on-chain analysis of the drains.
- **Trail of Bits** — retrospective on CDN-edge attack class.
- **Chainalysis** — fund-tracing.

## Root primitive

The CDN edge is a privileged execution context. The attacker
compromised the CDN ACCOUNT (not Badger's contracts) and
injected JavaScript that requested users to sign wallet-
draining transactions. The same primitive applies to any
JS-injection point in the request-response path:

- CDN worker
- Service worker registered by the dApp
- Browser extension that the user installs
- npm package consumed by the dApp build (SCN-026)
- Even the user's ISP if HTTPS isn't enforced

## Defense class

For a dApp + CDN architecture:

1. CDN account uses hardware-token MFA.
2. SRI hashes on every loaded asset.
3. CSP header restricts script-src.
4. Independent external monitoring of the served bytes.
5. CDN-worker change detection / alerting.
6. Off-chain client library distribution with content hashes
   that integrators can verify before consumption.

## Mapping to LTP

LTP has no CDN-fronted dApp today. The defenses move into
operator runbook when a dApp is first hosted.

## Date of last verification

2026-05-17 — SCN-025 added under R-4.
