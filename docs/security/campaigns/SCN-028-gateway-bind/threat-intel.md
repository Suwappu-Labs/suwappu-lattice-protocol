# SCN-028 — Threat intelligence sources

This scenario covers a **structural class** rather than a single
named incident.

## Canonical examples of the class

- **Redis-on-0.0.0.0** — countless crypto-related Redis
  instances exposed in 2017-2018 led to wallet-credential
  exfiltration via the Internet.
- **Solana RPC nodes** bound to 0.0.0.0 with no auth — repeated
  reports of validator-key leakage from open RPC endpoints.
- **MongoDB unauthenticated** — generic class affecting many
  Web2 + Web3 services.
- **Bridge admin APIs** — multiple smaller bridges have shipped
  with admin endpoints exposed to the Internet via misconfigured
  cloud security groups.

## Primary references

- **CIS Benchmarks** — recommends fail-safe defaults (bind
  loopback) for all administrative services.
- **OWASP Application Security Verification Standard (ASVS)** —
  V14 covers configuration hardening including default-network-
  binding.
- **NIST SP 800-53 CM-7** — "principle of least functionality"
  applied to network exposure.

## Root primitive

Services bound to `0.0.0.0` by default expose internal APIs to
the public Internet whenever cloud-security-group config drifts.
The defense is fail-safe defaults: loopback by default, explicit
opt-in for public exposure, paired with authentication and
rate-limiting at the public boundary.

## Mapping to LTP

LTP gateway VM defaults to `127.0.0.1` (loopback). Operators
opt in via `ETP_GATEWAY_HOST=0.0.0.0` and are expected to pair
that with the JWT + rate-limit middleware from
`gateway_vm/middleware.py` (LTP-A-011 close-out).

## Date of last verification

2026-05-17 — SCN-028 added under R-4.
