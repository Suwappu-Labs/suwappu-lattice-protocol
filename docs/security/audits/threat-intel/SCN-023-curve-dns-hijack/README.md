# SCN-023 — Curve Finance DNS hijack at registrar

**Status.** PARTIAL — no LTP dApp domain to hijack today; tabletop/policy deliverable.
**Layer.** 6 — Frontend / supply chain.
**Historical incident.** Curve Finance, 9 Aug 2022, ~\$610k.
**LTP-A-* link.** None directly. Future operator-policy deliverable.

## What happened (Curve)

A social-engineering attack at Curve's domain registrar
(Iwantmyname) let an attacker change the DNS A record for
`curve.fi` to an attacker-controlled server. The attacker
served a near-identical clone of the Curve UI that prompted
users to sign a `setApprovalForAll` transaction that drained
their wallets. ~\$610k stolen before Curve's team noticed and
re-pointed DNS.

Root primitive: **the registrar's account-takeover protection
was the WHOLE defense.** Two-factor authentication, registrar-
side lock policies, and DNSSEC are the layered defenses
against this class.

## LTP analogue

**LTP currently does not host a customer-facing dApp domain.**
The protocol is contract-based; integrators interact with
`LTPAnchorRegistry` directly via the on-chain ABI plus the
gateway VM's gRPC interface. There is no `ltp.gsn.network` web
UI that could be DNS-hijacked today.

If/when a dApp is added, the recommended defense stack:

| ID | Policy |
|----|--------|
| C1 | Registrar account uses TOTP-based MFA on a hardware token, NOT SMS |
| C2 | Domain transfer lock enabled at the registrar level |
| C3 | DNSSEC enabled on the zone |
| C4 | DNS A records pinned to a CDN whose TLS cert is shipped with the dApp client (cert pinning at the protocol level) |
| C5 | Dedicated registrar account NOT shared with other GSX domains; password manager + hardware-key gated |
| C6 | Monitor the zone via an external service (e.g., DNSWatch) for any record change; alert immediately |

These will move into `OPERATOR_RUNBOOK.md` §13.7 ("Frontend
operations") when LTP first hosts a dApp.

## Test pack

| Test type | Path | What it pins |
|---|---|---|
| **None.** | _structural_ | No LTP dApp domain exists. The defense stack is documented for future activation. |

## Cross-references

- **SCN-025** (Badger Cloudflare worker injection) — same
  frontend-tier attack class, different vector
- **SCN-013** (Radiant blind-signing) — operator-side
  hardening that complements frontend integrity
- **OPERATOR_RUNBOOK §13** — production deploy checklist;
  will gain §13.7 when a dApp is added

## Findings opened

None. Documentation deliverable; policy items C1-C6 captured for
future activation.
