# SCN-025 — Badger DAO Cloudflare worker injection

**Status.** PARTIAL — no LTP dApp/CDN today; tabletop/policy deliverable.
**Layer.** 6 — Frontend / supply chain.
**Historical incident.** Badger DAO, 1 Dec 2021, ~\$120M.
**LTP-A-* link.** None directly. Future operator-policy deliverable.

## What happened (Badger)

The attacker compromised Badger's Cloudflare account via a
social-engineering attack against the operator. They deployed
a Cloudflare Worker that intercepted requests to the Badger
dApp UI and injected JavaScript that requested users to sign
a `setApprovalForAll` transaction targeting attacker-controlled
addresses. The injected JS only fired for high-net-worth wallet
addresses (the attacker had previously scraped balances). ~\$120M
drained over weeks before discovery.

Root primitive: **the CDN edge was a privileged execution
context** with full ability to modify served content. Whoever
controlled the CDN account effectively controlled what the dApp
displayed and what transactions it requested.

The defense class is similar to SCN-023 (Curve DNS) but
displaced one layer down — CDN account-takeover protection,
Subresource Integrity (SRI) on every loaded asset, and CDN-
worker change monitoring.

## LTP analogue

**LTP currently does not host a customer-facing dApp or CDN.**
The same future-activation pattern as SCN-023 applies.

Recommended defenses when a dApp is added:

| ID | Policy |
|----|--------|
| B1 | CDN account uses hardware-token MFA, separate from other SUWAPPU accounts |
| B2 | All loaded JS / CSS assets carry SRI hashes that the HTML pins |
| B3 | Worker changes require dual-approval; alert on any deploy event |
| B4 | Independent external monitoring (e.g., a watcher that fetches the dApp from an external IP and diffs the bytes against a known baseline) |
| B5 | CSP (Content-Security-Policy) header restricts script-src to a known set; no `unsafe-inline` for scripts |
| B6 | The dApp client library (npm package consumed by integrators) ships with cert-pin or content-hash that an integrator can verify offline |

These will move into `OPERATOR_RUNBOOK.md` §13.7 alongside
SCN-023's C1-C6 when a dApp is first hosted.

## Test pack

| Test type | Path | What it pins |
|---|---|---|
| **None.** | _structural_ | No LTP CDN exists. Defenses documented for future activation. |

## Cross-references

- **SCN-023** (Curve DNS hijack) — sibling frontend-tier
  attack at the DNS layer
- **SCN-026** (Ledger Connect Kit npm) — supply-chain-tier
  attack at the package layer
- **OPERATOR_RUNBOOK §13.7** (future) — frontend operations

## Findings opened

None. Documentation deliverable; policy items B1-B6 captured for
future activation.
