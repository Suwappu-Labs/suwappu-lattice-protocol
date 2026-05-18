# LTP Security Audits

This directory consolidates every external and internal security
review touching the Lattice Transfer Protocol — modeled on the
LayerZero [`LayerZero-v2`][lz] audits layout, but organized around
LTP's three independently-versioned **repo surfaces** (per
[`docs/STABILITY_PROMISES.md`](../../STABILITY_PROMISES.md)).

[lz]: https://github.com/LayerZero-Labs/LayerZero-v2

## Layout

```
audits/
├── python-sdk/        ← audits scoped to src/ltp/   (Python SDK surface)
├── contracts/         ← audits scoped to contracts/ (Solidity registry)
├── corridor-wire/     ← audits of the LTP-corridor-v1 wire format
├── external/          ← formal third-party reviews (whitepaper, math)
├── internal/          ← internal red-team reports + security reviews
└── threat-intel/      ← historical-incident campaign library (SCN-XXX)
```

Each component folder (`python-sdk/`, `contracts/`, `corridor-wire/`)
has its own `README.md` listing the audits that have touched it,
chronologically. New audit reports land in the folder matching their
in-scope surface — multi-surface audits are filed under the surface
they primarily touched and cross-linked from the others.

## What goes where

| Type of artifact | Location | Examples |
|---|---|---|
| Vendor audit report (PDF / md) | `<surface>/<vendor>-YYYY-MM/` | `contracts/sigmaprime-2026-07/` |
| Formal third-party review | `external/` | Whitepaper review rounds 1–4 |
| Internal red-team campaign report | `internal/` | `RED_TEAM_REPORT_2026-05.md` |
| Internal security review note | `internal/` | `SECURITY_REVIEW-2-24-2026.md` |
| Historical-incident regression test pack | `threat-intel/SCN-XXX-<slug>/` | `SCN-001-wormhole-signature-skip/` |

## Why this layout

- **Per-surface organization** matches how LTP versions and ships.
  An audit of `contracts/` doesn't change the Python SDK's API
  surface, and vice versa — keeping them in separate folders makes
  scope explicit.
- **`threat-intel/` is its own subtree** because the SCN library is
  a regression-test corpus, not a one-time deliverable. It grows
  every time a new headline exploit lands somewhere in the
  ecosystem; treating it as an ongoing log under `audits/` rather
  than a sibling of `audits/` matches the way LayerZero files its
  per-feature audit history.
- **`external/` and `internal/` split** clarifies provenance for
  compliance evidence (FedRAMP-High and similar audits need to know
  whether a report came from us or from a third party).

## Cross-references

- Active audit-finding tracker: `LTP-A-NNN` IDs throughout the
  codebase. See [`docs/THREAT_MODEL.md`](../../THREAT_MODEL.md) for
  the current open / closed list.
- Stability boundaries: [`docs/STABILITY_PROMISES.md`](../../STABILITY_PROMISES.md).
- Threat model: [`docs/THREAT_MODEL.md`](../../THREAT_MODEL.md).
- Formal verification status:
  [`docs/FORMAL_VERIFICATION_STATUS.md`](../../FORMAL_VERIFICATION_STATUS.md).
