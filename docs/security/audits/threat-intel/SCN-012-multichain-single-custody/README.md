# SCN-012 — Multichain single-custody collapse

**Status.** VERIFIED-GREEN expected.
**Layer.** 3 — Key management.
**Historical incident.** Multichain (formerly Anyswap), May–Jul 2023, ~\$125M.
**LTP-A-* link.** [LTP-A-004](../../internal/SECURITY_AUDIT_2026-05-15.md)
(single-custody operator signing key).

## What happened (Multichain)

Multichain operated a multi-billion-dollar cross-chain bridge.
Its validator-set keys were all controlled by the founder/CEO
Zhaojun. After his detention by Chinese authorities in May 2023:

1. The project lost operational control.
2. Without Zhaojun's keys, the team could not pause the bridge,
   rotate validators, or process legitimate withdrawals.
3. Funds began to drain — ~\$125M over the subsequent weeks —
   from the validator-controlled signing addresses. The exact
   attribution is disputed (insider exfil vs external compromise
   under operational chaos), but the structural failure is
   unambiguous: **one individual had sufficient signing authority
   to drain the bridge unilaterally, and there was no mechanism
   for the rest of the organization or the community to act
   without him.**

Root primitive: **single-custody operator signing**. The bridge
was a 1-of-1 multisig dressed up as something more.

## LTP analogue

LTP has two orthogonal defenses against this class:

| ID | Layer | Defense | Source / Scenario |
|----|-------|---------|-------------------|
| Contract-tier | `LTPMultiSig` requires N-of-M owners | LTPMultiSig.sol + SCN-004 M1 + SCN-009 H2 deploy floor (`threshold >= ceil(N/2)+1`) |
| **C1-C5** | Threshold-signing tier — committee members produce partial BLS sigs that ONLY combine into a valid full signature when ≥ threshold cooperate | `src/ltp/execution/committee/dkg/threshold_signing.py` |

The defenses pinned in THIS scenario (C1-C5) cover the threshold-
signing tier:

| ID | Defense |
|----|---------|
| C1 | `combine_partial_signatures` raises when given fewer than `threshold` partials |
| C2 | A single partial does NOT verify as a full signature against the group public key |
| C3 | Combining EXACTLY threshold (or more) partials produces a signature that verifies |
| C5 | Combining duplicate partials (same participant) does NOT verify — Lagrange interpolation requires distinct indices; combine() accepts by length but threshold_verify rejects mathematically |

(C4, epoch-mismatch, is covered by the broader threshold-signing
test suite and is not duplicated here.)

## Test pack

| Test type | Path | What it pins |
|---|---|---|
| pytest | `tests/security/historical/test_scn_012_multichain.py` | C1, C2, C3 (×2 — exact and over-threshold), C5, plus an end-to-end "single-custody holder cannot unilaterally sign" assertion using a trusted-dealer Shamir share generator for the test fixture |

The trusted-dealer fixture mirrors what a real DKG produces but
without the multi-party protocol overhead. Production keygen uses
the DKG protocol in
`src/ltp/execution/committee/dkg/`; the property tested here
(threshold required for valid signature) is identical regardless
of how shares are generated.

## Tabletop component

The campaign plan flagged SCN-012 as "tabletop + pytest". The
tabletop component — how the LTP operations team would respond
to a Multichain-style sudden operator unavailability — is
deferred to R-5 with operator sign-off. This file pins ONLY the
pytest layer.

## How to run

```bash
pip install -e '.[dev]'
pytest tests/security/historical/test_scn_012_multichain.py -v
```

## Findings opened

None expected. Threshold-signing is the structural defense; the
test pack confirms it works as specified.

## Cross-references

- **SCN-008** (Ronin) — proxy-signing surface
- **SCN-009** (Harmony) — threshold-vs-VaR deploy policy
- **SCN-011** (Lazarus HSM) — HSM trust boundary
- **OPERATOR_RUNBOOK.md** — bus-factor procedures (key custody,
  emergency rotation, signer succession)
