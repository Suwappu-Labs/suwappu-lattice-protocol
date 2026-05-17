# Campaign Scenario Index — May 2026

**Campaign complete.** All 33 scenarios merged across R-1
through R-6; one real finding surfaced and fixed
(**LTP-A-031**). R-5 live drills scaffolded; execution pending
operator-team consent.

Status legend:
- **VERIFIED-GREEN** — defense pre-existed; regression test
  pinned on first run.
- **REMEDIATED-GREEN** — test surfaced a real bug; fix landed
  in the same branch; regression test now passes.
- **STRUCTURALLY-N/A** — attack surface doesn't exist in LTP.
- **PARTIAL** / **DOCUMENTATION-COMPLETE** — defense is
  operator-policy not contract code; surface doesn't exist on-
  chain today.
- **SCAFFOLDED** — live drill prerequisites documented; drill
  pending operator consent.

Each scenario links to its evidence directory `SCN-XXX-<slug>/`.

## Layer 1 — Smart-contract input validation

| # | Incident pattern | LTP target | Status |
|---|---|---|---|
| [SCN-001](SCN-001-wormhole-signature-skip/) | Wormhole signature-skip (Feb 2022, $326M) | `LTPAnchorRegistry.anchor` | ✓ VERIFIED-GREEN |
| [SCN-002](SCN-002-nomad-init-bug/) | Nomad init-bug (Aug 2022, $190M) | `_anchor` zero-input guards + initializer one-shot | ✓ VERIFIED-GREEN |
| [SCN-003](SCN-003-poly-keeper-escalation/) | Poly Network keeper escalation (Aug 2021, $611M) | onlyAdmin gates across privileged functions | ✓ VERIFIED-GREEN |
| [SCN-004](SCN-004-orbit-multisig-subversion/) | Orbit multisig threshold subversion (Jan 2024, $82M) | `LTPMultiSig` | ✓ VERIFIED-GREEN |
| [SCN-005](SCN-005-penpie-reentrancy/) | Penpie callback reentrancy (Sep 2024, $27M) | `OptimisticBridgeChallenge` | ✓ VERIFIED-GREEN |
| [SCN-006](SCN-006-euler-donate-to-self/) | Euler donate-to-self (Mar 2023, $197M recovered) | bond accounting + no receive/fallback | ✓ VERIFIED-GREEN |
| [SCN-007](SCN-007-thorchain-decode/) | THORChain decode bug (Jul 2021, $5M) | BridgeEmitter + ZKBridgeVerifier | ✓ VERIFIED-GREEN |

## Layer 2 — Validator / consensus / signing

| # | Incident pattern | LTP target | Status |
|---|---|---|---|
| [SCN-008](SCN-008-ronin-active-set/) | Ronin active-set collapse (Mar 2022, $625M) | `LTPMultiSig` no-proxy-signing | ✓ VERIFIED-GREEN |
| [SCN-009](SCN-009-harmony-low-threshold/) | Harmony low threshold (Jun 2022, $100M) | `DeployMainnet` Byzantine-floor policy | ✓ VERIFIED-GREEN |
| [SCN-010](SCN-010-thorchain-bifrost/) | THORChain Bifrost mis-signed aggregate (Jun 2021, $140k) | `BLS.aggregate_verify` | ✓ VERIFIED-GREEN |
| [SCN-011](SCN-011-lazarus-hsm/) | Lazarus sustained key compromise (multiple) | `HSMBackend` / `SoftwareHSM` | ✓ VERIFIED-GREEN |

## Layer 3 — Key management & rotation

| # | Incident pattern | LTP target | Status |
|---|---|---|---|
| [SCN-012](SCN-012-multichain-single-custody/) | Multichain single-custody (Jul 2023, $125M) | `threshold_signing.py` | ✓ VERIFIED-GREEN |
| [SCN-013](SCN-013-radiant-blind-signing/) | Radiant blind-signing (Oct 2024, $58M) | operator-policy O1-O5 | DOCUMENTATION-COMPLETE |
| [SCN-014](SCN-014-mt-gox-hot-wallet/) | Mt Gox hot-wallet drain (2011-2014) | (no on-chain hot-wallet) | STRUCTURALLY-N/A |
| [SCN-015](SCN-015-signer-rotation-grace/) | Signer-rotation in-flight race | `_anchor` `signerExpiresAt` check | ⚠ **REMEDIATED-GREEN (LTP-A-031)** |

## Layer 4 — Governance

| # | Incident pattern | LTP target | Status |
|---|---|---|---|
| [SCN-016](SCN-016-cypher-pause-bypass/) | Cypher pause-bypass (Aug 2023, $1M) | pause + upgrade co-control | ✓ VERIFIED-GREEN |
| [SCN-017](SCN-017-layerzero-dvn/) | LayerZero DVN downgrade (2024 debate) | `setArbiter` separation | ✓ VERIFIED-GREEN |
| [SCN-018](SCN-018-parity-init/) | Parity init-on-impl (Nov 2017, $280M frozen) | `_disableInitializers` | ✓ VERIFIED-GREEN (cross-ref) |
| [SCN-019](SCN-019-timelock-floor/) | Timelock-delay floor | `DeployMainnet` 24h floor | ✓ VERIFIED-GREEN |

## Layer 5 — Oracle / data feed

| # | Incident pattern | LTP target | Status |
|---|---|---|---|
| [SCN-020](SCN-020-mango-oracle-manipulation/) | Mango oracle manipulation (Oct 2022, $116M) | (no on-chain oracle) | STRUCTURALLY-N/A |
| [SCN-021](SCN-021-cream-flashloan-oracle/) | Cream flashloan+oracle (Oct 2021, $130M) | (no flashloan + no oracle) | STRUCTURALLY-N/A |
| [SCN-022](SCN-022-bzx-three-incident/) | bZx three-incident pattern (2020-2021) | (no leverage/margin/borrow) | STRUCTURALLY-N/A |

## Layer 6 — Frontend / supply chain

| # | Incident pattern | LTP target | Status |
|---|---|---|---|
| [SCN-023](SCN-023-curve-dns-hijack/) | Curve DNS hijack (Aug 2022, $610k) | (no LTP dApp domain today) | PARTIAL — C1-C6 policy drafted |
| [SCN-024](SCN-024-curve-vyper-compiler/) | Curve Vyper compiler reentrancy (Jul 2023, $73M) | Solidity pragma + SHA-pinned actions | ✓ VERIFIED-GREEN |
| [SCN-025](SCN-025-badger-cloudflare/) | Badger Cloudflare injection (Dec 2021, $120M) | (no LTP CDN today) | PARTIAL — B1-B6 policy drafted |
| [SCN-026](SCN-026-ledger-connect-kit-npm/) | Ledger Connect Kit npm (Dec 2023, $610k) | Docker digest-pin + pip-audit | ✓ VERIFIED-GREEN |

## Layer 7 — Off-chain infrastructure

| # | Incident pattern | LTP target | Status |
|---|---|---|---|
| [SCN-027](SCN-027-mixin-cloud-compromise/) | Mixin cloud-provider compromise (Sep 2023, $200M) | multi-account KMS distribution | DOCUMENTATION-COMPLETE — IAM audit deferred |
| [SCN-028](SCN-028-gateway-bind/) | Gateway 0.0.0.0 default exposure | `__main__.py` loopback default | ✓ VERIFIED-GREEN |
| [SCN-029](SCN-029-grpc-resource-exhaustion/) | gRPC resource exhaustion | `server.py` 4MB / 100-stream limits | ✓ VERIFIED-GREEN |
| [SCN-030](SCN-030-ibc-packet-replay/) | Cosmos IBC packet replay (theoretical class) | replay + chain-id + sequence | ✓ VERIFIED-GREEN (via SCN-001) |

## Layer 8 — Social engineering (tabletop only)

| # | Incident pattern | LTP target | Status |
|---|---|---|---|
| [SCN-031](SCN-031-ronin-fake-recruiter/) | Ronin fake-recruiter LinkedIn DM (Mar 2022) | operator awareness | SCAFFOLDED — live drill pending consent |
| [SCN-032](SCN-032-inferno-drainer/) | Inferno Drainer wallet-drainer kit (2023-2024) | end-user dApp posture + brand protection | SCAFFOLDED — live drill pending consent |
| [SCN-033](SCN-033-heco-opsec-hygiene/) | Sun-era OPSEC hygiene (Heco, Nov 2023, $86M) | self-audit | SCAFFOLDED — live drill pending consent |

## Findings produced

| Finding | Scenario | Severity | Linear | Remediation | Status |
|---|---|---|---|---|---|
| **LTP-A-031** | [SCN-015](SCN-015-signer-rotation-grace/) | HIGH | [GLO-832](https://linear.app/globalsettlement/issue/GLO-832) | [PR #26](https://github.com/GlobalSettlementNetwork/gsx-lattice-protocol/pull/26) commit `577e80f` | ✓ REMEDIATED-GREEN |

**One real finding caught + fixed across 33 scenarios.** That's
the campaign's headline outcome.

## Per-scenario directory template

```
SCN-XXX-<slug>/
├── README.md          # incident summary + LTP mapping
├── threat-intel.md    # post-mortem citations (>= 2 sources)
├── test-evidence.md   # commit refs, CI run URLs
├── remediation.md     # only if a finding opened: LTP-A-NNN + patch link
└── transcript.md      # only for tabletop drills
```

## Cross-references

- [`/SECURITY_TESTING.md`](../../../SECURITY_TESTING.md) — charter + authorization
- [`RED_TEAM_CAMPAIGN_2026-05.md`](../RED_TEAM_CAMPAIGN_2026-05.md) — campaign master doc
- [`SECURITY_AUDIT_2026-05-15.md`](../../SECURITY_AUDIT_2026-05-15.md) §28 — historical-incident → LTP-A-* cross-reference table (back-linked to SCN-XXX directories in R-6)
