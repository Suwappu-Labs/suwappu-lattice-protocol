# Campaign Scenario Index — May 2026

Status legend: `PLANNED` → `IN-PROGRESS` → `VERIFIED-GREEN` (defense
held on first run) | `REMEDIATED-GREEN` (test failed → finding →
patch → test now green) | `DEFERRED-WITH-RISK-ACCEPTED` (out of
scope or accepted residual risk).

Each scenario links to its evidence directory `SCN-XXX-<slug>/` once
it enters IN-PROGRESS.

## Layer 1 — Smart-contract input validation

| # | Incident pattern | LTP target | Test type | LTP-A-* link | Status |
|---|---|---|---|---|---|
| SCN-001 | Wormhole signature-verification skip (Feb 2022, $326M) | `LTPAnchorRegistry.submitAnchor` | Foundry unit | LTP-A-001 | PLANNED |
| SCN-002 | Nomad init-bug "any message valid" (Aug 2022, $190M) | Bridge initializer | Foundry unit + invariant | LTP-A-003 | PLANNED |
| SCN-003 | Poly Network keeper-role escalation (Aug 2021, $611M) | Cross-chain message handler | Foundry unit | LTP-A-005 | PLANNED |
| SCN-004 | Orbit Chain multisig threshold subversion (Jan 2024, $82M) | Multisig wrapper | Foundry unit | LTP-A-002, LTP-A-008 | PLANNED |
| SCN-005 | Penpie reentrancy via callback (Sep 2024, $27M) | `OptimisticBridgeChallenge` | Foundry invariant (new) | new finding candidate | PLANNED |
| SCN-006 | Euler donate-to-self accounting (Mar 2023, $197M, recovered) | Bond accounting | Foundry invariant | covered by existing `invariant_bonds_conserved` | PLANNED |
| SCN-007 | THORChain ETH router decode bug (Jul 2021, $5M) | Any ABI-decode surface | Foundry unit | new finding candidate | PLANNED |

## Layer 2 — Validator / consensus / signing

| # | Incident pattern | LTP target | Test type | LTP-A-* link | Status |
|---|---|---|---|---|---|
| SCN-008 | Ronin 5-of-9 with 4 active signers (Mar 2022, $625M) | LTP threshold + active-set check | Forge fork test against testnet | LTP-A-002 | PLANNED |
| SCN-009 | Harmony 2-of-5 key compromise (Jun 2022, $100M) | Multisig signer-count enforcement | Forge unit | LTP-A-002, LTP-A-004 | PLANNED |
| SCN-010 | THORChain Bifrost mis-signed transfer (Jun 2021, $140k) | BLS aggregate verifier on relayed messages | pytest | LTP-A-015 (BLS PoP) | PLANNED |
| SCN-011 | Lazarus-tier sustained key compromise (Ronin/Harmony/DMM/WazirX) | HSM-backed signing path | pytest (mocks HSM) | LTP-A-004 | PLANNED |

## Layer 3 — Key management & rotation

| # | Incident pattern | LTP target | Test type | LTP-A-* link | Status |
|---|---|---|---|---|---|
| SCN-012 | Multichain single-custody collapse (Jul 2023, $125M) | Operator-key custody policy | tabletop + pytest | LTP-A-004 | PLANNED |
| SCN-013 | Radiant Capital blind-signing (Oct 2024, $58M) | Hardware-wallet signing path | tabletop (operator runbook drill) | LTP-A-004 + new operator doc | PLANNED |
| SCN-014 | Mt Gox-class hot-wallet drain (2014) | Operator hot-wallet balance ceiling | pytest + alert rule | new finding candidate | PLANNED |
| SCN-015 | Signer rotation in-flight race | Rotation grace-period enforcement | Foundry unit | LTP-A-030 | PLANNED |

## Layer 4 — Governance

| # | Incident pattern | LTP target | Test type | LTP-A-* link | Status |
|---|---|---|---|---|---|
| SCN-016 | Cypher Protocol pause bypass via upgrade (Aug 2023, $1M) | Timelock enforcement on `pause()` | Foundry unit | LTP-A-018, LTP-A-009 | PLANNED |
| SCN-017 | LayerZero DVN-count downgrade (2024 debate) | Verifier-set governance | Foundry unit | LTP-A-006 | PLANNED |
| SCN-018 | Parity multisig accidental kill (Nov 2017) | Public-init protection on libraries | Foundry unit | covered by existing init guards (verify) | PLANNED |
| SCN-019 | Production-Timelock delay not asserted | Timelock minimum delay | Foundry unit | LTP-A-009 | PLANNED |

## Layer 5 — Oracle / data feed

| # | Incident pattern | LTP target | Test type | LTP-A-* link | Status |
|---|---|---|---|---|---|
| SCN-020 | Mango price manipulation (Oct 2022, $116M) | Verify LTP doesn't accept external feeds unfiltered | pytest | new finding candidate | PLANNED |
| SCN-021 | Cream flashloan + oracle (Oct 2021, $130M) | Same surface | pytest | new finding candidate | PLANNED |
| SCN-022 | bZx three-incident pattern (2020-2021) | Bond-pricing flow if any | pytest | new finding candidate | PLANNED |

## Layer 6 — Frontend / supply chain

| # | Incident pattern | LTP target | Test type | LTP-A-* link | Status |
|---|---|---|---|---|---|
| SCN-023 | Curve DNS hijack at registrar (Aug 2022) | LTP docs/dApp DNS posture | tabletop + DNSSEC check | new finding candidate | PLANNED |
| SCN-024 | Curve Vyper compiler reentrancy (Jul 2023) | Solidity compiler version + audit chain | pytest (compiler-version pin) | LTP-A-025 adjacent | PLANNED |
| SCN-025 | Badger Cloudflare worker injection (Dec 2021, $120M) | Any CDN-fronted LTP UI | tabletop + SRI check | new finding candidate | PLANNED |
| SCN-026 | Ledger Connect Kit npm compromise (Dec 2023) | Any npm dependency in dApp surface | pytest scanning dep lockfile | LTP-A-026 adjacent | PLANNED |

## Layer 7 — Off-chain infrastructure

| # | Incident pattern | LTP target | Test type | LTP-A-* link | Status |
|---|---|---|---|---|---|
| SCN-027 | Mixin Network cloud-provider compromise (Sep 2023, $200M) | Operator cloud-key blast radius | tabletop + IAM audit | new finding candidate | PLANNED |
| SCN-028 | Gateway 0.0.0.0 default exposure | Gateway HTTP bind | pytest | LTP-A-011 | PLANNED |
| SCN-029 | gRPC resource-exhaustion | Gateway gRPC server | pytest fuzz | LTP-A-019 | PLANNED |
| SCN-030 | Cosmos IBC packet replay (theoretical class) | LTP anchor replay protection | Foundry invariant | LTP-A-008 | PLANNED |

## Layer 8 — Social engineering (tabletop only)

| # | Incident pattern | LTP target | Test type | LTP-A-* link | Status |
|---|---|---|---|---|---|
| SCN-031 | Ronin fake-recruiter LinkedIn DM (Mar 2022) | Operator team awareness | Tabletop drill (paper) | new operator doc | PLANNED |
| SCN-032 | Inferno Drainer wallet-drainer kit (2023-2024) | End-user dApp posture | Tabletop drill (paper) | new operator doc | PLANNED |
| SCN-033 | Sun-era operational hygiene (Heco, Nov 2023, $86M) | Operator OPSEC posture | Tabletop drill (paper) | new operator doc | PLANNED |

## Per-scenario directory template

When a scenario enters IN-PROGRESS, create `SCN-XXX-<slug>/` with:

```
SCN-XXX-<slug>/
├── README.md          # incident summary + LTP mapping
├── threat-intel.md    # post-mortem citations (>= 2 sources)
├── test-evidence.md   # commit refs, CI run URLs
├── remediation.md     # only if a finding opened: LTP-A-NNN + patch link
└── transcript.md      # only for tabletop drills
```

Authoring tip: in the README, lead with "What happened" (one
paragraph) then "How LTP defends against this class" with the test
file path. The reader should be able to skim 10 scenarios in 5
minutes.
