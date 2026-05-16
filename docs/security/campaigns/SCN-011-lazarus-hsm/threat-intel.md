# SCN-011 — Threat intelligence sources

This scenario covers a class of incidents — **DPRK / Lazarus-
attributed sustained operator-key compromise** — rather than one
specific incident.

## Incidents in the cluster

| Date | Target | Loss | Attribution |
|------|--------|------|-------------|
| Mar 2022 | Ronin Bridge | $625M | Lazarus (OFAC, FBI, Chainalysis) |
| Jun 2022 | Harmony Horizon | $100M | Lazarus (Chainalysis, Elliptic) |
| Jun 2023 | Atomic Wallet | $100M | Lazarus (Elliptic, Chainalysis) |
| May 2024 | DMM Bitcoin | $305M | Lazarus (NPA Japan, FBI) |
| Jul 2024 | WazirX | $230M | Lazarus (CertiK, Elliptic) |

## Primary sources

- **OFAC / Treasury sanctions notices** — list of attacker
  wallets, fund-movement summaries.
- **FBI Internet Crime Complaint Center (IC3) advisories** —
  TraderTraitor, AppleJeus, BeaverTail toolkit families.
- **Mandiant APT38 / Lazarus Group profile** —
  https://www.mandiant.com/resources/insights/apt-groups
- **Project team post-mortems** for each incident.

## Secondary technical analyses

- **Chainalysis Crypto Crime Report** (annual) — quantitative
  attribution and TTP evolution.
- **Elliptic / TRM Labs** — fund-tracing chains showing the
  Tornado Cash / cross-chain mixer patterns.
- **CertiK / SlowMist** — incident-specific TTP analyses.

## Root primitive

Sustained operator-environment compromise. Adversary maintains
covert access to signing infrastructure over weeks or months,
minimizing detectable activity until a "drain window" — typically
a low-staff period — opens.

Defenses fall into three layers:

1. **Cryptographic** (contract / wire format): bound what the
   attacker can SIGN even with operator access. LTP's
   thin-on-chain design (LTP-A-001 BY-DESIGN) means signed
   anchors still must satisfy on-chain replay / sequence /
   binding checks. SCN-001 through SCN-004 cover this.

2. **Trust boundary** (HSM): private key material never reaches
   memory outside the HSM. An attacker on the operator host
   can request signatures during the access window, but cannot
   exfiltrate the key for offline signing. SCN-011 (this file)
   pins this.

3. **Operational** (process): monitor signing cadence, rotate
   keys regularly, enforce dual-control on high-value paths,
   alert on anomalies. Documented in `OPERATOR_RUNBOOK.md`.
   This is the layer where social-engineering tabletops
   (SCN-031, SCN-033) live.

## Mapping to LTP

LTP's HSM abstraction (`src/ltp/hsm.py`) implements layer 2.
The SoftwareHSM is for development; the abstract HSMBackend
defines a production-ready surface that PKCS#11 and Cloud-KMS
backends will implement. The defenses are:

- Private keys never returned via the public API (no
  `export_private`).
- Sign / decaps gated on key existence and key type.
- Destroy zeroizes material; signing after destroy fails.
- Duplicate key_id generation is rejected — defends against
  stealth-rotation.
- Production gate (LTP-A-004) refuses SoftwareHSM in prod.

The layer-3 (operational) defenses are explicitly OUT OF SCOPE
for this scenario — they're covered by the runbook and the
upcoming SCN-031 / SCN-033 tabletop drills.

## Date of last verification

2026-05-16 — SCN-011 added under R-3.
