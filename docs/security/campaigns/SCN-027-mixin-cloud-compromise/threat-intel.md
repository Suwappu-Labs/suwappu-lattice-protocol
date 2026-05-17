# SCN-027 — Threat intelligence sources

Historical incident: **Mixin Network compromise, 23 September 2023, ~\$200M.**

## Primary sources

- **Mixin Network team statements** — published on the project's
  X/Twitter and Discord during/after the incident.
- **Alibaba Cloud (cloud-provider) response** — limited public
  acknowledgement; technical specifics not disclosed.

## Secondary technical analyses

- **SlowMist incident report** — on-chain fund-tracing.
- **Chainalysis** — attribution analysis.
- **PeckShield** — multi-chain drain timeline.

## Root primitive

The cloud-provider account is a privileged execution context.
The attacker compromised it through a vector Mixin did not
disclose; downstream they had access to key material protected
by the cloud's KMS / TEE infrastructure.

Defenses cluster into three categories:

1. **Boundary separation**: spread privileged operations across
   multiple cloud accounts in multiple regions so no single
   account compromise reaches all key material.

2. **Privilege hygiene**: principle of least privilege on IAM,
   hardware-token-gated break-glass procedures, regular access
   reviews.

3. **Detection**: append-only audit logging to an isolated
   account, anomaly detection on key-use events.

Related incidents:
- DMM Bitcoin (May 2024, ~\$305M) — operator-environment
  compromise enabling drain
- WazirX (Jul 2024, ~\$230M) — Liminal Custody multisig with
  insufficient guardian independence (cloud-tier counterpart)
- Various smaller incidents involving compromised CI/CD
  credentials, leaked AWS access keys, etc.

## Mapping to LTP

LTP's gateway VM uses three KMS slots in three distinct cloud
accounts in three distinct regions (per OPERATOR_RUNBOOK §13.1).
A single-account compromise reaches at most one slot; the
multisig threshold means at least three slots must cooperate
to authorize anything.

The cloud-tier defenses (MX1-MX7 in scenario README) are
operational policy. SCN-027 documents them for the R-5
operator-team formalization.

## Date of last verification

2026-05-17 — SCN-027 added under R-4.
