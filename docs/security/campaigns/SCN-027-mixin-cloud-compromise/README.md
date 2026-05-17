# SCN-027 — Mixin Network cloud-provider compromise

**Status.** DOCUMENTATION-COMPLETE. Live IAM audit deferred to R-5.
**Layer.** 7 — Off-chain infrastructure.
**Historical incident.** Mixin Network, 23 Sep 2023, ~\$200M.
**LTP-A-* link.** None directly. Operator-policy deliverable.

## What happened (Mixin)

Mixin Network ran its TEE (Trusted Execution Environment)
infrastructure on Alibaba Cloud. The attacker compromised the
cloud-provider account (specifics never fully disclosed) and
gained access to key material that controlled the project's
on-chain hot wallets. ~\$200M drained across multiple chains.

Root primitive: **the cloud-provider account is a privileged
execution context.** Whoever controls IAM credentials with
sufficient privilege can:
- Spin up new compute that pulls key material from KMS.
- Modify IAM policies to grant themselves additional access.
- Read or modify any data at rest in S3/EFS/etc.
- Disable logging / audit trails before the operator notices.

## LTP analogue

LTP's gateway VM runs on AWS / GCP infrastructure with KMS-
managed keys (per `OPERATOR_RUNBOOK.md` §13.1):

| Slot | Role | Custody |
|------|------|---------|
| 1 | Engineering — region A | AWS KMS (us-east-1) gated by IAM + MFA |
| 2 | Engineering — region B | GCP Cloud KMS (europe-west1) gated by IAM + MFA |
| 3 | Engineering — region C | AWS KMS (ap-southeast-1) gated by IAM + MFA |

Each KMS slot is in a different cloud account in a different
region. A single-account compromise reaches at most ONE slot.

The defenses (drafted in this scenario; to be formalized):

| ID | Policy |
|----|--------|
| MX1 | Three KMS slots in three distinct cloud accounts in three distinct regions (already in runbook §13.1) |
| MX2 | Multi-region cloud-account boundary — no IAM trust relationships between the three accounts |
| MX3 | Root account credentials in hardware-token-protected break-glass procedure (NOT used for day-to-day) |
| MX4 | CloudTrail / Cloud Audit Logs streamed to an isolated logging account with append-only retention |
| MX5 | Anomaly detection on KMS Sign / Decrypt calls — alert on volume spikes, off-hours signing, novel principals |
| MX6 | Quarterly IAM access review: prune unused roles, rotate access keys |
| MX7 | Annual external red-team / penetration test of the cloud-account boundary |

## Test pack

| Test type | Path | What it pins |
|---|---|---|
| **None at code level.** | _operational_ | Verification path is an IAM-policy audit + cloud-account configuration review. Deferred to R-5 with operator team. |

## Cross-references

- **SCN-011** (Lazarus HSM trust boundary) — covers the
  cryptographic layer; SCN-027 covers the infra layer
  immediately above it
- **OPERATOR_RUNBOOK §13.1** — owner-set + key custody policy

## Findings opened

None. Policy items MX1-MX7 captured for R-5 formalization.
