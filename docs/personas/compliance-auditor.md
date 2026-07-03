# Compliance Auditor

You're doing a **third-party security audit**, evaluating LTP for use inside
a regulated environment, or verifying **FedRAMP High readiness**. You need
control evidence, not protocol design.

## 30-second value prop

LTP ships a fail-closed FedRAMP-High deployment profile
(`ETP_DEPLOYMENT_PROFILE=fedramp-high`), audit-event schemas aligned to
NIST SP 800-53 requirements, HSM/KMS custody boundaries, and published
internal security audits with per-finding remediation status. The full
FedRAMP High readiness package (control matrix, SSP narratives, system /
trust / assessment boundaries, evidence manifest) is maintained privately
and available to auditors on request.

## Start here

1. **[SECURITY_AUDIT_2026-05-15.md](../security/audits/internal/SECURITY_AUDIT_2026-05-15.md)** —
   the most recent internal audit, all findings, and remediation status
   per finding.
2. **[RED_TEAM_REPORT_2026-05.md](../security/audits/internal/RED_TEAM_REPORT_2026-05.md)** —
   internal red-team self-assessment.
3. **[THREAT_MODEL.md](../THREAT_MODEL.md)** — adversary model and
   trust-boundary analysis.
4. **[DEPLOYED_CONTRACTS.md](../DEPLOYED_CONTRACTS.md)** — verified
   on-chain anchor points for tying audit evidence back to immutable
   state.
5. **`src/ltp/compliance.py`** — the compliance framework surface:
   audit-event schema, `ComplianceConfig` validation, and the
   FedRAMP-High profile gates (exercised by
   `tests/test_fedramp_high_readiness.py`).

## What's machine-verifiable today

- **Deployment-profile gates** — `deploy/preflight_gateway.py` fails
  closed under `ETP_DEPLOYMENT_PROFILE=fedramp-high`; covered by
  `tests/test_fedramp_high_readiness.py`.
- **Control/audit-event schema** — `tests/test_compliance.py` exercises
  the audit-event and compliance-config surface.
- **Pinned dependency floors / ceilings** — see `pyproject.toml`
  `[project.optional-dependencies]` and the bump policy in
  [STABILITY_PROMISES.md](../STABILITY_PROMISES.md).
- **SHA-pinned CI actions** — all GitHub workflow actions are SHA-pinned
  per the security audit's LTP-A-025 finding.

## You probably don't need

- The whitepaper, threat model deep-dives, or formal proofs — those are
  for the cryptographer persona. Audit evidence references them where
  relevant.
- The dApp-developer or operator personas — they describe usage, not
  compliance evidence.
