# Compliance Auditor

You're verifying **FedRAMP High readiness**, doing a **third-party security
audit**, or evaluating LTP for use inside a regulated environment. You need
control-matrix evidence, not protocol design.

## 30-second value prop

LTP ships with a FedRAMP High control matrix mapping each in-scope NIST
SP 800-53 control to specific code, configuration, and operational
evidence. System boundaries, data flows, and trust boundaries are
documented. Release evidence is reproducible from CI artifacts.

## Start here

1. **[compliance/fedramp-high/README.md](../compliance/fedramp-high/README.md)** —
   readiness overview, scope statement, and an index of every control
   family document.
2. **[compliance/fedramp-high/control-matrix.md](../compliance/fedramp-high/control-matrix.md)** —
   the canonical mapping: control → implementation → evidence pointer.
3. **[compliance/fedramp-high/system-boundary.md](../compliance/fedramp-high/system-boundary.md)** —
   what is inside the LTP boundary, what is outside, and where the
   regulated/unregulated interface sits.
4. **[compliance/fedramp-high/release-evidence.md](../compliance/fedramp-high/release-evidence.md)** —
   how to verify the evidence manifest matches the live deploy. Every
   line item is a path or a command you can run.
5. **[SECURITY_AUDIT_2026-05-15.md](../SECURITY_AUDIT_2026-05-15.md)** —
   the most recent independent audit, all findings, and remediation
   status per finding.
6. **[DEPLOYED_CONTRACTS.md](../DEPLOYED_CONTRACTS.md)** — verified
   on-chain anchor points for tying audit evidence back to immutable
   state.

## What's machine-verifiable today

- **Evidence manifest paths exist** — checked by
  `tests/test_fedramp_high_readiness.py::test_evidence_manifest_has_existing_paths_and_commands`.
  Failing test is a doc-evidence drift signal.
- **Control-matrix completeness** —
  `tests/test_compliance.py` walks every entry in the matrix and asserts
  the linked evidence is present and parseable.
- **Pinned dependency floors / ceilings** — see `pyproject.toml`
  `[project.optional-dependencies]` and the bump policy in
  [STABILITY_PROMISES.md](../STABILITY_PROMISES.md).
- **SHA-pinned CI actions** — all GitHub workflow actions are SHA-pinned
  per the security audit's LTP-A-025 finding.

## Production roadmap context

[plans/2026-05-11-production-roadmap.md](../plans/2026-05-11-production-roadmap.md)
captures the gates between current state and FedRAMP authorization
candidate state. The audit log of completed gates is the
[plans/2026-05-15-gate-5-6-closure.md](../plans/2026-05-15-gate-5-6-closure.md)
document and its predecessors.

## You probably don't need

- The whitepaper, threat model, or formal proofs — those are for the
  cryptographer persona. The control matrix references them where
  relevant.
- The dApp-developer or operator personas — they describe usage, not
  compliance evidence.
