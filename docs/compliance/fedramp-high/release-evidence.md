# Release Evidence Requirements

Every FedRAMP High readiness release must include the artifacts below. Store
the generated files in the release evidence archive and link them from the
official SSP or POA&M package.

## Required Artifacts

| Artifact | Requirement |
|---|---|
| SBOM | CycloneDX or SPDX SBOM for Python, Solidity, Rust, and container layers |
| Dependency scan | Vulnerability scan with severity, exploitability, owner, and disposition |
| Semgrep | Static analysis results with all High/Critical findings resolved or POA&M-owned |
| Signed artifacts | Container image digests, contract build artifacts, and release bundles signed |
| Provenance | SLSA/in-toto provenance attestation for each shipped artifact |
| Pinned SHAs | Exact `suwappu-lattice-protocol`, `suwappu-dag`, and `suwappu-db` commits or tags |
| Test reports | Local LTP, contracts, simulator, DAG, and DB gate output |
| POA&M | Owner, due date, severity, residual risk, and mitigation for every gap |
| KMS/HSM evidence | FIPS 140-3 certificate, module boundary, operating mode, key policy |
| SIEM evidence | Ingest endpoint, retention setting, alert routing, review cadence |

## Release Report Template

```text
Release ID:
Release date:
Environment:
Deployment profile: fedramp-high

Repository pins:
- suwappu-lattice-protocol commit/tag:
- suwappu-dag commit/tag:
- suwappu-db commit/tag:

Artifacts:
- Container image digest:
- Contract artifact digest:
- SBOM path:
- Dependency scan path:
- Semgrep path:
- Provenance attestation path:
- Signature verification output:

LTP gates:
- python3 -m pytest tests/ -q:
- cd contracts && forge test -vvv:
- python3 -m src.simulator.ci_harness --seeds 42,123,777 --steps 500 --fault-rate 0.1:

Cross-repo gates:
- suwappu-dag cargo test --workspace:
- suwappu-dag PROPTEST_CASES=10000 cargo test --workspace --release:
- suwappu-db cargo test --workspace:
- suwappu-db scripts/check-lane-separation.sh:
- suwappu-db scripts/cross-parity.sh:
- suwappu-db PROPTEST_CASES=10000 cargo test --workspace --release:

KMS/HSM evidence:
- Module name:
- Validation certificate:
- Boundary description:
- Key IDs:

Open POA&M:
- Finding:
- Severity:
- Owner:
- Due date:
- Mitigation:
- Residual risk:
```
