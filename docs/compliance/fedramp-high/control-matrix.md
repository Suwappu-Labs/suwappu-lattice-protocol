# NIST SP 800-53 Rev. 5 High Readiness Matrix

This matrix is a repo-level evidence crosswalk. It does not replace the
official FedRAMP High SSP control implementation workbook for the deployed
cloud service offering.

| Control | Status | Owner | Evidence path | Test command | POA&M |
|---|---|---|---|---|---|
| AC-2 Account Management | Partial | Platform security | `src/ltp/compliance.py` | `python3 -m pytest tests/test_compliance.py -q` | Define IdP lifecycle evidence |
| AC-3 Access Enforcement | Implemented | LTP | `src/ltp/gateway/auth.py` | `python3 -m pytest tests/test_gateway_auth.py -q` | None |
| AC-6 Least Privilege | Partial | LTP | `src/ltp/compliance.py` | `python3 -m pytest tests/test_compliance.py -q` | Map production roles to IdP groups |
| AU-2 Event Logging | Implemented | LTP | `src/ltp/compliance.py` | `python3 -m pytest tests/test_fedramp_high_readiness.py -q` | None |
| AU-3 Content of Audit Records | Implemented | LTP | `src/ltp/compliance.py` | `python3 -m pytest tests/test_fedramp_high_readiness.py -q` | None |
| AU-6 Audit Review, Analysis, Reporting | Partial | SecOps | `src/ltp/compliance.py` | `python3 -m pytest tests/test_compliance.py -q` | Connect production SIEM playbooks |
| AU-8 Time Stamps | Partial | Platform | `src/ltp/compliance.py` | `python3 -m pytest tests/test_compliance.py -q` | Add NTP/time-source evidence |
| AU-9 Protection of Audit Information | Partial | SecOps | `src/ltp/compliance.py` | `python3 -m pytest tests/test_compliance.py -q` | Add immutable sink configuration |
| CA-7 Continuous Monitoring | Partial | SecOps | `src/ltp/observability/` | `python3 -m pytest tests/test_observability_wiring.py -q` | Add ConMon cadence |
| CM-2 Baseline Configuration | Partial | Platform | `config/fedramp-high.env.template` | `python3 -m pytest tests/test_fedramp_high_readiness.py -q` | Capture production baseline |
| CM-3 Configuration Change Control | Partial | Platform | `docs/compliance/fedramp-high/release-evidence.md` | `python3 -m pytest tests/test_fedramp_high_readiness.py -q` | Tie to CAB workflow |
| CM-6 Configuration Settings | Implemented | LTP | `deploy/preflight_gateway.py` | `python3 -m pytest tests/test_fedramp_high_readiness.py -q` | None |
| CM-8 System Component Inventory | Partial | Platform | `docs/compliance/fedramp-high/system-boundary.md` | `python3 -m pytest tests/test_fedramp_high_readiness.py -q` | Add cloud inventory export |
| CP-2 Contingency Plan | Planned | Platform | `docs/compliance/fedramp-high/ssp-narratives.md` | `python3 -m pytest tests/test_backup.py -q` | Write operational plan |
| CP-9 System Backup | Partial | LTP | `src/ltp/cloud/backup.py` | `python3 -m pytest tests/test_backup.py -q` | Add restoration exercise evidence |
| IA-2 Identification and Authentication | Partial | Platform security | `src/ltp/gateway/auth.py` | `python3 -m pytest tests/test_gateway_auth.py -q` | Integrate production IdP |
| IA-5 Authenticator Management | Partial | Platform security | `src/ltp/hsm.py` | `python3 -m pytest tests/test_key_lifecycle.py -q` | Add PKI/KMS rotation evidence |
| IR-4 Incident Handling | Planned | SecOps | `docs/compliance/fedramp-high/ssp-narratives.md` | `python3 -m pytest tests/test_alerts.py -q` | Add incident runbooks |
| IR-5 Incident Monitoring | Partial | SecOps | `src/ltp/observability/alerts.py` | `python3 -m pytest tests/test_alerts.py -q` | Wire alerts to SIEM |
| RA-5 Vulnerability Monitoring and Scanning | Planned | Security | `docs/compliance/fedramp-high/release-evidence.md` | `semgrep --config auto .` | Add scan artifacts |
| SA-10 Developer Configuration Management | Partial | Engineering | `docs/compliance/fedramp-high/release-evidence.md` | `git status --short` | Add protected branch evidence |
| SA-11 Developer Testing and Evaluation | Implemented | Engineering | `tests/` | `python3 -m pytest tests/ -q` | None |
| SA-15 Development Process, Standards, Tools | Partial | Engineering | `pyproject.toml` | `python3 -m pytest tests/ -q` | Add SDLC policy reference |
| SC-7 Boundary Protection | Partial | Platform | `docs/compliance/fedramp-high/trust-boundary.md` | `python3 -m pytest tests/test_tls_config.py -q` | Add network policy manifests |
| SC-8 Transmission Confidentiality and Integrity | Implemented | LTP | `src/ltp/network/credentials.py` | `python3 -m pytest tests/test_grpc_tls.py -q` | None |
| SC-12 Cryptographic Key Establishment and Management | Partial | Security | `src/ltp/hsm.py` | `python3 -m pytest tests/test_key_lifecycle.py -q` | Add FIPS 140-3 validation evidence |
| SC-13 Cryptographic Protection | Partial | LTP/Security | `src/ltp/compliance.py` | `python3 -m pytest tests/test_compliance.py -q` | Validate runtime module boundary |
| SC-28 Protection of Information at Rest | Partial | LTP | `src/ltp/primitives.py` | `python3 -m pytest tests/test_primitives.py -q` | Add storage encryption evidence |
| SI-2 Flaw Remediation | Planned | Engineering | `docs/compliance/fedramp-high/release-evidence.md` | `python3 -m pytest tests/ -q` | Add patch SLA evidence |
| SI-4 System Monitoring | Partial | SecOps | `src/ltp/observability/` | `python3 -m pytest tests/test_observability_integration.py -q` | Connect production SIEM |
| SR-3 Supply Chain Controls | Planned | Security | `docs/compliance/fedramp-high/release-evidence.md` | `python3 -m pytest tests/test_fedramp_high_readiness.py -q` | Add vendor inventory |
| SR-4 Provenance | Planned | Release | `docs/compliance/fedramp-high/release-evidence.md` | `cosign verify-attestation REPLACE_ARTIFACT` | Add signed provenance artifacts |
| SR-6 Supplier Assessments | Planned | Security | `docs/compliance/fedramp-high/release-evidence.md` | `python3 -m pytest tests/test_fedramp_high_readiness.py -q` | Add supplier assessments |
| SR-11 Component Authenticity | Planned | Release | `docs/compliance/fedramp-high/release-evidence.md` | `syft . -o cyclonedx-json` | Add SBOM and signature evidence |
