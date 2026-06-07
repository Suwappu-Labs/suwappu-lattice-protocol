# SSP-Style Narratives

## Access Control

LTP provides role and permission primitives in `src/ltp/compliance.py` and API
authentication hooks in `src/ltp/gateway/auth.py`. Production FedRAMP High
deployments must bind these identities to the authorized IdP, enforce least
privilege by role, and preserve audit records for allow and deny decisions.

## Audit Logging

`AuditEvent` records include schema version, event type, actor, action,
timestamp, outcome, component, source, correlation ID, control IDs, and
structured details. The required FedRAMP event families include authn/authz,
lattice-key issue/materialize, anchor submit/verify, signer/DKG events,
KMS/HSM operations, governance actions, config changes, preflight failures, and
cross-repo sync failures.

## Cryptography

The protocol uses FIPS-approved algorithm families where applicable:

- ML-KEM under FIPS 203 for key encapsulation
- ML-DSA under FIPS 204 for signatures
- SHA3/SHAKE under FIPS 202 for hashing and domain-separated digests

Algorithm approval is not the same as FIPS 140-3 module validation. Deployment
evidence must identify the validated module, certificate, boundary, operating
mode, and key lifecycle procedures for the runtime cryptographic module.

## Key Management

The `fedramp-high` profile rejects plaintext operator keys in environment
variables. Operators must use KMS/HSM key references. DKG and threshold-signing
evidence is part of the key ceremony story: quorum signing, subset
independence, key finalization, complaint handling, and verification tests must
be attached to the release evidence.

## Configuration Management

`deploy/preflight_gateway.py` is the implementation gate for the government
profile. The release process must preserve the exact profile values, production
chain IDs, deployed contract addresses, KMS/HSM references, mTLS certificate
paths, SIEM sink, and pinned repo commits.

## Incident Response

Preflight failures, auth failures, KMS/HSM errors, DKG complaints, quorum
failures, anchor verification failures, governance actions, and cross-repo
sync failures must emit audit events and route to the SIEM. SecOps must attach
incident runbooks, escalation paths, and after-action evidence outside this
repo.

## Contingency

Backup and restoration evidence must cover commitment logs, audit logs,
configuration baselines, key references, chain anchor reconciliation, and SUWAPPU-DB
state root recovery. LTP recovery cannot claim SUWAPPU-DB state recovery without
evidence from the `suwappu-db` release gates.

## Monitoring

Observability evidence lives under `src/ltp/observability/` and the related
tests. FedRAMP High readiness requires production alert routing, review
cadence, SIEM retention, and continuous monitoring evidence for the deployed
environment.

## Supply Chain

Each release must attach SBOM, dependency scan, Semgrep results, signed
artifacts, provenance attestation, pinned repo SHAs, release test reports, and
POA&M entries for unresolved findings.
