# System Boundary

## Boundary Statement

`suwappu-lattice-protocol` is the transfer, attestation, gateway, and anchor layer
for the SUWAPPU stack. The assessment boundary for this repository includes code,
configuration, contracts, tests, and operational evidence that prove LTP can
run as a hardened component inside a FedRAMP High cloud service offering.

The boundary does not include the SUWAPPU ordering engine or the SUWAPPU state
substrate. Those remain owned by `suwappu-dag` and `suwappu-db` and must provide their
own release evidence.

## In Boundary

| Component | Evidence path | Boundary role |
|---|---|---|
| Transfer lifecycle | `src/ltp/protocol.py` | COMMIT, LATTICE, MATERIALIZE protocol flow |
| Gateway VM | `src/ltp/gateway_vm/` | External chain observation and gateway attestations |
| Gateway preflight | `deploy/preflight_gateway.py` | Fail-closed deployment gate |
| Compliance controls | `src/ltp/compliance.py` | RBAC, audit events, SIEM export, HSM/KMS abstractions |
| Anchor registry | `contracts/src/LTPAnchorRegistry.sol` | On-chain anchor submit/verify surface |
| Gateway auth | `src/ltp/gateway/auth.py` | API authentication and signed JWT verification |
| mTLS support | `src/ltp/network/credentials.py` | gRPC mutual TLS credential loading |
| Observability | `src/ltp/observability/` | Metrics, structured logs, alerts |
| KMS adapters | `src/ltp/cloud/` | KMS lifecycle and AWS KMS envelope encryption |
| HSM abstraction | `src/ltp/hsm.py` | HSM interface for private-key operations |

## External Dependencies

| External system | Owner | Required evidence |
|---|---|---|
| `suwappu-dag` | DAG team | ordered-block integrity, validator consensus, LTP corridor attestation tests |
| `suwappu-db` | DB team | state mutation controls, state root correctness, recovery, L2 sync tests |
| KMS/HSM | Cloud/security team | FIPS 140-3 module boundary and validation certificate evidence |
| SIEM/audit sink | SecOps | ingest endpoint, retention, alert routing, access controls |
| IdP / PKI | Platform security | identity proofing, certificate issuance, revocation, mTLS trust anchors |
| Source/destination chains | Chain operations | production chain IDs, deployed bytecode, contract verification |

## Data Categories

- committed entity metadata and ciphertext shard references
- lattice keys sealed to authorized receivers
- anchor state roots and attestation records
- gateway event observations
- signed tree heads, DKG records, quorum-signing records
- audit events and SIEM exports
- KMS/HSM key IDs and public keys

Private keys, plaintext operator keys, and raw KMS/HSM private material must not
cross into application environment variables in the `fedramp-high` profile.
