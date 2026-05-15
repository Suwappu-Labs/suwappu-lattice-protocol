# Trust Boundary

## Zones

| Zone | Description | Required gate |
|---|---|---|
| Public API | Gateway and diagnostics endpoints | JWT/authz, public-mode redaction, rate limiting |
| Service mesh | LTP node, gateway, federation, and gossip channels | mTLS with client certs |
| Key boundary | KMS/HSM private-key operations | key IDs only, no plaintext operator key env vars |
| Chain boundary | External production chains and deployed contracts | chain ID, RPC, bytecode, registry version checks |
| Audit boundary | Audit logger to SIEM or audit sink | structured export, retention, review workflow |
| Cross-repo boundary | GSX-DAG and GSX-DB evidence surfaces | pinned commits and release gates |

## Fail-Closed Rules

The `fedramp-high` profile must stop deployment when:

- `ETP_REQUIRE_REAL_CRYPTO` is absent or false
- any plaintext operator key environment variable is set
- KMS/HSM configuration is absent
- mTLS is disabled or client certificates are not required
- SIEM export is absent
- bridge/prover mode is mock, simulated, disabled, dev, or test
- chain IDs are known dev/test IDs
- RPC URLs are local, placeholder, devnet, or testnet endpoints

## Lattice Key Constraint

A lattice key authorizes materialization of committed snapshots or deltas. It
does not authorize GSX-DB mutation, validator ordering, bridge-token issuance,
or direct writes to canonical `BalanceSlot`s. GSX-DB state mutation must pass
through `gsxdb-bridge` and its capability gate.

## Crypto Boundary Language

The repo may use FIPS-approved algorithms such as ML-KEM (FIPS 203), ML-DSA
(FIPS 204), and SHA3/SHAKE (FIPS 202). That is different from proving that the
runtime cryptographic module is FIPS 140-3 validated. FedRAMP High evidence
must identify the deployed module boundary, validation certificate, operating
mode, and configuration for the actual runtime.
