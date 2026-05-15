# Data Flow

## Primary Flow

```text
sender
  -> LTP COMMIT
  -> commitment log and encrypted shard placement
  -> GSX-DAG ordered block attestation from companion repo
  -> GSX-DB state root from companion repo
  -> LTP anchor submit/verify through LTPAnchorRegistry
  -> lattice-key materialization of snapshot or delta
  -> receiver
```

LTP carries transfer and attestation evidence. Ordering and state mutation are
outside this repository and must be evidenced by `gsx-dag` and `gsx-db`.

## Trust-Boundary Transitions

| Transition | Control intent | Evidence |
|---|---|---|
| API caller to gateway | authenticated and authorized request | `src/ltp/gateway/auth.py`, `tests/test_gateway_auth.py` |
| gateway to node services | mTLS and signed protocol messages | `src/ltp/network/credentials.py`, `tests/test_grpc_tls.py` |
| gateway to chains | production RPC endpoint and bytecode checks | `deploy/preflight_gateway.py` |
| application to KMS/HSM | key ID reference, no plaintext private key | `src/ltp/cloud/`, `src/ltp/hsm.py` |
| application to SIEM | structured audit export | `src/ltp/compliance.py` |
| LTP to GSX-DAG | attestation boundary only | `docs/design-decisions/GSX_DAG_DB_INTEGRATION.md` |
| LTP to GSX-DB | anchor/materialization boundary only | `docs/design-decisions/GSX_DAG_DB_INTEGRATION.md` |

## Required Audit Events

The audit schema in `src/ltp/compliance.py` must cover:

- authentication and authorization decisions
- lattice key issue and materialization
- anchor submit and verify
- signer, DKG, threshold quorum, and key-finalization events
- KMS/HSM operations
- governance actions and configuration changes
- preflight failures
- cross-repo sync or release-gate failures

Each event must include `event_id`, `schema_version`, `event_type`, `actor_id`,
`action`, `timestamp`, `outcome`, `component`, `source`, `control_ids`, and
structured `details`.
