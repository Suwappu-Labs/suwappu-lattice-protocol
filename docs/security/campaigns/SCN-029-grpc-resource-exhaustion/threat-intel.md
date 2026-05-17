# SCN-029 — Threat intelligence sources

This scenario covers a **structural class** rather than a single
named incident.

## Canonical references

- **gRPC project security best-practices** — explicitly
  recommends setting `max_receive_message_length`,
  `max_send_message_length`, and `max_concurrent_streams` to
  finite values appropriate to the workload.
- **NIST SP 800-53 SC-5** — "denial of service protection"
  applied to RPC interfaces.
- **CWE-770** — "Allocation of Resources Without Limits or
  Throttling."

## Related real-world incidents

- Multiple Kubernetes / etcd CVEs where default gRPC limits
  enabled cluster-wide DoS.
- Several Web3 RPC providers (Solana, Cosmos) have had
  resource-exhaustion incidents when public-facing nodes
  shipped with default-unlimited limits.
- The broader "happy eyeballs" class of resource-exhaustion
  bugs in distributed systems.

## Root primitive

Server-side configuration without explicit resource caps. A
single malicious client can:
- OOM the server with a large message.
- Exhaust the connection or thread pool with concurrent
  streams.
- Block legitimate traffic by saturating the executor.

Defenses are **explicit, low caps on every relevant resource**,
sized to the legitimate workload with reasonable headroom.

## Mapping to LTP

LTP's gRPC server caps message size (4 MiB), concurrent streams
(100), and thread pool (10 workers by default). LTP-A-019 was
closed by setting these limits; SCN-029 is the regression test
that pins them in CI.

## Date of last verification

2026-05-17 — SCN-029 added under R-4.
