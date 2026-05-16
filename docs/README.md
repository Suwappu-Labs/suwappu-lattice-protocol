# Lattice Transfer Protocol — Documentation

Post-quantum cryptographic data transfer with on-chain anchors. This index
routes you to the right document in one click; if you can't tell what
you're looking for yet, start with the persona pages.

## Who are you?

| You are… | Start here |
|---|---|
| **dApp developer** building on top of LTP anchors | [→ dApp Developer](personas/dapp-developer.md) |
| **Node operator** running a node, gateway, or corridor super-node | [→ Node Operator](personas/node-operator.md) |
| **Cryptographer** reviewing the protocol or the proofs | [→ Cryptographer](personas/cryptographer.md) |
| **Compliance auditor** verifying FedRAMP / third-party audit | [→ Compliance Auditor](personas/compliance-auditor.md) |
| **Contributor** sending a PR or filing a bug | [→ Contributor](personas/contributor.md) |

See [personas/README.md](personas/README.md) for the rationale and the
Diátaxis quadrant model.

## Quick start

New to LTP? Read in this order:

1. **[CONTRIBUTING.md](../CONTRIBUTING.md)** — clone, install, run the test
   suite (~10 minutes)
2. **[WHITEPAPER.md](WHITEPAPER.md)** — three-phase protocol design
3. **[visuals/README.md](visuals/README.md)** — Mermaid + HTML decks for
   LTP, GSX DAG, GSX-DB, and the ecosystem atlas
4. **[CORRIDOR_INTEGRATION.md](CORRIDOR_INTEGRATION.md)** — wire format
5. **[DEPLOYED_CONTRACTS.md](DEPLOYED_CONTRACTS.md)** — current registry
   addresses on GSX Testnet and Base Sepolia

## Visuals

- [Visuals overview (inline Mermaid)](visuals/README.md)
- Presentations: [LTP](visuals/ltp.html) · [GSX DAG](visuals/gsx-dag.html) · [GSX DB](visuals/gsx-db.html) · [Ecosystem Atlas](visuals/gsx-ecosystem-atlas.html) · [Visual index](visuals/index.html)
- Mermaid sources: [LTP](visuals/mermaid/ltp.md) · [GSX DAG](visuals/mermaid/gsx-dag.md) · [GSX DB](visuals/mermaid/gsx-db.md)
- Excalidraw sources: [LTP](visuals/excalidraw/ltp.excalidraw) · [GSX DAG](visuals/excalidraw/gsx-dag.excalidraw) · [GSX DB](visuals/excalidraw/gsx-db.excalidraw)

## Index by topic

| Category | Document | Description |
|---|---|---|
| **Getting Started** | [Contributing](../CONTRIBUTING.md) | Development setup, code style, PR workflow |
| | [Code of Conduct](../CODE_OF_CONDUCT.md) | Contributor Covenant 2.1 |
| | [Changelog](../CHANGELOG.md) | Version history v1.0.0 through v5.0.0 |
| | [Stability Promises](STABILITY_PROMISES.md) | What we will and won't break across versions |
| | [Security Policy](../SECURITY.md) | Vulnerability reporting and scope |
| **Specification** | [Whitepaper](WHITEPAPER.md) | Full protocol design — three-phase COMMIT / LATTICE / MATERIALIZE |
| | [Threat Model](THREAT_MODEL.md) | Adversary capabilities and invariants |
| | [Formal Verification Status](FORMAL_VERIFICATION_STATUS.md) | What's machine-checked vs paper-proven |
| **Architecture** | [Architecture](design-decisions/ARCHITECTURE.md) | System components, data flow, security layers |
| | [GSX DAG / GSX-DB Integration](design-decisions/GSX_DAG_DB_INTEGRATION.md) | Cross-repo boundary with the DAG L1 and state substrate |
| | [Corridor Integration](CORRIDOR_INTEGRATION.md) | Wire format and ABI surface |
| | [Streaming Protocol](design-decisions/STREAMING_PROTOCOL.md) | Chunked streaming, bandwidth amortization, backpressure |
| | [ZK Transfer Mode](design-decisions/ZK_TRANSFER_MODE.md) | Hiding commitments, Groth16 proofs |
| | [Enforcement Mechanisms](design-decisions/ENFORCEMENT_MECHANISMS.md) | PDP proofs, programmable slashing |
| | [Cross-Deployment Federation](design-decisions/CROSS_DEPLOYMENT_FEDERATION.md) | Network discovery, trust levels, federation |
| | [Commitment Network Options](design-decisions/COMMITMENT_NETWORK_OPTIONS.md) | Custom L1 vs Ethereum L1/L2 analysis |
| **Operations** | [Deployment Guide](DEPLOYMENT_GUIDE.md) | Docker, Kubernetes, CI/CD, key management |
| | [Operator Runbook](OPERATOR_RUNBOOK.md) | Day-2 operations, key rotation, on-call |
| | [Bridge MVP Scope](bridge-mvp-scope.md) | L1-L2 cross-chain bridge scope |
| | [Deployed Contracts](DEPLOYED_CONTRACTS.md) | Current registry addresses and governance topology |
| **Compliance** | [FedRAMP High Readiness](compliance/fedramp-high/README.md) | System boundary, control matrix, SSP narratives |
| **Security** | [Security Audit (2026-05-15)](SECURITY_AUDIT_2026-05-15.md) | Most recent independent audit |
| | [Security Review (2026-02-24)](design-decisions/Security/SECURITY_REVIEW-2-24-2026.md) | Formal security review |
| | [Shard Exposure Analysis](design-decisions/Security/001-lattice-key-shard-exposure.md) | Attack chain analysis and Option A-D comparison |
| | [Formal Protocol Analysis](formal/ANALYSIS.md) | Tamarin / ProVerif outputs |

## Document relationships

```mermaid
flowchart TD
    PERSONAS[Personas Landing] --> DAPP[dApp Developer]
    PERSONAS --> OPS[Node Operator]
    PERSONAS --> CRYPTO[Cryptographer]
    PERSONAS --> AUDIT[Compliance Auditor]
    PERSONAS --> CONTRIB[Contributor]

    DAPP --> DEPLOYED[Deployed Contracts]
    DAPP --> CORRIDOR[Corridor Integration]
    DAPP --> STABILITY[Stability Promises]

    OPS --> DEPLOY[Deployment Guide]
    OPS --> RUNBOOK[Operator Runbook]
    OPS --> DEPLOYED

    CRYPTO --> WP[Whitepaper]
    CRYPTO --> TM[Threat Model]
    CRYPTO --> FORMAL[Formal Verification Status]
    CRYPTO --> AUDITDOC[Security Audit]

    AUDIT --> FEDRAMP[FedRAMP Control Matrix]
    AUDIT --> AUDITDOC
    AUDIT --> DEPLOYED

    CONTRIB --> CONTRIBUTING[Contributing]
    CONTRIB --> MAKEFILE[Makefile]
    CONTRIB --> EXAMPLES[Examples]
```

## Examples

Runnable examples live in [`examples/`](../examples/) and double as
tutorial content. Start with [`quickstart.py`](../examples/quickstart.py)
and [`bridge_transfer.py`](../examples/bridge_transfer.py).
