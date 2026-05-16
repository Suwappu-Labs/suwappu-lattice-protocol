# Documentation by Role

Pick the path that matches what you're trying to do. Each persona page is a
router — it gives you a 30-second value prop, then the four or five deepest
links you need to get unblocked.

| You are… | Start here |
|---|---|
| Building a dApp that verifies LTP anchors | [dApp Developer](dapp-developer.md) |
| Running an LTP node, gateway, or corridor super-node | [Node Operator](node-operator.md) |
| Reviewing the cryptography or the proofs | [Cryptographer](cryptographer.md) |
| Verifying FedRAMP readiness or doing a third-party audit | [Compliance Auditor](compliance-auditor.md) |
| Contributing code, docs, or examples | [Contributor](contributor.md) |

## Why this exists

LTP has a lot of documentation — whitepaper, threat model, formal verification
status, deployment guide, operator runbook, FedRAMP control matrix, eight
design-decision documents, and so on. A single chronological index assumes
the reader already knows what they're looking for. The persona model triages
by use case instead, so you land on the right two or three documents in one
click.

## Diátaxis quadrants

Each persona page mixes four documentation types in different proportions:

| Quadrant | Question it answers | Example LTP doc |
|---|---|---|
| **Tutorial** | "How do I get started?" | [examples/quickstart.py](../../examples/quickstart.py) |
| **How-to** | "How do I accomplish this specific task?" | [OPERATOR_RUNBOOK.md](../OPERATOR_RUNBOOK.md) |
| **Reference** | "What is the exact API / parameter / address?" | [DEPLOYED_CONTRACTS.md](../DEPLOYED_CONTRACTS.md) |
| **Explanation** | "Why does it work this way?" | [WHITEPAPER.md](../WHITEPAPER.md) |

If you can't tell what kind of doc you need yet, start with the persona page.
