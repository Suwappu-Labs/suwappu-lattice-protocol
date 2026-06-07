# Examples

Self-contained code examples demonstrating ETP's capabilities, organized by complexity.

## Visuals

For architectural context behind these examples, see [`docs/visuals/`](../docs/visuals/README.md):

- [LTP presentation](../docs/visuals/ltp.html)
- [SUWAPPU DAG presentation](../docs/visuals/suwappu-dag.html)
- [SUWAPPU DB presentation](../docs/visuals/suwappu-db.html)
- [Ecosystem Atlas](../docs/visuals/suwappu-ecosystem-atlas.html)

## Prerequisites

```bash
pip install -e ".[dev]"
```

## Non-Python Integrations

For dApp developers verifying LTP anchors from JavaScript / TypeScript:

- [`verify_anchor_from_js.mjs`](verify_anchor_from_js.mjs) — ethers v6 script
  that reads [`contracts/abi/LTPAnchorRegistry.json`](../contracts/abi/LTPAnchorRegistry.json)
  and queries the registry on Base Sepolia (or any other deployment listed in
  [`docs/DEPLOYED_CONTRACTS.md`](../docs/DEPLOYED_CONTRACTS.md)). Run with
  `node examples/verify_anchor_from_js.mjs <rpcUrl> <registry> <entityIdHash>`.

## Quickstart

```python
from src.ltp import KeyPair, Entity, CommitmentNetwork, LTPProtocol, reset_poc_state

reset_poc_state()
alice, bob = KeyPair.generate("alice"), KeyPair.generate("bob")
net = CommitmentNetwork()
[net.add_node(f"n{i}", "us") for i in range(3)]
proto = LTPProtocol(net)

eid, rec, cek = proto.commit(Entity(b"Hello ETP!", "text/plain"), alice)
sealed = proto.lattice(eid, rec, cek, bob)
print(proto.materialize(sealed, bob))  # b'Hello ETP!'
```

## Examples by Complexity

### Beginner

| Example | Lines | Description |
|---------|:-----:|-------------|
| [quickstart.py](quickstart.py) | 10 | Minimal transfer in 10 lines |
| [primitives.py](primitives.py) | 65 | AEAD, ML-KEM-768, ML-DSA-65 directly |
| [dual_lane_hashing.py](dual_lane_hashing.py) | 45 | SHA3-256 canonical vs BLAKE3-256 internal |

### Intermediate

| Example | Lines | Description |
|---------|:-----:|-------------|
| [basic_transfer.py](basic_transfer.py) | 55 | Full COMMIT → LATTICE → MATERIALIZE with output |
| [signed_envelopes.py](signed_envelopes.py) | 80 | ML-DSA-65 envelopes, KID discovery, drift validation |
| [error_handling.py](error_handling.py) | 75 | What happens when things fail (wrong key, tamper, etc.) |

### Advanced

| Example | Lines | Description |
|---------|:-----:|-------------|
| [merkle_proofs.py](merkle_proofs.py) | 70 | Append-only log, inclusion proofs, signed tree heads |
| [streaming.py](streaming.py) | 75 | Chunked large entity transfer with backpressure |
| [bridge_transfer.py](bridge_transfer.py) | 82 | L1 → L2 cross-chain transfer with PQ-secure relay |

## Running

```bash
# Run any example
PYTHONPATH=. python examples/quickstart.py

# Run all examples
for f in examples/*.py; do echo "=== $f ===" && PYTHONPATH=. python3 "$f" && echo ""; done

# Run the full demo (covers everything)
PYTHONPATH=. python run_trust_layer.py
```

## Key Concepts

- **Entity**: Content + shape (media type). Content-addressed via SHA3-256.
- **CEK**: Random 256-bit Content Encryption Key. One per entity.
- **Sealed Key**: ~1.4KB ML-KEM-768 envelope. Constant size regardless of content.
- **Commitment Record**: ML-DSA-65 signed Merkle root. Append-only.
- **Forward Secrecy**: Fresh ML-KEM encapsulation per transfer.
- **Dual-Lane Hashing**: SHA3-256 for settlement, BLAKE3-256 for performance.
