# dApp Developer

You're building an application that needs to **verify LTP anchors on-chain**
or **subscribe to anchor events** to trigger downstream logic. You don't need
to run an LTP node yourself — you read from the deployed registry.

## 30-second value prop

LTP anchors a post-quantum-signed Merkle root of arbitrary off-chain state to
a deployed Solidity registry. Anyone can verify an inclusion proof against
the on-chain root. You consume LTP by reading `LTPAnchorRegistry.latestRoot()`
and validating the proof your counterparty sends you.

## Start here

1. **[DEPLOYED_CONTRACTS.md](../DEPLOYED_CONTRACTS.md)** — current registry
   addresses on SUWAPPU Testnet and Base Sepolia, plus the upgrade history.
   Verify these addresses match what your wallet sees before signing
   anything.
2. **[CORRIDOR_INTEGRATION.md](../CORRIDOR_INTEGRATION.md)** — the wire
   format and ABI surface. Read this before generating bindings.
3. **[examples/bridge_transfer.py](../../examples/bridge_transfer.py)** —
   end-to-end submit-anchor + verify-inclusion flow you can copy.
4. **[examples/merkle_proofs.py](../../examples/merkle_proofs.py)** — the
   inclusion-proof verifier in ~60 lines.
5. **[STABILITY_PROMISES.md](../STABILITY_PROMISES.md)** — what we won't
   break across minor versions, and what we will. Read this *before* you
   pin a version.

## Common questions

- **"How do I know the anchor I just read is current?"**
  → Check `latestRoot()` plus the `timestamp` field. The
  `STABILITY_PROMISES.md` cross-version matrix shows which registry version
  is live on each chain.
- **"What signature scheme verifies the anchor?"**
  → ML-DSA-65 (FIPS 204) for the post-quantum lane plus a hybrid Ed25519
  cosignature. See [THREAT_MODEL.md](../THREAT_MODEL.md) for the rationale.
- **"Can I subscribe to anchor events?"**
  → Yes — listen for `AnchorSubmitted(bytes32 root, uint256 epoch)` on
  the registry contract. The address is in
  [DEPLOYED_CONTRACTS.md](../DEPLOYED_CONTRACTS.md).

## You probably don't need

- The whitepaper or formal verification docs — your code never sees the
  internals.
- The operator runbook — you're not running a node.
- The FedRAMP compliance pages — those are for auditors of LTP-the-service,
  not consumers of LTP-the-registry.
