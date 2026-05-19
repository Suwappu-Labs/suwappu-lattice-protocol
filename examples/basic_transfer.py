"""
Basic ETP Transfer — COMMIT → LATTICE → MATERIALIZE

The simplest end-to-end transfer: Alice commits content, seals a lattice key
to Bob, and Bob materializes the original content.

Usage:
    pip install -e ".[dev]"
    python examples/basic_transfer.py
"""

from src.ltp import (
    CommitmentNetwork,
    Entity,
    KeyPair,
    LTPProtocol,
    reset_poc_state,
)

reset_poc_state()

# ── Setup ────────────────────────────────────────────────────────────────
print("Setting up keypairs and network...")
alice = KeyPair.generate("alice")  # Sender
bob = KeyPair.generate("bob")  # Receiver

# Create a 3-node commitment network
network = CommitmentNetwork()
for i in range(3):
    network.add_node(f"node-{i}", "us-east-1")

protocol = LTPProtocol(network)

# ── Phase 1: COMMIT ──────────────────────────────────────────────────────
print("\n▸ Phase 1: COMMIT")
entity = Entity(content=b"Hello from the Lattice Transfer Protocol!", shape="text/plain")
entity_id, record, cek = protocol.commit(entity, alice)

print(f"  Entity ID:    {entity_id[:48]}...")
print(f"  Merkle root:  {record.shard_map_root[:48]}...")
print(f"  Signed by:    {record.sender_id}")
print(f"  CEK:          {cek.hex()[:16]}... ({len(cek)} bytes)")

# ── Phase 2: LATTICE ─────────────────────────────────────────────────────
print("\n▸ Phase 2: LATTICE")
sealed_key = protocol.lattice(entity_id, record, cek, bob)

print(f"  Sealed key:   {len(sealed_key)} bytes (constant size, O(1))")
print(f"  Recipient:    bob")

# ── Phase 3: MATERIALIZE ─────────────────────────────────────────────────
print("\n▸ Phase 3: MATERIALIZE")
content = protocol.materialize(sealed_key, bob)

print(f"  Reconstructed: {content.decode('utf-8')}")
print(f"  Match:         {content == entity.content}")

print("\n✓ Transfer complete — content never moved as a monolithic payload.")
