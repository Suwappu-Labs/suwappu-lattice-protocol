"""
Merkle Log — Append-only ledger with inclusion and consistency proofs.

ETP's commitment log is a Merkle tree (RFC 6962 Certificate Transparency style)
that provides:
- Append-only: entries cannot be modified or deleted
- Inclusion proofs: prove a record exists in the log (O(log N))
- Signed Tree Heads (STH): ML-DSA-65 signed root hash

Usage:
    PYTHONPATH=. python examples/merkle_proofs.py
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
alice = KeyPair.generate("alice")
network = CommitmentNetwork()
for i in range(3):
    network.add_node(f"node-{i}", "us-east-1")
protocol = LTPProtocol(network)

# ── Commit multiple entities to build up the log ─────────────────────────
print("▸ Committing 5 entities to build Merkle log...")
entity_ids = []
for i in range(5):
    entity = Entity(content=f"Document #{i + 1}".encode(), shape="text/plain")
    eid, record, cek = protocol.commit(entity, alice)
    entity_ids.append(eid)
    print(f"  #{i + 1}: {eid[:48]}...")

# ── Merkle Log Properties ────────────────────────────────────────────────
log = network.log
print(f"\n▸ Merkle Log State")
print(f"  Log length:  {log.length}")
print(f"  Head hash:   {log.head_hash[:48]}...")

# ── Inclusion Proof ──────────────────────────────────────────────────────
print(f"\n▸ Inclusion Proof (entity #3)")
eid3 = entity_ids[2]
proof = log.get_inclusion_proof(eid3)
print(f"  Entity ID:   {eid3[:48]}...")
print(f"  Position:    {proof['position']}")
print(f"  Root hash:   {proof['root_hash'][:48]}...")

# Verify the proof
verified = log.verify_inclusion(eid3, proof)
print(f"  Verified:    {verified}")

# ── Signed Tree Head ─────────────────────────────────────────────────────
print(f"\n▸ Signed Tree Head (STH)")
sth = log.latest_sth
print(f"  Sequence:    {sth.sequence}")
print(f"  Tree size:   {sth.tree_size}")
print(f"  Root hash:   {sth.root_hash.hex()[:48]}...")
print(f"  Signature:   {len(sth.signature)} bytes")

# ── Portable Proof ───────────────────────────────────────────────────────
print(f"\n▸ Portable Merkle Proof (entity #1)")
portable = log.get_portable_proof(entity_ids[0])
if portable:
    print(f"  Tree type:   {portable.tree_type}")
    print(f"  Self-contained: can verify without log access")

print("\n✓ Merkle log provides tamper-evident, append-only commitment history.")
