"""
Signed Envelopes — ML-DSA-65 authenticated message wrappers.

Every protocol message in ETP is wrapped in a SignedEnvelope that provides:
- ML-DSA-65 signature (post-quantum non-repudiation)
- Signer KID (key identifier for discovery without full verification)
- Timestamp with optional drift validation
- Domain-separated signing (prevents cross-protocol replay)

Usage:
    pip install -e ".[dev]"
    python examples/signed_envelopes.py
"""

import time

from src.ltp import CommitmentNetwork, Entity, KeyPair, LTPProtocol, reset_poc_state
from src.ltp.domain import DOMAIN_COMMIT_RECORD, signer_fingerprint
from src.ltp.envelope import SignedEnvelope

reset_poc_state()

# ── Setup ────────────────────────────────────────────────────────────────
alice = KeyPair.generate("alice")
bob = KeyPair.generate("bob")

network = CommitmentNetwork()
for i in range(3):
    network.add_node(f"node-{i}", "us-east-1")
protocol = LTPProtocol(network)

# Commit an entity to get a real record
entity = Entity(content=b"Envelope demo payload", shape="text/plain")
eid, record, cek = protocol.commit(entity, alice)

# ── Create a Signed Envelope ─────────────────────────────────────────────
print("▸ Creating Signed Envelope")
envelope = record.to_envelope(alice.vk, alice.sk, "alice")
print(f"  Version:      {envelope.version}")
print(f"  Payload type: {envelope.payload_type}")
print(f"  Signer ID:    {envelope.signer_id}")
print(f"  Signer KID:   {envelope.signer_kid.hex()[:32]}...")
print(f"  Timestamp:    {envelope.timestamp:.3f}")
print(f"  Signature:    {len(envelope.signature)} bytes")

# ── Verify the Envelope ──────────────────────────────────────────────────
print("\n▸ Verification")
print(f"  Signature valid: {envelope.verify()}")

# ── Key Discovery (peek without full verify) ─────────────────────────────
print("\n▸ Key Discovery (unauthenticated)")
kid = SignedEnvelope.extract_signer_kid(envelope)
pt, payload = SignedEnvelope.peek_payload(envelope)
print(f"  Signer KID:    {kid.hex()[:32]}...")
print(f"  Payload type:  {pt}")
print(f"  Payload size:  {len(payload)} bytes")
print(f"  (These are unauthenticated — verify() before trusting!)")

# ── Timestamp Drift Validation ───────────────────────────────────────────
print("\n▸ Drift Validation")
# Create a stale envelope (2 minutes old)
stale = SignedEnvelope.create_at(
    domain=DOMAIN_COMMIT_RECORD,
    signer_vk=alice.vk,
    signer_sk=alice.sk,
    signer_id="alice",
    payload_type="test",
    payload=b"stale data",
    timestamp=time.time() - 120,
)
print(f"  Stale envelope (120s old):")
print(f"    verify():              {stale.verify()}")
print(f"    verify(max_drift=60):  {stale.verify(max_drift=60)}")
print(f"    verify(max_drift=300): {stale.verify(max_drift=300)}")

# ── Fingerprint Matching ─────────────────────────────────────────────────
print("\n▸ Fingerprint Matching")
alice_fp = signer_fingerprint(alice.vk)
bob_fp = signer_fingerprint(bob.vk)
envelope_fp = envelope.signer_kid
print(f"  Alice fingerprint: {alice_fp.hex()[:32]}...")
print(f"  Envelope KID:      {envelope_fp.hex()[:32]}...")
print(f"  Match (alice):     {alice_fp == envelope_fp}")
print(f"  Match (bob):       {bob_fp == envelope_fp}")
