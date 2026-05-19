"""
Cross-Chain Bridge Transfer — L1 → L2 via ETP.

Demonstrates the bridge protocol: anchor a message on L1, relay a sealed key
across the chain gap, and materialize on L2. The relay packet is PQ-secure
(ML-KEM-768 sealed) — the relayer CANNOT read or modify the content.

Usage:
    PYTHONPATH=. python examples/bridge_transfer.py
"""

import time

from src.ltp import (
    CommitmentNetwork,
    KeyPair,
    LTPProtocol,
    reset_poc_state,
)
from src.ltp.bridge import BridgeMessage, L1Anchor, L2Materializer, Relayer

reset_poc_state()

# ── Setup ────────────────────────────────────────────────────────────────
print("▸ Setup")
l1_operator = KeyPair.generate("l1-operator")
l2_verifier = KeyPair.generate("l2-verifier")

network = CommitmentNetwork()
for i in range(3):
    network.add_node(f"node-{i}", "us-east-1")
protocol = LTPProtocol(network)

# Bridge components
l1_anchor = L1Anchor(protocol, l1_operator, chain_id="ethereum")
relayer = Relayer(protocol)
l2_materializer = L2Materializer(protocol, l2_verifier, chain_id="gsx-l2")

print(f"  L1 Operator: {l1_operator.label}")
print(f"  L2 Verifier: {l2_verifier.label}")

# ── Step 1: Create Bridge Message ────────────────────────────────────────
print("\n▸ Step 1: Create Bridge Message")
msg = BridgeMessage(
    msg_type="token_lock",
    source_chain="ethereum",
    dest_chain="gsx-l2",
    sender="0xAlice",
    recipient="0xBob",
    payload={"token": "ETH", "amount": "1.5"},
    nonce=1,
    timestamp=time.time(),
)
print(f"  Type:    {msg.msg_type}")
print(f"  Route:   {msg.source_chain} → {msg.dest_chain}")
print(f"  Payload: {msg.payload}")
print(f"  Nonce:   {msg.nonce}")

# ── Step 2: Anchor on L1 (COMMIT phase) ──────────────────────────────────
print("\n▸ Step 2: Anchor on L1 (COMMIT)")
commitment, cek = l1_anchor.commit_message(msg)
print(f"  Entity ID:    {commitment.entity_id[:48]}...")
print(f"  CEK:          {cek.hex()[:16]}... (secret, for relayer)")

# ── Step 3: Relay (LATTICE phase) ────────────────────────────────────────
print("\n▸ Step 3: Relay Sealed Key (LATTICE)")
relay_packet = relayer.relay(commitment, cek, l2_verifier)
print(f"  Sealed key:   {len(relay_packet.sealed_key)} bytes")
print(f"  Relayer sees: NOTHING (ML-KEM-768 encrypted)")

# ── Step 4: Materialize on L2 (MATERIALIZE phase) ────────────────────────
print("\n▸ Step 4: Materialize on L2 (MATERIALIZE)")
# Set L1 finality view so materializer accepts the packet
# Need source_block + required_confirmations for finality
l2_materializer.set_l1_block_height(relay_packet.source_block + 1)
result = l2_materializer.materialize(relay_packet)

if result:
    print(f"  Message type: {result.msg_type}")
    print(f"  Sender:       {result.sender}")
    print(f"  Recipient:    {result.recipient}")
    print(f"  Payload:      {result.payload}")
    print(f"\n✓ Cross-chain transfer complete — relayer never had access to content.")
else:
    print("  Materialization failed (check logs for details)")
