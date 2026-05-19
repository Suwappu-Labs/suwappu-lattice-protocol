"""
Error Handling — What happens when things go wrong.

Demonstrates ETP's failure modes: wrong key, tampered data, invalid
operations. Understanding these helps build robust applications.

Usage:
    PYTHONPATH=. python examples/error_handling.py
"""

import os

from src.ltp import (
    CommitmentNetwork,
    Entity,
    KeyPair,
    LTPProtocol,
    reset_poc_state,
)
from src.ltp.keypair import SealedBox
from src.ltp.primitives import AEAD
from src.ltp.shards import ShardEncryptor

reset_poc_state()

alice = KeyPair.generate("alice")
bob = KeyPair.generate("bob")
eve = KeyPair.generate("eve-attacker")
network = CommitmentNetwork()
for i in range(3):
    network.add_node(f"node-{i}", "us-east-1")
protocol = LTPProtocol(network)

# ── Error 1: Wrong receiver key ──────────────────────────────────────────
print("▸ Error 1: Unseal with wrong key")
entity = Entity(content=b"Secret message", shape="text/plain")
eid, record, cek = protocol.commit(entity, alice)
sealed = protocol.lattice(eid, record, cek, bob)

try:
    protocol.materialize(sealed, eve)  # Eve tries to open Bob's sealed key
    print("  ERROR: should have failed!")
except (ValueError, Exception) as e:
    print(f"  Rejected: {type(e).__name__} — Eve cannot unseal Bob's key ✓")

# ── Error 2: Tampered ciphertext ─────────────────────────────────────────
print("\n▸ Error 2: Tampered AEAD ciphertext")
key = os.urandom(32)
nonce = os.urandom(AEAD.NONCE_SIZE)
ct = AEAD.encrypt(key, b"authentic data", nonce)
tampered = bytearray(ct)
tampered[len(tampered) // 2] ^= 0x01  # Flip one bit

try:
    AEAD.decrypt(key, bytes(tampered), nonce)
    print("  ERROR: should have failed!")
except ValueError:
    print(f"  Rejected: authentication tag mismatch ✓")

# ── Error 3: Wrong AEAD key ──────────────────────────────────────────────
print("\n▸ Error 3: Decrypt with wrong key")
wrong_key = os.urandom(32)
try:
    AEAD.decrypt(wrong_key, ct, nonce)
    print("  ERROR: should have failed!")
except ValueError:
    print(f"  Rejected: wrong decryption key ✓")

# ── Error 4: Degenerate CEK rejected ─────────────────────────────────────
print("\n▸ Error 4: Degenerate CEK")
try:
    ShardEncryptor.validate_cek(b"\x00" * 32)  # All-zeros
    print("  ERROR: should have failed!")
except ValueError:
    print(f"  Rejected: all-zero CEK is degenerate ✓")

try:
    ShardEncryptor.validate_cek(b"\xff" * 32)  # All-ones
    print("  ERROR: should have failed!")
except ValueError:
    print(f"  Rejected: all-ones CEK is degenerate ✓")

# ── Error 5: SealedBox with wrong receiver ───────────────────────────────
print("\n▸ Error 5: SealedBox receiver mismatch")
sealed_data = SealedBox.seal(b"for bob only", bob.ek)
try:
    SealedBox.unseal(sealed_data, eve)
    print("  ERROR: should have failed!")
except ValueError:
    print(f"  Rejected: wrong decapsulation key ✓")

# Bob can unseal it
recovered = SealedBox.unseal(sealed_data, bob)
print(f"  Bob unseals: {recovered} ✓")

print("\n✓ All error cases handled gracefully — no silent failures.")
