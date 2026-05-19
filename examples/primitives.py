"""
Cryptographic Primitives — Direct access to AEAD, ML-KEM, ML-DSA.

Shows how to use ETP's crypto primitives independently of the protocol.
Useful for understanding what happens under the hood.

Usage:
    PYTHONPATH=. python examples/primitives.py
"""

import os

from src.ltp import reset_poc_state
from src.ltp.primitives import AEAD, MLDSA, MLKEM

reset_poc_state()

# ── AEAD: Authenticated Encryption ──────────────────────────────────────
print("▸ AEAD (XChaCha20-Poly1305 / PoC)")
key = os.urandom(32)
nonce = os.urandom(AEAD.NONCE_SIZE)
plaintext = b"Sensitive data to encrypt"
aad = b"additional-authenticated-data"

ciphertext = AEAD.encrypt(key, plaintext, nonce, aad)
print(f"  Plaintext:  {len(plaintext)} bytes")
print(f"  Ciphertext: {len(ciphertext)} bytes (includes {AEAD.TAG_SIZE}B auth tag)")
print(f"  Nonce:      {AEAD.NONCE_SIZE} bytes")

decrypted = AEAD.decrypt(key, ciphertext, nonce, aad)
print(f"  Decrypted:  {decrypted}")
assert decrypted == plaintext

# Tamper detection
print(f"\n  Tamper detection:")
tampered = bytearray(ciphertext)
tampered[0] ^= 0xFF
try:
    AEAD.decrypt(key, bytes(tampered), nonce, aad)
    print("  ERROR: should have failed!")
except ValueError as e:
    print(f"  Tampered ciphertext rejected ✓")

# ── ML-KEM-768: Key Encapsulation ────────────────────────────────────────
print("\n▸ ML-KEM-768 (FIPS 203)")
ek, dk = MLKEM.keygen()
print(f"  Encapsulation key (public): {len(ek)} bytes")
print(f"  Decapsulation key (secret): {len(dk)} bytes")

shared_secret, ciphertext = MLKEM.encaps(ek)
print(f"  Shared secret: {len(shared_secret)} bytes")
print(f"  KEM ciphertext: {len(ciphertext)} bytes")

recovered = MLKEM.decaps(dk, ciphertext)
print(f"  Recovered:     {len(recovered)} bytes")
assert shared_secret == recovered
print(f"  Match: ✓ (sender and receiver derive same shared secret)")

# Forward secrecy: each encaps produces different output
ss2, ct2 = MLKEM.encaps(ek)
print(f"\n  Forward secrecy:")
print(f"  Second encaps: different ciphertext = {ct2 != ciphertext}")
print(f"  Second secret: different secret     = {ss2 != shared_secret}")

# ── ML-DSA-65: Digital Signatures ────────────────────────────────────────
print("\n▸ ML-DSA-65 (FIPS 204)")
vk, sk = MLDSA.keygen()
print(f"  Verification key (public): {len(vk)} bytes")
print(f"  Signing key (secret):      {len(sk)} bytes")

message = b"This message is signed with post-quantum security"
signature = MLDSA.sign(sk, message)
print(f"  Signature: {len(signature)} bytes")

valid = MLDSA.verify(vk, message, signature)
print(f"  Valid signature: {valid}")

forged = MLDSA.verify(vk, b"different message", signature)
print(f"  Forged message:  {forged}")

print("\n✓ All three PQC primitives demonstrated.")
print(f"  AEAD: {AEAD.NONCE_SIZE}B nonce, {AEAD.TAG_SIZE}B tag")
print(f"  ML-KEM-768: {len(ek)}B ek, {len(dk)}B dk, {len(ciphertext)}B ct, 32B ss")
print(f"  ML-DSA-65: {len(vk)}B vk, {len(sk)}B sk, {len(signature)}B sig")
