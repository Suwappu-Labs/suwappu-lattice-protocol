"""
Dual-Lane Hashing — SHA3-256 canonical vs BLAKE3-256 internal.

ETP enforces strict separation between two hash lanes:
- Canonical (SHA3-256): For all on-chain, settlement, and audit paths
- Internal (BLAKE3-256): For performance-optimized internal operations

Mixing lanes is a compliance violation caught by Semgrep rules.

Usage:
    PYTHONPATH=. python examples/dual_lane_hashing.py
"""

import sys
from pathlib import Path

sys.path.insert(
    0, str(Path(__file__).resolve().parents[1])
)  # repo root, so `src.ltp` imports work no matter where you run from

from src.ltp import canonical_hash, canonical_hash_bytes, internal_hash, internal_hash_bytes

data = b"Hello from the dual-lane architecture!"

# ── Canonical Lane (SHA3-256) ────────────────────────────────────────────
print("▸ Canonical Lane (SHA3-256)")
print("  Used for: entity IDs, commitment records, Merkle roots, signatures")
c_hash = canonical_hash(data)
c_bytes = canonical_hash_bytes(data)
print(f"  Hash:   {c_hash}")
print(f"  Bytes:  {c_bytes.hex()[:48]}... ({len(c_bytes)} bytes)")
print(f"  Prefix: {c_hash.split(':')[0]}")

# ── Internal Lane (BLAKE3-256) ───────────────────────────────────────────
print("\n▸ Internal Lane (BLAKE3-256)")
print("  Used for: shard indexing, caching, AEAD keystream, chunk integrity")
i_hash = internal_hash(data)
i_bytes = internal_hash_bytes(data)
print(f"  Hash:   {i_hash}")
print(f"  Bytes:  {i_bytes.hex()[:48]}... ({len(i_bytes)} bytes)")
print(f"  Prefix: {i_hash.split(':')[0]}")

# ── They are different! ──────────────────────────────────────────────────
print(f"\n▸ Comparison")
print(f"  Same input, different outputs: {c_bytes != i_bytes}")
print(f"  Same length (32 bytes):        {len(c_bytes) == len(i_bytes) == 32}")

# ── Determinism ──────────────────────────────────────────────────────────
print(f"\n▸ Determinism")
print(f"  canonical(data) == canonical(data): {canonical_hash(data) == canonical_hash(data)}")
print(f"  internal(data) == internal(data):   {internal_hash(data) == internal_hash(data)}")

# ── Why two lanes? ───────────────────────────────────────────────────────
print(f"""
▸ Why Two Lanes?
  1. FIPS compliance: SHA3-256 is NIST-approved for settlement paths
  2. Performance: BLAKE3 is 5-10x faster for internal operations
  3. Audit boundary: regulators verify canonical lane only
  4. Defense-in-depth: compromising one lane doesn't affect the other
""")
