"""Length-prefixed SHA3-256 domain hash.

Wire-compatible with `suwappu-dag/crates/suwappu-crypto/src/hash.rs::sha3_256_domain`:

    H(len(tag) as u32 BE || tag || data)

This is intentionally distinct from LTP's existing `domain_hash_bytes` helper,
which prepends the domain tag without a length prefix and uses a different tag
encoding (`SUWAPPU-LTP:name:v1\\x00`). The corridor surface lives on the cross-repo
wire so it must use the exact byte layout the DAG L1 publishes.
"""

from __future__ import annotations

import hashlib


def sha3_256_domain(tag: bytes, data: bytes) -> bytes:
    """Compute the length-prefixed domain-separated SHA3-256 digest.

    Matches `suwappu_crypto::hash::sha3_256_domain` in the suwappu-dag workspace.
    """
    if len(tag) > 0xFFFFFFFF:
        raise ValueError("tag length exceeds u32::MAX")
    h = hashlib.sha3_256()
    h.update(len(tag).to_bytes(4, "big"))
    h.update(tag)
    h.update(data)
    return h.digest()
